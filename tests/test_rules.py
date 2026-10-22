"""Regel-Engine und Regelschema."""

from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from helpers import make_record
from wineventai.enrich.aggregate import Enricher
from wineventai.rules.engine import RuleEngine, unmatched_keys
from wineventai.rules.loader import RuleLoadError, _load_file, builtin_rules, load_rules
from wineventai.rules.schema import Classification, RuleDefinition, Severity


def test_regel_ohne_provider_wird_abgelehnt() -> None:
    """Event-IDs sind nur je Provider eindeutig.

    1001 ist BugCheck im System-Kanal UND Windows Error Reporting im
    Application-Kanal. Eine Regel ohne Provider ist ein Fehlalarm-Generator.
    """
    with pytest.raises(ValidationError):
        RuleDefinition.model_validate(
            {"id": "test", "name": "Test", "match": {"event_id": 1001}, "severity": "fehler"}
        )


def test_message_regex_ohne_locale_wird_abgelehnt() -> None:
    """Meldungstexte sind uebersetzt. Ohne locale behauptet die Regel zu viel."""
    with pytest.raises(ValidationError) as excinfo:
        RuleDefinition.model_validate(
            {
                "id": "test",
                "name": "Test",
                "severity": "fehler",
                "match": {"provider": "X", "event_id": 1, "message_regex": "Fehler"},
            }
        )
    assert "locale" in str(excinfo.value)


def test_message_regex_mit_locale_ist_erlaubt() -> None:
    rule = RuleDefinition.model_validate(
        {
            "id": "test",
            "name": "Test",
            "severity": "fehler",
            "match": {
                "provider": "X",
                "event_id": 1,
                "message_regex": "Fehler",
                "locale": "de-DE",
            },
        }
    )
    assert rule.compiled_message() is not None


def test_ungueltiger_regex_wird_beim_laden_bemerkt() -> None:
    with pytest.raises(ValidationError):
        RuleDefinition.model_validate(
            {
                "id": "test",
                "name": "Test",
                "severity": "fehler",
                "match": {"provider": "X", "event_id": 1,
                          "message_regex": "([unvollstaendig", "locale": "de-DE"},
            }
        )


def test_mitgelieferte_regeln_sind_gueltig() -> None:
    rules = builtin_rules()
    assert len(rules) >= 20
    ids = [rule.id for rule in rules]
    assert len(ids) == len(set(ids)), "Regel-IDs muessen eindeutig sein"
    for rule in rules:
        assert rule.match.providers(), rule.id
        assert rule.match.event_ids(), rule.id


def test_bugcheck_und_wer_teilen_die_id_aber_nicht_den_provider() -> None:
    """Der Praezedenzfall fuer die Provider-Pflicht."""
    rules = {rule.id: rule for rule in builtin_rules()}
    bugcheck = rules["bugcheck-1001"]
    assert bugcheck.match.providers() == ["Microsoft-Windows-WER-SystemErrorReporting"]
    assert bugcheck.match.channels() == ["System"]


def test_sicherheitsregeln_nur_im_sicherheitsmodus() -> None:
    normal = load_rules(include_security=False)
    security = load_rules(include_security=True)
    assert not any(rule.security_indicator for rule in normal)
    assert any(rule.security_indicator for rule in security)


def test_overlay_ueberschreibt_nach_id(tmp_path) -> None:
    overlay = tmp_path / "rules"
    overlay.mkdir()
    (overlay / "eigene.yaml").write_text(
        yaml.safe_dump(
            [
                {
                    "id": "kernel-power-41",
                    "name": "Eigene Fassung",
                    "severity": "warnung",
                    "match": {"provider": "Microsoft-Windows-Kernel-Power", "event_id": 41},
                }
            ]
        ),
        encoding="utf-8",
    )
    rules = {rule.id: rule for rule in load_rules(overlay=str(overlay))}
    assert rules["kernel-power-41"].name == "Eigene Fassung"
    assert rules["kernel-power-41"].source.startswith("overlay:"), (
        "die Herkunft muss im Bericht sichtbar bleiben"
    )


def test_kaputte_overlay_datei_nennt_die_regel(tmp_path) -> None:
    path = tmp_path / "kaputt.yaml"
    path.write_text(
        yaml.safe_dump([{"id": "ohne-provider", "name": "X", "severity": "fehler",
                         "match": {"event_id": 1}}]),
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError) as excinfo:
        _load_file(path, source="test")
    assert "ohne-provider" in str(excinfo.value)


def _engine() -> RuleEngine:
    return RuleEngine(load_rules(include_security=True))


def test_rauschregeln_zaehlen_nicht_als_retention_prioritaet() -> None:
    """Sonst verbraucht DistributedCOM das Kontingent der Prioritaet 1."""
    engine = _engine()
    assert ("Microsoft-Windows-DistributedCOM", 10016) in engine.noise_keys
    assert ("Microsoft-Windows-DistributedCOM", 10016) not in engine.rule_keys
    assert ("Microsoft-Windows-Kernel-Power", 41) in engine.rule_keys


def test_rauschen_wird_klassifiziert_und_unterdrueckt() -> None:
    stream = [
        make_record(
            minutes_ago=i * 6,
            provider="Microsoft-Windows-DistributedCOM",
            event_id=10016,
            level=3,
            properties=["{GUID}", "SYSTEM"],
        )
        for i in range(300)
    ]
    result = Enricher(window_hours=168).consume(stream)
    findings = _engine().evaluate(result)

    assert findings, "das Rauschen muss erkannt, nicht ignoriert werden"
    assert all(finding.suppressed for finding in findings)
    assert findings[0].severity is Severity.RAUSCHEN


def test_schwellwert_eskaliert_die_schwere() -> None:
    stream = [
        make_record(minutes_ago=i, channel="System", provider="Service Control Manager",
                    event_id=7031, level=2, properties=["Druckwarteschlange", "1"])
        for i in range(25)
    ]
    result = Enricher(window_hours=168).consume(stream)
    findings = _engine().evaluate(result)
    treffer = [f for f in findings if f.rule_id == "scm-dienst-beendet"]
    assert treffer and treffer[0].escalated
    assert treffer[0].severity is Severity.KRITISCH


def test_burst_pflicht_verhindert_treffer_ohne_haeufung() -> None:
    """Die 4625-Regel verlangt eine Haeufung - Einzelfehler sind Alltag."""
    stream = [
        make_record(minutes_ago=i * 240, channel="Security",
                    provider="Microsoft-Windows-Security-Auditing", event_id=4625,
                    properties=["konto", "3"])
        for i in range(12)
    ]
    result = Enricher(window_hours=168).consume(stream)
    findings = _engine().evaluate(result)
    assert not [f for f in findings if f.rule_id == "sec-anmeldefehler-serie"]


def test_burst_loest_die_serienregel_aus() -> None:
    stream = [
        make_record(minutes_ago=i, channel="Security",
                    provider="Microsoft-Windows-Security-Auditing", event_id=4625,
                    properties=["konto", "3"])
        for i in range(40)
    ]
    result = Enricher(window_hours=168).consume(stream)
    findings = _engine().evaluate(result)
    assert [f for f in findings if f.rule_id == "sec-anmeldefehler-serie"]


def test_data_bedingung_liest_benanntes_eventdata_feld() -> None:
    """Logon Type 10 wird ueber EventData geprueft, nicht ueber den Text."""
    stream = [
        make_record(minutes_ago=1, channel="Security",
                    provider="Microsoft-Windows-Security-Auditing", event_id=4624,
                    properties=["konto", "10"],
                    event_data={"TargetUserName": "konto", "LogonType": "10"}),
    ]
    findings = _engine().evaluate(Enricher(window_hours=168).consume(stream))
    assert [f for f in findings if f.rule_id == "sec-remote-anmeldung"]

    stream_lokal = [
        make_record(minutes_ago=1, channel="Security",
                    provider="Microsoft-Windows-Security-Auditing", event_id=4624,
                    properties=["konto", "2"],
                    event_data={"TargetUserName": "konto", "LogonType": "2"}),
    ]
    findings = _engine().evaluate(Enricher(window_hours=168).consume(stream_lokal))
    assert not [f for f in findings if f.rule_id == "sec-remote-anmeldung"]


def test_unbekannte_paare_werden_als_arbeitsliste_gemeldet() -> None:
    stream = [make_record(minutes_ago=1, provider="Irgendein-Provider", event_id=9999)]
    result = Enricher(window_hours=168).consume(stream)
    unbekannt = unmatched_keys(result, _engine())
    assert ("Irgendein-Provider", 9999, 1) in unbekannt


def test_klassifikation_ist_typisiert() -> None:
    rules = {rule.id: rule for rule in builtin_rules()}
    assert rules["dcom-10016"].classification is Classification.RAUSCHEN
    assert rules["kernel-power-41"].classification is Classification.BEFUND
