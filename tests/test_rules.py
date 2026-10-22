"""Rule engine and rule schema."""

from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from helpers import make_record
from wineventai.enrich.aggregate import Enricher
from wineventai.rules.engine import RuleEngine, unmatched_keys
from wineventai.rules.loader import RuleLoadError, _load_file, builtin_rules, load_rules
from wineventai.rules.schema import Classification, RuleDefinition, Severity


def test_a_rule_without_provider_is_rejected() -> None:
    """Event ids are only unique per provider.

    1001 is BugCheck in the System channel AND Windows Error Reporting in the
    Application channel. A rule without provider is a false-alarm generator.
    """
    with pytest.raises(ValidationError):
        RuleDefinition.model_validate(
            {"id": "test", "name": "Test", "match": {"event_id": 1001}, "severity": "error"}
        )


def test_message_regex_without_locale_is_rejected() -> None:
    """Message texts are translated. Without a locale the rule claims too much."""
    with pytest.raises(ValidationError) as excinfo:
        RuleDefinition.model_validate(
            {
                "id": "test",
                "name": "Test",
                "severity": "error",
                "match": {"provider": "X", "event_id": 1, "message_regex": "Error"},
            }
        )
    assert "locale" in str(excinfo.value)


def test_message_regex_with_locale_is_allowed() -> None:
    rule = RuleDefinition.model_validate(
        {
            "id": "test",
            "name": "Test",
            "severity": "error",
            "match": {
                "provider": "X",
                "event_id": 1,
                "message_regex": "Fehler",
                "locale": "de-DE",
            },
        }
    )
    assert rule.compiled_message() is not None


def test_an_invalid_regex_is_noticed_when_loading() -> None:
    with pytest.raises(ValidationError):
        RuleDefinition.model_validate(
            {
                "id": "test",
                "name": "Test",
                "severity": "error",
                "match": {"provider": "X", "event_id": 1,
                          "message_regex": "([incomplete", "locale": "en-US"},
            }
        )


def test_bundled_rules_are_valid() -> None:
    rules = builtin_rules()
    assert len(rules) >= 20
    ids = [rule.id for rule in rules]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
    for rule in rules:
        assert rule.match.providers(), rule.id
        assert rule.match.event_ids(), rule.id


def test_bugcheck_and_wer_share_the_id_but_not_the_provider() -> None:
    """The precedent for the provider requirement."""
    rules = {rule.id: rule for rule in builtin_rules()}
    bugcheck = rules["bugcheck-1001"]
    assert bugcheck.match.providers() == ["Microsoft-Windows-WER-SystemErrorReporting"]
    assert bugcheck.match.channels() == ["System"]


def test_security_rules_only_in_security_mode() -> None:
    normal = load_rules(include_security=False)
    security = load_rules(include_security=True)
    assert not any(rule.security_indicator for rule in normal)
    assert any(rule.security_indicator for rule in security)


def test_the_overlay_overrides_by_id(tmp_path) -> None:
    overlay = tmp_path / "rules"
    overlay.mkdir()
    (overlay / "own.yaml").write_text(
        yaml.safe_dump(
            [
                {
                    "id": "kernel-power-41",
                    "name": "Own version",
                    "severity": "warning",
                    "match": {"provider": "Microsoft-Windows-Kernel-Power", "event_id": 41},
                }
            ]
        ),
        encoding="utf-8",
    )
    rules = {rule.id: rule for rule in load_rules(overlay=str(overlay))}
    assert rules["kernel-power-41"].name == "Own version"
    assert rules["kernel-power-41"].source.startswith("overlay:"), (
        "the origin must stay visible in the report"
    )


def test_an_overlay_written_for_older_german_versions_still_loads(tmp_path) -> None:
    """Rule overlays from before 2.0 used German field names and severities."""
    overlay = tmp_path / "rules"
    overlay.mkdir()
    (overlay / "legacy.yaml").write_text(
        yaml.safe_dump(
            [
                {
                    "id": "legacy-rule",
                    "name": "Legacy",
                    "severity": "kritisch",
                    "classification": "befund",
                    "bedeutung": "Old meaning",
                    "typische_ursachen": ["A"],
                    "empfohlene_checks": ["B"],
                    "match": {"provider": "Some-Provider", "event_id": 7},
                }
            ]
        ),
        encoding="utf-8",
    )
    rules = {rule.id: rule for rule in load_rules(overlay=str(overlay))}
    legacy = rules["legacy-rule"]
    assert legacy.severity is Severity.CRITICAL
    assert legacy.classification is Classification.FINDING
    assert legacy.meaning == "Old meaning"
    assert legacy.typical_causes == ["A"]
    assert legacy.recommended_checks == ["B"]


def test_a_broken_overlay_file_names_the_rule(tmp_path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text(
        yaml.safe_dump([{"id": "without-provider", "name": "X", "severity": "error",
                         "match": {"event_id": 1}}]),
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError) as excinfo:
        _load_file(path, source="test")
    assert "without-provider" in str(excinfo.value)


def _engine() -> RuleEngine:
    return RuleEngine(load_rules(include_security=True))


def test_noise_rules_do_not_count_as_retention_priority() -> None:
    """Otherwise DistributedCOM uses up the priority-1 quota."""
    engine = _engine()
    assert ("Microsoft-Windows-DistributedCOM", 10016) in engine.noise_keys
    assert ("Microsoft-Windows-DistributedCOM", 10016) not in engine.rule_keys
    assert ("Microsoft-Windows-Kernel-Power", 41) in engine.rule_keys


def test_noise_is_classified_and_suppressed() -> None:
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

    assert findings, "the noise must be recognized, not ignored"
    assert all(finding.suppressed for finding in findings)
    assert findings[0].severity is Severity.NOISE


def test_a_threshold_escalates_the_severity() -> None:
    stream = [
        make_record(minutes_ago=i, channel="System", provider="Service Control Manager",
                    event_id=7031, level=2, properties=["Print Spooler", "1"])
        for i in range(25)
    ]
    result = Enricher(window_hours=168).consume(stream)
    findings = _engine().evaluate(result)
    hits = [f for f in findings if f.rule_id == "scm-service-terminated"]
    assert hits and hits[0].escalated
    assert hits[0].severity is Severity.CRITICAL


def test_a_required_burst_prevents_hits_without_clustering() -> None:
    """The 4625 rule requires clustering - single failures are everyday life."""
    stream = [
        make_record(minutes_ago=i * 240, channel="Security",
                    provider="Microsoft-Windows-Security-Auditing", event_id=4625,
                    properties=["account", "3"])
        for i in range(12)
    ]
    result = Enricher(window_hours=168).consume(stream)
    findings = _engine().evaluate(result)
    assert not [f for f in findings if f.rule_id == "sec-logon-failure-series"]


def test_a_burst_triggers_the_series_rule() -> None:
    stream = [
        make_record(minutes_ago=i, channel="Security",
                    provider="Microsoft-Windows-Security-Auditing", event_id=4625,
                    properties=["account", "3"])
        for i in range(40)
    ]
    result = Enricher(window_hours=168).consume(stream)
    findings = _engine().evaluate(result)
    assert [f for f in findings if f.rule_id == "sec-logon-failure-series"]


def test_a_data_condition_reads_a_named_eventdata_field() -> None:
    """Logon type 10 is checked via EventData, not via the text."""
    stream = [
        make_record(minutes_ago=1, channel="Security",
                    provider="Microsoft-Windows-Security-Auditing", event_id=4624,
                    properties=["account", "10"],
                    event_data={"TargetUserName": "account", "LogonType": "10"}),
    ]
    findings = _engine().evaluate(Enricher(window_hours=168).consume(stream))
    assert [f for f in findings if f.rule_id == "sec-remote-logon"]

    stream_local = [
        make_record(minutes_ago=1, channel="Security",
                    provider="Microsoft-Windows-Security-Auditing", event_id=4624,
                    properties=["account", "2"],
                    event_data={"TargetUserName": "account", "LogonType": "2"}),
    ]
    findings = _engine().evaluate(Enricher(window_hours=168).consume(stream_local))
    assert not [f for f in findings if f.rule_id == "sec-remote-logon"]


def test_unknown_pairs_are_reported_as_a_work_list() -> None:
    stream = [make_record(minutes_ago=1, provider="Some-Provider", event_id=9999)]
    result = Enricher(window_hours=168).consume(stream)
    unknown = unmatched_keys(result, _engine())
    assert ("Some-Provider", 9999, 1) in unknown


def test_the_classification_is_typed() -> None:
    rules = {rule.id: rule for rule in builtin_rules()}
    assert rules["dcom-10016"].classification is Classification.NOISE
    assert rules["kernel-power-41"].classification is Classification.FINDING
