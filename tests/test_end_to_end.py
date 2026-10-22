"""Ende-zu-Ende: Laufverzeichnis rein, Bericht raus.

Der KI-Layer wird gemockt. Zwei Durchlaeufe pruefen die beiden Zustaende, die
im Betrieb wirklich vorkommen: mit erreichbarem Modell und ohne.
"""

from __future__ import annotations

import json

from test_ai import FakeClient, _fixture
from wineventai.ai.pipeline import AiLayer
from wineventai.ai.redaction import Redactor
from wineventai.analyze import analyze_run
from wineventai.config import load_config
from wineventai.kb.store import KnowledgeBase


def _config(**overrides: object):
    base = {"rules": {"security_mode": True}}
    base.update(overrides)  # type: ignore[arg-type]
    return load_config(overrides=base)


def test_lauf_ohne_modell_erzeugt_vollstaendigen_bericht(fixture_run) -> None:
    """Der Bericht muss auch ohne Sprachmodell vollstaendig entstehen."""
    result = analyze_run(fixture_run, _config(ai={"enabled": False}))

    assert result.report.findings
    assert (fixture_run.report_dir / "bericht.html").is_file()
    assert (fixture_run.report_dir / "bericht.md").is_file()
    assert (fixture_run.report_dir / "bericht.json").is_file()
    assert fixture_run.unknown_ids_path.is_file()
    assert (fixture_run.derived_dir / "groups.json").is_file()
    assert (fixture_run.derived_dir / "findings.json").is_file()


def test_buendel_werden_auch_ohne_modell_abgelegt(fixture_run) -> None:
    """Nachvollziehbarkeit haengt nicht am Modell."""
    analyze_run(fixture_run, _config(ai={"enabled": False}))
    bundles = list(fixture_run.bundles_dir.glob("*.json"))
    assert bundles, "die Buendel entstehen unabhaengig vom Modell"

    payload = json.loads(bundles[0].read_text(encoding="utf-8"))
    assert "belegbare_ereignisse" in payload
    assert "systemkontext" in payload


def test_lauf_mit_modell_schreibt_antwort_und_pruefergebnis(fixture_run) -> None:
    kb = KnowledgeBase.open_default()
    client = FakeClient([_fixture("explainer_gut.json")] * 60)
    layer = AiLayer(_config().ai, client=client, kb=kb, redactor=Redactor())

    result = analyze_run(fixture_run, _config(), kb=kb, ai_layer=layer)

    assert result.report.ai.used is True
    assert result.report.ai.model == "test-modell"
    antworten = list(fixture_run.ai_dir.glob("*.json"))
    assert antworten

    payload = json.loads(antworten[0].read_text(encoding="utf-8"))
    assert "verification" in payload
    kb.close()


def test_erfundene_aussagen_landen_sichtbar_im_bericht(fixture_run) -> None:
    """Die Nachpruefung darf nicht still verwerfen - sie muss es zeigen."""
    kb = KnowledgeBase.open_default()
    client = FakeClient([_fixture("explainer_erfundene_id.json")] * 60)
    layer = AiLayer(_config().ai, client=client, kb=kb, redactor=Redactor())

    result = analyze_run(fixture_run, _config(), kb=kb, ai_layer=layer)
    report = result.report

    assert report.ai.rejected_statements > 0
    assert "verworfen" in report.ai_note
    html = (fixture_run.report_dir / "bericht.html").read_text(encoding="utf-8")
    assert "Verworfen:" in html
    kb.close()


def test_zweiter_lauf_auf_demselben_verzeichnis_aendert_nichts(fixture_run) -> None:
    """analyze --run muss beliebig oft wiederholbar sein."""
    erste = analyze_run(fixture_run, _config(ai={"enabled": False}))
    zweite = analyze_run(fixture_run, _config(ai={"enabled": False}))

    assert [f.finding_id for f in erste.report.findings] == [
        f.finding_id for f in zweite.report.findings
    ]
    assert erste.enrichment.total_events == zweite.enrichment.total_events


def test_pseudonymisierte_fassung_trennt_bericht_und_zuordnung(fixture_run) -> None:
    from wineventai.analyze import redacted_report

    config = _config(ai={"enabled": False}, report={"redacted": True})
    result = analyze_run(fixture_run, config)
    redactor = Redactor(enabled=True)
    redactor.text("INTERN\\m.schmidt an 10.20.30.40")

    written = redacted_report(result.report, fixture_run, config, redactor)
    namen = [path.name for path in written]

    assert "bericht_pseudonymisiert.html" in namen
    assert "zuordnung.json" in namen, "die Zuordnungstabelle liegt separat"

    mapping = json.loads((fixture_run.report_dir / "zuordnung.json").read_text(encoding="utf-8"))
    assert any(key.startswith("BENUTZER_") for key in mapping)
