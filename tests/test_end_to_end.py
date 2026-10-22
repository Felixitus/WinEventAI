"""End to end: run directory in, report out.

The AI layer is mocked. Two passes check the two states that really occur in
operation: with a reachable model and without one.
"""

from __future__ import annotations

import json

from test_ai import FakeClient, _fixture
from wineventai.ai.pipeline import AiLayer
from wineventai.ai.redaction import Redactor
from wineventai.analyze import REPORT_HTML, REPORT_JSON, REPORT_MARKDOWN, analyze_run
from wineventai.config import load_config
from wineventai.kb.store import KnowledgeBase


def _config(**overrides: object):
    base = {"rules": {"security_mode": True}}
    base.update(overrides)  # type: ignore[arg-type]
    return load_config(overrides=base)


def test_a_run_without_model_produces_a_complete_report(fixture_run) -> None:
    """The report must be complete even without a language model."""
    result = analyze_run(fixture_run, _config(ai={"enabled": False}))

    assert result.report.findings
    assert (fixture_run.report_dir / REPORT_HTML).is_file()
    assert (fixture_run.report_dir / REPORT_MARKDOWN).is_file()
    assert (fixture_run.report_dir / REPORT_JSON).is_file()
    assert fixture_run.unknown_ids_path.is_file()
    assert (fixture_run.derived_dir / "groups.json").is_file()
    assert (fixture_run.derived_dir / "findings.json").is_file()


def test_a_run_with_unreachable_ollama_still_produces_the_full_report(fixture_run) -> None:
    """The default case on a machine without Ollama: AI enabled, service down."""
    client = FakeClient([], reachable=False)
    layer = AiLayer(_config().ai, client=client, redactor=Redactor())

    result = analyze_run(fixture_run, _config(), ai_layer=layer)

    assert result.report.findings
    assert result.report.ai.used is False
    assert "rule engine" in result.report.ai_note
    assert client.calls == [], "no prompt may be sent when the model is unavailable"
    assert (fixture_run.report_dir / REPORT_HTML).is_file()


def test_bundles_are_stored_even_without_a_model(fixture_run) -> None:
    """Traceability does not depend on the model."""
    analyze_run(fixture_run, _config(ai={"enabled": False}))
    bundles = list(fixture_run.bundles_dir.glob("*.json"))
    assert bundles, "the bundles are created independently of the model"

    payload = json.loads(bundles[0].read_text(encoding="utf-8"))
    assert "citable_events" in payload
    assert "system_context" in payload


def test_a_run_with_model_writes_answer_and_verification_result(fixture_run) -> None:
    kb = KnowledgeBase.open_default()
    client = FakeClient([_fixture("explainer_good.json")] * 60)
    layer = AiLayer(_config().ai, client=client, kb=kb, redactor=Redactor())

    result = analyze_run(fixture_run, _config(), kb=kb, ai_layer=layer)

    assert result.report.ai.used is True
    assert result.report.ai.model == "test-model"
    answers = list(fixture_run.ai_dir.glob("*.json"))
    assert answers

    payload = json.loads(answers[0].read_text(encoding="utf-8"))
    assert "verification" in payload
    kb.close()


def test_invented_statements_end_up_visibly_in_the_report(fixture_run) -> None:
    """The verification must not reject silently - it has to show it."""
    kb = KnowledgeBase.open_default()
    client = FakeClient([_fixture("explainer_invented_id.json")] * 60)
    layer = AiLayer(_config().ai, client=client, kb=kb, redactor=Redactor())

    result = analyze_run(fixture_run, _config(), kb=kb, ai_layer=layer)
    report = result.report

    assert report.ai.rejected_statements > 0
    assert "rejected" in report.ai_note
    html = (fixture_run.report_dir / REPORT_HTML).read_text(encoding="utf-8")
    assert "Rejected:" in html
    kb.close()


def test_a_second_run_on_the_same_directory_changes_nothing(fixture_run) -> None:
    """analyze --run must be repeatable any number of times."""
    first = analyze_run(fixture_run, _config(ai={"enabled": False}))
    second = analyze_run(fixture_run, _config(ai={"enabled": False}))

    assert [f.finding_id for f in first.report.findings] == [
        f.finding_id for f in second.report.findings
    ]
    assert first.enrichment.total_events == second.enrichment.total_events


def test_the_pseudonymized_version_separates_report_and_mapping(fixture_run) -> None:
    from wineventai.analyze import redacted_report

    config = _config(ai={"enabled": False}, report={"redacted": True})
    result = analyze_run(fixture_run, config)
    redactor = Redactor(enabled=True)
    redactor.text("INTERN\\m.schmidt at 10.20.30.40")

    written = redacted_report(result.report, fixture_run, config, redactor)
    names = [path.name for path in written]

    assert "report_pseudonymized.html" in names
    assert "mapping.json" in names, "the mapping table is kept separately"

    mapping = json.loads((fixture_run.report_dir / "mapping.json").read_text(encoding="utf-8"))
    assert any(key.startswith("USER_") for key in mapping)
