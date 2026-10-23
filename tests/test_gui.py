"""User interface: models, status messages, detail text and worker.

Tested without a screen (``QT_QPA_PLATFORM=offscreen``) and without real
widgets where possible. The models live in a file of their own exactly for
this reason: they are the part of the interface that makes statements about
data - and that belongs tested.

The worker is called directly instead of via a thread. What matters here is
which signals arrive with which content, not whether Qt can do threads.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason='The user interface is optional (pip install -e ".[gui]")')

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from wineventai.analyze import analyze_run  # noqa: E402
from wineventai.config import load_config  # noqa: E402
from wineventai.gui import detail  # noqa: E402
from wineventai.gui.models import (  # noqa: E402
    CoverageModel,
    FindingsModel,
    UnknownEventsFilter,
    UnknownEventsModel,
    coverage_warning,
    summary_line,
)
from wineventai.gui.status import Environment  # noqa: E402
from wineventai.gui.worker import RunWorker  # noqa: E402


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    return QApplication.instance() or QApplication([])


@pytest.fixture
def report(fixture_run):
    config = load_config(overrides={"ai": {"enabled": False}, "rules": {"security_mode": True}})
    return analyze_run(fixture_run, config).report


# --- Models ------------------------------------------------------------------


def test_the_coverage_model_shows_incomplete_first(qapp, report) -> None:
    model = CoverageModel(report.coverage)
    assert model.rowCount() == len(report.coverage)

    first = model.row_at(0)
    assert first is not None and first.inconclusive, (
        "what is missing belongs at the top - otherwise someone reads past the gap"
    )


def test_the_coverage_model_colors_incomplete_rows(qapp, report) -> None:
    model = CoverageModel(report.coverage)
    index = model.index(0, 1)
    color = model.data(index, Qt.ItemDataRole.ForegroundRole)
    background = model.data(index, Qt.ItemDataRole.BackgroundRole)

    assert color is not None
    assert background is not None, "incomplete sources need a background"


def test_the_coverage_model_marks_the_gap(qapp, report) -> None:
    model = CoverageModel(report.coverage)
    texts = [
        model.data(model.index(row, CoverageModel.COL_COVERED), Qt.ItemDataRole.DisplayRole)
        for row in range(model.rowCount())
    ]
    assert any("[gap]" in text for text in texts)


def test_the_findings_model_maps_all_visible_findings(qapp, report) -> None:
    model = FindingsModel(report.findings)
    assert model.rowCount() == len(report.findings)
    assert model.columnCount() == 4


def test_the_findings_model_shows_the_provider_only_in_the_tooltip(qapp, report) -> None:
    """The list is for scanning.

    'Microsoft-Windows-WER-SystemErrorReporting:1001' in a column eats half the
    width and pushes away the finding name one is actually looking for.
    """
    model = FindingsModel(report.findings)
    cells = [
        model.data(model.index(row, column), Qt.ItemDataRole.DisplayRole)
        for row in range(model.rowCount())
        for column in range(model.columnCount())
    ]
    assert not any(":" in str(text) and "Microsoft-Windows" in str(text) for text in cells)

    tooltip = model.data(model.index(0, 1), Qt.ItemDataRole.ToolTipRole)
    assert ":" in tooltip


def test_the_findings_model_colors_by_severity(qapp, report) -> None:
    model = FindingsModel(report.findings)
    color = model.data(model.index(0, 0), Qt.ItemDataRole.ForegroundRole)
    assert color is not None
    assert color.name() == "#a52218", "critical must be red, not the accent color"


def test_the_findings_model_marks_escalation(qapp, report) -> None:
    model = FindingsModel(report.findings)
    texts = [
        model.data(model.index(row, 0), Qt.ItemDataRole.DisplayRole)
        for row in range(model.rowCount())
    ]
    assert any("↑" in text for text in texts), "an escalation must be visible"


def test_the_findings_model_reports_a_missing_knowledge_base_in_the_tooltip(qapp) -> None:
    from helpers import make_record
    from wineventai.enrich.aggregate import Enricher
    from wineventai.rules.engine import RuleEngine
    from wineventai.rules.loader import load_rules

    stream = [
        make_record(minutes_ago=1, provider="Microsoft-Windows-WHEA-Logger",
                    event_id=18, level=1, properties=["x"])
    ]
    findings = RuleEngine(load_rules()).evaluate(Enricher(window_hours=168).consume(stream))
    model = FindingsModel(findings)

    tooltip = model.data(model.index(0, 1), Qt.ItemDataRole.ToolTipRole)
    assert "No verified meaning" in tooltip


def test_an_empty_model_does_not_crash(qapp) -> None:
    model = FindingsModel()
    assert model.rowCount() == 0
    assert model.data(model.index(0, 0), Qt.ItemDataRole.DisplayRole) is None


# --- Headlines ---------------------------------------------------------------


def test_the_figures_line_names_reduction_and_noise(qapp, report) -> None:
    text = summary_line(report)
    assert "events" in text
    assert "reduction" in text
    assert "noise" in text


def test_the_warning_banner_appears_on_gaps(qapp, report) -> None:
    warning = coverage_warning(report)
    assert warning is not None
    assert "not collected completely" in warning
    assert "channel:Security" in warning


def test_the_warning_banner_stays_off_when_everything_was_collected(qapp, report) -> None:
    clean = report.model_copy(
        update={"coverage": [row for row in report.coverage if not row.inconclusive]}
    )
    assert coverage_warning(clean) is None


# --- Status bar --------------------------------------------------------------


def test_the_status_separates_service_and_model() -> None:
    """The same distinction as in the client - here only as display."""
    missing = Environment(
        model_name="qwen2.5:14b", ollama_reachable=True, ollama_model_present=False,
        ollama_models=["llama3.1:8b"],
    )
    text, problem = missing.ollama_line()
    assert problem and "missing" in text
    assert "No Ollama" not in text

    down = Environment(model_name="qwen2.5:14b", ollama_reachable=False)
    text, problem = down.ollama_line()
    assert problem and "No Ollama" in text
    assert "rule engine only" in text, "without Ollama the tool still works - say so"

    good = Environment(
        model_name="qwen2.5:14b", ollama_reachable=True, ollama_model_present=True
    )
    _, problem = good.ollama_line()
    assert not problem


def test_the_status_shows_a_refused_cloud_model() -> None:
    env = Environment(
        model_name="glm-5.2:cloud", ollama_reachable=True, ollama_model_present=True,
        ollama_remote_model=True,
    )
    text, problem = env.ollama_line()
    assert problem and "Cloud model" in text
    assert not env.ollama_usable
    assert "allow_cloud" in env.tooltip()


def test_the_status_knows_the_hard_blocker() -> None:
    assert not Environment().ready_to_collect
    assert Environment(powershell="C:/pwsh.exe").ready_to_collect


def test_the_tooltip_names_the_available_models() -> None:
    env = Environment(
        model_name="missing:latest", ollama_reachable=True, ollama_model_present=False,
        ollama_models=["a:1", "b:2"], config_path="C:/x.yaml",
    )
    tooltip = env.tooltip()
    assert "a:1, b:2" in tooltip
    assert "not present" in tooltip, "a missing configuration belongs in the tooltip"


# --- Detail view -------------------------------------------------------------


def test_the_detail_contains_meaning_and_checks(qapp, report) -> None:
    finding = report.findings[0]
    html = detail.finding_detail_html(finding)

    assert finding.rule_name in html
    assert str(finding.severity).upper() in html
    for check in finding.recommended_checks[:1]:
        assert check[:30] in html


def test_the_detail_marks_a_missing_knowledge_base(qapp, report) -> None:
    finding = report.findings[0].model_copy(update={"kb_confidence": "missing"})
    html = detail.finding_detail_html(finding)
    assert "No verified meaning" in html


def test_the_detail_shows_rejected_model_statements(qapp, fixture_run) -> None:
    """Rejecting must not happen silently - not in the interface either."""
    from test_ai import FakeClient, _fixture
    from wineventai.ai.pipeline import AiLayer
    from wineventai.ai.redaction import Redactor
    from wineventai.kb.store import KnowledgeBase

    config = load_config(overrides={"rules": {"security_mode": True}})
    kb = KnowledgeBase.open_default()
    layer = AiLayer(
        config.ai,
        client=FakeClient([_fixture("explainer_invented_id.json")] * 60),
        kb=kb,
        redactor=Redactor(),
    )
    result = analyze_run(fixture_run, config, kb=kb, ai_layer=layer)
    kb.close()

    pages = [
        detail.finding_detail_html(f, result.report.ai) for f in result.report.findings
    ]
    assert any("Rejected:" in html for html in pages)


def test_the_detail_escapes_html_in_messages(qapp, report) -> None:
    """A message from an event log is foreign text."""
    finding = report.findings[0].model_copy(
        update={"meaning": "<script>alert(1)</script> & more"}
    )
    html = detail.finding_detail_html(finding)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# --- Worker ------------------------------------------------------------------


def test_the_worker_analyzes_an_existing_run(qapp, fixture_run) -> None:
    config = load_config(overrides={"ai": {"enabled": False}})
    worker = RunWorker(config, existing_run=fixture_run.path)

    results: list[tuple[object, object]] = []
    errors: list[tuple[str, str]] = []
    progress: list[int] = []
    worker.finished_ok.connect(lambda run, res: results.append((run, res)))
    worker.failed.connect(lambda title, text: errors.append((title, text)))
    worker.progress.connect(lambda percent, _text: progress.append(percent))

    worker.run()

    assert not errors, errors
    assert len(results) == 1
    assert progress[-1] == 100
    assert results[0][1].report.findings


def test_the_worker_reports_errors_instead_of_raising(qapp, tmp_path) -> None:
    """An interface must never die without a word."""
    config = load_config(overrides={"ai": {"enabled": False}})
    worker = RunWorker(config, existing_run=tmp_path / "does-not-exist")

    errors: list[tuple[str, str]] = []
    worker.failed.connect(lambda title, text: errors.append((title, text)))
    worker.run()

    assert len(errors) == 1
    assert errors[0][0] == "Not found"


def test_the_worker_mirrors_the_application_log(qapp, fixture_run) -> None:
    config = load_config(overrides={"ai": {"enabled": False}})
    worker = RunWorker(config, existing_run=fixture_run.path)

    lines: list[str] = []
    worker.log_line.connect(lines.append)
    worker.run()

    assert lines, "during a long run it must be visible that something is happening"
    assert any("Rules loaded" in line for line in lines)


def test_the_log_stream_survives_the_death_of_its_worker(qapp, fixture_run) -> None:
    """The bug that only the test order brought to light.

    The application log is process-wide, but the log stream hangs on ONE
    worker. If that is collected and something still logs, Qt raised "Signal
    source has been deleted" - and tore down everything that followed. A logger
    must never kill the application.
    """
    from wineventai.gui.worker import GuiLogStream

    config = load_config(overrides={"ai": {"enabled": False}})
    worker = RunWorker(config, existing_run=fixture_run.path)
    stream = GuiLogStream(worker.log_line)

    del worker  # the owner of the signal is gone

    assert stream.write("must not raise") > 0
    stream.flush()


def test_the_worker_releases_the_process_wide_log(qapp, fixture_run) -> None:
    """After the run the global log must no longer point to the worker."""
    from wineventai.applog import get_log

    config = load_config(overrides={"ai": {"enabled": False}})
    worker = RunWorker(config, existing_run=fixture_run.path)
    worker.run()
    del worker

    get_log().info("after the run")  # does not raise any more


# --- Coverage note and events without assessment -----------------------------


def test_the_coverage_shows_the_note_visibly_and_not_only_in_the_tooltip(qapp, report) -> None:
    model = CoverageModel(report.coverage)
    noted = [row for row, item in enumerate(report.coverage) if item.note]
    assert noted, "the fixture needs at least one source with a note"

    row = noted[0]
    text = model.data(model.index(row, CoverageModel.COL_NOTE), Qt.ItemDataRole.DisplayRole)
    assert text == report.coverage[row].note.strip()


def test_coverage_without_a_note_shows_the_status_text_instead_of_an_empty_cell(
    qapp, report
) -> None:
    model = CoverageModel(report.coverage)
    for row in range(model.rowCount()):
        text = model.data(model.index(row, CoverageModel.COL_NOTE), Qt.ItemDataRole.DisplayRole)
        assert text, f"empty note cell in row {row}"


UNKNOWN_ROWS = [
    {"provider": "P-Info", "event_id": 1, "count": 500, "channel": "K", "level": 4,
     "sample_message": "information only"},
    {"provider": "P-Error", "event_id": 2, "count": 3, "channel": "K/Operational", "level": 2,
     "sample_message": "Error 0x80070005"},
    {"provider": "P-Critical", "event_id": 3, "count": 1, "channel": "K", "level": 1,
     "sample_message": "critical"},
]


def test_events_without_assessment_list_the_most_severe_level_first(qapp) -> None:
    model = UnknownEventsModel(UNKNOWN_ROWS)

    levels = [model.data(model.index(row, 0), Qt.ItemDataRole.DisplayRole)
              for row in range(model.rowCount())]
    assert levels == ["critical", "error", "information"]


def test_events_without_assessment_say_not_on_record_instead_of_staying_empty(qapp) -> None:
    model = UnknownEventsModel(UNKNOWN_ROWS)

    meaning = model.data(model.index(0, 5), Qt.ItemDataRole.DisplayRole)
    assert meaning == "not on record"


def test_the_filter_shows_only_critical_and_error_by_default(qapp) -> None:
    proxy = UnknownEventsFilter()
    proxy.setSourceModel(UnknownEventsModel(UNKNOWN_ROWS))

    assert proxy.rowCount() == 2
    proxy.set_only_errors(False)
    assert proxy.rowCount() == 3


def test_the_filter_also_searches_the_message(qapp) -> None:
    proxy = UnknownEventsFilter()
    proxy.setSourceModel(UnknownEventsModel(UNKNOWN_ROWS))
    proxy.set_text("0x80070005")

    assert proxy.rowCount() == 1


def test_the_main_window_fills_the_tab_without_assessment(qapp, fixture_run) -> None:
    from wineventai.gui.main_window import MainWindow

    config = load_config(overrides={"ai": {"enabled": False}})
    result = analyze_run(fixture_run, config)
    window = MainWindow(config)
    try:
        window._on_finished(fixture_run, result)
        title = window.tabs.tabText(MainWindow.UNKNOWN_TAB_INDEX)
        assert title == f"{MainWindow.UNKNOWN_TAB_TITLE} ({len(result.report.unknown_ids)})"
        assert window.unknown_model.rowCount() == len(result.report.unknown_ids)
    finally:
        if window._probe:
            window._probe.stop()
        window.close()


def test_the_program_icon_carries_a_small_and_a_large_size() -> None:
    """Windows picks the matching size; without 16 px it scales the 256 px image down to mush."""
    import struct

    from wineventai.gui.app import ICON_RESOURCE
    from wineventai.resources import resource_path

    data = resource_path(ICON_RESOURCE).read_bytes()
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    assert (reserved, kind) == (0, 1), "not an ICO file"
    edges = {struct.unpack_from("<B", data, 6 + 16 * index)[0] for index in range(count)}
    assert {16, 24, 32, 48}.issubset(edges)
    assert 0 in edges, "256 px is written as 0 in the ICO directory"


def test_the_window_gets_the_program_icon(qapp) -> None:
    from wineventai.gui.app import app_icon

    icon = app_icon()
    assert not icon.isNull()
    assert icon.availableSizes(), "the ICO must be readable by Qt"
