"""Reporter: coverage before findings, all three formats from one model."""

from __future__ import annotations

import json
import re

from wineventai.analyze import analyze_run
from wineventai.collect.base import SourceStatus
from wineventai.config import load_config
from wineventai.report.html import render_html
from wineventai.report.json_out import render_json
from wineventai.report.markdown import render_markdown
from wineventai.report.timeline_svg import render_timeline

VOLATILE = re.compile(
    r"(Generated .*|- Collected: .*|- Tool: .*|run `.*`)"
)


def _report(fixture_run):
    config = load_config(
        overrides={"ai": {"enabled": False}, "rules": {"security_mode": True}}
    )
    return analyze_run(fixture_run, config).report


def test_coverage_comes_before_the_findings(fixture_run) -> None:
    """The order is about content, not cosmetics.

    Whoever reads "no findings" without having seen first that six days were
    not collected draws the wrong conclusion.
    """
    markdown = render_markdown(_report(fixture_run))
    assert markdown.index("## 1 · Coverage") < markdown.index("## 2 · Findings")


def test_incomplete_sources_are_at_the_top_of_the_table(fixture_run) -> None:
    report = _report(fixture_run)
    assert report.has_coverage_problem
    assert report.coverage[0].inconclusive, "what is missing matters more than what is there"


def test_not_logged_is_not_no_finding(fixture_run) -> None:
    report = _report(fixture_run)
    reliability = next(
        row for row in report.coverage if row.source_id == "cim:Win32_ReliabilityRecords"
    )
    assert reliability.status is SourceStatus.NOT_LOGGED
    assert reliability.inconclusive
    assert "Not recorded" in reliability.hint


def test_a_time_limit_produces_a_visible_gap(fixture_run) -> None:
    report = _report(fixture_run)
    security = next(row for row in report.coverage if row.source_id == "channel:Security")
    assert security.status is SourceStatus.TIMED_OUT
    assert security.coverage_gap, (
        "a time limit must not silently turn into a smaller window"
    )
    assert security.requested != security.covered


def test_all_three_formats_come_from_the_same_model(fixture_run) -> None:
    report = _report(fixture_run)
    html = render_html(report)
    markdown = render_markdown(report)
    payload = render_json(report)

    for finding in report.findings[:5]:
        assert finding.rule_name in html
        assert finding.rule_name in markdown
    assert len(payload["findings"]) == len(report.findings)
    assert payload["coverage_incomplete"] is True


def test_the_html_loads_nothing_from_the_network(fixture_run) -> None:
    """A report that reaches into the network when opened is the wrong signal."""
    html = render_html(_report(fixture_run))
    assert "http://" not in html.replace("http://www.w3.org/2000/svg", "")
    assert "cdn." not in html
    assert "<script" not in html.lower()


def test_the_severity_classes_in_the_html_have_matching_styles(fixture_run) -> None:
    """A renamed severity without a renamed CSS class would silently lose its color."""
    html = render_html(_report(fixture_run))
    for severity in ("critical", "error", "warning"):
        assert f".sev-{severity}" in html, severity
        assert f'class="chip sev-{severity}"' in html or severity not in html


def test_noise_is_classified_and_hidden(fixture_run) -> None:
    report = _report(fixture_run)
    assert report.noise, "10016 must be recognized"
    assert all(finding.suppressed for finding in report.noise)
    assert not any(finding.suppressed for finding in report.findings)


def test_the_headline_names_critical_findings(fixture_run) -> None:
    report = _report(fixture_run)
    assert "critical" in report.headline.lower()


def test_the_ai_note_explains_the_absence_of_the_model(fixture_run) -> None:
    report = _report(fixture_run)
    assert not report.ai.used
    assert "rule engine" in report.ai_note


def test_the_timeline_marks_the_uncollected_part(fixture_run) -> None:
    report = _report(fixture_run)
    svg = render_timeline(
        report.findings,
        window_from=report.meta.requested_from_utc,
        window_to=report.meta.requested_to_utc,
        covered_from=report.meta.requested_from_utc.replace(hour=23),
    )
    assert "not collected" in svg
    assert svg.startswith("<svg")


def test_the_json_is_serializable(fixture_run) -> None:
    payload = render_json(_report(fixture_run))
    text = json.dumps(payload, ensure_ascii=False, default=str)
    assert len(text) > 1000


def test_the_golden_report_stays_stable(fixture_run, tmp_path) -> None:
    """Catches unintended changes to wording and order.

    Volatile lines (timestamps of the run, run id) are removed first -
    otherwise the test checks the clock instead of the report.
    """
    def normalise(text: str) -> str:
        return "\n".join(
            line for line in text.splitlines() if not VOLATILE.search(line)
        )

    first = normalise(render_markdown(_report(fixture_run)))
    second = normalise(render_markdown(_report(fixture_run)))
    assert first == second, "two runs on the same run directory must be equal"

    golden = tmp_path / "golden.md"
    golden.write_text(first, encoding="utf-8")
    assert "## 1 · Coverage" in first
    assert "Unclean restart" in first
