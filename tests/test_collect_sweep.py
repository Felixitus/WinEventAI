"""Error sweep at the process boundary - without Windows, without PowerShell.

``parse_sweep`` / ``build_sweep_results`` are tested with fixture lines and
``ErrorSweepCollector`` with a replaced ``run_script``. The core of the promise:
a channel the sweep did not reach never looks like a channel without hits.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from helpers import WINDOW_END, WINDOW_START, make_record, ndjson_line
from wineventai.collect import sweep as sweep_module
from wineventai.collect.base import INCONCLUSIVE, SourceStatus
from wineventai.collect.shell import ShellInfo, ShellRun
from wineventai.collect.sweep import (
    SUMMARY_SOURCE_ID,
    ErrorSweepCollector,
    build_sweep_results,
    parse_sweep,
)
from wineventai.config import Config, ErrorSweepConfig
from wineventai.config.loader import default_config_dict

SHELL = ShellInfo(executable="powershell", path=r"C:\fake\powershell.exe", major_version=5)


def plan_line(channels: list[str], **skipped: int) -> str:
    return json.dumps({"__plan": {"channels": channels, "skipped": skipped}})


def channel_line(name: str, records: int, exception: str | None = None) -> str:
    return json.dumps({"__channel": {"log": name, "records": records, "exception": exception}})


def final_line(records: int = 0, exception: str | None = None) -> str:
    return json.dumps(
        {"__status": {"log": "*", "records": records, "truncated": False, "exception": exception}}
    )


def error_line(channel: str, minutes_ago: int, event_id: int = 10) -> str:
    return ndjson_line(
        make_record(
            channel=channel,
            provider=f"Provider-{channel}",
            event_id=event_id,
            level=2,
            minutes_ago=minutes_ago,
        )
    )


def build(lines: list[str], *, keep: int = 100, timed_out: bool = False):
    parsed = parse_sweep(lines, keep_per_channel=keep)
    return build_sweep_results(
        parsed,
        levels=[1, 2],
        window_from_utc=WINDOW_START,
        window_to_utc=WINDOW_END,
        duration_seconds=1.0,
        timed_out=timed_out,
    )


def by_id(sources) -> dict[str, object]:
    return {item.result.source_id: item for item in sources}


NOT_FOUND = "System.Exception"
DENIED = "System.UnauthorizedAccessException"


def test_a_channel_with_hits_gets_its_own_row_with_its_records() -> None:
    lines = [
        plan_line(["A/Operational", "B/Operational"]),
        error_line("A/Operational", 5),
        error_line("A/Operational", 6),
        channel_line("A/Operational", 2),
        channel_line("B/Operational", 0, NOT_FOUND),
        final_line(2),
    ]
    sources = by_id(build(lines))

    hit = sources["sweep:A/Operational"]
    assert hit.result.status == SourceStatus.COLLECTED
    assert hit.result.records_read == 2
    assert len(hit.records) == 2
    assert all(record.source_ref == "A/Operational" for record in hit.records)


def test_channels_without_hits_are_counted_but_not_listed_individually() -> None:
    lines = [
        plan_line(["A", "B", "C"]),
        error_line("A", 1),
        channel_line("A", 1),
        channel_line("B", 0, NOT_FOUND),
        channel_line("C", 0),
        final_line(1),
    ]
    sources = by_id(build(lines))

    assert "sweep:B" not in sources
    assert "sweep:C" not in sources
    summary = sources[SUMMARY_SOURCE_ID].result
    assert summary.status == SourceStatus.COLLECTED
    assert "3 channels" in summary.note
    assert "2 without hits" in summary.note


def test_unreached_channels_make_the_sweep_incomplete_instead_of_empty() -> None:
    """Time limit after the first channel: B and C were never read."""
    lines = [
        plan_line(["A", "B", "C"]),
        channel_line("A", 0, NOT_FOUND),
    ]
    sources = by_id(build(lines, timed_out=True))

    summary = sources[SUMMARY_SOURCE_ID].result
    assert summary.status == SourceStatus.TIMED_OUT
    assert summary.status in INCONCLUSIVE
    assert "B, C" in summary.note
    assert "No statement is possible" in summary.note


def test_a_started_channel_without_closing_line_counts_as_timed_out() -> None:
    lines = [
        plan_line(["A"]),
        error_line("A", 1),
        error_line("A", 2),
    ]
    sources = by_id(build(lines, timed_out=True))

    partial = sources["sweep:A"]
    assert partial.result.status == SourceStatus.TIMED_OUT
    assert partial.result.records_read == 2
    assert "Further errors" in partial.result.note


def test_the_limit_caps_retention_but_not_the_count() -> None:
    lines = [plan_line(["A"])]
    lines += [error_line("A", minute) for minute in range(30)]
    lines += [channel_line("A", 30), final_line(30)]

    sources = by_id(build(lines, keep=10))

    item = sources["sweep:A"]
    assert item.result.records_read == 30, "everything is counted"
    assert item.result.records_retained == 10, "retained only up to the limit"
    assert item.result.status == SourceStatus.TRUNCATED
    assert sources[SUMMARY_SOURCE_ID].result.records_read == 30


def test_missing_rights_on_a_channel_show_up_as_a_row_of_its_own() -> None:
    lines = [
        plan_line(["Secret/Operational"]),
        channel_line("Secret/Operational", 0, DENIED),
        final_line(0),
    ]
    sources = by_id(build(lines))

    denied = sources["sweep:Secret/Operational"].result
    assert denied.status == SourceStatus.NO_PERMISSION
    assert "1 not fully collected" in sources[SUMMARY_SOURCE_ID].result.note


def test_without_a_channel_plan_nothing_is_said_about_individual_channels() -> None:
    sources = build([final_line(0, "System.InvalidOperationException")])

    assert len(sources) == 1
    summary = sources[0].result
    assert summary.source_id == SUMMARY_SOURCE_ID
    assert summary.status == SourceStatus.FAILED
    assert summary.status != SourceStatus.EMPTY


def test_without_a_channel_plan_and_with_time_limit_it_is_timed_out() -> None:
    sources = build([], timed_out=True)

    assert sources[0].result.status == SourceStatus.TIMED_OUT


def test_without_plan_and_without_status_line_it_is_a_failure_not_an_empty_sweep() -> None:
    sources = build([])

    assert sources[0].result.status == SourceStatus.FAILED


def test_an_empty_sweep_with_a_complete_plan_is_honestly_empty() -> None:
    lines = [plan_line(["A", "B"]), channel_line("A", 0), channel_line("B", 0), final_line(0)]

    summary = by_id(build(lines))[SUMMARY_SOURCE_ID].result

    assert summary.status == SourceStatus.EMPTY
    assert "Warnings and informational events" in summary.note


def test_channel_names_are_matched_case_insensitively() -> None:
    lines = [
        plan_line(["Microsoft-Windows-Foo/Operational"]),
        error_line("microsoft-windows-foo/operational", 1),
        channel_line("MICROSOFT-WINDOWS-FOO/OPERATIONAL", 1),
        final_line(1),
    ]
    sources = by_id(build(lines))

    item = sources["sweep:Microsoft-Windows-Foo/Operational"]
    assert item.result.status == SourceStatus.COLLECTED
    assert item.result.records_read == 1


def test_records_from_a_channel_outside_the_plan_are_not_hidden() -> None:
    lines = [
        plan_line(["A"]),
        channel_line("A", 0),
        error_line("Unexpected", 1),
        final_line(1),
    ]
    sources = by_id(build(lines))

    assert sources["sweep:Unexpected"].result.records_read == 1


def test_skipped_channels_appear_with_their_reason_in_the_summary() -> None:
    lines = [
        plan_line(["A"], disabled=120, type=40, excluded=7, empty=3, unreadable=2),
        channel_line("A", 0),
        final_line(0),
    ]
    note = by_id(build(lines))[SUMMARY_SOURCE_ID].result.note

    assert "120 disabled" in note
    assert "2 not readable" in note


def test_a_broken_line_is_skipped_not_raised() -> None:
    lines = [plan_line(["A"]), "{no json", error_line("A", 1), channel_line("A", 1)]

    parsed = parse_sweep(lines, keep_per_channel=10)

    assert parsed.parse_errors == 1
    assert parsed.tally("A").records_read == 1


def collector(**overrides: object) -> ErrorSweepCollector:
    fields: dict[str, object] = {
        "config": ErrorSweepConfig(),
        "configured_channels": ["System", "Application", "Security"],
        "shell": SHELL,
        "window_from_utc": WINDOW_START,
        "window_to_utc": WINDOW_END,
    }
    fields.update(overrides)
    return ErrorSweepCollector(**fields)  # type: ignore[arg-type]


def test_configured_channels_are_skipped_by_the_sweep() -> None:
    args = collector(config=ErrorSweepConfig(exclude=["Windows PowerShell"])).script_args()

    excluded = args[args.index("-Exclude") + 1].split("|")
    assert excluded == ["Application", "Security", "System", "Windows PowerShell"]


def test_levels_and_channel_types_reach_the_script_as_separated_lists() -> None:
    args = collector().script_args()

    assert args[args.index("-Levels") + 1] == "1|2"
    assert args[args.index("-LogTypes") + 1] == "Administrative|Operational"
    assert args[args.index("-StartUtc") + 1] == WINDOW_START.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_the_sweeps_own_time_window_only_shortens_the_sweep() -> None:
    args = collector(config=ErrorSweepConfig(days=1)).script_args()

    start = args[args.index("-StartUtc") + 1]
    assert start == "2026-09-09T12:00:00Z"


def test_a_disabled_sweep_is_disabled_and_not_empty() -> None:
    sources = collector(config=ErrorSweepConfig(enabled=False)).collect_many()

    assert [item.result.status for item in sources] == [SourceStatus.DISABLED]


def test_evtx_analysis_does_not_read_the_local_machine(monkeypatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("run_script must not be called offline")

    monkeypatch.setattr(sweep_module, "run_script", fail)
    sources = collector(offline=True).collect_many()

    assert sources[0].result.status == SourceStatus.NOT_AVAILABLE
    assert ".evtx" in sources[0].result.note


def test_without_powershell_the_sweep_failed() -> None:
    sources = collector(shell=None).collect_many()

    assert sources[0].result.status == SourceStatus.FAILED


def test_blocked_execution_is_reported_as_blocked(monkeypatch) -> None:
    def blocked(*_args, **_kwargs) -> ShellRun:
        return ShellRun(
            lines=[],
            returncode=1,
            stderr="CategoryInfo : SecurityError: (:) [], PSSecurityException",
            duration_seconds=0.2,
            timed_out=False,
        )

    monkeypatch.setattr(sweep_module, "run_script", blocked)
    sources = collector().collect_many()

    assert sources[0].result.status == SourceStatus.BLOCKED


def test_the_collector_passes_time_limit_and_stream_on_to_the_evaluation(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake(script: str, args: list[str], **kwargs: object) -> ShellRun:
        captured["script"] = script
        captured["timeout"] = kwargs["timeout_seconds"]
        return ShellRun(
            lines=[plan_line(["A", "B"]), error_line("A", 1)],
            returncode=-1,
            stderr="",
            duration_seconds=600.0,
            timed_out=True,
        )

    monkeypatch.setattr(sweep_module, "run_script", fake)
    sources = by_id(collector(config=ErrorSweepConfig(timeout_seconds=600)).collect_many())

    assert captured == {"script": "sweep_errors.ps1", "timeout": 600}
    assert sources[SUMMARY_SOURCE_ID].result.status == SourceStatus.TIMED_OUT
    assert sources["sweep:A"].result.status == SourceStatus.TIMED_OUT


def test_an_empty_level_list_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ErrorSweepConfig(levels=[])


def test_level_zero_is_not_a_severity_and_is_rejected() -> None:
    with pytest.raises(ValidationError):
        ErrorSweepConfig(levels=[0, 1])


def test_an_unknown_channel_type_is_rejected() -> None:
    """Localized type names ("Betriebsbereit") are caught here, not in the script."""
    with pytest.raises(ValidationError):
        ErrorSweepConfig(log_types=["Betriebsbereit"])


def test_the_bundled_configuration_sets_the_sweep_to_critical_and_error() -> None:
    config = Config.model_validate(default_config_dict())

    assert config.collect.error_sweep.enabled is True
    assert config.collect.error_sweep.levels == [1, 2]


def test_a_script_abort_without_time_limit_is_a_failure_not_a_timeout() -> None:
    lines = [plan_line(["A", "B"]), error_line("A", 1)]
    sources = by_id(build(lines, timed_out=False))

    summary = sources[SUMMARY_SOURCE_ID].result
    assert summary.status == SourceStatus.FAILED
    assert "script abort" in summary.note
    assert sources["sweep:A"].result.status == SourceStatus.FAILED
