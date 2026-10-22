"""Collector at the process boundary - without Windows, without PowerShell.

``read_ndjson`` is tested with fixture lines. There is a case for every
``SourceStatus``; that is the core of the promise that missing rights, missing
channels and empty results are different things.
"""

from __future__ import annotations

import json

import pytest

from helpers import make_record, ndjson_line
from wineventai.collect.base import SourceResult, SourceStatus, status_for_exception
from wineventai.collect.shell import read_ndjson, status_from_stderr
from wineventai.normalize.mapper import NormalizationError, record_from_line


def status_line(**fields: object) -> str:
    payload = {"log": "System", "records": 0, "truncated": False, "exception": None}
    payload.update(fields)
    return json.dumps({"__status": payload})


def test_reads_records_and_the_status_line() -> None:
    lines = [
        ndjson_line(make_record(minutes_ago=1)),
        ndjson_line(make_record(minutes_ago=2, event_id=6006)),
        status_line(records=2),
    ]
    result = read_ndjson(lines, source_tool="test", source_ref="System")

    assert result.records_read == 2
    assert len(result.records) == 2
    assert result.exception_type is None
    assert result.status_line is not None


def test_keep_limits_only_retention_not_reading() -> None:
    """The limit applies to retained raw data, not to data read."""
    lines = [ndjson_line(make_record(minutes_ago=i)) for i in range(50)]
    lines.append(status_line(records=50))

    result = read_ndjson(lines, source_tool="test", source_ref="System", keep=10)

    assert result.records_read == 50, "everything is always read"
    assert len(result.records) == 10, "only retained up to the limit"


def test_a_broken_line_is_skipped_not_raised() -> None:
    lines = [
        ndjson_line(make_record(minutes_ago=1)),
        "{not valid json",
        '{"t": "not readable", "pr": "X", "id": 1}',
        status_line(records=1),
    ]
    result = read_ndjson(lines, source_tool="test", source_ref="System")

    assert result.records_read == 1
    assert result.parse_errors == 2


@pytest.mark.parametrize(
    ("exception", "records", "expected"),
    [
        (None, 5, SourceStatus.COLLECTED),
        (None, 0, SourceStatus.EMPTY),
        (
            "System.Diagnostics.Eventing.Reader.EventLogNotFoundException",
            0,
            SourceStatus.NOT_AVAILABLE,
        ),
        ("System.UnauthorizedAccessException", 0, SourceStatus.NO_PERMISSION),
        ("System.Security.SecurityException", 0, SourceStatus.NO_PERMISSION),
        # Without an error id (older run directories): a generic exception plus
        # zero records still counts as EMPTY.
        ("System.Exception", 0, SourceStatus.EMPTY),
        # The same generic exception WITH records is a real error.
        ("System.Exception", 12, SourceStatus.FAILED),
    ],
)
def test_the_exception_type_determines_the_status(
    exception: str | None, records: int, expected: SourceStatus
) -> None:
    assert status_for_exception(exception, records) is expected


def test_status_is_never_derived_from_localized_text() -> None:
    """German and English error text yield the same status."""
    german = status_line(
        records=0, exception="System.Diagnostics.Eventing.Reader.EventLogNotFoundException"
    )
    english = status_line(
        records=0, exception="System.Diagnostics.Eventing.Reader.EventLogNotFoundException"
    )
    for line in (german, english):
        parsed = read_ndjson([line], source_tool="test", source_ref="Foo")
        assert (
            status_for_exception(parsed.exception_type, parsed.records_read)
            is SourceStatus.NOT_AVAILABLE
        )


def test_blocked_execution_is_detected() -> None:
    stderr = "File cannot be loaded. ... PSSecurityException ... UnauthorizedAccess"
    assert status_from_stderr(stderr) is SourceStatus.BLOCKED
    assert status_from_stderr("") is None
    assert status_from_stderr("something else") is None


def test_the_ps51_date_format_is_read() -> None:
    """Windows PowerShell 5.1 serializes DateTime as /Date(...)/."""
    line = json.dumps(
        {"t": "/Date(1757505723000)/", "ch": "System", "pr": "EventLog", "id": 6005, "lvl": 4}
    )
    record = record_from_line(line, source_tool="test", source_ref="System")
    assert record.timestamp_utc.year == 2025


def test_a_missing_event_id_is_an_error() -> None:
    line = json.dumps({"t": "2026-09-10T12:00:00Z", "pr": "EventLog"})
    with pytest.raises(NormalizationError):
        record_from_line(line, source_tool="test", source_ref="System")


GERMAN_BINDING_ERROR = (
    'get_events.ps1 : Die Argumenttransformation fuer den Parameter "XmlForIds" kann nicht\n'
    "verarbeitet werden.\n"
    "    + CategoryInfo          : InvalidData: (:) [get_events.ps1], "
    "ParentContainsErrorRecordException\n"
    "    + FullyQualifiedErrorId : ParameterArgumentTransformationError,get_events.ps1\n"
)


def test_list_arguments_reach_the_script_separated_by_a_vertical_bar() -> None:
    from wineventai.collect.shell import join_list_arg

    assert join_list_arg([1001, 4624, 7045]) == "1001|4624|7045"


def test_the_error_id_is_read_even_from_a_german_powershell_message() -> None:
    from wineventai.collect.shell import error_id_from_stderr

    assert error_id_from_stderr(GERMAN_BINDING_ERROR) == "ParameterArgumentTransformationError"
    assert error_id_from_stderr("") is None


def test_a_stream_without_status_line_counts_as_unfinished() -> None:
    result = read_ndjson([], source_tool="test", source_ref="System")

    assert result.completed is False
    assert read_ndjson([status_line()], source_tool="test", source_ref="System").completed


def test_a_script_without_status_line_reports_failure_instead_of_no_hits(monkeypatch) -> None:
    """The case from the real machine: parameter error, zero lines, no status.

    Before, System, Application and Setup then said "no hits".
    """
    from helpers import WINDOW_END, WINDOW_START
    from wineventai.collect import eventlog
    from wineventai.collect.shell import ShellInfo, ShellRun
    from wineventai.config import ChannelConfig, CollectConfig

    captured: dict[str, list[str]] = {}

    def fake(script: str, args: list[str], **_kwargs: object) -> ShellRun:
        captured["args"] = args
        return ShellRun(
            lines=[], returncode=1, stderr=GERMAN_BINDING_ERROR,
            duration_seconds=0.5, timed_out=False,
        )

    monkeypatch.setattr(eventlog, "run_script", fake)
    collector = eventlog.EventChannelCollector(
        entry=ChannelConfig(name="System", event_ids=[41, 6008]),
        config=CollectConfig(xml_for=["Provider:1001", "Provider:4624"]),
        shell=ShellInfo(executable="powershell", path="powershell.exe"),
        window_from_utc=WINDOW_START,
        window_to_utc=WINDOW_END,
    )
    result = collector.collect().result

    assert result.status == SourceStatus.FAILED
    assert result.detail == "ParameterArgumentTransformationError"
    assert "Nothing can be said" in result.note
    args = captured["args"]
    assert args[args.index("-EventIds") + 1] == "41|6008"
    assert args[args.index("-XmlForIds") + 1] == "1001|4624"


@pytest.mark.parametrize(
    ("error_id", "expected"),
    [
        ("NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand",
         SourceStatus.EMPTY),
        ("NoMatchingLogsFound,Microsoft.PowerShell.Commands.GetWinEventCommand",
         SourceStatus.NOT_AVAILABLE),
        ("LogInfoUnavailable,Microsoft.PowerShell.Commands.GetWinEventCommand",
         SourceStatus.NO_PERMISSION),
    ],
)
def test_the_error_id_separates_empty_missing_and_locked(error_id, expected) -> None:
    """All three arrive as System.Exception - only the error id tells them apart."""
    assert status_for_exception("System.Exception", 0, error_id) is expected


def test_a_missing_channel_no_longer_shows_up_as_no_hits() -> None:
    lines = [
        json.dumps({"__status": {
            "log": "Microsoft-Windows-Kernel-Power/Operational", "records": 0,
            "truncated": False, "exception": "System.Exception",
            "error_id": "NoMatchingLogsFound,Microsoft.PowerShell.Commands.GetWinEventCommand",
        }}),
    ]
    parsed = read_ndjson(lines, source_tool="test", source_ref="x")

    status = status_for_exception(parsed.exception_type, parsed.records_read, parsed.error_id)
    assert status is SourceStatus.NOT_AVAILABLE


def test_an_unknown_error_id_with_zero_records_is_a_failure_not_empty() -> None:
    assert status_for_exception("System.Exception", 0, "SomethingNew,X") is SourceStatus.FAILED


def test_without_error_id_old_runs_keep_the_previous_rule() -> None:
    assert status_for_exception("System.Exception", 0, None) is SourceStatus.EMPTY


def test_status_values_of_older_german_run_directories_still_load() -> None:
    """Runs from before 2.0 stored German status labels in sources.json."""
    for legacy, current in (
        ("erhoben", SourceStatus.COLLECTED),
        ("keine treffer", SourceStatus.EMPTY),
        ("kanal fehlt", SourceStatus.NOT_AVAILABLE),
        ("abgebrochen", SourceStatus.TIMED_OUT),
    ):
        result = SourceResult.model_validate({"source_id": "channel:System", "status": legacy})
        assert result.status is current


def test_the_channel_check_separates_missing_from_unreadable() -> None:
    from wineventai.collect.shell import channel_states_from_lines

    lines = [
        json.dumps({"name": "System", "state": "present"}),
        json.dumps({"name": "Security", "state": "unreadable"}),
        json.dumps({"name": "Does-Not-Exist/Operational", "state": "missing"}),
        status_line(),
    ]
    states = channel_states_from_lines(lines)

    assert states == {
        "system": "present",
        "security": "unreadable",
        "does-not-exist/operational": "missing",
    }


def test_the_channel_check_without_status_line_cannot_be_checked() -> None:
    from wineventai.collect.shell import channel_states_from_lines

    assert channel_states_from_lines([json.dumps({"name": "System", "state": "present"})]) is None
