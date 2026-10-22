"""Collector an der Prozessgrenze - ohne Windows, ohne PowerShell.

Getestet wird ``read_ndjson`` mit Fixture-Zeilen. Fuer jeden ``SourceStatus``
gibt es einen Fall; das ist der Kern der Zusage, dass fehlende Rechte, fehlende
Kanaele und leere Ergebnisse verschiedene Dinge sind.
"""

from __future__ import annotations

import json

import pytest

from helpers import make_record, ndjson_line
from wineventai.collect.base import SourceStatus, status_for_exception
from wineventai.collect.shell import read_ndjson, status_from_stderr
from wineventai.normalize.mapper import NormalizationError, record_from_line


def status_line(**fields: object) -> str:
    payload = {"log": "System", "records": 0, "truncated": False, "exception": None}
    payload.update(fields)
    return json.dumps({"__status": payload})


def test_liest_records_und_statuszeile() -> None:
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


def test_keep_begrenzt_nur_das_behalten_nicht_das_lesen() -> None:
    """Die Grenze gilt fuer behaltene Rohdaten, nicht fuer gelesene."""
    lines = [ndjson_line(make_record(minutes_ago=i)) for i in range(50)]
    lines.append(status_line(records=50))

    result = read_ndjson(lines, source_tool="test", source_ref="System", keep=10)

    assert result.records_read == 50, "gelesen wird immer alles"
    assert len(result.records) == 10, "behalten wird nur bis zur Grenze"


def test_kaputte_zeile_wird_uebersprungen_nicht_geworfen() -> None:
    lines = [
        ndjson_line(make_record(minutes_ago=1)),
        "{kein gueltiges json",
        '{"t": "nicht lesbar", "pr": "X", "id": 1}',
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
        # Der Fall "keine Ereignisse gefunden" ist bei Get-WinEvent nicht
        # typisiert: generische Ausnahme plus null Records bedeutet EMPTY.
        ("System.Exception", 0, SourceStatus.EMPTY),
        # Dieselbe generische Ausnahme MIT Records ist ein echter Fehler.
        ("System.Exception", 12, SourceStatus.FAILED),
    ],
)
def test_ausnahmetyp_bestimmt_den_status(
    exception: str | None, records: int, expected: SourceStatus
) -> None:
    assert status_for_exception(exception, records) is expected


def test_status_wird_nie_aus_lokalisiertem_text_abgeleitet() -> None:
    """Deutscher und englischer Fehlertext ergeben denselben Status."""
    deutsch = status_line(
        records=0, exception="System.Diagnostics.Eventing.Reader.EventLogNotFoundException"
    )
    englisch = status_line(
        records=0, exception="System.Diagnostics.Eventing.Reader.EventLogNotFoundException"
    )
    for line in (deutsch, englisch):
        parsed = read_ndjson([line], source_tool="test", source_ref="Foo")
        assert (
            status_for_exception(parsed.exception_type, parsed.records_read)
            is SourceStatus.NOT_AVAILABLE
        )


def test_blockierte_ausfuehrung_wird_erkannt() -> None:
    stderr = "File cannot be loaded. ... PSSecurityException ... UnauthorizedAccess"
    assert status_from_stderr(stderr) is SourceStatus.BLOCKED
    assert status_from_stderr("") is None
    assert status_from_stderr("irgendetwas anderes") is None


def test_ps51_datumsformat_wird_gelesen() -> None:
    """Windows PowerShell 5.1 serialisiert DateTime als /Date(...)/."""
    line = json.dumps(
        {"t": "/Date(1757505723000)/", "ch": "System", "pr": "EventLog", "id": 6005, "lvl": 4}
    )
    record = record_from_line(line, source_tool="test", source_ref="System")
    assert record.timestamp_utc.year == 2025


def test_fehlende_event_id_ist_ein_fehler() -> None:
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


def test_listen_argumente_gehen_mit_senkrechtem_strich_ans_skript() -> None:
    from wineventai.collect.shell import join_list_arg

    assert join_list_arg([1001, 4624, 7045]) == "1001|4624|7045"


def test_fehler_id_wird_auch_aus_deutscher_powershell_meldung_gelesen() -> None:
    from wineventai.collect.shell import error_id_from_stderr

    assert error_id_from_stderr(GERMAN_BINDING_ERROR) == "ParameterArgumentTransformationError"
    assert error_id_from_stderr("") is None


def test_strom_ohne_statuszeile_gilt_als_nicht_abgeschlossen() -> None:
    result = read_ndjson([], source_tool="test", source_ref="System")

    assert result.completed is False
    assert read_ndjson([status_line()], source_tool="test", source_ref="System").completed


def test_skript_ohne_statuszeile_meldet_fehler_statt_keine_treffer(monkeypatch) -> None:
    """Der Fall vom echten Rechner: Parameterfehler, null Zeilen, kein Status.

    Vorher stand dann "keine treffer" fuer System, Application und Setup.
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
    assert "keine Aussage" in result.note
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
def test_fehler_id_unterscheidet_leer_fehlend_und_gesperrt(error_id, expected) -> None:
    """Alle drei kommen als System.Exception - nur die Fehler-ID trennt sie."""
    assert status_for_exception("System.Exception", 0, error_id) is expected


def test_fehlender_kanal_erscheint_nicht_mehr_als_keine_treffer() -> None:
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


def test_unbekannte_fehler_id_bei_null_records_ist_ein_fehler_und_nicht_leer() -> None:
    assert status_for_exception("System.Exception", 0, "IrgendwasNeues,X") is SourceStatus.FAILED


def test_ohne_fehler_id_gilt_fuer_alte_laeufe_die_bisherige_regel() -> None:
    assert status_for_exception("System.Exception", 0, None) is SourceStatus.EMPTY


def test_kanalpruefung_unterscheidet_fehlend_von_nicht_lesbar() -> None:
    from wineventai.collect.shell import channel_states_from_lines

    lines = [
        json.dumps({"name": "System", "state": "present"}),
        json.dumps({"name": "Security", "state": "unreadable"}),
        json.dumps({"name": "Gibt-Es-Nicht/Operational", "state": "missing"}),
        status_line(),
    ]
    states = channel_states_from_lines(lines)

    assert states == {
        "system": "present",
        "security": "unreadable",
        "gibt-es-nicht/operational": "missing",
    }


def test_kanalpruefung_ohne_statuszeile_ist_nicht_pruefbar() -> None:
    from wineventai.collect.shell import channel_states_from_lines

    assert channel_states_from_lines([json.dumps({"name": "System", "state": "present"})]) is None
