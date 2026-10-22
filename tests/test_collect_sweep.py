"""Fehler-Sweep an der Prozessgrenze - ohne Windows, ohne PowerShell.

Getestet wird ``parse_sweep`` / ``build_sweep_results`` mit Fixture-Zeilen und
``ErrorSweepCollector`` mit ersetztem ``run_script``. Der Kern der Zusage: Ein
Kanal, den der Sweep nicht erreicht hat, sieht nie aus wie ein Kanal ohne
Treffer.
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


def test_kanal_mit_treffern_bekommt_eine_eigene_zeile_mit_seinen_records() -> None:
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


def test_kanaele_ohne_treffer_werden_gezaehlt_aber_nicht_einzeln_gelistet() -> None:
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
    assert "3 Kanaele" in summary.note
    assert "2 ohne Treffer" in summary.note


def test_nicht_erreichte_kanaele_machen_den_sweep_unvollstaendig_statt_leer() -> None:
    """Zeitlimit nach dem ersten Kanal: B und C wurden nie gelesen."""
    lines = [
        plan_line(["A", "B", "C"]),
        channel_line("A", 0, NOT_FOUND),
    ]
    sources = by_id(build(lines, timed_out=True))

    summary = sources[SUMMARY_SOURCE_ID].result
    assert summary.status == SourceStatus.TIMED_OUT
    assert summary.status in INCONCLUSIVE
    assert "B, C" in summary.note
    assert "keine Aussage" in summary.note


def test_angefangener_kanal_ohne_abschlusszeile_gilt_als_abgebrochen() -> None:
    lines = [
        plan_line(["A"]),
        error_line("A", 1),
        error_line("A", 2),
    ]
    sources = by_id(build(lines, timed_out=True))

    partial = sources["sweep:A"]
    assert partial.result.status == SourceStatus.TIMED_OUT
    assert partial.result.records_read == 2
    assert "Weitere Fehler" in partial.result.note


def test_grenze_begrenzt_das_behalten_aber_nicht_die_zaehlung() -> None:
    lines = [plan_line(["A"])]
    lines += [error_line("A", minute) for minute in range(30)]
    lines += [channel_line("A", 30), final_line(30)]

    sources = by_id(build(lines, keep=10))

    item = sources["sweep:A"]
    assert item.result.records_read == 30, "gezaehlt wird alles"
    assert item.result.records_retained == 10, "behalten nur bis zur Grenze"
    assert item.result.status == SourceStatus.TRUNCATED
    assert sources[SUMMARY_SOURCE_ID].result.records_read == 30


def test_fehlende_rechte_an_einem_kanal_erscheinen_als_eigene_zeile() -> None:
    lines = [
        plan_line(["Geheim/Operational"]),
        channel_line("Geheim/Operational", 0, DENIED),
        final_line(0),
    ]
    sources = by_id(build(lines))

    denied = sources["sweep:Geheim/Operational"].result
    assert denied.status == SourceStatus.NO_PERMISSION
    assert "1 nicht vollstaendig erhoben" in sources[SUMMARY_SOURCE_ID].result.note


def test_ohne_kanalplan_gibt_es_keine_aussage_ueber_einzelne_kanaele() -> None:
    sources = build([final_line(0, "System.InvalidOperationException")])

    assert len(sources) == 1
    summary = sources[0].result
    assert summary.source_id == SUMMARY_SOURCE_ID
    assert summary.status == SourceStatus.FAILED
    assert summary.status != SourceStatus.EMPTY


def test_ohne_kanalplan_und_mit_zeitlimit_heisst_es_abgebrochen() -> None:
    sources = build([], timed_out=True)

    assert sources[0].result.status == SourceStatus.TIMED_OUT


def test_ohne_kanalplan_und_ohne_statuszeile_ist_es_ein_fehler_kein_leerer_sweep() -> None:
    sources = build([])

    assert sources[0].result.status == SourceStatus.FAILED


def test_leerer_sweep_mit_vollstaendigem_plan_ist_ehrlich_leer() -> None:
    lines = [plan_line(["A", "B"]), channel_line("A", 0), channel_line("B", 0), final_line(0)]

    summary = by_id(build(lines))[SUMMARY_SOURCE_ID].result

    assert summary.status == SourceStatus.EMPTY
    assert "Warnungen und Informationsereignisse" in summary.note


def test_kanalnamen_werden_ohne_ruecksicht_auf_gross_kleinschreibung_zugeordnet() -> None:
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


def test_records_aus_einem_kanal_ausserhalb_des_plans_werden_nicht_verschwiegen() -> None:
    lines = [
        plan_line(["A"]),
        channel_line("A", 0),
        error_line("Unerwartet", 1),
        final_line(1),
    ]
    sources = by_id(build(lines))

    assert sources["sweep:Unerwartet"].result.records_read == 1


def test_uebersprungene_kanaele_stehen_mit_grund_in_der_uebersicht() -> None:
    lines = [
        plan_line(["A"], disabled=120, type=40, excluded=7, empty=3, unreadable=2),
        channel_line("A", 0),
        final_line(0),
    ]
    note = by_id(build(lines))[SUMMARY_SOURCE_ID].result.note

    assert "120 abgeschaltet" in note
    assert "2 nicht lesbar" in note


def test_kaputte_zeile_wird_uebersprungen_nicht_geworfen() -> None:
    lines = [plan_line(["A"]), "{kein json", error_line("A", 1), channel_line("A", 1)]

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


def test_konfigurierte_kanaele_werden_vom_sweep_ausgelassen() -> None:
    args = collector(config=ErrorSweepConfig(exclude=["Windows PowerShell"])).script_args()

    excluded = args[args.index("-Exclude") + 1].split("|")
    assert excluded == ["Application", "Security", "System", "Windows PowerShell"]


def test_level_und_kanaltypen_gehen_als_getrennte_liste_ans_skript() -> None:
    args = collector().script_args()

    assert args[args.index("-Levels") + 1] == "1|2"
    assert args[args.index("-LogTypes") + 1] == "Administrative|Operational"
    assert args[args.index("-StartUtc") + 1] == WINDOW_START.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_eigenes_zeitfenster_des_sweeps_verkuerzt_nur_den_sweep() -> None:
    args = collector(config=ErrorSweepConfig(days=1)).script_args()

    start = args[args.index("-StartUtc") + 1]
    assert start == "2026-09-09T12:00:00Z"


def test_abgeschalteter_sweep_ist_abgeschaltet_und_nicht_leer() -> None:
    sources = collector(config=ErrorSweepConfig(enabled=False)).collect_many()

    assert [item.result.status for item in sources] == [SourceStatus.DISABLED]


def test_bei_evtx_auswertung_wird_nicht_der_lokale_rechner_gelesen(monkeypatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("run_script darf offline nicht aufgerufen werden")

    monkeypatch.setattr(sweep_module, "run_script", fail)
    sources = collector(offline=True).collect_many()

    assert sources[0].result.status == SourceStatus.NOT_AVAILABLE
    assert ".evtx" in sources[0].result.note


def test_ohne_powershell_ist_der_sweep_fehlgeschlagen() -> None:
    sources = collector(shell=None).collect_many()

    assert sources[0].result.status == SourceStatus.FAILED


def test_blockierte_ausfuehrung_wird_als_blockiert_gemeldet(monkeypatch) -> None:
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


def test_collector_reicht_zeitlimit_und_strom_an_die_auswertung_weiter(monkeypatch) -> None:
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


def test_leere_levelliste_wird_abgelehnt() -> None:
    with pytest.raises(ValidationError):
        ErrorSweepConfig(levels=[])


def test_level_null_ist_kein_schweregrad_und_wird_abgelehnt() -> None:
    with pytest.raises(ValidationError):
        ErrorSweepConfig(levels=[0, 1])


def test_unbekannter_kanaltyp_wird_abgelehnt() -> None:
    """Lokalisierte Typnamen ("Betriebsbereit") fallen hier auf, nicht erst im Skript."""
    with pytest.raises(ValidationError):
        ErrorSweepConfig(log_types=["Betriebsbereit"])


def test_mitgelieferte_konfiguration_schaltet_den_sweep_auf_kritisch_und_fehler() -> None:
    config = Config.model_validate(default_config_dict())

    assert config.collect.error_sweep.enabled is True
    assert config.collect.error_sweep.levels == [1, 2]


def test_skriptabbruch_ohne_zeitlimit_ist_ein_fehler_kein_zeitlimit() -> None:
    lines = [plan_line(["A", "B"]), error_line("A", 1)]
    sources = by_id(build(lines, timed_out=False))

    summary = sources[SUMMARY_SOURCE_ID].result
    assert summary.status == SourceStatus.FAILED
    assert "Skriptabbruch" in summary.note
    assert sources["sweep:A"].result.status == SourceStatus.FAILED
