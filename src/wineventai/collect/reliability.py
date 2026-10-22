"""Zuverlaessigkeitsverlauf ueber Win32_ReliabilityRecords.

Der entscheidende Punkt ist nicht das Auslesen, sondern die Unterscheidung:
Ist die Klasse leer, weil nichts passiert ist, oder weil der RACAgent-Task
deaktiviert ist? Auf Servern ist Letzteres der Regelfall. Das Skript meldet den
Task-Zustand mit; hier wird daraus ``NOT_LOGGED`` statt ``EMPTY``.
"""

from __future__ import annotations

from datetime import datetime

from ..config import CollectConfig
from .base import CollectedSource, SourceResult, SourceStatus, status_for_exception
from .shell import NdjsonResult, ShellInfo, read_ndjson, run_script, status_from_stderr

SOURCE_TOOL = "powershell:win32-reliabilityrecords"

#: Task-Zustaende, in denen der Zuverlaessigkeitsverlauf nicht gefuellt wird.
_INACTIVE_STATES = {"disabled", "nicht vorhanden", "unknown"}


class ReliabilityCollector:
    source_id = "cim:Win32_ReliabilityRecords"

    def __init__(
        self,
        *,
        config: CollectConfig,
        shell: ShellInfo,
        window_from_utc: datetime,
        window_to_utc: datetime,
    ) -> None:
        self.config = config
        self.shell = shell
        self.window_from = window_from_utc
        self.window_to = window_to_utc

    def collect(self) -> CollectedSource:
        if not self.config.reliability_records:
            return CollectedSource(
                result=SourceResult(
                    source_id=self.source_id,
                    status=SourceStatus.DISABLED,
                    requested_from_utc=self.window_from,
                    requested_to_utc=self.window_to,
                    note="Per Konfiguration abgeschaltet.",
                )
            )

        run = run_script(
            "get_reliability.ps1",
            [
                "-StartUtc",
                self.window_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "-MaxRecords",
                str(self.config.max_retained_per_channel),
            ],
            shell=self.shell,
            timeout_seconds=self.config.channel_timeout_seconds,
        )

        blocked = status_from_stderr(run.stderr)
        if blocked is not None:
            return CollectedSource(
                result=SourceResult(
                    source_id=self.source_id,
                    status=blocked,
                    requested_from_utc=self.window_from,
                    requested_to_utc=self.window_to,
                    duration_seconds=run.duration_seconds,
                )
            )

        parsed = read_ndjson(
            run.lines,
            source_tool=SOURCE_TOOL,
            source_ref="Reliability",
            keep=self.config.max_retained_per_channel,
        )
        return CollectedSource(
            result=build_reliability_result(
                parsed,
                self.window_from,
                self.window_to,
                run.duration_seconds,
                run.timed_out,
                self.source_id,
            ),
            records=parsed.records,
        )


def build_reliability_result(
    parsed: NdjsonResult,
    window_from: datetime,
    window_to: datetime,
    duration: float,
    timed_out: bool,
    source_id: str,
) -> SourceResult:
    """Erzeugt das ``SourceResult`` und wertet dabei den RACAgent-Zustand aus."""
    status = status_for_exception(parsed.exception_type, parsed.records_read, parsed.error_id)
    rac_state = str((parsed.status_line or {}).get("rac_state", "unbekannt")).strip().lower()
    note = None

    if status == SourceStatus.EMPTY and rac_state in _INACTIVE_STATES:
        status = SourceStatus.NOT_LOGGED
        note = (
            "Der Zuverlaessigkeitsverlauf wird auf diesem System nicht gefuehrt "
            f"(RacTask: {rac_state}). Das ist kein Befund, sondern eine Luecke."
        )
    elif status == SourceStatus.EMPTY:
        note = "Zuverlaessigkeitsverlauf aktiv, im Zeitfenster ohne Eintraege."

    if timed_out:
        status = SourceStatus.TIMED_OUT
    elif not parsed.completed:
        # Ohne Statuszeile ist das Skript nicht durchgelaufen; null Records
        # waeren sonst faelschlich "keine Treffer".
        status = SourceStatus.FAILED
        note = "Das Erhebungsskript hat keinen Abschlussstatus geliefert."

    stamps = [record.timestamp_utc for record in parsed.records]
    return SourceResult(
        source_id=source_id,
        status=status,
        requested_from_utc=window_from,
        requested_to_utc=window_to,
        covered_from_utc=min(stamps) if stamps else None,
        covered_to_utc=max(stamps) if stamps else None,
        records_read=parsed.records_read,
        records_retained=len(parsed.records),
        duration_seconds=duration,
        detail=parsed.exception_type,
        note=note,
    )
