"""Reliability history via Win32_ReliabilityRecords.

The crucial point is not reading it but telling apart: is the class empty
because nothing happened, or because the RACAgent task is disabled? On servers
the latter is the rule. The script reports the task state as well; here it
turns into ``NOT_LOGGED`` instead of ``EMPTY``.
"""

from __future__ import annotations

from datetime import datetime

from ..config import CollectConfig
from .base import CollectedSource, SourceResult, SourceStatus, status_for_exception
from .shell import NdjsonResult, ShellInfo, read_ndjson, run_script, status_from_stderr

SOURCE_TOOL = "powershell:win32-reliabilityrecords"

#: Task states in which the reliability history is not filled. The German
#: values are what scripts before version 2.0 wrote into run directories.
_INACTIVE_STATES = {"disabled", "not present", "unknown", "nicht vorhanden", "unbekannt"}


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
                    note="Disabled by configuration.",
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
    """Builds the ``SourceResult`` and evaluates the RACAgent state along the way."""
    status = status_for_exception(parsed.exception_type, parsed.records_read, parsed.error_id)
    rac_state = str((parsed.status_line or {}).get("rac_state", "unknown")).strip().lower()
    note = None

    if status == SourceStatus.EMPTY and rac_state in _INACTIVE_STATES:
        status = SourceStatus.NOT_LOGGED
        note = (
            "The reliability history is not kept on this system "
            f"(RacTask: {rac_state}). This is not a finding but a gap."
        )
    elif status == SourceStatus.EMPTY:
        note = "Reliability history active, no entries in the time window."

    if timed_out:
        status = SourceStatus.TIMED_OUT
    elif not parsed.completed:
        # Without a status line the script did not finish; zero records would
        # otherwise wrongly read as "no hits".
        status = SourceStatus.FAILED
        note = "The collection script returned no final status."

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
