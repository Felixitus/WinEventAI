"""Error sweep: every active channel, critical and error only.

Why this collector exists next to ``EventChannelCollector``:

* The configured core channels are read in full. Crashes of drivers and
  components, however, often land in one of the several hundred Operational
  channels nobody configures individually. Reading all of them in full would
  be slow and would drown the real errors in noise. Every channel is therefore
  read, but filtered server-side by the numeric level.
* ONE PowerShell process for all channels instead of one per channel. A process
  start costs roughly a second; with several hundred channels that would be
  most of the runtime. The price: one time limit covers the whole sweep. So
  that this does not silently swallow channels, the script first writes the
  plan (which channels it will read) and a closing line after each channel.
  Whatever is in the plan but has no closing line is "timed out" - not
  "no hits".
* Channels without hits get NO row of their own in the coverage table but are
  counted in one summary row. Hundreds of "no hits" rows would hide the one row
  that matters. Every channel with hits or with incomplete collection does get
  its own row.

The evaluation (``parse_sweep``, ``build_sweep_results``) only knows a line
iterator and is therefore testable without Windows.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..applog import get_log
from ..config import ErrorSweepConfig
from ..normalize.mapper import NormalizationError, record_from_line
from ..normalize.schema import EventRecord
from .base import CollectedSource, SourceResult, SourceStatus, status_for_exception
from .shell import LIST_SEPARATOR, STATUS_KEY, ShellInfo, run_script, status_from_stderr

SOURCE_TOOL = "powershell:get-winevent-sweep"
SOURCE_PREFIX = "sweep:"
SUMMARY_SOURCE_ID = "sweep:summary"

PLAN_KEY = "__plan"
CHANNEL_KEY = "__channel"

#: Rationale: see ``shell.LIST_SEPARATOR``.
ARG_SEPARATOR = LIST_SEPARATOR

#: Readable reasons why a channel never made it into the plan.
SKIP_REASONS: dict[str, str] = {
    "disabled": "disabled",
    "type": "other channel type",
    "excluded": "excluded",
    "empty": "empty",
    "unreadable": "not readable (usually missing admin rights)",
}


@dataclass(slots=True)
class ChannelTally:
    """What the sweep stream said about one channel."""

    name: str
    records: list[EventRecord] = field(default_factory=list)
    records_read: int = 0
    finished: bool = False
    exception_type: str | None = None
    error_id: str | None = None


@dataclass(slots=True)
class SweepParse:
    """Raw result of the sweep stream, not yet rated."""

    planned: list[str] | None = None
    skipped: dict[str, int] = field(default_factory=dict)
    channels: dict[str, ChannelTally] = field(default_factory=dict)
    final_status: dict[str, object] | None = None
    parse_errors: int = 0

    def tally(self, name: str) -> ChannelTally:
        """Returns the tally for a channel; case does not matter.

        Windows treats channel names case-insensitively. The name in the plan
        and the ``LogName`` on the event need not match character for character.
        """
        key = name.lower()
        entry = self.channels.get(key)
        if entry is None:
            entry = ChannelTally(name=name)
            self.channels[key] = entry
        return entry


def parse_sweep(lines: Iterable[str], *, keep_per_channel: int) -> SweepParse:
    """Reads the sweep stream: plan, records, channel closings, status line.

    ``keep_per_channel`` only limits retention. Every record is counted - the
    number in the coverage table is always the number read, not the number kept.
    """
    log = get_log()
    result = SweepParse()

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        head = line[:24]
        if PLAN_KEY in head or CHANNEL_KEY in head or STATUS_KEY in head:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                result.parse_errors += 1
                continue
            if isinstance(payload, dict) and _consume_control(payload, result):
                continue

        try:
            record = record_from_line(line, source_tool=SOURCE_TOOL, source_ref="")
        except NormalizationError as exc:
            result.parse_errors += 1
            if result.parse_errors <= 3:
                log.warn("Sweep line skipped", reason=str(exc))
            continue

        entry = result.tally(record.channel)
        record = record.model_copy(update={"source_ref": entry.name})
        entry.records_read += 1
        if len(entry.records) < keep_per_channel:
            entry.records.append(record)

    if result.parse_errors:
        log.warn("Unreadable sweep lines", count=result.parse_errors)
    return result


def _consume_control(payload: dict[str, object], result: SweepParse) -> bool:
    """Processes a control line. False if it was not one after all."""
    if PLAN_KEY in payload:
        plan = payload[PLAN_KEY]
        if isinstance(plan, dict):
            names = plan.get("channels") or []
            result.planned = [str(name) for name in names] if isinstance(names, list) else []
            # Create the tallies right away: then the plan decides the spelling
            # in the report, not whichever record happens to come first.
            for name in result.planned:
                result.tally(name)
            skipped = plan.get("skipped") or {}
            if isinstance(skipped, dict):
                result.skipped = {str(k): int(v) for k, v in skipped.items() if _is_int(v)}
        else:
            result.planned = []
        return True
    if CHANNEL_KEY in payload:
        done = payload[CHANNEL_KEY]
        if isinstance(done, dict) and done.get("log"):
            entry = result.tally(str(done["log"]))
            entry.finished = True
            exception = done.get("exception")
            entry.exception_type = str(exception) if exception else None
            error_id = done.get("error_id")
            entry.error_id = str(error_id) if error_id else None
        return True
    if STATUS_KEY in payload:
        status = payload[STATUS_KEY]
        result.final_status = status if isinstance(status, dict) else {}
        return True
    return False


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _channel_status(entry: ChannelTally, timed_out: bool) -> SourceStatus:
    """Status of a single sweep channel.

    A channel without a closing line is unfinished even if it already delivered
    records: nobody knows whether more would have followed.
    """
    if not entry.finished:
        return SourceStatus.TIMED_OUT if timed_out else SourceStatus.FAILED
    status = status_for_exception(entry.exception_type, entry.records_read, entry.error_id)
    if status == SourceStatus.COLLECTED and entry.records_read > len(entry.records):
        return SourceStatus.TRUNCATED
    return status


def build_sweep_results(
    parsed: SweepParse,
    *,
    levels: list[int],
    window_from_utc: datetime,
    window_to_utc: datetime,
    duration_seconds: float,
    timed_out: bool,
) -> list[CollectedSource]:
    """Rates the parsed stream and builds the report sources from it.

    Output order: the summary row first, then one entry for every channel with
    hits or with incomplete collection.
    """
    level_text = ", ".join(str(level) for level in levels)

    def base_result(source_id: str, status: SourceStatus, **fields: object) -> SourceResult:
        return SourceResult(
            source_id=source_id,
            status=status,
            requested_from_utc=window_from_utc,
            requested_to_utc=window_to_utc,
            **fields,
        )

    final_exception = None
    if parsed.final_status:
        value = parsed.final_status.get("exception")
        final_exception = str(value) if value else None

    if parsed.planned is None:
        # The script did not even get as far as the channel list. Without a plan
        # nothing can be said about individual channels - so no "no hits" either.
        if timed_out:
            status = SourceStatus.TIMED_OUT
        elif final_exception:
            status = status_for_exception(final_exception, 1)
        else:
            status = SourceStatus.FAILED
        return [
            CollectedSource(
                result=base_result(
                    SUMMARY_SOURCE_ID,
                    status,
                    duration_seconds=duration_seconds,
                    detail=final_exception,
                    note=(
                        "The channel list could not be determined. Nothing can be "
                        "said about the channels that are not configured."
                    ),
                )
            )
        ]

    # Channels that delivered records but were not in the plan are a
    # contradiction in the stream. They are shown anyway - discarding them would
    # mean hiding errors that were read.
    names = list(parsed.planned)
    planned_keys = {name.lower() for name in names}
    for key, entry in parsed.channels.items():
        if key not in planned_keys and entry.records_read:
            get_log().warn("Sweep channel outside the plan", channel=entry.name)
            # Outside the plan no closing line is to be expected.
            entry.finished = entry.finished or not timed_out
            names.append(entry.name)
            planned_keys.add(key)

    detailed: list[CollectedSource] = []
    empty = 0
    unreached: list[str] = []
    with_hits = 0
    incomplete = 0
    total_read = 0

    for name in names:
        entry = parsed.channels.get(name.lower()) or ChannelTally(name=name)
        if not entry.finished and entry.records_read == 0:
            unreached.append(entry.name)
            continue

        status = _channel_status(entry, timed_out)
        total_read += entry.records_read
        if status == SourceStatus.EMPTY:
            empty += 1
            continue
        if status in {SourceStatus.COLLECTED, SourceStatus.TRUNCATED}:
            with_hits += 1
        if status != SourceStatus.COLLECTED:
            incomplete += 1

        note = None
        if status == SourceStatus.FAILED and not entry.finished:
            note = (
                "The script aborted while this channel was being read. "
                "Further errors in this channel are possible."
            )
        elif status == SourceStatus.TIMED_OUT:
            note = (
                "The sweep time limit was reached while this channel was being read. "
                "Further errors in this channel are possible."
            )
        elif status == SourceStatus.TRUNCATED:
            note = (
                f"{entry.records_read} events counted, {len(entry.records)} retained. "
                "The count is complete, the raw data is not."
            )

        covered_from, covered_to = _covered(entry.records)
        detailed.append(
            CollectedSource(
                result=base_result(
                    f"{SOURCE_PREFIX}{entry.name}",
                    status,
                    covered_from_utc=covered_from,
                    covered_to_utc=covered_to,
                    records_read=entry.records_read,
                    records_retained=len(entry.records),
                    detail=entry.error_id or entry.exception_type,
                    note=note,
                ),
                records=entry.records,
            )
        )

    if unreached:
        incomplete += len(unreached)

    summary_parts = [
        f"{len(names)} channels checked at level {level_text}: "
        f"{with_hits} with hits, {empty} without hits, "
        f"{incomplete} not fully collected."
    ]
    if unreached:
        summary_parts.append(
            (
                "Not reached due to the time limit"
                if timed_out
                else "Not reached due to a script abort"
            )
            + f" ({len(unreached)}): "
            + ", ".join(unreached)
            + ". No statement is possible for these channels."
        )
    skipped = [
        f"{count} {SKIP_REASONS.get(reason, reason)}"
        for reason, count in sorted(parsed.skipped.items())
        if count
    ]
    if skipped:
        summary_parts.append("Not included in the sweep: " + ", ".join(skipped) + ".")
    summary_parts.append(
        "Warnings and informational events of these channels were not read."
    )

    if (unreached or not parsed.final_status) and timed_out:
        summary_status = SourceStatus.TIMED_OUT
    elif unreached or not parsed.final_status or final_exception:
        # Without a time limit and without a status line, the script crashed.
        summary_status = SourceStatus.FAILED
    elif total_read:
        summary_status = SourceStatus.COLLECTED
    else:
        summary_status = SourceStatus.EMPTY

    summary = CollectedSource(
        result=base_result(
            SUMMARY_SOURCE_ID,
            summary_status,
            records_read=total_read,
            records_retained=sum(item.result.records_retained for item in detailed),
            duration_seconds=duration_seconds,
            detail=final_exception,
            note=" ".join(summary_parts),
        )
    )
    return [summary, *detailed]


def _covered(records: list[EventRecord]) -> tuple[datetime | None, datetime | None]:
    if not records:
        return None, None
    stamps = [record.timestamp_utc for record in records]
    return min(stamps), max(stamps)


class ErrorSweepCollector:
    """Runs the error sweep live.

    Delivers several sources instead of one and therefore has ``collect_many``
    instead of ``collect``. Deliberately no support for .evtx exports: a sweep
    over "all channels" of another machine presupposes that machine's channel
    list, which an export does not contain. Reading the local machine instead
    would be a false attribution.
    """

    source_id = SUMMARY_SOURCE_ID

    def __init__(
        self,
        *,
        config: ErrorSweepConfig,
        configured_channels: list[str],
        shell: ShellInfo | None,
        window_from_utc: datetime,
        window_to_utc: datetime,
        offline: bool = False,
    ) -> None:
        self.config = config
        self.configured_channels = configured_channels
        self.shell = shell
        self.window_from = window_from_utc
        self.window_to = window_to_utc
        self.offline = offline

    def _window_from(self) -> datetime:
        if self.config.days:
            return max(self.window_from, self.window_to - timedelta(days=self.config.days))
        return self.window_from

    def _single(self, status: SourceStatus, note: str, detail: str | None = None) -> list[
        CollectedSource
    ]:
        return [
            CollectedSource(
                result=SourceResult(
                    source_id=SUMMARY_SOURCE_ID,
                    status=status,
                    requested_from_utc=self._window_from(),
                    requested_to_utc=self.window_to,
                    detail=detail,
                    note=note,
                )
            )
        ]

    def script_args(self) -> list[str]:
        """Arguments for ``sweep_errors.ps1``; separated out so it is testable."""
        window_from = self._window_from()
        args = [
            "-StartUtc", window_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "-EndUtc", self.window_to.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "-Levels", ARG_SEPARATOR.join(str(level) for level in self.config.levels),
            "-LogTypes", ARG_SEPARATOR.join(self.config.log_types),
        ]
        excluded = sorted(
            {name for name in [*self.configured_channels, *self.config.exclude] if name},
            key=str.lower,
        )
        if excluded:
            args += ["-Exclude", ARG_SEPARATOR.join(excluded)]
        return args

    def collect_many(self) -> list[CollectedSource]:
        if not self.config.enabled:
            return self._single(SourceStatus.DISABLED, "Disabled by configuration.")
        if self.offline:
            return self._single(
                SourceStatus.NOT_AVAILABLE,
                "Not possible when analyzing .evtx exports: the channel list of the "
                "source machine is not available.",
            )
        if self.shell is None:
            return self._single(
                SourceStatus.FAILED,
                "Event channels cannot be read without PowerShell.",
                detail="PowerShellNotFound",
            )

        run = run_script(
            "sweep_errors.ps1",
            self.script_args(),
            shell=self.shell,
            timeout_seconds=self.config.timeout_seconds,
        )
        blocked = status_from_stderr(run.stderr)
        if blocked is not None:
            get_log().warn("Error sweep blocked")
            return self._single(
                blocked,
                "Execution policy or permissions prevent the call.",
                detail="PowerShell execution refused",
            )

        parsed = parse_sweep(run.lines, keep_per_channel=self.config.max_retained_per_channel)
        return build_sweep_results(
            parsed,
            levels=self.config.levels,
            window_from_utc=self._window_from(),
            window_to_utc=self.window_to,
            duration_seconds=run.duration_seconds,
            timed_out=run.timed_out,
        )


__all__ = [
    "ErrorSweepCollector",
    "SUMMARY_SOURCE_ID",
    "build_sweep_results",
    "parse_sweep",
]
