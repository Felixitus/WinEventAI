"""CBS.log, DISM.log and setupapi.dev.log - error lines only.

These files are hundreds of megabytes and 99 percent noise. They are read line
by line and only what matches an error pattern is kept. The patterns are
deliberately language-neutral: the markers in these logs are English, even on
German systems.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from ..normalize.schema import EventRecord
from .base import CollectedSource, SourceResult, SourceStatus

SOURCE_TOOL = "file:logline"

DEFAULT_LOG_FILES: dict[str, str] = {
    "CBS": r"C:\Windows\Logs\CBS\CBS.log",
    "DISM": r"C:\Windows\Logs\DISM\dism.log",
    "SetupAPI": r"C:\Windows\INF\setupapi.dev.log",
}

_ERROR_MARKER = re.compile(
    r"(?:\[SR\]\s+Cannot|\bError\b|\bFAILED\b|\bfailure\b|0x8[0-9A-Fa-f]{7}|!!!\s)",
)

# CBS and DISM: "2026-09-10 14:22:03, Error ..."
_TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")
# setupapi: ">>>  Section start 2026/09/10 14:22:03.123"
_TIMESTAMP_SLASH = re.compile(r"(\d{4}/\d{2}/\d{2})\s+(\d{2}:\d{2}:\d{2})")


def parse_line_timestamp(line: str, fallback: datetime) -> datetime:
    """Extracts the timestamp from a log line.

    These logs record local time without a zone. Lacking further knowledge it
    is interpreted as local time and converted to UTC - any other assumption
    would be a guess.
    """
    match = _TIMESTAMP.search(line) or _TIMESTAMP_SLASH.search(line)
    if not match:
        return fallback
    date_part = match.group(1).replace("/", "-")
    try:
        naive = datetime.fromisoformat(f"{date_part}T{match.group(2)}")
    except ValueError:
        return fallback
    return naive.astimezone().astimezone(UTC)


class LogFileCollector:
    """Extracts error lines from one of the known log files."""

    def __init__(
        self,
        *,
        name: str,
        path: str,
        enabled: bool,
        window_from_utc: datetime,
        window_to_utc: datetime,
        limit: int = 500,
    ) -> None:
        self.name = name
        self.path = Path(path)
        self.enabled = enabled
        self.window_from = window_from_utc
        self.window_to = window_to_utc
        self.limit = limit
        self.source_id = f"logfile:{name}"

    def collect(self) -> CollectedSource:
        base = SourceResult(
            source_id=self.source_id,
            requested_from_utc=self.window_from,
            requested_to_utc=self.window_to,
            status=SourceStatus.DISABLED,
        )
        if not self.enabled:
            return CollectedSource(result=base)
        if not self.path.is_file():
            return CollectedSource(
                result=base.model_copy(update={"status": SourceStatus.NOT_AVAILABLE})
            )

        records: list[EventRecord] = []
        read = 0
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    read += 1
                    if not _ERROR_MARKER.search(line):
                        continue
                    stamp = parse_line_timestamp(line, self.window_to)
                    if stamp < self.window_from:
                        continue
                    if len(records) >= self.limit:
                        continue
                    records.append(
                        EventRecord(
                            timestamp_utc=stamp,
                            channel=self.name,
                            provider=self.name,
                            event_id=0,
                            level=2,
                            message=line.strip()[:1000],
                            source_tool=SOURCE_TOOL,
                            source_ref=str(self.path),
                        )
                    )
        except PermissionError:
            return CollectedSource(
                result=base.model_copy(update={"status": SourceStatus.NO_PERMISSION})
            )
        except OSError as exc:
            return CollectedSource(
                result=base.model_copy(
                    update={"status": SourceStatus.FAILED, "detail": type(exc).__name__}
                )
            )

        stamps = [record.timestamp_utc for record in records]
        status = SourceStatus.COLLECTED if records else SourceStatus.EMPTY
        if len(records) >= self.limit:
            status = SourceStatus.TRUNCATED
        return CollectedSource(
            result=base.model_copy(
                update={
                    "status": status,
                    "records_read": read,
                    "records_retained": len(records),
                    "covered_from_utc": min(stamps) if stamps else None,
                    "covered_to_utc": max(stamps) if stamps else None,
                }
            ),
            records=records,
        )
