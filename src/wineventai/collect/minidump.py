"""Minidumps: existence, timestamp, size. No parser.

A dump parser is explicitly a non-goal of version 1. The value here is high
anyway: a minidump with a matching timestamp next to a Kernel-Power 41 turns
"unclean restart" into "blue screen with a dump on disk".
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ..normalize.schema import EventRecord
from .base import CollectedSource, SourceResult, SourceStatus

DEFAULT_MINIDUMP_DIR = r"C:\Windows\Minidump"
SOURCE_TOOL = "file:minidump-listing"


class MinidumpCollector:
    source_id = "file:Minidump"

    def __init__(
        self,
        *,
        enabled: bool,
        window_from_utc: datetime,
        window_to_utc: datetime,
        directory: str = DEFAULT_MINIDUMP_DIR,
    ) -> None:
        self.enabled = enabled
        self.window_from = window_from_utc
        self.window_to = window_to_utc
        self.directory = Path(directory)

    def collect(self) -> CollectedSource:
        if not self.enabled:
            return CollectedSource(
                result=SourceResult(
                    source_id=self.source_id,
                    status=SourceStatus.DISABLED,
                    requested_from_utc=self.window_from,
                    requested_to_utc=self.window_to,
                )
            )
        if not self.directory.is_dir():
            return CollectedSource(
                result=SourceResult(
                    source_id=self.source_id,
                    status=SourceStatus.NOT_AVAILABLE,
                    requested_from_utc=self.window_from,
                    requested_to_utc=self.window_to,
                    note=(
                        "No minidump directory. This can mean: no crashes - "
                        "or dumps are disabled in the system settings."
                    ),
                )
            )

        records: list[EventRecord] = []
        read = 0
        try:
            entries = sorted(self.directory.glob("*.dmp"))
        except PermissionError:
            return CollectedSource(
                result=SourceResult(
                    source_id=self.source_id,
                    status=SourceStatus.NO_PERMISSION,
                    requested_from_utc=self.window_from,
                    requested_to_utc=self.window_to,
                )
            )

        for dump in entries:
            read += 1
            try:
                stat = dump.stat()
            except OSError:
                continue
            stamp = datetime.fromtimestamp(stat.st_mtime, tz=UTC)
            if stamp < self.window_from:
                continue
            records.append(
                EventRecord(
                    timestamp_utc=stamp,
                    channel="Minidump",
                    provider="Minidump",
                    event_id=0,
                    level=1,
                    message=(
                        f"Memory dump {dump.name} present, {stat.st_size} bytes. "
                        "Version 1 does not analyze its content."
                    ),
                    properties=[dump.name, str(stat.st_size)],
                    source_tool=SOURCE_TOOL,
                    source_ref=str(dump),
                )
            )

        stamps = [record.timestamp_utc for record in records]
        return CollectedSource(
            result=SourceResult(
                source_id=self.source_id,
                status=SourceStatus.COLLECTED if records else SourceStatus.EMPTY,
                requested_from_utc=self.window_from,
                requested_to_utc=self.window_to,
                covered_from_utc=min(stamps) if stamps else None,
                covered_to_utc=max(stamps) if stamps else None,
                records_read=read,
                records_retained=len(records),
            ),
            records=records,
        )
