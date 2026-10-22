"""Helper functions for tests - building records without Windows and without files."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from wineventai.normalize.schema import EventRecord

FIXTURES = Path(__file__).parent / "fixtures"
WINDOW_END = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
WINDOW_START = WINDOW_END - timedelta(days=7)


def make_record(
    *,
    minutes_ago: int = 0,
    channel: str = "System",
    provider: str = "EventLog",
    event_id: int = 6005,
    level: int = 4,
    message: str = "Test message",
    properties: list[str | None] | None = None,
    computer: str = "WS-4711",
    user_sid: str | None = None,
    event_data: dict[str, str] | None = None,
) -> EventRecord:
    """Builds a record for tests - without file, without Windows."""
    return EventRecord(
        timestamp_utc=WINDOW_END - timedelta(minutes=minutes_ago),
        channel=channel,
        provider=provider,
        event_id=event_id,
        event_version=0,
        level=level,
        computer=computer,
        user_sid=user_sid,
        message=message,
        properties=properties or [],
        event_data=event_data,
        raw_hash=f"hash-{provider}-{event_id}-{minutes_ago}",
        source_tool="test",
        source_ref=channel,
    )


def ndjson_line(record: EventRecord) -> str:
    """Serializes a record the way the PowerShell script would."""
    return json.dumps(
        {
            "t": record.timestamp_utc.isoformat(),
            "ch": record.channel,
            "pr": record.provider,
            "id": record.event_id,
            "ver": record.event_version,
            "lvl": record.level,
            "cmp": record.computer,
            "sid": record.user_sid,
            "rec": record.record_id,
            "msg": record.message,
            "pv": record.properties,
        },
        ensure_ascii=False,
    )
