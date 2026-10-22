"""Gaps in the timeline of the logs.

An important restriction without which this check only produces false alarms:
a gap between a 6006 and the next 6005 is a switched-off machine, not a deleted
log. This check therefore works on the boot sessions and only reports gaps
WITHIN a running session.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict

from ..enrich.boot import BootSession
from ..normalize.schema import EventRecord


class TimelineGap(BaseModel):
    """A conspicuously event-free period within a session."""

    model_config = ConfigDict(extra="forbid")

    from_utc: datetime
    to_utc: datetime
    hours: float
    boot_session: int
    channel: str

    @property
    def description(self) -> str:
        return (
            f"{self.channel}: {self.hours:.1f} hours without any entry "
            f"({self.from_utc:%Y-%m-%d %H:%M} to {self.to_utc:%Y-%m-%d %H:%M} UTC), "
            f"within a running session."
        )


def find_gaps(
    records: list[EventRecord],
    sessions: list[BootSession],
    *,
    min_hours: float = 6.0,
    channels: tuple[str, ...] = ("Security", "System"),
) -> list[TimelineGap]:
    """Finds gaps within running sessions.

    ``records`` may arrive in any order; they are sorted ascending here,
    because a gap is a forward concept.
    """
    by_index = {session.index: session for session in sessions}
    gaps: list[TimelineGap] = []
    threshold = timedelta(hours=min_hours)

    for channel in channels:
        relevant = sorted(
            (record for record in records if record.channel == channel),
            key=lambda record: record.timestamp_utc,
        )
        for previous, current in zip(relevant, relevant[1:], strict=False):
            if previous.boot_session != current.boot_session:
                # Session change - the machine was off. Not a gap.
                continue
            session = by_index.get(previous.boot_session or 0)
            if session is not None and session.clean_shutdown is not None and (
                previous.boot_session != current.boot_session
            ):
                continue
            delta = current.timestamp_utc - previous.timestamp_utc
            if delta >= threshold:
                gaps.append(
                    TimelineGap(
                        from_utc=previous.timestamp_utc,
                        to_utc=current.timestamp_utc,
                        hours=delta.total_seconds() / 3600.0,
                        boot_session=previous.boot_session or 0,
                        channel=channel,
                    )
                )

    gaps.sort(key=lambda gap: -gap.hours)
    return gaps
