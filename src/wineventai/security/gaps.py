"""Luecken in der Zeitachse der Protokolle.

Wichtige Einschraenkung, ohne die diese Pruefung nur Fehlalarme produziert:
Eine Luecke zwischen einem 6006 und dem naechsten 6005 ist ein ausgeschalteter
Rechner, kein geloeschtes Protokoll. Deshalb arbeitet diese Pruefung auf den
Boot-Sessions und meldet nur Luecken INNERHALB einer laufenden Sitzung.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict

from ..enrich.boot import BootSession
from ..normalize.schema import EventRecord


class TimelineGap(BaseModel):
    """Ein auffaellig ereignisloser Zeitraum innerhalb einer Sitzung."""

    model_config = ConfigDict(extra="forbid")

    from_utc: datetime
    to_utc: datetime
    hours: float
    boot_session: int
    channel: str

    @property
    def description(self) -> str:
        return (
            f"{self.channel}: {self.hours:.1f} Stunden ohne jeden Eintrag "
            f"({self.from_utc:%d.%m. %H:%M} bis {self.to_utc:%d.%m. %H:%M} UTC), "
            f"innerhalb einer laufenden Sitzung."
        )


def find_gaps(
    records: list[EventRecord],
    sessions: list[BootSession],
    *,
    min_hours: float = 6.0,
    channels: tuple[str, ...] = ("Security", "System"),
) -> list[TimelineGap]:
    """Findet Luecken innerhalb laufender Sitzungen.

    ``records`` darf in beliebiger Reihenfolge kommen; hier wird aufsteigend
    sortiert, weil eine Luecke ein Vorwaertsbegriff ist.
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
                # Sitzungswechsel - der Rechner war aus. Keine Luecke.
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
