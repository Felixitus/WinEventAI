"""Zeitfenster-Korrelation um Marker-Events.

Weil der Strom absteigend laeuft, wird "alle Events fuenf Minuten VOR dem
Absturz" zu einer Vorwaerts-Pufferung: Die gesuchten Events kommen NACH dem
Marker an. Ein offenes Fenster je Marker reicht, kein Rueckblick ueber die
gesamte Historie.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict

from ..normalize.schema import EventRecord

#: Ereignisse, um die herum Kontext eingesammelt wird.
MARKER_KEYS: frozenset[tuple[str, int]] = frozenset(
    {
        ("Microsoft-Windows-Kernel-Power", 41),
        ("EventLog", 6008),
        ("Microsoft-Windows-WER-SystemErrorReporting", 1001),
        ("BugCheck", 1001),
        ("Minidump", 0),
    }
)


class ContextWindow(BaseModel):
    """Die Ereignisse rund um einen Marker."""

    model_config = ConfigDict(extra="forbid")

    marker_provider: str
    marker_event_id: int
    marker_time_utc: datetime
    before: list[EventRecord] = []

    @property
    def key(self) -> str:
        return f"{self.marker_provider}:{self.marker_event_id}@{self.marker_time_utc.isoformat()}"


class ContextCollector:
    """Sammelt Kontext um Marker waehrend des absteigenden Durchlaufs."""

    def __init__(self, *, window_minutes: int, max_events: int) -> None:
        self.window = timedelta(minutes=window_minutes)
        self.max_events = max_events
        self.windows: list[ContextWindow] = []
        self._open: list[tuple[ContextWindow, datetime]] = []

    def is_marker(self, record: EventRecord) -> bool:
        if (record.provider, record.event_id) in MARKER_KEYS:
            return True
        # Ein Speicherabbild ist ebenfalls ein Ankerpunkt.
        return record.channel == "Minidump"

    def observe(self, record: EventRecord) -> bool:
        """Verarbeitet einen Record. Liefert True, wenn er Kontext eines Markers ist."""
        self._close_expired(record.timestamp_utc)

        is_context = False
        for window, deadline in self._open:
            if record.timestamp_utc >= deadline and len(window.before) < self.max_events:
                window.before.append(record)
                is_context = True

        if self.is_marker(record):
            window = ContextWindow(
                marker_provider=record.provider,
                marker_event_id=record.event_id,
                marker_time_utc=record.timestamp_utc,
            )
            self.windows.append(window)
            self._open.append((window, record.timestamp_utc - self.window))

        return is_context

    def _close_expired(self, now: datetime) -> None:
        self._open = [entry for entry in self._open if now >= entry[1]]

    def finish(self) -> list[ContextWindow]:
        self._open.clear()
        self.windows.sort(key=lambda window: window.marker_time_utc, reverse=True)
        return self.windows

    def window_for(self, provider: str, event_id: int, moment: datetime) -> ContextWindow | None:
        for window in self.windows:
            if (
                window.marker_provider == provider
                and window.marker_event_id == event_id
                and window.marker_time_utc == moment
            ):
                return window
        return None
