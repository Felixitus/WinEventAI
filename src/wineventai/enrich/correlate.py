"""Time-window correlation around marker events.

Because the stream runs descending, "all events five minutes BEFORE the crash"
becomes forward buffering: the events we look for arrive AFTER the marker. One
open window per marker suffices; no look back over the whole history.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict

from ..normalize.schema import EventRecord

#: Events around which context is collected.
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
    """The events around one marker."""

    model_config = ConfigDict(extra="forbid")

    marker_provider: str
    marker_event_id: int
    marker_time_utc: datetime
    before: list[EventRecord] = []

    @property
    def key(self) -> str:
        return f"{self.marker_provider}:{self.marker_event_id}@{self.marker_time_utc.isoformat()}"


class ContextCollector:
    """Collects context around markers during the descending pass."""

    def __init__(self, *, window_minutes: int, max_events: int) -> None:
        self.window = timedelta(minutes=window_minutes)
        self.max_events = max_events
        self.windows: list[ContextWindow] = []
        self._open: list[tuple[ContextWindow, datetime]] = []

    def is_marker(self, record: EventRecord) -> bool:
        if (record.provider, record.event_id) in MARKER_KEYS:
            return True
        # A memory dump is an anchor point as well.
        return record.channel == "Minidump"

    def observe(self, record: EventRecord) -> bool:
        """Processes a record. Returns True if it is context of a marker."""
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
