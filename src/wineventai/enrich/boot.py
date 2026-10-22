"""Boot sessions from the log markers.

Markers:

* ``EventLog 6005``  - event log service started, i.e. a session begins
* ``EventLog 6006``  - event log service stopped, i.e. a clean shutdown
* ``EventLog 6008``  - the PREVIOUS shutdown was unexpected
* ``Kernel-Power 41`` - the system restarted without shutting down cleanly

The stream runs descending, so sessions are discovered backwards. Session 0 is
the newest. ``clean_shutdown`` stays ``None`` if the time window does not
contain the transition at all - nothing is guessed.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from ..normalize.schema import EventRecord

BOOT_START = ("EventLog", 6005)
BOOT_STOP = ("EventLog", 6006)
UNEXPECTED_SHUTDOWN = ("EventLog", 6008)
KERNEL_POWER = ("Microsoft-Windows-Kernel-Power", 41)


class BootSession(BaseModel):
    """A period between two boots."""

    model_config = ConfigDict(extra="forbid")

    index: int
    start_utc: datetime | None = None
    end_utc: datetime | None = None
    clean_shutdown: bool | None = None
    event_count: int = 0
    unexpected_marker_ids: list[int] = []

    @property
    def label(self) -> str:
        if self.index == 0:
            return "current session"
        return f"session -{self.index}"


class BootTracker:
    """Assigns session indices during the descending pass."""

    def __init__(self) -> None:
        self.sessions: list[BootSession] = [BootSession(index=0)]
        self._current = 0
        self._pending_unclean = False

    @property
    def current_index(self) -> int:
        return self._current

    def _session(self, index: int) -> BootSession:
        while len(self.sessions) <= index:
            self.sessions.append(BootSession(index=len(self.sessions)))
        return self.sessions[index]

    def observe(self, record: EventRecord) -> int:
        """Assigns a record to a session and evaluates markers."""
        session = self._session(self._current)
        session.event_count += 1
        if session.end_utc is None:
            session.end_utc = record.timestamp_utc

        key = (record.provider, record.event_id)

        if key in (UNEXPECTED_SHUTDOWN, KERNEL_POWER):
            # These markers appear at boot and say something about the
            # PREVIOUS, i.e. older, session.
            self._pending_unclean = True
            session.unexpected_marker_ids.append(record.event_id)

        if key == BOOT_START:
            session.start_utc = record.timestamp_utc
            self._current += 1
            older = self._session(self._current)
            if self._pending_unclean:
                older.clean_shutdown = False
                self._pending_unclean = False
            return session.index

        if key == BOOT_STOP:
            session.end_utc = record.timestamp_utc
            if session.clean_shutdown is None:
                session.clean_shutdown = True

        return session.index

    def finish(self) -> list[BootSession]:
        """Returns the detected sessions, newest first."""
        return [session for session in self.sessions if session.event_count > 0]
