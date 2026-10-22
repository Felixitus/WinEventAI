"""Boot-Sessions aus den Protokollmarkern.

Marker:

* ``EventLog 6005``  - Protokolldienst gestartet, also Beginn einer Session
* ``EventLog 6006``  - Protokolldienst gestoppt, also sauberes Herunterfahren
* ``EventLog 6008``  - das VORIGE Herunterfahren war unerwartet
* ``Kernel-Power 41`` - System wurde ohne sauberes Herunterfahren neu gestartet

Der Strom laeuft absteigend, Sessions werden also rueckwaerts entdeckt.
Session 0 ist die neueste. ``clean_shutdown`` bleibt ``None``, wenn das
Zeitfenster den Uebergang gar nicht enthaelt - geraten wird nicht.
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
    """Ein Zeitraum zwischen zwei Startvorgaengen."""

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
            return "laufende Sitzung"
        return f"Sitzung -{self.index}"


class BootTracker:
    """Vergibt Session-Indizes waehrend des absteigenden Durchlaufs."""

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
        """Ordnet einen Record einer Session zu und wertet Marker aus."""
        session = self._session(self._current)
        session.event_count += 1
        if session.end_utc is None:
            session.end_utc = record.timestamp_utc

        key = (record.provider, record.event_id)

        if key in (UNEXPECTED_SHUTDOWN, KERNEL_POWER):
            # Diese Marker stehen beim Hochfahren und sagen etwas ueber die
            # VORIGE, also aeltere Sitzung aus.
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
        """Liefert die erkannten Sessions, neueste zuerst."""
        return [session for session in self.sessions if session.event_count > 0]
