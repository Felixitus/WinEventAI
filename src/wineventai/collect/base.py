"""Gemeinsame Begriffe aller Collector.

``SourceStatus`` ist der wichtigste Typ dieser Datei. Er unterscheidet drei
Lagen, die im Bericht niemals gleich aussehen duerfen:

* ``EMPTY``          - erhoben, im Zeitfenster nichts gefunden. Das ist "kein Befund".
* ``NOT_LOGGED``     - Windows erhebt die Quelle auf diesem System gar nicht.
* ``NO_PERMISSION``  - die Quelle existiert, aber der Lauf hatte keine Rechte.

Wer diese drei zusammenwirft, produziert ein Werkzeug, das Schweigen als
Unbedenklichkeit meldet.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from ..normalize.schema import EventRecord


class SourceStatus(StrEnum):
    COLLECTED = "erhoben"
    EMPTY = "keine treffer"
    NOT_AVAILABLE = "kanal fehlt"
    NO_PERMISSION = "keine rechte"
    NOT_LOGGED = "nicht protokolliert"
    DISABLED = "abgeschaltet"
    TRUNCATED = "unvollstaendig"
    TIMED_OUT = "abgebrochen"
    BLOCKED = "blockiert"
    FAILED = "fehler"


#: Lagen, in denen "keine Befunde" eine falsche Aussage waere.
INCONCLUSIVE: frozenset[SourceStatus] = frozenset(
    {
        SourceStatus.NOT_AVAILABLE,
        SourceStatus.NO_PERMISSION,
        SourceStatus.NOT_LOGGED,
        SourceStatus.DISABLED,
        SourceStatus.TRUNCATED,
        SourceStatus.TIMED_OUT,
        SourceStatus.BLOCKED,
        SourceStatus.FAILED,
    }
)

STATUS_HINT_DE: dict[SourceStatus, str] = {
    SourceStatus.COLLECTED: "Vollstaendig erhoben.",
    SourceStatus.EMPTY: "Erhoben, im Zeitfenster ohne Treffer.",
    SourceStatus.NOT_AVAILABLE: "Kanal auf diesem System nicht vorhanden.",
    SourceStatus.NO_PERMISSION: "Keine Berechtigung. Mit Adminrechten wiederholen.",
    SourceStatus.NOT_LOGGED: "Wird auf diesem System nicht protokolliert - das ist kein Befund.",
    SourceStatus.DISABLED: "Per Konfiguration abgeschaltet.",
    SourceStatus.TRUNCATED: "Nur teilweise erhoben. Abgedeckter Zeitraum beachten.",
    SourceStatus.TIMED_OUT: "Zeitlimit erreicht. Abgedeckter Zeitraum beachten.",
    SourceStatus.BLOCKED: "Ausfuehrung blockiert, z.B. durch Ausfuehrungsrichtlinie.",
    SourceStatus.FAILED: "Erhebung fehlgeschlagen.",
}

#: Abbildung .NET-Ausnahmetyp -> Status. Bewusst ueber den TYPNAMEN, nie ueber
#: den Meldungstext: Fehlermeldungen von Get-WinEvent sind lokalisiert.
EXCEPTION_STATUS: dict[str, SourceStatus] = {
    "System.Diagnostics.Eventing.Reader.EventLogNotFoundException": SourceStatus.NOT_AVAILABLE,
    "System.Diagnostics.Eventing.Reader.EventLogException": SourceStatus.FAILED,
    "System.UnauthorizedAccessException": SourceStatus.NO_PERMISSION,
    "System.Security.SecurityException": SourceStatus.NO_PERMISSION,
    "System.IO.FileNotFoundException": SourceStatus.NOT_AVAILABLE,
    "System.IO.DirectoryNotFoundException": SourceStatus.NOT_AVAILABLE,
    "System.Management.ManagementException": SourceStatus.FAILED,
}


#: Abbildung FullyQualifiedErrorId -> Status. Get-WinEvent wirft fuer "keine
#: Ereignisse" UND fuer "Kanal gibt es nicht" dieselbe generische
#: ``System.Exception``; unterscheidbar sind beide nur ueber die
#: FullyQualifiedErrorId, die - anders als der Meldungstext - nicht
#: lokalisiert ist (Windows 11, de-AT, PowerShell 5.1 beobachtet). Verglichen
#: wird der Teil vor dem ersten Komma.
#:
#: Bekannte Falle: Der Security-Kanal OHNE Adminrechte liefert ebenfalls
#: ``NoMatchingEventsFound``. Fehlende Rechte sehen dort also aus wie "leer".
#: Deshalb prueft ``EventChannelCollector`` ``requires_admin`` VOR der Abfrage.
ERROR_ID_STATUS: dict[str, SourceStatus] = {
    "NoMatchingEventsFound": SourceStatus.EMPTY,
    "NoMatchingLogsFound": SourceStatus.NOT_AVAILABLE,
    "LogInfoUnavailable": SourceStatus.NO_PERMISSION,
}


def status_for_exception(
    exception_type: str | None, records: int, error_id: str | None = None
) -> SourceStatus:
    """Bildet Ausnahme-Typname und FullyQualifiedErrorId auf einen Status ab.

    Die Fehler-ID hat Vorrang, weil sie die genauere Aussage ist. Liegt eine
    Fehler-ID vor, die nicht bekannt ist, wird bei null Records NICHT mehr
    "keine Treffer" angenommen, sondern "Fehler": Die frueher geltende Regel
    "generische Ausnahme plus null Records heisst leer" hat auf einem echten
    Rechner einen fehlenden Kanal als leer gemeldet. Fehlt die Fehler-ID ganz
    (Laufverzeichnisse aelterer Versionen), gilt die alte Regel weiter.
    """
    if error_id:
        mapped_id = ERROR_ID_STATUS.get(error_id.split(",", 1)[0].strip())
        if mapped_id is not None:
            return mapped_id
    if not exception_type:
        return SourceStatus.COLLECTED if records else SourceStatus.EMPTY
    mapped = EXCEPTION_STATUS.get(exception_type)
    if mapped is not None:
        return mapped
    if error_id:
        return SourceStatus.FAILED
    return SourceStatus.EMPTY if records == 0 else SourceStatus.FAILED


class SourceResult(BaseModel):
    """Was ueber eine Quelle bekannt ist - unabhaengig davon, ob sie Daten lieferte."""

    model_config = ConfigDict(extra="forbid")

    source_id: str
    status: SourceStatus
    requested_from_utc: datetime | None = None
    requested_to_utc: datetime | None = None
    covered_from_utc: datetime | None = None
    covered_to_utc: datetime | None = None
    records_read: int = 0
    records_retained: int = 0
    duration_seconds: float = 0.0
    detail: str | None = None
    note: str | None = None

    @property
    def is_inconclusive(self) -> bool:
        return self.status in INCONCLUSIVE

    @property
    def coverage_gap(self) -> bool:
        """True, wenn der abgedeckte Zeitraum merklich hinter dem angeforderten bleibt.

        Genau das ist die Stelle, an der ein Zeitlimit sonst still zu einem
        verkleinerten Zeitfenster wuerde.
        """
        if self.requested_from_utc is None or self.covered_from_utc is None:
            return self.status in {SourceStatus.TRUNCATED, SourceStatus.TIMED_OUT}
        gap = (self.covered_from_utc - self.requested_from_utc).total_seconds()
        return gap > 3600.0

    def hint(self) -> str:
        return STATUS_HINT_DE.get(self.status, "")


class CollectedSource(BaseModel):
    """Ergebnis einer Erhebung inklusive der behaltenen Records."""

    model_config = ConfigDict(extra="forbid")

    result: SourceResult
    records: list[EventRecord] = []


class EventSource(Protocol):
    """Schnittstelle jedes Collectors.

    Kein Modul oberhalb dieser Schnittstelle darf wissen, dass unter ihr
    PowerShell laeuft. Das ist die Voraussetzung dafuer, das Backend spaeter
    gegen pywin32 tauschen zu koennen, ohne die Pipeline anzufassen.
    """

    source_id: str

    def collect(self) -> CollectedSource:
        """Erhebt die Quelle und liefert Status plus Records."""
        ...
