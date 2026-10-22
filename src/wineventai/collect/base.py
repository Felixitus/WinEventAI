"""Shared vocabulary of all collectors.

``SourceStatus`` is the most important type in this file. It separates three
situations that must never look alike in the report:

* ``EMPTY``          - collected, nothing found in the window. That is "no finding".
* ``NOT_LOGGED``     - Windows does not record this source on this system at all.
* ``NO_PERMISSION``  - the source exists, but the run lacked the rights to read it.

A tool that lumps these together reports silence as all-clear.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from ..normalize.schema import EventRecord

#: Status values written by versions before 2.0, which used German labels.
#: Run directories from those versions must stay readable, so ``_missing_``
#: maps them onto the current members instead of failing validation.
_LEGACY_STATUS_VALUES: dict[str, str] = {
    "erhoben": "collected",
    "keine treffer": "no hits",
    "kanal fehlt": "not available",
    "keine rechte": "no permission",
    "nicht protokolliert": "not logged",
    "abgeschaltet": "disabled",
    "unvollstaendig": "incomplete",
    "abgebrochen": "timed out",
    "blockiert": "blocked",
    "fehler": "failed",
}


class SourceStatus(StrEnum):
    COLLECTED = "collected"
    EMPTY = "no hits"
    NOT_AVAILABLE = "not available"
    NO_PERMISSION = "no permission"
    NOT_LOGGED = "not logged"
    DISABLED = "disabled"
    TRUNCATED = "incomplete"
    TIMED_OUT = "timed out"
    BLOCKED = "blocked"
    FAILED = "failed"

    @classmethod
    def _missing_(cls, value: object) -> SourceStatus | None:
        if isinstance(value, str):
            current = _LEGACY_STATUS_VALUES.get(value.strip().lower())
            if current is not None:
                return cls(current)
        return None


#: Situations in which "no findings" would be a false statement.
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

STATUS_HINT: dict[SourceStatus, str] = {
    SourceStatus.COLLECTED: "Fully collected.",
    SourceStatus.EMPTY: "Collected, no hits in the time window.",
    SourceStatus.NOT_AVAILABLE: "Not present on this system.",
    SourceStatus.NO_PERMISSION: "No permission. Repeat with administrator rights.",
    SourceStatus.NOT_LOGGED: "Not recorded on this system - this is not a finding.",
    SourceStatus.DISABLED: "Disabled by configuration.",
    SourceStatus.TRUNCATED: "Only partially collected. Check the covered period.",
    SourceStatus.TIMED_OUT: "Time limit reached. Check the covered period.",
    SourceStatus.BLOCKED: "Execution blocked, e.g. by the execution policy.",
    SourceStatus.FAILED: "Collection failed.",
}

#: .NET exception type -> status. Deliberately keyed on the TYPE NAME, never on
#: the message text: Get-WinEvent error messages are localized.
EXCEPTION_STATUS: dict[str, SourceStatus] = {
    "System.Diagnostics.Eventing.Reader.EventLogNotFoundException": SourceStatus.NOT_AVAILABLE,
    "System.Diagnostics.Eventing.Reader.EventLogException": SourceStatus.FAILED,
    "System.UnauthorizedAccessException": SourceStatus.NO_PERMISSION,
    "System.Security.SecurityException": SourceStatus.NO_PERMISSION,
    "System.IO.FileNotFoundException": SourceStatus.NOT_AVAILABLE,
    "System.IO.DirectoryNotFoundException": SourceStatus.NOT_AVAILABLE,
    "System.Management.ManagementException": SourceStatus.FAILED,
}


#: FullyQualifiedErrorId -> status. Get-WinEvent throws the same generic
#: ``System.Exception`` for "no events" AND for "channel does not exist"; the two
#: can only be told apart by the FullyQualifiedErrorId, which - unlike the
#: message - is not localized (observed on Windows 11, de-AT, PowerShell 5.1).
#: The part before the first comma is compared.
#:
#: Known trap: the Security channel WITHOUT admin rights also yields
#: ``NoMatchingEventsFound``, so missing rights look like "empty" there. That
#: is why ``EventChannelCollector`` checks ``requires_admin`` BEFORE querying.
ERROR_ID_STATUS: dict[str, SourceStatus] = {
    "NoMatchingEventsFound": SourceStatus.EMPTY,
    "NoMatchingLogsFound": SourceStatus.NOT_AVAILABLE,
    "LogInfoUnavailable": SourceStatus.NO_PERMISSION,
}


def status_for_exception(
    exception_type: str | None, records: int, error_id: str | None = None
) -> SourceStatus:
    """Maps exception type name and FullyQualifiedErrorId onto a status.

    The error id wins because it is the more precise statement. If an error id
    is present but unknown, zero records are NOT read as "no hits" but as
    "failed": the earlier rule "generic exception plus zero records means
    empty" reported a missing channel as empty on a real machine. Without any
    error id (run directories of older versions) the old rule still applies.
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
    """What is known about a source - whether or not it delivered data."""

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
        """True if the covered period falls noticeably short of the requested one.

        This is exactly the spot where a time limit would otherwise silently
        turn into a smaller time window.
        """
        if self.requested_from_utc is None or self.covered_from_utc is None:
            return self.status in {SourceStatus.TRUNCATED, SourceStatus.TIMED_OUT}
        gap = (self.covered_from_utc - self.requested_from_utc).total_seconds()
        return gap > 3600.0

    def hint(self) -> str:
        return STATUS_HINT.get(self.status, "")


class CollectedSource(BaseModel):
    """Result of one collection including the retained records."""

    model_config = ConfigDict(extra="forbid")

    result: SourceResult
    records: list[EventRecord] = []


class EventSource(Protocol):
    """Interface of every collector.

    No module above this interface may know that PowerShell runs beneath it.
    That is the precondition for swapping the backend for pywin32 later without
    touching the pipeline.
    """

    source_id: str

    def collect(self) -> CollectedSource:
        """Collects the source and returns status plus records."""
        ...
