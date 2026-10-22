"""Collectors: gather raw records per source into a run directory."""

from .base import (
    EXCEPTION_STATUS,
    INCONCLUSIVE,
    STATUS_HINT,
    CollectedSource,
    EventSource,
    SourceResult,
    SourceStatus,
    status_for_exception,
)
from .eventlog import CachedChannelCollector, EventChannelCollector
from .rundir import RunDirectory, RunMeta, default_runs_root, is_admin, safe_name
from .runner import CollectionAborted, collect_all, load_records, window_for, write_records
from .shell import (
    NdjsonResult,
    PowerShellNotFoundError,
    ShellInfo,
    find_powershell,
    read_ndjson,
    status_from_stderr,
)

__all__ = [
    "EXCEPTION_STATUS",
    "INCONCLUSIVE",
    "STATUS_HINT",
    "CachedChannelCollector",
    "CollectedSource",
    "CollectionAborted",
    "EventChannelCollector",
    "EventSource",
    "NdjsonResult",
    "PowerShellNotFoundError",
    "RunDirectory",
    "RunMeta",
    "ShellInfo",
    "SourceResult",
    "SourceStatus",
    "collect_all",
    "default_runs_root",
    "find_powershell",
    "is_admin",
    "load_records",
    "read_ndjson",
    "safe_name",
    "status_for_exception",
    "status_from_stderr",
    "window_for",
    "write_records",
]
