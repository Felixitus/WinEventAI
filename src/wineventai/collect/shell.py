"""PowerShell discovery, invocation and NDJSON processing.

The split in this file is the collector's test boundary: ``read_ndjson`` only
knows a line iterator and nothing about processes. Tests feed fixture files; in
production the lines come from PowerShell's ``stdout``. That makes the whole
collector testable without Windows.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ..applog import get_log
from ..normalize.mapper import NormalizationError, record_from_line
from ..normalize.schema import EventRecord
from ..resources import resource_path
from .base import SourceStatus

STATUS_KEY = "__status"

#: Separator for list arguments to every bundled script.
#: Via ``-File`` arguments arrive as strings. Passing "1001,4624,..." to an
#: ``[int[]]`` parameter fails under Windows PowerShell 5.1 with
#: ParameterArgumentTransformationError (observed on Windows 11); a
#: ``[string[]]`` parameter receives the whole list as ONE element. Every script
#: therefore takes lists as a single string and splits it itself. To current
#: knowledge the vertical bar does not occur in channel, role or service names
#: (unconfirmed for service display names).
LIST_SEPARATOR = "|"

_ERROR_ID = re.compile(r"FullyQualifiedErrorId\s*:\s*([^\s,]+)")


def join_list_arg(values: Iterable[object]) -> str:
    """Builds a list argument for a script."""
    return LIST_SEPARATOR.join(str(value) for value in values)


def error_id_from_stderr(stderr: str) -> str | None:
    """Extracts the FullyQualifiedErrorId from a PowerShell error message.

    The message itself is localized; the label ``FullyQualifiedErrorId`` and
    its value are not - even on a German Windows it reads
    ``ParameterArgumentTransformationError``.
    """
    if not stderr:
        return None
    match = _ERROR_ID.search(stderr)
    return match.group(1) if match else None


class PowerShellNotFoundError(RuntimeError):
    """Neither pwsh nor powershell on PATH."""


@dataclass(slots=True)
class ShellInfo:
    """Which PowerShell is used."""

    executable: str
    path: str
    major_version: int | None = None

    @property
    def is_core(self) -> bool:
        return Path(self.path).stem.lower() == "pwsh"


def find_powershell(preference: Iterable[str] = ("pwsh", "powershell")) -> ShellInfo:
    """Finds a usable PowerShell.

    ``pwsh`` is preferred but not required: every version difference that would
    affect us - DateTime serialization and output encoding - is already
    neutralized inside the scripts. That is why the choice here is one line and
    not a test matrix.
    """
    for name in preference:
        found = shutil.which(name)
        if found:
            return ShellInfo(executable=name, path=found)
    raise PowerShellNotFoundError(
        "No PowerShell found. Expected 'pwsh' or 'powershell' on PATH."
    )


@dataclass(slots=True)
class NdjsonResult:
    """What came out of reading an NDJSON stream."""

    records: list[EventRecord] = field(default_factory=list)
    records_read: int = 0
    status_line: dict[str, object] | None = None
    parse_errors: int = 0
    truncated: bool = False

    @property
    def completed(self) -> bool:
        """True if the script got as far as its status line.

        Without a status line the script crashed or never started (e.g. a
        parameter error). Zero records then do NOT mean "no hits" - exactly
        this confusion made System, Application and Setup look empty on a real
        machine.
        """
        return self.status_line is not None

    @property
    def error_id(self) -> str | None:
        """FullyQualifiedErrorId from the status line, if the script writes one."""
        if not self.status_line:
            return None
        value = self.status_line.get("error_id")
        return str(value) if value else None

    @property
    def exception_type(self) -> str | None:
        if not self.status_line:
            return None
        value = self.status_line.get("exception")
        return str(value) if value else None


def read_ndjson(
    lines: Iterable[str],
    *,
    source_tool: str,
    source_ref: str,
    keep: int | None = None,
    on_record: callable | None = None,
) -> NdjsonResult:
    """Reads an NDJSON stream into records plus the closing status line.

    ``keep`` only limits how many records are *retained*. Everything is always
    read and counted - that is the difference between a raw-data cap and a
    silently shrunken time window.
    """
    import json

    result = NdjsonResult()
    log = get_log()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if STATUS_KEY in line[:24]:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                result.parse_errors += 1
                continue
            if isinstance(payload, dict) and STATUS_KEY in payload:
                status = payload[STATUS_KEY]
                result.status_line = status if isinstance(status, dict) else {}
                result.truncated = bool(result.status_line.get("truncated"))
                continue
        try:
            record = record_from_line(line, source_tool=source_tool, source_ref=source_ref)
        except NormalizationError as exc:
            result.parse_errors += 1
            if result.parse_errors <= 3:
                log.warn("Line skipped", source=source_ref, reason=str(exc))
            continue

        result.records_read += 1
        if on_record is not None:
            on_record(record)
        if keep is None or len(result.records) < keep:
            result.records.append(record)

    if result.parse_errors:
        log.warn("Unreadable lines", source=source_ref, count=result.parse_errors)
    return result


@dataclass(slots=True)
class ShellRun:
    """Raw result of one PowerShell invocation."""

    lines: list[str]
    returncode: int
    stderr: str
    duration_seconds: float
    timed_out: bool


def run_script(
    script: str,
    args: list[str],
    *,
    shell: ShellInfo,
    timeout_seconds: float,
    folder: str = "collect/scripts",
) -> ShellRun:
    """Starts a bundled .ps1 and collects its NDJSON lines.

    Invoked via ``-File``, not ``-EncodedCommand``. Base64-encoded PowerShell is
    one of the most conspicuous EDR signatures there is - for a tool that reads
    security logs, the worst possible look.

    On timeout the process is killed but whatever was already read is kept: a
    hanging channel must not kill the run.
    """
    script_path = resource_path(f"{folder}/{script}")
    command = [
        shell.path,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        *args,
    ]

    started = time.monotonic()
    lines: list[str] = []
    timed_out = False
    stderr_text = ""

    process = subprocess.Popen(  # noqa: S603 - fixed interpreter, bundled script
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    try:
        assert process.stdout is not None
        for line in process.stdout:
            lines.append(line)
            if time.monotonic() - started > timeout_seconds:
                timed_out = True
                break
        if timed_out:
            process.kill()
        stderr_text = (process.stderr.read() if process.stderr else "") or ""
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - process does not respond
        process.kill()
        timed_out = True
    finally:
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()

    return ShellRun(
        lines=lines,
        returncode=process.returncode if process.returncode is not None else -1,
        stderr=stderr_text,
        duration_seconds=time.monotonic() - started,
        timed_out=timed_out,
    )


def status_from_stderr(stderr: str) -> SourceStatus | None:
    """Detects the few cases where PowerShell aborts before the script starts.

    Text *has* to be inspected here as an exception, because in these cases the
    script never runs and therefore cannot write a status line. The check is
    therefore against language-neutral parts - identifiers such as
    ``UnauthorizedAccess`` and ``PSSecurityException`` appear untranslated in
    the error id even on German systems.
    """
    if not stderr:
        return None
    lowered = stderr.lower()
    if "pssecurityexception" in lowered or "unauthorizedaccess" in lowered:
        return SourceStatus.BLOCKED
    if "executionpolicy" in lowered.replace(" ", ""):
        return SourceStatus.BLOCKED
    return None


#: States reported by ``list_channels.ps1`` and how ``doctor`` displays them.
CHANNEL_STATE_LABEL: dict[str, str] = {
    "present": "present",
    "missing": "MISSING",
    "unreadable": "present, not readable without admin rights",
    "error": "cannot be checked",
}


def channel_states_from_lines(lines: Iterable[str]) -> dict[str, str] | None:
    """Reads the output of ``list_channels.ps1``: channel name -> state.

    ``None`` means "cannot be checked" (the script did not reach its status
    line), not "no channel present". Keys are lower-case because Windows treats
    channel names case-insensitively.
    """
    import json

    states: dict[str, str] = {}
    completed = False
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        if STATUS_KEY in payload:
            completed = True
            continue
        name = payload.get("name")
        state = payload.get("state")
        if isinstance(name, str) and isinstance(state, str):
            states[name.lower()] = state if state in CHANNEL_STATE_LABEL else "error"
    return states if completed else None


def iter_file_lines(path: Path) -> Iterator[str]:
    """Line reader for NDJSON files in the run directory."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        yield from handle
