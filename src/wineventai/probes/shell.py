"""Calling the probe scripts and reading their output.

The probes use the same path as the collector - a bundled ``.ps1`` via
``-File``, output as NDJSON - but not the same reader: ``read_ndjson`` in the
collector builds ``EventRecord`` objects, and a ping result is not an event.
Here the payload stays a ``dict``, so every probe can keep its own format.

The test boundary is the same as there: ``read_payloads`` only knows a line
iterator. That makes all probes testable without Windows, and the three
PowerShell scripts remain the only thing that can only be proven on the target
system.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..applog import get_log
from ..collect.shell import STATUS_KEY, ShellInfo, run_script

SCRIPT_FOLDER = "probes/scripts"


@dataclass(slots=True)
class ProbePayloads:
    """What a probe script delivered."""

    items: list[dict[str, object]] = field(default_factory=list)
    status: dict[str, object] | None = None
    parse_errors: int = 0

    @property
    def exception(self) -> str | None:
        """The .NET type name of an exception, if the script reported one.

        The *type name*, not the message: ``System.UnauthorizedAccessException``
        reads the same on a German Windows as on an English one.
        """
        if not self.status:
            return None
        value = self.status.get("exception")
        return str(value) if value else None

    def of_kind(self, kind: str) -> list[dict[str, object]]:
        return [item for item in self.items if item.get("kind") == kind]


def read_payloads(lines: Iterable[str]) -> ProbePayloads:
    """Reads the NDJSON lines of a probe script."""
    result = ProbePayloads()
    log = get_log()

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            result.parse_errors += 1
            continue
        if not isinstance(payload, dict):
            result.parse_errors += 1
            continue
        if STATUS_KEY in payload:
            status = payload[STATUS_KEY]
            result.status = status if isinstance(status, dict) else {}
            continue
        result.items.append(payload)

    if result.parse_errors:
        log.warn("Probe: unreadable lines", count=result.parse_errors)
    return result


@dataclass(slots=True)
class ProbeRun:
    """Result of a probe call including runtime."""

    payloads: ProbePayloads
    returncode: int
    stderr: str
    duration_seconds: float
    timed_out: bool


def run_probe_script(
    script: str,
    args: list[str],
    *,
    shell: ShellInfo,
    timeout_seconds: float,
) -> ProbeRun:
    """Runs a probe script and reads its output."""
    run = run_script(
        script,
        args,
        shell=shell,
        timeout_seconds=timeout_seconds,
        folder=SCRIPT_FOLDER,
    )
    return ProbeRun(
        payloads=read_payloads(run.lines),
        returncode=run.returncode,
        stderr=run.stderr,
        duration_seconds=run.duration_seconds,
        timed_out=run.timed_out,
    )
