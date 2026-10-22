"""Aufruf der Sonden-Skripte und Lesen ihrer Ausgabe.

Die Sonden benutzen denselben Weg wie der Collector - ein mitgeliefertes ``.ps1``
ueber ``-File``, Ausgabe als NDJSON - aber nicht denselben Leser: ``read_ndjson``
im Collector baut ``EventRecord``-Objekte, und ein Ping-Ergebnis ist kein
Ereignis. Hier bleibt die Nutzlast ein ``dict``, damit jede Sonde ihr eigenes
Format behalten kann.

Die Testgrenze ist dieselbe wie dort: ``read_payloads`` kennt nur einen
Zeilen-Iterator. Damit sind alle Sonden ohne Windows testbar, und die drei
PowerShell-Skripte bleiben das einzige, was sich nur auf dem Zielsystem
beweisen laesst.
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
    """Was ein Sonden-Skript geliefert hat."""

    items: list[dict[str, object]] = field(default_factory=list)
    status: dict[str, object] | None = None
    parse_errors: int = 0

    @property
    def exception(self) -> str | None:
        """Der .NET-Typname einer Ausnahme, falls das Skript eine gemeldet hat.

        Der *Typname*, nicht die Meldung: ``System.UnauthorizedAccessException``
        steht auf einem deutschen Windows genauso da wie auf einem englischen.
        """
        if not self.status:
            return None
        value = self.status.get("exception")
        return str(value) if value else None

    def of_kind(self, kind: str) -> list[dict[str, object]]:
        return [item for item in self.items if item.get("kind") == kind]


def read_payloads(lines: Iterable[str]) -> ProbePayloads:
    """Liest NDJSON-Zeilen eines Sonden-Skripts."""
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
        log.warn("Sonde: nicht lesbare Zeilen", anzahl=result.parse_errors)
    return result


@dataclass(slots=True)
class ProbeRun:
    """Ergebnis eines Sonden-Aufrufs samt Laufzeit."""

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
    """Fuehrt ein Sonden-Skript aus und liest dessen Ausgabe."""
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
