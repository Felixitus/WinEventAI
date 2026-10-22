"""Dienstsonde: Wie steht der Dienst, der laut Protokoll gestorben ist, jetzt da?

Der Dienstname kommt aus ``properties[0]`` von SCM 7031/7034/7000/7009 - und das
ist der ANZEIGENAME, nicht der Dienstname. Auf einem deutschen Windows steht
dort "Druckwarteschlange" und nicht "Spooler". Deshalb sucht das Skript ueber
DisplayName; wer hier auf den Dienstnamen filtert, findet ausserhalb englischer
Systeme nichts.

Dass die Gruppierung das mitmacht, ist kein Zufall: Der Fingerprint hasht den
maskierten Property-Vektor, und ein Dienstname ist weder Zahl noch Pfad noch
GUID - er ueberlebt die Maskierung. Zwei verschiedene Dienste ergeben deshalb
zwei Befunde, und jeder Befund hat genau einen Dienst.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..applog import get_log
from ..collect.shell import ShellInfo, join_list_arg
from .base import (
    ProbeBearing,
    ProbeResult,
    ProbeStatus,
    failed_result,
    timed_out_result,
)
from .shell import ProbePayloads, run_probe_script

if TYPE_CHECKING:  # pragma: no cover
    from ..rules.engine import Finding

PROBE_ID = "dienst"
TITLE = "Zustand des Dienstes"

#: SCM meldet den Anzeigenamen in der ersten Property - bei allen vier IDs.
SERVICE_EVENTS: frozenset[tuple[str, int]] = frozenset(
    {
        ("service control manager", 7000),
        ("service control manager", 7009),
        ("service control manager", 7031),
        ("service control manager", 7034),
        ("service control manager", 7024),
        ("service control manager", 7043),
    }
)

#: WMI liefert diese Bezeichner unuebersetzt; sie sind hier Schluessel, kein Text.
RUNNING = "running"
AUTO_START = {"auto", "automatic"}
DISABLED = "disabled"

STARTMODE_DE: dict[str, str] = {
    "auto": "Automatisch",
    "automatic": "Automatisch",
    "manual": "Manuell",
    "disabled": "Deaktiviert",
    "boot": "Systemstart",
    "system": "System",
}

STATE_DE: dict[str, str] = {
    "running": "laeuft",
    "stopped": "gestoppt",
    "paused": "angehalten",
    "start pending": "startet gerade",
    "stop pending": "stoppt gerade",
}


class ServiceProbe:
    """Fragt den aktuellen Zustand der Dienste ab, die in Befunden auftauchen."""

    probe_id = PROBE_ID
    title = TITLE

    def __init__(self, shell: ShellInfo, *, timeout_seconds: float = 25.0) -> None:
        self.shell = shell
        self.timeout_seconds = timeout_seconds

    def target_for(self, finding: Finding) -> str | None:
        if (finding.group.provider.lower(), finding.group.event_id) not in SERVICE_EVENTS:
            return None
        for sample in finding.group.samples:
            name = (sample.property_at(0) or "").strip()
            if name:
                return name
        return None

    def run(self, targets: dict[str, list[Finding]]) -> list[ProbeResult]:
        namen = sorted(targets)
        if not namen:
            return []

        args = ["-DisplayName", join_list_arg(namen)]
        run = run_probe_script(
            "probe_services.ps1", args, shell=self.shell, timeout_seconds=self.timeout_seconds
        )
        if run.timed_out:
            return [timed_out_result(PROBE_ID, TITLE, run.duration_seconds)]
        if run.payloads.exception or (run.returncode != 0 and not run.payloads.items):
            get_log().warn(
                "Dienstsonde fehlgeschlagen",
                ausnahme=run.payloads.exception,
                code=run.returncode,
            )
            return [
                failed_result(
                    PROBE_ID,
                    TITLE,
                    "Die Dienstliste liess sich nicht lesen.",
                    error=run.payloads.exception or run.stderr.strip()[:200] or None,
                )
            ]

        return interpret(run.payloads, namen, duration_seconds=run.duration_seconds)


def interpret(
    payloads: ProbePayloads, namen: list[str], *, duration_seconds: float = 0.0
) -> list[ProbeResult]:
    """Baut je angefragtem Dienst ein Ergebnis."""
    nach_name = {str(item.get("gesucht")): item for item in payloads.of_kind("dienst")}
    results: list[ProbeResult] = []

    for name in namen:
        item = nach_name.get(name)
        if item is None:
            results.append(
                ProbeResult(
                    probe_id=PROBE_ID,
                    title=TITLE,
                    status=ProbeStatus.UNAVAILABLE,
                    target=name,
                    summary=f"Zu '{name}' kam keine Antwort aus der Dienstabfrage.",
                    duration_seconds=duration_seconds,
                )
            )
            continue
        results.append(_one(name, item, duration_seconds))
    return results


def _one(name: str, item: dict[str, object], duration_seconds: float) -> ProbeResult:
    if not item.get("gefunden"):
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.NOT_APPLICABLE,
            target=name,
            summary=(
                f"Es gibt derzeit keinen Dienst mit dem Anzeigenamen '{name}'. "
                "Entweder wurde er entfernt oder umbenannt - oder der Name in der "
                "Ereignismeldung stammt aus einer anderen Sprachfassung."
            ),
            duration_seconds=duration_seconds,
        )

    zustand = str(item.get("zustand", "")).strip()
    starttyp = str(item.get("starttyp", "")).strip()
    zustand_key = zustand.lower()
    start_key = starttyp.lower()

    details = [
        f"Dienstname: {item.get('name')}",
        f"Zustand: {STATE_DE.get(zustand_key, zustand or 'unbekannt')}",
        f"Starttyp: {STARTMODE_DE.get(start_key, starttyp or 'unbekannt')}",
    ]
    if item.get("konto"):
        details.append(f"Konto: {item.get('konto')}")
    exit_code = item.get("exit_code")
    if isinstance(exit_code, int) and exit_code not in (0, 1077):
        # 1077 heisst "seit dem letzten Start nie versucht" - kein Fehler.
        details.append(f"Letzter Exit-Code: {exit_code}")

    if zustand_key == RUNNING:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.OK,
            bearing=ProbeBearing.WEAKENS,
            target=name,
            summary=f"'{name}' laeuft derzeit.",
            details=details,
            duration_seconds=duration_seconds,
        )

    if start_key == DISABLED:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target=name,
            summary=(
                f"'{name}' ist gestoppt und auf 'Deaktiviert' gesetzt. Dass jemand "
                "den Dienst abgeschaltet hat, ist selbst ein Befund - er kann nicht "
                "mehr von allein zurueckkommen."
            ),
            details=details,
            duration_seconds=duration_seconds,
        )

    if start_key in AUTO_START:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target=name,
            summary=(
                f"'{name}' ist auf automatischen Start gesetzt, laeuft aber nicht. "
                "Der Ausfall aus dem Protokoll besteht also fort."
            ),
            details=details,
            duration_seconds=duration_seconds,
        )

    return ProbeResult(
        probe_id=PROBE_ID,
        title=TITLE,
        status=ProbeStatus.OK,
        bearing=ProbeBearing.INCONCLUSIVE,
        target=name,
        summary=(
            f"'{name}' laeuft nicht, wird aber auch nicht automatisch gestartet. "
            "Das ist fuer sich genommen der vorgesehene Zustand."
        ),
        details=details,
        duration_seconds=duration_seconds,
    )
