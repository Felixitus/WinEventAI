"""Ueberwachungsrichtlinie pruefen - der Unterschied zwischen "kein Befund"
und "nicht protokolliert".

Ohne aktivierte Prozessverfolgung gibt es keine 4688. Ohne Script Block Logging
gibt es (von als verdaechtig eingestuften Bloecken abgesehen) keine 4104. Ein
Werkzeug, das daraus "unauffaellig" macht, ist gefaehrlicher als keines.

Ohne Adminrechte ist ``auditpol`` selbst nicht abfragbar. Dann lautet die
Antwort "Pruefstatus unbekannt" - nicht "aktiv".
"""

from __future__ import annotations

import shutil
import subprocess
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from ..applog import get_log


class PolicyState(StrEnum):
    ACTIVE = "aktiv"
    INACTIVE = "nicht aktiv"
    UNKNOWN = "unbekannt"


class PolicyCheck(BaseModel):
    """Ergebnis fuer eine Unterkategorie."""

    model_config = ConfigDict(extra="forbid")

    subcategory: str
    state: PolicyState
    affects_event_ids: list[int] = Field(default_factory=list)
    hint: str = ""


#: Unterkategorie -> Event-IDs, die ohne sie gar nicht entstehen.
SUBCATEGORY_EVENTS: dict[str, list[int]] = {
    "Process Creation": [4688],
    "Prozesserstellung": [4688],
    "Logon": [4624, 4625],
    "Anmelden": [4624, 4625],
    "Security Group Management": [4728, 4732],
    "Verwaltung von Sicherheitsgruppen": [4728, 4732],
    "User Account Management": [4720],
    "Benutzerkontenverwaltung": [4720],
    "Audit Policy Change": [4719],
    "Aenderung der Ueberwachungsrichtlinie": [4719],
    "Security System Extension": [4697],
    "Sicherheitssystemerweiterung": [4697],
}

#: Werte, die auditpol als "aus" ausgibt - beide Sprachfassungen.
_OFF_VALUES = {"no auditing", "keine ueberwachung", "keine überwachung", ""}


def parse_auditpol(output: str) -> dict[str, PolicyState]:
    """Wertet die CSV-Ausgabe von ``auditpol /get /category:* /r`` aus.

    Die Spaltenueberschriften sind lokalisiert; ausgewertet wird deshalb ueber
    die Position, nicht ueber den Namen. Unterkategorie ist Spalte 3,
    Einstellung die letzte.
    """
    states: dict[str, PolicyState] = {}
    for index, line in enumerate(output.splitlines()):
        if index == 0 or not line.strip():
            continue
        columns = [part.strip() for part in line.split(",")]
        if len(columns) < 4:
            continue
        subcategory = columns[2]
        setting = columns[-1].casefold()
        if not subcategory:
            continue
        states[subcategory] = (
            PolicyState.INACTIVE if setting in _OFF_VALUES else PolicyState.ACTIVE
        )
    return states


def query_audit_policy(*, is_admin: bool, timeout: float = 20.0) -> dict[str, PolicyState]:
    """Fragt die Ueberwachungsrichtlinie ab. Ohne Rechte: leeres Ergebnis."""
    if not is_admin:
        return {}
    executable = shutil.which("auditpol")
    if executable is None:
        return {}
    try:
        completed = subprocess.run(  # noqa: S603 - fester Systembefehl, keine Nutzereingabe
            [executable, "/get", "/category:*", "/r"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        get_log().warn("auditpol nicht abfragbar", grund=type(exc).__name__)
        return {}
    if completed.returncode != 0:
        return {}
    return parse_auditpol(completed.stdout)


def evaluate_policy(states: dict[str, PolicyState]) -> list[PolicyCheck]:
    """Bildet die Richtlinie auf die betroffenen Event-IDs ab."""
    checks: list[PolicyCheck] = []
    seen: set[tuple[int, ...]] = set()

    for subcategory, event_ids in SUBCATEGORY_EVENTS.items():
        key = tuple(sorted(event_ids))
        state = states.get(subcategory)
        if state is None:
            if key in seen:
                continue
            checks.append(
                PolicyCheck(
                    subcategory=subcategory,
                    state=PolicyState.UNKNOWN,
                    affects_event_ids=event_ids,
                    hint=(
                        "Pruefstatus unbekannt. Ohne Adminrechte laesst sich die "
                        "Ueberwachungsrichtlinie nicht abfragen; ein Fehlen dieser "
                        "Ereignisse ist deshalb NICHT als Unauffaelligkeit zu lesen."
                    ),
                )
            )
            seen.add(key)
            continue

        seen.add(key)
        checks.append(
            PolicyCheck(
                subcategory=subcategory,
                state=state,
                affects_event_ids=event_ids,
                hint=(
                    ""
                    if state is PolicyState.ACTIVE
                    else (
                        "Diese Unterkategorie wird nicht ueberwacht. Die betroffenen "
                        "Ereignisse entstehen auf diesem System gar nicht - "
                        "'nicht protokolliert', nicht 'kein Befund'."
                    )
                ),
            )
        )

    # Doppelte Sprachfassungen zusammenfassen: pro ID-Menge nur der beste Zustand.
    best: dict[tuple[int, ...], PolicyCheck] = {}
    order = {PolicyState.ACTIVE: 0, PolicyState.INACTIVE: 1, PolicyState.UNKNOWN: 2}
    for check in checks:
        key = tuple(sorted(check.affects_event_ids))
        current = best.get(key)
        if current is None or order[check.state] < order[current.state]:
            best[key] = check
    return sorted(best.values(), key=lambda check: check.affects_event_ids)


def not_logged_event_ids(checks: list[PolicyCheck]) -> set[int]:
    """Event-IDs, die auf diesem System nachweislich nicht entstehen."""
    out: set[int] = set()
    for check in checks:
        if check.state is PolicyState.INACTIVE:
            out.update(check.affects_event_ids)
    return out


def fix_suggestion(check: PolicyCheck) -> dict[str, str]:
    """Vorschlag, keine Aktion: Befehl, Wirkung, Risiko, Rueckbau."""
    return {
        "befehl": (
            f'auditpol /set /subcategory:"{check.subcategory}" '
            "/success:enable /failure:enable"
        ),
        "wirkung": (
            "Ab sofort entstehen Ereignisse "
            + ", ".join(str(value) for value in check.affects_event_ids)
            + "."
        ),
        "risiko": (
            "Das Sicherheitsprotokoll waechst deutlich schneller; auf Servern kann es "
            "schneller ueberlaufen. Ausserdem werden personenbezogene Daten "
            "protokolliert - vor dem Regelbetrieb mit Datenschutz und "
            "Arbeitnehmervertretung klaeren."
        ),
        "rueckbau": (
            f'auditpol /set /subcategory:"{check.subcategory}" /success:disable /failure:disable'
        ),
    }
