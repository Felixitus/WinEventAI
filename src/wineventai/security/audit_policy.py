"""Checking the audit policy - the difference between "no finding" and "not
logged".

Without process tracking enabled there is no 4688. Without script block
logging there is (apart from blocks rated as suspicious) no 4104. A tool that
turns this into "inconspicuous" is more dangerous than none.

Without admin rights ``auditpol`` itself cannot be queried. Then the answer is
"check state unknown" - not "active".

Known weakness (open item): subcategory names and the setting are matched as
text, in English and German. That is the one place in the code that relies on
localized output; a language-neutral variant would key on the subcategory GUID.
"""

from __future__ import annotations

import shutil
import subprocess
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from ..applog import get_log


class PolicyState(StrEnum):
    ACTIVE = "active"
    INACTIVE = "not active"
    UNKNOWN = "unknown"


class PolicyCheck(BaseModel):
    """Result for one subcategory."""

    model_config = ConfigDict(extra="forbid")

    subcategory: str
    state: PolicyState
    affects_event_ids: list[int] = Field(default_factory=list)
    hint: str = ""


#: Subcategory -> event ids that do not arise at all without it. The German
#: names are what auditpol prints on a German Windows.
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

#: Values auditpol prints for "off" - both language versions.
_OFF_VALUES = {"no auditing", "keine ueberwachung", "keine überwachung", ""}


def parse_auditpol(output: str) -> dict[str, PolicyState]:
    """Evaluates the CSV output of ``auditpol /get /category:* /r``.

    The column headings are localized; evaluation is therefore by position, not
    by name. Subcategory is column 3, the setting the last one.
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
    """Queries the audit policy. Without rights: empty result."""
    if not is_admin:
        return {}
    executable = shutil.which("auditpol")
    if executable is None:
        return {}
    try:
        completed = subprocess.run(  # noqa: S603 - fixed system command, no user input
            [executable, "/get", "/category:*", "/r"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        get_log().warn("auditpol not queryable", reason=type(exc).__name__)
        return {}
    if completed.returncode != 0:
        return {}
    return parse_auditpol(completed.stdout)


def evaluate_policy(states: dict[str, PolicyState]) -> list[PolicyCheck]:
    """Maps the policy onto the affected event ids."""
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
                        "Check state unknown. Without admin rights the audit policy "
                        "cannot be queried; the absence of these events must therefore "
                        "NOT be read as inconspicuousness."
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
                        "This subcategory is not audited. The affected events do not "
                        "arise on this system at all - 'not logged', not 'no finding'."
                    )
                ),
            )
        )

    # Merge duplicate language versions: only the best state per id set.
    best: dict[tuple[int, ...], PolicyCheck] = {}
    order = {PolicyState.ACTIVE: 0, PolicyState.INACTIVE: 1, PolicyState.UNKNOWN: 2}
    for check in checks:
        key = tuple(sorted(check.affects_event_ids))
        current = best.get(key)
        if current is None or order[check.state] < order[current.state]:
            best[key] = check
    return sorted(best.values(), key=lambda check: check.affects_event_ids)


def not_logged_event_ids(checks: list[PolicyCheck]) -> set[int]:
    """Event ids that demonstrably do not arise on this system."""
    out: set[int] = set()
    for check in checks:
        if check.state is PolicyState.INACTIVE:
            out.update(check.affects_event_ids)
    return out


def fix_suggestion(check: PolicyCheck) -> dict[str, str]:
    """A suggestion, not an action: command, effect, risk, rollback."""
    return {
        "command": (
            f'auditpol /set /subcategory:"{check.subcategory}" '
            "/success:enable /failure:enable"
        ),
        "effect": (
            "From now on events "
            + ", ".join(str(value) for value in check.affects_event_ids)
            + " are produced."
        ),
        "risk": (
            "The security log grows considerably faster; on servers it can overflow "
            "sooner. In addition, personal data is logged - clarify with data "
            "protection and the works council before regular operation."
        ),
        "rollback": (
            f'auditpol /set /subcategory:"{check.subcategory}" /success:disable /failure:disable'
        ),
    }
