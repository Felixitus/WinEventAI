"""Service probe: how does the service that died according to the log stand now?

The service name comes from ``properties[0]`` of SCM 7031/7034/7000/7009 - and
that is the DISPLAY NAME, not the service name. On a German Windows it says
"Druckwarteschlange" there, not "Spooler". The script therefore searches by
DisplayName; filtering by the service name finds nothing outside English
systems.

That the grouping plays along is no accident: the fingerprint hashes the
masked property vector, and a service name is neither number nor path nor
GUID - it survives the masking. Two different services therefore make two
findings, and every finding has exactly one service.
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

PROBE_ID = "service"
TITLE = "State of the service"

#: SCM reports the display name in the first property - for all these ids.
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

#: WMI delivers these identifiers untranslated; they are keys here, not text.
RUNNING = "running"
AUTO_START = {"auto", "automatic"}
DISABLED = "disabled"

STARTMODE_LABEL: dict[str, str] = {
    "auto": "Automatic",
    "automatic": "Automatic",
    "manual": "Manual",
    "disabled": "Disabled",
    "boot": "Boot",
    "system": "System",
}

STATE_LABEL: dict[str, str] = {
    "running": "running",
    "stopped": "stopped",
    "paused": "paused",
    "start pending": "starting",
    "stop pending": "stopping",
}


class ServiceProbe:
    """Queries the current state of the services that appear in findings."""

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
        names = sorted(targets)
        if not names:
            return []

        args = ["-DisplayName", join_list_arg(names)]
        run = run_probe_script(
            "probe_services.ps1", args, shell=self.shell, timeout_seconds=self.timeout_seconds
        )
        if run.timed_out:
            return [timed_out_result(PROBE_ID, TITLE, run.duration_seconds)]
        if run.payloads.exception or (run.returncode != 0 and not run.payloads.items):
            get_log().warn(
                "Service probe failed",
                exception=run.payloads.exception,
                code=run.returncode,
            )
            return [
                failed_result(
                    PROBE_ID,
                    TITLE,
                    "The service list could not be read.",
                    error=run.payloads.exception or run.stderr.strip()[:200] or None,
                )
            ]

        return interpret(run.payloads, names, duration_seconds=run.duration_seconds)


def interpret(
    payloads: ProbePayloads, names: list[str], *, duration_seconds: float = 0.0
) -> list[ProbeResult]:
    """Builds one result per requested service."""
    by_name = {str(item.get("searched")): item for item in payloads.of_kind("service")}
    results: list[ProbeResult] = []

    for name in names:
        item = by_name.get(name)
        if item is None:
            results.append(
                ProbeResult(
                    probe_id=PROBE_ID,
                    title=TITLE,
                    status=ProbeStatus.UNAVAILABLE,
                    target=name,
                    summary=f"The service query returned no answer for '{name}'.",
                    duration_seconds=duration_seconds,
                )
            )
            continue
        results.append(_one(name, item, duration_seconds))
    return results


def _one(name: str, item: dict[str, object], duration_seconds: float) -> ProbeResult:
    if not item.get("found"):
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.NOT_APPLICABLE,
            target=name,
            summary=(
                f"There is currently no service with the display name '{name}'. "
                "Either it was removed or renamed - or the name in the event message "
                "comes from a different language version."
            ),
            duration_seconds=duration_seconds,
        )

    state = str(item.get("state", "")).strip()
    start_mode = str(item.get("start_mode", "")).strip()
    state_key = state.lower()
    start_key = start_mode.lower()

    details = [
        f"Service name: {item.get('name')}",
        f"State: {STATE_LABEL.get(state_key, state or 'unknown')}",
        f"Start type: {STARTMODE_LABEL.get(start_key, start_mode or 'unknown')}",
    ]
    if item.get("account"):
        details.append(f"Account: {item.get('account')}")
    exit_code = item.get("exit_code")
    if isinstance(exit_code, int) and exit_code not in (0, 1077):
        # 1077 means "never attempted since the last start" - not an error.
        details.append(f"Last exit code: {exit_code}")

    if state_key == RUNNING:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.OK,
            bearing=ProbeBearing.WEAKENS,
            target=name,
            summary=f"'{name}' is currently running.",
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
                f"'{name}' is stopped and set to 'Disabled'. That someone switched the "
                "service off is a finding in itself - it cannot come back on its own."
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
                f"'{name}' is set to start automatically but is not running. "
                "The failure from the log therefore persists."
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
            f"'{name}' is not running, but it is not started automatically either. "
            "On its own that is the intended state."
        ),
        details=details,
        duration_seconds=duration_seconds,
    )
