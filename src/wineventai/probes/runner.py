"""Running the probes and assigning the results to the findings.

This runner decides three things, and all three matter more than the
measurement itself:

**Whether measuring is allowed at all.** The analysis runs on a run directory,
not on a machine. Whoever analyzes a server's run on their workstation - the
normal case in 2nd level - would otherwise get the network values of their own
machine written into the card of someone else's finding. The runner therefore
checks the machine name from the header data against the local one and
measures nothing if they differ.

**How often is measured.** A probe receives all targets at once and is started
exactly once. Twelve findings about DNS timeouts make one PowerShell call, not
twelve.

**What a result means for the individual finding.** The same measurement hangs
on findings of different ages. A "speaks against it" is therefore downgraded to
"says nothing about it" as soon as more than an hour lies between measurement
and last occurrence - the time gap thus has a consequence in the code and does
not merely stand as a sentence underneath. A "supports the finding" is not
downgraded: a service that is still down today does support the failure of
the day before yesterday.
"""

from __future__ import annotations

import socket
import sys
from datetime import timedelta
from typing import TYPE_CHECKING

from ..applog import get_log
from ..collect.shell import PowerShellNotFoundError, ShellInfo, find_powershell
from ..config.model import Config
from .base import (
    Probe,
    ProbeBearing,
    ProbeResult,
    disabled_result,
    unavailable_result,
)
from .network import ROLE_FOR, NetworkProbe
from .services import SERVICE_EVENTS, ServiceProbe
from .storage import STORAGE_EVENTS, StorageProbe

if TYPE_CHECKING:  # pragma: no cover
    from ..rules.engine import Finding

#: From this gap on a measurement no longer refutes anything.
FRESHNESS = timedelta(hours=1)

ALL_PROBE_TITLES: dict[str, str] = {
    NetworkProbe.probe_id: NetworkProbe.title,
    ServiceProbe.probe_id: ServiceProbe.title,
    StorageProbe.probe_id: StorageProbe.title,
}

#: Which provider/id pairs request which probe. The same basis as
#: ``target_for``, just without a probe object - because when nothing can be
#: measured there is no probe, but there are findings that must learn the reason.
CANDIDATE_KEYS: dict[str, frozenset[tuple[str, int]]] = {
    NetworkProbe.probe_id: frozenset(ROLE_FOR),
    ServiceProbe.probe_id: SERVICE_EVENTS,
    StorageProbe.probe_id: STORAGE_EVENTS,
}


def build_probes(config: Config, shell: ShellInfo) -> list[Probe]:
    """Creates the enabled probes."""
    probes: list[Probe] = []
    settings = config.probes
    if settings.network:
        probes.append(
            NetworkProbe(
                shell,
                timeout_seconds=settings.timeout_seconds,
                ping_count=settings.ping_count,
                ping_timeout_ms=settings.ping_timeout_ms,
            )
        )
    if settings.services:
        probes.append(ServiceProbe(shell, timeout_seconds=settings.timeout_seconds))
    if settings.storage:
        probes.append(StorageProbe(shell, timeout_seconds=settings.timeout_seconds))
    return probes


def _short_host(name: str) -> str:
    return name.split(".", 1)[0].strip().casefold()


def _disabled_probe_ids(config: Config) -> list[str]:
    settings = config.probes
    off = []
    if not settings.network:
        off.append(NetworkProbe.probe_id)
    if not settings.services:
        off.append(ServiceProbe.probe_id)
    if not settings.storage:
        off.append(StorageProbe.probe_id)
    return off


class ProbeRunner:
    """Runs the probes and attaches the results to the findings."""

    def __init__(
        self,
        config: Config,
        *,
        run_host: str,
        local_host: str | None = None,
        shell: ShellInfo | None = None,
        probes: list[Probe] | None = None,
    ) -> None:
        self.config = config
        self.run_host = run_host
        self.local_host = local_host if local_host is not None else socket.gethostname()
        self._shell = shell
        self._probes = probes

    # --- Preconditions -------------------------------------------------------

    def blocked_reason(self) -> str | None:
        """Why nothing can be measured at all. ``None`` means: it works."""
        # The machine name comes before the platform: whoever analyzes a
        # server's run elsewhere should learn that, not merely read that the
        # probes do not run here.
        if _short_host(self.run_host) != _short_host(self.local_host):
            return (
                f"The run comes from '{self.run_host}', it is analyzed on "
                f"'{self.local_host}'. A measurement would describe the wrong machine "
                "and is therefore skipped."
            )
        if sys.platform != "win32":
            return (
                "Probes measure Windows states and only run on Windows. "
                f"This system reports itself as '{sys.platform}'."
            )
        if self._probes is None and self._shell is None:
            try:
                self._shell = find_powershell(self.config.collect.powershell_preference)
            except PowerShellNotFoundError as exc:
                return str(exc)
        return None

    # --- Execution -----------------------------------------------------------

    def attach(self, findings: list[Finding]) -> int:
        """Measures and attaches the results. Returns the number of measurements."""
        if not self.config.probes.enabled or not findings:
            return 0

        log = get_log()
        reason = self.blocked_reason()
        if reason is not None:
            self._attach_blocked(findings, reason)
            log.info("Probes skipped", reason=reason)
            return 0

        probes = self._probes
        if probes is None:
            if self._shell is None:  # pragma: no cover - blocked_reason obtained it
                return 0
            probes = build_probes(self.config, self._shell)
        self._attach_switched_off(findings)

        measured = 0
        for probe in probes:
            targets: dict[str, list[Finding]] = {}
            for finding in findings:
                target = probe.target_for(finding)
                if target:
                    targets.setdefault(target, []).append(finding)
            if not targets:
                continue

            log.info("Probe running", probe=probe.probe_id, targets=len(targets))
            try:
                results = probe.run(targets)
            except Exception as exc:  # noqa: BLE001 - a probe must never kill the run
                log.warn("Probe aborted", probe=probe.probe_id, error=str(exc))
                results = [
                    unavailable_result(
                        probe.probe_id,
                        ALL_PROBE_TITLES.get(probe.probe_id, probe.title),
                        "The measurement aborted with an unexpected error.",
                        error=f"{type(exc).__name__}: {exc}",
                    )
                ]

            measured += self._distribute(results, targets, findings)
        return measured

    def _distribute(
        self,
        results: list[ProbeResult],
        targets: dict[str, list[Finding]],
        findings: list[Finding],
    ) -> int:
        """Assigns measurement results to the findings that requested them."""
        all_requested = [f for group in targets.values() for f in group]
        measured = 0

        for result in results:
            if result.target is not None and result.target in targets:
                recipients = targets[result.target]
            else:
                # Results without a target - abort, timeout, failure - go to
                # every finding that requested this probe.
                recipients = all_requested

            for finding in recipients:
                finding.probes.append(self._for_finding(result, finding))
            if result.measured:
                measured += 1

        _ = findings
        return measured

    @staticmethod
    def _for_finding(result: ProbeResult, finding: Finding) -> ProbeResult:
        copy = result.model_copy(
            update={
                "finding_id": finding.finding_id,
                "finding_last_seen_utc": finding.group.last_seen_utc,
            }
        )
        if copy.bearing is ProbeBearing.WEAKENS:
            gap = copy.age
            if gap is None or gap > FRESHNESS:
                copy.bearing = ProbeBearing.INCONCLUSIVE
        return copy

    def _attach_blocked(self, findings: list[Finding], reason: str) -> None:
        """Attaches the reason to every finding that would have requested a probe."""
        for probe_id, title in ALL_PROBE_TITLES.items():
            if probe_id in _disabled_probe_ids(self.config):
                continue
            for finding in self._candidates(findings, probe_id):
                finding.probes.append(
                    self._for_finding(unavailable_result(probe_id, title, reason), finding)
                )

    def _attach_switched_off(self, findings: list[Finding]) -> None:
        """A probe switched off individually stays visible in the finding card.

        A "nothing was measured here" is information; an empty field is an
        invitation to take it for a measurement.
        """
        for probe_id in _disabled_probe_ids(self.config):
            title = ALL_PROBE_TITLES[probe_id]
            for finding in self._candidates(findings, probe_id):
                finding.probes.append(
                    self._for_finding(
                        disabled_result(
                            probe_id, title, "This probe is disabled in the configuration."
                        ),
                        finding,
                    )
                )

    @staticmethod
    def _candidates(findings: list[Finding], probe_id: str) -> list[Finding]:
        """Which findings would have requested this probe - without building it."""
        keys = CANDIDATE_KEYS.get(probe_id, frozenset())
        return [
            finding
            for finding in findings
            if (finding.group.provider.lower(), finding.group.event_id) in keys
        ]
