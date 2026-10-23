"""Time probe: is the Windows time service working NOW?

Hangs on the W32Time warnings 36, 47, 48, 50, 129 and 134 of
``Microsoft-Windows-Time-Service`` (ids checked against the provider manifest
on Windows 11). A wrong clock is not cosmetic: Kerberos refuses tickets from a
skew of five minutes on, TLS certificates appear not yet valid, and every
timeline in this report is shifted.

What is measured, and what deliberately not:

* The service state from WMI. On a workstation outside a domain W32Time is
  set to "Manual" and is only started on demand - "stopped" is the normal
  state there and must not be reported as a fault. Only "Disabled", or
  "Automatic" and not running, is a finding.
* The configured source type and servers from the registry - no parsing of
  ``w32tm /query``, whose output is translated.
* The real offset by one SNTP request, but only to servers in a private
  address range. ``time.windows.com`` and every other internet source are not
  queried: the same promise as the network probe, no traffic of its own to
  the internet. Then the statement explicitly stays weak.

Domain members (type ``NT5DS``) take the time from the domain hierarchy; the
domain controller cannot be determined reliably without ``nltest`` and is
therefore not measured - that is said, not glossed over.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..applog import get_log
from ..collect.shell import ShellInfo
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

PROBE_ID = "time"
TITLE = "Time synchronization"
TARGET = "w32time"

TIME_PROVIDER = "microsoft-windows-time-service"
TIME_EVENTS: frozenset[tuple[str, int]] = frozenset(
    (TIME_PROVIDER, event_id) for event_id in (36, 47, 48, 50, 129, 134)
)

#: Registry values of Parameters\Type - identifiers, not display text.
TYPE_LABEL: dict[str, str] = {
    "ntp": "manually configured NTP servers",
    "nt5ds": "domain hierarchy",
    "allsync": "all available sources",
    "nosync": "no synchronization",
}


def _number(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


class TimeProbe:
    """Measures the time service and - within the local network - the offset."""

    probe_id = PROBE_ID
    title = TITLE

    def __init__(
        self,
        shell: ShellInfo,
        *,
        timeout_seconds: float = 25.0,
        max_offset_seconds: float = 2.0,
        request_timeout_ms: int = 1500,
    ) -> None:
        self.shell = shell
        self.timeout_seconds = timeout_seconds
        self.max_offset_seconds = max_offset_seconds
        self.request_timeout_ms = request_timeout_ms

    def target_for(self, finding: Finding) -> str | None:
        key = (finding.group.provider.lower(), finding.group.event_id)
        return TARGET if key in TIME_EVENTS else None

    def run(self, targets: dict[str, list[Finding]]) -> list[ProbeResult]:
        if not targets:
            return []
        run = run_probe_script(
            "probe_time.ps1",
            ["-TimeoutMs", str(self.request_timeout_ms)],
            shell=self.shell,
            timeout_seconds=self.timeout_seconds,
        )
        if run.timed_out:
            return [timed_out_result(PROBE_ID, TITLE, run.duration_seconds)]
        if run.payloads.exception or (run.returncode != 0 and not run.payloads.items):
            get_log().warn(
                "Time probe failed", exception=run.payloads.exception, code=run.returncode
            )
            return [
                failed_result(
                    PROBE_ID,
                    TITLE,
                    "The state of the time service could not be read.",
                    error=run.payloads.exception or run.stderr.strip()[:200] or None,
                )
            ]
        return [
            interpret(
                run.payloads,
                max_offset_seconds=self.max_offset_seconds,
                duration_seconds=run.duration_seconds,
            )
        ]


def interpret(
    payloads: ProbePayloads,
    *,
    max_offset_seconds: float,
    duration_seconds: float = 0.0,
) -> ProbeResult:
    """One result for the time service. Pure - no process, no network."""
    services = payloads.of_kind("service")
    configs = payloads.of_kind("config")
    peers = payloads.of_kind("peer")

    service = services[0] if services else {}
    config = configs[0] if configs else {}
    state = str(service.get("state", "")).strip().lower()
    start_mode = str(service.get("start_mode", "")).strip().lower()
    source_type = str(config.get("type", "")).strip().lower()

    details: list[str] = []
    if service.get("found"):
        details.append(
            f"Service W32Time: {state or 'unknown'}, start type {start_mode or 'unknown'}"
        )
    details.append(
        "Source: " + TYPE_LABEL.get(source_type, source_type or "not configured")
    )
    for peer in peers:
        details.append(_peer_line(peer))

    def result(status: ProbeStatus, bearing: ProbeBearing, summary: str) -> ProbeResult:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=status,
            bearing=bearing,
            target=TARGET,
            summary=summary,
            details=details,
            duration_seconds=duration_seconds,
        )

    if not service.get("found"):
        return result(
            ProbeStatus.WARN,
            ProbeBearing.SUPPORTS,
            "The time service W32Time does not exist on this system.",
        )
    if start_mode == "disabled":
        return result(
            ProbeStatus.WARN,
            ProbeBearing.SUPPORTS,
            "The time service is disabled - the clock is not synchronized at all.",
        )
    if start_mode in ("auto", "automatic") and state != "running":
        return result(
            ProbeStatus.WARN,
            ProbeBearing.SUPPORTS,
            "The time service is set to start automatically but is not running.",
        )
    if source_type == "nosync":
        return result(
            ProbeStatus.WARN,
            ProbeBearing.SUPPORTS,
            "The time service is configured with 'NoSync' - it synchronizes with nothing.",
        )

    measured = [peer for peer in peers if peer.get("success")]
    failed = [peer for peer in peers if not peer.get("success") and not peer.get("skipped")]
    limit_ms = max_offset_seconds * 1000.0
    off = [
        peer for peer in measured
        if abs(_number(peer.get("offset_ms")) or 0.0) > limit_ms
    ]

    if off:
        worst = max(abs(_number(peer.get("offset_ms")) or 0.0) for peer in off) / 1000.0
        return result(
            ProbeStatus.WARN,
            ProbeBearing.SUPPORTS,
            f"The clock deviates by {worst:.1f} s from the configured time source "
            f"(allowed: {max_offset_seconds:g} s). Kerberos refuses logons from 300 s on.",
        )
    if failed and not measured:
        return result(
            ProbeStatus.WARN,
            ProbeBearing.SUPPORTS,
            f"None of the {len(failed)} configured time sources in the local network "
            "answers an SNTP request.",
        )
    if measured:
        return result(
            ProbeStatus.OK,
            ProbeBearing.WEAKENS,
            f"The clock agrees with the configured time source to within "
            f"{max_offset_seconds:g} s.",
        )

    # Nothing measurable: only internet sources, or the domain hierarchy.
    if source_type == "nt5ds":
        reason = (
            "The time comes from the domain hierarchy; the domain controller is not "
            "determined without nltest, so the offset was not measured."
        )
    elif peers:
        reason = (
            "The configured time sources are on the internet and are deliberately not "
            "queried by this probe - the offset was not measured."
        )
    else:
        reason = "No time source is configured, so no offset could be measured."
    return result(
        ProbeStatus.OK,
        ProbeBearing.INCONCLUSIVE,
        f"The time service is in its normal state. {reason}",
    )


def _peer_line(peer: dict[str, object]) -> str:
    server = str(peer.get("server", "?"))
    address = peer.get("address")
    where = f"{server} ({address})" if address else server
    if peer.get("skipped"):
        return f"{where}: not queried - internet address"
    if peer.get("success"):
        offset = _number(peer.get("offset_ms"))
        delay = _number(peer.get("delay_ms"))
        parts = [f"{where}: offset {offset:+.1f} ms" if offset is not None else where]
        if delay is not None:
            parts.append(f"round trip {delay:.1f} ms")
        return ", ".join(parts)
    return f"{where}: no answer ({peer.get('error') or 'no detail'})"
