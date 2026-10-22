"""Network probe: reachability of DNS server, gateway and DHCP server.

This probe answers the question a DNS Client 1014 bundle raises: is the path
to name resolution standing at all? It answers it for NOW - the time caveat
from ``base.py`` applies especially here, because a network disturbance is the
most fleeting of all symptoms.

Two measurements, and the order matters:

1. ICMP to the configured servers. Cheap but weak: a machine that answers ping
   can have a dead DNS service.
2. A real name query to the same server. It asks for the own machine name - no
   foreign name leaves the house, and the question still hits the service and
   not just the host.

If step 2 is missing because ``Resolve-DnsName`` is unavailable, the statement
explicitly stays weak. It is not upgraded then.
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

PROBE_ID = "network"
TITLE = "Network path and name resolution"

#: Which finding lets which role be measured. The key is provider (lower case)
#: plus event id - never the id alone, which is only unique per provider.
ROLE_FOR: dict[tuple[str, int], str] = {
    ("microsoft-windows-dns-client", 1014): "dns",
    ("dnsapi", 1014): "dns",
    ("dns client events", 1014): "dns",
    ("microsoft-windows-dhcp-client", 1003): "dhcp",
    ("dhcp-client", 1003): "dhcp",
    ("dhcp", 1003): "dhcp",
    ("tcpip", 4227): "gateway",
    ("tcpip", 4231): "gateway",
    ("microsoft-windows-tcpip", 4227): "gateway",
    ("microsoft-windows-tcpip", 4231): "gateway",
    ("netbt", 4321): "gateway",
}

ROLE_TITLE: dict[str, str] = {
    "dns": "DNS server reachable",
    "gateway": "Default gateway reachable",
    "dhcp": "DHCP server reachable",
}

ROLE_LABEL: dict[str, str] = {"dns": "DNS servers", "gateway": "gateways", "dhcp": "DHCP servers"}


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


class NetworkProbe:
    """Measures the local network infrastructure - and only that."""

    probe_id = PROBE_ID
    title = TITLE

    def __init__(
        self,
        shell: ShellInfo,
        *,
        timeout_seconds: float = 25.0,
        ping_count: int = 3,
        ping_timeout_ms: int = 1500,
    ) -> None:
        self.shell = shell
        self.timeout_seconds = timeout_seconds
        self.ping_count = ping_count
        self.ping_timeout_ms = ping_timeout_ms

    def target_for(self, finding: Finding) -> str | None:
        return ROLE_FOR.get((finding.group.provider.lower(), finding.group.event_id))

    def run(self, targets: dict[str, list[Finding]]) -> list[ProbeResult]:
        roles = sorted(targets)
        if not roles:
            return []

        args = [
            "-Role",
            join_list_arg(roles),
            "-Count",
            str(self.ping_count),
            "-TimeoutMs",
            str(self.ping_timeout_ms),
        ]
        run = run_probe_script(
            "probe_network.ps1", args, shell=self.shell, timeout_seconds=self.timeout_seconds
        )
        if run.timed_out:
            return [timed_out_result(PROBE_ID, TITLE, run.duration_seconds)]
        if run.payloads.exception or (run.returncode != 0 and not run.payloads.items):
            get_log().warn(
                "Network probe failed",
                exception=run.payloads.exception,
                code=run.returncode,
            )
            return [
                failed_result(
                    PROBE_ID,
                    TITLE,
                    "The network configuration could not be read.",
                    error=run.payloads.exception or run.stderr.strip()[:200] or None,
                )
            ]

        return interpret(run.payloads, roles, duration_seconds=run.duration_seconds)


def interpret(
    payloads: ProbePayloads, roles: list[str], *, duration_seconds: float = 0.0
) -> list[ProbeResult]:
    """Builds one result per role. Pure - no process, no network, testable."""
    results: list[ProbeResult] = []
    targets = payloads.of_kind("target")
    empty = {
        str(item.get("role")): str(item.get("reason", ""))
        for item in payloads.of_kind("empty")
    }
    queries = payloads.of_kind("dnsquery")
    notes = [str(item.get("text", "")) for item in payloads.of_kind("note")]

    for role in roles:
        own = [item for item in targets if item.get("role") == role]
        title = ROLE_TITLE.get(role, TITLE)

        if not own:
            reason = empty.get(role) or "Nothing is configured for this role on the system."
            results.append(
                ProbeResult(
                    probe_id=PROBE_ID,
                    title=title,
                    status=ProbeStatus.NOT_APPLICABLE,
                    target=role,
                    summary=reason,
                    duration_seconds=duration_seconds,
                )
            )
            continue

        measured = [item for item in own if not item.get("skipped")]
        skipped = [item for item in own if item.get("skipped")]
        details = [_target_line(item) for item in own]

        if not measured:
            results.append(
                ProbeResult(
                    probe_id=PROBE_ID,
                    title=title,
                    status=ProbeStatus.NOT_APPLICABLE,
                    target=role,
                    summary=(
                        f"All configured {ROLE_LABEL.get(role, role)} are outside the private "
                        "address ranges. This probe only measures within the local network."
                    ),
                    details=details,
                    duration_seconds=duration_seconds,
                )
            )
            continue

        dead = [item for item in measured if _as_int(item.get("received")) == 0]
        partial = [
            item
            for item in measured
            if 0 < _as_int(item.get("received")) < _as_int(item.get("sent"), 1)
        ]

        if role == "dns":
            results.append(
                _dns_result(measured, dead, partial, queries, details, notes, duration_seconds)
            )
        else:
            results.append(
                _ping_result(role, title, measured, dead, partial, details, duration_seconds)
            )

        if skipped:
            # No finding entry of its own - but it has to stay visible that part
            # of the configuration remained unmeasured.
            results[-1].details.append(
                f"{len(skipped)} address(es) skipped because they are outside the "
                "local network."
            )

    return results


def _target_line(item: dict[str, object]) -> str:
    address = str(item.get("address", "?"))
    adapter = str(item.get("adapter") or "").strip()
    suffix = f" ({adapter})" if adapter else ""

    if item.get("skipped"):
        return f"{address}{suffix}: not measured - public address"

    sent = _as_int(item.get("sent"))
    received = _as_int(item.get("received"))
    if received == 0:
        error = str(item.get("error") or "no answer")
        return f"{address}{suffix}: {sent} attempts, no answer ({error})"

    average = item.get("avg_ms")
    timing = f", {average} ms on average" if average is not None else ""
    return f"{address}{suffix}: {received} of {sent} answered{timing}"


def _ping_result(
    role: str,
    title: str,
    measured: list[dict[str, object]],
    dead: list[dict[str, object]],
    partial: list[dict[str, object]],
    details: list[str],
    duration_seconds: float,
) -> ProbeResult:
    label = ROLE_LABEL.get(role, role)
    if dead:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=title,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target=role,
            summary=f"{len(dead)} of {len(measured)} configured {label} do not answer.",
            details=details,
            duration_seconds=duration_seconds,
        )
    if partial:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=title,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target=role,
            summary=f"Packet loss on the way to the {label}.",
            details=details,
            duration_seconds=duration_seconds,
        )
    return ProbeResult(
        probe_id=PROBE_ID,
        title=title,
        status=ProbeStatus.OK,
        bearing=ProbeBearing.WEAKENS,
        target=role,
        summary=f"All configured {label} answer without loss.",
        details=details,
        duration_seconds=duration_seconds,
    )


def _dns_result(
    measured: list[dict[str, object]],
    dead: list[dict[str, object]],
    partial: list[dict[str, object]],
    queries: list[dict[str, object]],
    details: list[str],
    notes: list[str],
    duration_seconds: float,
) -> ProbeResult:
    title = ROLE_TITLE["dns"]
    all_details = list(details)
    for entry in queries:
        all_details.append(_query_line(entry))
    all_details.extend(notes)

    failed = [item for item in queries if not item.get("success")]

    if dead:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=title,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target="dns",
            summary=f"{len(dead)} of {len(measured)} DNS servers do not answer.",
            details=all_details,
            duration_seconds=duration_seconds,
        )

    if failed:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=title,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target="dns",
            summary=(
                f"{len(failed)} of {len(queries)} DNS servers answer ICMP but no name "
                "query. Exactly this picture produces event 1014."
            ),
            details=all_details,
            duration_seconds=duration_seconds,
        )

    if not queries:
        # Only ICMP measured. That is explicitly not enough for an all-clear: a
        # host that answers ping can have a dead DNS service.
        return ProbeResult(
            probe_id=PROBE_ID,
            title=title,
            status=ProbeStatus.OK,
            bearing=ProbeBearing.INCONCLUSIVE,
            target="dns",
            summary=(
                "The DNS servers answer ICMP. No name query was performed, so nothing "
                "is said about the DNS service itself."
            ),
            details=all_details,
            duration_seconds=duration_seconds,
        )

    if partial:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=title,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target="dns",
            summary="Name queries succeed, but the path to the DNS server loses packets.",
            details=all_details,
            duration_seconds=duration_seconds,
        )

    return ProbeResult(
        probe_id=PROBE_ID,
        title=title,
        status=ProbeStatus.OK,
        bearing=ProbeBearing.WEAKENS,
        target="dns",
        summary="All DNS servers answer and resolve the own machine name.",
        details=all_details,
        duration_seconds=duration_seconds,
    )


def _query_line(item: dict[str, object]) -> str:
    server = str(item.get("server", "?"))
    if item.get("success"):
        duration = item.get("duration_ms")
        answer = item.get("answer")
        parts = [f"Name query to {server}: answered"]
        if answer:
            parts.append(f"({answer})")
        if duration is not None:
            parts.append(f"in {duration} ms")
        return " ".join(parts)
    return f"Name query to {server}: failed ({item.get('error') or 'no detail'})"
