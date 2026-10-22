"""Tests of the context probes.

The test boundary is ``read_payloads``: everything from there on is pure
evaluation and runs without Windows and without PowerShell. What can NOT be
checked here are the three ``.ps1`` files themselves - they only prove
themselves on a target system, and the status documentation says so.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from helpers import WINDOW_END, make_record
from wineventai.config import Config
from wineventai.enrich.aggregate import FingerprintGroup
from wineventai.probes import network, services, storage
from wineventai.probes.base import ProbeBearing, ProbeResult, ProbeStatus
from wineventai.probes.runner import ProbeRunner
from wineventai.probes.shell import read_payloads
from wineventai.rules.engine import Finding
from wineventai.rules.schema import Severity


def payloads(*items: dict[str, object], status: dict[str, object] | None = None):
    lines = [json.dumps(item, ensure_ascii=False) for item in items]
    lines.append(json.dumps({"__status": status or {"probe": "test", "exception": None}}))
    return read_payloads(lines)


def make_finding(
    *,
    provider: str,
    event_id: int,
    rule_id: str = "rule-1",
    minutes_ago: int = 5,
    properties: list[str | None] | None = None,
) -> Finding:
    sample = make_record(
        provider=provider, event_id=event_id, minutes_ago=minutes_ago, properties=properties
    )
    group = FingerprintGroup(
        fingerprint=f"{provider}|{event_id}|0|pabcdef0123456789",
        provider=provider,
        event_id=event_id,
        channel="System",
        level=2,
        count=12,
        first_seen_utc=sample.timestamp_utc - timedelta(hours=1),
        last_seen_utc=sample.timestamp_utc,
        samples=[sample],
    )
    return Finding(
        rule_id=rule_id,
        rule_name="Test rule",
        rule_source="builtin",
        severity=Severity.ERROR,
        group=group,
    )


# --- Basic vocabulary --------------------------------------------------------


def test_the_time_caveat_gets_clearer_with_the_gap():
    now = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
    fresh = ProbeResult(
        probe_id="network",
        title="T",
        status=ProbeStatus.OK,
        measured_utc=now,
        finding_last_seen_utc=now - timedelta(minutes=10),
    )
    old = fresh.model_copy(update={"finding_last_seen_utc": now - timedelta(days=5)})

    assert "shortly after" in fresh.age_note()
    assert "5 days" in old.age_note()
    assert "says nothing about the state" in old.age_note()


def test_states_without_measurement_do_not_count_as_measurement():
    for status in (
        ProbeStatus.FAILED,
        ProbeStatus.NOT_APPLICABLE,
        ProbeStatus.NO_PERMISSION,
        ProbeStatus.TIMED_OUT,
        ProbeStatus.DISABLED,
        ProbeStatus.UNAVAILABLE,
    ):
        result = ProbeResult(probe_id="x", title="T", status=status)
        assert result.measured is False
    assert ProbeResult(probe_id="x", title="T", status=ProbeStatus.OK).measured is True


# --- Network probe -----------------------------------------------------------


def test_network_a_dead_dns_server_supports_the_finding():
    result = network.interpret(
        payloads(
            {
                "kind": "target",
                "role": "dns",
                "address": "192.168.1.1",
                "private": True,
                "skipped": False,
                "sent": 3,
                "received": 0,
                "error": "TimedOut",
            }
        ),
        ["dns"],
    )[0]

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS
    assert "do not answer" in result.summary


def test_network_ping_alone_does_not_exonerate_the_dns_service():
    """A host that answers ICMP can have a dead DNS service."""
    result = network.interpret(
        payloads(
            {
                "kind": "target",
                "role": "dns",
                "address": "192.168.1.1",
                "private": True,
                "skipped": False,
                "sent": 3,
                "received": 3,
                "avg_ms": 1.0,
            }
        ),
        ["dns"],
    )[0]

    assert result.status is ProbeStatus.OK
    assert result.bearing is ProbeBearing.INCONCLUSIVE
    assert "No name query was performed" in result.summary


def test_network_ping_good_but_name_query_fails_is_the_core_case():
    result = network.interpret(
        payloads(
            {
                "kind": "target",
                "role": "dns",
                "address": "10.0.0.53",
                "private": True,
                "skipped": False,
                "sent": 3,
                "received": 3,
                "avg_ms": 0.8,
            },
            {
                "kind": "dnsquery",
                "server": "10.0.0.53",
                "name": "WS-4711",
                "success": False,
                "error": "System.ComponentModel.Win32Exception",
            },
        ),
        ["dns"],
    )[0]

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS
    assert "1014" in result.summary


def test_network_a_public_address_is_not_measured():
    result = network.interpret(
        payloads(
            {
                "kind": "target",
                "role": "dns",
                "address": "8.8.8.8",
                "private": False,
                "skipped": True,
                "reason": "public",
            }
        ),
        ["dns"],
    )[0]

    assert result.status is ProbeStatus.NOT_APPLICABLE
    assert "only measures within the local network" in result.summary


def test_network_without_configuration_is_not_applicable_and_not_unremarkable():
    result = network.interpret(
        payloads({"kind": "empty", "role": "dhcp", "reason": "No interface uses DHCP."}),
        ["dhcp"],
    )[0]

    assert result.status is ProbeStatus.NOT_APPLICABLE
    assert result.measured is False


def test_network_finds_its_target_by_provider_and_id():
    probe = network.NetworkProbe.__new__(network.NetworkProbe)
    dns = make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)
    other = make_finding(provider="EventLog", event_id=1014)

    assert probe.target_for(dns) == "dns"
    assert probe.target_for(other) is None


# --- Service probe -----------------------------------------------------------


def test_service_stopped_and_automatic_supports_the_finding():
    result = services.interpret(
        payloads(
            {
                "kind": "service",
                "searched": "Druckwarteschlange",
                "found": True,
                "name": "Spooler",
                "display_name": "Druckwarteschlange",
                "state": "Stopped",
                "start_mode": "Auto",
            }
        ),
        ["Druckwarteschlange"],
    )[0]

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS


def test_a_running_service_speaks_against_the_finding():
    result = services.interpret(
        payloads(
            {
                "kind": "service",
                "searched": "Print Spooler",
                "found": True,
                "name": "Spooler",
                "state": "Running",
                "start_mode": "Auto",
            }
        ),
        ["Print Spooler"],
    )[0]

    assert result.status is ProbeStatus.OK
    assert result.bearing is ProbeBearing.WEAKENS


def test_a_disabled_service_is_a_finding_in_itself():
    result = services.interpret(
        payloads(
            {
                "kind": "service",
                "searched": "Windows Update",
                "found": True,
                "name": "wuauserv",
                "state": "Stopped",
                "start_mode": "Disabled",
            }
        ),
        ["Windows Update"],
    )[0]

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS
    assert "Disabled" in result.summary


def test_a_manual_stopped_service_is_the_intended_state():
    result = services.interpret(
        payloads(
            {
                "kind": "service",
                "searched": "Diagnostic Policy Service",
                "found": True,
                "name": "DPS",
                "state": "Stopped",
                "start_mode": "Manual",
            }
        ),
        ["Diagnostic Policy Service"],
    )[0]

    assert result.status is ProbeStatus.OK
    assert result.bearing is ProbeBearing.INCONCLUSIVE


def test_a_service_not_found_names_the_language_version_as_a_possibility():
    result = services.interpret(
        payloads({"kind": "service", "searched": "Print Spooler", "found": False}),
        ["Print Spooler"],
    )[0]

    assert result.status is ProbeStatus.NOT_APPLICABLE
    assert "language version" in result.summary


def test_the_service_target_comes_from_the_first_property():
    """SCM 7031 carries the display name in properties[0] - not the service name."""
    probe = services.ServiceProbe.__new__(services.ServiceProbe)
    finding = make_finding(
        provider="Service Control Manager",
        event_id=7031,
        properties=["Druckwarteschlange", "1", "60000"],
    )
    assert probe.target_for(finding) == "Druckwarteschlange"


# --- Storage probe -----------------------------------------------------------


def test_storage_healthy_explicitly_does_not_exonerate():
    result = storage.interpret(
        payloads(
            {
                "kind": "disk",
                "name": "Samsung SSD 980",
                "media": "SSD",
                "health": "Healthy",
                "size_b": 1_000_204_886_016,
                "read_errors": 0,
                "write_errors": 0,
                "counters_available": True,
            },
            {"kind": "smart", "instance": "SCSI\\Disk", "failure_predicted": False},
        )
    )

    assert result.status is ProbeStatus.OK
    assert result.bearing is ProbeBearing.INCONCLUSIVE
    assert "does not rule out a defect" in result.summary


def test_storage_error_counters_support_despite_a_healthy_overall_status():
    result = storage.interpret(
        payloads(
            {
                "kind": "disk",
                "name": "WDC WD10",
                "health": "Healthy",
                "read_errors": 12,
                "write_errors": 3,
                "counters_available": True,
            }
        )
    )

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS
    assert "15" in result.summary


def test_storage_predicted_failure_carries_the_attribution_caveat():
    result = storage.interpret(
        payloads(
            {"kind": "disk", "name": "WDC WD10", "health": "Warning"},
            {"kind": "smart", "instance": "SCSI\\Disk", "failure_predicted": True},
        )
    )

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS
    assert any("Device\\HarddiskN" in line for line in result.details)


def test_storage_without_values_is_not_measurable():
    result = storage.interpret(payloads({"kind": "note", "text": "Get-PhysicalDisk missing"}))
    assert result.status is ProbeStatus.UNAVAILABLE
    assert result.measured is False


# --- Runner ------------------------------------------------------------------


class FakeProbe:
    """A probe that does not measure but returns what the test prescribes."""

    probe_id = "network"
    title = "Network path and name resolution"

    def __init__(self, results: list[ProbeResult]) -> None:
        self.results = results
        self.calls: list[dict[str, list[Finding]]] = []

    def target_for(self, finding: Finding) -> str | None:
        return "dns" if finding.group.event_id == 1014 else None

    def run(self, targets):
        self.calls.append(targets)
        return list(self.results)


def local_runner(config: Config, probes) -> ProbeRunner:
    """Runner that does not need the platform check."""

    class Runner(ProbeRunner):
        def blocked_reason(self) -> str | None:
            return None

    return Runner(config, run_host="WS-4711", local_host="WS-4711", probes=probes)


def test_the_runner_starts_a_probe_once_for_many_findings():
    probe = FakeProbe(
        [
            ProbeResult(
                probe_id="network", title="DNS", status=ProbeStatus.OK, target="dns",
                bearing=ProbeBearing.WEAKENS,
            )
        ]
    )
    findings = [
        make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014, rule_id=f"r{i}")
        for i in range(4)
    ]

    measured = local_runner(Config(), [probe]).attach(findings)

    assert len(probe.calls) == 1
    assert measured == 1
    assert all(len(f.probes) == 1 for f in findings)


def test_the_runner_downgrades_speaks_against_for_an_old_finding():
    """The time gap has a consequence in the code, not just a sentence underneath."""
    result = ProbeResult(
        probe_id="network",
        title="DNS",
        status=ProbeStatus.OK,
        target="dns",
        bearing=ProbeBearing.WEAKENS,
        measured_utc=WINDOW_END,
    )
    fresh = make_finding(
        provider="Microsoft-Windows-DNS-Client", event_id=1014, minutes_ago=10
    )
    old = make_finding(
        provider="Microsoft-Windows-DNS-Client", event_id=1014, rule_id="r2", minutes_ago=60 * 30
    )

    local_runner(Config(), [FakeProbe([result])]).attach([fresh, old])

    assert fresh.probes[0].bearing is ProbeBearing.WEAKENS
    assert old.probes[0].bearing is ProbeBearing.INCONCLUSIVE


def test_the_runner_does_not_downgrade_supports():
    """A service that is still down today supports the failure of the day before yesterday."""
    result = ProbeResult(
        probe_id="network",
        title="DNS",
        status=ProbeStatus.WARN,
        target="dns",
        bearing=ProbeBearing.SUPPORTS,
        measured_utc=WINDOW_END,
    )
    old = make_finding(
        provider="Microsoft-Windows-DNS-Client", event_id=1014, minutes_ago=60 * 72
    )

    local_runner(Config(), [FakeProbe([result])]).attach([old])

    assert old.probes[0].bearing is ProbeBearing.SUPPORTS


def test_the_runner_does_not_measure_on_a_different_machine():
    """A server's run analyzed on a workstation - the normal case in 2nd level."""
    findings = [make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)]
    runner = ProbeRunner(Config(), run_host="SRV-DC01", local_host="WS-4711")

    measured = runner.attach(findings)

    assert measured == 0
    assert len(findings[0].probes) == 1
    assert findings[0].probes[0].status is ProbeStatus.UNAVAILABLE
    assert "SRV-DC01" in findings[0].probes[0].summary


def test_the_runner_accepts_an_fqdn_against_the_short_name():
    runner = ProbeRunner(Config(), run_host="ws-4711.intern.example", local_host="WS-4711")
    reason = runner.blocked_reason()
    # On non-Windows the platform check remains; the machine name must not be
    # the reason in any case.
    assert reason is None or "Windows" in reason


def test_a_disabled_probe_stays_visible_in_the_card():
    config = Config()
    config.probes.network = False
    findings = [make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)]

    local_runner(config, []).attach(findings)

    assert len(findings[0].probes) == 1
    assert findings[0].probes[0].status is ProbeStatus.DISABLED


def test_completely_disabled_probes_produce_no_entry():
    config = Config()
    config.probes.enabled = False
    findings = [make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)]

    local_runner(config, []).attach(findings)

    assert findings[0].probes == []


def test_a_crashing_probe_does_not_kill_the_run():
    class Broken(FakeProbe):
        def run(self, targets):
            raise RuntimeError("access denied")

    findings = [make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)]
    local_runner(Config(), [Broken([])]).attach(findings)

    assert findings[0].probes[0].status is ProbeStatus.UNAVAILABLE
    assert "RuntimeError" in (findings[0].probes[0].detail_error or "")


def test_probes_end_up_in_the_json_output_of_the_finding():
    findings = [make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)]
    local_runner(
        Config(),
        [
            FakeProbe(
                [
                    ProbeResult(
                        probe_id="network", title="DNS", status=ProbeStatus.OK, target="dns",
                        summary="ok",
                    )
                ]
            )
        ],
    ).attach(findings)

    output = findings[0].to_public_dict()
    assert output["probes"][0]["probe"] == "network"
    assert "time_caveat" in output["probes"][0]


# --- Reading layer -----------------------------------------------------------


def test_read_payloads_skips_broken_lines_and_finds_the_status():
    result = read_payloads(
        [
            '{"kind":"target","role":"dns"}',
            "this is not JSON",
            "",
            '{"__status":{"probe":"network","exception":"System.UnauthorizedAccessException"}}',
        ]
    )

    assert len(result.items) == 1
    assert result.parse_errors == 1
    assert result.exception == "System.UnauthorizedAccessException"


@pytest.mark.parametrize(
    ("provider", "event_id", "expected"),
    [
        ("disk", 153, "all"),
        ("storahci", 129, "all"),
        ("Ntfs", 55, "all"),
        ("EventLog", 6005, None),
    ],
)
def test_the_storage_probe_hangs_on_the_right_findings(provider, event_id, expected):
    probe = storage.StorageProbe.__new__(storage.StorageProbe)
    finding = make_finding(provider=provider, event_id=event_id)
    assert probe.target_for(finding) == expected
