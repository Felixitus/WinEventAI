"""Time probe: a stopped service is not always a fault, an internet source is never queried.

The payload lines below are the shapes ``probe_time.ps1`` printed on a real
Windows 11 (service, config, skipped internet peer) and against a local SNTP
test server running 5 s fast (successful peer with ``offset_ms`` 4999.4).
"""

from __future__ import annotations

import json

from helpers import make_record
from wineventai.enrich.aggregate import Enricher
from wineventai.probes.base import ProbeBearing, ProbeStatus
from wineventai.probes.shell import read_payloads
from wineventai.probes.timesync import TARGET, TimeProbe, interpret
from wineventai.rules.engine import RuleEngine
from wineventai.rules.loader import load_rules

STATUS = '{"__status":{"probe":"time","records":3,"exception":null}}'


def _payloads(*items: dict) -> object:
    return read_payloads([json.dumps(item) for item in items] + [STATUS])


def _service(state: str = "Stopped", start_mode: str = "Manual") -> dict:
    return {"kind": "service", "found": True, "state": state, "start_mode": start_mode}


def _config(kind: str = "NTP", servers: list[str] | None = None) -> dict:
    return {"kind": "config", "type": kind, "servers": servers or ["time.windows.com"]}


INTERNET_PEER = {
    "kind": "peer", "server": "time.windows.com", "address": "20.101.57.9",
    "private": False, "skipped": True,
}


def _peer(offset_ms: float = 12.0, success: bool = True) -> dict:
    if not success:
        return {
            "kind": "peer", "server": "dc01", "address": "10.0.0.5", "private": True,
            "skipped": False, "success": False,
            "error": "System.Net.Sockets.SocketException",
        }
    return {
        "kind": "peer", "server": "dc01", "address": "10.0.0.5", "private": True,
        "skipped": False, "success": True, "stratum": 2, "offset_ms": offset_ms,
        "delay_ms": 4.0, "error": None,
    }


def _judge(*items: dict):
    return interpret(_payloads(*items), max_offset_seconds=2.0)


def test_a_stopped_manual_service_is_the_normal_state_of_a_workstation() -> None:
    """Measured on Windows 11 outside a domain: Stopped / Manual, internet source."""
    result = _judge(_service(), _config(), INTERNET_PEER)
    assert result.status is ProbeStatus.OK
    assert result.bearing is ProbeBearing.INCONCLUSIVE
    assert "not measured" in result.summary


def test_an_internet_time_source_is_listed_but_never_queried() -> None:
    result = _judge(_service(), _config(), INTERNET_PEER)
    assert any("not queried - internet address" in line for line in result.details)


def test_a_disabled_service_supports_the_finding() -> None:
    result = _judge(_service("Stopped", "Disabled"), _config())
    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS


def test_an_automatic_service_that_is_not_running_supports_the_finding() -> None:
    result = _judge(_service("Stopped", "Auto"), _config())
    assert result.status is ProbeStatus.WARN


def test_nosync_is_a_finding_in_itself() -> None:
    result = _judge(_service("Running", "Auto"), _config("NoSync", []))
    assert result.status is ProbeStatus.WARN
    assert "NoSync" in result.summary


def test_an_offset_above_the_limit_supports_the_finding() -> None:
    """The local test server ran 5 s fast; the script measured 4999.4 ms."""
    result = _judge(_service("Running", "Auto"), _config("NTP", ["dc01"]), _peer(4999.4))
    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS
    assert "5.0 s" in result.summary


def test_a_small_offset_speaks_against_the_finding() -> None:
    result = _judge(_service("Running", "Auto"), _config("NTP", ["dc01"]), _peer(12.0))
    assert result.status is ProbeStatus.OK
    assert result.bearing is ProbeBearing.WEAKENS
    assert any("+12.0 ms" in line for line in result.details)


def test_a_negative_offset_counts_like_a_positive_one() -> None:
    result = _judge(_service("Running", "Auto"), _config("NTP", ["dc01"]), _peer(-3500.0))
    assert result.status is ProbeStatus.WARN


def test_local_sources_that_do_not_answer_support_the_finding() -> None:
    result = _judge(_service("Running", "Auto"), _config("NTP", ["dc01"]), _peer(success=False))
    assert result.status is ProbeStatus.WARN
    assert "answers" in result.summary


def test_a_domain_member_says_why_nothing_was_measured() -> None:
    result = _judge(_service("Running", "Auto"), {"kind": "config", "type": "NT5DS", "servers": []})
    assert result.bearing is ProbeBearing.INCONCLUSIVE
    assert "domain hierarchy" in result.summary


def test_the_probe_hangs_on_the_time_service_events_only() -> None:
    engine = RuleEngine(load_rules())
    stream = [
        make_record(minutes_ago=0, provider="Microsoft-Windows-Time-Service", event_id=36,
                    level=3, message="The time service has not synchronized."),
        make_record(minutes_ago=1, provider="EventLog", event_id=6008, level=2,
                    message="Unexpected shutdown."),
    ]
    findings = engine.evaluate(Enricher(window_hours=168).consume(stream))
    probe = TimeProbe(shell=None)  # type: ignore[arg-type]
    targets = {finding.rule_id: probe.target_for(finding) for finding in findings}
    assert targets["time-sync-warning"] == TARGET
    assert targets["eventlog-6008"] is None


def test_the_time_probe_can_be_switched_off() -> None:
    from wineventai.config import Config
    from wineventai.probes.runner import build_probes

    config = Config.model_validate({"probes": {"time": False}})
    assert all(probe.probe_id != "time" for probe in build_probes(config, shell=None))  # type: ignore[arg-type]
