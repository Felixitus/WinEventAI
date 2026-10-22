"""Enricher: fingerprint, boot sessions, bursts, correlation, retention."""

from __future__ import annotations

from helpers import make_record
from wineventai.enrich.aggregate import Enricher
from wineventai.enrich.boot import BootTracker
from wineventai.enrich.burst import detect_bursts
from wineventai.enrich.fingerprint import describe_fingerprint, fingerprint_for
from wineventai.enrich.merge import merge_descending
from wineventai.enrich.retention import Priority, RetentionReservoir


def test_the_fingerprint_hangs_on_properties_not_on_the_message_text() -> None:
    """The same incident on a German and an English Windows.

    The message text is translated, the property vector is not. If the
    fingerprint were built from the text, the same incident would produce two
    groups - and comparing two runs would silently go wrong.
    """
    german = make_record(
        provider="Service Control Manager",
        event_id=7031,
        message="Der Dienst \"Druckwarteschlange\" wurde unerwartet beendet.",
        properties=["Druckwarteschlange", "3", "60000"],
    )
    english = make_record(
        provider="Service Control Manager",
        event_id=7031,
        message='The "Print Spooler" service terminated unexpectedly.',
        properties=["Druckwarteschlange", "3", "60000"],
    )
    assert fingerprint_for(german) == fingerprint_for(english)
    assert describe_fingerprint(fingerprint_for(german))["basis"] == "properties"


def test_without_properties_the_fingerprint_falls_back_to_the_message() -> None:
    record = make_record(message="Something happened", properties=[])
    described = describe_fingerprint(fingerprint_for(record))
    assert described["basis"] == "message text"


def test_the_fingerprint_keeps_different_services_apart() -> None:
    a = make_record(provider="Service Control Manager", event_id=7031,
                    properties=["Print Spooler", "3"])
    b = make_record(provider="Service Control Manager", event_id=7031,
                    properties=["Windows Update", "3"])
    assert fingerprint_for(a) != fingerprint_for(b)


def test_boot_sessions_are_detected_backwards() -> None:
    """Descending stream: session 0 is the newest."""
    tracker = BootTracker()
    stream = [
        make_record(minutes_ago=10, provider="Microsoft-Windows-Kernel-Power",
                    event_id=41, level=1),
        make_record(minutes_ago=11, provider="EventLog", event_id=6008, level=2),
        make_record(minutes_ago=12, provider="EventLog", event_id=6005),
        make_record(minutes_ago=600, provider="Application Error", event_id=1000),
        make_record(minutes_ago=900, provider="EventLog", event_id=6005),
    ]
    for record in stream:
        tracker.observe(record)
    sessions = tracker.finish()

    assert sessions[0].index == 0
    assert len(sessions) >= 2
    # 41 and 6008 appear at boot and say something about the OLDER session -
    # that one has to be marked unclean.
    assert sessions[1].clean_shutdown is False


def test_clean_shutdown_stays_none_if_the_transition_is_missing() -> None:
    """Do not guess: without a marker in the window the state is unknown."""
    tracker = BootTracker()
    tracker.observe(make_record(minutes_ago=5, provider="disk", event_id=51, level=2))
    sessions = tracker.finish()
    assert sessions[0].clean_shutdown is None


def test_a_clean_shutdown_is_detected() -> None:
    tracker = BootTracker()
    for record in (
        make_record(minutes_ago=10, provider="EventLog", event_id=6005),
        make_record(minutes_ago=200, provider="EventLog", event_id=6006),
    ):
        tracker.observe(record)
    sessions = tracker.finish()
    assert sessions[-1].clean_shutdown is True


def test_burst_detects_concentration_in_one_single_hour() -> None:
    """The case where a median-based method fails.

    64 events in exactly one hour: the median of the occupied hours is then 64 -
    the outlier hides behind itself. Measured against the density of the whole
    window, the concentration is the signal.
    """
    hourly = {"2026-09-09T07": 64}
    assert detect_bursts(hourly, factor=5.0, min_count=10, window_hours=168) != []
    assert detect_bursts(hourly, factor=5.0, min_count=10) == []


def test_even_noise_is_not_a_burst() -> None:
    hourly = {f"2026-09-0{d}T{h:02d}": 10 for d in (3, 4) for h in range(24)}
    bursts = detect_bursts(hourly, factor=5.0, min_count=10, window_hours=168)
    assert bursts == []


def test_the_reservoir_keeps_rule_hits_even_with_lots_of_noise() -> None:
    """The core of priority instead of capping."""
    reservoir = RetentionReservoir(limit=20, error_share=0.5, seed=1)
    for index in range(1000):
        reservoir.offer(make_record(minutes_ago=index), Priority.OTHER)
    hit = make_record(minutes_ago=5, provider="Microsoft-Windows-Kernel-Power",
                      event_id=41, level=1)
    reservoir.offer(hit, Priority.RULE_HIT)

    kept = reservoir.records()
    assert any(record.event_id == 41 for record in kept), (
        "a rule hit must never be pushed out by noise"
    )


def test_the_reservoir_is_deterministic() -> None:
    def run() -> list[str]:
        reservoir = RetentionReservoir(limit=10, error_share=0.5, seed=99)
        for index in range(200):
            reservoir.offer(make_record(minutes_ago=index), Priority.OTHER)
        return [record.raw_hash for record in reservoir.records()]

    assert run() == run()


def test_merge_delivers_descending() -> None:
    a = [make_record(minutes_ago=i, channel="System") for i in (1, 5, 9)]
    b = [make_record(minutes_ago=i, channel="Application") for i in (2, 6)]
    merged = list(merge_descending([a, b]))
    stamps = [record.timestamp_utc for record in merged]
    assert stamps == sorted(stamps, reverse=True)
    assert len(merged) == 5


def test_correlation_finds_events_before_the_marker() -> None:
    """In the descending stream the lead-up arrives AFTER the marker."""
    stream = [
        make_record(minutes_ago=0, provider="Microsoft-Windows-Kernel-Power",
                    event_id=41, level=1),
        make_record(minutes_ago=1, provider="disk", event_id=153, level=2),
        make_record(minutes_ago=3, provider="disk", event_id=153, level=2,
                    properties=["1", "4001"]),
        make_record(minutes_ago=90, provider="disk", event_id=153, level=2,
                    properties=["1", "4002"]),
    ]
    enricher = Enricher(context_window_minutes=5, window_hours=168)
    result = enricher.consume(stream)

    assert len(result.context_windows) == 1
    context = result.context_windows[0]
    assert len(context.before) == 2, "only the two within five minutes"


def test_the_aggregate_sees_every_record_even_with_small_retention() -> None:
    """The limit affects the raw-data appendix, not the figures."""
    stream = [
        make_record(minutes_ago=index, provider="Microsoft-Windows-DistributedCOM",
                    event_id=10016, properties=["{GUID}", "SYSTEM"])
        for index in range(500)
    ]
    enricher = Enricher(retention_limit=10, window_hours=168)
    result = enricher.consume(stream)

    assert result.total_events == 500
    assert result.groups[0].count == 500, "the counter knows all records"
    assert len(result.retained) <= 10
    assert result.truncated is True


def test_the_reduction_rate_is_computed() -> None:
    stream = [
        make_record(minutes_ago=i, provider="X", event_id=1, properties=["same"])
        for i in range(100)
    ]
    result = Enricher(window_hours=168).consume(stream)
    assert len(result.groups) == 1
    assert result.reduction_rate > 0.98
