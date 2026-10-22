"""Enricher: Fingerprint, Boot-Sessions, Burst, Korrelation, Retention."""

from __future__ import annotations

from helpers import make_record
from wineventai.enrich.aggregate import Enricher
from wineventai.enrich.boot import BootTracker
from wineventai.enrich.burst import detect_bursts
from wineventai.enrich.fingerprint import describe_fingerprint, fingerprint_for
from wineventai.enrich.merge import merge_descending
from wineventai.enrich.retention import Priority, RetentionReservoir


def test_fingerprint_haengt_an_properties_nicht_am_meldungstext() -> None:
    """Derselbe Vorfall auf deutschem und englischem Windows.

    Der Meldungstext ist uebersetzt, der Property-Vektor nicht. Waere der
    Fingerprint aus dem Text gebildet, ergaeben sich zwei Gruppen fuer denselben
    Vorfall - und ein Vergleich zweier Laeufe wuerde still falsch.
    """
    deutsch = make_record(
        provider="Service Control Manager",
        event_id=7031,
        message="Der Dienst \"Druckwarteschlange\" wurde unerwartet beendet.",
        properties=["Druckwarteschlange", "3", "60000"],
    )
    englisch = make_record(
        provider="Service Control Manager",
        event_id=7031,
        message='The "Print Spooler" service terminated unexpectedly.',
        properties=["Druckwarteschlange", "3", "60000"],
    )
    assert fingerprint_for(deutsch) == fingerprint_for(englisch)
    assert describe_fingerprint(fingerprint_for(deutsch))["basis"] == "properties"


def test_fingerprint_faellt_ohne_properties_auf_die_meldung_zurueck() -> None:
    record = make_record(message="Etwas ist passiert", properties=[])
    described = describe_fingerprint(fingerprint_for(record))
    assert described["basis"] == "meldungstext"


def test_fingerprint_trennt_verschiedene_dienste() -> None:
    a = make_record(provider="Service Control Manager", event_id=7031,
                    properties=["Druckwarteschlange", "3"])
    b = make_record(provider="Service Control Manager", event_id=7031,
                    properties=["Windows Update", "3"])
    assert fingerprint_for(a) != fingerprint_for(b)


def test_boot_sessions_werden_rueckwaerts_erkannt() -> None:
    """Absteigender Strom: Sitzung 0 ist die neueste."""
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
    # 41 und 6008 stehen beim Hochfahren und sagen etwas ueber die AELTERE
    # Sitzung aus - die muss als unsauber markiert sein.
    assert sessions[1].clean_shutdown is False


def test_clean_shutdown_bleibt_none_wenn_der_uebergang_fehlt() -> None:
    """Nicht raten: Ohne Marker im Fenster ist der Zustand unbekannt."""
    tracker = BootTracker()
    tracker.observe(make_record(minutes_ago=5, provider="disk", event_id=51, level=2))
    sessions = tracker.finish()
    assert sessions[0].clean_shutdown is None


def test_sauberes_herunterfahren_wird_erkannt() -> None:
    tracker = BootTracker()
    for record in (
        make_record(minutes_ago=10, provider="EventLog", event_id=6005),
        make_record(minutes_ago=200, provider="EventLog", event_id=6006),
    ):
        tracker.observe(record)
    sessions = tracker.finish()
    assert sessions[-1].clean_shutdown is True


def test_burst_erkennt_konzentration_in_einer_einzigen_stunde() -> None:
    """Der Fall, an dem ein Median-basiertes Verfahren scheitert.

    64 Ereignisse in genau einer Stunde: Der Median der belegten Stunden ist
    dann 64 - der Ausreisser versteckt sich hinter sich selbst. Gegen die
    Dichte des gesamten Fensters gerechnet ist die Konzentration das Signal.
    """
    hourly = {"2026-09-09T07": 64}
    assert detect_bursts(hourly, factor=5.0, min_count=10, window_hours=168) != []
    assert detect_bursts(hourly, factor=5.0, min_count=10) == []


def test_gleichmaessiges_rauschen_ist_kein_burst() -> None:
    hourly = {f"2026-09-0{d}T{h:02d}": 10 for d in (3, 4) for h in range(24)}
    bursts = detect_bursts(hourly, factor=5.0, min_count=10, window_hours=168)
    assert bursts == []


def test_reservoir_behaelt_regeltreffer_auch_bei_viel_rauschen() -> None:
    """Der Kern von Prioritaet statt Kappung."""
    reservoir = RetentionReservoir(limit=20, error_share=0.5, seed=1)
    for index in range(1000):
        reservoir.offer(make_record(minutes_ago=index), Priority.OTHER)
    treffer = make_record(minutes_ago=5, provider="Microsoft-Windows-Kernel-Power",
                          event_id=41, level=1)
    reservoir.offer(treffer, Priority.RULE_HIT)

    kept = reservoir.records()
    assert any(record.event_id == 41 for record in kept), (
        "ein Regeltreffer darf nie vom Rauschen verdraengt werden"
    )


def test_reservoir_ist_deterministisch() -> None:
    def run() -> list[str]:
        reservoir = RetentionReservoir(limit=10, error_share=0.5, seed=99)
        for index in range(200):
            reservoir.offer(make_record(minutes_ago=index), Priority.OTHER)
        return [record.raw_hash for record in reservoir.records()]

    assert run() == run()


def test_merge_liefert_absteigend() -> None:
    a = [make_record(minutes_ago=i, channel="System") for i in (1, 5, 9)]
    b = [make_record(minutes_ago=i, channel="Application") for i in (2, 6)]
    merged = list(merge_descending([a, b]))
    stamps = [record.timestamp_utc for record in merged]
    assert stamps == sorted(stamps, reverse=True)
    assert len(merged) == 5


def test_korrelation_findet_ereignisse_vor_dem_marker() -> None:
    """Im absteigenden Strom kommt der Vorlauf NACH dem Marker an."""
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
    assert len(context.before) == 2, "nur die beiden innerhalb von fuenf Minuten"


def test_aggregat_sieht_jeden_record_auch_bei_kleiner_retention() -> None:
    """Die Grenze betrifft den Rohdatenanhang, nicht die Kennzahlen."""
    stream = [
        make_record(minutes_ago=index, provider="Microsoft-Windows-DistributedCOM",
                    event_id=10016, properties=["{GUID}", "SYSTEM"])
        for index in range(500)
    ]
    enricher = Enricher(retention_limit=10, window_hours=168)
    result = enricher.consume(stream)

    assert result.total_events == 500
    assert result.groups[0].count == 500, "der Zaehler kennt alle Records"
    assert len(result.retained) <= 10
    assert result.truncated is True


def test_reduktionsrate_wird_berechnet() -> None:
    stream = [
        make_record(minutes_ago=i, provider="X", event_id=1, properties=["gleich"])
        for i in range(100)
    ]
    result = Enricher(window_hours=168).consume(stream)
    assert len(result.groups) == 1
    assert result.reduction_rate > 0.98
