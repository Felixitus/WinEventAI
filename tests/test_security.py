"""Sicherheitsmodus: Richtlinienpruefung, blinde Flecken, Zeitluecken."""

from __future__ import annotations

from helpers import make_record
from wineventai.enrich.boot import BootSession
from wineventai.security.audit_policy import (
    PolicyState,
    evaluate_policy,
    fix_suggestion,
    not_logged_event_ids,
    parse_auditpol,
)
from wineventai.security.gaps import find_gaps
from wineventai.security.indicators import build_security_report

AUDITPOL_DE = """Computername,Richtlinienziel,Unterkategorie,Unterkategorie-GUID,Einstellungen
WS-4711,System,Prozesserstellung,{0CCE922B-69AE-11D9-BED3-505054503030},Keine Ueberwachung
WS-4711,System,Anmelden,{0CCE9215-69AE-11D9-BED3-505054503030},Erfolg und Fehler
"""

AUDITPOL_EN = """Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting
WS-4711,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},No Auditing
WS-4711,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure
"""


def test_auditpol_wird_ueber_spaltenposition_gelesen_nicht_ueber_namen() -> None:
    """Die Spaltenueberschriften sind uebersetzt, die Positionen nicht."""
    deutsch = parse_auditpol(AUDITPOL_DE)
    englisch = parse_auditpol(AUDITPOL_EN)

    assert deutsch["Prozesserstellung"] is PolicyState.INACTIVE
    assert englisch["Process Creation"] is PolicyState.INACTIVE
    assert deutsch["Anmelden"] is PolicyState.ACTIVE
    assert englisch["Logon"] is PolicyState.ACTIVE


def test_abgeschaltete_kategorie_wird_zu_nicht_protokolliert() -> None:
    checks = evaluate_policy(parse_auditpol(AUDITPOL_DE))
    blind = not_logged_event_ids(checks)
    assert 4688 in blind, "ohne Prozessverfolgung entsteht keine 4688"
    assert 4624 not in blind


def test_ohne_adminrechte_lautet_die_antwort_unbekannt_nicht_aktiv() -> None:
    """Der gefaehrlichste Fehler waere, Unwissen als Unauffaelligkeit zu lesen."""
    checks = evaluate_policy({})
    assert all(check.state is PolicyState.UNKNOWN for check in checks)
    assert not not_logged_event_ids(checks)
    assert all("unbekannt" in check.hint.lower() for check in checks)


def test_vorschlag_nennt_befehl_wirkung_risiko_und_rueckbau() -> None:
    checks = evaluate_policy(parse_auditpol(AUDITPOL_DE))
    inaktiv = next(check for check in checks if check.state is PolicyState.INACTIVE)
    vorschlag = fix_suggestion(inaktiv)

    assert set(vorschlag) == {"befehl", "wirkung", "risiko", "rueckbau"}
    assert vorschlag["befehl"].startswith("auditpol /set")
    assert "disable" in vorschlag["rueckbau"]


def test_luecke_zwischen_sitzungen_ist_kein_befund() -> None:
    """Zwischen 6006 und 6005 war der Rechner aus - das ist keine Luecke."""
    davor = make_record(minutes_ago=2000, channel="System")
    danach = make_record(minutes_ago=10, channel="System")
    davor.boot_session = 1
    danach.boot_session = 0

    sessions = [BootSession(index=0, event_count=1), BootSession(index=1, event_count=1)]
    assert find_gaps([davor, danach], sessions, min_hours=6.0) == []


def test_luecke_innerhalb_einer_sitzung_wird_gemeldet() -> None:
    davor = make_record(minutes_ago=2000, channel="Security")
    danach = make_record(minutes_ago=10, channel="Security")
    davor.boot_session = 0
    danach.boot_session = 0

    gaps = find_gaps([davor, danach], [BootSession(index=0, event_count=2)], min_hours=6.0)
    assert len(gaps) == 1
    assert gaps[0].hours > 6
    assert "innerhalb einer laufenden Sitzung" in gaps[0].description


def test_sicherheitsbericht_ist_als_hinweis_gekennzeichnet() -> None:
    report = build_security_report([], [], [], enabled=True, is_admin=False, policy_states={})
    assert "keine forensische Feststellung" in report.disclaimer
    assert report.has_blind_spots, "ohne abfragbare Richtlinie gibt es blinde Flecken"


def test_abgeschalteter_sicherheitsmodus_liefert_leeren_bericht() -> None:
    report = build_security_report([], [], [], enabled=False, is_admin=True)
    assert report.enabled is False
    assert not report.findings
