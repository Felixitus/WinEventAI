"""Security mode: policy check, blind spots, timeline gaps.

The German auditpol output below is test data on purpose: it is what a German
Windows prints, and the parser must handle both language versions.
"""

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


def test_auditpol_is_read_by_column_position_not_by_name() -> None:
    """The column headings are translated, the positions are not."""
    german = parse_auditpol(AUDITPOL_DE)
    english = parse_auditpol(AUDITPOL_EN)

    assert german["Prozesserstellung"] is PolicyState.INACTIVE
    assert english["Process Creation"] is PolicyState.INACTIVE
    assert german["Anmelden"] is PolicyState.ACTIVE
    assert english["Logon"] is PolicyState.ACTIVE


def test_a_switched_off_category_becomes_not_logged() -> None:
    checks = evaluate_policy(parse_auditpol(AUDITPOL_DE))
    blind = not_logged_event_ids(checks)
    assert 4688 in blind, "without process tracking there is no 4688"
    assert 4624 not in blind


def test_without_admin_rights_the_answer_is_unknown_not_active() -> None:
    """The most dangerous error would be reading ignorance as inconspicuousness."""
    checks = evaluate_policy({})
    assert all(check.state is PolicyState.UNKNOWN for check in checks)
    assert not not_logged_event_ids(checks)
    assert all("unknown" in check.hint.lower() for check in checks)


def test_the_suggestion_names_command_effect_risk_and_rollback() -> None:
    checks = evaluate_policy(parse_auditpol(AUDITPOL_DE))
    inactive = next(check for check in checks if check.state is PolicyState.INACTIVE)
    suggestion = fix_suggestion(inactive)

    assert set(suggestion) == {"command", "effect", "risk", "rollback"}
    assert suggestion["command"].startswith("auditpol /set")
    assert "disable" in suggestion["rollback"]


def test_a_gap_between_sessions_is_not_a_finding() -> None:
    """Between 6006 and 6005 the machine was off - that is not a gap."""
    before = make_record(minutes_ago=2000, channel="System")
    after = make_record(minutes_ago=10, channel="System")
    before.boot_session = 1
    after.boot_session = 0

    sessions = [BootSession(index=0, event_count=1), BootSession(index=1, event_count=1)]
    assert find_gaps([before, after], sessions, min_hours=6.0) == []


def test_a_gap_within_a_session_is_reported() -> None:
    before = make_record(minutes_ago=2000, channel="Security")
    after = make_record(minutes_ago=10, channel="Security")
    before.boot_session = 0
    after.boot_session = 0

    gaps = find_gaps([before, after], [BootSession(index=0, event_count=2)], min_hours=6.0)
    assert len(gaps) == 1
    assert gaps[0].hours > 6
    assert "within a running session" in gaps[0].description


def test_the_security_report_is_marked_as_an_indication() -> None:
    report = build_security_report([], [], [], enabled=True, is_admin=False, policy_states={})
    assert "not a forensic finding" in report.disclaimer
    assert report.has_blind_spots, "without a queryable policy there are blind spots"


def test_a_disabled_security_mode_delivers_an_empty_report() -> None:
    report = build_security_report([], [], [], enabled=False, is_admin=True)
    assert report.enabled is False
    assert not report.findings
