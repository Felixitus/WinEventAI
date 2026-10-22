"""Sicherheitsmodus: Zusammenfuehrung von Indikatoren, Richtlinie und Luecken.

Alle Ergebnisse sind ausdruecklich als HINWEIS gekennzeichnet, nicht als
forensische Feststellung. Diese Kennzeichnung ist kein Textbaustein, sondern ein
Feld - damit sie im Bericht nicht verloren gehen kann.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ..enrich.boot import BootSession
from ..normalize.schema import EventRecord
from ..rules.engine import Finding
from .audit_policy import (
    PolicyCheck,
    PolicyState,
    evaluate_policy,
    fix_suggestion,
    not_logged_event_ids,
    query_audit_policy,
)
from .gaps import TimelineGap, find_gaps

HINWEIS = (
    "Hinweis, keine forensische Feststellung. Die Ergebnisse dieses Abschnitts "
    "begruenden weitere Pruefung, nicht mehr."
)


class NotLoggedIndicator(BaseModel):
    """Ein Indikator, der auf diesem System gar nicht entstehen kann."""

    model_config = ConfigDict(extra="forbid")

    event_ids: list[int]
    subcategory: str
    state: PolicyState
    hint: str
    vorschlag: dict[str, str] = Field(default_factory=dict)


class SecurityReport(BaseModel):
    """Ergebnis des Sicherheitsmodus."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    disclaimer: str = HINWEIS
    findings: list[Finding] = Field(default_factory=list)
    policy_checks: list[PolicyCheck] = Field(default_factory=list)
    not_logged: list[NotLoggedIndicator] = Field(default_factory=list)
    gaps: list[TimelineGap] = Field(default_factory=list)
    policy_queryable: bool = True

    @property
    def has_blind_spots(self) -> bool:
        return bool(self.not_logged) or not self.policy_queryable


def build_security_report(
    findings: list[Finding],
    records: list[EventRecord],
    sessions: list[BootSession],
    *,
    enabled: bool,
    is_admin: bool,
    policy_states: dict[str, PolicyState] | None = None,
) -> SecurityReport:
    """Baut den Sicherheitsteil des Berichts."""
    if not enabled:
        return SecurityReport(enabled=False)

    states = policy_states if policy_states is not None else query_audit_policy(is_admin=is_admin)
    checks = evaluate_policy(states)
    blind = not_logged_event_ids(checks)

    not_logged = [
        NotLoggedIndicator(
            event_ids=check.affects_event_ids,
            subcategory=check.subcategory,
            state=check.state,
            hint=check.hint,
            vorschlag=fix_suggestion(check) if check.state is PolicyState.INACTIVE else {},
        )
        for check in checks
        if check.state is not PolicyState.ACTIVE
    ]

    security_findings = [finding for finding in findings if finding.security_indicator]

    # Ein Indikator, der nicht protokolliert wird, darf nicht als "kein Befund"
    # durchgehen - er wird oben ausdruecklich als blinder Fleck ausgewiesen.
    _ = blind

    return SecurityReport(
        enabled=True,
        findings=security_findings,
        policy_checks=checks,
        not_logged=not_logged,
        gaps=find_gaps(records, sessions),
        policy_queryable=bool(states),
    )
