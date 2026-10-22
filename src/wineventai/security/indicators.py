"""Security mode: combining indicators, policy and gaps.

All results are explicitly marked as an INDICATION, not as a forensic finding.
This marking is not a text snippet but a field - so it cannot get lost in the
report.
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

DISCLAIMER = (
    "Indication, not a forensic finding. The results of this section justify "
    "further checks, nothing more."
)


class NotLoggedIndicator(BaseModel):
    """An indicator that cannot arise on this system at all."""

    model_config = ConfigDict(extra="forbid")

    event_ids: list[int]
    subcategory: str
    state: PolicyState
    hint: str
    suggestion: dict[str, str] = Field(default_factory=dict)


class SecurityReport(BaseModel):
    """Result of the security mode."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    disclaimer: str = DISCLAIMER
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
    """Builds the security part of the report."""
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
            suggestion=fix_suggestion(check) if check.state is PolicyState.INACTIVE else {},
        )
        for check in checks
        if check.state is not PolicyState.ACTIVE
    ]

    security_findings = [finding for finding in findings if finding.security_indicator]

    # An indicator that is not logged must not pass as "no finding" - it is
    # explicitly shown above as a blind spot.
    _ = blind

    return SecurityReport(
        enabled=True,
        findings=security_findings,
        policy_checks=checks,
        not_logged=not_logged,
        gaps=find_gaps(records, sessions),
        policy_queryable=bool(states),
    )
