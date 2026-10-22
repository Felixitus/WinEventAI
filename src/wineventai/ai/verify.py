"""Verification of the model output.

Two stages:

1. Every ``Evidence`` triple must occur in the input bundle. Timestamps with a
   tolerance, because models like to round to the minute.
2. A regular expression searches the prose for numbers that look like event
   ids and do NOT occur in the bundle.

The individual statement is rejected, not the whole answer: otherwise one bad
footnote costs three good hypotheses.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from .bundles import FindingBundle
from .redaction import Redactor
from .schema import CorrelatorOutput, Evidence, ExplainerOutput, Statement

#: "Event ID 1001", "EventID 41", "ID 6008" - deliberately narrow, so that not
#: every number in the text counts as an event id.
_ID_IN_PROSE = re.compile(r"(?i)\bevent[- ]?id[:\s]*(\d{1,5})\b|\bID\s+(\d{3,5})\b")

DEFAULT_TOLERANCE = timedelta(minutes=2)


class VerificationReport(BaseModel):
    """What the verification found. Goes unchanged into the report."""

    model_config = ConfigDict(extra="forbid")

    statements_total: int = 0
    statements_rejected: int = 0
    rejected_reasons: list[str] = Field(default_factory=list)
    invented_event_ids: list[int] = Field(default_factory=list)
    invented_placeholders: list[str] = Field(default_factory=list)

    @property
    def clean(self) -> bool:
        return self.statements_rejected == 0 and not self.invented_event_ids


class EvidenceIndex:
    """The search space that is checked against: only what was in the bundle."""

    def __init__(self, bundles: list[FindingBundle]) -> None:
        self.pairs: set[tuple[str, int]] = set()
        self.ids: set[int] = set()
        self.times: dict[tuple[str, int], list[datetime]] = {}
        self.finding_ids: set[str] = set()

        for bundle in bundles:
            self.finding_ids.add(bundle.finding_id)
            self.finding_ids.add(bundle.finding_id.split("#")[0])
            for entry in bundle.citable_events + bundle.context_events:
                provider = str(entry["provider"])
                event_id = int(entry["event_id"])
                self.pairs.add((provider, event_id))
                self.ids.add(event_id)
                stamp = _parse(entry.get("timestamp_utc"))
                if stamp is not None:
                    self.times.setdefault((provider, event_id), []).append(stamp)

    def covers(self, evidence: Evidence, tolerance: timedelta) -> tuple[bool, str]:
        key = (evidence.provider, evidence.event_id)
        if key not in self.pairs:
            return False, (
                f"provider/id {evidence.provider}:{evidence.event_id} did not occur in the bundle"
            )
        stamps = self.times.get(key, [])
        if not stamps:
            return True, ""
        target = evidence.timestamp_utc
        if target.tzinfo is None:
            target = target.replace(tzinfo=stamps[0].tzinfo)
        if any(abs(target - stamp) <= tolerance for stamp in stamps):
            return True, ""
        return False, (
            f"timestamp {evidence.timestamp_utc.isoformat()} matches no occurrence "
            f"of {evidence.provider}:{evidence.event_id}"
        )


def _parse(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def prose_event_ids(text: str) -> set[int]:
    """Event ids named in the running text."""
    found: set[int] = set()
    for match in _ID_IN_PROSE.finditer(text):
        raw = match.group(1) or match.group(2)
        if raw:
            found.add(int(raw))
    return found


def verify_statement(
    statement: Statement,
    index: EvidenceIndex,
    *,
    redactor: Redactor | None = None,
    tolerance: timedelta = DEFAULT_TOLERANCE,
) -> tuple[Statement, list[str], set[int], set[str]]:
    """Checks one statement. Returns the marked statement and the findings."""
    reasons: list[str] = []

    for evidence in statement.evidence:
        ok, reason = index.covers(evidence, tolerance)
        if not ok:
            reasons.append(reason)

    invented_ids = prose_event_ids(statement.statement) - index.ids
    if invented_ids:
        reasons.append(
            "event ids named in the text without a counterpart in the bundle: "
            + ", ".join(str(value) for value in sorted(invented_ids))
        )

    invented_placeholders: set[str] = set()
    if redactor is not None:
        invented_placeholders = redactor.invented_placeholders(statement.statement)
        if invented_placeholders:
            reasons.append(
                "invented placeholders: " + ", ".join(sorted(invented_placeholders))
            )

    if reasons:
        statement = statement.model_copy(
            update={"verified": False, "verification_note": " / ".join(reasons)}
        )
    return statement, reasons, invented_ids, invented_placeholders


def verify_explainer(
    output: ExplainerOutput,
    bundles: list[FindingBundle],
    *,
    redactor: Redactor | None = None,
    tolerance: timedelta = DEFAULT_TOLERANCE,
) -> tuple[ExplainerOutput, VerificationReport]:
    """Checks an explainer answer and marks uncovered statements."""
    index = EvidenceIndex(bundles)
    report = VerificationReport()
    invented_ids: set[int] = set()
    invented_placeholders: set[str] = set()

    def check(items: list[Statement]) -> list[Statement]:
        checked: list[Statement] = []
        for statement in items:
            report.statements_total += 1
            marked, reasons, ids, placeholders = verify_statement(
                statement, index, redactor=redactor, tolerance=tolerance
            )
            invented_ids.update(ids)
            invented_placeholders.update(placeholders)
            if reasons:
                report.statements_rejected += 1
                report.rejected_reasons.append(f"{statement.statement[:80]}… -> {reasons[0]}")
            checked.append(marked)
        return checked

    verified = output.model_copy(
        update={
            "hypotheses": check(output.hypotheses),
            "recommended_steps": check(output.recommended_steps),
        }
    )
    report.invented_event_ids = sorted(invented_ids)
    report.invented_placeholders = sorted(invented_placeholders)
    return verified, report


def verify_correlator(
    output: CorrelatorOutput,
    bundles: list[FindingBundle],
    *,
    tolerance: timedelta = DEFAULT_TOLERANCE,
) -> tuple[CorrelatorOutput, VerificationReport]:
    """Checks a correlator answer. Unknown finding ids count as a violation."""
    index = EvidenceIndex(bundles)
    report = VerificationReport()
    groups = []

    for group in output.incidents:
        report.statements_total += 1
        reasons: list[str] = []

        unknown = [fid for fid in group.finding_ids if fid not in index.finding_ids]
        if unknown:
            reasons.append("unknown finding ids: " + ", ".join(unknown))
        for evidence in group.evidence:
            ok, reason = index.covers(evidence, tolerance)
            if not ok:
                reasons.append(reason)

        if reasons:
            report.statements_rejected += 1
            report.rejected_reasons.append(f"{group.title} -> {reasons[0]}")
            group = group.model_copy(
                update={"verified": False, "verification_note": " / ".join(reasons)}
            )
        groups.append(group)

    return output.model_copy(update={"incidents": groups}), report
