"""Nachpruefung der Modellausgabe.

Zwei Stufen:

1. Jedes ``Evidence``-Tripel muss im Eingabebuendel vorkommen. Zeitstempel mit
   Toleranz, weil Modelle gern auf die Minute runden.
2. Ein regulaerer Ausdruck sucht in der Prosa nach Zahlen, die wie Event-IDs
   aussehen und im Buendel NICHT vorkommen.

Verworfen wird die einzelne Aussage, nicht die gesamte Antwort: Sonst kostet
eine schlechte Fussnote drei gute Hypothesen.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from .bundles import FindingBundle
from .redaction import Redactor
from .schema import CorrelatorOutput, Evidence, ExplainerOutput, Statement

#: "Event-ID 1001", "EventID 41", "ID 6008" - bewusst eng gefasst, damit nicht
#: jede Zahl im Text als Event-ID gilt.
_ID_IN_PROSE = re.compile(r"(?i)\bevent[- ]?id[:\s]*(\d{1,5})\b|\bID\s+(\d{3,5})\b")

DEFAULT_TOLERANCE = timedelta(minutes=2)


class VerificationReport(BaseModel):
    """Was die Nachpruefung ergeben hat. Wandert unveraendert in den Bericht."""

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
    """Der Suchraum, gegen den geprueft wird: nur was im Buendel stand."""

    def __init__(self, bundles: list[FindingBundle]) -> None:
        self.pairs: set[tuple[str, int]] = set()
        self.ids: set[int] = set()
        self.times: dict[tuple[str, int], list[datetime]] = {}
        self.finding_ids: set[str] = set()

        for bundle in bundles:
            self.finding_ids.add(bundle.befund_id)
            self.finding_ids.add(bundle.befund_id.split("#")[0])
            for entry in bundle.belegbare_ereignisse + bundle.kontext_ereignisse:
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
                f"Provider/ID {evidence.provider}:{evidence.event_id} kam im Buendel nicht vor"
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
            f"Zeitstempel {evidence.timestamp_utc.isoformat()} passt zu keinem "
            f"Vorkommen von {evidence.provider}:{evidence.event_id}"
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
    """Event-IDs, die im Fliesstext genannt werden."""
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
    """Prueft eine Aussage. Liefert die markierte Aussage und die Befunde."""
    reasons: list[str] = []

    for evidence in statement.evidence:
        ok, reason = index.covers(evidence, tolerance)
        if not ok:
            reasons.append(reason)

    invented_ids = prose_event_ids(statement.aussage) - index.ids
    if invented_ids:
        reasons.append(
            "Im Text genannte Event-IDs ohne Entsprechung im Buendel: "
            + ", ".join(str(value) for value in sorted(invented_ids))
        )

    invented_placeholders: set[str] = set()
    if redactor is not None:
        invented_placeholders = redactor.invented_placeholders(statement.aussage)
        if invented_placeholders:
            reasons.append(
                "Erfundene Platzhalter: " + ", ".join(sorted(invented_placeholders))
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
    """Prueft eine Erklaerer-Antwort und markiert ungedeckte Aussagen."""
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
                report.rejected_reasons.append(f"{statement.aussage[:80]}… -> {reasons[0]}")
            checked.append(marked)
        return checked

    verified = output.model_copy(
        update={
            "hypothesen": check(output.hypothesen),
            "empfohlene_schritte": check(output.empfohlene_schritte),
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
    """Prueft eine Korrelator-Antwort. Unbekannte Befund-IDs zaehlen als Verstoss."""
    index = EvidenceIndex(bundles)
    report = VerificationReport()
    groups = []

    for group in output.vorfaelle:
        report.statements_total += 1
        reasons: list[str] = []

        unknown = [fid for fid in group.befund_ids if fid not in index.finding_ids]
        if unknown:
            reasons.append("Unbekannte Befund-IDs: " + ", ".join(unknown))
        for evidence in group.evidence:
            ok, reason = index.covers(evidence, tolerance)
            if not ok:
                reasons.append(reason)

        if reasons:
            report.statements_rejected += 1
            report.rejected_reasons.append(f"{group.titel} -> {reasons[0]}")
            group = group.model_copy(
                update={"verified": False, "verification_note": " / ".join(reasons)}
            )
        groups.append(group)

    return output.model_copy(update={"vorfaelle": groups}), report
