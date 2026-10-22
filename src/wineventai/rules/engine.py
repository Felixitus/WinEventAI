"""Rule engine: deterministic, without a language model.

The report must be complete even without a model. Every decision needed for a
finding's severity, order and visibility is therefore made here; the AI layer
only comments afterwards.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from ..enrich.aggregate import EnrichmentResult, FingerprintGroup
from ..enrich.correlate import ContextWindow
from ..normalize.schema import EventRecord
from ..probes.base import ProbeResult
from .schema import SEVERITY_ORDER, Classification, RuleDefinition, Severity

if TYPE_CHECKING:  # pragma: no cover
    pass

#: Knowledge-base state of a finding when the KB has no entry at all.
KB_MISSING = "missing"


class Finding(BaseModel):
    """A rule hit on a fingerprint group."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    rule_id: str
    rule_name: str
    rule_source: str
    severity: Severity
    meaning: str = ""
    typical_causes: list[str] = Field(default_factory=list)
    recommended_checks: list[str] = Field(default_factory=list)
    reference: str | None = None
    group: FingerprintGroup
    context_events: list[EventRecord] = Field(default_factory=list)
    suppressed: bool = False
    security_indicator: bool = False
    kb_confidence: str = KB_MISSING
    kb_meaning: str | None = None
    kb_source: str | None = None
    escalated: bool = False
    probes: list[ProbeResult] = Field(
        default_factory=list,
        description="Context measurements for this finding. Measured NOW, not back then.",
    )

    @property
    def finding_id(self) -> str:
        return f"{self.rule_id}::{self.group.fingerprint[-8:]}"

    @property
    def key(self) -> str:
        return self.group.key

    @property
    def has_verified_meaning(self) -> bool:
        """True if a verified meaning is stored in the knowledge base.

        If not, the entry is NOT embedded in the prompt and the finding appears
        in the report with the note "no verified meaning on record".
        """
        return self.kb_confidence == "verified" and bool(self.kb_meaning)

    def to_public_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "rule": self.rule_id,
            "rule_name": self.rule_name,
            "rule_origin": self.rule_source,
            "severity": str(self.severity),
            "escalated": self.escalated,
            "meaning": self.meaning,
            "typical_causes": self.typical_causes,
            "recommended_checks": self.recommended_checks,
            "reference": self.reference,
            "suppressed": self.suppressed,
            "security_indicator": self.security_indicator,
            "knowledge_base": {
                "confidence": self.kb_confidence,
                "meaning": self.kb_meaning,
                "source": self.kb_source,
            },
            "group": self.group.to_public_dict(),
            "context": [record.to_public_dict() for record in self.context_events],
            "probes": [probe.to_public_dict() for probe in self.probes],
        }


def _matches_scalar(value: object, allowed: list[object]) -> bool:
    return not allowed or value in allowed


class RuleEngine:
    """Applies rules to fingerprint groups."""

    def __init__(self, rules: list[RuleDefinition], *, suppress_noise: bool = True) -> None:
        self.rules = rules
        self.suppress_noise = suppress_noise
        self._by_key: dict[tuple[str, int], list[RuleDefinition]] = {}
        for rule in rules:
            for key in rule.match.match_keys():
                self._by_key.setdefault(key, []).append(rule)

    @property
    def rule_keys(self) -> set[tuple[str, int]]:
        """Pre-filter for retention: which provider/id pairs are of interest.

        Noise rules explicitly do NOT count here. Otherwise the priority-1 quota
        would immediately be used up by DistributedCOM on a noisy system -
        exactly the error the priority classes are built against.
        """
        keys: set[tuple[str, int]] = set()
        for key, rules in self._by_key.items():
            if any(rule.classification is not Classification.NOISE for rule in rules):
                keys.add(key)
        return keys

    @property
    def noise_keys(self) -> set[tuple[str, int]]:
        """Pairs for which only noise rules exist."""
        return set(self._by_key) - self.rule_keys

    # --- Hits ----------------------------------------------------------------

    def _group_matches(self, rule: RuleDefinition, group: FingerprintGroup) -> bool:
        if not _matches_scalar(group.channel, list(rule.match.channels())):
            return False
        if rule.match.level_max is not None and group.level > rule.match.level_max:
            return False
        if group.count < rule.threshold.count_min:
            return False
        if rule.threshold.burst_required and not group.bursts:
            return False
        if rule.match.event_version is not None:
            versions = {
                sample.event_version for sample in group.samples if sample.event_version is not None
            }
            if versions and rule.match.event_version not in versions:
                return False

        message_pattern = rule.compiled_message()
        data_patterns = rule.compiled_data()
        if message_pattern is None and not data_patterns:
            return True

        # Text conditions are checked against the samples, not the whole group -
        # nothing more is available after condensing.
        for sample in group.samples:
            if message_pattern is not None and not message_pattern.search(sample.message or ""):
                continue
            if data_patterns and not self._data_matches(data_patterns, sample):
                continue
            return True
        return False

    @staticmethod
    def _data_matches(patterns: dict[str, object], sample: EventRecord) -> bool:
        for name, pattern in patterns.items():
            value = sample.data_value(name)
            if value is None or not pattern.search(value):  # type: ignore[union-attr]
                return False
        return True

    def _severity_for(self, rule: RuleDefinition, group: FingerprintGroup) -> tuple[Severity, bool]:
        threshold = rule.threshold
        if (
            threshold.escalate_to is not None
            and threshold.escalate_above is not None
            and group.count > threshold.escalate_above
        ):
            return threshold.escalate_to, True
        return rule.severity, False

    def evaluate(
        self,
        enrichment: EnrichmentResult,
        *,
        context_for: dict[str, list[ContextWindow]] | None = None,
    ) -> list[Finding]:
        """Produces the findings of a run, sorted by severity."""
        findings: list[Finding] = []

        for group in enrichment.groups:
            for rule in self._by_key.get((group.provider, group.event_id), []):
                if not self._group_matches(rule, group):
                    continue
                severity, escalated = self._severity_for(rule, group)
                suppressed = (
                    rule.classification is Classification.NOISE and self.suppress_noise
                )
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        rule_source=rule.source,
                        severity=severity,
                        meaning=rule.meaning,
                        typical_causes=list(rule.typical_causes),
                        recommended_checks=list(rule.recommended_checks),
                        reference=rule.reference,
                        group=group,
                        context_events=self._context_for(group, enrichment),
                        suppressed=suppressed,
                        security_indicator=rule.security_indicator,
                        escalated=escalated,
                    )
                )

        findings.sort(
            key=lambda finding: (
                SEVERITY_ORDER[finding.severity],
                finding.suppressed,
                -finding.group.count,
                finding.rule_id,
            )
        )
        return findings

    @staticmethod
    def _context_for(
        group: FingerprintGroup, enrichment: EnrichmentResult
    ) -> list[EventRecord]:
        """Context events, if the group itself is a marker."""
        from ..enrich.correlate import MARKER_KEYS

        if (group.provider, group.event_id) not in MARKER_KEYS:
            return []
        context: list[EventRecord] = []
        for window in enrichment.context_windows:
            if (window.marker_provider, window.marker_event_id) == (
                group.provider,
                group.event_id,
            ):
                context.extend(window.before)
        return context[:60]


def unmatched_keys(
    enrichment: EnrichmentResult, engine: RuleEngine
) -> list[tuple[str, int, int]]:
    """Provider/id pairs without a rule hit, with count - the work list."""
    known = engine.rule_keys
    counter: dict[tuple[str, int], int] = {}
    for group in enrichment.groups:
        key = (group.provider, group.event_id)
        if key in known:
            continue
        counter[key] = counter.get(key, 0) + group.count
    return sorted(
        ((provider, event_id, count) for (provider, event_id), count in counter.items()),
        key=lambda entry: -entry[2],
    )
