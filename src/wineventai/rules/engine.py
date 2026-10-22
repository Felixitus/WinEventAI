"""Regel-Engine: deterministisch, ohne Sprachmodell.

Der Bericht muss auch ohne Modell vollstaendig entstehen koennen. Deshalb faellt
hier jede Entscheidung, die fuer Schwere, Reihenfolge und Sichtbarkeit eines
Befunds noetig ist; der KI-Layer kommentiert danach nur noch.
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


class Finding(BaseModel):
    """Ein Regeltreffer auf einer Fingerprint-Gruppe."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    rule_id: str
    rule_name: str
    rule_source: str
    severity: Severity
    bedeutung: str = ""
    typische_ursachen: list[str] = Field(default_factory=list)
    empfohlene_checks: list[str] = Field(default_factory=list)
    referenz: str | None = None
    group: FingerprintGroup
    context_events: list[EventRecord] = Field(default_factory=list)
    suppressed: bool = False
    security_indicator: bool = False
    kb_confidence: str = "fehlt"
    kb_bedeutung: str | None = None
    kb_quelle: str | None = None
    escalated: bool = False
    probes: list[ProbeResult] = Field(
        default_factory=list,
        description="Kontext-Messungen zu diesem Befund. Gemessen wird JETZT, nicht damals.",
    )

    @property
    def finding_id(self) -> str:
        return f"{self.rule_id}::{self.group.fingerprint[-8:]}"

    @property
    def key(self) -> str:
        return self.group.key

    @property
    def has_verified_meaning(self) -> bool:
        """True, wenn eine gepruefte Bedeutung in der Wissensbasis steht.

        Ist das nicht der Fall, wird der Eintrag NICHT in den Prompt eingebettet
        und der Befund erscheint im Bericht mit dem Vermerk
        "keine gesicherte Bedeutung hinterlegt".
        """
        return self.kb_confidence == "sicher" and bool(self.kb_bedeutung)

    def to_public_dict(self) -> dict[str, object]:
        return {
            "befund_id": self.finding_id,
            "regel": self.rule_id,
            "regel_name": self.rule_name,
            "regel_herkunft": self.rule_source,
            "severity": str(self.severity),
            "eskaliert": self.escalated,
            "bedeutung": self.bedeutung,
            "typische_ursachen": self.typische_ursachen,
            "empfohlene_checks": self.empfohlene_checks,
            "referenz": self.referenz,
            "unterdrueckt": self.suppressed,
            "sicherheitsindikator": self.security_indicator,
            "wissensbasis": {
                "confidence": self.kb_confidence,
                "bedeutung": self.kb_bedeutung,
                "quelle": self.kb_quelle,
            },
            "gruppe": self.group.to_public_dict(),
            "kontext": [record.to_public_dict() for record in self.context_events],
            "sonden": [probe.to_public_dict() for probe in self.probes],
        }


def _matches_scalar(value: object, allowed: list[object]) -> bool:
    return not allowed or value in allowed


class RuleEngine:
    """Wendet Regeln auf Fingerprint-Gruppen an."""

    def __init__(self, rules: list[RuleDefinition], *, suppress_noise: bool = True) -> None:
        self.rules = rules
        self.suppress_noise = suppress_noise
        self._by_key: dict[tuple[str, int], list[RuleDefinition]] = {}
        for rule in rules:
            for key in rule.match.match_keys():
                self._by_key.setdefault(key, []).append(rule)

    @property
    def rule_keys(self) -> set[tuple[str, int]]:
        """Vorabfilter fuer die Retention: welche Provider/ID-Paare interessieren.

        Rauschregeln zaehlen hier ausdruecklich NICHT mit. Sonst waere das
        Kontingent der Prioritaetsklasse 1 auf einem verrauschten System sofort
        von DistributedCOM aufgebraucht - genau der Fehler, gegen den die
        Prioritaetsklassen gebaut sind.
        """
        keys: set[tuple[str, int]] = set()
        for key, rules in self._by_key.items():
            if any(rule.classification is not Classification.RAUSCHEN for rule in rules):
                keys.add(key)
        return keys

    @property
    def noise_keys(self) -> set[tuple[str, int]]:
        """Paare, fuer die es ausschliesslich Rauschregeln gibt."""
        return set(self._by_key) - self.rule_keys

    # --- Treffer -------------------------------------------------------------

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

        # Textbedingungen werden gegen die Beispiele geprueft, nicht gegen die
        # gesamte Gruppe - mehr steht nach der Verdichtung nicht zur Verfuegung.
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
        """Erzeugt die Befunde eines Laufs, sortiert nach Schwere."""
        findings: list[Finding] = []

        for group in enrichment.groups:
            for rule in self._by_key.get((group.provider, group.event_id), []):
                if not self._group_matches(rule, group):
                    continue
                severity, escalated = self._severity_for(rule, group)
                suppressed = (
                    rule.classification is Classification.RAUSCHEN and self.suppress_noise
                )
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        rule_source=rule.source,
                        severity=severity,
                        bedeutung=rule.bedeutung,
                        typische_ursachen=list(rule.typische_ursachen),
                        empfohlene_checks=list(rule.empfohlene_checks),
                        referenz=rule.referenz,
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
        """Kontextereignisse, falls die Gruppe selbst ein Marker ist."""
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
    """Provider/ID-Paare ohne Regeltreffer, mit Anzahl - die Arbeitsliste."""
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
