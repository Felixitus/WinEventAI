"""Finding bundles: the only thing the model gets to see.

Never the raw log. A bundle contains the rule hit, period, frequency, a few
shortened sample messages, the system context and - only if verified - the
matching knowledge-base entry.

Token estimation without an external library: ``tiktoken`` downloads its BPE
files on first use and would therefore break offline operation; besides, its
tokenizer would be the wrong one for a local model anyway. Instead a
conservative heuristic plus self-calibration: the Ollama answer reports the
prompt tokens actually used in ``prompt_eval_count``, and the deviation goes
into the application log.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..enrich.burst import hour_label
from ..kb.store import KnowledgeBase
from ..rules.engine import KB_MISSING, Finding
from .redaction import Redactor


class SystemContext(BaseModel):
    """Concise system context attached to every bundle."""

    model_config = ConfigDict(extra="forbid")

    host: str
    operating_system: str
    period_from_utc: str
    period_to_utc: str
    boot_sessions: int
    incomplete_sources: list[str] = Field(default_factory=list)


class FindingBundle(BaseModel):
    """One bundle per finding cluster."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    rule: str
    rule_name: str
    severity: str
    provider: str
    event_id: int
    channel: str
    count: int
    first_seen_utc: str
    last_seen_utc: str
    bursts: list[str] = Field(default_factory=list)
    sample_messages: list[str] = Field(default_factory=list)
    citable_events: list[dict[str, Any]] = Field(default_factory=list)
    context_events: list[dict[str, Any]] = Field(default_factory=list)
    knowledge_base: dict[str, Any] | None = None
    knowledge_base_status: str = KB_MISSING
    system_context: SystemContext

    def as_prompt_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), ensure_ascii=False, indent=1)


def estimate_tokens(text: str, chars_per_token: float) -> int:
    """Conservative estimate. Rather too large than too small."""
    if chars_per_token <= 0:
        chars_per_token = 3.2
    return int(len(text) / chars_per_token) + 1


def build_bundle(
    finding: Finding,
    *,
    context: SystemContext,
    redactor: Redactor,
    kb: KnowledgeBase | None,
    max_samples: int,
    excerpt_chars: int,
    max_context_events: int = 12,
) -> FindingBundle:
    """Builds the bundle of a finding - redacted and shortened."""
    samples = finding.group.samples[:max_samples]
    redacted_samples = [redactor.record(sample) for sample in samples]

    kb_entry = kb.get(finding.group.provider, finding.group.event_id) if kb else None
    kb_payload: dict[str, Any] | None = None
    kb_status = KB_MISSING
    if kb_entry is not None:
        kb_status = str(kb_entry.confidence)
        if kb_entry.usable_in_prompt:
            kb_payload = {
                "meaning": kb_entry.meaning.strip(),
                "typical_causes": kb_entry.typical_causes,
                "checks": kb_entry.checks,
                "source": kb_entry.source_url,
            }

    context_events = [
        redactor.record(record) for record in finding.context_events[:max_context_events]
    ]

    return FindingBundle(
        finding_id=finding.finding_id,
        rule=finding.rule_id,
        rule_name=finding.rule_name,
        severity=str(finding.severity),
        provider=finding.group.provider,
        event_id=finding.group.event_id,
        channel=finding.group.channel,
        count=finding.group.count,
        first_seen_utc=finding.group.first_seen_utc.isoformat(),
        last_seen_utc=finding.group.last_seen_utc.isoformat(),
        bursts=[
            f"{hour_label(burst.hour_utc)}: {burst.count} occurrences"
            for burst in finding.group.bursts[:5]
        ],
        sample_messages=[record.excerpt(excerpt_chars) for record in redacted_samples],
        citable_events=[
            {
                "provider": record.provider,
                "event_id": record.event_id,
                "timestamp_utc": record.timestamp_utc.isoformat(),
            }
            for record in redacted_samples
        ],
        context_events=[
            {
                "provider": record.provider,
                "event_id": record.event_id,
                "timestamp_utc": record.timestamp_utc.isoformat(),
                "level": record.level,
                "message": record.excerpt(160),
            }
            for record in context_events
        ],
        knowledge_base=kb_payload,
        knowledge_base_status=kb_status,
        system_context=context,
    )


def split_bundle(bundle: FindingBundle, parts: int) -> list[FindingBundle]:
    """Splits a bundle that is too large into partial bundles - map-reduce, not truncation.

    Samples and context are split, not the figures: every partial bundle keeps
    frequency and period, so no partial statement arises that misrepresents the
    extent of the finding.
    """
    parts = max(parts, 1)
    if parts == 1:
        return [bundle]

    chunks: list[FindingBundle] = []
    sample_size = max(1, len(bundle.sample_messages) // parts)
    context_size = max(1, len(bundle.context_events) // parts)

    for index in range(parts):
        sample_slice = slice(index * sample_size, (index + 1) * sample_size)
        context_slice = slice(index * context_size, (index + 1) * context_size)
        samples = bundle.sample_messages[sample_slice]
        evidence = bundle.citable_events[sample_slice]
        contexts = bundle.context_events[context_slice]
        if not samples and not contexts:
            continue
        chunks.append(
            bundle.model_copy(
                update={
                    "finding_id": f"{bundle.finding_id}#{index + 1}",
                    "sample_messages": samples,
                    "citable_events": evidence,
                    "context_events": contexts,
                }
            )
        )
    return chunks or [bundle]


def fit_to_budget(
    bundle: FindingBundle,
    *,
    max_tokens: int,
    chars_per_token: float,
) -> list[FindingBundle]:
    """Makes sure every partial bundle fits into the budget."""
    text = bundle.as_prompt_json()
    tokens = estimate_tokens(text, chars_per_token)
    if tokens <= max_tokens:
        return [bundle]

    parts = (tokens // max_tokens) + 1
    pieces = split_bundle(bundle, parts)
    if len(pieces) == 1:
        # Not divisible any further: shorten the samples instead of losing the finding.
        shortened = bundle.model_copy(
            update={
                "sample_messages": [
                    text[: max(80, int(max_tokens * chars_per_token / 4))]
                    for text in bundle.sample_messages[:1]
                ],
                "context_events": bundle.context_events[:3],
            }
        )
        return [shortened]
    return pieces


def evidence_index(bundles: list[FindingBundle]) -> set[tuple[str, int]]:
    """All provider/id pairs that actually occur in the input material."""
    index: set[tuple[str, int]] = set()
    for bundle in bundles:
        for entry in bundle.citable_events + bundle.context_events:
            index.add((str(entry["provider"]), int(entry["event_id"])))
    return index
