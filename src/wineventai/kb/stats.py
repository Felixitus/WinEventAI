"""Inventory of the knowledge base (``wineventai kb stats``).

This command used to be called ``kb bench``. The name was misleading: in this
project a "bench" is the acceptance test for the model choice (HANDOVER item
9.5) and queries a language model. This file queries no model; it only counts
how complete the entries are. The name ``bench`` therefore stays free for the
real acceptance test.

The evaluation (``compute_stats``) only knows a list of entries and is
therefore testable without a database; the output (``format_stats``) is kept
separate.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from .store import KbConfidence, KbEntry


@dataclass(slots=True)
class KbStats:
    """Figures on the completeness of the knowledge base."""

    total: int = 0
    by_confidence: dict[str, int] = field(default_factory=dict)
    usable_in_prompt: int = 0
    without_meaning: list[str] = field(default_factory=list)
    without_causes: list[str] = field(default_factory=list)
    without_checks: list[str] = field(default_factory=list)
    without_source: list[str] = field(default_factory=list)


def compute_stats(entries: Iterable[KbEntry]) -> KbStats:
    """Counts entries by confidence level and lists gaps per key.

    Keys (``provider:event_id``) are listed, not just numbers: whoever
    maintains the knowledge base needs the work list, not the statistics.
    """
    stats = KbStats()
    confidence = Counter()
    for entry in entries:
        stats.total += 1
        confidence[str(entry.confidence)] += 1
        if entry.usable_in_prompt:
            stats.usable_in_prompt += 1
        if not entry.meaning.strip():
            stats.without_meaning.append(entry.key)
        if not entry.typical_causes:
            stats.without_causes.append(entry.key)
        if not entry.checks:
            stats.without_checks.append(entry.key)
        if entry.confidence == KbConfidence.VERIFIED and not entry.source_url:
            # "verified" without a source is a claim, not a check.
            stats.without_source.append(entry.key)
    # Fixed order, also for levels without entries: a missing row would
    # otherwise read as "does not exist" instead of "zero".
    stats.by_confidence = {level.value: confidence.get(level.value, 0) for level in KbConfidence}
    return stats


def format_stats(stats: KbStats, location: str) -> list[str]:
    """Builds the text output for the command line."""

    def share(count: int) -> str:
        return f"{count / stats.total * 100:5.1f} %" if stats.total else "  -  "

    def listing(title: str, keys: list[str]) -> list[str]:
        if not keys:
            return [f"{title}: none"]
        return [f"{title}: {len(keys)}", *(f"    {key}" for key in keys)]

    lines = [f"Knowledge base: {location}", f"Entries total: {stats.total}", ""]
    lines.append("Confidence levels:")
    for level, count in stats.by_confidence.items():
        lines.append(f"    {level:<11} {count:>5}  {share(count)}")
    lines.append(
        f"Usable in the prompt: {stats.usable_in_prompt} "
        "(only 'verified' with a meaning goes to the language model)"
    )
    lines.append("")
    lines += listing("Without meaning", stats.without_meaning)
    lines += listing("Without typical causes", stats.without_causes)
    lines += listing("Without checks", stats.without_checks)
    lines += listing("'verified' without source", stats.without_source)
    return lines


__all__ = ["KbStats", "compute_stats", "format_stats"]
