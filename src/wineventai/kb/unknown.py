"""Work list: provider/id pairs without an entry in the knowledge base.

Every run writes the touched pairs without a KB entry to ``unknown_ids.csv``.
That way the knowledge base grows from real cases instead of copied
documentation.
"""

from __future__ import annotations

import csv
from pathlib import Path

from ..enrich.aggregate import EnrichmentResult
from .store import KnowledgeBase

HEADER = ("provider", "event_id", "count", "channel", "level", "sample_message")


def collect_unknown(
    enrichment: EnrichmentResult,
    kb: KnowledgeBase,
    *,
    excerpt_chars: int = 200,
) -> list[dict[str, object]]:
    """Finds all groups about which the knowledge base says nothing verified."""
    rows: dict[tuple[str, int], dict[str, object]] = {}
    for group in enrichment.groups:
        entry = kb.get(group.provider, group.event_id)
        if entry is not None and entry.usable_in_prompt:
            continue
        key = (group.provider, group.event_id)
        existing = rows.get(key)
        sample = group.samples[0].excerpt(excerpt_chars) if group.samples else ""
        if existing is None:
            rows[key] = {
                "provider": group.provider,
                "event_id": group.event_id,
                "count": group.count,
                "channel": group.channel,
                "level": group.level,
                "sample_message": sample,
            }
        else:
            existing["count"] = int(existing["count"]) + group.count

    return sorted(rows.values(), key=lambda row: -int(row["count"]))


def write_unknown_csv(path: Path, rows: list[dict[str, object]]) -> Path:
    """Writes the work list. UTF-8 with BOM so Excel opens it correctly."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(HEADER), delimiter=";")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path
