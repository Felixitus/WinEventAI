"""Arbeitsliste: Provider/ID-Paare ohne Eintrag in der Wissensbasis.

Jeder Lauf schreibt die beruehrten Paare ohne KB-Eintrag nach
``unknown_ids.csv``. So waechst die Wissensbasis aus echten Faellen statt aus
abgeschriebener Dokumentation.
"""

from __future__ import annotations

import csv
from pathlib import Path

from ..enrich.aggregate import EnrichmentResult
from .store import KnowledgeBase

HEADER = ("provider", "event_id", "anzahl", "kanal", "level", "beispielmeldung")


def collect_unknown(
    enrichment: EnrichmentResult,
    kb: KnowledgeBase,
    *,
    excerpt_chars: int = 200,
) -> list[dict[str, object]]:
    """Findet alle Gruppen, zu denen die Wissensbasis nichts Gesichertes sagt."""
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
                "anzahl": group.count,
                "kanal": group.channel,
                "level": group.level,
                "beispielmeldung": sample,
            }
        else:
            existing["anzahl"] = int(existing["anzahl"]) + group.count

    return sorted(rows.values(), key=lambda row: -int(row["anzahl"]))


def write_unknown_csv(path: Path, rows: list[dict[str, object]]) -> Path:
    """Schreibt die Arbeitsliste. UTF-8 mit BOM, damit Excel sie richtig oeffnet."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(HEADER), delimiter=";")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path
