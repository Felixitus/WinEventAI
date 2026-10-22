"""Bestandsaufnahme der Wissensbasis (``wineventai kb stats``).

Frueher hiess dieser Befehl ``kb bench``. Der Name war irrefuehrend: Ein
"Bench" ist in diesem Projekt der Abnahmetest fuer die Modellwahl
(HANDOVER Punkt 9.5) und befragt ein Sprachmodell. Diese Datei befragt kein
Modell, sondern zaehlt nur, wie vollstaendig die Eintraege sind. Der Name
``bench`` bleibt deshalb fuer den echten Abnahmetest frei.

Die Auswertung (``compute_stats``) kennt nur eine Liste von Eintraegen und ist
damit ohne Datenbank testbar; die Ausgabe (``format_stats``) ist davon
getrennt.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from .store import KbConfidence, KbEntry


@dataclass(slots=True)
class KbStats:
    """Zahlen zur Vollstaendigkeit der Wissensbasis."""

    total: int = 0
    by_confidence: dict[str, int] = field(default_factory=dict)
    usable_in_prompt: int = 0
    without_meaning: list[str] = field(default_factory=list)
    without_causes: list[str] = field(default_factory=list)
    without_checks: list[str] = field(default_factory=list)
    without_source: list[str] = field(default_factory=list)


def compute_stats(entries: Iterable[KbEntry]) -> KbStats:
    """Zaehlt Eintraege nach Vertrauensstufe und listet Luecken je Schluessel.

    Gelistet werden Schluessel (``provider:event_id``), nicht nur Zahlen: Wer
    die Wissensbasis pflegt, braucht die Arbeitsliste, nicht die Statistik.
    """
    stats = KbStats()
    confidence = Counter()
    for entry in entries:
        stats.total += 1
        confidence[str(entry.confidence)] += 1
        if entry.usable_in_prompt:
            stats.usable_in_prompt += 1
        if not entry.bedeutung.strip():
            stats.without_meaning.append(entry.key)
        if not entry.typische_ursachen:
            stats.without_causes.append(entry.key)
        if not entry.checks:
            stats.without_checks.append(entry.key)
        if entry.confidence == KbConfidence.SICHER and not entry.quelle_url:
            # "sicher" ohne Quelle ist eine Behauptung, keine Pruefung.
            stats.without_source.append(entry.key)
    # Feste Reihenfolge, auch fuer Stufen ohne Eintrag: Eine fehlende Zeile
    # liest sich sonst wie "gibt es nicht" statt wie "null".
    stats.by_confidence = {level.value: confidence.get(level.value, 0) for level in KbConfidence}
    return stats


def format_stats(stats: KbStats, location: str) -> list[str]:
    """Baut die Textausgabe fuer die Kommandozeile."""

    def share(count: int) -> str:
        return f"{count / stats.total * 100:5.1f} %" if stats.total else "  -  "

    def listing(title: str, keys: list[str]) -> list[str]:
        if not keys:
            return [f"{title}: keine"]
        return [f"{title}: {len(keys)}", *(f"    {key}" for key in keys)]

    lines = [f"Wissensbasis: {location}", f"Eintraege gesamt: {stats.total}", ""]
    lines.append("Vertrauensstufen:")
    for level, count in stats.by_confidence.items():
        lines.append(f"    {level:<9} {count:>5}  {share(count)}")
    lines.append(
        f"Im Prompt verwendbar: {stats.usable_in_prompt} "
        "(nur 'sicher' mit Bedeutung geht an das Sprachmodell)"
    )
    lines.append("")
    lines += listing("Ohne Bedeutung", stats.without_meaning)
    lines += listing("Ohne typische Ursachen", stats.without_causes)
    lines += listing("Ohne Pruefschritte", stats.without_checks)
    lines += listing("'sicher' ohne Quellenangabe", stats.without_source)
    return lines


__all__ = ["KbStats", "compute_stats", "format_stats"]
