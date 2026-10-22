"""Zusammenfuehrung der Kanalstroeme.

Get-WinEvent liefert die neuesten Records zuerst. Statt dagegen anzuarbeiten,
nutzt der Enricher das: ``heapq.merge`` vereinigt die je Kanal bereits sortierten
Stroeme zu einem absteigenden Gesamtstrom, ohne irgendetwas vollstaendig im
Speicher zu halten.

Zwei angenehme Folgen:

* "Alle Events fuenf Minuten VOR dem Absturz" wird zur Vorwaerts-Pufferung: die
  fraglichen Events kommen NACH dem Marker an. Kein Rueckblick noetig.
* Ein Abbruch trifft das Aelteste, nicht das Neueste.
"""

from __future__ import annotations

import heapq
from collections.abc import Iterable, Iterator

from ..normalize.schema import EventRecord


def _sorted_descending(records: Iterable[EventRecord]) -> list[EventRecord]:
    return sorted(records, key=lambda record: record.timestamp_utc, reverse=True)


def merge_descending(streams: Iterable[Iterable[EventRecord]]) -> Iterator[EventRecord]:
    """Vereinigt mehrere Record-Stroeme zu einem absteigend sortierten Strom.

    Jeder Eingangsstrom wird zur Sicherheit selbst absteigend sortiert. Fuer
    Live-Kanaele ist das ein billiger No-Op; fuer .evtx-Dateien, deren Reihenfolge
    nicht garantiert ist, ist es die Stelle, an der die Ordnung hergestellt wird.
    """
    prepared = [_sorted_descending(stream) for stream in streams]
    prepared = [stream for stream in prepared if stream]
    if not prepared:
        return iter(())
    return heapq.merge(
        *prepared, key=lambda record: record.timestamp_utc, reverse=True
    )


def merge_sources(sources: dict[str, list[EventRecord]]) -> Iterator[EventRecord]:
    """Bequemer Einstieg fuer das Ergebnis von ``collect.load_records``."""
    return merge_descending(sources.values())
