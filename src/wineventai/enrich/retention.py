"""Retention: welche Rohdaten behalten werden.

Eine reine Obergrenze je Kanal ist die falsche Konstruktion. Auf einem Rechner,
der 400.000 mal DistributedCOM 10016 protokolliert, ist das Kontingent von
Rauschen aufgebraucht, bevor der Bluescheck an der Reihe ist. Deshalb vier
Prioritaetsklassen:

* **P1** Records, die eine Regel treffen - immer behalten.
* **P2** Records im Kontextfenster um einen Marker - immer behalten.
* **P3** ``level <= 2`` (kritisch/fehler) - bis zu einem Anteil des Kontingents.
* **P4** alles uebrige - Reservoir-Sampling im Restkontingent, damit die
  Stichprobe ueber das Zeitfenster streut, statt am Anfang zu klumpen.

Das Aggregat ist davon NICHT betroffen: Zaehler, erstes und letztes Vorkommen
und das Histogramm sehen jeden gelesenen Record. Abgeschnitten wird nur der
Rohdatenanhang.
"""

from __future__ import annotations

import random
from enum import IntEnum

from ..normalize.schema import EventRecord


class Priority(IntEnum):
    RULE_HIT = 1
    CONTEXT = 2
    ERROR_LEVEL = 3
    OTHER = 4


class RetentionReservoir:
    """Behaelt Records nach Prioritaet statt nach Ankunftsreihenfolge."""

    def __init__(
        self,
        *,
        limit: int,
        error_share: float = 0.6,
        seed: int = 1701,
    ) -> None:
        self.limit = max(limit, 0)
        self.error_quota = int(self.limit * error_share)
        self._rng = random.Random(seed)
        self._kept: dict[Priority, list[EventRecord]] = {p: [] for p in Priority}
        self._seen_other = 0
        self._seen_error = 0
        self.dropped = 0

    # --- Aufnahme ------------------------------------------------------------

    def offer(self, record: EventRecord, priority: Priority) -> None:
        """Bietet einen Record zur Aufbewahrung an."""
        if priority in (Priority.RULE_HIT, Priority.CONTEXT):
            self._kept[priority].append(record)
            return

        if priority is Priority.ERROR_LEVEL:
            self._seen_error += 1
            bucket = self._kept[Priority.ERROR_LEVEL]
            if len(bucket) < self.error_quota:
                bucket.append(record)
            else:
                self._replace_randomly(bucket, record, self._seen_error)
            return

        self._seen_other += 1
        remaining = self.limit - self.error_quota
        bucket = self._kept[Priority.OTHER]
        if len(bucket) < remaining:
            bucket.append(record)
        else:
            self._replace_randomly(bucket, record, self._seen_other)

    def _replace_randomly(self, bucket: list[EventRecord], record: EventRecord, seen: int) -> None:
        """Klassisches Reservoir-Sampling: gleiche Chance fuer jeden Record."""
        if not bucket:
            self.dropped += 1
            return
        index = self._rng.randrange(seen)
        if index < len(bucket):
            bucket[index] = record
        else:
            self.dropped += 1

    # --- Ergebnis ------------------------------------------------------------

    @property
    def truncated(self) -> bool:
        return self.dropped > 0

    def records(self) -> list[EventRecord]:
        """Alle behaltenen Records, absteigend nach Zeit."""
        out: list[EventRecord] = []
        seen_hashes: set[tuple[str, int, str]] = set()
        for priority in Priority:
            for record in self._kept[priority]:
                key = (record.channel, record.record_id or -1, record.raw_hash)
                if key in seen_hashes:
                    continue
                seen_hashes.add(key)
                out.append(record)
        out.sort(key=lambda record: record.timestamp_utc, reverse=True)
        return out

    def stats(self) -> dict[str, int]:
        return {
            "regeltreffer": len(self._kept[Priority.RULE_HIT]),
            "kontext": len(self._kept[Priority.CONTEXT]),
            "fehlerstufe": len(self._kept[Priority.ERROR_LEVEL]),
            "stichprobe": len(self._kept[Priority.OTHER]),
            "verworfen": self.dropped,
        }
