"""Retention: which raw data is kept.

A plain upper limit per channel is the wrong construction. On a machine that
logs DistributedCOM 10016 400,000 times, the quota is used up by noise before
the bug check gets its turn. Hence four priority classes:

* **P1** records that hit a rule - always kept.
* **P2** records in the context window around a marker - always kept.
* **P3** ``level <= 2`` (critical/error) - up to a share of the quota.
* **P4** everything else - reservoir sampling in the remaining quota, so the
  sample spreads over the time window instead of clumping at the start.

The aggregate is NOT affected by this: counters, first and last occurrence and
the histogram see every record read. Only the raw-data appendix is cut.
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
    """Keeps records by priority instead of by order of arrival."""

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

    # --- Intake --------------------------------------------------------------

    def offer(self, record: EventRecord, priority: Priority) -> None:
        """Offers a record for retention."""
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
        """Classic reservoir sampling: the same chance for every record."""
        if not bucket:
            self.dropped += 1
            return
        index = self._rng.randrange(seen)
        if index < len(bucket):
            bucket[index] = record
        else:
            self.dropped += 1

    # --- Result --------------------------------------------------------------

    @property
    def truncated(self) -> bool:
        return self.dropped > 0

    def records(self) -> list[EventRecord]:
        """All retained records, descending by time."""
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
            "rule_hits": len(self._kept[Priority.RULE_HIT]),
            "context": len(self._kept[Priority.CONTEXT]),
            "error_level": len(self._kept[Priority.ERROR_LEVEL]),
            "sample": len(self._kept[Priority.OTHER]),
            "dropped": self.dropped,
        }
