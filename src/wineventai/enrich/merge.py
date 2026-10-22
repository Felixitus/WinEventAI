"""Merging the channel streams.

Get-WinEvent delivers the newest records first. Instead of working against
that, the enricher uses it: ``heapq.merge`` combines the per-channel streams,
which are already sorted, into one descending overall stream without holding
anything completely in memory.

Two pleasant consequences:

* "All events five minutes BEFORE the crash" becomes forward buffering: the
  events in question arrive AFTER the marker. No look back needed.
* An abort hits the oldest data, not the newest.
"""

from __future__ import annotations

import heapq
from collections.abc import Iterable, Iterator

from ..normalize.schema import EventRecord


def _sorted_descending(records: Iterable[EventRecord]) -> list[EventRecord]:
    return sorted(records, key=lambda record: record.timestamp_utc, reverse=True)


def merge_descending(streams: Iterable[Iterable[EventRecord]]) -> Iterator[EventRecord]:
    """Combines several record streams into one stream sorted descending.

    Every input stream is sorted descending itself, to be safe. For live
    channels that is a cheap no-op; for .evtx files, whose order is not
    guaranteed, it is the place where the order is established.
    """
    prepared = [_sorted_descending(stream) for stream in streams]
    prepared = [stream for stream in prepared if stream]
    if not prepared:
        return iter(())
    return heapq.merge(
        *prepared, key=lambda record: record.timestamp_utc, reverse=True
    )


def merge_sources(sources: dict[str, list[EventRecord]]) -> Iterator[EventRecord]:
    """Convenient entry for the result of ``collect.load_records``."""
    return merge_descending(sources.values())
