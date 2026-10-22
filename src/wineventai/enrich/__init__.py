"""Enricher: Deduplizierung, Burst-Erkennung, Boot-Sessions, Korrelation."""

from .aggregate import Enricher, EnrichmentResult, FingerprintGroup
from .boot import BootSession, BootTracker
from .burst import Burst, detect_bursts, hour_label
from .correlate import MARKER_KEYS, ContextCollector, ContextWindow
from .fingerprint import describe_fingerprint, fingerprint_for
from .merge import merge_descending, merge_sources
from .retention import Priority, RetentionReservoir

__all__ = [
    "MARKER_KEYS",
    "BootSession",
    "BootTracker",
    "Burst",
    "ContextCollector",
    "ContextWindow",
    "Enricher",
    "EnrichmentResult",
    "FingerprintGroup",
    "Priority",
    "RetentionReservoir",
    "describe_fingerprint",
    "detect_bursts",
    "fingerprint_for",
    "hour_label",
    "merge_descending",
    "merge_sources",
]
