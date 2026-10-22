"""Burst detection on an hourly histogram.

One histogram per fingerprint with hourly resolution: 168 buckets for seven
days, 720 for thirty. Memory use therefore depends on the number of *distinct*
fingerprints, not on the number of events - and the number of distinct
fingerprints is small on real systems.
"""

from __future__ import annotations

from datetime import datetime
from statistics import median

from pydantic import BaseModel, ConfigDict


class Burst(BaseModel):
    """A conspicuously dense hour of a fingerprint."""

    model_config = ConfigDict(extra="forbid")

    hour_utc: str
    count: int
    baseline: float


def hour_key(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H")


def hour_label(key: str) -> str:
    return key.replace("T", " ") + ":00 UTC"


def detect_bursts(
    hourly: dict[str, int],
    *,
    factor: float,
    min_count: int,
    window_hours: float | None = None,
) -> list[Burst]:
    """Finds hours that lie clearly above the usual density.

    The baseline is the density over the WHOLE analysis window, not over the
    occupied hours. That is the decisive difference: if 64 events occur only in
    one single hour, the median of the occupied hours is exactly those 64 - the
    outlier hides behind itself and the burst is never detected. Measured
    against the window density, exactly this concentration is the signal.

    Without ``window_hours`` the calculation falls back to the median of the
    occupied hours; that is weaker, but better than an invented window length.
    """
    if not hourly:
        return []
    counts = sorted(hourly.values())
    if window_hours and window_hours > 0:
        baseline = sum(counts) / float(window_hours)
    else:
        baseline = float(median(counts))
    threshold = max(baseline * factor, float(min_count))

    bursts = [
        Burst(hour_utc=key, count=value, baseline=baseline)
        for key, value in hourly.items()
        if value >= threshold and value >= min_count
    ]
    bursts.sort(key=lambda burst: (-burst.count, burst.hour_utc))
    return bursts
