"""Burst-Erkennung auf einem Stundenhistogramm.

Je Fingerprint ein Histogramm mit Stundenaufloesung: 168 Buckets bei sieben
Tagen, 720 bei dreissig. Der Speicherbedarf haengt damit an der Zahl
*verschiedener* Fingerprints, nicht an der Zahl der Events - und die Zahl
verschiedener Fingerprints ist auf realen Systemen klein.
"""

from __future__ import annotations

from datetime import datetime
from statistics import median

from pydantic import BaseModel, ConfigDict


class Burst(BaseModel):
    """Eine auffaellig dichte Stunde eines Fingerprints."""

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
    """Findet Stunden, die deutlich ueber der ueblichen Dichte liegen.

    Bezugswert ist die Dichte ueber das GESAMTE Analysefenster, nicht ueber die
    belegten Stunden. Das ist der entscheidende Unterschied: Treten 64 Ereignisse
    ausschliesslich in einer einzigen Stunde auf, ist der Median der belegten
    Stunden genau diese 64 - der Ausreisser versteckt sich hinter sich selbst,
    und der Burst wird nie erkannt. Gegen die Fensterdichte gerechnet ist genau
    diese Konzentration das Signal.

    Ohne ``window_hours`` faellt die Rechnung auf den Median der belegten Stunden
    zurueck; das ist schwaecher, aber besser als eine erfundene Fensterlaenge.
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
