"""Kontext-Sonden.

Eine Sonde ist kein Werkzeug im Werkzeugkasten, sondern der Nachsatz zu einem
Befund: Sie laeuft nur, wenn ein Befund sie anfordert, sie misst genau das, was
dieser Befund nahelegt, und sie erscheint in dessen Karte. Ein Menue voller
Knoepfe - "Ping", "Traceroute", "SMART" - waere leichter zu bauen und deutlich
weniger wert: Wer selbst weiss, welchen Knopf er druecken muss, braucht dieses
Werkzeug nicht.
"""

from .base import (
    NO_MEASUREMENT,
    Probe,
    ProbeBearing,
    ProbeResult,
    ProbeStatus,
    disabled_result,
    failed_result,
    timed_out_result,
    unavailable_result,
)
from .runner import ProbeRunner, build_probes

__all__ = [
    "NO_MEASUREMENT",
    "Probe",
    "ProbeBearing",
    "ProbeResult",
    "ProbeRunner",
    "ProbeStatus",
    "build_probes",
    "disabled_result",
    "failed_result",
    "timed_out_result",
    "unavailable_result",
]
