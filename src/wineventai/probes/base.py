"""Context probes: shared vocabulary.

A probe measures the current state of a system to explain or refute a finding.
It is not a free-standing tool: every probe hangs on a finding and appears in
that finding's card.

**The caveat that accompanies every probe.** A probe measures NOW. The finding
arose BACK THEN. A ping that succeeds today says nothing about a name
resolution that ran into a timeout five days ago. The time gap is therefore a
field in the model and not a text snippet - just as "not logged" in security
mode is a status and not a footnote. Whoever reads a green probe as all-clear
otherwise draws the same wrong conclusion as with "no findings" on a channel
that was never collected.

All probes are read-only and stay within the local network. No speed test
against an internet service: it would break "works offline", "no telemetry"
(the own IP would go to the provider) and "read-only" (it saturates the line
and produces on a troubled machine exactly the disturbance one is looking for).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # pragma: no cover
    # Deliberately for type checking only: ``rules.engine`` imports
    # ``ProbeResult`` to attach it to the finding. A runtime import in the
    # other direction would be a cycle. The probes only need ``Finding`` as a
    # type annotation anyway - thanks to ``from __future__ import annotations``
    # it stays text.
    from ..rules.engine import Finding


class ProbeStatus(StrEnum):
    OK = "unremarkable"
    WARN = "conspicuous"
    FAILED = "failed"
    NOT_APPLICABLE = "not applicable"
    NO_PERMISSION = "no permission"
    TIMED_OUT = "timed out"
    DISABLED = "disabled"
    UNAVAILABLE = "not measurable"


#: States in which the probe said nothing. "unremarkable" is a measurement;
#: everything here is the absence of a measurement - and that must never look
#: like an all-clear in the report.
NO_MEASUREMENT: frozenset[ProbeStatus] = frozenset(
    {
        ProbeStatus.FAILED,
        ProbeStatus.NOT_APPLICABLE,
        ProbeStatus.NO_PERMISSION,
        ProbeStatus.TIMED_OUT,
        ProbeStatus.DISABLED,
        ProbeStatus.UNAVAILABLE,
    }
)


class ProbeBearing(StrEnum):
    """What the measurement means for the finding."""

    SUPPORTS = "supports the finding"
    WEAKENS = "speaks against it"
    INCONCLUSIVE = "says nothing about it"


class ProbeResult(BaseModel):
    """The result of a measurement, related to a finding."""

    model_config = ConfigDict(extra="forbid")

    probe_id: str
    title: str
    status: ProbeStatus
    bearing: ProbeBearing = ProbeBearing.INCONCLUSIVE
    summary: str = ""
    details: list[str] = Field(default_factory=list)
    target: str | None = None
    finding_id: str | None = None
    measured_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finding_last_seen_utc: datetime | None = None
    duration_seconds: float = 0.0
    detail_error: str | None = None

    @property
    def measured(self) -> bool:
        """True if something was actually measured."""
        return self.status not in NO_MEASUREMENT

    @property
    def age(self) -> timedelta | None:
        """Gap between the measurement and the last occurrence of the finding."""
        if self.finding_last_seen_utc is None:
            return None
        return self.measured_utc - self.finding_last_seen_utc

    def age_note(self) -> str:
        """The time caveat in plain text.

        Appears in every representation of a probe. The larger the gap, the
        clearer the wording - after several days the measurement is practically
        worthless for the finding, and that should be stated.
        """
        gap = self.age
        if gap is None:
            return "Measured now; a relation to the time of the finding is not established."

        hours = gap.total_seconds() / 3600.0
        if hours < 1:
            return "Measured shortly after the last occurrence."
        if hours < 24:
            return (
                f"Measured {hours:.0f} hours after the last occurrence - "
                "the state may have changed since."
            )
        days = hours / 24.0
        return (
            f"Measured {days:.0f} days after the last occurrence. This measurement "
            "says nothing about the state at the time of the finding."
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "probe": self.probe_id,
            "title": self.title,
            "status": str(self.status),
            "bearing": str(self.bearing),
            "measured": self.measured,
            "summary": self.summary,
            "details": self.details,
            "target": self.target,
            "finding_id": self.finding_id,
            "measured_utc": self.measured_utc.isoformat(),
            "time_caveat": self.age_note(),
            "duration_s": round(self.duration_seconds, 2),
            "error": self.detail_error,
        }


class Probe(Protocol):
    """Interface of every probe.

    ``target_for`` is the core of the decision "context probe instead of a
    toolbox": a probe only runs if a finding requests it, and it knows from the
    finding WHAT to measure.
    """

    probe_id: str
    title: str

    def target_for(self, finding: Finding) -> str | None:
        """What this probe would measure for this finding. ``None`` = nothing."""
        ...

    def run(self, targets: dict[str, list[Finding]]) -> list[ProbeResult]:
        """Measures all requested targets and assigns the results."""
        ...


def disabled_result(probe_id: str, title: str, reason: str) -> ProbeResult:
    return ProbeResult(
        probe_id=probe_id,
        title=title,
        status=ProbeStatus.DISABLED,
        summary=reason,
    )


def unavailable_result(
    probe_id: str, title: str, reason: str, *, error: str | None = None
) -> ProbeResult:
    return ProbeResult(
        probe_id=probe_id,
        title=title,
        status=ProbeStatus.UNAVAILABLE,
        summary=reason,
        detail_error=error,
    )


def failed_result(
    probe_id: str, title: str, reason: str, *, target: str | None = None, error: str | None = None
) -> ProbeResult:
    return ProbeResult(
        probe_id=probe_id,
        title=title,
        status=ProbeStatus.FAILED,
        summary=reason,
        target=target,
        detail_error=error,
    )


def timed_out_result(probe_id: str, title: str, seconds: float) -> ProbeResult:
    return ProbeResult(
        probe_id=probe_id,
        title=title,
        status=ProbeStatus.TIMED_OUT,
        summary=(
            f"The measurement was aborted after {seconds:.0f} seconds. "
            "What was read until then is not enough for a statement."
        ),
        duration_seconds=seconds,
    )
