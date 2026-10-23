"""Comparison with the previous run of the same machine.

The question a supporter asks on the second visit is not "what is wrong?" but
"what changed since last time?". This module answers it from the run
directories alone - the previous run's ``derived/findings.json`` and
``run.json`` - so the pipeline boundary holds: nothing here touches Windows.

Three categories, and the wording is chosen with care:

* **new** - a finding the previous run did not have.
* **not seen in this window** - deliberately NOT "resolved". The current window
  may simply not reach back to when it happened, and the absence of an event is
  no proof of a repair.
* **more frequent** - compared per day, not per run: the two time windows may
  differ in length, and 20 hits in 30 days are fewer than 10 in 7.

Findings are matched by ``finding_id`` (rule plus fingerprint). The fingerprint
hangs on the masked property vector, so the same fault matches across runs even
when process ids and timestamps differ.

If the two runs differ in security mode, findings that only the security rules
produce are left out of the comparison - otherwise switching the mode on would
report every security indication as "new".
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..applog import get_log
from ..collect.rundir import RunDirectory, RunMeta
from ..rules.engine import Finding

FINDINGS_FILE = "findings.json"

Change = Literal["new", "not seen in this window", "more frequent"]


class FindingChange(BaseModel):
    """One finding that changed between the two runs."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    rule_name: str
    severity: str
    change: Change
    count_now: int | None = None
    count_before: int | None = None
    per_day_now: float | None = None
    per_day_before: float | None = None


class RunComparison(BaseModel):
    """Result of the comparison - including why there is none."""

    model_config = ConfigDict(extra="forbid")

    available: bool = False
    note: str = ""
    previous_run_id: str | None = None
    previous_started_utc: datetime | None = None
    new: list[FindingChange] = Field(default_factory=list)
    not_seen: list[FindingChange] = Field(default_factory=list)
    more_frequent: list[FindingChange] = Field(default_factory=list)

    @property
    def unchanged(self) -> bool:
        return self.available and not (self.new or self.not_seen or self.more_frequent)

    def summary(self) -> str:
        """One line for the GUI and the report."""
        if not self.available:
            return self.note
        when = (
            self.previous_started_utc.strftime("%Y-%m-%d %H:%M UTC")
            if self.previous_started_utc
            else self.previous_run_id or "?"
        )
        if self.unchanged:
            return f"Since the previous run ({when}): no change in the findings."
        return (
            f"Since the previous run ({when}): {len(self.new)} new, "
            f"{len(self.more_frequent)} more frequent, "
            f"{len(self.not_seen)} not seen in this window."
        )

    def change_for(self, finding_id: str) -> FindingChange | None:
        for entry in self.new + self.more_frequent:
            if entry.finding_id == finding_id:
                return entry
        return None


def _window_days(meta: RunMeta) -> float:
    seconds = (meta.requested_to_utc - meta.requested_from_utc).total_seconds()
    return max(seconds / 86400.0, 1.0 / 24.0)


def find_previous_run(run: RunDirectory) -> RunDirectory | None:
    """The latest earlier, analyzed run of the same machine next to this one.

    "Analyzed" means it has a ``findings.json`` - a run that was only collected
    has nothing to compare against. Unreadable directories are skipped, not
    fatal: one broken old run must not cost the current report.
    """
    current = run.read_meta()
    best: tuple[datetime, RunDirectory] | None = None
    for candidate in run.path.parent.iterdir():
        if candidate == run.path or not candidate.is_dir():
            continue
        if not (candidate / "derived" / FINDINGS_FILE).is_file():
            continue
        try:
            other = RunDirectory.open(candidate)
            meta = other.read_meta()
        except Exception:  # noqa: BLE001 - a broken old run is skipped, not fatal
            continue
        if meta.host.lower() != current.host.lower():
            continue
        if meta.started_utc >= current.started_utc:
            continue
        if best is None or meta.started_utc > best[0]:
            best = (meta.started_utc, other)
    return best[1] if best else None


def _previous_findings(run: RunDirectory) -> list[dict[str, Any]]:
    path = run.derived_dir / FINDINGS_FILE
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [entry for entry in payload if isinstance(entry, dict)]


def compare_runs(
    current_meta: RunMeta,
    findings: list[Finding],
    previous: RunDirectory | None,
    *,
    increase_factor: float,
    min_count: int,
) -> RunComparison:
    """Compares the visible findings of this run with the previous run."""
    if previous is None:
        return RunComparison(
            note=(
                "No earlier analyzed run of this machine in the run folder - "
                "nothing to compare. The next run will be compared with this one."
            )
        )

    try:
        previous_meta = previous.read_meta()
        before = _previous_findings(previous)
    except (OSError, ValueError) as exc:
        get_log().warn("Previous run not readable", run=str(previous.path), error=str(exc))
        return RunComparison(note=f"The previous run could not be read ({exc}).")

    modes_differ = previous_meta.security_mode != current_meta.security_mode
    days_now = _window_days(current_meta)
    days_before = _window_days(previous_meta)

    now = {
        finding.finding_id: finding
        for finding in findings
        if not finding.suppressed and not (modes_differ and finding.security_indicator)
    }
    then = {
        str(entry.get("finding_id")): entry
        for entry in before
        if not entry.get("suppressed")
        and not (modes_differ and entry.get("security_indicator"))
    }

    result = RunComparison(
        available=True,
        previous_run_id=previous_meta.run_id,
        previous_started_utc=previous_meta.started_utc,
        note=(
            "Security indications are not compared: only one of the two runs used "
            "the security mode."
            if modes_differ
            else ""
        ),
    )

    for finding_id, finding in now.items():
        count = finding.group.count
        entry = then.get(finding_id)
        if entry is None:
            result.new.append(
                FindingChange(
                    finding_id=finding_id,
                    rule_name=finding.rule_name,
                    severity=str(finding.severity),
                    change="new",
                    count_now=count,
                    per_day_now=round(count / days_now, 2),
                )
            )
            continue
        count_before = int((entry.get("group") or {}).get("count") or 0)
        rate_now = count / days_now
        rate_before = count_before / days_before
        if count >= min_count and rate_now >= increase_factor * max(rate_before, 1e-9):
            result.more_frequent.append(
                FindingChange(
                    finding_id=finding_id,
                    rule_name=finding.rule_name,
                    severity=str(finding.severity),
                    change="more frequent",
                    count_now=count,
                    count_before=count_before,
                    per_day_now=round(rate_now, 2),
                    per_day_before=round(rate_before, 2),
                )
            )

    for finding_id, entry in then.items():
        if finding_id in now:
            continue
        result.not_seen.append(
            FindingChange(
                finding_id=finding_id,
                rule_name=str(entry.get("rule_name") or entry.get("rule") or finding_id),
                severity=str(entry.get("severity") or ""),
                change="not seen in this window",
                count_before=int((entry.get("group") or {}).get("count") or 0),
            )
        )
    return result
