"""Comparison with the previous run: new, more frequent, not seen.

The wording is part of the contract: "not seen in this window" must never turn
into "resolved", and a longer window must not make a finding look more
frequent.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from wineventai.analyze import analyze_run
from wineventai.collect.rundir import RunDirectory
from wineventai.config import load_config
from wineventai.report.compare import compare_runs, find_previous_run

CONFIG = load_config(
    overrides={
        "ai": {"enabled": False},
        "rules": {"security_mode": True},
        "probes": {"enabled": False},
    }
)


@pytest.fixture
def current(fixture_run):
    result = analyze_run(fixture_run, CONFIG, write_outputs=False)
    visible = [finding for finding in result.findings if not finding.suppressed]
    assert len(visible) >= 2, "the fixture needs at least two visible findings"
    return fixture_run, result.findings, visible


def _previous(run: RunDirectory, findings: list[dict], *, days_earlier: int = 1,
              host: str | None = None, window_days: float | None = None,
              security_mode: bool | None = None, name: str = "previous") -> RunDirectory:
    meta = run.read_meta()
    path = run.path.parent / name
    (path / "derived").mkdir(parents=True)
    other = RunDirectory(path)
    window_to = meta.requested_to_utc - timedelta(days=days_earlier)
    window = (
        timedelta(days=window_days)
        if window_days is not None
        else meta.requested_to_utc - meta.requested_from_utc
    )
    other.write_meta(
        meta.model_copy(
            update={
                "run_id": name,
                "started_utc": meta.started_utc - timedelta(days=days_earlier),
                "host": host or meta.host,
                "requested_to_utc": window_to,
                "requested_from_utc": window_to - window,
                "security_mode": meta.security_mode if security_mode is None else security_mode,
            }
        )
    )
    (path / "derived" / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    return other


def _as_stored(finding, *, count: int | None = None) -> dict:
    payload = finding.to_public_dict()
    if count is not None:
        payload["group"]["count"] = count
    return json.loads(json.dumps(payload, default=str))


def _compare(run, findings):
    return compare_runs(
        run.read_meta(), findings, find_previous_run(run), increase_factor=2.0, min_count=3
    )


def test_without_a_previous_run_the_report_says_so(current) -> None:
    run, findings, _ = current
    result = _compare(run, findings)
    assert not result.available
    assert "nothing to compare" in result.summary()


def test_the_same_findings_mean_no_change(current) -> None:
    run, findings, visible = current
    _previous(run, [_as_stored(finding) for finding in visible])
    result = _compare(run, findings)
    assert result.available and result.unchanged
    assert "no change" in result.summary()


def test_a_finding_missing_before_is_new(current) -> None:
    run, findings, visible = current
    _previous(run, [_as_stored(finding) for finding in visible[1:]])
    result = _compare(run, findings)
    assert [entry.finding_id for entry in result.new] == [visible[0].finding_id]


def test_a_finding_missing_now_is_not_seen_and_never_resolved(current) -> None:
    run, findings, visible = current
    gone = _as_stored(visible[0])
    gone["finding_id"] = "disk-io-error::deadbeef"
    gone["rule_name"] = "Disk I/O error"
    _previous(run, [_as_stored(finding) for finding in visible] + [gone])
    result = _compare(run, findings)
    assert [entry.rule_name for entry in result.not_seen] == ["Disk I/O error"]
    assert "resolved" not in result.summary().lower()
    assert result.not_seen[0].change == "not seen in this window"


def test_more_frequent_is_measured_per_day_not_per_run(current) -> None:
    run, findings, visible = current
    target = max(visible, key=lambda finding: finding.group.count)
    assert target.group.count >= 3
    days_now = (run.read_meta().requested_to_utc - run.read_meta().requested_from_utc).days

    # Same count before, but over a window four times as long: four times the
    # rate now - more frequent.
    stored = [_as_stored(finding) for finding in visible if finding is not target]
    stored.append(_as_stored(target, count=target.group.count))
    _previous(run, stored, window_days=days_now * 4)
    result = _compare(run, findings)
    frequent = {entry.finding_id for entry in result.more_frequent}
    assert target.finding_id in frequent
    # Only findings with enough hits may count as a trend.
    assert all(entry.count_now >= 3 for entry in result.more_frequent)


def test_a_longer_current_window_alone_is_no_increase(current) -> None:
    run, findings, visible = current
    target = max(visible, key=lambda finding: finding.group.count)
    days_now = (run.read_meta().requested_to_utc - run.read_meta().requested_from_utc).days
    # Before: half the count in half the window - the same rate.
    stored = [_as_stored(finding) for finding in visible if finding is not target]
    stored.append(_as_stored(target, count=max(target.group.count // 2, 1)))
    _previous(run, stored, window_days=days_now / 2)
    result = _compare(run, findings)
    assert target.finding_id not in [entry.finding_id for entry in result.more_frequent]


def test_a_run_of_another_machine_is_not_compared(current) -> None:
    run, findings, visible = current
    _previous(run, [], host="OTHER-PC")
    assert find_previous_run(run) is None


def test_a_later_run_is_not_taken_as_previous(current) -> None:
    run, findings, visible = current
    _previous(run, [], days_earlier=-1, name="later")
    assert find_previous_run(run) is None


def test_the_latest_earlier_run_wins(current) -> None:
    run, _, _ = current
    _previous(run, [], days_earlier=5, name="older")
    newer = _previous(run, [], days_earlier=1, name="newer")
    assert find_previous_run(run).path == newer.path


def test_a_different_security_mode_leaves_security_indications_out(current) -> None:
    run, findings, visible = current
    _previous(run, [_as_stored(f) for f in visible if not f.security_indicator],
              security_mode=False)
    result = _compare(run, findings)
    assert all(not entry.rule_name.startswith("Security") for entry in result.new)
    assert all(
        entry.finding_id not in {f.finding_id for f in visible if f.security_indicator}
        for entry in result.new
    )
    assert "security mode" in result.note


def test_the_second_analysis_shows_the_comparison_in_the_report(fixture_run) -> None:
    analyze_run(fixture_run, CONFIG)
    first = fixture_run.read_meta()
    # Pretend the first analysis is the previous run by moving it back in time.
    previous = _previous(fixture_run, json.loads(
        (fixture_run.derived_dir / "findings.json").read_text(encoding="utf-8")
    ), name="earlier")
    assert previous.read_meta().started_utc < first.started_utc

    report = analyze_run(fixture_run, CONFIG, write_outputs=False).report
    assert report.comparison.available
    assert report.comparison.unchanged
