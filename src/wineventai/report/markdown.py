"""Markdown report from the same model as HTML and JSON."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ..enrich.burst import hour_label
from .model import ReportModel


def _dt(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "—"


def _n(value: int) -> str:
    return f"{value:,}"


def render_markdown(report: ReportModel) -> str:
    lines: list[str] = []
    add = lines.append

    add(f"# {report.title} – {report.meta.host}")
    add("")
    add(f"**{report.headline}**")
    add("")
    add(f"- Operating system: {report.meta.os_caption}")
    add(f"- Collected: {_dt(report.meta.started_utc)} UTC "
        f"({report.meta.timezone_name}, {report.meta.utc_offset_minutes} min offset)")
    add(f"- Time window: {_dt(report.meta.requested_from_utc)} – "
        f"{_dt(report.meta.requested_to_utc)} UTC")
    add(f"- Run by: {report.meta.account}"
        f"{'' if report.meta.is_admin else ' (without admin rights)'}")
    add(f"- Tool: WinEventAI {report.meta.tool_version}, run `{report.meta.run_id}`")
    if report.redacted:
        add("- **Pseudonymized version** – the mapping table is kept separately.")
    add("")

    if report.has_coverage_problem:
        add("> **The period was not collected completely.** No statements are possible")
        add("> about uncovered periods. Read the coverage table first.")
        add("")

    add("## 1 · Coverage")
    add("")
    add("| Source | Status | Requested | Covered | Read | Retained | Note |")
    add("| --- | --- | --- | --- | ---: | ---: | --- |")
    for row in report.coverage:
        marker = " ⚠" if row.inconclusive else ""
        note = (row.note or row.hint or "").replace("|", "/")
        add(f"| `{row.source_id}` | {row.status}{marker} | {row.requested} | {row.covered} "
            f"| {_n(row.records_read)} | {_n(row.records_retained)} | {note} |")
    add("")
    add(f"{_n(report.total_events)} events read, "
        f"{_n(report.distinct_groups)} distinct fingerprints, "
        f"reduction {report.reduction_rate * 100:.1f} percent.")
    add("")

    add("## 2 · Findings")
    add("")
    comparison = report.comparison
    add(comparison.summary())
    if comparison.note and comparison.available:
        add("")
        add(comparison.note)
    add("")
    for label, entries in (
        ("New", comparison.new),
        ("More frequent", comparison.more_frequent),
        ("Not seen in this window", comparison.not_seen),
    ):
        for entry in entries:
            before = f", before {entry.count_before}x" if entry.count_before is not None else ""
            now = f"{entry.count_now}x" if entry.count_now is not None else "-"
            add(f"- {label}: {entry.rule_name} ({now}{before})")
    if comparison.new or comparison.more_frequent or comparison.not_seen:
        add("")
    if not report.findings:
        add("No rule hits in the covered period.")
        add("")
    for finding in report.findings:
        add(f"### [{finding.severity}] {finding.rule_name}")
        add("")
        add(f"- Provider/ID: `{finding.group.provider}:{finding.group.event_id}` "
            f"(channel `{finding.group.channel}`)")
        add(f"- Count: {_n(finding.group.count)}x")
        add(f"- Period: {_dt(finding.group.first_seen_utc)} – "
            f"{_dt(finding.group.last_seen_utc)} UTC")
        add(f"- Rule: `{finding.rule_id}` ({finding.rule_source})")
        if finding.group.bursts:
            spans = ", ".join(
                f"{hour_label(burst.hour_utc)} ({burst.count}x)"
                for burst in finding.group.bursts[:3]
            )
            add(f"- Conspicuous clustering: {spans}")
        add("")
        if finding.meaning:
            add(finding.meaning.strip())
            add("")
        if not finding.has_verified_meaning:
            add(f"> No verified meaning on record in the knowledge base "
                f"(state: {finding.kb_confidence}). Statements about it are unverified.")
            add("")
        if finding.typical_causes:
            add("**Typical causes**")
            add("")
            for item in finding.typical_causes:
                add(f"- {item}")
            add("")
        if finding.recommended_checks:
            add("**Recommended checks**")
            add("")
            for item in finding.recommended_checks:
                add(f"- {item}")
            add("")

        if finding.probes:
            add("**Measurements of the current state**")
            add("")
            for probe in finding.probes:
                target = f" ({probe.target})" if probe.target else ""
                add(f"- [{probe.status}] {probe.title}{target} — {probe.bearing}")
                if probe.summary:
                    add(f"  - {probe.summary}")
                for line in probe.details:
                    add(f"  - {line}")
                add(f"  - *{probe.age_note()}*")
            add("")

        ai = report.ai.for_finding(finding.finding_id)
        if ai and ai.explanation:
            add("**Assessment by the language model**")
            add("")
            add(ai.explanation.summary.strip())
            add("")
            for statement in ai.explanation.hypotheses:
                mark = "" if statement.verified else " *(rejected)*"
                evidence = " · ".join(
                    f"{item.provider}:{item.event_id} @ {_dt(item.timestamp_utc)}"
                    for item in statement.evidence
                )
                add(f"- [{statement.confidence}]{mark} {statement.statement}")
                add(f"  - Evidence: {evidence}")
                if not statement.verified and statement.verification_note:
                    add(f"  - Reason: {statement.verification_note}")
            add("")
        elif ai and ai.note:
            add(f"> Language model: {ai.note}")
            add("")
        if finding.reference:
            add(f"Reference: {finding.reference}")
            add("")

    add("## 3 · Boot sessions")
    add("")
    if report.boot_sessions:
        add("| Session | Start (UTC) | End (UTC) | Shutdown | Events |")
        add("| --- | --- | --- | --- | ---: |")
        for session in report.boot_sessions:
            if session.clean_shutdown is None:
                shutdown = "unknown"
            else:
                shutdown = "clean" if session.clean_shutdown else "**unclean**"
            add(f"| {session.label} | {_dt(session.start_utc)} | {_dt(session.end_utc)} "
                f"| {shutdown} | {_n(session.event_count)} |")
    else:
        add("No session markers in the time window.")
    add("")

    if report.ai.correlation and report.ai.correlation.incidents:
        add("## 4 · Connections")
        add("")
        for incident in report.ai.correlation.incidents:
            mark = "" if incident.verified else " *(rejected)*"
            add(f"### {incident.title} [{incident.confidence}]{mark}")
            add("")
            add(incident.rationale.strip())
            add("")
            add(f"Findings: {' · '.join(incident.finding_ids)}")
            add("")

    if report.security.enabled:
        add("## 5 · Security mode")
        add("")
        add(f"> {report.security.disclaimer}")
        add("")
        if report.security.not_logged:
            add("### Blind spots")
            add("")
            add("These indicators do not arise on this system at all. "
                "Their absence must *not* be read as inconspicuousness.")
            add("")
            for entry in report.security.not_logged:
                ids = ", ".join(str(value) for value in entry.event_ids)
                add(f"- `{ids}` – {entry.subcategory}: **{entry.state}**. {entry.hint}")
                if entry.suggestion:
                    add(f"  - Command: `{entry.suggestion['command']}`")
                    add(f"  - Effect: {entry.suggestion['effect']}")
                    add(f"  - Risk: {entry.suggestion['risk']}")
                    add(f"  - Rollback: `{entry.suggestion['rollback']}`")
            add("")
        if report.security.gaps:
            add("### Gaps in the timeline")
            add("")
            for gap in report.security.gaps[:10]:
                add(f"- {gap.description}")
            add("")
        if report.security.findings:
            add("### Indicators with hits")
            add("")
            for finding in report.security.findings:
                add(f"- [{finding.severity}] {finding.rule_name} – "
                    f"{_n(finding.group.count)}x until {_dt(finding.group.last_seen_utc)} UTC")
            add("")
        else:
            add("No hits for the evaluated indicators.")
            add("")

    noise_heading = 6 if report.security.enabled else 5
    add(f"## {noise_heading} · Suppressed noise")
    add("")
    if report.noise:
        for finding in report.noise:
            add(f"- {finding.rule_name} (`{finding.group.provider}:"
                f"{finding.group.event_id}`): {_n(finding.group.count)}x")
    else:
        add("Nothing classified as noise.")
    add("")

    add(f"## {noise_heading + 1} · Notes")
    add("")
    add(report.ai_note)
    add("")
    if report.unknown_ids:
        add(f"{len(report.unknown_ids)} provider/id pairs without a verified "
            "knowledge-base entry – see `unknown_ids.csv` in the run directory.")
        add("")
    add(f"Generated {_dt(report.generated_utc)} UTC. Read-only: "
        "nothing on the system was changed.")
    add("")

    return "\n".join(lines)


def write_markdown(report: ReportModel, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report), encoding="utf-8")
    return path
