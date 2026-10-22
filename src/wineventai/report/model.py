"""The report model - one source for HTML, Markdown and JSON.

The three output formats are produced from this model, not from each other.
Otherwise they drift apart after the third change, and the Markdown report
says something different from the HTML report.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ..ai.pipeline import RULES_ONLY_NOTE, AiRunResult
from ..collect.base import INCONCLUSIVE, STATUS_HINT, SourceResult, SourceStatus
from ..collect.rundir import RunMeta
from ..enrich.aggregate import EnrichmentResult
from ..enrich.boot import BootSession
from ..normalize.schema import EventRecord
from ..rules.engine import Finding
from ..rules.schema import SEVERITY_ORDER, Severity
from ..security.indicators import SecurityReport


class CoverageRow(BaseModel):
    """One row of the coverage table.

    This table comes BEFORE the findings in the report. It is the difference
    between "no findings" and "six and a half days never read".
    """

    model_config = ConfigDict(extra="forbid")

    source_id: str
    status: SourceStatus
    hint: str
    requested: str
    covered: str
    records_read: int
    records_retained: int
    note: str | None = None
    inconclusive: bool = False
    coverage_gap: bool = False


def _format_range(start: datetime | None, end: datetime | None) -> str:
    if start is None or end is None:
        return "—"
    return f"{start:%Y-%m-%d %H:%M} – {end:%Y-%m-%d %H:%M} UTC"


def coverage_rows(sources: list[SourceResult]) -> list[CoverageRow]:
    rows = [
        CoverageRow(
            source_id=source.source_id,
            status=source.status,
            hint=STATUS_HINT.get(source.status, ""),
            requested=_format_range(source.requested_from_utc, source.requested_to_utc),
            covered=_format_range(source.covered_from_utc, source.covered_to_utc),
            records_read=source.records_read,
            records_retained=source.records_retained,
            note=source.note,
            inconclusive=source.status in INCONCLUSIVE,
            coverage_gap=source.coverage_gap,
        )
        for source in sources
    ]
    # Incomplete first - what is missing matters more than what is there.
    rows.sort(key=lambda row: (not row.inconclusive, row.source_id))
    return rows


class SeverityCount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    count: int


class ReportModel(BaseModel):
    """Everything that belongs in a report."""

    model_config = ConfigDict(extra="forbid")

    title: str
    meta: RunMeta
    generated_utc: datetime
    redacted: bool = False

    coverage: list[CoverageRow] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    noise: list[Finding] = Field(default_factory=list)
    boot_sessions: list[BootSession] = Field(default_factory=list)
    severity_counts: list[SeverityCount] = Field(default_factory=list)

    total_events: int = 0
    distinct_groups: int = 0
    reduction_rate: float = 0.0
    retention_stats: dict[str, int] = Field(default_factory=dict)

    ai: AiRunResult = Field(default_factory=AiRunResult)
    security: SecurityReport = Field(default_factory=SecurityReport)
    raw_appendix: list[EventRecord] = Field(default_factory=list)
    unknown_ids: list[dict[str, object]] = Field(default_factory=list)

    # --- Derived -------------------------------------------------------------

    @property
    def has_coverage_problem(self) -> bool:
        return any(row.inconclusive for row in self.coverage)

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.CRITICAL]

    @property
    def headline(self) -> str:
        """The one sentence that is read first."""
        critical = len(self.critical_findings)
        if critical:
            return (
                f"{critical} critical findings in the examined period."
                if critical > 1
                else "One critical finding in the examined period."
            )
        if self.findings:
            return f"No critical findings, {len(self.findings)} findings in total."
        if self.has_coverage_problem:
            return (
                "No findings - but the period was not collected completely. "
                "See coverage."
            )
        return "No findings in the examined period."

    @property
    def ai_note(self) -> str:
        if self.ai.used:
            rejected = self.ai.rejected_statements
            base = f"Model {self.ai.model}, context window {self.ai.num_ctx}."
            if rejected:
                return (
                    f"{base} {rejected} statement(s) were rejected because they were not "
                    "covered by events from the input."
                )
            return f"{base} All statements are covered by events from the input."
        return self.ai.unavailable_reason or f"The AI layer was not used. {RULES_ONLY_NOTE}"


def build_report(
    *,
    title: str,
    meta: RunMeta,
    sources: list[SourceResult],
    enrichment: EnrichmentResult,
    findings: list[Finding],
    ai: AiRunResult,
    security: SecurityReport,
    unknown_ids: list[dict[str, object]],
    raw_appendix_limit: int,
    redacted: bool,
) -> ReportModel:
    """Assembles the report model."""
    visible = [finding for finding in findings if not finding.suppressed]
    noise = [finding for finding in findings if finding.suppressed]

    counts: dict[Severity, int] = {}
    for finding in visible:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    return ReportModel(
        title=title,
        meta=meta,
        generated_utc=datetime.now(meta.started_utc.tzinfo),
        redacted=redacted,
        coverage=coverage_rows(sources),
        findings=visible,
        noise=noise,
        boot_sessions=enrichment.boot_sessions,
        severity_counts=[
            SeverityCount(severity=severity, count=count)
            for severity, count in sorted(
                counts.items(), key=lambda item: SEVERITY_ORDER[item[0]]
            )
        ],
        total_events=enrichment.total_events,
        distinct_groups=len(enrichment.groups),
        reduction_rate=enrichment.reduction_rate,
        retention_stats=enrichment.retention_stats,
        ai=ai,
        security=security,
        raw_appendix=enrichment.retained[:raw_appendix_limit],
        unknown_ids=unknown_ids,
    )
