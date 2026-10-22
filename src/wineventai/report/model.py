"""Das Berichtsmodell - eine Quelle fuer HTML, Markdown und JSON.

Die drei Ausgabeformate entstehen aus diesem Modell, nicht auseinander. Sonst
driften sie nach der dritten Aenderung auseinander, und der Markdown-Bericht
sagt etwas anderes als der HTML-Bericht.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ..ai.pipeline import AiRunResult
from ..collect.base import INCONCLUSIVE, STATUS_HINT_DE, SourceResult, SourceStatus
from ..collect.rundir import RunMeta
from ..enrich.aggregate import EnrichmentResult
from ..enrich.boot import BootSession
from ..normalize.schema import EventRecord
from ..rules.engine import Finding
from ..rules.schema import SEVERITY_ORDER, Severity
from ..security.indicators import SecurityReport


class CoverageRow(BaseModel):
    """Eine Zeile der Abdeckungstabelle.

    Diese Tabelle steht im Bericht VOR den Befunden. Sie ist der Unterschied
    zwischen "keine Befunde" und "sechseinhalb Tage nie gelesen".
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
    return f"{start:%d.%m.%Y %H:%M} – {end:%d.%m.%Y %H:%M} UTC"


def coverage_rows(sources: list[SourceResult]) -> list[CoverageRow]:
    rows = [
        CoverageRow(
            source_id=source.source_id,
            status=source.status,
            hint=STATUS_HINT_DE.get(source.status, ""),
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
    # Unvollstaendiges zuerst - was fehlt, ist wichtiger als was da ist.
    rows.sort(key=lambda row: (not row.inconclusive, row.source_id))
    return rows


class SeverityCount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity
    count: int


class ReportModel(BaseModel):
    """Alles, was in einen Bericht gehoert."""

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

    # --- Abgeleitetes --------------------------------------------------------

    @property
    def has_coverage_problem(self) -> bool:
        return any(row.inconclusive for row in self.coverage)

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.KRITISCH]

    @property
    def headline(self) -> str:
        """Ein Satz, der zuerst gelesen wird."""
        critical = len(self.critical_findings)
        if critical:
            return (
                f"{critical} kritische Befunde im untersuchten Zeitraum."
                if critical > 1
                else "Ein kritischer Befund im untersuchten Zeitraum."
            )
        if self.findings:
            return f"Keine kritischen Befunde, {len(self.findings)} Befunde insgesamt."
        if self.has_coverage_problem:
            return (
                "Keine Befunde - aber der Zeitraum wurde nicht vollstaendig erhoben. "
                "Siehe Abdeckung."
            )
        return "Keine Befunde im untersuchten Zeitraum."

    @property
    def ai_note(self) -> str:
        if self.ai.used:
            rejected = self.ai.rejected_statements
            base = f"Modell {self.ai.model}, Kontextfenster {self.ai.num_ctx}."
            if rejected:
                return (
                    f"{base} {rejected} Aussage(n) wurden verworfen, weil sie nicht durch "
                    "Ereignisse aus der Eingabe gedeckt waren."
                )
            return f"{base} Alle Aussagen sind durch Ereignisse aus der Eingabe gedeckt."
        return (
            self.ai.unavailable_reason
            or "Der KI-Layer wurde nicht verwendet. Der Bericht entsteht aus der Regel-Engine."
        )


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
    """Setzt das Berichtsmodell zusammen."""
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
