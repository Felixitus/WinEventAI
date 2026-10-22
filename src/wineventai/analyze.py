"""Analysis of a run directory: enricher, rules, knowledge base, AI, report.

This stage no longer touches the target system. It reads exclusively from the
run directory - so it can be repeated any number of times with changed rules
without anyone having to read the logs again.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .ai.bundles import SystemContext
from .ai.pipeline import AiLayer
from .ai.redaction import Redactor
from .applog import get_log
from .collect.base import INCONCLUSIVE
from .collect.rundir import RunDirectory
from .collect.runner import load_records
from .config import Config
from .enrich.aggregate import Enricher, EnrichmentResult
from .enrich.merge import merge_sources
from .kb.store import KnowledgeBase
from .kb.unknown import collect_unknown, write_unknown_csv
from .probes.runner import ProbeRunner
from .report.html import write_html
from .report.json_out import write_json
from .report.markdown import write_markdown
from .report.model import ReportModel, build_report
from .rules.engine import Finding, RuleEngine
from .rules.loader import load_rules
from .security.indicators import build_security_report

#: File names of the report inside ``<run>/report``.
REPORT_HTML = "report.html"
REPORT_MARKDOWN = "report.md"
REPORT_JSON = "report.json"


class AnalysisResult(BaseModel):
    """What the analysis produced."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    report: ReportModel
    written: list[Path] = []
    enrichment: EnrichmentResult
    findings: list[Finding] = []


def _system_context(
    run: RunDirectory, enrichment: EnrichmentResult, redactor: Redactor
) -> SystemContext:
    meta = run.read_meta()
    incomplete = [
        source.source_id
        for source in run.read_sources()
        if source.status in INCONCLUSIVE
    ]
    return SystemContext(
        host=redactor.register_host(meta.host) if redactor.enabled else meta.host,
        operating_system=meta.os_caption,
        period_from_utc=meta.requested_from_utc.isoformat(),
        period_to_utc=meta.requested_to_utc.isoformat(),
        boot_sessions=len(enrichment.boot_sessions),
        incomplete_sources=incomplete,
    )


def analyze_run(
    run: RunDirectory,
    config: Config,
    *,
    kb: KnowledgeBase | None = None,
    ai_layer: AiLayer | None = None,
    probe_runner: ProbeRunner | None = None,
    write_outputs: bool = True,
) -> AnalysisResult:
    """Analyzes a run directory completely."""
    log = get_log()
    meta = run.read_meta()
    sources = run.read_sources()

    rules = load_rules(
        overlay=config.rules.overlay_dir,
        include_security=config.rules.security_mode,
    )
    engine = RuleEngine(rules, suppress_noise=config.rules.suppress_noise)
    log.info("Rules loaded", count=len(rules), security_mode=config.rules.security_mode)

    records_by_source = load_records(run)
    enricher = Enricher(
        samples_per_group=config.enrich.samples_per_group,
        burst_factor=config.enrich.burst_factor,
        burst_min_count=config.enrich.burst_min_count,
        context_window_minutes=config.enrich.context_window_minutes,
        context_max_events=config.enrich.context_max_events,
        window_hours=max(
            (meta.requested_to_utc - meta.requested_from_utc).total_seconds() / 3600.0, 1.0
        ),
        retention_limit=config.collect.max_retained_per_channel,
        retention_error_share=config.enrich.retention_error_share,
        seed=config.enrich.sampling_seed,
        rule_keys=engine.rule_keys,
    )
    enrichment = enricher.consume(merge_sources(records_by_source))
    log.info(
        "Condensed",
        events=enrichment.total_events,
        fingerprints=len(enrichment.groups),
        reduction=f"{enrichment.reduction_rate * 100:.1f}%",
    )

    findings = engine.evaluate(enrichment)

    knowledge = kb if kb is not None else KnowledgeBase.open_default()
    for finding in findings:
        entry = knowledge.get(finding.group.provider, finding.group.event_id)
        if entry is None:
            continue
        finding.kb_confidence = str(entry.confidence)
        finding.kb_source = entry.source_url
        if entry.usable_in_prompt:
            finding.kb_meaning = entry.meaning.strip()

    unknown = collect_unknown(enrichment, knowledge)
    if write_outputs:
        write_unknown_csv(run.unknown_ids_path, unknown)

    redactor = Redactor(enabled=config.ai.redact)
    layer = ai_layer or AiLayer(config.ai, kb=knowledge, redactor=redactor)
    context = _system_context(run, enrichment, layer.redactor)
    ai_result, bundles = layer.run(findings, context)

    if write_outputs:
        for finding_id, parts in bundles.items():
            for index, part in enumerate(parts, start=1):
                suffix = "" if len(parts) == 1 else f"_{index}"
                name = f"{finding_id.replace('::', '__')}{suffix}.json"
                (run.bundles_dir / name).write_text(part.as_prompt_json(), encoding="utf-8")
        for entry in ai_result.findings:
            name = f"{entry.finding_id.replace('::', '__')}.json"
            (run.ai_dir / name).write_text(
                entry.model_dump_json(indent=2), encoding="utf-8"
            )

    # Probes run AFTER the AI layer, and that is no accident: a measurement
    # carries no event ids, so the evidence check cannot hold it against the
    # input. Anything in the prompt that cannot be checked is an invitation to
    # invent. The probes therefore appear in the report and in the user
    # interface, but never in the bundle.
    runner = probe_runner or ProbeRunner(config, run_host=meta.host)
    measured = runner.attach(findings)
    if measured:
        log.info("Probes measured", count=measured)

    security = build_security_report(
        findings,
        enrichment.retained,
        enrichment.boot_sessions,
        enabled=config.rules.security_mode,
        is_admin=meta.is_admin,
    )

    report = build_report(
        title=config.report.title,
        meta=meta,
        sources=sources,
        enrichment=enrichment,
        findings=findings,
        ai=ai_result,
        security=security,
        unknown_ids=unknown,
        raw_appendix_limit=config.report.raw_appendix_limit,
        redacted=config.report.redacted,
    )

    written: list[Path] = []
    if write_outputs:
        written = write_report_files(report, run, config)
        run.update_meta(ai_model=ai_result.model, ai_used=ai_result.used)
        run.write_derived("groups.json", [group.to_public_dict() for group in enrichment.groups])
        run.write_derived("findings.json", [f.to_public_dict() for f in findings])

    if kb is None:
        knowledge.close()

    return AnalysisResult(
        report=report, written=written, enrichment=enrichment, findings=findings
    )


def write_report_files(report: ReportModel, run: RunDirectory, config: Config) -> list[Path]:
    """Writes the configured output formats."""
    written: list[Path] = []
    if "html" in config.report.formats:
        written.append(write_html(report, run.report_dir / REPORT_HTML))
    if "md" in config.report.formats:
        written.append(write_markdown(report, run.report_dir / REPORT_MARKDOWN))
    if "json" in config.report.formats:
        written.append(write_json(report, run.report_dir / REPORT_JSON))
    return written


def redacted_report(
    report: ReportModel, run: RunDirectory, config: Config, redactor: Redactor
) -> list[Path]:
    """Additionally writes a shareable version plus mapping table.

    The report contains logon times, account names and machine names - i.e.
    personal data - and gets passed around. This version keeps the pseudonyms;
    the mapping table lies next to it and does not go along.
    """
    import json

    target = run.report_dir / "report_pseudonymized.html"
    written = [write_html(report.model_copy(update={"redacted": True}), target)]
    mapping_path = run.report_dir / "mapping.json"
    mapping_path.write_text(
        json.dumps(redactor.mapping(), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    written.append(mapping_path)
    return written
