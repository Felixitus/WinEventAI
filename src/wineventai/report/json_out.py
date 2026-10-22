"""JSON report.

Machine-readable version for further processing and ticket systems. Produced
from the same ``ReportModel`` as HTML and Markdown - not from either of them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import ReportModel


def render_json(report: ReportModel) -> dict[str, Any]:
    """Builds the JSON structure of the report."""
    return {
        "title": report.title,
        "headline": report.headline,
        "generated_utc": report.generated_utc.isoformat(),
        "pseudonymized": report.redacted,
        "run": report.meta.model_dump(mode="json"),
        "coverage": [row.model_dump(mode="json") for row in report.coverage],
        "coverage_incomplete": report.has_coverage_problem,
        "figures": {
            "events_read": report.total_events,
            "fingerprints": report.distinct_groups,
            "reduction_rate": round(report.reduction_rate, 4),
            "retention": report.retention_stats,
        },
        "findings": [finding.to_public_dict() for finding in report.findings],
        "noise": [finding.to_public_dict() for finding in report.noise],
        "boot_sessions": [session.model_dump(mode="json") for session in report.boot_sessions],
        "ai": {
            "used": report.ai.used,
            "model": report.ai.model,
            "num_ctx": report.ai.num_ctx,
            "reason_if_not": report.ai.unavailable_reason,
            "rejected_statements": report.ai.rejected_statements,
            "per_finding": [entry.model_dump(mode="json") for entry in report.ai.findings],
            "correlations": (
                report.ai.correlation.model_dump(mode="json") if report.ai.correlation else None
            ),
        },
        "security": report.security.model_dump(mode="json"),
        "unknown_ids": report.unknown_ids,
        "raw_appendix": [record.to_public_dict() for record in report.raw_appendix],
    }


def write_json(report: ReportModel, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(render_json(report), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return path
