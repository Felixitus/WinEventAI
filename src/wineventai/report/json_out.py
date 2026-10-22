"""JSON-Bericht.

Maschinenlesbare Fassung fuer Weiterverarbeitung und Ticketsysteme. Erzeugt aus
demselben ``ReportModel`` wie HTML und Markdown - nicht aus einem der beiden.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import ReportModel


def render_json(report: ReportModel) -> dict[str, Any]:
    """Baut die JSON-Struktur des Berichts."""
    return {
        "titel": report.title,
        "kopfzeile": report.headline,
        "erzeugt_utc": report.generated_utc.isoformat(),
        "pseudonymisiert": report.redacted,
        "lauf": report.meta.model_dump(mode="json"),
        "abdeckung": [row.model_dump(mode="json") for row in report.coverage],
        "abdeckung_unvollstaendig": report.has_coverage_problem,
        "kennzahlen": {
            "ereignisse_gelesen": report.total_events,
            "fingerprints": report.distinct_groups,
            "reduktionsrate": round(report.reduction_rate, 4),
            "retention": report.retention_stats,
        },
        "befunde": [finding.to_public_dict() for finding in report.findings],
        "rauschen": [finding.to_public_dict() for finding in report.noise],
        "boot_sitzungen": [session.model_dump(mode="json") for session in report.boot_sessions],
        "ki": {
            "verwendet": report.ai.used,
            "modell": report.ai.model,
            "num_ctx": report.ai.num_ctx,
            "grund_falls_nicht": report.ai.unavailable_reason,
            "verworfene_aussagen": report.ai.rejected_statements,
            "je_befund": [entry.model_dump(mode="json") for entry in report.ai.findings],
            "zusammenhaenge": (
                report.ai.correlation.model_dump(mode="json") if report.ai.correlation else None
            ),
        },
        "sicherheit": report.security.model_dump(mode="json"),
        "unbekannte_ids": report.unknown_ids,
        "rohdaten_anhang": [record.to_public_dict() for record in report.raw_appendix],
    }


def write_json(report: ReportModel, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(render_json(report), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return path
