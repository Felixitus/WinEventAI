"""HTML-Bericht: eine einzige Datei ohne externe Ressourcen.

Kein CDN, keine JavaScript-Bibliothek, keine nachgeladenen Schriften. Das folgt
aus "vollstaendig offline" - und aus derselben Ueberlegung wie beim Verzicht auf
kodierte PowerShell: Eine HTML-Datei, die beim Oeffnen ins Netz greift, ist auf
einem untersuchten Rechner das falsche Signal.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..enrich.burst import hour_label
from ..resources import read_resource_text, resource_path
from .model import ReportModel
from .timeline_svg import render_timeline

TEMPLATE_NAME = "bericht.html.j2"


def _format_datetime(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.strftime("%d.%m.%Y %H:%M:%S")


def _format_number(value: object) -> str:
    try:
        return f"{int(value):,}".replace(",", ".")
    except (TypeError, ValueError):
        return str(value)


def _environment() -> Environment:
    template_dir = resource_path(f"report/templates/{TEMPLATE_NAME}").parent
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["dt"] = _format_datetime
    env.filters["zahl"] = _format_number
    env.filters["stunde"] = hour_label
    return env


def render_html(report: ReportModel) -> str:
    """Rendert den vollstaendigen Bericht als HTML-Zeichenkette."""
    covered = [
        row for row in report.coverage if row.status.value not in {"abgeschaltet", "kanal fehlt"}
    ]
    covered_from = None
    for source in covered:
        _ = source  # Abdeckung steckt bereits in den Zeilen; hier nur Zeitleiste.

    earliest = [
        finding.group.first_seen_utc for finding in report.findings if finding.group.samples
    ]
    if earliest:
        covered_from = min(earliest)

    timeline = render_timeline(
        report.findings,
        window_from=report.meta.requested_from_utc,
        window_to=report.meta.requested_to_utc,
        covered_from=covered_from,
    )

    template = _environment().get_template(TEMPLATE_NAME)
    return template.render(
        report=report,
        css=read_resource_text("report/assets/bericht.css"),
        timeline=timeline,
    )


def write_html(report: ReportModel, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
    return path
