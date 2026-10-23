"""HTML report: one single file without external resources.

No CDN, no JavaScript library, no web fonts loaded afterwards. That follows
from "fully offline" - and from the same consideration as avoiding encoded
PowerShell: an HTML file that reaches into the network when opened is the
wrong signal on a machine under examination.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..enrich.burst import hour_label
from ..resources import read_resource_text, resource_path
from .model import ReportModel
from .timeline_svg import render_timeline

TEMPLATE_NAME = "report.html.j2"
STYLESHEET = "report/assets/report.css"
#: Inline, not linked: the report is one file without external resources.
#: A copy of docs/logo.svg, written by packaging/make_icons.py.
LOGO = "report/assets/logo.svg"


def _format_datetime(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _format_number(value: object) -> str:
    try:
        return f"{int(value):,}"
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
    env.filters["number"] = _format_number
    env.filters["hour"] = hour_label
    return env


def render_html(report: ReportModel) -> str:
    """Renders the complete report as an HTML string."""
    covered_from = None
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
        css=read_resource_text(STYLESHEET),
        logo=read_resource_text(LOGO),
        timeline=timeline,
    )


def write_html(report: ReportModel, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
    return path
