"""Reporter: HTML, Markdown und JSON aus einem gemeinsamen Modell."""

from .html import render_html, write_html
from .json_out import render_json, write_json
from .markdown import render_markdown, write_markdown
from .model import CoverageRow, ReportModel, build_report, coverage_rows
from .timeline_svg import render_timeline

__all__ = [
    "CoverageRow",
    "ReportModel",
    "build_report",
    "coverage_rows",
    "render_html",
    "render_json",
    "render_markdown",
    "render_timeline",
    "write_html",
    "write_json",
    "write_markdown",
]
