"""Timeline as inline SVG.

No JavaScript library and no CDN: the report must work offline, and an HTML
file that reaches into the network when opened is the wrong signal on a machine
under examination. The SVG is therefore drawn here in Python.
"""

from __future__ import annotations

from datetime import datetime
from html import escape

from ..rules.engine import Finding
from ..rules.schema import Severity

WIDTH = 900
HEIGHT = 190
MARGIN_LEFT = 60
MARGIN_RIGHT = 20
MARGIN_TOP = 26
LANE_Y = 96
LANE_HEIGHT = 26

SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#a52218",
    Severity.ERROR: "#b4551a",
    Severity.WARNING: "#8a6a12",
    Severity.INFO: "#3a5a86",
    Severity.NOISE: "#78757f",
}


def _x_for(moment: datetime, start: datetime, end: datetime) -> float:
    span = (end - start).total_seconds()
    if span <= 0:
        return MARGIN_LEFT
    ratio = (moment - start).total_seconds() / span
    ratio = min(max(ratio, 0.0), 1.0)
    return MARGIN_LEFT + ratio * (WIDTH - MARGIN_LEFT - MARGIN_RIGHT)


def render_timeline(
    findings: list[Finding],
    *,
    window_from: datetime,
    window_to: datetime,
    covered_from: datetime | None = None,
) -> str:
    """Draws the timeline of a run.

    The uncovered part of the window is hatched - it is not event-free time but
    unread time, and that has to be visible.
    """
    if window_to <= window_from:
        return ""

    parts: list[str] = [
        f'<svg viewBox="0 0 {WIDTH} {HEIGHT}" width="100%" '
        f'role="img" aria-label="Timeline of the examined period" '
        f'xmlns="http://www.w3.org/2000/svg" class="timeline">',
        '<defs><pattern id="unread" width="8" height="8" patternUnits="userSpaceOnUse" '
        'patternTransform="rotate(45)">'
        '<rect width="8" height="8" fill="var(--surface-sunk)"/>'
        '<line x1="0" y1="0" x2="0" y2="8" stroke="var(--rule-strong)" stroke-width="2"/>'
        "</pattern></defs>",
    ]

    axis_y = LANE_Y + LANE_HEIGHT + 18
    parts.append(
        f'<rect x="{MARGIN_LEFT}" y="{LANE_Y}" '
        f'width="{WIDTH - MARGIN_LEFT - MARGIN_RIGHT}" height="{LANE_HEIGHT}" '
        f'fill="var(--surface-sunk)" stroke="var(--rule)"/>'
    )

    if covered_from is not None and covered_from > window_from:
        gap_end = _x_for(covered_from, window_from, window_to)
        parts.append(
            f'<rect x="{MARGIN_LEFT}" y="{LANE_Y}" width="{max(gap_end - MARGIN_LEFT, 0):.1f}" '
            f'height="{LANE_HEIGHT}" fill="url(#unread)"/>'
        )
        parts.append(
            f'<text x="{MARGIN_LEFT + 4}" y="{LANE_Y - 6}" class="tl-label">'
            f"not collected</text>"
        )

    parts.append(
        f'<line x1="{MARGIN_LEFT}" y1="{axis_y}" x2="{WIDTH - MARGIN_RIGHT}" y2="{axis_y}" '
        f'stroke="var(--rule-strong)"/>'
    )
    parts.append(
        f'<text x="{MARGIN_LEFT}" y="{axis_y + 16}" class="tl-label">'
        f"{escape(window_from.strftime('%Y-%m-%d %H:%M'))} UTC</text>"
    )
    parts.append(
        f'<text x="{WIDTH - MARGIN_RIGHT}" y="{axis_y + 16}" text-anchor="end" class="tl-label">'
        f"{escape(window_to.strftime('%Y-%m-%d %H:%M'))} UTC</text>"
    )

    drawn = 0
    for finding in findings:
        if finding.suppressed:
            continue
        color = SEVERITY_COLOR.get(finding.severity, "#78757f")
        for sample in finding.group.samples[:2]:
            x = _x_for(sample.timestamp_utc, window_from, window_to)
            parts.append(
                f'<line x1="{x:.1f}" y1="{LANE_Y - 8}" x2="{x:.1f}" '
                f'y2="{LANE_Y + LANE_HEIGHT + 8}" stroke="{color}" stroke-width="2">'
                f"<title>{escape(finding.rule_name)} — "
                f"{escape(sample.timestamp_utc.strftime('%Y-%m-%d %H:%M:%S'))} UTC</title>"
                f"</line>"
            )
            drawn += 1
            if drawn > 400:
                break
        if drawn > 400:
            break

    legend_x = MARGIN_LEFT
    for severity in (Severity.CRITICAL, Severity.ERROR, Severity.WARNING, Severity.INFO):
        parts.append(
            f'<rect x="{legend_x}" y="{HEIGHT - 24}" width="10" height="10" '
            f'fill="{SEVERITY_COLOR[severity]}"/>'
        )
        parts.append(
            f'<text x="{legend_x + 15}" y="{HEIGHT - 15}" class="tl-label">'
            f"{escape(str(severity))}</text>"
        )
        legend_x += 100

    parts.append("</svg>")
    return "".join(parts)
