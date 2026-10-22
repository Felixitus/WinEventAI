"""Detail view of a finding as Qt rich text.

Deliberately QTextBrowser instead of QtWebEngine: the latter brings about
150 MB of Chromium into the PyInstaller bundle, for a tool that only shows text
and tables anyway. The full HTML report is instead opened from the interface in
the system browser - that is where it belongs, because it gets passed on.

Qt rich text is a subset of HTML 4: no flexbox, no grid, no external CSS. Hence
tables and inline styles here instead of the classes from the report.
"""

from __future__ import annotations

from html import escape

from ..ai.pipeline import AiRunResult
from ..probes.base import ProbeResult, ProbeStatus
from ..rules.engine import Finding
from . import theme


def _list(title: str, entries: list[str]) -> str:
    if not entries:
        return ""
    rows = "".join(f"<li>{escape(item)}</li>" for item in entries)
    return (
        f'<p style="margin:14px 0 2px;color:{theme.INK_FAINT};font-size:10px;'
        f'font-weight:600;">{escape(title.upper())}</p>'
        f'<ul style="margin:0 0 0 14px;">{rows}</ul>'
    )


def _figure(name: str, value: str) -> str:
    return (
        f'<td style="padding:0 22px 6px 0;">'
        f'<div style="color:{theme.INK_FAINT};font-size:10px;font-weight:600;">'
        f"{escape(name.upper())}</div>"
        f'<div style="font-size:13px;">{value}</div></td>'
    )


def _statement_block(statement: object, *, with_evidence: bool = True) -> str:
    """One model statement including evidence and verification note."""
    text = getattr(statement, "statement", "")
    confidence = str(getattr(statement, "confidence", "unclear"))
    verified = bool(getattr(statement, "verified", True))
    note = getattr(statement, "verification_note", None)

    color = {
        "high": theme.OK,
        "medium": theme.INFO,
        "low": theme.WARN,
        "unclear": theme.INK_FAINT,
    }.get(confidence, theme.INK_FAINT)

    text_color = theme.INK if verified else theme.INK_FAINT
    parts = [
        f'<div style="margin:0 0 10px;">'
        f'<span style="color:{color};font-size:10px;font-weight:700;">'
        f"{escape(confidence.upper())}</span>&nbsp;&nbsp;"
        f'<span style="color:{text_color};">{escape(text)}</span>'
    ]

    if with_evidence:
        evidence = getattr(statement, "evidence", []) or []
        if evidence:
            joined = " · ".join(
                f"{escape(item.provider)}:{item.event_id} @ "
                f"{item.timestamp_utc.strftime('%Y-%m-%d %H:%M:%S')}"
                for item in evidence[:4]
            )
            parts.append(
                f'<div style="color:{theme.INK_FAINT};font-size:11px;'
                f'font-family:Consolas,monospace;">{joined}</div>'
            )

    if not verified and note:
        parts.append(
            f'<div style="color:{theme.CRIT};font-size:11px;">'
            f"Rejected: {escape(str(note))}</div>"
        )

    parts.append("</div>")
    return "".join(parts)


def _probe_block(probe: ProbeResult) -> str:
    """One measurement including the time caveat.

    The caveat is in EVERY card, not once above the section. Whoever reads only
    one probe - and that is the normal case - should read it as well.
    """
    color = {
        ProbeStatus.OK: theme.OK,
        ProbeStatus.WARN: theme.WARN,
    }.get(probe.status, theme.INK_FAINT)

    # No colored bar on the left: Qt rich text does not draw ``border-left``
    # outside of tables, and a block character as a substitute depends on the
    # installed font. The carrier of the distinction is therefore the status
    # word - in capitals AND in color, so not only colored.
    parts = [
        f'<div style="margin:0 0 12px;">'
        f'<div><span style="color:{color};font-size:10px;font-weight:700;">'
        f"{escape(str(probe.status).upper())}</span>&nbsp;&nbsp;"
        f'<span style="font-weight:600;">{escape(probe.title)}</span>'
    ]
    if probe.target:
        parts.append(
            f'&nbsp;<span style="color:{theme.INK_FAINT};font-family:Consolas,monospace;'
            f'font-size:11px;">{escape(probe.target)}</span>'
        )
    parts.append(
        f'&nbsp;&nbsp;<span style="color:{theme.INK_FAINT};font-size:11px;">'
        f"{escape(str(probe.bearing))}</span></div>"
    )

    if probe.summary:
        parts.append(f'<div style="margin:2px 0;">{escape(probe.summary)}</div>')
    if probe.details:
        rows = "".join(f"<li>{escape(item)}</li>" for item in probe.details)
        parts.append(
            f'<ul style="margin:2px 0 2px 14px;color:{theme.INK_SOFT};font-size:12px;">'
            f"{rows}</ul>"
        )
    if probe.detail_error:
        parts.append(
            f'<div style="color:{theme.CRIT};font-size:11px;">'
            f"{escape(probe.detail_error)}</div>"
        )
    parts.append(
        f'<div style="color:{theme.INK_FAINT};font-size:11px;font-style:italic;">'
        f"{escape(probe.age_note())}</div></div>"
    )
    return "".join(parts)


def finding_detail_html(finding: Finding, ai: AiRunResult | None = None) -> str:
    """Builds the detail view of a finding."""
    color = theme.SEVERITY_COLOR.get(finding.severity, theme.NOISE)
    escalated = " (escalated)" if finding.escalated else ""

    head = (
        f'<div style="border-left:3px solid {color};padding-left:12px;margin-bottom:4px;">'
        f'<div style="color:{color};font-size:10px;font-weight:700;">'
        f"{escape(str(finding.severity).upper())}{escape(escalated)}</div>"
        f'<div style="font-size:17px;font-weight:600;">{escape(finding.rule_name)}</div>'
        f"</div>"
    )

    period = (
        f"{finding.group.first_seen_utc.strftime('%Y-%m-%d %H:%M')} – "
        f"{finding.group.last_seen_utc.strftime('%Y-%m-%d %H:%M')}"
    )
    figures = (
        '<table cellspacing="0" cellpadding="0" style="margin:10px 0 4px;"><tr>'
        + _figure("Count", f"{finding.group.count} ×")
        + _figure("Period (UTC)", escape(period))
        + _figure("Channel", f"<code>{escape(finding.group.channel)}</code>")
        + _figure(
            "Rule",
            f"<code>{escape(finding.rule_id)}</code> "
            f'<span style="color:{theme.INK_FAINT};">({escape(finding.rule_source)})</span>',
        )
        + "</tr></table>"
    )

    parts = [head, figures]

    if finding.group.bursts:
        spans = ", ".join(
            f"{b.hour_utc.replace('T', ' ')}:00 ({b.count}×)" for b in finding.group.bursts[:3]
        )
        parts.append(
            f'<p style="color:{theme.ERR};margin:6px 0;">'
            f"Conspicuous clustering: {escape(spans)}</p>"
        )

    if finding.meaning:
        parts.append(f'<p style="margin:10px 0;">{escape(finding.meaning.strip())}</p>')

    if not finding.has_verified_meaning:
        parts.append(
            f'<p style="background:{theme.WARN_BG};padding:8px 10px;margin:8px 0;">'
            f"No verified meaning on record in the knowledge base "
            f"(state: {escape(finding.kb_confidence)}). Statements about this finding "
            f"are unverified.</p>"
        )

    parts.append(_list("Typical causes", finding.typical_causes))
    parts.append(_list("Recommended checks", finding.recommended_checks))

    if finding.probes:
        parts.append(
            f'<hr style="border:none;border-top:1px solid {theme.RULE};margin:16px 0 10px;">'
            f'<p style="color:{theme.INK_FAINT};font-size:10px;font-weight:600;margin:0 0 6px;">'
            f"MEASUREMENTS OF THE CURRENT STATE</p>"
        )
        parts.extend(_probe_block(probe) for probe in finding.probes)

    entry = ai.for_finding(finding.finding_id) if ai else None
    if entry and entry.explanation:
        parts.append(
            f'<hr style="border:none;border-top:1px solid {theme.RULE};margin:16px 0;">'
            f'<p style="color:{theme.INK_FAINT};font-size:10px;font-weight:600;">'
            f"ASSESSMENT BY THE LANGUAGE MODEL</p>"
            f'<p style="margin:4px 0 12px;">'
            f"{escape(entry.explanation.summary)}</p>"
        )
        for statement in entry.explanation.hypotheses:
            parts.append(_statement_block(statement))
        if entry.explanation.recommended_steps:
            parts.append(
                f'<p style="color:{theme.INK_FAINT};font-size:10px;font-weight:600;'
                f'margin-top:10px;">SUGGESTED NEXT STEPS</p>'
            )
            for statement in entry.explanation.recommended_steps:
                parts.append(_statement_block(statement, with_evidence=False))
        if entry.verification.statements_rejected:
            parts.append(
                f'<p style="color:{theme.CRIT};font-size:11px;">'
                f"{entry.verification.statements_rejected} statement(s) rejected "
                f"because they were not covered by events from the input.</p>"
            )
    elif entry and entry.note:
        parts.append(
            f'<p style="color:{theme.INK_FAINT};margin-top:12px;">'
            f"Language model: {escape(entry.note)}</p>"
        )

    if finding.context_events:
        rows = "".join(
            f"<tr>"
            f'<td style="padding:2px 10px 2px 0;font-family:Consolas,monospace;'
            f'font-size:11px;white-space:nowrap;">'
            f"{event.timestamp_utc.strftime('%Y-%m-%d %H:%M:%S')}</td>"
            f'<td style="padding:2px 10px 2px 0;font-family:Consolas,monospace;'
            f'font-size:11px;">{escape(event.provider)}:{event.event_id}</td>'
            f'<td style="padding:2px 0;font-size:11px;color:{theme.INK_SOFT};">'
            f"{escape(event.excerpt(140))}</td></tr>"
            for event in finding.context_events[:25]
        )
        parts.append(
            f'<p style="color:{theme.INK_FAINT};font-size:10px;font-weight:600;'
            f'margin-top:16px;">{len(finding.context_events)} EVENTS IN THE SURROUNDINGS '
            f"(the first 25)</p>"
            f'<table cellspacing="0" cellpadding="0">{rows}</table>'
        )

    if finding.reference:
        parts.append(
            f'<p style="margin-top:14px;"><a href="{escape(finding.reference)}" '
            f'style="color:{theme.ACCENT};">Open reference</a></p>'
        )

    return (
        f'<div style="font-family:Segoe UI,sans-serif;font-size:13px;'
        f'color:{theme.INK};">' + "".join(parts) + "</div>"
    )


PLACEHOLDER = (
    f'<div style="color:{theme.INK_FAINT};padding:24px;font-family:Segoe UI,sans-serif;">'
    "Select a finding on the left.</div>"
)
