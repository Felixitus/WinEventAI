"""Detaildarstellung eines Befunds als Qt-Rich-Text.

Bewusst QTextBrowser statt QtWebEngine: Letzteres bringt rund 150 MB Chromium
in das PyInstaller-Bundle, fuer ein Werkzeug, das ohnehin nur Text und Tabellen
zeigt. Der vollstaendige HTML-Bericht wird stattdessen aus der Oberflaeche
heraus im System-Browser geoeffnet - dort gehoert er hin, denn er wird
weitergegeben.

Qt-Rich-Text ist eine Untermenge von HTML 4: keine Flexbox, kein Grid, kein
externes CSS. Deshalb hier Tabellen und Inline-Stile statt der Klassen aus dem
Bericht.
"""

from __future__ import annotations

from html import escape

from ..ai.pipeline import AiRunResult
from ..probes.base import ProbeResult, ProbeStatus
from ..rules.engine import Finding
from . import theme


def _liste(titel: str, eintraege: list[str]) -> str:
    if not eintraege:
        return ""
    zeilen = "".join(f"<li>{escape(item)}</li>" for item in eintraege)
    return (
        f'<p style="margin:14px 0 2px;color:{theme.INK_FAINT};font-size:10px;'
        f'font-weight:600;">{escape(titel.upper())}</p>'
        f'<ul style="margin:0 0 0 14px;">{zeilen}</ul>'
    )


def _kennzahl(name: str, wert: str) -> str:
    return (
        f'<td style="padding:0 22px 6px 0;">'
        f'<div style="color:{theme.INK_FAINT};font-size:10px;font-weight:600;">'
        f"{escape(name.upper())}</div>"
        f'<div style="font-size:13px;">{wert}</div></td>'
    )


def _aussage_block(statement: object, *, mit_belegen: bool = True) -> str:
    """Eine Modellaussage samt Belegen und Pruefvermerk."""
    aussage = getattr(statement, "aussage", "")
    confidence = str(getattr(statement, "confidence", "unklar"))
    verified = bool(getattr(statement, "verified", True))
    note = getattr(statement, "verification_note", None)

    farbe = {
        "hoch": theme.OK,
        "mittel": theme.INFO,
        "niedrig": theme.WARN,
        "unklar": theme.INK_FAINT,
    }.get(confidence, theme.INK_FAINT)

    text_farbe = theme.INK if verified else theme.INK_FAINT
    teile = [
        f'<div style="margin:0 0 10px;">'
        f'<span style="color:{farbe};font-size:10px;font-weight:700;">'
        f"{escape(confidence.upper())}</span>&nbsp;&nbsp;"
        f'<span style="color:{text_farbe};">{escape(aussage)}</span>'
    ]

    if mit_belegen:
        belege = getattr(statement, "evidence", []) or []
        if belege:
            gefasst = " · ".join(
                f"{escape(item.provider)}:{item.event_id} @ "
                f"{item.timestamp_utc.strftime('%d.%m. %H:%M:%S')}"
                for item in belege[:4]
            )
            teile.append(
                f'<div style="color:{theme.INK_FAINT};font-size:11px;'
                f'font-family:Consolas,monospace;">{gefasst}</div>'
            )

    if not verified and note:
        teile.append(
            f'<div style="color:{theme.CRIT};font-size:11px;">'
            f"Verworfen: {escape(str(note))}</div>"
        )

    teile.append("</div>")
    return "".join(teile)


def _sonde_block(probe: ProbeResult) -> str:
    """Eine Messung samt Zeitvorbehalt.

    Der Vorbehalt steht in JEDER Karte, nicht einmal ueber dem Abschnitt. Wer
    nur eine Sonde liest - und das ist der Normalfall - soll ihn trotzdem
    mitlesen.
    """
    farbe = {
        ProbeStatus.OK: theme.OK,
        ProbeStatus.WARN: theme.WARN,
    }.get(probe.status, theme.INK_FAINT)

    # Kein farbiger Balken links: Qt-Rich-Text zeichnet ``border-left``
    # ausserhalb von Tabellen nicht, und ein Blockzeichen als Ersatz haengt an
    # der installierten Schrift. Traeger der Unterscheidung ist deshalb das
    # Statuswort - in Grossbuchstaben UND in Farbe, also nicht nur farbig.
    teile = [
        f'<div style="margin:0 0 12px;">'
        f'<div><span style="color:{farbe};font-size:10px;font-weight:700;">'
        f"{escape(str(probe.status).upper())}</span>&nbsp;&nbsp;"
        f'<span style="font-weight:600;">{escape(probe.title)}</span>'
    ]
    if probe.target:
        teile.append(
            f'&nbsp;<span style="color:{theme.INK_FAINT};font-family:Consolas,monospace;'
            f'font-size:11px;">{escape(probe.target)}</span>'
        )
    teile.append(
        f'&nbsp;&nbsp;<span style="color:{theme.INK_FAINT};font-size:11px;">'
        f"{escape(str(probe.bearing))}</span></div>"
    )

    if probe.summary:
        teile.append(f'<div style="margin:2px 0;">{escape(probe.summary)}</div>')
    if probe.details:
        zeilen = "".join(f"<li>{escape(item)}</li>" for item in probe.details)
        teile.append(
            f'<ul style="margin:2px 0 2px 14px;color:{theme.INK_SOFT};font-size:12px;">'
            f"{zeilen}</ul>"
        )
    if probe.detail_error:
        teile.append(
            f'<div style="color:{theme.CRIT};font-size:11px;">'
            f"{escape(probe.detail_error)}</div>"
        )
    teile.append(
        f'<div style="color:{theme.INK_FAINT};font-size:11px;font-style:italic;">'
        f"{escape(probe.age_note())}</div></div>"
    )
    return "".join(teile)


def finding_detail_html(finding: Finding, ai: AiRunResult | None = None) -> str:
    """Baut die Detailansicht eines Befunds."""
    farbe = theme.SEVERITY_COLOR.get(finding.severity, theme.NOISE)
    eskaliert = " (eskaliert)" if finding.escalated else ""

    kopf = (
        f'<div style="border-left:3px solid {farbe};padding-left:12px;margin-bottom:4px;">'
        f'<div style="color:{farbe};font-size:10px;font-weight:700;">'
        f"{escape(str(finding.severity).upper())}{escape(eskaliert)}</div>"
        f'<div style="font-size:17px;font-weight:600;">{escape(finding.rule_name)}</div>'
        f"</div>"
    )

    zeitraum = (
        f"{finding.group.first_seen_utc.strftime('%d.%m.%Y %H:%M')} – "
        f"{finding.group.last_seen_utc.strftime('%d.%m.%Y %H:%M')}"
    )
    kennzahlen = (
        '<table cellspacing="0" cellpadding="0" style="margin:10px 0 4px;"><tr>'
        + _kennzahl("Haeufigkeit", f"{finding.group.count} ×")
        + _kennzahl("Zeitraum (UTC)", escape(zeitraum))
        + _kennzahl("Kanal", f"<code>{escape(finding.group.channel)}</code>")
        + _kennzahl(
            "Regel",
            f"<code>{escape(finding.rule_id)}</code> "
            f'<span style="color:{theme.INK_FAINT};">({escape(finding.rule_source)})</span>',
        )
        + "</tr></table>"
    )

    teile = [kopf, kennzahlen]

    if finding.group.bursts:
        spans = ", ".join(
            f"{b.hour_utc.replace('T', ' ')}:00 ({b.count}×)" for b in finding.group.bursts[:3]
        )
        teile.append(
            f'<p style="color:{theme.ERR};margin:6px 0;">'
            f"Auffaellige Haeufung: {escape(spans)}</p>"
        )

    if finding.bedeutung:
        teile.append(f'<p style="margin:10px 0;">{escape(finding.bedeutung.strip())}</p>')

    if not finding.has_verified_meaning:
        teile.append(
            f'<p style="background:{theme.WARN_BG};padding:8px 10px;margin:8px 0;">'
            f"Keine gesicherte Bedeutung in der Wissensbasis hinterlegt "
            f"(Status: {escape(finding.kb_confidence)}). Aussagen zu diesem Befund "
            f"sind ungeprueft.</p>"
        )

    teile.append(_liste("Typische Ursachen", finding.typische_ursachen))
    teile.append(_liste("Empfohlene Pruefschritte", finding.empfohlene_checks))

    if finding.probes:
        teile.append(
            f'<hr style="border:none;border-top:1px solid {theme.RULE};margin:16px 0 10px;">'
            f'<p style="color:{theme.INK_FAINT};font-size:10px;font-weight:600;margin:0 0 6px;">'
            f"MESSUNGEN ZUM AKTUELLEN ZUSTAND</p>"
        )
        teile.extend(_sonde_block(probe) for probe in finding.probes)

    eintrag = ai.for_finding(finding.finding_id) if ai else None
    if eintrag and eintrag.explanation:
        teile.append(
            f'<hr style="border:none;border-top:1px solid {theme.RULE};margin:16px 0;">'
            f'<p style="color:{theme.INK_FAINT};font-size:10px;font-weight:600;">'
            f"EINSCHAETZUNG DES SPRACHMODELLS</p>"
            f'<p style="margin:4px 0 12px;">'
            f"{escape(eintrag.explanation.zusammenfassung)}</p>"
        )
        for statement in eintrag.explanation.hypothesen:
            teile.append(_aussage_block(statement))
        if eintrag.explanation.empfohlene_schritte:
            teile.append(
                f'<p style="color:{theme.INK_FAINT};font-size:10px;font-weight:600;'
                f'margin-top:10px;">VORGESCHLAGENE NAECHSTE SCHRITTE</p>'
            )
            for statement in eintrag.explanation.empfohlene_schritte:
                teile.append(_aussage_block(statement, mit_belegen=False))
        if eintrag.verification.statements_rejected:
            teile.append(
                f'<p style="color:{theme.CRIT};font-size:11px;">'
                f"{eintrag.verification.statements_rejected} Aussage(n) verworfen, "
                f"weil sie nicht durch Ereignisse aus der Eingabe gedeckt waren.</p>"
            )
    elif eintrag and eintrag.note:
        teile.append(
            f'<p style="color:{theme.INK_FAINT};margin-top:12px;">'
            f"Sprachmodell: {escape(eintrag.note)}</p>"
        )

    if finding.context_events:
        zeilen = "".join(
            f"<tr>"
            f'<td style="padding:2px 10px 2px 0;font-family:Consolas,monospace;'
            f'font-size:11px;white-space:nowrap;">'
            f"{event.timestamp_utc.strftime('%d.%m. %H:%M:%S')}</td>"
            f'<td style="padding:2px 10px 2px 0;font-family:Consolas,monospace;'
            f'font-size:11px;">{escape(event.provider)}:{event.event_id}</td>'
            f'<td style="padding:2px 0;font-size:11px;color:{theme.INK_SOFT};">'
            f"{escape(event.excerpt(140))}</td></tr>"
            for event in finding.context_events[:25]
        )
        teile.append(
            f'<p style="color:{theme.INK_FAINT};font-size:10px;font-weight:600;'
            f'margin-top:16px;">{len(finding.context_events)} EREIGNISSE IM UMFELD '
            f"(die ersten 25)</p>"
            f'<table cellspacing="0" cellpadding="0">{zeilen}</table>'
        )

    if finding.referenz:
        teile.append(
            f'<p style="margin-top:14px;"><a href="{escape(finding.referenz)}" '
            f'style="color:{theme.ACCENT};">Referenz oeffnen</a></p>'
        )

    return (
        f'<div style="font-family:Segoe UI,sans-serif;font-size:13px;'
        f'color:{theme.INK};">' + "".join(teile) + "</div>"
    )


PLACEHOLDER = (
    f'<div style="color:{theme.INK_FAINT};padding:24px;font-family:Segoe UI,sans-serif;">'
    "Links einen Befund auswaehlen.</div>"
)
