"""Markdown-Bericht aus demselben Modell wie HTML und JSON."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ..enrich.burst import hour_label
from .model import ReportModel


def _dt(value: datetime | None) -> str:
    return value.strftime("%d.%m.%Y %H:%M:%S") if value else "—"


def _n(value: int) -> str:
    return f"{value:,}".replace(",", ".")


def render_markdown(report: ReportModel) -> str:
    lines: list[str] = []
    add = lines.append

    add(f"# {report.title} – {report.meta.host}")
    add("")
    add(f"**{report.headline}**")
    add("")
    add(f"- Betriebssystem: {report.meta.os_caption}")
    add(f"- Erhoben: {_dt(report.meta.started_utc)} UTC "
        f"({report.meta.timezone_name}, {report.meta.utc_offset_minutes} min Versatz)")
    add(f"- Zeitfenster: {_dt(report.meta.requested_from_utc)} – "
        f"{_dt(report.meta.requested_to_utc)} UTC")
    add(f"- Ausgefuehrt von: {report.meta.account}"
        f"{'' if report.meta.is_admin else ' (ohne Adminrechte)'}")
    add(f"- Werkzeug: WinEventAI {report.meta.tool_version}, Lauf `{report.meta.run_id}`")
    if report.redacted:
        add("- **Pseudonymisierte Fassung** – Zuordnungstabelle liegt separat.")
    add("")

    if report.has_coverage_problem:
        add("> **Der Zeitraum wurde nicht vollstaendig erhoben.** Aussagen ueber nicht")
        add("> abgedeckte Zeitraeume sind nicht moeglich. Abdeckungstabelle zuerst lesen.")
        add("")

    add("## 1 · Abdeckung")
    add("")
    add("| Quelle | Status | Angefordert | Abgedeckt | Gelesen | Behalten |")
    add("| --- | --- | --- | --- | ---: | ---: |")
    for row in report.coverage:
        marker = " ⚠" if row.inconclusive else ""
        add(f"| `{row.source_id}` | {row.status}{marker} | {row.requested} | {row.covered} "
            f"| {_n(row.records_read)} | {_n(row.records_retained)} |")
    add("")
    add(f"{_n(report.total_events)} Ereignisse gelesen, "
        f"{_n(report.distinct_groups)} verschiedene Fingerprints, "
        f"Reduktion {report.reduction_rate * 100:.1f} Prozent.")
    add("")

    add("## 2 · Befunde")
    add("")
    if not report.findings:
        add("Keine Regeltreffer im abgedeckten Zeitraum.")
        add("")
    for finding in report.findings:
        add(f"### [{finding.severity}] {finding.rule_name}")
        add("")
        add(f"- Provider/ID: `{finding.group.provider}:{finding.group.event_id}` "
            f"(Kanal `{finding.group.channel}`)")
        add(f"- Haeufigkeit: {_n(finding.group.count)} ×")
        add(f"- Zeitraum: {_dt(finding.group.first_seen_utc)} – "
            f"{_dt(finding.group.last_seen_utc)} UTC")
        add(f"- Regel: `{finding.rule_id}` ({finding.rule_source})")
        if finding.group.bursts:
            spans = ", ".join(
                f"{hour_label(burst.hour_utc)} ({burst.count}×)"
                for burst in finding.group.bursts[:3]
            )
            add(f"- Auffaellige Haeufung: {spans}")
        add("")
        if finding.bedeutung:
            add(finding.bedeutung.strip())
            add("")
        if not finding.has_verified_meaning:
            add(f"> Keine gesicherte Bedeutung in der Wissensbasis hinterlegt "
                f"(Status: {finding.kb_confidence}). Aussagen dazu sind ungeprueft.")
            add("")
        if finding.typische_ursachen:
            add("**Typische Ursachen**")
            add("")
            for item in finding.typische_ursachen:
                add(f"- {item}")
            add("")
        if finding.empfohlene_checks:
            add("**Empfohlene Pruefschritte**")
            add("")
            for item in finding.empfohlene_checks:
                add(f"- {item}")
            add("")

        if finding.probes:
            add("**Messungen zum aktuellen Zustand**")
            add("")
            for probe in finding.probes:
                ziel = f" ({probe.target})" if probe.target else ""
                add(f"- [{probe.status}] {probe.title}{ziel} — {probe.bearing}")
                if probe.summary:
                    add(f"  - {probe.summary}")
                for zeile in probe.details:
                    add(f"  - {zeile}")
                add(f"  - *{probe.age_note()}*")
            add("")

        ai = report.ai.for_finding(finding.finding_id)
        if ai and ai.explanation:
            add("**Einschaetzung des Sprachmodells**")
            add("")
            add(ai.explanation.zusammenfassung.strip())
            add("")
            for statement in ai.explanation.hypothesen:
                mark = "" if statement.verified else " *(verworfen)*"
                evidence = " · ".join(
                    f"{item.provider}:{item.event_id} @ {_dt(item.timestamp_utc)}"
                    for item in statement.evidence
                )
                add(f"- [{statement.confidence}]{mark} {statement.aussage}")
                add(f"  - Belege: {evidence}")
                if not statement.verified and statement.verification_note:
                    add(f"  - Grund: {statement.verification_note}")
            add("")
        elif ai and ai.note:
            add(f"> Sprachmodell: {ai.note}")
            add("")
        if finding.referenz:
            add(f"Referenz: {finding.referenz}")
            add("")

    add("## 3 · Boot-Sitzungen")
    add("")
    if report.boot_sessions:
        add("| Sitzung | Beginn (UTC) | Ende (UTC) | Herunterfahren | Ereignisse |")
        add("| --- | --- | --- | --- | ---: |")
        for session in report.boot_sessions:
            if session.clean_shutdown is None:
                shutdown = "unbekannt"
            else:
                shutdown = "sauber" if session.clean_shutdown else "**unsauber**"
            add(f"| {session.label} | {_dt(session.start_utc)} | {_dt(session.end_utc)} "
                f"| {shutdown} | {_n(session.event_count)} |")
    else:
        add("Keine Sitzungsmarker im Zeitfenster.")
    add("")

    if report.ai.correlation and report.ai.correlation.vorfaelle:
        add("## 4 · Zusammenhaenge")
        add("")
        for vorfall in report.ai.correlation.vorfaelle:
            mark = "" if vorfall.verified else " *(verworfen)*"
            add(f"### {vorfall.titel} [{vorfall.confidence}]{mark}")
            add("")
            add(vorfall.begruendung.strip())
            add("")
            add(f"Befunde: {' · '.join(vorfall.befund_ids)}")
            add("")

    if report.security.enabled:
        add("## 5 · Sicherheitsmodus")
        add("")
        add(f"> {report.security.disclaimer}")
        add("")
        if report.security.not_logged:
            add("### Blinde Flecken")
            add("")
            add("Diese Indikatoren entstehen auf diesem System gar nicht. "
                "Ihr Fehlen ist *nicht* als Unauffaelligkeit zu lesen.")
            add("")
            for entry in report.security.not_logged:
                ids = ", ".join(str(value) for value in entry.event_ids)
                add(f"- `{ids}` – {entry.subcategory}: **{entry.state}**. {entry.hint}")
                if entry.vorschlag:
                    add(f"  - Befehl: `{entry.vorschlag['befehl']}`")
                    add(f"  - Wirkung: {entry.vorschlag['wirkung']}")
                    add(f"  - Risiko: {entry.vorschlag['risiko']}")
                    add(f"  - Rueckbau: `{entry.vorschlag['rueckbau']}`")
            add("")
        if report.security.gaps:
            add("### Luecken in der Zeitachse")
            add("")
            for gap in report.security.gaps[:10]:
                add(f"- {gap.description}")
            add("")
        if report.security.findings:
            add("### Indikatoren mit Treffer")
            add("")
            for finding in report.security.findings:
                add(f"- [{finding.severity}] {finding.rule_name} – "
                    f"{_n(finding.group.count)} × bis {_dt(finding.group.last_seen_utc)} UTC")
            add("")
        else:
            add("Keine Treffer bei den ausgewerteten Indikatoren.")
            add("")

    noise_heading = 6 if report.security.enabled else 5
    add(f"## {noise_heading} · Unterdruecktes Rauschen")
    add("")
    if report.noise:
        for finding in report.noise:
            add(f"- {finding.rule_name} (`{finding.group.provider}:"
                f"{finding.group.event_id}`): {_n(finding.group.count)} ×")
    else:
        add("Nichts als Rauschen klassifiziert.")
    add("")

    add(f"## {noise_heading + 1} · Hinweise")
    add("")
    add(report.ai_note)
    add("")
    if report.unknown_ids:
        add(f"{len(report.unknown_ids)} Provider/ID-Paare ohne gesicherten "
            "Wissensbasis-Eintrag – siehe `unknown_ids.csv` im Laufverzeichnis.")
        add("")
    add(f"Erzeugt {_dt(report.generated_utc)} UTC. Read-only: "
        "Es wurde nichts am System geaendert.")
    add("")

    return "\n".join(lines)


def write_markdown(report: ReportModel, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report), encoding="utf-8")
    return path
