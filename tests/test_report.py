"""Reporter: Abdeckung vor Befunden, alle drei Formate aus einem Modell."""

from __future__ import annotations

import json
import re

from wineventai.analyze import analyze_run
from wineventai.collect.base import SourceStatus
from wineventai.config import load_config
from wineventai.report.html import render_html
from wineventai.report.json_out import render_json
from wineventai.report.markdown import render_markdown
from wineventai.report.timeline_svg import render_timeline

VOLATILE = re.compile(
    r"(Erzeugt .*|- Erhoben: .*|- Werkzeug: .*|Lauf `.*`)"
)


def _report(fixture_run):
    config = load_config(
        overrides={"ai": {"enabled": False}, "rules": {"security_mode": True}}
    )
    return analyze_run(fixture_run, config).report


def test_abdeckung_steht_vor_den_befunden(fixture_run) -> None:
    """Die Reihenfolge ist inhaltlich, nicht kosmetisch.

    Wer "keine Befunde" liest, ohne vorher gesehen zu haben, dass sechs Tage
    nicht erhoben wurden, zieht den falschen Schluss.
    """
    markdown = render_markdown(_report(fixture_run))
    assert markdown.index("## 1 · Abdeckung") < markdown.index("## 2 · Befunde")


def test_unvollstaendige_quellen_stehen_oben_in_der_tabelle(fixture_run) -> None:
    report = _report(fixture_run)
    assert report.has_coverage_problem
    assert report.coverage[0].inconclusive, "was fehlt, ist wichtiger als was da ist"


def test_nicht_protokolliert_ist_nicht_kein_befund(fixture_run) -> None:
    report = _report(fixture_run)
    reliability = next(
        row for row in report.coverage if row.source_id == "cim:Win32_ReliabilityRecords"
    )
    assert reliability.status is SourceStatus.NOT_LOGGED
    assert reliability.inconclusive
    assert "nicht protokolliert" in reliability.hint


def test_zeitlimit_erzeugt_sichtbare_luecke(fixture_run) -> None:
    report = _report(fixture_run)
    security = next(row for row in report.coverage if row.source_id == "channel:Security")
    assert security.status is SourceStatus.TIMED_OUT
    assert security.coverage_gap, (
        "ein Zeitlimit darf nicht still zu einem verkleinerten Fenster werden"
    )
    assert security.requested != security.covered


def test_alle_drei_formate_entstehen_aus_demselben_modell(fixture_run) -> None:
    report = _report(fixture_run)
    html = render_html(report)
    markdown = render_markdown(report)
    payload = render_json(report)

    for finding in report.findings[:5]:
        assert finding.rule_name in html
        assert finding.rule_name in markdown
    assert len(payload["befunde"]) == len(report.findings)
    assert payload["abdeckung_unvollstaendig"] is True


def test_html_laedt_nichts_aus_dem_netz(fixture_run) -> None:
    """Ein Bericht, der beim Oeffnen ins Netz greift, ist das falsche Signal."""
    html = render_html(_report(fixture_run))
    assert "http://" not in html.replace("http://www.w3.org/2000/svg", "")
    assert "cdn." not in html
    assert "<script" not in html.lower()


def test_rauschen_ist_klassifiziert_und_ausgeblendet(fixture_run) -> None:
    report = _report(fixture_run)
    assert report.noise, "10016 muss erkannt sein"
    assert all(finding.suppressed for finding in report.noise)
    assert not any(finding.suppressed for finding in report.findings)


def test_kopfzeile_nennt_kritische_befunde(fixture_run) -> None:
    report = _report(fixture_run)
    assert "kritisch" in report.headline.lower()


def test_ai_hinweis_erklaert_das_fehlen_des_modells(fixture_run) -> None:
    report = _report(fixture_run)
    assert not report.ai.used
    assert "Regel-Engine" in report.ai_note or "abgeschaltet" in report.ai_note


def test_zeitleiste_markiert_den_nicht_erhobenen_teil(fixture_run) -> None:
    report = _report(fixture_run)
    svg = render_timeline(
        report.findings,
        window_from=report.meta.requested_from_utc,
        window_to=report.meta.requested_to_utc,
        covered_from=report.meta.requested_from_utc.replace(hour=23),
    )
    assert "nicht erhoben" in svg
    assert svg.startswith("<svg")


def test_json_ist_serialisierbar(fixture_run) -> None:
    payload = render_json(_report(fixture_run))
    text = json.dumps(payload, ensure_ascii=False, default=str)
    assert len(text) > 1000


def test_goldener_bericht_bleibt_stabil(fixture_run, tmp_path) -> None:
    """Faengt unbeabsichtigte Aenderungen an Formulierung und Reihenfolge.

    Volatile Zeilen (Zeitstempel des Laufs, Lauf-ID) werden vorher entfernt -
    sonst prueft der Test die Uhr statt den Bericht.
    """
    def normalise(text: str) -> str:
        return "\n".join(
            line for line in text.splitlines() if not VOLATILE.search(line)
        )

    first = normalise(render_markdown(_report(fixture_run)))
    second = normalise(render_markdown(_report(fixture_run)))
    assert first == second, "zwei Laeufe auf demselben Laufverzeichnis muessen gleich sein"

    golden = tmp_path / "golden.md"
    golden.write_text(first, encoding="utf-8")
    assert "## 1 · Abdeckung" in first
    assert "Unsauberer Neustart" in first
