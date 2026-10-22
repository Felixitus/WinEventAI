"""Oberflaeche: Modelle, Statusmeldungen, Detailtext und Worker.

Getestet wird ohne Bildschirm (``QT_QPA_PLATFORM=offscreen``) und ohne echte
Widgets, wo es geht. Die Modelle liegen genau deshalb in einer eigenen Datei:
Sie sind der Teil der Oberflaeche, der Aussagen ueber Daten trifft - und der
gehoert getestet.

Der Worker wird direkt aufgerufen statt ueber einen Thread. Was hier interessiert,
ist welche Signale mit welchem Inhalt kommen, nicht ob Qt Threads kann.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason='Oberflaeche ist optional (pip install -e ".[gui]")')

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from wineventai.analyze import analyze_run  # noqa: E402
from wineventai.config import load_config  # noqa: E402
from wineventai.gui import detail  # noqa: E402
from wineventai.gui.models import (  # noqa: E402
    CoverageModel,
    FindingsModel,
    UnknownEventsFilter,
    UnknownEventsModel,
    coverage_warning,
    summary_line,
)
from wineventai.gui.status import Environment  # noqa: E402
from wineventai.gui.worker import RunWorker  # noqa: E402


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    return QApplication.instance() or QApplication([])


@pytest.fixture
def report(fixture_run):
    config = load_config(overrides={"ai": {"enabled": False}, "rules": {"security_mode": True}})
    return analyze_run(fixture_run, config).report


# --- Modelle -----------------------------------------------------------------


def test_abdeckungsmodell_zeigt_unvollstaendiges_zuerst(qapp, report) -> None:
    model = CoverageModel(report.coverage)
    assert model.rowCount() == len(report.coverage)

    erste = model.row_at(0)
    assert erste is not None and erste.inconclusive, (
        "was fehlt, gehoert nach oben - sonst liest jemand ueber die Luecke hinweg"
    )


def test_abdeckungsmodell_faerbt_unvollstaendige_zeilen(qapp, report) -> None:
    model = CoverageModel(report.coverage)
    index = model.index(0, 1)
    farbe = model.data(index, Qt.ItemDataRole.ForegroundRole)
    hintergrund = model.data(index, Qt.ItemDataRole.BackgroundRole)

    assert farbe is not None
    assert hintergrund is not None, "unvollstaendige Quellen brauchen einen Hintergrund"


def test_abdeckungsmodell_markiert_die_luecke(qapp, report) -> None:
    model = CoverageModel(report.coverage)
    texte = [
        model.data(model.index(row, CoverageModel.COL_COVERED), Qt.ItemDataRole.DisplayRole)
        for row in range(model.rowCount())
    ]
    assert any("[Luecke]" in text for text in texte)


def test_befundmodell_bildet_alle_sichtbaren_befunde_ab(qapp, report) -> None:
    model = FindingsModel(report.findings)
    assert model.rowCount() == len(report.findings)
    assert model.columnCount() == 4


def test_befundmodell_zeigt_provider_nur_im_tooltip(qapp, report) -> None:
    """Die Liste ist zum Scannen da.

    'Microsoft-Windows-WER-SystemErrorReporting:1001' in einer Spalte frisst die
    halbe Breite und draengt den Befundnamen weg, nach dem man eigentlich sucht.
    """
    model = FindingsModel(report.findings)
    zeilen = [
        model.data(model.index(row, spalte), Qt.ItemDataRole.DisplayRole)
        for row in range(model.rowCount())
        for spalte in range(model.columnCount())
    ]
    assert not any(":" in str(text) and "Microsoft-Windows" in str(text) for text in zeilen)

    tooltip = model.data(model.index(0, 1), Qt.ItemDataRole.ToolTipRole)
    assert ":" in tooltip


def test_befundmodell_faerbt_nach_schwere(qapp, report) -> None:
    model = FindingsModel(report.findings)
    farbe = model.data(model.index(0, 0), Qt.ItemDataRole.ForegroundRole)
    assert farbe is not None
    assert farbe.name() == "#a52218", "kritisch muss rot sein, nicht die Akzentfarbe"


def test_befundmodell_markiert_eskalation(qapp, report) -> None:
    model = FindingsModel(report.findings)
    texte = [
        model.data(model.index(row, 0), Qt.ItemDataRole.DisplayRole)
        for row in range(model.rowCount())
    ]
    assert any("↑" in text for text in texte), "eine Eskalation muss sichtbar sein"


def test_befundmodell_meldet_fehlende_wissensbasis_im_tooltip(qapp) -> None:
    from helpers import make_record
    from wineventai.enrich.aggregate import Enricher
    from wineventai.rules.engine import RuleEngine
    from wineventai.rules.loader import load_rules

    stream = [
        make_record(minutes_ago=1, provider="Microsoft-Windows-WHEA-Logger",
                    event_id=18, level=1, properties=["x"])
    ]
    findings = RuleEngine(load_rules()).evaluate(Enricher(window_hours=168).consume(stream))
    model = FindingsModel(findings)

    tooltip = model.data(model.index(0, 1), Qt.ItemDataRole.ToolTipRole)
    assert "Keine gesicherte Bedeutung" in tooltip


def test_leeres_modell_stuerzt_nicht_ab(qapp) -> None:
    model = FindingsModel()
    assert model.rowCount() == 0
    assert model.data(model.index(0, 0), Qt.ItemDataRole.DisplayRole) is None


# --- Kopfzeilen --------------------------------------------------------------


def test_kennzahlenzeile_nennt_reduktion_und_rauschen(qapp, report) -> None:
    text = summary_line(report)
    assert "Ereignisse" in text
    assert "Reduktion" in text
    assert "Rauschen" in text


def test_warnbanner_erscheint_bei_luecken(qapp, report) -> None:
    warnung = coverage_warning(report)
    assert warnung is not None
    assert "nicht vollstaendig erhoben" in warnung
    assert "channel:Security" in warnung


def test_warnbanner_bleibt_aus_wenn_alles_erhoben_wurde(qapp, report) -> None:
    sauber = report.model_copy(
        update={"coverage": [row for row in report.coverage if not row.inconclusive]}
    )
    assert coverage_warning(sauber) is None


# --- Statusleiste ------------------------------------------------------------


def test_status_unterscheidet_dienst_und_modell() -> None:
    """Dieselbe Unterscheidung wie im Client - hier nur als Anzeige."""
    fehlt = Environment(
        model_name="qwen2.5:14b", ollama_reachable=True, ollama_model_present=False,
        ollama_models=["llama3.1:8b"],
    )
    text, problem = fehlt.ollama_line()
    assert problem and "fehlt" in text
    assert "nicht erreichbar" not in text

    tot = Environment(model_name="qwen2.5:14b", ollama_reachable=False)
    text, problem = tot.ollama_line()
    assert problem and "nicht erreichbar" in text

    gut = Environment(
        model_name="qwen2.5:14b", ollama_reachable=True, ollama_model_present=True
    )
    _, problem = gut.ollama_line()
    assert not problem


def test_status_kennt_den_harten_blocker() -> None:
    assert not Environment().ready_to_collect
    assert Environment(powershell="C:/pwsh.exe").ready_to_collect


def test_tooltip_nennt_die_vorhandenen_modelle() -> None:
    env = Environment(
        model_name="fehlt:latest", ollama_reachable=True, ollama_model_present=False,
        ollama_models=["a:1", "b:2"], config_path="C:/x.yaml",
    )
    tooltip = env.tooltip()
    assert "a:1, b:2" in tooltip
    assert "nicht vorhanden" in tooltip, "eine fehlende Konfiguration gehoert in den Tooltip"


# --- Detailansicht -----------------------------------------------------------


def test_detail_enthaelt_bedeutung_und_pruefschritte(qapp, report) -> None:
    finding = report.findings[0]
    html = detail.finding_detail_html(finding)

    assert finding.rule_name in html
    assert str(finding.severity).upper() in html
    for check in finding.empfohlene_checks[:1]:
        assert check[:30] in html


def test_detail_kennzeichnet_fehlende_wissensbasis(qapp, report) -> None:
    finding = report.findings[0].model_copy(update={"kb_confidence": "fehlt"})
    html = detail.finding_detail_html(finding)
    assert "Keine gesicherte Bedeutung" in html


def test_detail_zeigt_verworfene_modellaussagen(qapp, fixture_run) -> None:
    """Verwerfen darf nicht still passieren - auch nicht in der Oberflaeche."""
    from test_ai import FakeClient, _fixture
    from wineventai.ai.pipeline import AiLayer
    from wineventai.ai.redaction import Redactor
    from wineventai.kb.store import KnowledgeBase

    config = load_config(overrides={"rules": {"security_mode": True}})
    kb = KnowledgeBase.open_default()
    layer = AiLayer(
        config.ai,
        client=FakeClient([_fixture("explainer_erfundene_id.json")] * 60),
        kb=kb,
        redactor=Redactor(),
    )
    result = analyze_run(fixture_run, config, kb=kb, ai_layer=layer)
    kb.close()

    treffer = [
        detail.finding_detail_html(f, result.report.ai) for f in result.report.findings
    ]
    assert any("Verworfen:" in html for html in treffer)


def test_detail_maskiert_html_in_meldungen(qapp, report) -> None:
    """Eine Meldung aus einem Ereignisprotokoll ist Fremdtext."""
    finding = report.findings[0].model_copy(
        update={"bedeutung": "<script>alert(1)</script> & mehr"}
    )
    html = detail.finding_detail_html(finding)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# --- Worker ------------------------------------------------------------------


def test_worker_wertet_vorhandenen_lauf_aus(qapp, fixture_run) -> None:
    config = load_config(overrides={"ai": {"enabled": False}})
    worker = RunWorker(config, existing_run=fixture_run.path)

    ergebnisse: list[tuple[object, object]] = []
    fehler: list[tuple[str, str]] = []
    fortschritt: list[int] = []
    worker.finished_ok.connect(lambda run, res: ergebnisse.append((run, res)))
    worker.failed.connect(lambda titel, text: fehler.append((titel, text)))
    worker.progress.connect(lambda percent, _text: fortschritt.append(percent))

    worker.run()

    assert not fehler, fehler
    assert len(ergebnisse) == 1
    assert fortschritt[-1] == 100
    assert ergebnisse[0][1].report.findings


def test_worker_meldet_fehler_statt_zu_werfen(qapp, tmp_path) -> None:
    """Eine Oberflaeche darf nie kommentarlos sterben."""
    config = load_config(overrides={"ai": {"enabled": False}})
    worker = RunWorker(config, existing_run=tmp_path / "gibt-es-nicht")

    fehler: list[tuple[str, str]] = []
    worker.failed.connect(lambda titel, text: fehler.append((titel, text)))
    worker.run()

    assert len(fehler) == 1
    assert fehler[0][0] == "Nicht gefunden"


def test_worker_spiegelt_das_anwendungslog(qapp, fixture_run) -> None:
    config = load_config(overrides={"ai": {"enabled": False}})
    worker = RunWorker(config, existing_run=fixture_run.path)

    zeilen: list[str] = []
    worker.log_line.connect(zeilen.append)
    worker.run()

    assert zeilen, "waehrend eines langen Laufs muss sichtbar sein, dass etwas passiert"
    assert any("Regeln geladen" in zeile for zeile in zeilen)


def test_logstream_ueberlebt_den_tod_seines_workers(qapp, fixture_run) -> None:
    """Der Bug, den erst die Testreihenfolge zutage gefoerdert hat.

    Das Anwendungslog ist prozessweit, der Log-Stream haengt aber an EINEM
    Worker. Wird der eingesammelt und irgendetwas loggt noch, warf Qt
    "Signal source has been deleted" - und riss alles Nachfolgende mit.
    Ein Logger darf die Anwendung nie umbringen.
    """
    from wineventai.gui.worker import GuiLogStream

    config = load_config(overrides={"ai": {"enabled": False}})
    worker = RunWorker(config, existing_run=fixture_run.path)
    stream = GuiLogStream(worker.log_line)

    del worker  # der Besitzer des Signals ist weg

    assert stream.write("darf nicht werfen") > 0
    stream.flush()


def test_worker_loest_das_prozessweite_log_wieder(qapp, fixture_run) -> None:
    """Nach dem Lauf darf das globale Log nicht mehr auf den Worker zeigen."""
    from wineventai.applog import get_log

    config = load_config(overrides={"ai": {"enabled": False}})
    worker = RunWorker(config, existing_run=fixture_run.path)
    worker.run()
    del worker

    get_log().info("nach dem Lauf")  # wirft nicht mehr


# --- Abdeckungshinweis und Ereignisse ohne Bewertung -------------------------


def test_abdeckung_zeigt_den_vermerk_sichtbar_und_nicht_nur_im_tooltip(qapp, report) -> None:
    model = CoverageModel(report.coverage)
    vermerkte = [row for row, item in enumerate(report.coverage) if item.note]
    assert vermerkte, "die Fixture braucht mindestens eine Quelle mit Vermerk"

    zeile = vermerkte[0]
    text = model.data(model.index(zeile, CoverageModel.COL_NOTE), Qt.ItemDataRole.DisplayRole)
    assert text == report.coverage[zeile].note.strip()


def test_abdeckung_ohne_vermerk_zeigt_den_statustext_statt_einer_leeren_zelle(
    qapp, report
) -> None:
    model = CoverageModel(report.coverage)
    for zeile in range(model.rowCount()):
        text = model.data(model.index(zeile, CoverageModel.COL_NOTE), Qt.ItemDataRole.DisplayRole)
        assert text, f"leere Hinweiszelle in Zeile {zeile}"


UNKNOWN_ROWS = [
    {"provider": "P-Info", "event_id": 1, "anzahl": 500, "kanal": "K", "level": 4,
     "beispielmeldung": "nur Information"},
    {"provider": "P-Fehler", "event_id": 2, "anzahl": 3, "kanal": "K/Operational", "level": 2,
     "beispielmeldung": "Fehler 0x80070005"},
    {"provider": "P-Kritisch", "event_id": 3, "anzahl": 1, "kanal": "K", "level": 1,
     "beispielmeldung": "kritisch"},
]


def test_unbewertete_ereignisse_stehen_schwerste_stufe_zuerst(qapp) -> None:
    model = UnknownEventsModel(UNKNOWN_ROWS)

    stufen = [model.data(model.index(row, 0), Qt.ItemDataRole.DisplayRole)
              for row in range(model.rowCount())]
    assert stufen == ["kritisch", "fehler", "info"]


def test_unbewertete_ereignisse_sagen_nicht_hinterlegt_statt_leer_zu_bleiben(qapp) -> None:
    model = UnknownEventsModel(UNKNOWN_ROWS)

    bedeutung = model.data(model.index(0, 5), Qt.ItemDataRole.DisplayRole)
    assert bedeutung == "nicht hinterlegt"


def test_filter_zeigt_standardmaessig_nur_kritisch_und_fehler(qapp) -> None:
    proxy = UnknownEventsFilter()
    proxy.setSourceModel(UnknownEventsModel(UNKNOWN_ROWS))

    assert proxy.rowCount() == 2
    proxy.set_only_errors(False)
    assert proxy.rowCount() == 3


def test_filter_sucht_auch_in_der_meldung(qapp) -> None:
    proxy = UnknownEventsFilter()
    proxy.setSourceModel(UnknownEventsModel(UNKNOWN_ROWS))
    proxy.set_text("0x80070005")

    assert proxy.rowCount() == 1


def test_hauptfenster_fuellt_den_reiter_ohne_bewertung(qapp, fixture_run) -> None:
    from wineventai.gui.main_window import MainWindow

    config = load_config(overrides={"ai": {"enabled": False}})
    result = analyze_run(fixture_run, config)
    window = MainWindow(config)
    try:
        window._on_finished(fixture_run, result)
        titel = window.tabs.tabText(MainWindow.UNKNOWN_TAB_INDEX)
        assert titel == f"Ohne Bewertung ({len(result.report.unknown_ids)})"
        assert window.unknown_model.rowCount() == len(result.report.unknown_ids)
    finally:
        if window._probe:
            window._probe.stop()
        window.close()
