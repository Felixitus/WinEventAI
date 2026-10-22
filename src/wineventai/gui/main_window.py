"""Das Hauptfenster.

Aufbau von oben nach unten - und die Reihenfolge ist inhaltlich, nicht
kosmetisch:

1. Startleiste: Zeitfenster, Sicherheitsmodus, Start
2. Kopfzeile mit dem einen Satz, der zuerst gelesen wird
3. Warnbanner, falls der Zeitraum nicht vollstaendig erhoben wurde
4. Abdeckung - VOR den Befunden, aus demselben Grund wie im Bericht
5. Befundliste links, Detail rechts
6. Protokoll und Statusleiste

Das Fenster enthaelt keine Diagnoselogik. Es startet den Worker und stellt
``ReportModel`` dar; alles andere passiert in der Pipeline.
"""

from __future__ import annotations

import webbrowser
from html import escape
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableView,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..analyze import AnalysisResult
from ..collect.rundir import RunDirectory, default_runs_root
from ..config import Config, load_config
from ..config.loader import user_config_path, write_user_config
from . import detail, theme
from .delegates import SeverityChipDelegate, StatusChipDelegate
from .models import (
    CoverageModel,
    FindingsModel,
    UnknownEventsFilter,
    UnknownEventsModel,
    coverage_warning,
    summary_line,
)
from .status import Environment, ProbeHandle
from .worker import RunWorker, WorkerHandle


def _card(*widgets: QWidget) -> QFrame:
    frame = QFrame()
    frame.setObjectName("Karte")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(8)
    for widget in widgets:
        layout.addWidget(widget)
    return frame


def _section(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("Abschnitt")
    return label


class MainWindow(QMainWindow):
    """WinEventAI als Fenster."""

    UNKNOWN_TAB_TITLE = "Ohne Bewertung"
    UNKNOWN_TAB_INDEX = 2

    def __init__(self, config: Config | None = None) -> None:
        super().__init__()
        self.config = config or load_config()
        self.environment = Environment()
        self._worker: WorkerHandle | None = None
        self._probe: ProbeHandle | None = None
        self._run: RunDirectory | None = None
        self._result: AnalysisResult | None = None

        self.setWindowTitle(f"WinEventAI {__version__}")
        self.resize(1180, 820)
        self.setStyleSheet(theme.STYLESHEET)

        self._build_menu()
        self._build_body()
        self._set_idle_state()
        self._start_probe()

    # --- Aufbau --------------------------------------------------------------

    def _build_menu(self) -> None:
        datei = self.menuBar().addMenu("&Datei")

        self.action_open_run = QAction("Vorhandenen Lauf oeffnen ...", self)
        self.action_open_run.triggered.connect(self._open_existing_run)
        datei.addAction(self.action_open_run)

        self.action_open_report = QAction("Bericht im Browser oeffnen", self)
        self.action_open_report.triggered.connect(self._open_report)
        self.action_open_report.setEnabled(False)
        datei.addAction(self.action_open_report)

        self.action_open_folder = QAction("Laufverzeichnis oeffnen", self)
        self.action_open_folder.triggered.connect(self._open_run_folder)
        self.action_open_folder.setEnabled(False)
        datei.addAction(self.action_open_folder)

        datei.addSeparator()
        beenden = QAction("Beenden", self)
        beenden.triggered.connect(self.close)
        datei.addAction(beenden)

        einstellungen = self.menuBar().addMenu("&Einstellungen")
        anlegen = QAction("Konfiguration anlegen", self)
        anlegen.triggered.connect(self._create_config)
        einstellungen.addAction(anlegen)
        oeffnen = QAction("Konfiguration oeffnen", self)
        oeffnen.triggered.connect(self._open_config)
        einstellungen.addAction(oeffnen)
        neu_laden = QAction("Konfiguration neu laden", self)
        neu_laden.triggered.connect(self._reload_config)
        einstellungen.addAction(neu_laden)

    def _build_body(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 12, 16, 8)
        layout.setSpacing(10)

        layout.addWidget(self._build_runbar())

        self.label_headline = QLabel("Noch kein Lauf.")
        self.label_headline.setObjectName("Kopfzeile")
        self.label_summary = QLabel("Oben das Zeitfenster waehlen und auf Analyse starten.")
        self.label_summary.setObjectName("Unterzeile")
        layout.addWidget(self.label_headline)
        layout.addWidget(self.label_summary)

        self.label_warning = QLabel()
        self.label_warning.setObjectName("Warnbanner")
        self.label_warning.setWordWrap(True)
        self.label_warning.hide()
        layout.addWidget(self.label_warning)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_findings_tab(), "Befunde")
        self.tabs.addTab(self._build_coverage_tab(), "Abdeckung")
        self.tabs.addTab(self._build_unknown_tab(), self.UNKNOWN_TAB_TITLE)
        self.tabs.addTab(self._build_log_tab(), "Protokoll")
        layout.addWidget(self.tabs, stretch=1)

        self.setCentralWidget(central)

        self.status_left = QLabel()
        self.status_left.setTextFormat(Qt.TextFormat.RichText)
        self.status_right = QLabel()
        self.statusBar().addWidget(self.status_left, 1)
        self.statusBar().addPermanentWidget(self.status_right)

    def _build_runbar(self) -> QFrame:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        layout.addWidget(QLabel("Zeitfenster:"))
        self.spin_days = QSpinBox()
        self.spin_days.setRange(1, 365)
        self.spin_days.setValue(self.config.collect.days)
        self.spin_days.setSuffix(" Tage")
        self.spin_days.setToolTip(
            "Das Fenster wird nie automatisch verkleinert. Bei sehr grossen Kanaelen "
            "bricht der Lauf lieber ab, als still unvollstaendig zu werden."
        )
        layout.addWidget(self.spin_days)

        self.check_security = QCheckBox("Sicherheitsmodus")
        self.check_security.setToolTip(
            "Wertet zusaetzlich 1102, 4625-Serien, 4624 Typ 10, 7045 und weitere aus. "
            "Braucht Adminrechte. Ergebnisse sind Hinweise, keine forensischen "
            "Feststellungen."
        )
        layout.addWidget(self.check_security)

        self.check_ai = QCheckBox("Sprachmodell verwenden")
        self.check_ai.setChecked(self.config.ai.enabled)
        self.check_ai.setToolTip(
            "Der Bericht entsteht auch ohne Modell vollstaendig. Die KI erklaert nur, "
            "was die Regel-Engine bereits gefunden hat."
        )
        layout.addWidget(self.check_ai)

        layout.addStretch(1)

        self.progress = QProgressBar()
        self.progress.setFixedWidth(220)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setFormat("%p %")
        self.progress.hide()
        layout.addWidget(self.progress)

        self.button_cancel = QPushButton("Abbrechen")
        self.button_cancel.setObjectName("Abbruch")
        self.button_cancel.clicked.connect(self._cancel_run)
        self.button_cancel.hide()
        layout.addWidget(self.button_cancel)

        self.button_start = QPushButton("Analyse starten")
        self.button_start.setObjectName("Primaer")
        self.button_start.clicked.connect(self._start_run)
        layout.addWidget(self.button_start)

        return _card(row)

    def _build_findings_tab(self) -> QWidget:
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.findings_model = FindingsModel()
        self.table_findings = QTableView()
        self.table_findings.setModel(self.findings_model)
        self.table_findings.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table_findings.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table_findings.verticalHeader().hide()
        self.table_findings.verticalHeader().setDefaultSectionSize(32)
        self.table_findings.setAlternatingRowColors(False)
        self.table_findings.setShowGrid(False)
        self.table_findings.setWordWrap(False)
        # Farbe allein ist eine schlechte einzige Unterscheidung. Der Chip gibt
        # dem Schweregrad zusaetzlich Flaeche und Rahmen.
        self.table_findings.setItemDelegateForColumn(0, SeverityChipDelegate(self))
        header = self.table_findings.horizontalHeader()
        for column in (0, 2, 3):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setStretchLastSection(False)
        # Ohne das schneidet die Tabelle bei schmalem Splitter Spalten ab, statt
        # den Befundnamen zu kuerzen - und dann fehlt ausgerechnet die Anzahl.
        self.table_findings.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.table_findings.setHorizontalScrollMode(
            QTableView.ScrollMode.ScrollPerPixel
        )
        self.table_findings.selectionModel().selectionChanged.connect(self._show_detail)
        splitter.addWidget(self.table_findings)

        self.detail_view = QTextBrowser()
        self.detail_view.setOpenExternalLinks(True)
        self.detail_view.setHtml(detail.PLACEHOLDER)
        splitter.addWidget(self.detail_view)

        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 5)
        splitter.setSizes([560, 580])
        return splitter

    def _build_coverage_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        hinweis = QLabel(
            "„Keine Treffer“ heisst kein Befund. Alles andere heisst, dass an dieser "
            "Stelle nichts ausgesagt werden kann - unvollstaendige Quellen stehen oben."
        )
        hinweis.setObjectName("Unterzeile")
        hinweis.setWordWrap(True)
        layout.addWidget(hinweis)

        self.coverage_model = CoverageModel()
        self.table_coverage = QTableView()
        self.table_coverage.setModel(self.coverage_model)
        self.table_coverage.verticalHeader().hide()
        self.table_coverage.verticalHeader().setDefaultSectionSize(34)
        self.table_coverage.setShowGrid(False)
        self.table_coverage.setWordWrap(False)
        self.table_coverage.setItemDelegateForColumn(
            CoverageModel.COL_STATUS, StatusChipDelegate(self)
        )
        header = self.table_coverage.horizontalHeader()
        for column in range(len(CoverageModel.HEADERS)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        # Quellnamen aus dem Sweep sind sehr lang; ungekappt schoeben sie den
        # Hinweis aus dem Bild. Volle Laenge steht im Tooltip und ist ziehbar.
        header.setSectionResizeMode(CoverageModel.COL_SOURCE, QHeaderView.ResizeMode.Interactive)
        header.resizeSection(CoverageModel.COL_SOURCE, 340)
        # Der Hinweis bekommt eine feste, grosse Breite: Er ist die Spalte, die
        # erklaert, warum eine Quelle unvollstaendig ist. Als Dehnspalte bekaeme
        # er nur den Rest - und der ist neben den Zeitraeumen fast null.
        header.setSectionResizeMode(CoverageModel.COL_NOTE, QHeaderView.ResizeMode.Interactive)
        header.resizeSection(CoverageModel.COL_NOTE, 520)
        header.setStretchLastSection(True)
        self.table_coverage.setTextElideMode(Qt.TextElideMode.ElideRight)
        layout.addWidget(self.table_coverage, stretch=1)
        return page

    def _build_unknown_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        hinweis = QLabel(
            "Ereignisse, fuer die es weder eine Regel noch einen gesicherten Eintrag in "
            "der Wissensbasis gibt - vor allem aus dem Fehler-Sweep. Die Meldung ist der "
            "Originaltext von Windows. Eine Bewertung findet hier nicht statt; "
            "'nicht hinterlegt' heisst nicht 'harmlos'."
        )
        hinweis.setObjectName("Unterzeile")
        hinweis.setWordWrap(True)
        layout.addWidget(hinweis)

        filter_row = QHBoxLayout()
        self.check_unknown_errors = QCheckBox("Nur Kritisch und Fehler")
        self.check_unknown_errors.setChecked(True)
        filter_row.addWidget(self.check_unknown_errors)
        self.edit_unknown_search = QLineEdit()
        self.edit_unknown_search.setPlaceholderText("Suchen: Provider, ID, Kanal, Meldung ...")
        self.edit_unknown_search.setClearButtonEnabled(True)
        filter_row.addWidget(self.edit_unknown_search, stretch=1)
        self.label_unknown_count = QLabel()
        self.label_unknown_count.setObjectName("Unterzeile")
        filter_row.addWidget(self.label_unknown_count)
        layout.addLayout(filter_row)

        self.unknown_model = UnknownEventsModel()
        self.unknown_filter = UnknownEventsFilter()
        self.unknown_filter.setSourceModel(self.unknown_model)
        self.table_unknown = QTableView()
        self.table_unknown.setModel(self.unknown_filter)
        self.table_unknown.verticalHeader().hide()
        self.table_unknown.verticalHeader().setDefaultSectionSize(28)
        self.table_unknown.setShowGrid(False)
        self.table_unknown.setWordWrap(False)
        self.table_unknown.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table_unknown.setTextElideMode(Qt.TextElideMode.ElideRight)
        header = self.table_unknown.horizontalHeader()
        for column in range(6):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table_unknown, stretch=1)

        self.check_unknown_errors.toggled.connect(self._filter_unknown)
        self.edit_unknown_search.textChanged.connect(self._filter_unknown)
        self._filter_unknown()
        return page

    def _filter_unknown(self, *_args: object) -> None:
        self.unknown_filter.set_only_errors(self.check_unknown_errors.isChecked())
        self.unknown_filter.set_text(self.edit_unknown_search.text())
        sichtbar = self.unknown_filter.rowCount()
        gesamt = self.unknown_model.rowCount()
        self.label_unknown_count.setText(f"{sichtbar} von {gesamt} Gruppen")

    def _build_log_tab(self) -> QWidget:
        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("Protokoll")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(5000)
        return self.log_view

    # --- Zustand -------------------------------------------------------------

    def _set_idle_state(self) -> None:
        self.button_start.setEnabled(True)
        self.button_cancel.hide()
        self.progress.hide()
        self.spin_days.setEnabled(True)
        self.check_security.setEnabled(True)
        self.check_ai.setEnabled(True)

    def _set_busy_state(self) -> None:
        self.button_start.setEnabled(False)
        self.button_cancel.show()
        self.progress.setValue(0)
        self.progress.show()
        self.spin_days.setEnabled(False)
        self.check_security.setEnabled(False)
        self.check_ai.setEnabled(False)

    def _append_log(self, line: str) -> None:
        self.log_view.appendPlainText(line)

    # --- Umgebung ------------------------------------------------------------

    def _start_probe(self) -> None:
        self._probe = ProbeHandle(self.config)
        self._probe.probe.done.connect(self._apply_environment)
        self._probe.start()

    def _apply_environment(self, env: Environment) -> None:
        self.environment = env

        # Ampelpunkte statt Warndreiecken: Ein Punkt je Zustand liest sich beim
        # Ueberfliegen schneller, und die Langfassung steht im Tooltip.
        teile: list[str] = []
        for text, problem in (env.powershell_line(), env.admin_line(), env.ollama_line()):
            farbe = theme.ERR if problem else theme.OK
            teile.append(
                f'<span style="color:{farbe};">&#9679;</span>&nbsp;{escape(text)}'
            )
        self.status_left.setText("&nbsp;&nbsp;&nbsp;".join(teile))
        self.status_left.setToolTip(env.tooltip())

        _, ollama_problem = env.ollama_line()
        if ollama_problem and env.ollama_enabled:
            # Nicht still abwaehlen - das waere eine Entscheidung ueber den Kopf
            # des Nutzers. Aber sichtbar machen, dass der Haken nichts bewirkt.
            self.check_ai.setText("Sprachmodell verwenden (nicht verfuegbar)")
        else:
            self.check_ai.setText("Sprachmodell verwenden")

        rechts = f"{env.rules} Regeln · {env.kb_entries} KB-Eintraege"
        if not env.config_exists:
            rechts += "  ·  keine eigene Konfiguration"
        self.status_right.setText(rechts)

        if not env.ready_to_collect:
            self.button_start.setEnabled(False)
            self.button_start.setToolTip(
                "Ohne PowerShell laesst sich nichts erheben. Ein vorhandenes "
                "Laufverzeichnis kann trotzdem geoeffnet werden (Datei-Menue)."
            )
        if env.rules_error:
            self._append_log(f"Regeln: {env.rules_error}")
        if env.ollama_detail:
            self._append_log(f"Ollama: {env.ollama_detail}")

    # --- Lauf ----------------------------------------------------------------

    def _effective_config(self) -> Config:
        """Die Schalter der Startleiste auf die geladene Konfiguration anwenden."""
        config = self.config.model_copy(deep=True)
        config.collect.days = self.spin_days.value()
        config.rules.security_mode = self.check_security.isChecked()
        config.ai.enabled = self.check_ai.isChecked()
        if self.check_security.isChecked():
            for entry in config.collect.channels:
                if entry.name.lower() == "security":
                    entry.enabled = True
        return config

    def _start_run(self, *, existing: Path | None = None) -> None:
        if self._worker and self._worker.running:
            return

        config = self._effective_config()
        if existing is None and self.check_security.isChecked() and not self.environment.admin:
            antwort = QMessageBox.question(
                self,
                "Ohne Adminrechte",
                "Der Sicherheitsmodus braucht Adminrechte. Ohne sie bleibt der "
                "Security-Kanal gesperrt und erscheint als „keine Rechte“ - "
                "nicht als „kein Befund“.\n\nTrotzdem starten?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if antwort != QMessageBox.StandardButton.Yes:
                return

        self._set_busy_state()
        self.log_view.clear()

        worker = RunWorker(
            config,
            days=None if existing else self.spin_days.value(),
            security=self.check_security.isChecked(),
            existing_run=existing,
        )
        worker.progress.connect(self._on_progress)
        worker.log_line.connect(self._append_log)
        worker.finished_ok.connect(self._on_finished)
        worker.failed.connect(self._on_failed)

        self._worker = WorkerHandle(worker)
        self._worker.start()

    def _cancel_run(self) -> None:
        if self._worker:
            self._worker.worker.cancel()
            self.button_cancel.setEnabled(False)

    def _on_progress(self, percent: int, text: str) -> None:
        self.progress.setValue(percent)
        self.label_summary.setText(text)

    def _on_finished(self, run: RunDirectory, result: AnalysisResult) -> None:
        self._run = run
        self._result = result
        self._set_idle_state()
        self.button_cancel.setEnabled(True)

        report = result.report
        self.label_headline.setText(report.headline)
        self.label_summary.setText(summary_line(report))

        warnung = coverage_warning(report)
        if warnung:
            self.label_warning.setText(warnung)
            self.label_warning.show()
        else:
            self.label_warning.hide()

        self.coverage_model.set_rows(report.coverage)
        self.findings_model.set_findings(report.findings)
        self.unknown_model.set_rows(report.unknown_ids)
        self._filter_unknown()
        self.tabs.setTabText(
            self.UNKNOWN_TAB_INDEX, f"{self.UNKNOWN_TAB_TITLE} ({len(report.unknown_ids)})"
        )
        self.detail_view.setHtml(detail.PLACEHOLDER)

        if report.findings:
            self.table_findings.selectRow(0)
        if warnung:
            # Wer nicht vollstaendig erhoben hat, soll das zuerst sehen.
            self.tabs.setCurrentIndex(1)

        self.action_open_report.setEnabled(True)
        self.action_open_folder.setEnabled(True)
        self._append_log(f"Bericht: {run.report_dir}")

    def _on_failed(self, titel: str, text: str) -> None:
        self._set_idle_state()
        self.button_cancel.setEnabled(True)
        self.label_summary.setText(f"{titel}: {text.splitlines()[0]}")
        self._append_log(f"{titel}: {text}")
        QMessageBox.warning(self, titel, text)

    # --- Detail --------------------------------------------------------------

    def _show_detail(self) -> None:
        rows = self.table_findings.selectionModel().selectedRows()
        if not rows or self._result is None:
            self.detail_view.setHtml(detail.PLACEHOLDER)
            return
        finding = self.findings_model.finding_at(rows[0].row())
        if finding is None:
            return
        self.detail_view.setHtml(
            detail.finding_detail_html(finding, self._result.report.ai)
        )

    # --- Menuebefehle --------------------------------------------------------

    def _open_existing_run(self) -> None:
        start = str(default_runs_root())
        chosen = QFileDialog.getExistingDirectory(self, "Laufverzeichnis waehlen", start)
        if chosen:
            self._start_run(existing=Path(chosen))

    def _open_report(self) -> None:
        if self._run is None:
            return
        target = self._run.report_dir / "bericht.html"
        if not target.is_file():
            QMessageBox.information(
                self, "Kein Bericht", f"{target} wurde nicht gefunden."
            )
            return
        webbrowser.open(target.as_uri())

    def _open_run_folder(self) -> None:
        if self._run is None:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._run.path)))

    def _create_config(self) -> None:
        try:
            path = write_user_config()
        except FileExistsError as exc:
            QMessageBox.information(self, "Bereits vorhanden", str(exc))
            return
        QMessageBox.information(
            self,
            "Angelegt",
            f"{path}\n\nAlles ist auskommentiert. Wirksam wird nur, was Sie "
            "einkommentieren - der Elternschluessel muss dabei mit.",
        )
        self._start_probe()

    def _open_config(self) -> None:
        path = user_config_path()
        if not path.is_file():
            QMessageBox.information(
                self,
                "Nicht vorhanden",
                f"{path} existiert nicht.\n\nEinstellungen › Konfiguration anlegen.",
            )
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _reload_config(self) -> None:
        try:
            self.config = load_config()
        except Exception as exc:  # noqa: BLE001 - eine kaputte YAML darf nicht toeten
            QMessageBox.warning(self, "Konfiguration fehlerhaft", str(exc))
            return
        self.spin_days.setValue(self.config.collect.days)
        self.check_ai.setChecked(self.config.ai.enabled)
        self._append_log("Konfiguration neu geladen.")
        self._start_probe()

    # --- Ende ----------------------------------------------------------------

    def closeEvent(self, event) -> None:  # noqa: N802, ANN001 - Qt-Signatur
        """Threads sauber beenden, sonst stuerzt Qt beim Schliessen ab."""
        if self._worker and self._worker.running:
            antwort = QMessageBox.question(
                self,
                "Lauf laeuft noch",
                "Es laeuft gerade eine Analyse. Wirklich beenden?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if antwort != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._worker.stop()
        if self._probe:
            self._probe.stop()
        event.accept()
