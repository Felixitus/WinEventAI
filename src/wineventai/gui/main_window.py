"""The main window.

Layout from top to bottom - and the order is about content, not cosmetics:

1. Run bar: time window, security mode, start
2. Headline with the one sentence that is read first
3. Warning banner, if the period was not collected completely
4. Coverage - BEFORE the findings, for the same reason as in the report
5. List of findings on the left, detail on the right
6. Log and status bar

The window contains no diagnostic logic. It starts the worker and displays
``ReportModel``; everything else happens in the pipeline.
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
from ..analyze import REPORT_HTML, AnalysisResult
from ..collect.rundir import RunDirectory, default_runs_root
from ..config import Config, load_config
from ..config.loader import user_config_path, write_user_config
from . import detail, theme
from .delegates import SeverityChipDelegate, StatusChipDelegate
from .elevation import relaunch_elevated
from .models import (
    CoverageModel,
    FindingsModel,
    UnknownEventsFilter,
    UnknownEventsModel,
    coverage_warning,
    summary_line,
)
from .status import Environment, ProbeHandle
from .worker import EvidenceWorker, RunWorker, WorkerHandle


def _card(*widgets: QWidget) -> QFrame:
    frame = QFrame()
    frame.setObjectName("Card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(8)
    for widget in widgets:
        layout.addWidget(widget)
    return frame


class MainWindow(QMainWindow):
    """WinEventAI as a window."""

    UNKNOWN_TAB_TITLE = "Not assessed"
    UNKNOWN_TAB_INDEX = 2
    AI_LABEL = "Use language model"

    def __init__(self, config: Config | None = None, *, security: bool = False) -> None:
        super().__init__()
        self.config = config or load_config()
        self.environment = Environment()
        self._worker: WorkerHandle | None = None
        self._evidence: WorkerHandle | None = None
        self._probe: ProbeHandle | None = None
        self._run: RunDirectory | None = None
        self._result: AnalysisResult | None = None

        self.setWindowTitle(f"WinEventAI {__version__}")
        self.resize(1180, 820)
        self.setStyleSheet(theme.STYLESHEET)

        self._build_menu()
        self._build_body()
        self._set_idle_state()
        self.check_security.setChecked(security)
        self._start_probe()

    # --- Layout --------------------------------------------------------------

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")

        self.action_open_run = QAction("Open existing run ...", self)
        self.action_open_run.triggered.connect(self._open_existing_run)
        file_menu.addAction(self.action_open_run)

        self.action_open_report = QAction("Open report in browser", self)
        self.action_open_report.triggered.connect(self._open_report)
        self.action_open_report.setEnabled(False)
        file_menu.addAction(self.action_open_report)

        self.action_open_folder = QAction("Open run directory", self)
        self.action_open_folder.triggered.connect(self._open_run_folder)
        self.action_open_folder.setEnabled(False)
        file_menu.addAction(self.action_open_folder)

        file_menu.addSeparator()
        quit_action = QAction("Exit", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        settings_menu = self.menuBar().addMenu("&Settings")
        create = QAction("Create configuration", self)
        create.triggered.connect(self._create_config)
        settings_menu.addAction(create)
        open_config = QAction("Open configuration", self)
        open_config.triggered.connect(self._open_config)
        settings_menu.addAction(open_config)
        reload_config = QAction("Reload configuration", self)
        reload_config.triggered.connect(self._reload_config)
        settings_menu.addAction(reload_config)

    def _build_body(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 12, 16, 8)
        layout.setSpacing(10)

        layout.addWidget(self._build_runbar())

        self.label_headline = QLabel("No run yet.")
        self.label_headline.setObjectName("Headline")
        self.label_summary = QLabel("Choose the time window above and click Start analysis.")
        self.label_summary.setObjectName("Subline")
        layout.addWidget(self.label_headline)
        layout.addWidget(self.label_summary)
        self.label_compare = QLabel()
        self.label_compare.setObjectName("Subline")
        self.label_compare.setWordWrap(True)
        self.label_compare.hide()
        layout.addWidget(self.label_compare)
        layout.addWidget(self._build_actions())

        self.label_warning = QLabel()
        self.label_warning.setObjectName("WarningBanner")
        self.label_warning.setWordWrap(True)
        self.label_warning.hide()
        layout.addWidget(self.label_warning)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_findings_tab(), "Findings")
        self.tabs.addTab(self._build_coverage_tab(), "Coverage")
        self.tabs.addTab(self._build_unknown_tab(), self.UNKNOWN_TAB_TITLE)
        self.tabs.addTab(self._build_log_tab(), "Log")
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

        layout.addWidget(QLabel("Time window:"))
        self.spin_days = QSpinBox()
        self.spin_days.setRange(1, 365)
        self.spin_days.setValue(self.config.collect.days)
        self.spin_days.setSuffix(" days")
        self.spin_days.setToolTip(
            "The window is never shrunk automatically. With very large channels the "
            "run would rather abort than become silently incomplete."
        )
        layout.addWidget(self.spin_days)

        self.check_security = QCheckBox("Security mode")
        self.check_security.setToolTip(
            "Additionally evaluates 1102, 4625 series, 4624 type 10, 7045 and more. "
            "Needs admin rights. Results are indications, not forensic findings."
        )
        layout.addWidget(self.check_security)

        self.check_ai = QCheckBox(self.AI_LABEL)
        self.check_ai.setChecked(self.config.ai.enabled)
        self.check_ai.setToolTip(
            "The report is complete without a model as well. The AI only explains what "
            "the rule engine has already found."
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

        self.button_cancel = QPushButton("Cancel")
        self.button_cancel.setObjectName("Cancel")
        self.button_cancel.clicked.connect(self._cancel_run)
        self.button_cancel.hide()
        layout.addWidget(self.button_cancel)

        self.button_admin = QPushButton("Restart as administrator")
        self.button_admin.setToolTip(
            "Starts WinEventAI again with the Windows UAC prompt. Needed for the "
            "Security channel and the security mode."
        )
        self.button_admin.clicked.connect(self._restart_as_admin)
        self.button_admin.hide()
        layout.addWidget(self.button_admin)

        self.button_start = QPushButton("Start analysis")
        self.button_start.setObjectName("Primary")
        self.button_start.clicked.connect(self._start_run)
        layout.addWidget(self.button_start)

        return _card(row)

    def _build_actions(self) -> QWidget:
        """What to do with a finished run - visible, not hidden in the File menu.

        The menu entries stay; the buttons are for whoever never opens a menu.
        They appear only once there is a run, so that an empty window does not
        offer actions that cannot work yet.
        """
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.button_report = QPushButton("Open report")
        self.button_report.clicked.connect(self._open_report)
        self.button_folder = QPushButton("Open folder")
        self.button_folder.clicked.connect(self._open_run_folder)
        self.button_evidence = QPushButton("Create evidence ZIP")
        self.button_evidence.setToolTip(
            "Original .evtx of the collected core channels, report, manifest with "
            "SHA-256 and verify.ps1. Not pseudonymized - it is evidence."
        )
        self.button_evidence.clicked.connect(self._create_evidence)
        for button in (self.button_report, self.button_folder, self.button_evidence):
            layout.addWidget(button)
        layout.addStretch(1)

        self.actions_row = row
        row.hide()
        return row

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
        # Color alone is a poor only distinction. The chip additionally gives the
        # severity an area and a border.
        self.table_findings.setItemDelegateForColumn(0, SeverityChipDelegate(self))
        header = self.table_findings.horizontalHeader()
        for column in (0, 2, 3):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setStretchLastSection(False)
        # Without this the table cuts off columns in a narrow splitter instead of
        # shortening the finding name - and then it is the count that is missing.
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

        hint = QLabel(
            '"No hits" means no finding. Anything else means nothing can be said at this '
            "point - incomplete sources are at the top."
        )
        hint.setObjectName("Subline")
        hint.setWordWrap(True)
        layout.addWidget(hint)

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
        # Source names from the sweep are very long; uncapped they would push the
        # note out of view. The full length is in the tooltip and can be dragged.
        header.setSectionResizeMode(CoverageModel.COL_SOURCE, QHeaderView.ResizeMode.Interactive)
        header.resizeSection(CoverageModel.COL_SOURCE, 340)
        # The note gets a fixed, large width: it is the column that explains why
        # a source is incomplete. As a stretch column it would only get the
        # rest - and next to the periods that is almost nothing.
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

        hint = QLabel(
            "Events for which there is neither a rule nor a verified entry in the "
            "knowledge base - mostly from the error sweep. The message is the original "
            "Windows text. No assessment takes place here; 'not on record' does not mean "
            "'harmless'."
        )
        hint.setObjectName("Subline")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        filter_row = QHBoxLayout()
        self.check_unknown_errors = QCheckBox("Critical and error only")
        self.check_unknown_errors.setChecked(True)
        filter_row.addWidget(self.check_unknown_errors)
        self.edit_unknown_search = QLineEdit()
        self.edit_unknown_search.setPlaceholderText("Search: provider, id, channel, message ...")
        self.edit_unknown_search.setClearButtonEnabled(True)
        filter_row.addWidget(self.edit_unknown_search, stretch=1)
        self.label_unknown_count = QLabel()
        self.label_unknown_count.setObjectName("Subline")
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
        visible = self.unknown_filter.rowCount()
        total = self.unknown_model.rowCount()
        self.label_unknown_count.setText(f"{visible} of {total} groups")

    def _build_log_tab(self) -> QWidget:
        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("Log")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(5000)
        return self.log_view

    # --- State ---------------------------------------------------------------

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

    # --- Environment ---------------------------------------------------------

    def _start_probe(self) -> None:
        self._probe = ProbeHandle(self.config)
        self._probe.probe.done.connect(self._apply_environment)
        self._probe.start()

    def _apply_environment(self, env: Environment) -> None:
        self.environment = env

        # Traffic-light dots instead of warning triangles: one dot per state
        # reads faster when skimming, and the long version is in the tooltip.
        parts: list[str] = []
        for text, problem in (env.powershell_line(), env.admin_line(), env.ollama_line()):
            color = theme.ERR if problem else theme.OK
            parts.append(
                f'<span style="color:{color};">&#9679;</span>&nbsp;{escape(text)}'
            )
        self.status_left.setText("&nbsp;&nbsp;&nbsp;".join(parts))
        self.status_left.setToolTip(env.tooltip())

        _, ollama_problem = env.ollama_line()
        if ollama_problem and env.ollama_enabled:
            # Do not untick silently - that would be a decision over the user's
            # head. But make visible that the tick has no effect: the report is
            # built from the rule engine alone.
            self.check_ai.setText(f"{self.AI_LABEL} (not available - rules only)")
        else:
            self.check_ai.setText(self.AI_LABEL)

        right = f"{env.rules} rules · {env.kb_entries} KB entries"
        if not env.config_exists:
            right += "  ·  no own configuration"
        self.status_right.setText(right)

        if not env.ready_to_collect:
            self.button_start.setEnabled(False)
            self.button_start.setToolTip(
                "Nothing can be collected without PowerShell. An existing run "
                "directory can still be opened (File menu)."
            )
        self.button_admin.setVisible(env.can_elevate)
        if env.legacy_note:
            self._append_log(env.legacy_note)
        if env.rules_error:
            self._append_log(f"Rules: {env.rules_error}")
        if env.ollama_detail:
            self._append_log(f"Ollama: {env.ollama_detail}")

    # --- Run -----------------------------------------------------------------

    def _effective_config(self) -> Config:
        """Applies the switches of the run bar to the loaded configuration."""
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
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Question)
            box.setWindowTitle("Without admin rights")
            box.setText(
                "Security mode needs admin rights. Without them the Security channel "
                'stays locked and appears as "no permission" - not as "no finding".'
            )
            elevate = box.addButton(
                "Restart as administrator", QMessageBox.ButtonRole.AcceptRole
            )
            anyway = box.addButton("Start anyway", QMessageBox.ButtonRole.DestructiveRole)
            box.addButton(QMessageBox.StandardButton.Cancel)
            box.exec()
            if box.clickedButton() is elevate:
                self._restart_as_admin()
                return
            if box.clickedButton() is not anyway:
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

        warning = coverage_warning(report)
        if warning:
            self.label_warning.setText(warning)
            self.label_warning.show()
        else:
            self.label_warning.hide()

        self.coverage_model.set_rows(report.coverage)
        self.findings_model.set_findings(report.findings, report.comparison)
        self.label_compare.setText(report.comparison.summary())
        self.label_compare.show()
        self.unknown_model.set_rows(report.unknown_ids)
        self._filter_unknown()
        self.tabs.setTabText(
            self.UNKNOWN_TAB_INDEX, f"{self.UNKNOWN_TAB_TITLE} ({len(report.unknown_ids)})"
        )
        self.detail_view.setHtml(detail.PLACEHOLDER)

        if report.findings:
            self.table_findings.selectRow(0)
        if warning:
            # Whoever did not collect completely should see that first.
            self.tabs.setCurrentIndex(1)

        self.action_open_report.setEnabled(True)
        self.action_open_folder.setEnabled(True)
        self.actions_row.show()
        self.button_evidence.setEnabled(True)
        self._append_log(f"Report: {run.report_dir}")

    def _on_failed(self, title: str, text: str) -> None:
        self._set_idle_state()
        self.button_cancel.setEnabled(True)
        self.label_summary.setText(f"{title}: {text.splitlines()[0]}")
        self._append_log(f"{title}: {text}")
        QMessageBox.warning(self, title, text)

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

    # --- Menu commands -------------------------------------------------------

    def _open_existing_run(self) -> None:
        start = str(default_runs_root())
        chosen = QFileDialog.getExistingDirectory(self, "Choose run directory", start)
        if chosen:
            self._start_run(existing=Path(chosen))

    def _open_report(self) -> None:
        if self._run is None:
            return
        target = self._run.report_dir / REPORT_HTML
        if not target.is_file():
            QMessageBox.information(
                self, "No report", f"{target} was not found."
            )
            return
        webbrowser.open(target.as_uri())

    def _open_run_folder(self) -> None:
        if self._run is None:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._run.path)))

    def _create_evidence(self) -> None:
        if self._run is None or (self._evidence and self._evidence.running):
            return
        self.button_evidence.setEnabled(False)
        worker = EvidenceWorker(self.config, self._run)
        worker.log_line.connect(self._append_log)
        worker.finished_ok.connect(self._on_evidence_done)
        worker.failed.connect(self._on_evidence_failed)
        self._evidence = WorkerHandle(worker)
        self._evidence.start()

    def _on_evidence_done(self, path: Path) -> None:
        self.button_evidence.setEnabled(True)
        self._append_log(f"Evidence bundle: {path}")
        QMessageBox.information(
            self,
            "Evidence bundle created",
            f"{path}\n\nCheck it after extracting with verify.ps1. The bundle is not "
            "pseudonymized - hand it on only where the raw logs may go.",
        )

    def _on_evidence_failed(self, title: str, text: str) -> None:
        self.button_evidence.setEnabled(True)
        self._append_log(f"Evidence: {title}: {text}")
        QMessageBox.warning(self, title, text)

    def _restart_as_admin(self) -> None:
        if self._worker and self._worker.running:
            QMessageBox.information(
                self, "Run in progress", "Wait for the analysis to finish, then restart."
            )
            return
        if relaunch_elevated(security=self.check_security.isChecked()):
            self.close()
            return
        # Declined UAC prompt or no shell: the current window simply stays.
        self._append_log("Restart as administrator was cancelled or is not possible.")

    def _create_config(self) -> None:
        try:
            path = write_user_config()
        except FileExistsError as exc:
            QMessageBox.information(self, "Already present", str(exc))
            return
        QMessageBox.information(
            self,
            "Created",
            f"{path}\n\nEverything is commented out. Only what you uncomment takes "
            "effect - the parent key has to come along.",
        )
        self._start_probe()

    def _open_config(self) -> None:
        path = user_config_path()
        if not path.is_file():
            QMessageBox.information(
                self,
                "Not present",
                f"{path} does not exist.\n\nSettings › Create configuration.",
            )
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _reload_config(self) -> None:
        try:
            self.config = load_config()
        except Exception as exc:  # noqa: BLE001 - a broken YAML must not kill the window
            QMessageBox.warning(self, "Configuration invalid", str(exc))
            return
        self.spin_days.setValue(self.config.collect.days)
        self.check_ai.setChecked(self.config.ai.enabled)
        self._append_log("Configuration reloaded.")
        self._start_probe()

    # --- End -----------------------------------------------------------------

    def closeEvent(self, event) -> None:  # noqa: N802, ANN001 - Qt signature
        """End threads cleanly, otherwise Qt crashes on close."""
        if self._worker and self._worker.running:
            answer = QMessageBox.question(
                self,
                "Run still in progress",
                "An analysis is currently running. Really exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._worker.stop()
        if self._evidence and self._evidence.running:
            self._evidence.stop()
        if self._probe:
            self._probe.stop()
        event.accept()
