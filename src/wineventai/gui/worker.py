"""Hintergrundarbeit fuer die Oberflaeche.

Der zentrale Punkt dieser Datei: Ein Lauf dauert Minuten. Liefe er im
Qt-Hauptthread, waere das Fenster die ganze Zeit eingefroren - Windows wuerde
es nach kurzer Zeit als "reagiert nicht" markieren. Deshalb laeuft die gesamte
Pipeline in einem ``QThread``, und die Oberflaeche erfaehrt ueber Signale, was
gerade passiert.

Zweiter Punkt: Hier steht KEINE Diagnoselogik. Der Worker ruft genau dieselben
Funktionen wie die Kommandozeile. Die Oberflaeche ist eine Huelle, sonst driften
GUI und CLI auseinander und man debuggt am Ende zwei Werkzeuge.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal

from ..analyze import AnalysisResult, analyze_run
from ..applog import configure
from ..collect.rundir import RunDirectory, is_admin
from ..collect.runner import CollectionAborted, collect_all, window_for
from ..config import Config
from ..rules.loader import RuleLoadError


class GuiLogStream:
    """Faengt das Anwendungslog ab und leitet es als Signal weiter.

    Das Anwendungslog schreibt sonst nach ``stderr``, das in einer GUI niemand
    sieht. Hier wird es zusaetzlich in das Protokollfenster gespiegelt - der
    Nutzer soll waehrend eines langen Laufs sehen, dass etwas passiert.

    Das ``try``/``except`` ist nicht Vorsicht, sondern Notwendigkeit: Das
    Anwendungslog ist prozessweit, dieser Stream haengt aber an EINEM Worker.
    Ist der Worker weg und irgendetwas loggt noch, wirft Qt
    "Signal source has been deleted" - und ein Logger, der die Anwendung
    umbringt, ist schlimmer als gar keiner.
    """

    def __init__(self, emit_line: Signal) -> None:
        self._emit = emit_line

    def write(self, text: str) -> int:
        cleaned = text.rstrip("\n")
        if cleaned:
            try:
                self._emit.emit(cleaned)
            except RuntimeError:
                return len(text)
        return len(text)

    def flush(self) -> None:
        return None


class RunWorker(QObject):
    """Fuehrt Erhebung und Auswertung aus und meldet den Fortschritt."""

    # Fortschritt in Prozent und ein Klartext, was gerade laeuft.
    progress = Signal(int, str)
    log_line = Signal(str)
    # Ein Lauf ist fertig: Laufverzeichnis und Ergebnis.
    finished_ok = Signal(object, object)
    failed = Signal(str, str)

    def __init__(
        self,
        config: Config,
        *,
        days: int | None = None,
        security: bool = False,
        runs_root: Path | None = None,
        existing_run: Path | None = None,
    ) -> None:
        super().__init__()
        self.config = config
        self.days = days
        self.security = security
        self.runs_root = runs_root
        self.existing_run = existing_run
        self._cancelled = False

    def cancel(self) -> None:
        """Bittet um Abbruch.

        Ehrlich zu den Grenzen: Ein laufender PowerShell-Aufruf laesst sich von
        hier aus nicht sofort beenden - er hat sein eigenes Wall-Clock-Limit.
        Der Abbruch greift zwischen den Quellen, nicht mitten in einer.
        """
        self._cancelled = True
        self.log_line.emit("Abbruch angefordert - laufende Quelle wird noch beendet.")

    # --- Ablauf --------------------------------------------------------------

    def run(self) -> None:
        log = configure(self.config.log_level, stream=GuiLogStream(self.log_line))
        try:
            run = self._open_or_create_run()
            log.attach_file(run.applog_path)

            if self.existing_run is None:
                self.progress.emit(5, "Quellen werden erhoben ...")
                collect_all(self.config, run, days=self.days)
                if self._cancelled:
                    self.failed.emit("Abgebrochen", "Der Lauf wurde vom Benutzer abgebrochen.")
                    return

            self.progress.emit(60, "Befunde werden ausgewertet ...")
            result: AnalysisResult = analyze_run(run, self.config)

            self.progress.emit(100, "Fertig.")
            self.finished_ok.emit(run, result)

        except CollectionAborted as exc:
            self.failed.emit("Erhebung abgebrochen", str(exc))
        except RuleLoadError as exc:
            self.failed.emit("Regeln fehlerhaft", str(exc))
        except FileNotFoundError as exc:
            self.failed.emit("Nicht gefunden", str(exc))
        except Exception as exc:  # noqa: BLE001 - eine GUI darf nie kommentarlos sterben
            self.failed.emit(type(exc).__name__, str(exc))
        finally:
            log.detach_file()
            # Das prozessweite Log wieder von diesem Worker loesen. Sonst zeigt
            # es nach dem Lauf auf ein Signal, dessen Besitzer bald weg ist.
            configure(self.config.log_level, stream=None)

    def _open_or_create_run(self) -> RunDirectory:
        if self.existing_run is not None:
            return RunDirectory.open(self.existing_run)

        days = self.days or self.config.collect.days
        window_from, window_to = window_for(days)
        run = RunDirectory.create(
            root=self.runs_root,
            requested_from=window_from,
            requested_to=window_to,
            security_mode=self.security,
            command_line="wineventai gui",
        )
        self.log_line.emit(
            f"Lauf angelegt: {run.path} "
            f"(Zeitfenster {days} Tage, Adminrechte: {'ja' if is_admin() else 'nein'})"
        )
        return run


class WorkerHandle:
    """Haelt Thread und Worker zusammen, damit nichts vorzeitig eingesammelt wird.

    Ohne diese Klammer sammelt der Python-Garbage-Collector den Worker ein,
    waehrend der C++-Thread noch laeuft - das aeussert sich als Absturz ohne
    Meldung und ist der klassische Anfaengerfehler bei Qt-Threads.
    """

    def __init__(self, worker: RunWorker) -> None:
        self.worker = worker
        self.thread = QThread()
        worker.moveToThread(self.thread)
        self.thread.started.connect(worker.run)
        worker.finished_ok.connect(self.thread.quit)
        worker.failed.connect(self.thread.quit)

    def start(self) -> None:
        self.thread.start()

    def stop(self, timeout_ms: int = 5000) -> None:
        self.worker.cancel()
        self.thread.quit()
        self.thread.wait(timeout_ms)

    @property
    def running(self) -> bool:
        return self.thread.isRunning()


def format_duration(started: datetime, finished: datetime) -> str:
    seconds = max((finished - started).total_seconds(), 0.0)
    if seconds < 60:
        return f"{seconds:.0f} s"
    return f"{int(seconds // 60)} min {int(seconds % 60)} s"
