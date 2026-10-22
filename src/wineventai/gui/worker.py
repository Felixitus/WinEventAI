"""Background work for the user interface.

The central point of this file: a run takes minutes. If it ran in the Qt main
thread, the window would be frozen the whole time - Windows would mark it as
"not responding" after a short while. The whole pipeline therefore runs in a
``QThread``, and the interface learns via signals what is going on.

Second point: there is NO diagnostic logic here. The worker calls exactly the
same functions as the command line. The interface is a shell; otherwise GUI and
CLI drift apart and in the end one debugs two tools.
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
    """Captures the application log and forwards it as a signal.

    The application log otherwise writes to ``stderr``, which nobody sees in a
    GUI. Here it is mirrored into the log window as well - the user should see
    during a long run that something is happening.

    The ``try``/``except`` is not caution but necessity: the application log
    is process-wide, but this stream hangs on ONE worker. If the worker is gone
    and something still logs, Qt raises "Signal source has been deleted" - and
    a logger that kills the application is worse than none.
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
    """Runs collection and analysis and reports progress."""

    # Progress in percent and plain text of what is running.
    progress = Signal(int, str)
    log_line = Signal(str)
    # A run is finished: run directory and result.
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
        """Asks for cancellation.

        Honest about the limits: a running PowerShell call cannot be ended
        immediately from here - it has its own wall-clock limit. Cancellation
        takes effect between sources, not in the middle of one.
        """
        self._cancelled = True
        self.log_line.emit("Cancellation requested - the current source is still finishing.")

    # --- Flow ----------------------------------------------------------------

    def run(self) -> None:
        log = configure(self.config.log_level, stream=GuiLogStream(self.log_line))
        try:
            run = self._open_or_create_run()
            log.attach_file(run.applog_path)

            if self.existing_run is None:
                self.progress.emit(5, "Collecting sources ...")
                collect_all(self.config, run, days=self.days)
                if self._cancelled:
                    self.failed.emit("Cancelled", "The run was cancelled by the user.")
                    return

            self.progress.emit(60, "Analyzing findings ...")
            result: AnalysisResult = analyze_run(run, self.config)

            self.progress.emit(100, "Done.")
            self.finished_ok.emit(run, result)

        except CollectionAborted as exc:
            self.failed.emit("Collection aborted", str(exc))
        except RuleLoadError as exc:
            self.failed.emit("Rules invalid", str(exc))
        except FileNotFoundError as exc:
            self.failed.emit("Not found", str(exc))
        except Exception as exc:  # noqa: BLE001 - a GUI must never die without a word
            self.failed.emit(type(exc).__name__, str(exc))
        finally:
            log.detach_file()
            # Detach the process-wide log from this worker again. Otherwise it
            # points after the run to a signal whose owner will soon be gone.
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
            f"Run created: {run.path} "
            f"(time window {days} days, admin rights: {'yes' if is_admin() else 'no'})"
        )
        return run


class WorkerHandle:
    """Keeps thread and worker together so nothing is collected prematurely.

    Without this clamp the Python garbage collector collects the worker while
    the C++ thread is still running - that shows up as a crash without a
    message and is the classic beginner's mistake with Qt threads.
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
