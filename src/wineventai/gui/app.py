"""Entry point of the user interface.

PySide6 is an OPTIONAL dependency (``pip install -e ".[gui]"`` in the project
folder - the package is not on PyPI). The command line must run without Qt: it
is the way for servers, for software distribution and for sessions without a
graphical logon.
"""

from __future__ import annotations

import sys

from ..config import Config, load_config

GUI_MISSING = (
    "The user interface needs PySide6.\n"
    "\n"
    "Install it in the project folder (where pyproject.toml is):\n"
    "    pip install -e \".[gui]\"\n"
    "\n"
    "Or only the library, without reinstalling the package:\n"
    "    pip install PySide6\n"
    "\n"
    "WinEventAI is not on PyPI - 'pip install wineventai[gui]' without a path\n"
    "does not find it. The command line works without Qt as well."
)


def gui_available() -> bool:
    """Checks whether Qt is present without importing it."""
    from importlib.util import find_spec

    return find_spec("PySide6") is not None


def run_gui(config: Config | None = None) -> int:
    """Starts the window and returns the exit code of the application."""
    if not gui_available():
        print(GUI_MISSING, file=sys.stderr)
        return 3

    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication

    from .main_window import MainWindow

    QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeMenuBar, False)
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("WinEventAI")
    app.setOrganizationName("WinEventAI")

    window = MainWindow(config or load_config())
    window.show()
    return int(app.exec())


def main() -> int:  # pragma: no cover - entry point
    return run_gui()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
