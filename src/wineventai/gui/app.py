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


ICON_RESOURCE = "gui/assets/wineventai.ico"

#: Own taskbar identity. Without it Windows groups a window started via
#: ``python -m wineventai gui`` under python.exe and shows the Python icon,
#: however often the window sets its own.
APP_USER_MODEL_ID = "WinEventAI.Diagnostics"


def app_icon() -> object:
    """The program icon as QIcon - an empty icon if the file is missing.

    A missing icon is cosmetic; it must never keep the window from opening.
    """
    from PySide6.QtGui import QIcon

    from ..resources import resource_path

    try:
        return QIcon(str(resource_path(ICON_RESOURCE)))
    except FileNotFoundError:
        return QIcon()


def _set_taskbar_identity() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except (AttributeError, OSError):
        # Cosmetic only: the taskbar then shows the icon of the host process.
        return


def run_gui(config: Config | None = None, *, security: bool = False) -> int:
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
    _set_taskbar_identity()
    app.setWindowIcon(app_icon())

    window = MainWindow(config or load_config(), security=security)
    window.show()
    return int(app.exec())


def main() -> int:  # pragma: no cover - entry point
    from .elevation import wants_security_mode

    return run_gui(security=wants_security_mode(sys.argv))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
