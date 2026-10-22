"""Einstiegspunkt der Oberflaeche.

PySide6 ist eine OPTIONALE Abhaengigkeit (``pip install -e ".[gui]"`` im
Projektordner - das Paket liegt nicht auf PyPI). Die
Kommandozeile muss ohne Qt laufen: Sie ist der Weg fuer Server, fuer
Softwareverteilung und fuer Sitzungen ohne grafische Anmeldung.
"""

from __future__ import annotations

import sys

from ..config import Config, load_config

GUI_MISSING = (
    "Die Oberflaeche braucht PySide6.\n"
    "\n"
    "Nachinstallieren im Projektordner (dort, wo pyproject.toml liegt):\n"
    "    pip install -e \".[gui]\"\n"
    "\n"
    "Oder nur die Bibliothek, ohne das Paket neu zu installieren:\n"
    "    pip install PySide6\n"
    "\n"
    "WinEventAI liegt nicht auf PyPI - 'pip install wineventai[gui]' ohne\n"
    "Pfadangabe findet es nicht. Die Kommandozeile funktioniert auch ohne Qt."
)


def gui_available() -> bool:
    """Prueft, ob Qt vorhanden ist, ohne es zu importieren."""
    from importlib.util import find_spec

    return find_spec("PySide6") is not None


def run_gui(config: Config | None = None) -> int:
    """Startet das Fenster und gibt den Rueckgabewert der Anwendung zurueck."""
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


def main() -> int:  # pragma: no cover - Einstiegspunkt
    return run_gui()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
