"""Einstiegspunkt fuer ``python -m wineventai`` und fuer beide EXE-Dateien.

Die PyInstaller-Spezifikation baut ``wineventai.exe`` (Konsole) und
``wineventai-gui.exe`` (ohne Konsolenfenster) aus EINER Analyse, damit beide
sich dieselben Bibliotheken teilen. Beide starten deshalb dieses Skript; welche
Oberflaeche gemeint ist, entscheidet der Name der gestarteten Datei. Ohne diese
Weiche oeffnete die GUI-Datei die Kommandozeile - ohne Konsole, also unsichtbar.
"""

from __future__ import annotations

import sys
from pathlib import Path

GUI_EXECUTABLE_SUFFIX = "-gui"


def wants_gui(executable: str, frozen: bool) -> bool:
    """True, wenn die gestartete EXE die Oberflaeche ist."""
    return frozen and Path(executable).stem.lower().endswith(GUI_EXECUTABLE_SUFFIX)


def main() -> None:
    if wants_gui(sys.executable, bool(getattr(sys, "frozen", False))):
        from .gui.app import main as gui_main

        raise SystemExit(gui_main())

    from .cli import cli

    cli()


if __name__ == "__main__":
    main()
