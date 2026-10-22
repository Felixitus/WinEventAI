"""Grafische Oberflaeche (PySide6, optional).

Die Oberflaeche ist eine Huelle um dieselben Funktionen, die auch die
Kommandozeile aufruft. Sie enthaelt keine Diagnoselogik - sonst driften GUI und
CLI auseinander, und man debuggt am Ende zwei Werkzeuge.

Importiert wird Qt erst in ``run_gui``, damit ``import wineventai.gui`` auch auf
Systemen ohne PySide6 funktioniert.
"""

from .app import GUI_MISSING, gui_available, run_gui

__all__ = ["GUI_MISSING", "gui_available", "run_gui"]
