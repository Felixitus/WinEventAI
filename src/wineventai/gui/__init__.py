"""Graphical user interface (PySide6, optional).

The interface is a shell around the same functions the command line calls. It
contains no diagnostic logic - otherwise GUI and CLI drift apart, and in the
end one debugs two tools.

Qt is only imported in ``run_gui``, so that ``import wineventai.gui`` also works
on systems without PySide6.
"""

from .app import GUI_MISSING, gui_available, run_gui

__all__ = ["GUI_MISSING", "gui_available", "run_gui"]
