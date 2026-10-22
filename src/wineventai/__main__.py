"""Entry point for ``python -m wineventai`` and for both EXE files.

The PyInstaller spec builds ``wineventai.exe`` (console) and
``wineventai-gui.exe`` (without a console window) from ONE analysis so that
both share the same libraries. Both therefore start this script; which
interface is meant is decided by the name of the started file. Without this
switch the GUI file opened the command line - without a console, i.e.
invisibly.

Absolute imports, no relative ones: PyInstaller runs this file as a script, not
as a module of a package. ``from .cli import cli`` fails there with
"attempted relative import with no known parent package" - the EXE did not
start at all because of that.
"""

from __future__ import annotations

import sys
from pathlib import Path

GUI_EXECUTABLE_SUFFIX = "-gui"


def wants_gui(executable: str, frozen: bool) -> bool:
    """True if the started EXE is the user interface."""
    return frozen and Path(executable).stem.lower().endswith(GUI_EXECUTABLE_SUFFIX)


def main() -> None:
    if wants_gui(sys.executable, bool(getattr(sys, "frozen", False))):
        from wineventai.gui.app import main as gui_main

        raise SystemExit(gui_main())

    from wineventai.cli import cli

    cli()


if __name__ == "__main__":
    main()
