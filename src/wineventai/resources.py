"""Resolving bundled package resources.

Exactly one function knows the three possible locations:

1. ``sys._MEIPASS``      - PyInstaller (one-dir as well as one-file)
2. the directory next to the executable
3. ``importlib.resources`` - regular installation as a package

All other modules only call ``resource_path`` and know nothing about the
packaging.
"""

from __future__ import annotations

import sys
from importlib import resources
from pathlib import Path

_PACKAGE = "wineventai"


def _frozen_roots() -> list[Path]:
    """Candidate directories when the program runs bundled as an EXE."""
    roots: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots.append(Path(meipass) / _PACKAGE)
        roots.append(Path(meipass))
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        roots.append(exe_dir / "_internal" / _PACKAGE)
        roots.append(exe_dir / _PACKAGE)
        roots.append(exe_dir)
    return roots


def resource_path(relative: str) -> Path:
    """Returns the path of a bundled resource.

    ``relative`` is always package-relative with forward slashes, e.g.
    ``"rules/builtin/core_system.yaml"``.

    Raises:
        FileNotFoundError: if the resource exists in none of the locations.
    """
    rel = Path(relative)

    for root in _frozen_roots():
        candidate = root / rel
        if candidate.exists():
            return candidate

    try:
        base = resources.files(_PACKAGE)
        candidate = Path(str(base.joinpath(*rel.parts)))
        if candidate.exists():
            return candidate
    except (ModuleNotFoundError, TypeError):  # pragma: no cover - package missing
        pass

    fallback = Path(__file__).resolve().parent / rel
    if fallback.exists():
        return fallback

    raise FileNotFoundError(f"Bundled resource not found: {relative}")


def read_resource_text(relative: str) -> str:
    """Reads a bundled text resource as UTF-8."""
    return resource_path(relative).read_text(encoding="utf-8")


#: Where versions before 2.3.0 kept their data. Only looked at to warn - never
#: read from, see ``data_dir``.
LEGACY_SHARED_DIR = Path(r"C:\ProgramData\WinEventAI")


def data_dir() -> Path:
    """Writable directory for configuration, rule overlay, knowledge base and runs.

    On Windows ``%LOCALAPPDATA%/WinEventAI``, otherwise
    ``~/.local/share/wineventai``. The directory is not created here; callers do
    that when needed.

    Why per user and not ``%PROGRAMDATA%`` (as up to 2.2.0): below ProgramData
    every local user may create files in every subfolder and read everything.
    A normal user could therefore plant a ``wineventai.yaml`` with
    ``allow_cloud`` and a foreign address, or a rule overlay, and the next
    administrator who runs the tool would load it - and send redacted Security
    log content out. The reports themselves, with logon times and account
    names, were readable by everyone as well. The profile folder is private to
    its owner (plus SYSTEM and administrators), and an elevated start of the
    same account uses the same folder.
    """
    import os

    override = os.environ.get("WINEVENTAI_DATA_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "WinEventAI"
    return Path.home() / ".local" / "share" / "wineventai"


def legacy_shared_data() -> Path | None:
    """The pre-2.3.0 shared data folder, if it still exists - for a visible note.

    Its content is deliberately not migrated: whatever lies there may have been
    planted by another user, and copying it into the private folder would carry
    exactly that risk along.
    """
    import os

    if sys.platform != "win32" or os.environ.get("WINEVENTAI_DATA_DIR"):
        return None
    return LEGACY_SHARED_DIR if LEGACY_SHARED_DIR.is_dir() else None


LEGACY_NOTE = (
    f"Data of a version before 2.3.0 lies in {LEGACY_SHARED_DIR}. It is no "
    "longer read: every user of this machine can write there. Configuration, "
    "rules and runs now live in your own profile ({target}). Copy your own "
    "configuration over by hand if you trust it, then delete the old folder."
)
