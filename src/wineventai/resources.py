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


def program_data_dir() -> Path:
    """Writable directory for configuration, rule overlay and knowledge base.

    On Windows ``%PROGRAMDATA%\\WinEventAI``, otherwise ``~/.local/share/wineventai``.
    The directory is not created here; callers do that when needed.
    """
    import os

    program_data = os.environ.get("WINEVENTAI_DATA_DIR")
    if program_data:
        return Path(program_data)
    if sys.platform == "win32":
        base = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return Path(base) / "WinEventAI"
    return Path.home() / ".local" / "share" / "wineventai"
