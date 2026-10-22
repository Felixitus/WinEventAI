"""Aufloesung mitgelieferter Paket-Ressourcen.

Genau eine Funktion kennt die drei moeglichen Ablageorte:

1. ``sys._MEIPASS``      - PyInstaller (one-dir wie one-file)
2. Verzeichnis neben der ausfuehrbaren Datei
3. ``importlib.resources`` - regulaere Installation als Paket

Alle uebrigen Module rufen nur ``resource_path`` auf und wissen nichts ueber
das Packaging.
"""

from __future__ import annotations

import sys
from importlib import resources
from pathlib import Path

_PACKAGE = "wineventai"


def _frozen_roots() -> list[Path]:
    """Kandidatenverzeichnisse, wenn das Programm als EXE gebuendelt laeuft."""
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
    """Liefert den Pfad einer mitgelieferten Ressource.

    ``relative`` ist immer paketrelativ mit Schraegstrichen, z.B.
    ``"rules/builtin/core_system.yaml"``.

    Raises:
        FileNotFoundError: wenn die Ressource in keinem Ablageort existiert.
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
    except (ModuleNotFoundError, TypeError):  # pragma: no cover - Paket fehlt
        pass

    fallback = Path(__file__).resolve().parent / rel
    if fallback.exists():
        return fallback

    raise FileNotFoundError(f"Mitgelieferte Ressource nicht gefunden: {relative}")


def read_resource_text(relative: str) -> str:
    """Liest eine mitgelieferte Textressource als UTF-8."""
    return resource_path(relative).read_text(encoding="utf-8")


def program_data_dir() -> Path:
    """Beschreibbares Verzeichnis fuer Konfiguration, Regel-Overlay und Wissensbasis.

    Unter Windows ``%PROGRAMDATA%\\WinEventAI``, sonst ``~/.local/share/wineventai``.
    Das Verzeichnis wird nicht angelegt; das machen die Aufrufer bei Bedarf.
    """
    import os

    program_data = os.environ.get("WINEVENTAI_DATA_DIR")
    if program_data:
        return Path(program_data)
    if sys.platform == "win32":
        base = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return Path(base) / "WinEventAI"
    return Path.home() / ".local" / "share" / "wineventai"
