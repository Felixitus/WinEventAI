"""Eigenes Anwendungslog, strikt getrennt vom analysierten Material.

Das Anwendungslog ist JSONL. Es landet im Laufverzeichnis unter ``applog.jsonl``
und - solange kein Laufverzeichnis existiert - nur auf der Konsole. Keine Zeile
dieses Logs darf jemals in den Bericht wandern; umgekehrt wird kein analysiertes
Event hier hineingeschrieben.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

_LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}


class AppLog:
    """Minimaler strukturierter Logger ohne Abhaengigkeit auf ``logging``.

    Der Verzicht auf ``logging`` ist Absicht: Das Werkzeug startet PowerShell und
    liest fremde Protokolle; eine global konfigurierte Logging-Hierarchie, in die
    Fremdcode hineinschreibt, ist an dieser Stelle mehr Risiko als Nutzen.
    """

    def __init__(self, level: str = "info", stream: TextIO | None = None) -> None:
        self.level = _LEVELS.get(level, 20)
        self.stream = stream if stream is not None else sys.stderr
        self._file: TextIO | None = None
        self._path: Path | None = None

    def attach_file(self, path: Path) -> None:
        """Haengt das Anwendungslog zusaetzlich an eine Datei im Laufverzeichnis."""
        self.detach_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = path.open("a", encoding="utf-8")
        self._path = path

    def detach_file(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
            self._path = None

    @property
    def path(self) -> Path | None:
        return self._path

    def _emit(self, level: str, message: str, fields: dict[str, Any]) -> None:
        if _LEVELS[level] < self.level:
            return
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": level,
            "msg": message,
        }
        record.update(fields)
        line = json.dumps(record, ensure_ascii=False)
        if self._file is not None:
            self._file.write(line + "\n")
            self._file.flush()
        if self.stream is not None:
            self.stream.write(f"[{level:<5}] {message}"
                              + (f" {json.dumps(fields, ensure_ascii=False)}" if fields else "")
                              + "\n")
            self.stream.flush()

    def debug(self, message: str, **fields: Any) -> None:
        self._emit("debug", message, fields)

    def info(self, message: str, **fields: Any) -> None:
        self._emit("info", message, fields)

    def warn(self, message: str, **fields: Any) -> None:
        self._emit("warn", message, fields)

    def error(self, message: str, **fields: Any) -> None:
        self._emit("error", message, fields)


_default = AppLog()


def get_log() -> AppLog:
    """Liefert das prozessweite Anwendungslog."""
    return _default


def configure(level: str = "info", stream: TextIO | None = None) -> AppLog:
    """Setzt Schwelle und Ausgabestrom des prozessweiten Anwendungslogs."""
    global _default
    _default.detach_file()
    _default = AppLog(level=level, stream=stream)
    return _default
