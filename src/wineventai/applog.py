"""The tool's own application log, strictly separate from the analyzed material.

The application log is JSONL. It goes into the run directory as
``applog.jsonl`` and - as long as no run directory exists - only to the
console. No line of this log may ever end up in the report; conversely, no
analyzed event is written into it.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

_LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}


class AppLog:
    """Minimal structured logger without depending on ``logging``.

    Avoiding ``logging`` is intentional: the tool starts PowerShell and reads
    foreign logs; a globally configured logging hierarchy that third-party code
    writes into is more risk than benefit here.
    """

    def __init__(self, level: str = "info", stream: TextIO | None = None) -> None:
        self.level = _LEVELS.get(level, 20)
        self.stream = stream if stream is not None else sys.stderr
        self._file: TextIO | None = None
        self._path: Path | None = None

    def attach_file(self, path: Path) -> None:
        """Additionally attaches the application log to a file in the run directory."""
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
    """Returns the process-wide application log."""
    return _default


def configure(level: str = "info", stream: TextIO | None = None) -> AppLog:
    """Sets threshold and output stream of the process-wide application log."""
    global _default
    _default.detach_file()
    _default = AppLog(level=level, stream=stream)
    return _default
