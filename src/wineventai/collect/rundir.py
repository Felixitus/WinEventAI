"""The run directory - the boundary between collection and analysis.

The collector does not write into objects but into a directory; everything
after it reads only from there. That solves four things at once:

* Live collection and a brought-along .evtx export end up in the same code.
* ``analyze --run <dir>`` runs changed rules against the same raw data.
* The evidence manifest is built from files that are there anyway.
* AI bundle and model answer sit traceably side by side.
"""

from __future__ import annotations

import getpass
import json
import platform
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .. import __version__
from ..resources import program_data_dir
from .base import SourceResult

RUN_META = "run.json"
SOURCES = "sources.json"


class RunMeta(BaseModel):
    """Header data of a run. Goes unchanged into the evidence manifest."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    started_utc: datetime
    finished_utc: datetime | None = None
    timezone_name: str
    utc_offset_minutes: int
    host: str
    account: str
    os_caption: str
    tool_version: str
    command_line: str
    requested_from_utc: datetime
    requested_to_utc: datetime
    is_admin: bool
    security_mode: bool
    ai_model: str | None = None
    ai_used: bool = False


def _utc_offset_minutes(moment: datetime) -> int:
    local = moment.astimezone()
    offset = local.utcoffset()
    return int(offset.total_seconds() // 60) if offset else 0


def _timezone_name() -> str:
    return datetime.now().astimezone().tzname() or "unknown"


def _current_account() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - environment without a user context
        return "unknown"


def is_admin() -> bool:
    """Checks for admin rights. Always False outside Windows."""
    if sys.platform != "win32":
        return False
    try:  # pragma: no cover - only reachable on Windows
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover
        return False


def default_runs_root() -> Path:
    return program_data_dir() / "runs"


class RunDirectory:
    """Access to a run directory, for reading and writing."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    # --- Create and open ------------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        root: Path | None = None,
        requested_from: datetime,
        requested_to: datetime,
        security_mode: bool,
        command_line: str | None = None,
    ) -> RunDirectory:
        now = datetime.now(UTC)
        host = socket.gethostname()
        run_id = f"{now.strftime('%Y-%m-%dT%H-%M-%SZ')}_{host}"
        base = Path(root) if root is not None else default_runs_root()
        path = base / run_id
        (path / "raw").mkdir(parents=True, exist_ok=True)
        (path / "derived" / "bundles").mkdir(parents=True, exist_ok=True)
        (path / "derived" / "ai").mkdir(parents=True, exist_ok=True)
        (path / "report").mkdir(parents=True, exist_ok=True)

        run = cls(path)
        run.write_meta(
            RunMeta(
                run_id=run_id,
                started_utc=now,
                timezone_name=_timezone_name(),
                utc_offset_minutes=_utc_offset_minutes(now),
                host=host,
                account=_current_account(),
                os_caption=f"{platform.system()} {platform.release()}",
                tool_version=__version__,
                command_line=command_line or " ".join(sys.argv),
                requested_from_utc=requested_from,
                requested_to_utc=requested_to,
                is_admin=is_admin(),
                security_mode=security_mode,
            )
        )
        return run

    @classmethod
    def open(cls, path: Path) -> RunDirectory:
        run = cls(path)
        if not run.meta_path.is_file():
            raise FileNotFoundError(f"Not a run directory: {path} ({RUN_META} is missing)")
        return run

    # --- Paths ---------------------------------------------------------------

    @property
    def meta_path(self) -> Path:
        return self.path / RUN_META

    @property
    def sources_path(self) -> Path:
        return self.path / SOURCES

    @property
    def raw_dir(self) -> Path:
        return self.path / "raw"

    @property
    def derived_dir(self) -> Path:
        return self.path / "derived"

    @property
    def bundles_dir(self) -> Path:
        return self.derived_dir / "bundles"

    @property
    def ai_dir(self) -> Path:
        return self.derived_dir / "ai"

    @property
    def report_dir(self) -> Path:
        return self.path / "report"

    @property
    def applog_path(self) -> Path:
        return self.path / "applog.jsonl"

    @property
    def unknown_ids_path(self) -> Path:
        return self.path / "unknown_ids.csv"

    def raw_path(self, source_id: str) -> Path:
        return self.raw_dir / f"{safe_name(source_id)}.ndjson"

    # --- Read and write -----------------------------------------------------

    def write_meta(self, meta: RunMeta) -> None:
        self.meta_path.parent.mkdir(parents=True, exist_ok=True)
        self.meta_path.write_text(
            meta.model_dump_json(indent=2), encoding="utf-8"
        )

    def read_meta(self) -> RunMeta:
        return RunMeta.model_validate_json(self.meta_path.read_text(encoding="utf-8"))

    def update_meta(self, **fields: object) -> RunMeta:
        meta = self.read_meta()
        updated = meta.model_copy(update=fields)
        self.write_meta(updated)
        return updated

    def write_sources(self, results: list[SourceResult]) -> None:
        payload = [result.model_dump(mode="json") for result in results]
        self.sources_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def read_sources(self) -> list[SourceResult]:
        if not self.sources_path.is_file():
            return []
        payload = json.loads(self.sources_path.read_text(encoding="utf-8"))
        return [SourceResult.model_validate(entry) for entry in payload]

    def write_derived(self, name: str, payload: object) -> Path:
        self.derived_dir.mkdir(parents=True, exist_ok=True)
        target = self.derived_dir / name
        target.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )
        return target

    def read_derived(self, name: str) -> object | None:
        target = self.derived_dir / name
        if not target.is_file():
            return None
        return json.loads(target.read_text(encoding="utf-8"))


def safe_name(value: str) -> str:
    """Makes a channel name file-system safe without making it unrecognizable."""
    out = []
    for char in value:
        out.append(char if char.isalnum() or char in "-_." else "_")
    return "".join(out).strip("_") or "source"
