"""Evidence bundle as a ZIP.

No file format of our own: whoever has to check the evidence later needs the
original ``.evtx``, not our JSON extract. The bundle therefore contains both
and a manifest that hashes the originals.

Two points that are easily missed:

* The hash is taken over the ``.evtx`` original, not over the extract -
  otherwise one hashes one's own interpretation.
* The bundle is NOT redacted. It is evidence. Redaction only concerns the path
  to the language model; the mapping table is not exported.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..applog import get_log
from ..collect.rundir import RunDirectory
from ..collect.shell import ShellInfo, read_ndjson, run_script

VERIFY_SCRIPT = """<#
    verify.ps1 - checks the checksums of this bundle.
    Run in the extracted directory:  powershell -ExecutionPolicy Bypass -File verify.ps1
#>
$manifest = Get-Content -Raw -Path (Join-Path $PSScriptRoot 'manifest.json') | ConvertFrom-Json
$manifest.files | ForEach-Object {
    $path = Join-Path $PSScriptRoot $_.name
    if (-not (Test-Path -LiteralPath $path)) { "MISSING  $($_.name)"; return }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
    if ($actual -eq $_.sha256) { "OK       $($_.name)" } else { "MISMATCH $($_.name)" }
}
"""


class ManifestFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    sha256: str
    size_b: int
    kind: str
    note: str | None = None


class Manifest(BaseModel):
    """Header data of the bundle. What someone may have to present if in doubt."""

    model_config = ConfigDict(extra="forbid")

    created_utc: str
    collected_utc: str
    timezone: str
    utc_offset_minutes: int
    host: str
    executing_account: str
    tool_version: str
    command_line: str
    model: str | None = None
    window_from_utc: str
    window_to_utc: str
    redacted: bool = False
    note: str = (
        "This data is NOT pseudonymized. Pseudonymization only concerns the path "
        "to the language model. Checksums refer to the original .evtx, not to the "
        "JSON extract."
    )
    files: list[ManifestFile] = Field(default_factory=list)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def export_channels(
    run: RunDirectory,
    channels: list[str],
    *,
    shell: ShellInfo,
    target_dir: Path,
    timeout_seconds: float = 300.0,
) -> list[tuple[Path, str | None]]:
    """Exports original channels with ``wevtutil epl``.

    If an export fails, the file is missing from the bundle and the manifest
    says why - instead of producing an empty ZIP that feigns completeness.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    exported: list[tuple[Path, str | None]] = []

    for channel in channels:
        safe = channel.replace("/", "%4").replace("\\", "%4")
        target = target_dir / f"{safe}.evtx"
        result = run_script(
            "export_evtx.ps1",
            ["-LogName", channel, "-Target", str(target)],
            shell=shell,
            timeout_seconds=timeout_seconds,
        )
        parsed = read_ndjson(result.lines, source_tool="wevtutil", source_ref=channel)
        status = parsed.status_line or {}
        exception = status.get("exception")
        if target.is_file() and not exception:
            exported.append((target, None))
        else:
            get_log().warn("Channel export failed", channel=channel, reason=str(exception))
            exported.append((target, str(exception or "export produced no file")))
    return exported


def build_bundle(
    run: RunDirectory,
    target: Path,
    *,
    evtx_files: list[tuple[Path, str | None]] | None = None,
    model_name: str | None = None,
) -> Path:
    """Packs the evidence bundle."""
    meta = run.read_meta()
    now = datetime.now(UTC)
    files: list[ManifestFile] = []
    members: list[tuple[Path, str]] = []

    def add(path: Path, arcname: str, kind: str, note: str | None = None) -> None:
        if not path.is_file():
            files.append(
                ManifestFile(
                    name=arcname, sha256="", size_b=0, kind=kind,
                    note=note or "File was not present at packing time.",
                )
            )
            return
        files.append(
            ManifestFile(
                name=arcname,
                sha256=sha256_file(path),
                size_b=path.stat().st_size,
                kind=kind,
                note=note,
            )
        )
        members.append((path, arcname))

    for evtx, error in evtx_files or []:
        add(
            evtx,
            f"evtx/{evtx.name}",
            "original-evtx",
            error or "Complete channel export via wevtutil epl.",
        )

    for raw in sorted(run.raw_dir.glob("*.ndjson")):
        add(raw, f"normalized/{raw.name}", "normalized-json")

    for report in sorted(run.report_dir.glob("*")):
        if report.is_file():
            add(report, f"report/{report.name}", "report")

    add(run.meta_path, "run.json", "run-data")
    add(run.sources_path, "sources.json", "source-status")
    if run.unknown_ids_path.is_file():
        add(run.unknown_ids_path, "unknown_ids.csv", "work-list")

    manifest = Manifest(
        created_utc=now.isoformat(),
        collected_utc=meta.started_utc.isoformat(),
        timezone=meta.timezone_name,
        utc_offset_minutes=meta.utc_offset_minutes,
        host=meta.host,
        executing_account=meta.account,
        tool_version=meta.tool_version,
        command_line=meta.command_line,
        model=model_name or meta.ai_model,
        window_from_utc=meta.requested_from_utc.isoformat(),
        window_to_utc=meta.requested_to_utc.isoformat(),
        files=files,
    )

    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, arcname in members:
            archive.write(path, arcname)
        archive.writestr(
            "manifest.json",
            json.dumps(manifest.model_dump(mode="json"), indent=2, ensure_ascii=False),
        )
        archive.writestr("verify.ps1", VERIFY_SCRIPT)

    get_log().info("Evidence bundle written", file=str(target), files=len(files))
    return target
