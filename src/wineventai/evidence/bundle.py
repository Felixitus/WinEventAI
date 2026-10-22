"""Evidenz-Bundle als ZIP.

Kein eigenes Dateiformat: Wer die Evidenz spaeter pruefen muss, braucht das
Original-``.evtx``, nicht unseren JSON-Auszug. Das Bundle enthaelt deshalb beides
und ein Manifest, das die Originale hasht.

Zwei Punkte, die leicht untergehen:

* Der Hash geht ueber das ``.evtx``-Original, nicht ueber den Auszug - sonst
  hasht man die eigene Interpretation.
* Das Bundle ist NICHT redigiert. Es ist Evidenz. Die Redaction betrifft
  ausschliesslich den Pfad zum Sprachmodell; die Zuordnungstabelle wird nicht
  mit exportiert.
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
    verify.ps1 - prueft die Pruefsummen dieses Bundles.
    Aufruf im entpackten Verzeichnis:  powershell -ExecutionPolicy Bypass -File verify.ps1
#>
$manifest = Get-Content -Raw -Path (Join-Path $PSScriptRoot 'manifest.json') | ConvertFrom-Json
$manifest.dateien | ForEach-Object {
    $pfad = Join-Path $PSScriptRoot $_.name
    if (-not (Test-Path -LiteralPath $pfad)) { "FEHLT   $($_.name)"; return }
    $ist = (Get-FileHash -LiteralPath $pfad -Algorithm SHA256).Hash.ToLower()
    if ($ist -eq $_.sha256) { "OK      $($_.name)" } else { "ABWEICHUNG $($_.name)" }
}
"""


class ManifestFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    sha256: str
    size_b: int
    art: str
    hinweis: str | None = None


class Manifest(BaseModel):
    """Kopfdaten des Bundles. Was im Zweifel jemand vorlegen muss."""

    model_config = ConfigDict(extra="forbid")

    erstellt_utc: str
    erhebung_utc: str
    zeitzone: str
    utc_versatz_minuten: int
    host: str
    ausfuehrendes_konto: str
    tool_version: str
    kommandozeile: str
    modell: str | None = None
    zeitfenster_von_utc: str
    zeitfenster_bis_utc: str
    redigiert: bool = False
    hinweis: str = (
        "Diese Daten sind NICHT pseudonymisiert. Die Pseudonymisierung betrifft "
        "ausschliesslich den Pfad zum Sprachmodell. Pruefsummen beziehen sich auf "
        "die Original-.evtx, nicht auf den JSON-Auszug."
    )
    dateien: list[ManifestFile] = Field(default_factory=list)


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
    """Exportiert Originalkanaele mit ``wevtutil epl``.

    Scheitert ein Export, fehlt die Datei im Bundle und das Manifest sagt warum -
    statt dass ein leeres ZIP entsteht, das Vollstaendigkeit vortaeuscht.
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
            get_log().warn("Kanalexport fehlgeschlagen", kanal=channel, grund=str(exception))
            exported.append((target, str(exception or "Export lieferte keine Datei")))
    return exported


def build_bundle(
    run: RunDirectory,
    target: Path,
    *,
    evtx_files: list[tuple[Path, str | None]] | None = None,
    model_name: str | None = None,
) -> Path:
    """Packt das Evidenz-Bundle."""
    meta = run.read_meta()
    now = datetime.now(UTC)
    files: list[ManifestFile] = []
    members: list[tuple[Path, str]] = []

    def add(path: Path, arcname: str, art: str, hinweis: str | None = None) -> None:
        if not path.is_file():
            files.append(
                ManifestFile(
                    name=arcname, sha256="", size_b=0, art=art,
                    hinweis=hinweis or "Datei war beim Packen nicht vorhanden.",
                )
            )
            return
        files.append(
            ManifestFile(
                name=arcname,
                sha256=sha256_file(path),
                size_b=path.stat().st_size,
                art=art,
                hinweis=hinweis,
            )
        )
        members.append((path, arcname))

    for evtx, error in evtx_files or []:
        add(
            evtx,
            f"evtx/{evtx.name}",
            "original-evtx",
            error or "Vollstaendiger Kanalexport ueber wevtutil epl.",
        )

    for raw in sorted(run.raw_dir.glob("*.ndjson")):
        add(raw, f"normalisiert/{raw.name}", "normalisiertes-json")

    for report in sorted(run.report_dir.glob("*")):
        if report.is_file():
            add(report, f"bericht/{report.name}", "bericht")

    add(run.meta_path, "run.json", "laufdaten")
    add(run.sources_path, "sources.json", "quellenstatus")
    if run.unknown_ids_path.is_file():
        add(run.unknown_ids_path, "unknown_ids.csv", "arbeitsliste")

    manifest = Manifest(
        erstellt_utc=now.isoformat(),
        erhebung_utc=meta.started_utc.isoformat(),
        zeitzone=meta.timezone_name,
        utc_versatz_minuten=meta.utc_offset_minutes,
        host=meta.host,
        ausfuehrendes_konto=meta.account,
        tool_version=meta.tool_version,
        kommandozeile=meta.command_line,
        modell=model_name or meta.ai_model,
        zeitfenster_von_utc=meta.requested_from_utc.isoformat(),
        zeitfenster_bis_utc=meta.requested_to_utc.isoformat(),
        dateien=files,
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

    get_log().info("Evidenz-Bundle geschrieben", datei=str(target), dateien=len(files))
    return target
