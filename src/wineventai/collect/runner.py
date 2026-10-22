"""Orchestrierung der Erhebung: alle Quellen in ein Laufverzeichnis.

Quellen werden nacheinander erhoben und sofort als NDJSON weggeschrieben. Das
ist bewusst nicht parallel: Ein Werkzeug, das auf einem gestoerten Rechner
laeuft, soll ihn nicht zusaetzlich belasten, und die Wall-Clock-Grenze je Quelle
ist nur dann eine ehrliche Zusage, wenn nicht mehrere Kanaele gleichzeitig um
denselben Dienst konkurrieren.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..applog import get_log
from ..config import Config
from ..normalize.schema import EventRecord
from .base import CollectedSource, SourceResult, SourceStatus
from .eventlog import EventChannelCollector
from .logfiles import DEFAULT_LOG_FILES, LogFileCollector
from .minidump import MinidumpCollector
from .reliability import ReliabilityCollector
from .rundir import RunDirectory, is_admin
from .shell import PowerShellNotFoundError, find_powershell
from .sweep import SUMMARY_SOURCE_ID as SWEEP_SUMMARY_ID
from .sweep import ErrorSweepCollector
from .wer import WerCollector


class CollectionAborted(RuntimeError):
    """Der Lauf wurde abgebrochen, weil die Datenmenge absurd ist."""


def window_for(days: int, now: datetime | None = None) -> tuple[datetime, datetime]:
    end = now or datetime.now(UTC)
    return end - timedelta(days=days), end


def write_records(path: Path, records: list[EventRecord]) -> None:
    """Schreibt die behaltenen Records als NDJSON in das Laufverzeichnis."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(
                json.dumps(
                    {
                        "t": record.timestamp_utc.isoformat(),
                        "ch": record.channel,
                        "pr": record.provider,
                        "id": record.event_id,
                        "ver": record.event_version,
                        "lvl": record.level,
                        "tsk": record.task,
                        "op": record.opcode,
                        "kw": record.keywords,
                        "cmp": record.computer,
                        "sid": record.user_sid,
                        "rec": record.record_id,
                        "pid": record.process_id,
                        "tid": record.thread_id,
                        "msg": record.message,
                        "pv": record.properties,
                        "xml": None,
                        "ed": record.event_data,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )


def collect_all(
    config: Config,
    run: RunDirectory,
    *,
    days: int | None = None,
    evtx_dir: Path | None = None,
) -> list[SourceResult]:
    """Erhebt alle konfigurierten Quellen und fuellt das Laufverzeichnis."""
    log = get_log()
    meta = run.read_meta()
    window_from = meta.requested_from_utc
    window_to = meta.requested_to_utc
    if days is not None:
        window_from, window_to = window_for(days, window_to)

    admin = is_admin()
    results: list[SourceResult] = []
    total_read = 0

    try:
        shell = find_powershell(config.collect.powershell_preference)
        log.info("PowerShell gefunden", pfad=shell.path)
    except PowerShellNotFoundError as exc:
        log.error("Keine PowerShell", grund=str(exc))
        shell = None

    for entry in config.collect.channels:
        if shell is None:
            results.append(
                SourceResult(
                    source_id=f"channel:{entry.name}",
                    status=SourceStatus.FAILED,
                    requested_from_utc=window_from,
                    requested_to_utc=window_to,
                    detail="PowerShellNotFound",
                    note="Ohne PowerShell koennen Ereigniskanaele nicht gelesen werden.",
                )
            )
            continue

        evtx_path = _evtx_for(entry.name, evtx_dir)
        collector = EventChannelCollector(
            entry=entry,
            config=config.collect,
            shell=shell,
            window_from_utc=window_from,
            window_to_utc=window_to,
            evtx_path=evtx_path,
            is_admin=admin,
        )
        collected = _run_source(collector, run, log)
        total_read += collected.result.records_read
        _abort_if_absurd(total_read, config)
        results.append(collected.result)

    sweep = ErrorSweepCollector(
        config=config.collect.error_sweep,
        configured_channels=[entry.name for entry in config.collect.channels],
        shell=shell,
        window_from_utc=window_from,
        window_to_utc=window_to,
        offline=evtx_dir is not None,
    )
    for collected in sweep.collect_many():
        _store(collected, run)
        # Die Uebersichtszeile traegt die Summe aller Sweep-Kanaele; die
        # Einzelzeilen noch einmal zu addieren, zaehlte doppelt.
        if collected.result.source_id == SWEEP_SUMMARY_ID:
            total_read += collected.result.records_read
        results.append(collected.result)
    _abort_if_absurd(total_read, config)

    if shell is not None:
        collected = _run_source(
            ReliabilityCollector(
                config=config.collect,
                shell=shell,
                window_from_utc=window_from,
                window_to_utc=window_to,
            ),
            run,
            log,
        )
        results.append(collected.result)

    for extra in (
        WerCollector(
            enabled=config.collect.wer_reports,
            window_from_utc=window_from,
            window_to_utc=window_to,
        ),
        MinidumpCollector(
            enabled=config.collect.minidump_listing,
            window_from_utc=window_from,
            window_to_utc=window_to,
        ),
    ):
        results.append(_run_source(extra, run, log).result)

    for name, path in DEFAULT_LOG_FILES.items():
        results.append(
            _run_source(
                LogFileCollector(
                    name=name,
                    path=path,
                    enabled=config.collect.log_files,
                    window_from_utc=window_from,
                    window_to_utc=window_to,
                ),
                run,
                log,
            ).result
        )

    run.write_sources(results)
    run.update_meta(finished_utc=datetime.now(UTC))
    return results


def _evtx_for(channel: str, evtx_dir: Path | None) -> Path | None:
    """Sucht eine passende .evtx-Datei fuer einen Kanal im Offline-Betrieb."""
    if evtx_dir is None:
        return None
    stem = channel.replace("/", "%4").replace("\\", "%4")
    for candidate in (evtx_dir / f"{stem}.evtx", evtx_dir / f"{channel.split('/')[0]}.evtx"):
        if candidate.is_file():
            return candidate
    return None


def _run_source(collector: object, run: RunDirectory, log: object) -> CollectedSource:
    """Erhebt eine Quelle, schreibt ihre Records und protokolliert das Ergebnis."""
    assert hasattr(collector, "collect")
    collected: CollectedSource = collector.collect()  # type: ignore[attr-defined]
    _store(collected, run)
    return collected


def _store(collected: CollectedSource, run: RunDirectory) -> None:
    """Schreibt die Records einer Quelle und protokolliert das Ergebnis."""
    result = collected.result
    if collected.records:
        write_records(run.raw_path(result.source_id), collected.records)

    get_log().info(
        "Quelle erhoben",
        quelle=result.source_id,
        status=str(result.status),
        gelesen=result.records_read,
        behalten=result.records_retained,
    )


def _abort_if_absurd(total_read: int, config: Config) -> None:
    if total_read <= config.collect.abort_above_records:
        return
    raise CollectionAborted(
        f"Es wurden bereits {total_read:,} Records gelesen "
        f"(Grenze: {config.collect.abort_above_records:,}). "
        "Das Zeitfenster wird NICHT automatisch verkleinert, weil der Bericht dann "
        "still unvollstaendig waere. Vorschlag: '--days 1' setzen oder in der "
        "Konfiguration fuer den groessten Kanal 'event_ids' einschraenken."
    )


def load_records(run: RunDirectory) -> dict[str, list[EventRecord]]:
    """Liest alle Rohdaten eines Laufverzeichnisses zurueck."""
    from .eventlog import CachedChannelCollector

    out: dict[str, list[EventRecord]] = {}
    for result in run.read_sources():
        path = run.raw_path(result.source_id)
        if not path.is_file():
            out[result.source_id] = []
            continue
        collector = CachedChannelCollector(
            source_id=result.source_id, path=path, result=result
        )
        out[result.source_id] = collector.collect().records
    return out


__all__ = [
    "CollectionAborted",
    "collect_all",
    "load_records",
    "window_for",
    "write_records",
]


# Nachtrag: ShellInfo wird re-exportiert, damit Tests den Collector ohne
# PowerShell-Suche konstruieren koennen.
__all__.append("ShellInfo")
