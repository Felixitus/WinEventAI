"""Collector fuer Ereigniskanaele - live vom System oder aus einer .evtx-Datei.

Beide Faelle benutzen dasselbe PowerShell-Skript und muenden in dasselbe
Laufverzeichnis. Der Unterschied ist ein Parameter.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ..applog import get_log
from ..config import ChannelConfig, CollectConfig
from ..normalize.schema import EventRecord
from .base import CollectedSource, SourceResult, SourceStatus, status_for_exception
from .shell import (
    ShellInfo,
    error_id_from_stderr,
    iter_file_lines,
    join_list_arg,
    read_ndjson,
    run_script,
    status_from_stderr,
)

SOURCE_TOOL_LIVE = "powershell:get-winevent"
SOURCE_TOOL_FILE = "powershell:get-winevent-path"
SOURCE_TOOL_CACHE = "rundir:ndjson"


def _xml_ids_for(channel: str, config: CollectConfig, entry: ChannelConfig) -> list[int]:
    """IDs, fuer die das vollstaendige Event-XML geholt wird.

    Das XML kostet Zeit und Platz, liefert dafuer die benannten EventData-Felder,
    die - anders als der Meldungstext - sprachneutral sind.
    """
    if entry.with_xml:
        return list(entry.event_ids)
    ids: list[int] = []
    for pair in config.xml_for:
        _, _, id_part = pair.rpartition(":")
        try:
            ids.append(int(id_part))
        except ValueError:
            get_log().warn("xml_for-Eintrag nicht lesbar", eintrag=pair, kanal=channel)
    return sorted(set(ids))


class EventChannelCollector:
    """Erhebt einen Ereigniskanal ueber Get-WinEvent."""

    def __init__(
        self,
        *,
        entry: ChannelConfig,
        config: CollectConfig,
        shell: ShellInfo,
        window_from_utc: datetime,
        window_to_utc: datetime,
        evtx_path: Path | None = None,
        is_admin: bool = False,
    ) -> None:
        self.entry = entry
        self.config = config
        self.shell = shell
        self.window_from = window_from_utc
        self.window_to = window_to_utc
        self.evtx_path = evtx_path
        self.is_admin = is_admin
        self.source_id = f"channel:{entry.name}"

    def _keep_limit(self) -> int:
        return self.entry.max_retained or self.config.max_retained_per_channel

    def collect(self) -> CollectedSource:
        log = get_log()

        if not self.entry.enabled:
            return CollectedSource(
                result=SourceResult(
                    source_id=self.source_id,
                    status=SourceStatus.DISABLED,
                    requested_from_utc=self.window_from,
                    requested_to_utc=self.window_to,
                    note="Per Konfiguration abgeschaltet.",
                )
            )

        if self.entry.requires_admin and not self.is_admin:
            return CollectedSource(
                result=SourceResult(
                    source_id=self.source_id,
                    status=SourceStatus.NO_PERMISSION,
                    requested_from_utc=self.window_from,
                    requested_to_utc=self.window_to,
                    note="Kanal erfordert Adminrechte; der Lauf hat keine.",
                )
            )

        window_from = self.window_from
        if self.entry.days:
            from datetime import timedelta

            candidate = self.window_to - timedelta(days=self.entry.days)
            window_from = max(window_from, candidate)

        args = [
            "-LogName", self.entry.name,
            "-StartUtc", window_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "-EndUtc", self.window_to.strftime("%Y-%m-%dT%H:%M:%SZ"),
        ]
        if self.evtx_path is not None:
            args += ["-Path", str(self.evtx_path)]
        if self.entry.event_ids:
            args += ["-EventIds", join_list_arg(self.entry.event_ids)]
        xml_ids = _xml_ids_for(self.entry.name, self.config, self.entry)
        if xml_ids:
            args += ["-XmlForIds", join_list_arg(xml_ids)]

        run = run_script(
            "get_events.ps1",
            args,
            shell=self.shell,
            timeout_seconds=self.config.channel_timeout_seconds,
        )

        blocked = status_from_stderr(run.stderr)
        if blocked is not None:
            log.warn("Kanal blockiert", kanal=self.entry.name)
            return CollectedSource(
                result=SourceResult(
                    source_id=self.source_id,
                    status=blocked,
                    requested_from_utc=window_from,
                    requested_to_utc=self.window_to,
                    duration_seconds=run.duration_seconds,
                    detail="PowerShell-Ausfuehrung abgelehnt",
                    note="Ausfuehrungsrichtlinie oder Rechte verhindern den Aufruf.",
                )
            )

        source_tool = SOURCE_TOOL_FILE if self.evtx_path else SOURCE_TOOL_LIVE
        parsed = read_ndjson(
            run.lines,
            source_tool=source_tool,
            source_ref=self.entry.name,
            keep=self._keep_limit(),
        )

        return CollectedSource(
            result=self._build_result(
                parsed, run.duration_seconds, run.timed_out, window_from, run.stderr
            ),
            records=parsed.records,
        )

    def _build_result(
        self,
        parsed: object,
        duration: float,
        timed_out: bool,
        window_from: datetime,
        stderr: str = "",
    ) -> SourceResult:
        from .shell import NdjsonResult

        assert isinstance(parsed, NdjsonResult)
        status = status_for_exception(
            parsed.exception_type, parsed.records_read, parsed.error_id
        )
        detail = parsed.error_id or parsed.exception_type

        covered_from, covered_to = _covered_range(parsed.records)

        if timed_out:
            status = SourceStatus.TIMED_OUT
        elif not parsed.completed:
            status = SourceStatus.FAILED
            detail = error_id_from_stderr(stderr) or "keine Statuszeile"
        elif parsed.records_read >= self._keep_limit() and status == SourceStatus.COLLECTED:
            status = SourceStatus.TRUNCATED

        note = None
        if status == SourceStatus.FAILED and not parsed.completed:
            note = (
                "Das Erhebungsskript hat keinen Abschlussstatus geliefert. Ueber diesen "
                "Kanal ist keine Aussage moeglich - auch nicht 'keine Treffer'."
            )
        elif status in {SourceStatus.TIMED_OUT, SourceStatus.TRUNCATED}:
            note = (
                "Nur ein Teil des angeforderten Zeitraums liegt vor. "
                "Aussagen ueber den nicht abgedeckten Teil sind nicht moeglich."
            )

        return SourceResult(
            source_id=self.source_id,
            status=status,
            requested_from_utc=window_from,
            requested_to_utc=self.window_to,
            covered_from_utc=covered_from,
            covered_to_utc=covered_to,
            records_read=parsed.records_read,
            records_retained=len(parsed.records),
            duration_seconds=duration,
            detail=detail,
            note=note,
        )


def _covered_range(records: list[EventRecord]) -> tuple[datetime | None, datetime | None]:
    """Tatsaechlich abgedeckter Zeitraum aus den gelesenen Records.

    Diese beiden Werte sind der Unterschied zwischen "keine Befunde" und
    "sechseinhalb Tage nie gelesen". Der Bericht zeigt sie oben, nicht in einer
    Fussnote.
    """
    if not records:
        return None, None
    stamps = [record.timestamp_utc for record in records]
    return min(stamps), max(stamps)


class CachedChannelCollector:
    """Liest einen bereits erhobenen Kanal aus dem Laufverzeichnis.

    Das ist der Weg, auf dem ``analyze --run`` ohne Neuerhebung arbeitet - und
    zugleich der Weg, auf dem Tests echte Exporte einspeisen.
    """

    def __init__(self, *, source_id: str, path: Path, result: SourceResult) -> None:
        self.source_id = source_id
        self.path = path
        self._result = result

    def collect(self) -> CollectedSource:
        if not self.path.is_file():
            return CollectedSource(
                result=self._result.model_copy(
                    update={"status": SourceStatus.NOT_AVAILABLE, "records_retained": 0}
                )
            )
        parsed = read_ndjson(
            iter_file_lines(self.path),
            source_tool=SOURCE_TOOL_CACHE,
            source_ref=self._result.source_id.removeprefix("channel:").removeprefix("sweep:"),
        )
        return CollectedSource(result=self._result, records=parsed.records)
