"""Windows Error Reporting - nur die Metadaten aus Report.wer.

Bewusst kein Zugriff auf die Anhaenge: Speicherabbilder und Heap-Auszuege in
einem WER-Archiv enthalten beliebige Prozessinhalte. Gelesen wird nur die
INI-artige Kopfsektion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ..normalize.schema import EventRecord
from .base import CollectedSource, SourceResult, SourceStatus

DEFAULT_WER_DIRS = (
    r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
    r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
)

SOURCE_TOOL = "file:report.wer"

_INTERESTING = (
    "EventType",
    "AppName",
    "AppPath",
    "ApplicationName",
    "Sig[0].Value",
    "Sig[1].Value",
    "Sig[2].Value",
    "Sig[3].Value",
    "Response.type",
    "ReportStatus",
)


def parse_report_wer(text: str) -> dict[str, str]:
    """Liest die ``Schluessel=Wert``-Zeilen einer Report.wer.

    Report.wer ist UTF-16 mit BOM; das Dekodieren erledigt der Aufrufer.
    """
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip().lstrip("\ufeff")
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key:
            fields[key] = value.strip()
    return fields


def _read_text(path: Path) -> str | None:
    for encoding in ("utf-16", "utf-16-le", "utf-8-sig", "utf-8"):
        try:
            return path.read_text(encoding=encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
        except OSError:
            return None
    return None


def record_from_report(
    path: Path, fields: dict[str, str], window_from: datetime
) -> EventRecord | None:
    """Baut aus einer Report.wer einen ``EventRecord``.

    Der Zeitstempel kommt aus der Dateizeit, weil Report.wer selbst kein
    verlaessliches Feld dafuer fuehrt. Das ist eine Naeherung und wird als
    solche im Meldungstext kenntlich gemacht.
    """
    try:
        stamp = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except OSError:
        return None
    if stamp < window_from:
        return None

    app = fields.get("AppName") or fields.get("ApplicationName") or "unbekannt"
    event_type = fields.get("EventType") or "WER"
    parts = [f"{key}={fields[key]}" for key in _INTERESTING if key in fields]
    message = (
        f"Windows Error Reporting: {event_type} fuer {app}. "
        f"Zeit aus Dateizeitstempel von {path.name}. " + " | ".join(parts)
    )

    return EventRecord(
        timestamp_utc=stamp,
        channel="WER",
        provider="Windows Error Reporting",
        event_id=0,
        level=2,
        message=message,
        properties=[event_type, app, fields.get("AppPath")],
        event_data=dict(fields) or None,
        source_tool=SOURCE_TOOL,
        source_ref=str(path),
    )


class WerCollector:
    source_id = "wer:ReportArchive"

    def __init__(
        self,
        *,
        enabled: bool,
        window_from_utc: datetime,
        window_to_utc: datetime,
        directories: tuple[str, ...] = DEFAULT_WER_DIRS,
        limit: int = 2000,
    ) -> None:
        self.enabled = enabled
        self.window_from = window_from_utc
        self.window_to = window_to_utc
        self.directories = directories
        self.limit = limit

    def collect(self) -> CollectedSource:
        if not self.enabled:
            return CollectedSource(
                result=SourceResult(
                    source_id=self.source_id,
                    status=SourceStatus.DISABLED,
                    requested_from_utc=self.window_from,
                    requested_to_utc=self.window_to,
                )
            )

        existing = [Path(d) for d in self.directories if Path(d).is_dir()]
        if not existing:
            return CollectedSource(
                result=SourceResult(
                    source_id=self.source_id,
                    status=SourceStatus.NOT_AVAILABLE,
                    requested_from_utc=self.window_from,
                    requested_to_utc=self.window_to,
                    note="WER-Archivverzeichnis nicht gefunden.",
                )
            )

        records: list[EventRecord] = []
        read = 0
        denied = False
        for directory in existing:
            try:
                candidates = sorted(directory.rglob("Report.wer"))
            except PermissionError:
                denied = True
                continue
            for report in candidates:
                read += 1
                text = _read_text(report)
                if text is None:
                    continue
                record = record_from_report(report, parse_report_wer(text), self.window_from)
                if record is not None and len(records) < self.limit:
                    records.append(record)

        if denied and not records:
            status = SourceStatus.NO_PERMISSION
        elif records:
            status = SourceStatus.COLLECTED
        else:
            status = SourceStatus.EMPTY

        stamps = [record.timestamp_utc for record in records]
        return CollectedSource(
            result=SourceResult(
                source_id=self.source_id,
                status=status,
                requested_from_utc=self.window_from,
                requested_to_utc=self.window_to,
                covered_from_utc=min(stamps) if stamps else None,
                covered_to_utc=max(stamps) if stamps else None,
                records_read=read,
                records_retained=len(records),
            ),
            records=records,
        )
