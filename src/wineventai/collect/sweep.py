"""Fehler-Sweep: alle aktiven Kanaele, nur Kritisch und Fehler.

Warum es diesen Collector neben ``EventChannelCollector`` gibt:

* Die konfigurierten Kernkanaele werden vollstaendig gelesen. Abstuerze von
  Treibern und Komponenten landen aber oft in einem der mehreren hundert
  Operational-Kanaele, die niemand einzeln konfiguriert. Alle davon vollstaendig
  zu lesen, waere langsam und wuerde die echten Fehler im Rauschen ertraenken.
  Deshalb wird jeder Kanal gelesen, aber serverseitig auf den numerischen
  Level gefiltert.
* EIN PowerShell-Prozess fuer alle Kanaele statt einer je Kanal. Ein
  Prozessstart kostet grob eine Sekunde; bei mehreren hundert Kanaelen waere
  das der groesste Teil der Laufzeit. Der Preis: Ein Zeitlimit gilt fuer den
  ganzen Sweep. Damit das nicht still Kanaele verschluckt, schreibt das Skript
  zuerst den Plan (welche Kanaele es lesen wird) und nach jedem Kanal eine
  Abschlusszeile. Was im Plan steht, aber keine Abschlusszeile hat, ist
  "abgebrochen" - nicht "keine Treffer".
* Kanaele ohne Treffer bekommen KEINE eigene Zeile in der Abdeckungstabelle,
  sondern werden in einer Uebersichtszeile gezaehlt. Hunderte "keine
  Treffer"-Zeilen wuerden die eine Zeile verdecken, auf die es ankommt. Jeder
  Kanal mit Treffern oder mit unvollstaendiger Erhebung bekommt dagegen seine
  eigene Zeile.

Die Auswertung (``parse_sweep``, ``build_sweep_results``) kennt nur einen
Zeilen-Iterator und ist damit ohne Windows testbar.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..applog import get_log
from ..config import ErrorSweepConfig
from ..normalize.mapper import NormalizationError, record_from_line
from ..normalize.schema import EventRecord
from .base import CollectedSource, SourceResult, SourceStatus, status_for_exception
from .shell import LIST_SEPARATOR, STATUS_KEY, ShellInfo, run_script, status_from_stderr

SOURCE_TOOL = "powershell:get-winevent-sweep"
SOURCE_PREFIX = "sweep:"
SUMMARY_SOURCE_ID = "sweep:uebersicht"

PLAN_KEY = "__plan"
CHANNEL_KEY = "__channel"

#: Begruendung siehe ``shell.LIST_SEPARATOR``.
ARG_SEPARATOR = LIST_SEPARATOR

#: Lesbare Gruende, warum ein Kanal gar nicht erst in den Plan kam.
SKIP_REASONS_DE: dict[str, str] = {
    "disabled": "abgeschaltet",
    "type": "anderer Kanaltyp",
    "excluded": "ausgelassen",
    "empty": "leer",
    "unreadable": "nicht lesbar (meist fehlende Adminrechte)",
}


@dataclass(slots=True)
class ChannelTally:
    """Was zu einem Kanal im Sweep-Strom stand."""

    name: str
    records: list[EventRecord] = field(default_factory=list)
    records_read: int = 0
    finished: bool = False
    exception_type: str | None = None
    error_id: str | None = None


@dataclass(slots=True)
class SweepParse:
    """Rohes Ergebnis des Sweep-Stroms, noch ohne Statusbewertung."""

    planned: list[str] | None = None
    skipped: dict[str, int] = field(default_factory=dict)
    channels: dict[str, ChannelTally] = field(default_factory=dict)
    final_status: dict[str, object] | None = None
    parse_errors: int = 0

    def tally(self, name: str) -> ChannelTally:
        """Liefert den Zaehler zu einem Kanal; Gross-/Kleinschreibung egal.

        Windows behandelt Kanalnamen ohne Ruecksicht auf Gross-/Kleinschreibung.
        Der Name im Plan und der ``LogName`` am Ereignis muessen nicht
        zeichengleich sein.
        """
        key = name.lower()
        entry = self.channels.get(key)
        if entry is None:
            entry = ChannelTally(name=name)
            self.channels[key] = entry
        return entry


def parse_sweep(lines: Iterable[str], *, keep_per_channel: int) -> SweepParse:
    """Liest den Sweep-Strom: Plan, Records, Kanalabschluesse, Statuszeile.

    ``keep_per_channel`` begrenzt nur das Behalten. Gezaehlt wird jeder Record -
    die Zahl in der Abdeckungstabelle ist immer die gelesene, nicht die
    behaltene.
    """
    log = get_log()
    result = SweepParse()

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        head = line[:24]
        if PLAN_KEY in head or CHANNEL_KEY in head or STATUS_KEY in head:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                result.parse_errors += 1
                continue
            if isinstance(payload, dict) and _consume_control(payload, result):
                continue

        try:
            record = record_from_line(line, source_tool=SOURCE_TOOL, source_ref="")
        except NormalizationError as exc:
            result.parse_errors += 1
            if result.parse_errors <= 3:
                log.warn("Sweep-Zeile uebersprungen", grund=str(exc))
            continue

        entry = result.tally(record.channel)
        record = record.model_copy(update={"source_ref": entry.name})
        entry.records_read += 1
        if len(entry.records) < keep_per_channel:
            entry.records.append(record)

    if result.parse_errors:
        log.warn("Nicht lesbare Sweep-Zeilen", anzahl=result.parse_errors)
    return result


def _consume_control(payload: dict[str, object], result: SweepParse) -> bool:
    """Verarbeitet eine Steuerzeile. False, wenn es doch keine war."""
    if PLAN_KEY in payload:
        plan = payload[PLAN_KEY]
        if isinstance(plan, dict):
            names = plan.get("channels") or []
            result.planned = [str(name) for name in names] if isinstance(names, list) else []
            # Zaehler sofort anlegen: Dann bestimmt der Name aus dem Plan die
            # Schreibweise im Bericht, nicht der zufaellig erste Record.
            for name in result.planned:
                result.tally(name)
            skipped = plan.get("skipped") or {}
            if isinstance(skipped, dict):
                result.skipped = {str(k): int(v) for k, v in skipped.items() if _is_int(v)}
        else:
            result.planned = []
        return True
    if CHANNEL_KEY in payload:
        done = payload[CHANNEL_KEY]
        if isinstance(done, dict) and done.get("log"):
            entry = result.tally(str(done["log"]))
            entry.finished = True
            exception = done.get("exception")
            entry.exception_type = str(exception) if exception else None
            error_id = done.get("error_id")
            entry.error_id = str(error_id) if error_id else None
        return True
    if STATUS_KEY in payload:
        status = payload[STATUS_KEY]
        result.final_status = status if isinstance(status, dict) else {}
        return True
    return False


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _channel_status(entry: ChannelTally, timed_out: bool) -> SourceStatus:
    """Status eines einzelnen Sweep-Kanals.

    Ein Kanal ohne Abschlusszeile ist abgebrochen, auch wenn er schon Records
    geliefert hat: Ob danach noch weitere gekommen waeren, weiss niemand.
    """
    if not entry.finished:
        return SourceStatus.TIMED_OUT if timed_out else SourceStatus.FAILED
    status = status_for_exception(entry.exception_type, entry.records_read, entry.error_id)
    if status == SourceStatus.COLLECTED and entry.records_read > len(entry.records):
        return SourceStatus.TRUNCATED
    return status


def build_sweep_results(
    parsed: SweepParse,
    *,
    levels: list[int],
    window_from_utc: datetime,
    window_to_utc: datetime,
    duration_seconds: float,
    timed_out: bool,
) -> list[CollectedSource]:
    """Bewertet den geparsten Strom und baut daraus die Quellen fuer den Bericht.

    Reihenfolge der Ausgabe: zuerst die Uebersichtszeile, dann je ein Eintrag
    fuer jeden Kanal mit Treffern oder unvollstaendiger Erhebung.
    """
    level_text = ", ".join(str(level) for level in levels)

    def base_result(source_id: str, status: SourceStatus, **fields: object) -> SourceResult:
        return SourceResult(
            source_id=source_id,
            status=status,
            requested_from_utc=window_from_utc,
            requested_to_utc=window_to_utc,
            **fields,
        )

    final_exception = None
    if parsed.final_status:
        value = parsed.final_status.get("exception")
        final_exception = str(value) if value else None

    if parsed.planned is None:
        # Das Skript kam nicht einmal bis zur Kanalliste. Ohne Plan laesst sich
        # nichts ueber einzelne Kanaele sagen - also auch kein "keine Treffer".
        if timed_out:
            status = SourceStatus.TIMED_OUT
        elif final_exception:
            status = status_for_exception(final_exception, 1)
        else:
            status = SourceStatus.FAILED
        return [
            CollectedSource(
                result=base_result(
                    SUMMARY_SOURCE_ID,
                    status,
                    duration_seconds=duration_seconds,
                    detail=final_exception,
                    note=(
                        "Die Kanalliste konnte nicht ermittelt werden. Ueber die "
                        "nicht konfigurierten Kanaele ist keine Aussage moeglich."
                    ),
                )
            )
        ]

    # Kanaele, die Records lieferten, aber nicht im Plan standen, sind ein
    # Widerspruch im Strom. Sie werden trotzdem gezeigt - verwerfen hiesse,
    # gelesene Fehler zu verschweigen.
    names = list(parsed.planned)
    planned_keys = {name.lower() for name in names}
    for key, entry in parsed.channels.items():
        if key not in planned_keys and entry.records_read:
            get_log().warn("Sweep-Kanal ausserhalb des Plans", kanal=entry.name)
            # Ausserhalb des Plans gibt es keine Abschlusszeile zu erwarten.
            entry.finished = entry.finished or not timed_out
            names.append(entry.name)
            planned_keys.add(key)

    detailed: list[CollectedSource] = []
    empty = 0
    unreached: list[str] = []
    with_hits = 0
    incomplete = 0
    total_read = 0

    for name in names:
        entry = parsed.channels.get(name.lower()) or ChannelTally(name=name)
        if not entry.finished and entry.records_read == 0:
            unreached.append(entry.name)
            continue

        status = _channel_status(entry, timed_out)
        total_read += entry.records_read
        if status == SourceStatus.EMPTY:
            empty += 1
            continue
        if status in {SourceStatus.COLLECTED, SourceStatus.TRUNCATED}:
            with_hits += 1
        if status != SourceStatus.COLLECTED:
            incomplete += 1

        note = None
        if status == SourceStatus.FAILED and not entry.finished:
            note = (
                "Das Skript brach ab, waehrend dieser Kanal gelesen wurde. "
                "Weitere Fehler in diesem Kanal sind moeglich."
            )
        elif status == SourceStatus.TIMED_OUT:
            note = (
                "Zeitlimit des Sweeps erreicht, waehrend dieser Kanal gelesen wurde. "
                "Weitere Fehler in diesem Kanal sind moeglich."
            )
        elif status == SourceStatus.TRUNCATED:
            note = (
                f"{entry.records_read} Ereignisse gezaehlt, {len(entry.records)} behalten. "
                "Die Zaehlung ist vollstaendig, die Rohdaten nicht."
            )

        covered_from, covered_to = _covered(entry.records)
        detailed.append(
            CollectedSource(
                result=base_result(
                    f"{SOURCE_PREFIX}{entry.name}",
                    status,
                    covered_from_utc=covered_from,
                    covered_to_utc=covered_to,
                    records_read=entry.records_read,
                    records_retained=len(entry.records),
                    detail=entry.error_id or entry.exception_type,
                    note=note,
                ),
                records=entry.records,
            )
        )

    if unreached:
        incomplete += len(unreached)

    summary_parts = [
        f"{len(names)} Kanaele auf Level {level_text} geprueft: "
        f"{with_hits} mit Treffern, {empty} ohne Treffer, "
        f"{incomplete} nicht vollstaendig erhoben."
    ]
    if unreached:
        summary_parts.append(
            ("Wegen Zeitlimit" if timed_out else "Wegen Skriptabbruch")
            + f" nicht erreicht ({len(unreached)}): "
            + ", ".join(unreached)
            + ". Fuer diese Kanaele ist keine Aussage moeglich."
        )
    skipped = [
        f"{count} {SKIP_REASONS_DE.get(reason, reason)}"
        for reason, count in sorted(parsed.skipped.items())
        if count
    ]
    if skipped:
        summary_parts.append("Nicht in den Sweep aufgenommen: " + ", ".join(skipped) + ".")
    summary_parts.append(
        "Warnungen und Informationsereignisse dieser Kanaele wurden nicht gelesen."
    )

    if (unreached or not parsed.final_status) and timed_out:
        summary_status = SourceStatus.TIMED_OUT
    elif unreached or not parsed.final_status or final_exception:
        # Ohne Zeitlimit und ohne Statuszeile ist das Skript abgestuerzt.
        summary_status = SourceStatus.FAILED
    elif total_read:
        summary_status = SourceStatus.COLLECTED
    else:
        summary_status = SourceStatus.EMPTY

    summary = CollectedSource(
        result=base_result(
            SUMMARY_SOURCE_ID,
            summary_status,
            records_read=total_read,
            records_retained=sum(item.result.records_retained for item in detailed),
            duration_seconds=duration_seconds,
            detail=final_exception,
            note=" ".join(summary_parts),
        )
    )
    return [summary, *detailed]


def _covered(records: list[EventRecord]) -> tuple[datetime | None, datetime | None]:
    if not records:
        return None, None
    stamps = [record.timestamp_utc for record in records]
    return min(stamps), max(stamps)


class ErrorSweepCollector:
    """Fuehrt den Fehler-Sweep live aus.

    Liefert mehrere Quellen statt einer und hat deshalb ``collect_many`` statt
    ``collect``. Bewusst keine Unterstuetzung fuer .evtx-Exporte: Ein Sweep
    ueber "alle Kanaele" eines fremden Rechners setzt dessen Kanalliste voraus,
    und die liegt bei einem Export nicht vor. Den lokalen Rechner stattdessen zu
    lesen, waere eine falsche Zuordnung.
    """

    source_id = SUMMARY_SOURCE_ID

    def __init__(
        self,
        *,
        config: ErrorSweepConfig,
        configured_channels: list[str],
        shell: ShellInfo | None,
        window_from_utc: datetime,
        window_to_utc: datetime,
        offline: bool = False,
    ) -> None:
        self.config = config
        self.configured_channels = configured_channels
        self.shell = shell
        self.window_from = window_from_utc
        self.window_to = window_to_utc
        self.offline = offline

    def _window_from(self) -> datetime:
        if self.config.days:
            return max(self.window_from, self.window_to - timedelta(days=self.config.days))
        return self.window_from

    def _single(self, status: SourceStatus, note: str, detail: str | None = None) -> list[
        CollectedSource
    ]:
        return [
            CollectedSource(
                result=SourceResult(
                    source_id=SUMMARY_SOURCE_ID,
                    status=status,
                    requested_from_utc=self._window_from(),
                    requested_to_utc=self.window_to,
                    detail=detail,
                    note=note,
                )
            )
        ]

    def script_args(self) -> list[str]:
        """Argumente fuer ``sweep_errors.ps1``; ausgelagert, damit testbar."""
        window_from = self._window_from()
        args = [
            "-StartUtc", window_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "-EndUtc", self.window_to.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "-Levels", ARG_SEPARATOR.join(str(level) for level in self.config.levels),
            "-LogTypes", ARG_SEPARATOR.join(self.config.log_types),
        ]
        excluded = sorted(
            {name for name in [*self.configured_channels, *self.config.exclude] if name},
            key=str.lower,
        )
        if excluded:
            args += ["-Exclude", ARG_SEPARATOR.join(excluded)]
        return args

    def collect_many(self) -> list[CollectedSource]:
        if not self.config.enabled:
            return self._single(SourceStatus.DISABLED, "Per Konfiguration abgeschaltet.")
        if self.offline:
            return self._single(
                SourceStatus.NOT_AVAILABLE,
                "Bei der Auswertung von .evtx-Exporten nicht moeglich: Die Kanalliste "
                "des Quellrechners liegt nicht vor.",
            )
        if self.shell is None:
            return self._single(
                SourceStatus.FAILED,
                "Ohne PowerShell koennen Ereigniskanaele nicht gelesen werden.",
                detail="PowerShellNotFound",
            )

        run = run_script(
            "sweep_errors.ps1",
            self.script_args(),
            shell=self.shell,
            timeout_seconds=self.config.timeout_seconds,
        )
        blocked = status_from_stderr(run.stderr)
        if blocked is not None:
            get_log().warn("Fehler-Sweep blockiert")
            return self._single(
                blocked,
                "Ausfuehrungsrichtlinie oder Rechte verhindern den Aufruf.",
                detail="PowerShell-Ausfuehrung abgelehnt",
            )

        parsed = parse_sweep(run.lines, keep_per_channel=self.config.max_retained_per_channel)
        return build_sweep_results(
            parsed,
            levels=self.config.levels,
            window_from_utc=self._window_from(),
            window_to_utc=self.window_to,
            duration_seconds=run.duration_seconds,
            timed_out=run.timed_out,
        )


__all__ = [
    "ErrorSweepCollector",
    "SUMMARY_SOURCE_ID",
    "build_sweep_results",
    "parse_sweep",
]
