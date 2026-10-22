"""PowerShell-Erkennung, Aufruf und NDJSON-Verarbeitung.

Die Trennung in dieser Datei ist die Testgrenze des Collectors: ``read_ndjson``
kennt nur einen Zeilen-Iterator und weiss nichts von Prozessen. Tests speisen
Fixture-Dateien ein; im Betrieb kommen die Zeilen aus ``stdout`` von PowerShell.
Damit ist der gesamte Collector ohne Windows testbar.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ..applog import get_log
from ..normalize.mapper import NormalizationError, record_from_line
from ..normalize.schema import EventRecord
from ..resources import resource_path
from .base import SourceStatus

STATUS_KEY = "__status"

#: Trennzeichen fuer Listen-Argumente an alle mitgelieferten Skripte.
#: Ueber ``-File`` kommen Argumente als Zeichenketten an. "1001,4624,...," in
#: einen ``[int[]]``-Parameter zu geben, scheitert unter Windows PowerShell 5.1
#: mit ParameterArgumentTransformationError (auf Windows 11 beobachtet); ein
#: ``[string[]]``-Parameter bekommt die ganze Liste als EIN Element. Deshalb
#: nimmt jedes Skript Listen als eine Zeichenkette und trennt selbst. Der
#: senkrechte Strich kommt in Kanal-, Rollen- und Dienstnamen nach derzeitigem
#: Kenntnisstand nicht vor (unbestaetigt fuer Dienst-Anzeigenamen).
LIST_SEPARATOR = "|"

_ERROR_ID = re.compile(r"FullyQualifiedErrorId\s*:\s*([^\s,]+)")


def join_list_arg(values: Iterable[object]) -> str:
    """Baut ein Listen-Argument fuer ein Skript."""
    return LIST_SEPARATOR.join(str(value) for value in values)


def error_id_from_stderr(stderr: str) -> str | None:
    """Zieht die FullyQualifiedErrorId aus einer PowerShell-Fehlermeldung.

    Die Meldung selbst ist lokalisiert, die Bezeichnung
    ``FullyQualifiedErrorId`` und ihr Wert sind es nicht - auch auf einem
    deutschen Windows steht dort ``ParameterArgumentTransformationError``.
    """
    if not stderr:
        return None
    match = _ERROR_ID.search(stderr)
    return match.group(1) if match else None


class PowerShellNotFoundError(RuntimeError):
    """Weder pwsh noch powershell im PATH."""


@dataclass(slots=True)
class ShellInfo:
    """Welche PowerShell benutzt wird."""

    executable: str
    path: str
    major_version: int | None = None

    @property
    def is_core(self) -> bool:
        return Path(self.path).stem.lower() == "pwsh"


def find_powershell(preference: Iterable[str] = ("pwsh", "powershell")) -> ShellInfo:
    """Sucht eine nutzbare PowerShell.

    ``pwsh`` wird bevorzugt, ist aber nicht erforderlich: Alle
    Versionsunterschiede, die uns betreffen wuerden - DateTime-Serialisierung
    und Ausgabekodierung - sind bereits im Skript neutralisiert. Deshalb ist die
    Wahl hier eine Zeile und keine Testmatrix.
    """
    for name in preference:
        found = shutil.which(name)
        if found:
            return ShellInfo(executable=name, path=found)
    raise PowerShellNotFoundError(
        "Keine PowerShell gefunden. Erwartet wurde 'pwsh' oder 'powershell' im PATH."
    )


@dataclass(slots=True)
class NdjsonResult:
    """Was beim Lesen eines NDJSON-Stroms herauskam."""

    records: list[EventRecord] = field(default_factory=list)
    records_read: int = 0
    status_line: dict[str, object] | None = None
    parse_errors: int = 0
    truncated: bool = False

    @property
    def completed(self) -> bool:
        """True, wenn das Skript bis zu seiner Statuszeile gekommen ist.

        Ohne Statuszeile ist das Skript abgestuerzt oder gar nicht erst
        gestartet (z.B. Parameterfehler). Null Records bedeuten dann NICHT
        "keine Treffer" - genau diese Verwechslung liess System, Application
        und Setup auf einem echten Rechner als leer erscheinen.
        """
        return self.status_line is not None

    @property
    def error_id(self) -> str | None:
        """FullyQualifiedErrorId aus der Statuszeile, sofern das Skript sie schreibt."""
        if not self.status_line:
            return None
        value = self.status_line.get("error_id")
        return str(value) if value else None

    @property
    def exception_type(self) -> str | None:
        if not self.status_line:
            return None
        value = self.status_line.get("exception")
        return str(value) if value else None


def read_ndjson(
    lines: Iterable[str],
    *,
    source_tool: str,
    source_ref: str,
    keep: int | None = None,
    on_record: callable | None = None,
) -> NdjsonResult:
    """Liest einen NDJSON-Strom in Records und die abschliessende Statuszeile.

    ``keep`` begrenzt nur, wie viele Records *behalten* werden. Gelesen und
    gezaehlt wird immer alles - das ist der Unterschied zwischen einer
    Rohdatengrenze und einem stillschweigend verkleinerten Zeitfenster.
    """
    import json

    result = NdjsonResult()
    log = get_log()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if STATUS_KEY in line[:24]:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                result.parse_errors += 1
                continue
            if isinstance(payload, dict) and STATUS_KEY in payload:
                status = payload[STATUS_KEY]
                result.status_line = status if isinstance(status, dict) else {}
                result.truncated = bool(result.status_line.get("truncated"))
                continue
        try:
            record = record_from_line(line, source_tool=source_tool, source_ref=source_ref)
        except NormalizationError as exc:
            result.parse_errors += 1
            if result.parse_errors <= 3:
                log.warn("Zeile uebersprungen", quelle=source_ref, grund=str(exc))
            continue

        result.records_read += 1
        if on_record is not None:
            on_record(record)
        if keep is None or len(result.records) < keep:
            result.records.append(record)

    if result.parse_errors:
        log.warn("Nicht lesbare Zeilen", quelle=source_ref, anzahl=result.parse_errors)
    return result


@dataclass(slots=True)
class ShellRun:
    """Rohes Ergebnis eines PowerShell-Aufrufs."""

    lines: list[str]
    returncode: int
    stderr: str
    duration_seconds: float
    timed_out: bool


def run_script(
    script: str,
    args: list[str],
    *,
    shell: ShellInfo,
    timeout_seconds: float,
    folder: str = "collect/scripts",
) -> ShellRun:
    """Startet ein mitgeliefertes .ps1 und sammelt dessen NDJSON-Zeilen.

    Aufruf ueber ``-File``, nicht ueber ``-EncodedCommand``. Base64-kodierte
    PowerShell ist eine der auffaelligsten EDR-Signaturen ueberhaupt - fuer ein
    Werkzeug, das Sicherheitsprotokolle liest, das denkbar schlechteste Bild.

    Bei Zeitueberschreitung wird der Prozess beendet, aber das bereits Gelesene
    behalten: ein haengender Kanal darf den Lauf nicht toeten.
    """
    script_path = resource_path(f"{folder}/{script}")
    command = [
        shell.path,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        *args,
    ]

    started = time.monotonic()
    lines: list[str] = []
    timed_out = False
    stderr_text = ""

    process = subprocess.Popen(  # noqa: S603 - fester Interpreter, mitgeliefertes Skript
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    try:
        assert process.stdout is not None
        for line in process.stdout:
            lines.append(line)
            if time.monotonic() - started > timeout_seconds:
                timed_out = True
                break
        if timed_out:
            process.kill()
        stderr_text = (process.stderr.read() if process.stderr else "") or ""
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - Prozess reagiert nicht
        process.kill()
        timed_out = True
    finally:
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()

    return ShellRun(
        lines=lines,
        returncode=process.returncode if process.returncode is not None else -1,
        stderr=stderr_text,
        duration_seconds=time.monotonic() - started,
        timed_out=timed_out,
    )


def status_from_stderr(stderr: str) -> SourceStatus | None:
    """Erkennt die wenigen Faelle, die PowerShell vor dem Skriptstart abbricht.

    Hier *muss* ausnahmsweise Text betrachtet werden, weil das Skript in diesen
    Faellen gar nicht erst laeuft und daher keine Statuszeile schreiben kann.
    Geprueft wird deshalb auf sprachneutrale Bestandteile - Bezeichner wie
    ``UnauthorizedAccess`` und ``PSSecurityException`` stehen auch auf deutschen
    Systemen unuebersetzt in der Fehler-ID.
    """
    if not stderr:
        return None
    lowered = stderr.lower()
    if "pssecurityexception" in lowered or "unauthorizedaccess" in lowered:
        return SourceStatus.BLOCKED
    if "executionpolicy" in lowered.replace(" ", ""):
        return SourceStatus.BLOCKED
    return None


#: Zustaende aus ``list_channels.ps1`` und ihre Anzeige in ``doctor``.
CHANNEL_STATE_DE: dict[str, str] = {
    "present": "vorhanden",
    "missing": "FEHLT",
    "unreadable": "vorhanden, ohne Adminrechte nicht lesbar",
    "error": "nicht pruefbar",
}


def channel_states_from_lines(lines: Iterable[str]) -> dict[str, str] | None:
    """Liest die Ausgabe von ``list_channels.ps1``: Kanalname -> Zustand.

    ``None`` heisst "nicht pruefbar" (Skript lief nicht bis zur Statuszeile),
    nicht "kein Kanal vorhanden". Schluessel sind kleingeschrieben, weil
    Windows Kanalnamen ohne Ruecksicht auf Gross-/Kleinschreibung behandelt.
    """
    import json

    states: dict[str, str] = {}
    completed = False
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        if STATUS_KEY in payload:
            completed = True
            continue
        name = payload.get("name")
        state = payload.get("state")
        if isinstance(name, str) and isinstance(state, str):
            states[name.lower()] = state if state in CHANNEL_STATE_DE else "error"
    return states if completed else None


def iter_file_lines(path: Path) -> Iterator[str]:
    """Zeilenweiser Leser fuer NDJSON-Dateien im Laufverzeichnis."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        yield from handle
