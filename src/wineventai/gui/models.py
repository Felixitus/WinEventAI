"""Qt-Modelle fuer Abdeckung und Befunde.

Die Modelle enthalten keine Logik, sie stellen ``ReportModel`` dar. Deshalb sind
sie auch ohne Fenster testbar - was der Grund ist, warum sie in einer eigenen
Datei stehen und nicht in den Widgets.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor, QFont

from ..collect.base import INCONCLUSIVE
from ..report.model import CoverageRow, ReportModel
from ..rules.engine import Finding
from . import theme


def _fmt_int(value: int) -> str:
    return f"{value:,}".replace(",", ".")


class CoverageModel(QAbstractTableModel):
    """Die Abdeckungstabelle - im Fenster genauso weit oben wie im Bericht.

    Grund ist derselbe: Wer "keine Befunde" liest, ohne vorher gesehen zu haben,
    dass eine Quelle gar nicht erhoben wurde, zieht den falschen Schluss.
    """

    # Reihenfolge nach Nutzen beim Ueberfliegen: Der Hinweis steht vor dem
    # angeforderten Zeitraum, weil Letzterer in jeder Zeile gleich ist und den
    # Hinweis sonst aus dem sichtbaren Bereich schiebt.
    HEADERS = ("Quelle", "Status", "Gelesen", "Behalten", "Abgedeckt", "Hinweis", "Angefordert")
    COL_SOURCE, COL_STATUS, COL_READ, COL_RETAINED, COL_COVERED, COL_NOTE, COL_REQUESTED = range(7)

    def __init__(self, rows: list[CoverageRow] | None = None) -> None:
        super().__init__()
        self._rows: list[CoverageRow] = rows or []

    def set_rows(self, rows: list[CoverageRow]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def rowCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        return 0 if (parent and parent.isValid()) else len(self._rows)

    def columnCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        return 0 if (parent and parent.isValid()) else len(self.HEADERS)

    def headerData(  # noqa: N802
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def row_at(self, index: int) -> CoverageRow | None:
        return self._rows[index] if 0 <= index < len(self._rows) else None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return (
                row.source_id,
                str(row.status),
                _fmt_int(row.records_read),
                _fmt_int(row.records_retained),
                row.covered + ("  [Luecke]" if row.coverage_gap else ""),
                coverage_note(row),
                row.requested,
            )[column]

        if role == Qt.ItemDataRole.ForegroundRole and column == self.COL_STATUS:
            return QColor(theme.ERR if row.inconclusive else theme.OK)

        if role == Qt.ItemDataRole.BackgroundRole and row.inconclusive:
            return QColor(theme.WARN_BG)

        if role == Qt.ItemDataRole.ToolTipRole:
            parts = [row.source_id, row.hint]
            if row.note:
                parts.append(row.note)
            return "\n".join(part for part in parts if part)

        if role == Qt.ItemDataRole.TextAlignmentRole and column in (
            self.COL_READ,
            self.COL_RETAINED,
        ):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        return None


def coverage_note(row: CoverageRow) -> str:
    """Der sichtbare Hinweis je Quelle: zuerst der konkrete Vermerk, sonst der Statustext.

    Frueher stand der Vermerk nur im Tooltip. Gerade die wichtigsten Saetze -
    welche Kanaele der Sweep nicht erreicht hat, warum eine Quelle fehlt -
    waren damit fuer jeden unsichtbar, der nicht zufaellig mit der Maus
    darueberfaehrt.
    """
    return (row.note or row.hint or "").strip()


#: Numerischer Windows-Level -> Anzeige. Bewusst ueber die Zahl, nie ueber
#: LevelDisplayName - der ist lokalisiert.
LEVEL_LABEL: dict[int, str] = {
    0: "immer",
    1: "kritisch",
    2: "fehler",
    3: "warnung",
    4: "info",
    5: "ausfuehrlich",
}


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


class UnknownEventsModel(QAbstractTableModel):
    """Ereignisgruppen ohne gesicherte Bedeutung in der Wissensbasis.

    Das ist der Teil, den der Fehler-Sweep zusaetzlich hereinholt: Fehler aus
    Kanaelen, fuer die es keine Regel gibt. Angezeigt wird die Originalmeldung
    von Windows - eine Bewertung findet hier ausdruecklich NICHT statt, und die
    Spalte "Bedeutung" sagt das, statt leer zu bleiben.
    """

    HEADERS = ("Stufe", "Anzahl", "Provider", "ID", "Kanal", "Bedeutung", "Meldung (Beispiel)")
    NO_MEANING = "nicht hinterlegt"

    def __init__(self, rows: list[dict[str, object]] | None = None) -> None:
        super().__init__()
        self._rows: list[dict[str, object]] = []
        self.set_rows(rows or [])

    def set_rows(self, rows: list[dict[str, object]]) -> None:
        """Sortiert schwerste Stufe zuerst, innerhalb der Stufe nach Haeufigkeit."""
        self.beginResetModel()
        self._rows = sorted(
            rows,
            key=lambda row: (
                _as_int(row.get("level"), 9) or 9,
                -_as_int(row.get("anzahl")),
            ),
        )
        self.endResetModel()

    def row_at(self, index: int) -> dict[str, object] | None:
        return self._rows[index] if 0 <= index < len(self._rows) else None

    def level_at(self, index: int) -> int:
        row = self.row_at(index)
        return _as_int(row.get("level"), 9) if row else 9

    def rowCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        return 0 if (parent and parent.isValid()) else len(self._rows)

    def columnCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        return 0 if (parent and parent.isValid()) else len(self.HEADERS)

    def headerData(  # noqa: N802
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()
        level = _as_int(row.get("level"), -1)
        meldung = " ".join(str(row.get("beispielmeldung") or "").split())

        if role == Qt.ItemDataRole.DisplayRole:
            return (
                LEVEL_LABEL.get(level, f"level {level}" if level >= 0 else "unbekannt"),
                _fmt_int(_as_int(row.get("anzahl"))),
                str(row.get("provider") or ""),
                str(row.get("event_id") or ""),
                str(row.get("kanal") or ""),
                self.NO_MEANING,
                meldung or "(keine Meldung)",
            )[column]

        if role == Qt.ItemDataRole.ForegroundRole:
            if column == 0 and level in (1, 2):
                return QColor(theme.ERR)
            if column == 5:
                return QColor(theme.NOISE)

        if role == Qt.ItemDataRole.ToolTipRole:
            return (
                f"{row.get('provider')}:{row.get('event_id')} im Kanal {row.get('kanal')}\n\n"
                f"{meldung}\n\nFuer dieses Paar gibt es keinen gesicherten Eintrag in der "
                "Wissensbasis. Die Meldung ist der Originaltext von Windows, keine Bewertung."
            )

        if role == Qt.ItemDataRole.TextAlignmentRole and column in (1, 3):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        return None


class UnknownEventsFilter(QSortFilterProxyModel):
    """Filter fuer die Liste: nur Kritisch/Fehler und/oder Volltext.

    Die Filterung ist reine Darstellung - welche Gruppen ueberhaupt in der
    Liste stehen, entscheidet die Pipeline.
    """

    def __init__(self) -> None:
        super().__init__()
        self.only_errors = True
        self.text = ""

    def set_only_errors(self, value: bool) -> None:
        self.only_errors = value
        self.invalidate()

    def set_text(self, value: str) -> None:
        self.text = value.strip().lower()
        self.invalidate()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        model = self.sourceModel()
        if not isinstance(model, UnknownEventsModel):
            return True
        if self.only_errors and model.level_at(source_row) not in (1, 2):
            return False
        if not self.text:
            return True
        row = model.row_at(source_row) or {}
        haystack = " ".join(str(value) for value in row.values()).lower()
        return self.text in haystack


class FindingsModel(QAbstractTableModel):
    """Die Befundliste, sortiert wie im Bericht: Schwere zuerst."""

    HEADERS = ("Schwere", "Befund", "Anzahl", "Zuletzt (UTC)")

    def __init__(self, findings: list[Finding] | None = None) -> None:
        super().__init__()
        self._findings: list[Finding] = findings or []

    def set_findings(self, findings: list[Finding]) -> None:
        self.beginResetModel()
        self._findings = findings
        self.endResetModel()

    def finding_at(self, index: int) -> Finding | None:
        return self._findings[index] if 0 <= index < len(self._findings) else None

    def rowCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        return 0 if (parent and parent.isValid()) else len(self._findings)

    def columnCount(self, parent: QModelIndex | None = None) -> int:  # noqa: N802
        return 0 if (parent and parent.isValid()) else len(self.HEADERS)

    def headerData(  # noqa: N802
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        finding = self._findings[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            schwere = str(finding.severity)
            if finding.escalated:
                schwere += " ↑"
            return (
                schwere,
                finding.rule_name,
                _fmt_int(finding.group.count),
                finding.group.last_seen_utc.strftime("%d.%m. %H:%M"),
            )[column]

        if role == Qt.ItemDataRole.ForegroundRole and column == 0:
            return theme.severity_color(finding.severity)

        if role == Qt.ItemDataRole.FontRole and column == 0:
            font = QFont()
            font.setBold(True)
            return font

        if role == Qt.ItemDataRole.TextAlignmentRole and column == 2:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        if role == Qt.ItemDataRole.ToolTipRole:
            kopf = f"{finding.group.provider}:{finding.group.event_id}"
            if not finding.has_verified_meaning:
                return (
                    f"{kopf}\n\nKeine gesicherte Bedeutung in der Wissensbasis "
                    f"hinterlegt (Status: {finding.kb_confidence})."
                )
            return f"{kopf}\n\n{finding.bedeutung.strip()}"

        return None


def summary_line(report: ReportModel) -> str:
    """Eine Zeile Kennzahlen unter der Kopfzeile."""
    return (
        f"{_fmt_int(report.total_events)} Ereignisse · "
        f"{_fmt_int(report.distinct_groups)} Fingerprints · "
        f"Reduktion {report.reduction_rate * 100:.1f} % · "
        f"{len(report.findings)} Befunde, {len(report.noise)} als Rauschen ausgeblendet"
    )


def coverage_warning(report: ReportModel) -> str | None:
    """Der Warnhinweis ueber der Befundliste, oder ``None``."""
    unvollstaendig = [row for row in report.coverage if row.inconclusive]
    if not unvollstaendig:
        return None
    namen = ", ".join(row.source_id for row in unvollstaendig[:4])
    if len(unvollstaendig) > 4:
        namen += f" und {len(unvollstaendig) - 4} weitere"
    return (
        f"Der Zeitraum wurde nicht vollstaendig erhoben ({namen}). "
        "Ueber die nicht abgedeckten Zeitraeume laesst sich nichts aussagen - "
        "bitte zuerst die Abdeckung lesen."
    )


def inconclusive_sources(report: ReportModel) -> list[str]:
    return [row.source_id for row in report.coverage if row.status in INCONCLUSIVE]
