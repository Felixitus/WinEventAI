"""Qt models for coverage and findings.

The models contain no logic, they display ``ReportModel``. That makes them
testable without a window - which is the reason they live in a file of their
own and not in the widgets.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor, QFont

from ..collect.base import INCONCLUSIVE
from ..normalize.schema import LEVEL_LABEL
from ..report.model import CoverageRow, ReportModel
from ..rules.engine import Finding
from . import theme


def _fmt_int(value: int) -> str:
    return f"{value:,}"


class CoverageModel(QAbstractTableModel):
    """The coverage table - in the window as far up as in the report.

    The reason is the same: whoever reads "no findings" without having seen
    first that a source was not collected at all draws the wrong conclusion.
    """

    # Order by usefulness when skimming: the note comes before the requested
    # period, because the latter is the same in every row and would otherwise
    # push the note out of the visible area.
    HEADERS = ("Source", "Status", "Read", "Retained", "Covered", "Note", "Requested")
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
                row.covered + ("  [gap]" if row.coverage_gap else ""),
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
    """The visible note per source: the concrete note first, otherwise the status text.

    The note used to be in the tooltip only. Exactly the most important
    sentences - which channels the sweep did not reach, why a source is missing
    - were therefore invisible to everyone who did not happen to hover over it.
    """
    return (row.note or row.hint or "").strip()


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


class UnknownEventsModel(QAbstractTableModel):
    """Event groups without a verified meaning in the knowledge base.

    This is the part the error sweep brings in additionally: errors from
    channels for which there is no rule. The original Windows message is shown
    - an assessment explicitly does NOT take place here, and the column
    "Meaning" says so instead of staying empty.
    """

    HEADERS = ("Level", "Count", "Provider", "ID", "Channel", "Meaning", "Message (sample)")
    NO_MEANING = "not on record"

    def __init__(self, rows: list[dict[str, object]] | None = None) -> None:
        super().__init__()
        self._rows: list[dict[str, object]] = []
        self.set_rows(rows or [])

    def set_rows(self, rows: list[dict[str, object]]) -> None:
        """Sorts the most severe level first, by frequency within a level."""
        self.beginResetModel()
        self._rows = sorted(
            rows,
            key=lambda row: (
                _as_int(row.get("level"), 9) or 9,
                -_as_int(row.get("count")),
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
        message = " ".join(str(row.get("sample_message") or "").split())

        if role == Qt.ItemDataRole.DisplayRole:
            return (
                LEVEL_LABEL.get(level, f"level {level}" if level >= 0 else "unknown"),
                _fmt_int(_as_int(row.get("count"))),
                str(row.get("provider") or ""),
                str(row.get("event_id") or ""),
                str(row.get("channel") or ""),
                self.NO_MEANING,
                message or "(no message)",
            )[column]

        if role == Qt.ItemDataRole.ForegroundRole:
            if column == 0 and level in (1, 2):
                return QColor(theme.ERR)
            if column == 5:
                return QColor(theme.NOISE)

        if role == Qt.ItemDataRole.ToolTipRole:
            return (
                f"{row.get('provider')}:{row.get('event_id')} in channel {row.get('channel')}\n\n"
                f"{message}\n\nThere is no verified entry in the knowledge base for this "
                "pair. The message is the original Windows text, not an assessment."
            )

        if role == Qt.ItemDataRole.TextAlignmentRole and column in (1, 3):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        return None


class UnknownEventsFilter(QSortFilterProxyModel):
    """Filter for the list: critical/error only and/or full text.

    Filtering is pure presentation - which groups are in the list at all is
    decided by the pipeline.
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
    """The list of findings, sorted as in the report: severity first."""

    HEADERS = ("Severity", "Finding", "Count", "Last (UTC)")

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
            severity = str(finding.severity)
            if finding.escalated:
                severity += " ↑"
            return (
                severity,
                finding.rule_name,
                _fmt_int(finding.group.count),
                finding.group.last_seen_utc.strftime("%Y-%m-%d %H:%M"),
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
            head = f"{finding.group.provider}:{finding.group.event_id}"
            if not finding.has_verified_meaning:
                return (
                    f"{head}\n\nNo verified meaning on record in the knowledge base "
                    f"(state: {finding.kb_confidence})."
                )
            return f"{head}\n\n{finding.meaning.strip()}"

        return None


def summary_line(report: ReportModel) -> str:
    """One line of figures below the headline."""
    return (
        f"{_fmt_int(report.total_events)} events · "
        f"{_fmt_int(report.distinct_groups)} fingerprints · "
        f"reduction {report.reduction_rate * 100:.1f} % · "
        f"{len(report.findings)} findings, {len(report.noise)} hidden as noise"
    )


def coverage_warning(report: ReportModel) -> str | None:
    """The warning above the list of findings, or ``None``."""
    incomplete = [row for row in report.coverage if row.inconclusive]
    if not incomplete:
        return None
    names = ", ".join(row.source_id for row in incomplete[:4])
    if len(incomplete) > 4:
        names += f" and {len(incomplete) - 4} more"
    return (
        f"The period was not collected completely ({names}). "
        "Nothing can be said about the uncovered periods - "
        "please read the coverage first."
    )


def inconclusive_sources(report: ReportModel) -> list[str]:
    return [row.source_id for row in report.coverage if row.status in INCONCLUSIVE]
