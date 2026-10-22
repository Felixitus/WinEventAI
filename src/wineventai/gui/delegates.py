"""Zeichner fuer Tabellenzellen.

Bislang war der Schweregrad nur farbiger Text. Das funktioniert, hat aber eine
Schwaeche: Farbe allein ist die einzige Unterscheidung, und wer rot und orange
schlecht auseinanderhaelt - rund acht Prozent der Maenner - sieht eine Liste
gleich aussehender Zeilen.

Ein Chip loest das: Er hat eine Flaeche, einen Rahmen und Text. Die Farbe ist
dann eine von drei Unterscheidungen statt der einzigen.
"""

from __future__ import annotations

from PySide6.QtCore import QModelIndex, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QApplication, QStyle, QStyledItemDelegate, QStyleOptionViewItem

from ..rules.schema import Severity
from . import theme


def _paint_cell_background(
    delegate: QStyledItemDelegate,
    painter: QPainter,
    option: QStyleOptionViewItem,
    index: QModelIndex,
) -> None:
    """Zeichnet Zellhintergrund, Auswahl und Hover - aber keinen Text.

    Nicht ueber ``super().paint``: ``QStyledItemDelegate.paint`` ruft
    ``initStyleOption`` intern noch einmal auf und fuellt den zuvor geleerten
    Text wieder. Der Chip-Text stand dann doppelt und verschoben uebereinander.
    """
    opt = QStyleOptionViewItem(option)
    delegate.initStyleOption(opt, index)
    opt.text = ""
    widget = opt.widget
    style = widget.style() if widget is not None else QApplication.style()
    style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, widget)


class SeverityChipDelegate(QStyledItemDelegate):
    """Malt den Schweregrad als gerundeten Chip statt als farbigen Text."""

    PADDING_X = 9
    PADDING_Y = 3
    RADIUS = 8.0

    def paint(
        self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex
    ) -> None:
        text = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
        if not text:
            super().paint(painter, option, index)
            return

        # Auswahl und Hover kommen vom Stylesheet - erst den Untergrund, dann
        # den Chip darauf, sonst verschwindet die Zeilenmarkierung.
        _paint_cell_background(self, painter, option, index)

        severity = self._severity(text)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        font = QFont(option.font)
        font.setPointSizeF(max(font.pointSizeF() - 0.5, 6.5))
        font.setBold(True)
        painter.setFont(font)

        metrics = painter.fontMetrics()
        breite = metrics.horizontalAdvance(text) + 2 * self.PADDING_X
        hoehe = metrics.height() + 2 * self.PADDING_Y

        rect = QRectF(
            option.rect.left() + 6,
            option.rect.center().y() - hoehe / 2 + 1,
            min(breite, max(option.rect.width() - 8, 10)),
            hoehe,
        )

        vordergrund = QColor(theme.SEVERITY_COLOR.get(severity, theme.NOISE))
        hintergrund = QColor(theme.SEVERITY_BG.get(severity, "#f0eff2"))

        painter.setBrush(hintergrund)
        painter.setPen(QPen(vordergrund, 1.0))
        painter.drawRoundedRect(rect, self.RADIUS, self.RADIUS)

        painter.setPen(QPen(vordergrund))
        painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), text)
        painter.restore()

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex):  # noqa: N802, ANN201
        size = super().sizeHint(option, index)
        size.setHeight(max(size.height() + 8, 30))
        size.setWidth(size.width() + 2 * self.PADDING_X + 22)
        return size

    @staticmethod
    def _severity(text: str) -> Severity:
        """Liest die Schwere aus dem Anzeigetext, der ein '↑' tragen kann."""
        sauber = text.replace("↑", "").strip()
        try:
            return Severity(sauber)
        except ValueError:
            return Severity.RAUSCHEN


class StatusChipDelegate(QStyledItemDelegate):
    """Dasselbe fuer die Abdeckungstabelle: Status als Chip.

    Hier traegt der Chip zusaetzlich Bedeutung, die Farbe allein nicht traegt -
    ein unvollstaendiger Kanal soll auch beim Ueberfliegen auffallen.
    """

    def paint(
        self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex
    ) -> None:
        text = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
        farbe = index.data(Qt.ItemDataRole.ForegroundRole)
        if not text or farbe is None:
            super().paint(painter, option, index)
            return

        _paint_cell_background(self, painter, option, index)

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        font = QFont(option.font)
        font.setPointSizeF(max(font.pointSizeF() - 0.5, 6.5))
        font.setBold(True)
        painter.setFont(font)

        metrics = painter.fontMetrics()
        breite = metrics.horizontalAdvance(text) + 18
        hoehe = metrics.height() + 6
        rect = QRectF(
            option.rect.left() + 6,
            option.rect.center().y() - hoehe / 2,
            min(breite, max(option.rect.width() - 8, 10)),
            hoehe,
        )

        vordergrund = QColor(farbe)
        hintergrund = QColor(vordergrund)
        hintergrund.setAlpha(28)

        painter.setBrush(hintergrund)
        painter.setPen(QPen(vordergrund, 1.0))
        painter.drawRoundedRect(rect, 8.0, 8.0)
        painter.setPen(QPen(vordergrund))
        painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), text)
        painter.restore()

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex):  # noqa: N802, ANN201
        size = super().sizeHint(option, index)
        size.setHeight(max(size.height() + 8, 30))
        size.setWidth(size.width() + 32)
        return size
