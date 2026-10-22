"""Painters for table cells.

The severity used to be colored text only. That works but has a weakness:
color is the only distinction, and whoever has trouble telling red from orange
- about eight percent of men - sees a list of identical-looking rows.

A chip solves this: it has an area, a border and text. Color is then one of
three distinctions instead of the only one.
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
    """Paints cell background, selection and hover - but no text.

    Not via ``super().paint``: ``QStyledItemDelegate.paint`` calls
    ``initStyleOption`` internally once more and fills in the text that was
    cleared before. The chip text then appeared twice, shifted on top of itself.
    """
    opt = QStyleOptionViewItem(option)
    delegate.initStyleOption(opt, index)
    opt.text = ""
    widget = opt.widget
    style = widget.style() if widget is not None else QApplication.style()
    style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, widget)


class SeverityChipDelegate(QStyledItemDelegate):
    """Paints the severity as a rounded chip instead of colored text."""

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

        # Selection and hover come from the stylesheet - first the background,
        # then the chip on top, otherwise the row highlight disappears.
        _paint_cell_background(self, painter, option, index)

        severity = self._severity(text)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        font = QFont(option.font)
        font.setPointSizeF(max(font.pointSizeF() - 0.5, 6.5))
        font.setBold(True)
        painter.setFont(font)

        metrics = painter.fontMetrics()
        width = metrics.horizontalAdvance(text) + 2 * self.PADDING_X
        height = metrics.height() + 2 * self.PADDING_Y

        rect = QRectF(
            option.rect.left() + 6,
            option.rect.center().y() - height / 2 + 1,
            min(width, max(option.rect.width() - 8, 10)),
            height,
        )

        foreground = QColor(theme.SEVERITY_COLOR.get(severity, theme.NOISE))
        background = QColor(theme.SEVERITY_BG.get(severity, "#f0eff2"))

        painter.setBrush(background)
        painter.setPen(QPen(foreground, 1.0))
        painter.drawRoundedRect(rect, self.RADIUS, self.RADIUS)

        painter.setPen(QPen(foreground))
        painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), text)
        painter.restore()

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex):  # noqa: N802, ANN201
        size = super().sizeHint(option, index)
        size.setHeight(max(size.height() + 8, 30))
        size.setWidth(size.width() + 2 * self.PADDING_X + 22)
        return size

    @staticmethod
    def _severity(text: str) -> Severity:
        """Reads the severity from the display text, which may carry an '↑'."""
        clean = text.replace("↑", "").strip()
        try:
            return Severity(clean)
        except ValueError:
            return Severity.NOISE


class StatusChipDelegate(QStyledItemDelegate):
    """The same for the coverage table: status as a chip.

    Here the chip additionally carries meaning that color alone does not - an
    incomplete channel should stand out even when skimming.
    """

    def paint(
        self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex
    ) -> None:
        text = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
        color = index.data(Qt.ItemDataRole.ForegroundRole)
        if not text or color is None:
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
        width = metrics.horizontalAdvance(text) + 18
        height = metrics.height() + 6
        rect = QRectF(
            option.rect.left() + 6,
            option.rect.center().y() - height / 2,
            min(width, max(option.rect.width() - 8, 10)),
            height,
        )

        foreground = QColor(color)
        background = QColor(foreground)
        background.setAlpha(28)

        painter.setBrush(background)
        painter.setPen(QPen(foreground, 1.0))
        painter.drawRoundedRect(rect, 8.0, 8.0)
        painter.setPen(QPen(foreground))
        painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), text)
        painter.restore()

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex):  # noqa: N802, ANN201
        size = super().sizeHint(option, index)
        size.setHeight(max(size.height() + 8, 30))
        size.setWidth(size.width() + 32)
        return size
