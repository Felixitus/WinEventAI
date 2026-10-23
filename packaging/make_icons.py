"""Renders the program icon from docs/logo.svg and docs/logo-small.svg.

Call:  python packaging/make_icons.py

Writes ``src/wineventai/gui/assets/wineventai.ico`` (for the EXE files and the
window), ``wineventai.png`` (256 px, for places that cannot read ICO) and a copy
of the logo into ``report/assets`` for the HTML report, which embeds it inline.

Why a script and not a converter from the internet: the result has to be
reproducible from the SVG sources in the repository, and the build must not
depend on a tool nobody can find again. PySide6 is a development dependency
anyway; its SVG renderer is enough.

Why two sources: at 16 and 24 pixels the lens of the logo is only a grey blur.
Windows picks the image of the matching size from the ICO, so the small sizes
get the variant without lens and with thicker lines.

The ICO is assembled by hand (PNG-compressed entries, supported since Windows
Vista) instead of via Pillow - one dependency less for a 30-line format.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QRectF, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

ROOT = Path(__file__).resolve().parent.parent
LOGO = ROOT / "docs" / "logo.svg"
LOGO_SMALL = ROOT / "docs" / "logo-small.svg"
TARGET = ROOT / "src" / "wineventai" / "gui" / "assets"
REPORT_LOGO = ROOT / "src" / "wineventai" / "report" / "assets" / "logo.svg"

SMALL_SIZES = (16, 24)
LARGE_SIZES = (32, 48, 64, 128, 256)


def render_png(svg: Path, size: int) -> bytes:
    """Renders one SVG at one size and returns the PNG bytes."""
    renderer = QSvgRenderer(str(svg))
    if not renderer.isValid():
        raise SystemExit(f"Not a valid SVG: {svg}")
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()

    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    image.save(buffer, "PNG")
    buffer.close()
    return bytes(data.data())


def build_ico(images: list[tuple[int, bytes]]) -> bytes:
    """ICO container with PNG entries. A size of 256 is written as 0 in the directory."""
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = len(header) + 16 * len(images)
    directory = b""
    payload = b""
    for size, png in images:
        edge = 0 if size >= 256 else size
        directory += struct.pack("<BBBBHHII", edge, edge, 0, 0, 1, 32, len(png), offset)
        payload += png
        offset += len(png)
    return header + directory + payload


def main() -> int:
    app = QGuiApplication(sys.argv[:1])  # noqa: F841 - Qt needs an application object
    images = [(size, render_png(LOGO_SMALL, size)) for size in SMALL_SIZES]
    images += [(size, render_png(LOGO, size)) for size in LARGE_SIZES]

    TARGET.mkdir(parents=True, exist_ok=True)
    ico = TARGET / "wineventai.ico"
    ico.write_bytes(build_ico(images))
    png = TARGET / "wineventai.png"
    png.write_bytes(images[-1][1])
    print(f"written: {ico} ({len(images)} sizes)")
    print(f"written: {png}")
    REPORT_LOGO.write_text(LOGO.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"written: {REPORT_LOGO}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
