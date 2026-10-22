"""Colors, fonts and stylesheet of the user interface.

The same palette as the HTML report. Whoever sees both side by side - and that
is the normal case, because the report is opened from the interface - should
not believe they are looking at two different tools.

The severity colors are deliberately NOT the accent color: red, orange and
yellow carry meaning here, and an interface that uses the same tones for
decoration makes that meaning worthless. The accent is therefore a plum tone
that appears in no traffic light.
"""

from __future__ import annotations

from PySide6.QtGui import QColor

from ..rules.schema import Severity

GROUND = "#f4f4f7"
SURFACE = "#ffffff"
SURFACE_SUNK = "#eceaf0"
SURFACE_HOVER = "#f7f5fa"
INK = "#17161c"
INK_SOFT = "#4a4854"
INK_FAINT = "#78757f"
RULE = "#dedce4"
RULE_STRONG = "#c3c0cc"
ACCENT = "#6b4a80"
ACCENT_HOVER = "#7d5894"
ACCENT_PRESSED = "#573c68"
ACCENT_SOFT = "#f0e9f4"

CRIT = "#a52218"
ERR = "#b4551a"
WARN = "#8a6a12"
INFO = "#3a5a86"
NOISE = "#78757f"
OK = "#2f6647"
WARN_BG = "#fbf3e4"
CRIT_BG = "#fbeceb"
OK_BG = "#eaf3ee"

SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: CRIT,
    Severity.ERROR: ERR,
    Severity.WARNING: WARN,
    Severity.INFO: INFO,
    Severity.NOISE: NOISE,
}

#: Background of the severity chips. Very pale so the row stays readable.
SEVERITY_BG: dict[Severity, str] = {
    Severity.CRITICAL: "#fbeceb",
    Severity.ERROR: "#fbf1e8",
    Severity.WARNING: "#fbf6e4",
    Severity.INFO: "#eef2f9",
    Severity.NOISE: "#f0eff2",
}


def severity_color(severity: Severity | str) -> QColor:
    key = severity if isinstance(severity, Severity) else Severity(str(severity))
    return QColor(SEVERITY_COLOR.get(key, NOISE))


def severity_background(severity: Severity | str) -> QColor:
    key = severity if isinstance(severity, Severity) else Severity(str(severity))
    return QColor(SEVERITY_BG.get(key, "#f0eff2"))


STYLESHEET = f"""
QMainWindow, QWidget {{
    background: {GROUND};
    color: {INK};
    font-family: "Segoe UI", system-ui, sans-serif;
    font-size: 13px;
}}

/* --- Headlines ---------------------------------------------------------- */
QLabel#Headline {{
    font-size: 20px;
    font-weight: 600;
    padding: 2px 0;
}}
QLabel#Subline {{
    color: {INK_SOFT};
    font-size: 12.5px;
}}
QLabel#Hint {{
    color: {INK_FAINT};
    font-size: 12px;
}}
QLabel#WarningBanner {{
    background: {WARN_BG};
    border: 1px solid #e8dcbb;
    border-left: 3px solid {WARN};
    border-radius: 3px;
    padding: 10px 14px;
    color: {INK};
}}

/* --- Cards -------------------------------------------------------------- */
QFrame#Card {{
    background: {SURFACE};
    border: 1px solid {RULE};
    border-radius: 4px;
}}

/* --- Buttons ------------------------------------------------------------ */
QPushButton {{
    background: {SURFACE};
    border: 1px solid {RULE_STRONG};
    border-radius: 4px;
    padding: 7px 16px;
    color: {INK};
}}
QPushButton:hover {{
    background: {SURFACE_HOVER};
    border-color: {ACCENT};
    color: {ACCENT};
}}
QPushButton:pressed {{
    background: {ACCENT_SOFT};
    border-color: {ACCENT_PRESSED};
    color: {ACCENT_PRESSED};
}}
QPushButton:disabled {{
    background: {SURFACE_SUNK};
    color: {INK_FAINT};
    border-color: {RULE};
}}
QPushButton:focus {{
    outline: none;
    border: 2px solid {ACCENT};
    padding: 6px 15px;
}}

QPushButton#Primary {{
    background: {ACCENT};
    color: #ffffff;
    border: 1px solid {ACCENT};
    font-weight: 600;
    padding: 7px 20px;
}}
QPushButton#Primary:hover {{
    background: {ACCENT_HOVER};
    border-color: {ACCENT_HOVER};
    color: #ffffff;
}}
QPushButton#Primary:pressed {{
    background: {ACCENT_PRESSED};
    border-color: {ACCENT_PRESSED};
}}
QPushButton#Primary:disabled {{
    background: {RULE_STRONG};
    border-color: {RULE_STRONG};
    color: {SURFACE};
}}
QPushButton#Primary:focus {{
    border: 2px solid {ACCENT_PRESSED};
    padding: 6px 19px;
}}

QPushButton#Cancel:hover {{
    border-color: {CRIT};
    color: {CRIT};
    background: {CRIT_BG};
}}

/* --- Inputs ------------------------------------------------------------- */
QSpinBox {{
    background: {SURFACE};
    border: 1px solid {RULE_STRONG};
    border-radius: 4px;
    padding: 5px 6px;
    min-width: 88px;
    selection-background-color: {ACCENT_SOFT};
    selection-color: {INK};
}}
QSpinBox:focus {{ border-color: {ACCENT}; }}
QSpinBox::up-button, QSpinBox::down-button {{
    width: 16px;
    border-left: 1px solid {RULE};
    background: {SURFACE_SUNK};
}}
QSpinBox::up-button:hover, QSpinBox::down-button:hover {{ background: {ACCENT_SOFT}; }}

QCheckBox {{ spacing: 7px; padding: 3px 0; }}
QCheckBox::indicator {{
    width: 15px;
    height: 15px;
    border: 1px solid {RULE_STRONG};
    border-radius: 3px;
    background: {SURFACE};
}}
QCheckBox::indicator:hover {{ border-color: {ACCENT}; }}
QCheckBox::indicator:checked {{
    background: {ACCENT};
    border-color: {ACCENT};
    image: none;
}}
QCheckBox:disabled {{ color: {INK_FAINT}; }}

/* --- Tables ------------------------------------------------------------- */
QTableView, QTreeView, QListView {{
    background: {SURFACE};
    border: 1px solid {RULE};
    border-radius: 4px;
    gridline-color: {RULE};
    selection-background-color: {ACCENT_SOFT};
    selection-color: {INK};
    outline: none;
}}
QTableView::item {{ padding: 5px 4px; }}
QTableView::item:hover {{ background: {SURFACE_HOVER}; }}
QTableView::item:selected {{
    background: {ACCENT_SOFT};
    color: {INK};
    border-left: 2px solid {ACCENT};
}}
QHeaderView::section {{
    background: {SURFACE_SUNK};
    color: {INK_FAINT};
    border: none;
    border-bottom: 1px solid {RULE};
    border-right: 1px solid {RULE};
    padding: 7px 9px;
    font-size: 10px;
    font-weight: 700;
}}
QHeaderView::section:last {{ border-right: none; }}

/* --- Text --------------------------------------------------------------- */
QTextBrowser {{
    background: {SURFACE};
    border: 1px solid {RULE};
    border-radius: 4px;
    padding: 6px 10px;
}}
QPlainTextEdit#Log {{
    background: #1b1a21;
    border: 1px solid {RULE};
    border-radius: 4px;
    font-family: Consolas, "SF Mono", monospace;
    font-size: 11.5px;
    color: #cfcbd6;
    padding: 6px;
    selection-background-color: {ACCENT};
}}

/* --- Progress ----------------------------------------------------------- */
QProgressBar {{
    border: 1px solid {RULE_STRONG};
    border-radius: 4px;
    background: {SURFACE};
    text-align: center;
    height: 22px;
    font-size: 11px;
    color: {INK_SOFT};
}}
QProgressBar::chunk {{
    background: {ACCENT};
    border-radius: 3px;
}}

/* --- Tabs --------------------------------------------------------------- */
QTabWidget::pane {{
    border: 1px solid {RULE};
    border-radius: 4px;
    background: {SURFACE};
    top: -1px;
}}
QTabBar::tab {{
    background: transparent;
    color: {INK_SOFT};
    padding: 8px 18px;
    border: 1px solid transparent;
    border-bottom: 2px solid transparent;
    margin-right: 2px;
}}
QTabBar::tab:hover {{ color: {ACCENT}; }}
QTabBar::tab:selected {{
    background: {SURFACE};
    color: {INK};
    font-weight: 600;
    border: 1px solid {RULE};
    border-bottom: 2px solid {ACCENT};
}}

/* --- Rest --------------------------------------------------------------- */
QStatusBar {{
    background: {SURFACE_SUNK};
    color: {INK_SOFT};
    border-top: 1px solid {RULE};
}}
QStatusBar::item {{ border: none; }}
QSplitter::handle {{ background: transparent; width: 8px; }}
QSplitter::handle:hover {{ background: {ACCENT_SOFT}; }}

QScrollBar:vertical {{
    background: transparent; width: 11px; margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {RULE_STRONG}; border-radius: 5px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {INK_FAINT}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 0; }}
QScrollBar::handle:horizontal {{
    background: {RULE_STRONG}; border-radius: 5px; min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{ background: {INK_FAINT}; }}

QMenuBar {{ background: {GROUND}; border-bottom: 1px solid {RULE}; }}
QMenuBar::item {{ padding: 6px 12px; background: transparent; }}
QMenuBar::item:selected {{ background: {ACCENT_SOFT}; color: {ACCENT}; }}
QMenu {{ background: {SURFACE}; border: 1px solid {RULE_STRONG}; padding: 4px; }}
QMenu::item {{ padding: 6px 24px 6px 14px; border-radius: 3px; }}
QMenu::item:selected {{ background: {ACCENT_SOFT}; color: {ACCENT}; }}
QMenu::separator {{ height: 1px; background: {RULE}; margin: 4px 8px; }}

QToolTip {{
    background: #1b1a21;
    color: #eceaf1;
    border: 1px solid {RULE_STRONG};
    padding: 6px 8px;
}}
"""
