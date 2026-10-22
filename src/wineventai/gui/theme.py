"""Farben, Schriften und Stylesheet der Oberflaeche.

Dieselbe Palette wie der HTML-Bericht. Wer beides nebeneinander sieht - und das
ist der Normalfall, weil der Bericht aus der Oberflaeche heraus geoeffnet wird -
soll nicht zwei verschiedene Werkzeuge zu sehen glauben.

Die Schweregrad-Farben sind bewusst NICHT die Akzentfarbe: Rot, Orange und Gelb
tragen hier Bedeutung, und eine Oberflaeche, die dieselben Toene auch zur
Verzierung benutzt, macht diese Bedeutung wertlos. Deshalb ist der Akzent ein
Pflaumenton, der in keiner Ampel vorkommt.
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
    Severity.KRITISCH: CRIT,
    Severity.FEHLER: ERR,
    Severity.WARNUNG: WARN,
    Severity.INFO: INFO,
    Severity.RAUSCHEN: NOISE,
}

#: Hintergrund der Schweregrad-Chips. Sehr blass, damit die Zeile lesbar bleibt.
SEVERITY_BG: dict[Severity, str] = {
    Severity.KRITISCH: "#fbeceb",
    Severity.FEHLER: "#fbf1e8",
    Severity.WARNUNG: "#fbf6e4",
    Severity.INFO: "#eef2f9",
    Severity.RAUSCHEN: "#f0eff2",
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

/* --- Kopfzeilen --------------------------------------------------------- */
QLabel#Kopfzeile {{
    font-size: 20px;
    font-weight: 600;
    padding: 2px 0;
}}
QLabel#Unterzeile {{
    color: {INK_SOFT};
    font-size: 12.5px;
}}
QLabel#Hinweis {{
    color: {INK_FAINT};
    font-size: 12px;
}}
QLabel#Warnbanner {{
    background: {WARN_BG};
    border: 1px solid #e8dcbb;
    border-left: 3px solid {WARN};
    border-radius: 3px;
    padding: 10px 14px;
    color: {INK};
}}

/* --- Karten ------------------------------------------------------------- */
QFrame#Karte {{
    background: {SURFACE};
    border: 1px solid {RULE};
    border-radius: 4px;
}}

/* --- Schalter ----------------------------------------------------------- */
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

QPushButton#Primaer {{
    background: {ACCENT};
    color: #ffffff;
    border: 1px solid {ACCENT};
    font-weight: 600;
    padding: 7px 20px;
}}
QPushButton#Primaer:hover {{
    background: {ACCENT_HOVER};
    border-color: {ACCENT_HOVER};
    color: #ffffff;
}}
QPushButton#Primaer:pressed {{
    background: {ACCENT_PRESSED};
    border-color: {ACCENT_PRESSED};
}}
QPushButton#Primaer:disabled {{
    background: {RULE_STRONG};
    border-color: {RULE_STRONG};
    color: {SURFACE};
}}
QPushButton#Primaer:focus {{
    border: 2px solid {ACCENT_PRESSED};
    padding: 6px 19px;
}}

QPushButton#Abbruch:hover {{
    border-color: {CRIT};
    color: {CRIT};
    background: {CRIT_BG};
}}

/* --- Eingaben ----------------------------------------------------------- */
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

/* --- Tabellen ----------------------------------------------------------- */
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
QPlainTextEdit#Protokoll {{
    background: #1b1a21;
    border: 1px solid {RULE};
    border-radius: 4px;
    font-family: Consolas, "SF Mono", monospace;
    font-size: 11.5px;
    color: #cfcbd6;
    padding: 6px;
    selection-background-color: {ACCENT};
}}

/* --- Fortschritt -------------------------------------------------------- */
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

/* --- Reiter ------------------------------------------------------------- */
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
