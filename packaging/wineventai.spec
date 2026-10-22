# PyInstaller-Spezifikation fuer WinEventAI.
#
# ONE-DIR, nicht one-file. One-file entpackt bei jedem Start nach %TEMP% und
# sieht fuer EDR nach Packer-Verhalten aus. Fuer ein Werkzeug, das
# Sicherheitsprotokolle liest, ist das die denkbar schlechteste Signatur.
#
# Aufruf:  pyinstaller packaging\wineventai.spec --noconfirm

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent  # noqa: F821 - von PyInstaller gesetzt
PACKAGE = ROOT / "src" / "wineventai"

# Mitgelieferte Ressourcen. resource_path() findet sie spaeter ueber
# sys._MEIPASS bzw. das Verzeichnis neben der EXE - der uebrige Code weiss
# nichts davon.
datas = [
    (str(PACKAGE / "config" / "wineventai.default.yaml"), "wineventai/config"),
    (str(PACKAGE / "collect" / "scripts"), "wineventai/collect/scripts"),
    (str(PACKAGE / "probes" / "scripts"), "wineventai/probes/scripts"),
    (str(PACKAGE / "rules" / "builtin"), "wineventai/rules/builtin"),
    (str(PACKAGE / "kb" / "seed.yaml"), "wineventai/kb"),
    (str(PACKAGE / "ai" / "prompts"), "wineventai/ai/prompts"),
    (str(PACKAGE / "report" / "templates"), "wineventai/report/templates"),
    (str(PACKAGE / "report" / "assets"), "wineventai/report/assets"),
]

# Qt nur einsammeln, wenn es da ist: Die Kommandozeile muss sich auch ohne
# PySide6 bauen lassen - sie ist der Weg fuer Server und Softwareverteilung.
try:
    import PySide6  # noqa: F401

    HAS_QT = True
except ImportError:
    HAS_QT = False

hiddenimports = collect_submodules("wineventai") + [
    "pydantic",
    "pydantic_core",
    "yaml",
    "jinja2",
    "typer",
    "click",
]

if HAS_QT:
    hiddenimports += [
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
    ]

a = Analysis(  # noqa: F821
    [str(PACKAGE / "__main__.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    # Nichts davon wird gebraucht und alles davon macht das Paket gross.
    excludes=[
        "tkinter", "matplotlib", "numpy", "pandas", "PIL", "pytest",
        # QtWebEngine waere rund 150 MB Chromium fuer eine Oberflaeche, die nur
        # Text und Tabellen zeigt. Der HTML-Bericht wird im System-Browser
        # geoeffnet - dort gehoert er hin, denn er wird weitergegeben.
        "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
        "PySide6.QtQml", "PySide6.QtQuick", "PySide6.Qt3DCore", "PySide6.QtMultimedia",
        "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtPdf",
        "PySide6.QtDesigner", "PySide6.QtSql", "PySide6.QtTest",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="wineventai",
    console=True,
    disable_windowed_traceback=False,
    upx=False,  # UPX ist genau die Packer-Signatur, die wir vermeiden wollen
)

# Zweite ausfuehrbare Datei fuer die Oberflaeche: console=False, damit beim
# Start kein schwarzes Fenster aufblitzt. Beide teilen sich dieselbe Analysis,
# also auch dieselben Bibliotheken - das kostet keinen zweiten Satz DLLs.
targets = [exe]
if HAS_QT:
    exe_gui = EXE(  # noqa: F821
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="wineventai-gui",
        console=False,
        disable_windowed_traceback=False,
        upx=False,
    )
    targets.append(exe_gui)

coll = COLLECT(  # noqa: F821
    *targets,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="wineventai",
)
