# PyInstaller specification for WinEventAI.
#
# ONE-DIR, not one-file. One-file unpacks to %TEMP% on every start and looks
# like packer behavior to EDR. For a tool that reads security logs that is the
# worst possible signature.
#
# Call:  pyinstaller packaging\wineventai.spec --noconfirm

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent  # noqa: F821 - set by PyInstaller
PACKAGE = ROOT / "src" / "wineventai"

# Program icon, generated from docs/logo.svg by packaging/make_icons.py.
ICON = str(PACKAGE / "gui" / "assets" / "wineventai.ico")

# Version resource: what Explorer shows under Properties > Details. An EXE
# without it looks like something nobody stands behind - to users and to
# reputation-based scanners alike. The version is read from the package, so
# there is exactly one place that holds it.
import re  # noqa: E402

from PyInstaller.utils.win32.versioninfo import (  # noqa: E402
    FixedFileInfo,
    StringFileInfo,
    StringStruct,
    StringTable,
    VarFileInfo,
    VarStruct,
    VSVersionInfo,
)

VERSION = re.search(
    r'__version__ = "([^"]+)"', (PACKAGE / "__init__.py").read_text(encoding="utf-8")
).group(1)
VERSION_TUPLE = tuple(int(part) for part in VERSION.split(".")[:3]) + (0,)
AUTHOR = "Felix Spiß"  # escaped: no non-ASCII characters in source code


def version_resource(internal_name, description):
    return VSVersionInfo(
        ffi=FixedFileInfo(
            filevers=VERSION_TUPLE,
            prodvers=VERSION_TUPLE,
            mask=0x3F,
            flags=0x0,
            OS=0x40004,
            fileType=0x1,
            subtype=0x0,
            date=(0, 0),
        ),
        kids=[
            StringFileInfo([
                StringTable("040904B0", [
                    StringStruct("CompanyName", AUTHOR),
                    StringStruct("FileDescription", description),
                    StringStruct("FileVersion", VERSION),
                    StringStruct("InternalName", internal_name),
                    StringStruct("LegalCopyright", f"(c) 2026 {AUTHOR}, MIT licence"),
                    StringStruct("OriginalFilename", f"{internal_name}.exe"),
                    StringStruct("ProductName", "WinEventAI"),
                    StringStruct("ProductVersion", VERSION),
                ])
            ]),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ],
    )

# Bundled resources. resource_path() later finds them via sys._MEIPASS or
# the directory next to the EXE - the rest of the code knows nothing of it.
datas = [
    (str(PACKAGE / "config" / "wineventai.default.yaml"), "wineventai/config"),
    (str(PACKAGE / "collect" / "scripts"), "wineventai/collect/scripts"),
    (str(PACKAGE / "probes" / "scripts"), "wineventai/probes/scripts"),
    (str(PACKAGE / "rules" / "builtin"), "wineventai/rules/builtin"),
    (str(PACKAGE / "kb" / "seed.yaml"), "wineventai/kb"),
    (str(PACKAGE / "ai" / "prompts"), "wineventai/ai/prompts"),
    (str(PACKAGE / "ai" / "bench_cases.yaml"), "wineventai/ai"),
    (str(PACKAGE / "report" / "templates"), "wineventai/report/templates"),
    (str(PACKAGE / "report" / "assets"), "wineventai/report/assets"),
    (str(PACKAGE / "gui" / "assets"), "wineventai/gui/assets"),
]

# Collect Qt only if it is there: the command line must also build without
# PySide6 - it is the way for servers and software distribution.
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
    # None of this is needed and all of it makes the package big.
    excludes=[
        "tkinter", "matplotlib", "numpy", "pandas", "PIL", "pytest",
        # QtWebEngine would be about 150 MB of Chromium for a user interface that
        # only shows text and tables. The HTML report opens in the system
        # browser - that is where it belongs, because it gets passed on.
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
    icon=ICON,
    version=version_resource("wineventai", "WinEventAI command line"),
    console=True,
    disable_windowed_traceback=False,
    upx=False,  # UPX is exactly the packer signature we want to avoid
)

# Second executable for the user interface: console=False, so that no black
# window flashes up on start. Both share the same Analysis, hence the same
# libraries - that costs no second set of DLLs.
targets = [exe]
if HAS_QT:
    exe_gui = EXE(  # noqa: F821
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="wineventai-gui",
        icon=ICON,
        version=version_resource("wineventai-gui", "WinEventAI"),
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
