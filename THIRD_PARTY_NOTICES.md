# Third-party notices

WinEventAI itself is under the MIT licence (`LICENSE`). The Windows release
(`WinEventAI-Setup-*.exe` and the ZIP) bundles the following components. The
licence texts of the Python packages are included in the release under
`licenses/packages/`, the full GPL and LGPL texts under `licenses/`.

| Component | Version | Licence |
|---|---|---|
| Python runtime | 3.13 | PSF License Agreement (`licenses/Python-PSF.txt`) |
| Qt for Python: PySide6, shiboken6 | 6.11 | LGPL-3.0 (used under the LGPL option; `licenses/LGPL-3.0.txt`, `licenses/GPL-3.0.txt`) |
| Qt libraries (inside PySide6) | 6.11 | LGPL-3.0 |
| pydantic, pydantic-core | 2.13 / 2.46 | MIT |
| annotated-types | 0.8 | MIT |
| typing-extensions | 4.16 | PSF-2.0 |
| typing-inspection | 0.4 | MIT |
| PyYAML | 6.0 | MIT |
| Jinja2 | 3.1 | BSD-3-Clause |
| MarkupSafe | 3.0 | BSD-3-Clause |
| typer | 0.27 | MIT |
| shellingham | 1.5 | ISC |
| OpenSSL (part of the Python runtime) | 3 | Apache-2.0 |
| SQLite (part of the Python runtime) | 3 | Public domain |
| libffi (part of the Python runtime) | 3 | MIT |
| Microsoft Visual C++ runtime (`VCRUNTIME140*.dll`) | 14 | Microsoft redistributable licence |
| PyInstaller bootloader | 6.22 | GPL-2.0-or-later with the PyInstaller bootloader exception |

## Qt / PySide6 and the LGPL

Qt and PySide6 are used under the GNU Lesser General Public License v3. The
release is built as a **folder of separate files** (PyInstaller "one-dir"),
not as a single packed executable. The Qt and PySide6 libraries therefore lie
unchanged as separate DLLs and `.pyd` files in `_internal\PySide6` and
`_internal\shiboken6` of the installation directory and can be replaced by the
user with compatible versions.

Source code of Qt: <https://download.qt.io/official_releases/qt/>
Source code of Qt for Python: <https://download.qt.io/official_releases/QtForPython/>

No changes were made to Qt or PySide6.

## PyInstaller

The bootloader that starts `wineventai.exe` and `wineventai-gui.exe` comes
from PyInstaller. Its licence (GPL-2.0-or-later with a special exception)
explicitly allows distributing the bootloader with programs of any licence.
