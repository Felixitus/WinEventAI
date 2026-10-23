"""Copies every licence text the release has to carry next to the EXE files.

Call:  python packaging/collect_licenses.py <target directory>

Why a step of its own and not PyInstaller ``datas``: PyInstaller 6 puts data
files into ``_internal``, where nobody looks. The licences belong next to the
programs - and into the installer, which shows ``LICENSE`` before installing.

Which packages: exactly the third-party distributions the program imports at
run time (see THIRD_PARTY_NOTICES.md). Their licence files come from their own
``.dist-info`` - copied, not retyped. A package that is missing in the build
environment fails the build instead of producing a release without its notice.
"""

from __future__ import annotations

import shutil
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

BUNDLED = (
    "pydantic",
    "pydantic_core",
    "annotated-types",
    "typing_extensions",
    "typing-inspection",
    "PyYAML",
    "Jinja2",
    "MarkupSafe",
    "typer",
    "shellingham",
)

#: Qt for Python is used under the LGPL. Its wheels only carry a reference
#: file to the commercial Qt licence, which would be misleading in this
#: release - the LGPL-3.0 and GPL-3.0 texts in licenses/ apply instead.
QT_PACKAGES = ("PySide6", "PySide6_Essentials", "shiboken6")

OWN_FILES = ("LICENSE", "THIRD_PARTY_NOTICES.md", "SECURITY.md", "CHANGELOG.md")
MARKERS = ("licen", "copying", "notice")


def licence_files(name: str) -> list[Path]:
    dist = metadata.distribution(name)
    found: list[Path] = []
    for entry in dist.files or []:
        if ".dist-info" not in str(entry.parent):
            continue
        if any(marker in entry.name.lower() for marker in MARKERS):
            found.append(Path(str(entry.locate())))
    return found


def main(target: Path) -> int:
    target.mkdir(parents=True, exist_ok=True)
    for name in OWN_FILES:
        shutil.copy2(ROOT / name, target / name)
    shutil.copytree(ROOT / "licenses", target / "licenses", dirs_exist_ok=True)

    missing: list[str] = []
    for name in BUNDLED:
        try:
            files = licence_files(name)
        except metadata.PackageNotFoundError:
            missing.append(name)
            continue
        if not files:
            missing.append(f"{name} (no licence file in its dist-info)")
            continue
        destination = target / "licenses" / "packages" / metadata.metadata(name)["Name"]
        destination.mkdir(parents=True, exist_ok=True)
        for file in files:
            shutil.copy2(file, destination / file.name)

    if missing:
        print("Missing licence information: " + ", ".join(missing), file=sys.stderr)
        return 1
    for name in QT_PACKAGES:
        try:
            metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        print(f"{name}: LGPL-3.0, see licenses/LGPL-3.0.txt")
    print(f"Licences written to {target / 'licenses'}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: collect_licenses.py <target directory>")
    raise SystemExit(main(Path(sys.argv[1])))
