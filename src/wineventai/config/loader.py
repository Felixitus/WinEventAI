"""Laden und Zusammenfuehren der Konfiguration.

Rangfolge, schwaechste zuerst:

1. mitgelieferte ``wineventai.default.yaml``
2. ``%PROGRAMDATA%\\WinEventAI\\wineventai.yaml``
3. explizit uebergebene Datei (``--config``)
4. Einzelwerte von der Kommandozeile

Zusammengefuehrt wird rekursiv je Schluessel; Listen werden ersetzt, nicht
verschmolzen. Eine halb ueberschriebene Kanalliste waere schwerer zu erklaeren
als eine ganz ersetzte.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..resources import program_data_dir, resource_path
from .model import Config

DEFAULT_RESOURCE = "config/wineventai.default.yaml"
USER_CONFIG_NAME = "wineventai.yaml"


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _read_yaml(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(
            f"{path}: erwartet wurde eine YAML-Abbildung, "
            f"gefunden {type(data).__name__}"
        )
    return data


def default_config_dict() -> dict[str, Any]:
    """Die mitgelieferten Vorgabewerte als reine Abbildung."""
    return _read_yaml(resource_path(DEFAULT_RESOURCE))


def user_config_path() -> Path:
    return program_data_dir() / USER_CONFIG_NAME


def default_config_text() -> str:
    """Der Wortlaut der mitgelieferten Vorgabedatei, inklusive Kommentare."""
    return resource_path(DEFAULT_RESOURCE).read_text(encoding="utf-8")


def commented_out(text: str) -> str:
    """Kommentiert jede Wertzeile aus, laesst Kommentare und Leerzeilen stehen.

    Das ist der Sinn der ganzen Uebung: Eine Datei, in der alles auskommentiert
    ist, uebernimmt NUR das, was jemand bewusst einkommentiert. Alles uebrige
    bleibt an den mitgelieferten Vorgaben haengen und wandert mit jeder neuen
    Version mit.

    Eine vollstaendige Kopie waere bequemer und schlechter: Sie friert die
    Vorgaben des Installationstags ein. Wird spaeter ein Vorgabewert korrigiert,
    ueberschreibt die alte Kopie die Korrektur - und niemand sucht den Fehler in
    einer Datei, die er vor einem Jahr angelegt hat.
    """
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            lines.append(line)
        else:
            lines.append(f"# {line}")
    return "\n".join(lines) + "\n"


HEADER = """\
# WinEventAI - eigene Konfiguration
#
# Angelegt mit 'wineventai config init'.
#
# Hier steht ALLES auskommentiert. Wirksam wird nur, was Sie einkommentieren -
# alles uebrige bleibt an den mitgelieferten Vorgaben und wandert mit kuenftigen
# Versionen mit. Deshalb bitte nicht alles pauschal einkommentieren: Sie wuerden
# die Vorgaben des heutigen Tages einfrieren.
#
# YAML-Falle: Beim Einkommentieren muss der ELTERNSCHLUESSEL mit. Wer nur
#   #   days: 30
# zu
#       days: 30
# macht, setzt "days" auf oberster Ebene - und der Start bricht mit
# "Extra inputs are not permitted" ab. Richtig ist:
#   collect:
#     days: 30
#
# Rangfolge, schwaechste zuerst:
#   1. mitgelieferte Vorgaben
#   2. DIESE DATEI
#   3. --config <datei>
#   4. Schalter auf der Kommandozeile
#
# Wirksame Werte pruefen:  wineventai config show
# Umgebung pruefen:        wineventai doctor

"""


def write_user_config(*, full: bool = False, force: bool = False) -> Path:
    """Legt die Benutzerkonfiguration an.

    Bewusst NICHT automatisch beim ersten Start: Eine Datei, die von selbst
    entsteht, wird nie gelesen - und friert trotzdem Werte ein.

    Raises:
        FileExistsError: wenn die Datei existiert und ``force`` nicht gesetzt ist.
    """
    target = user_config_path()
    if target.exists() and not force:
        raise FileExistsError(
            f"{target} existiert bereits. Mit --force ueberschreiben "
            "(die bisherige Fassung wird dabei als .bak gesichert)."
        )

    body = default_config_text() if full else commented_out(default_config_text())
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        backup = target.with_suffix(target.suffix + ".bak")
        backup.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")

    target.write_text(HEADER + body, encoding="utf-8")
    return target


def effective_config_sources() -> list[tuple[str, Path | None, bool]]:
    """Welche Ebenen es gibt und welche davon tatsaechlich existieren."""
    user = user_config_path()
    return [
        ("mitgeliefert", resource_path(DEFAULT_RESOURCE), True),
        ("benutzer", user, user.is_file()),
    ]


def load_config(
    explicit: Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> Config:
    """Baut die Konfiguration aus allen Ebenen zusammen und validiert sie."""
    merged = default_config_dict()

    user_path = user_config_path()
    if user_path.is_file():
        merged = _deep_merge(merged, _read_yaml(user_path))

    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"Konfigurationsdatei nicht gefunden: {explicit}")
        merged = _deep_merge(merged, _read_yaml(explicit))

    if overrides:
        merged = _deep_merge(merged, overrides)

    return Config.model_validate(merged)
