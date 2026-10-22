"""Loading and merging the configuration.

Precedence, weakest first:

1. bundled ``wineventai.default.yaml``
2. ``%PROGRAMDATA%\\WinEventAI\\wineventai.yaml``
3. explicitly passed file (``--config``)
4. single values from the command line

Merging is recursive per key; lists are replaced, not merged. A half-overridden
channel list would be harder to explain than a fully replaced one.
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
            f"{path}: expected a YAML mapping, found {type(data).__name__}"
        )
    return data


def default_config_dict() -> dict[str, Any]:
    """The bundled defaults as a plain mapping."""
    return _read_yaml(resource_path(DEFAULT_RESOURCE))


def user_config_path() -> Path:
    return program_data_dir() / USER_CONFIG_NAME


def default_config_text() -> str:
    """The exact text of the bundled defaults file, including comments."""
    return resource_path(DEFAULT_RESOURCE).read_text(encoding="utf-8")


def commented_out(text: str) -> str:
    """Comments out every value line, leaving comments and blank lines alone.

    That is the whole point: a file in which everything is commented out takes
    over ONLY what someone deliberately uncomments. Everything else stays tied
    to the bundled defaults and moves along with every new version.

    A complete copy would be more convenient and worse: it freezes the defaults
    of the installation day. If a default is corrected later, the old copy
    overrides the correction - and nobody looks for the bug in a file they
    created a year ago.
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
# WinEventAI - own configuration
#
# Created with 'wineventai config init'.
#
# EVERYTHING here is commented out. Only what you uncomment takes effect -
# everything else stays tied to the bundled defaults and moves along with
# future versions. So please do not uncomment everything wholesale: you would
# freeze today's defaults.
#
# YAML trap: when uncommenting, the PARENT KEY has to come along. Turning
#   #   days: 30
# into
#       days: 30
# sets "days" at the top level - and startup fails with
# "Extra inputs are not permitted". Correct is:
#   collect:
#     days: 30
#
# Precedence, weakest first:
#   1. bundled defaults
#   2. THIS FILE
#   3. --config <file>
#   4. command-line switches
#
# Check effective values:  wineventai config show
# Check the environment:   wineventai doctor

"""


def write_user_config(*, full: bool = False, force: bool = False) -> Path:
    """Creates the user configuration.

    Deliberately NOT automatic on first start: a file that appears by itself is
    never read - and freezes values anyway.

    Raises:
        FileExistsError: if the file exists and ``force`` is not set.
    """
    target = user_config_path()
    if target.exists() and not force:
        raise FileExistsError(
            f"{target} already exists. Overwrite with --force "
            "(the previous version is kept as .bak)."
        )

    body = default_config_text() if full else commented_out(default_config_text())
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        backup = target.with_suffix(target.suffix + ".bak")
        backup.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")

    target.write_text(HEADER + body, encoding="utf-8")
    return target


def effective_config_sources() -> list[tuple[str, Path | None, bool]]:
    """Which layers exist and which of them are actually present."""
    user = user_config_path()
    return [
        ("bundled", resource_path(DEFAULT_RESOURCE), True),
        ("user", user, user.is_file()),
    ]


def load_config(
    explicit: Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> Config:
    """Builds the configuration from all layers and validates it."""
    merged = default_config_dict()

    user_path = user_config_path()
    if user_path.is_file():
        merged = _deep_merge(merged, _read_yaml(user_path))

    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"Configuration file not found: {explicit}")
        merged = _deep_merge(merged, _read_yaml(explicit))

    if overrides:
        merged = _deep_merge(merged, overrides)

    return Config.model_validate(merged)
