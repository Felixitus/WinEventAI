"""Loading rules: bundled defaults plus overlay from %PROGRAMDATA%.

Merging is by ``id``. The origin goes into ``RuleDefinition.source`` and later
into the report - otherwise someone will eventually argue about a finding that
was produced by a local YAML nobody knows about.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from ..applog import get_log
from ..resources import program_data_dir, resource_path
from .schema import RuleDefinition

BUILTIN_FILES = (
    "core_system.yaml",
    "core_application.yaml",
    "storage.yaml",
    "hardware.yaml",
    "noise.yaml",
    "security.yaml",
)


class RuleLoadError(ValueError):
    """A rule file could not be loaded."""


def _load_file(path: Path, source: str) -> list[RuleDefinition]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"{path}: YAML not readable: {exc}") from exc

    if payload is None:
        return []
    if isinstance(payload, dict) and "rules" in payload:
        payload = payload["rules"]
    if not isinstance(payload, list):
        raise RuleLoadError(f"{path}: expected a list of rules")

    rules: list[RuleDefinition] = []
    for index, entry in enumerate(payload):
        if not isinstance(entry, dict):
            raise RuleLoadError(f"{path}: entry {index} is not a mapping")
        entry = {**entry, "source": source}
        try:
            rules.append(RuleDefinition.model_validate(entry))
        except ValidationError as exc:
            rule_id = entry.get("id", f"#{index}")
            raise RuleLoadError(f"{path}: rule {rule_id} is invalid:\n{exc}") from exc
    return rules


def builtin_rules() -> list[RuleDefinition]:
    """The bundled rules."""
    rules: list[RuleDefinition] = []
    for name in BUILTIN_FILES:
        path = resource_path(f"rules/builtin/{name}")
        rules.extend(_load_file(path, source="builtin"))
    return rules


def overlay_dir(configured: str | None = None) -> Path:
    if configured:
        return Path(configured)
    return program_data_dir() / "rules"


def overlay_rules(configured: str | None = None) -> list[RuleDefinition]:
    """Rules from the overlay directory. If it is missing, that is not an error."""
    directory = overlay_dir(configured)
    if not directory.is_dir():
        return []
    rules: list[RuleDefinition] = []
    for path in sorted(directory.glob("*.yaml")):
        rules.extend(_load_file(path, source=f"overlay:{path.name}"))
    return rules


def load_rules(
    *,
    overlay: str | None = None,
    include_security: bool = False,
) -> list[RuleDefinition]:
    """Assembles the effective rule set.

    Security rules are only active when security mode is switched on.
    Otherwise a 4625 series on a terminal server makes noise every day without
    anyone having asked for it.
    """
    merged: dict[str, RuleDefinition] = {}
    for rule in builtin_rules():
        merged[rule.id] = rule
    for rule in overlay_rules(overlay):
        if rule.id in merged:
            get_log().info("Rule overridden", rule=rule.id, origin=rule.source)
        merged[rule.id] = rule

    rules = list(merged.values())
    if not include_security:
        rules = [rule for rule in rules if not rule.security_indicator]
    rules.sort(key=lambda rule: rule.id)
    return rules
