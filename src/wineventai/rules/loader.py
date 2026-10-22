"""Regeln laden: mitgelieferte Defaults plus Overlay aus %PROGRAMDATA%.

Zusammengefuehrt wird nach ``id``. Die Herkunft wandert in ``RuleDefinition.source``
und spaeter in den Bericht - sonst diskutiert irgendwann jemand ueber einen
Befund, den eine lokale YAML erzeugt hat, die niemand kennt.
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
    """Eine Regeldatei liess sich nicht laden."""


def _load_file(path: Path, source: str) -> list[RuleDefinition]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"{path}: YAML nicht lesbar: {exc}") from exc

    if payload is None:
        return []
    if isinstance(payload, dict) and "rules" in payload:
        payload = payload["rules"]
    if not isinstance(payload, list):
        raise RuleLoadError(f"{path}: erwartet wurde eine Liste von Regeln")

    rules: list[RuleDefinition] = []
    for index, entry in enumerate(payload):
        if not isinstance(entry, dict):
            raise RuleLoadError(f"{path}: Eintrag {index} ist keine Abbildung")
        entry = {**entry, "source": source}
        try:
            rules.append(RuleDefinition.model_validate(entry))
        except ValidationError as exc:
            rule_id = entry.get("id", f"#{index}")
            raise RuleLoadError(f"{path}: Regel {rule_id} ist ungueltig:\n{exc}") from exc
    return rules


def builtin_rules() -> list[RuleDefinition]:
    """Die mitgelieferten Regeln."""
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
    """Regeln aus dem Overlay-Verzeichnis. Fehlt es, ist das kein Fehler."""
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
    """Baut das wirksame Regelwerk zusammen.

    Sicherheitsregeln sind nur aktiv, wenn der Sicherheitsmodus eingeschaltet
    ist. Sonst erzeugt eine 4625-Serie auf einem Terminalserver jeden Tag Laerm,
    ohne dass jemand danach gefragt haette.
    """
    merged: dict[str, RuleDefinition] = {}
    for rule in builtin_rules():
        merged[rule.id] = rule
    for rule in overlay_rules(overlay):
        if rule.id in merged:
            get_log().info(
                "Regel ueberschrieben", regel=rule.id, herkunft=rule.source
            )
        merged[rule.id] = rule

    rules = list(merged.values())
    if not include_security:
        rules = [rule for rule in rules if not rule.security_indicator]
    rules.sort(key=lambda rule: rule.id)
    return rules
