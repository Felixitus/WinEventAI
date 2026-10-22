"""Rule engine: deterministic triage before the language model."""

from .engine import Finding, RuleEngine, unmatched_keys
from .loader import RuleLoadError, builtin_rules, load_rules, overlay_dir, overlay_rules
from .schema import (
    SEVERITY_ORDER,
    Classification,
    RuleDefinition,
    RuleMatch,
    RuleThreshold,
    Severity,
)

__all__ = [
    "SEVERITY_ORDER",
    "Classification",
    "Finding",
    "RuleDefinition",
    "RuleEngine",
    "RuleLoadError",
    "RuleMatch",
    "RuleThreshold",
    "Severity",
    "builtin_rules",
    "load_rules",
    "overlay_dir",
    "overlay_rules",
    "unmatched_keys",
]
