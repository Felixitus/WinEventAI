"""Rule model.

The most important line in this file is the validator that rejects rules
without ``provider``. Event ids are only unique per provider: 1001 is BugCheck
in the System channel AND Windows Error Reporting in the Application channel,
1000 exists dozens of times. A rule with only ``event_id`` is not a terse
style but a false-alarm generator.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

#: Severity values used by versions before 2.0. Rule overlays written for those
#: versions keep loading instead of failing validation.
_LEGACY_SEVERITY: dict[str, str] = {
    "kritisch": "critical",
    "fehler": "error",
    "warnung": "warning",
    "rauschen": "noise",
}

#: Rule field names used by versions before 2.0, mapped onto the current ones.
_LEGACY_RULE_FIELDS: dict[str, str] = {
    "bedeutung": "meaning",
    "typische_ursachen": "typical_causes",
    "empfohlene_checks": "recommended_checks",
    "referenz": "reference",
}


class Severity(StrEnum):
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    NOISE = "noise"

    @classmethod
    def _missing_(cls, value: object) -> Severity | None:
        if isinstance(value, str):
            current = _LEGACY_SEVERITY.get(value.strip().lower())
            if current is not None:
                return cls(current)
        return None


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.ERROR: 1,
    Severity.WARNING: 2,
    Severity.INFO: 3,
    Severity.NOISE: 4,
}


class Classification(StrEnum):
    FINDING = "finding"
    NOISE = "noise"

    @classmethod
    def _missing_(cls, value: object) -> Classification | None:
        legacy = {"befund": "finding", "rauschen": "noise"}
        if isinstance(value, str) and value.strip().lower() in legacy:
            return cls(legacy[value.strip().lower()])
        return None


class RuleMatch(BaseModel):
    """Conditions of a rule.

    Order of the fields, on purpose: ``provider`` and ``event_id`` are
    language-neutral and mandatory. ``data`` reads named EventData fields whose
    names come from the provider manifest and are language-neutral as well.
    ``message_regex`` is the last resort and therefore requires a ``locale`` -
    otherwise a rule that only fires on English systems would falsely pass
    itself off as universally valid.
    """

    model_config = ConfigDict(extra="forbid")

    provider: str | list[str]
    event_id: int | list[int]
    channel: str | list[str] | None = None
    level_max: int | None = Field(default=None, ge=0, le=5)
    event_version: int | None = None
    message_regex: str | None = None
    locale: str | None = None
    data: dict[str, str] | None = Field(
        default=None, description="Named EventData field -> regular expression."
    )

    @field_validator("provider")
    @classmethod
    def _provider_not_empty(cls, value: str | list[str]) -> str | list[str]:
        values = [value] if isinstance(value, str) else value
        if not values or not all(str(item).strip() for item in values):
            raise ValueError("provider must not be empty")
        return value

    @model_validator(mode="after")
    def _regex_needs_locale(self) -> RuleMatch:
        if self.message_regex and not self.locale:
            raise ValueError(
                "message_regex requires a locale (e.g. 'de-DE' or 'en-US'). "
                "Message texts are translated; a rule without locale falsely "
                "claims to be universally valid."
            )
        if self.message_regex:
            try:
                re.compile(self.message_regex)
            except re.error as exc:
                raise ValueError(f"message_regex is not a valid expression: {exc}") from exc
        for name, pattern in (self.data or {}).items():
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"data.{name} is not a valid expression: {exc}") from exc
        return self

    def providers(self) -> list[str]:
        return [self.provider] if isinstance(self.provider, str) else list(self.provider)

    def event_ids(self) -> list[int]:
        return [self.event_id] if isinstance(self.event_id, int) else list(self.event_id)

    def channels(self) -> list[str]:
        if self.channel is None:
            return []
        return [self.channel] if isinstance(self.channel, str) else list(self.channel)

    def match_keys(self) -> set[tuple[str, int]]:
        """Provider/id pairs of this rule - the pre-filter for retention."""
        return {(provider, event_id)
                for provider in self.providers()
                for event_id in self.event_ids()}


class RuleThreshold(BaseModel):
    """Threshold at group level.

    "7031 once" and "7031 four hundred times in ten minutes" are different
    findings. At group level that is one rule with a threshold instead of two
    rules.
    """

    model_config = ConfigDict(extra="forbid")

    count_min: int = 1
    burst_required: bool = False
    escalate_to: Severity | None = None
    escalate_above: int | None = None


class RuleDefinition(BaseModel):
    """A rule as written in YAML."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    match: RuleMatch
    severity: Severity
    meaning: str = ""
    typical_causes: list[str] = Field(default_factory=list)
    recommended_checks: list[str] = Field(default_factory=list)
    reference: str | None = None
    threshold: RuleThreshold = Field(default_factory=RuleThreshold)
    classification: Classification = Classification.FINDING
    security_indicator: bool = False
    source: str = "builtin"

    @model_validator(mode="before")
    @classmethod
    def _legacy_field_names(cls, data: Any) -> Any:
        """Accepts the German field names of rule overlays written before 2.0."""
        if not isinstance(data, dict):
            return data
        renamed = dict(data)
        for old, new in _LEGACY_RULE_FIELDS.items():
            if old in renamed and new not in renamed:
                renamed[new] = renamed.pop(old)
        return renamed

    @field_validator("id")
    @classmethod
    def _id_shape(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", value):
            raise ValueError(
                "id must be lower case and may only contain a-z, 0-9, '.', '_' and '-': "
                f"{value!r}"
            )
        return value

    def compiled_message(self) -> re.Pattern[str] | None:
        if not self.match.message_regex:
            return None
        return re.compile(self.match.message_regex, re.IGNORECASE)

    def compiled_data(self) -> dict[str, re.Pattern[str]]:
        return {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in (self.match.data or {}).items()
        }

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": str(self.severity),
            "meaning": self.meaning,
            "typical_causes": self.typical_causes,
            "recommended_checks": self.recommended_checks,
            "reference": self.reference,
            "origin": self.source,
        }
