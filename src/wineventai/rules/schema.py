"""Regelmodell.

Die wichtigste Zeile dieser Datei ist der Validator, der Regeln ohne
``provider`` ablehnt. Event-IDs sind nur je Provider eindeutig: 1001 ist
BugCheck im System-Kanal UND Windows Error Reporting im Application-Kanal, 1000
existiert dutzendfach. Eine Regel nur mit ``event_id`` ist kein knapper Stil,
sondern ein Fehlalarm-Generator.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Severity(StrEnum):
    KRITISCH = "kritisch"
    FEHLER = "fehler"
    WARNUNG = "warnung"
    INFO = "info"
    RAUSCHEN = "rauschen"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.KRITISCH: 0,
    Severity.FEHLER: 1,
    Severity.WARNUNG: 2,
    Severity.INFO: 3,
    Severity.RAUSCHEN: 4,
}


class Classification(StrEnum):
    BEFUND = "befund"
    RAUSCHEN = "rauschen"


class RuleMatch(BaseModel):
    """Bedingungen einer Regel.

    Rangfolge der Felder, absichtlich: ``provider`` und ``event_id`` sind
    sprachneutral und Pflicht. ``data`` liest benannte EventData-Felder, deren
    Namen aus dem Provider-Manifest kommen und ebenfalls sprachneutral sind.
    ``message_regex`` ist der letzte Ausweg und verlangt deshalb eine
    ``locale``-Angabe - sonst gibt sich eine Regel, die nur auf englischen
    Systemen greift, faelschlich als allgemeingueltig aus.
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
        default=None, description="Benanntes EventData-Feld -> regulaerer Ausdruck."
    )

    @field_validator("provider")
    @classmethod
    def _provider_not_empty(cls, value: str | list[str]) -> str | list[str]:
        values = [value] if isinstance(value, str) else value
        if not values or not all(str(item).strip() for item in values):
            raise ValueError("provider darf nicht leer sein")
        return value

    @model_validator(mode="after")
    def _regex_needs_locale(self) -> RuleMatch:
        if self.message_regex and not self.locale:
            raise ValueError(
                "message_regex verlangt eine locale-Angabe (z.B. 'de-DE' oder 'en-US'). "
                "Meldungstexte sind uebersetzt; eine Regel ohne locale behauptet "
                "faelschlich Allgemeingueltigkeit."
            )
        if self.message_regex:
            try:
                re.compile(self.message_regex)
            except re.error as exc:
                raise ValueError(f"message_regex ist kein gueltiger Ausdruck: {exc}") from exc
        for name, pattern in (self.data or {}).items():
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"data.{name} ist kein gueltiger Ausdruck: {exc}") from exc
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
        """Provider/ID-Paare dieser Regel - der Vorabfilter fuer die Retention."""
        return {(provider, event_id)
                for provider in self.providers()
                for event_id in self.event_ids()}


class RuleThreshold(BaseModel):
    """Schwellwert auf Gruppenebene.

    "7031 einmal" und "7031 vierhundertmal in zehn Minuten" sind verschiedene
    Befunde. Auf Gruppenebene ist das eine Regel mit Schwellwert statt zweier
    Regeln.
    """

    model_config = ConfigDict(extra="forbid")

    count_min: int = 1
    burst_required: bool = False
    escalate_to: Severity | None = None
    escalate_above: int | None = None


class RuleDefinition(BaseModel):
    """Eine Regel, wie sie in YAML steht."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    match: RuleMatch
    severity: Severity
    bedeutung: str = ""
    typische_ursachen: list[str] = Field(default_factory=list)
    empfohlene_checks: list[str] = Field(default_factory=list)
    referenz: str | None = None
    threshold: RuleThreshold = Field(default_factory=RuleThreshold)
    classification: Classification = Classification.BEFUND
    security_indicator: bool = False
    source: str = "builtin"

    @field_validator("id")
    @classmethod
    def _id_shape(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", value):
            raise ValueError(
                "id muss klein geschrieben sein und darf nur a-z, 0-9, '.', '_' und '-' "
                f"enthalten: {value!r}"
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
            "bedeutung": self.bedeutung,
            "typische_ursachen": self.typische_ursachen,
            "empfohlene_checks": self.empfohlene_checks,
            "referenz": self.referenz,
            "herkunft": self.source,
        }
