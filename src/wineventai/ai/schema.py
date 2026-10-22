"""Input and output schema of the AI layer.

The evidence is a STRUCTURED field, not prose. Only that makes the requirement
"every model statement points to concrete event ids and timestamps"
machine-checkable. Whoever has to scrape the evidence out of running text ends
up testing their own regular expression, not the model.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Confidence = Literal["high", "medium", "low", "unclear"]


class Evidence(BaseModel):
    """One piece of evidence: exactly one event from the input bundle."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    event_id: int
    timestamp_utc: datetime


class Statement(BaseModel):
    """A single statement of the model with evidence and a confidence rating."""

    model_config = ConfigDict(extra="forbid")

    statement: str
    evidence: list[Evidence] = Field(min_length=1)
    confidence: Confidence

    # Set by the verification, not by the model.
    verified: bool = True
    verification_note: str | None = None


class ExplainerOutput(BaseModel):
    """Answer of the "explainer" role."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    hypotheses: list[Statement] = Field(default_factory=list)
    recommended_steps: list[Statement] = Field(default_factory=list)


class CorrelationGroup(BaseModel):
    """Findings the model attributes to the same incident."""

    model_config = ConfigDict(extra="forbid")

    title: str
    finding_ids: list[str] = Field(min_length=1)
    rationale: str
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: Confidence

    verified: bool = True
    verification_note: str | None = None


class CorrelatorOutput(BaseModel):
    """Answer of the "correlator" role."""

    model_config = ConfigDict(extra="forbid")

    incidents: list[CorrelationGroup] = Field(default_factory=list)


def json_schema_for(model: type[BaseModel]) -> dict[str, Any]:
    """JSON schema for the ``format`` field of the Ollama request.

    With a schema instead of ``format: "json"`` decoding is grammar-bound:
    schema violations become a marginal phenomenon. What remains is valid JSON
    with wrong content - and that is exactly what ``verify.py`` works against.
    """
    schema = model.model_json_schema()
    # The fields set by the verification are not part of the contract with the
    # model.
    for name in ("verified", "verification_note"):
        _strip_property(schema, name)
    return schema


def _strip_property(schema: dict[str, Any], name: str) -> None:
    for definition in list(schema.get("$defs", {}).values()) + [schema]:
        properties = definition.get("properties")
        if isinstance(properties, dict):
            properties.pop(name, None)
        required = definition.get("required")
        if isinstance(required, list) and name in required:
            required.remove(name)
