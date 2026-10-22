"""Ein- und Ausgabeschema des KI-Layers.

Die Belege sind ein STRUKTURIERTES Feld, nicht Prosa. Nur so ist die Vorgabe
"jede Modellaussage verweist auf konkrete Event-IDs und Zeitstempel" maschinell
pruefbar. Wer die Belege aus dem Fliesstext kratzen muss, prueft am Ende seinen
eigenen regulaeren Ausdruck und nicht das Modell.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Confidence = Literal["hoch", "mittel", "niedrig", "unklar"]


class Evidence(BaseModel):
    """Ein Beleg: genau ein Ereignis aus dem Eingabebuendel."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    event_id: int
    timestamp_utc: datetime


class Statement(BaseModel):
    """Eine einzelne Aussage des Modells mit Belegen und Sicherheitsangabe."""

    model_config = ConfigDict(extra="forbid")

    aussage: str
    evidence: list[Evidence] = Field(min_length=1)
    confidence: Confidence

    # Wird von der Nachpruefung gesetzt, nicht vom Modell.
    verified: bool = True
    verification_note: str | None = None


class ExplainerOutput(BaseModel):
    """Antwort der Rolle "Erklaerer"."""

    model_config = ConfigDict(extra="forbid")

    zusammenfassung: str
    hypothesen: list[Statement] = Field(default_factory=list)
    empfohlene_schritte: list[Statement] = Field(default_factory=list)


class CorrelationGroup(BaseModel):
    """Befunde, die das Modell demselben Vorfall zuordnet."""

    model_config = ConfigDict(extra="forbid")

    titel: str
    befund_ids: list[str] = Field(min_length=1)
    begruendung: str
    evidence: list[Evidence] = Field(default_factory=list)
    confidence: Confidence

    verified: bool = True
    verification_note: str | None = None


class CorrelatorOutput(BaseModel):
    """Antwort der Rolle "Korrelator"."""

    model_config = ConfigDict(extra="forbid")

    vorfaelle: list[CorrelationGroup] = Field(default_factory=list)


def json_schema_for(model: type[BaseModel]) -> dict[str, Any]:
    """JSON-Schema fuer das ``format``-Feld der Ollama-Anfrage.

    Mit einem Schema statt ``format: "json"`` ist die Dekodierung
    grammatikgebunden: Schemaverstoesse werden zur Randerscheinung. Was bleibt,
    ist gueltiges JSON mit falschem Inhalt - und genau dagegen arbeitet
    ``verify.py``.
    """
    schema = model.model_json_schema()
    # Die von der Nachpruefung gesetzten Felder gehoeren nicht in den Vertrag
    # mit dem Modell.
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
