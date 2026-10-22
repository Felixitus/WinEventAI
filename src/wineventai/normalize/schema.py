"""Einheitliches Event-Schema.

Grundsatz: Gespeichert wird, was sprachneutral ist. Windows uebersetzt
``LevelDisplayName``, ``TaskDisplayName``, ``OpcodeDisplayName`` und
``KeywordsDisplayNames``; auf gemischten deutschen und englischen Systemen sind
diese Felder als Matching-Grundlage unbrauchbar. Deshalb steht hier ueberall der
numerische Wert, und der Anzeigename ist optionales Beiwerk fuer den Bericht.
"""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Level(IntEnum):
    """Numerische Schweregrade des Windows-Ereignisprotokolls."""

    LOG_ALWAYS = 0
    CRITICAL = 1
    ERROR = 2
    WARNING = 3
    INFORMATION = 4
    VERBOSE = 5


LEVEL_LABEL_DE: dict[int, str] = {
    0: "immer",
    1: "kritisch",
    2: "fehler",
    3: "warnung",
    4: "information",
    5: "ausfuehrlich",
}


def level_label(value: int | None) -> str:
    """Deutsche Bezeichnung eines numerischen Level-Werts."""
    if value is None:
        return "unbekannt"
    return LEVEL_LABEL_DE.get(int(value), f"stufe {value}")


class EventRecord(BaseModel):
    """Ein normalisiertes Ereignis, unabhaengig von der Quelle."""

    model_config = ConfigDict(extra="forbid")

    timestamp_utc: datetime
    channel: str
    provider: str
    event_id: int
    event_version: int | None = None
    level: int = Level.INFORMATION
    task: int | None = None
    opcode: int | None = None
    keywords: int | None = Field(default=None, description="Bitmaske, nicht die Anzeigenamen.")
    computer: str = ""
    user_sid: str | None = None
    record_id: int | None = Field(
        default=None, description="Zeiger in das Original-.evtx, fuer die Evidenzkette."
    )
    process_id: int | None = None
    thread_id: int | None = None
    message: str | None = Field(default=None, description="Lokalisiert. Kann fehlen.")
    properties: list[str | None] = Field(
        default_factory=list, description="Positionale EventData-Werte, sprachneutral."
    )
    event_data: dict[str, str] | None = Field(
        default=None, description="Benannte EventData-Felder; nur wenn XML angefordert wurde."
    )
    raw_hash: str = ""
    source_tool: str = ""
    source_ref: str = ""

    # Wird vom Enricher gesetzt, nicht vom Collector.
    fingerprint: str | None = None
    boot_session: int | None = None

    @property
    def level_label(self) -> str:
        return level_label(self.level)

    @property
    def key(self) -> str:
        """Provider und ID als ein Schluessel. Event-IDs sind nur je Provider eindeutig."""
        return f"{self.provider}:{self.event_id}"

    def excerpt(self, limit: int) -> str:
        """Gekuerzte Meldung fuer Prompt und Bericht."""
        text = " ".join((self.message or "").split())
        if len(text) <= limit:
            return text
        return text[: limit - 1].rstrip() + "…"

    def data_value(self, name: str) -> str | None:
        """Benanntes EventData-Feld, falls das XML geholt wurde."""
        if not self.event_data:
            return None
        for key, value in self.event_data.items():
            if key.lower() == name.lower():
                return value
        return None

    def property_at(self, index: int) -> str | None:
        if 0 <= index < len(self.properties):
            return self.properties[index]
        return None

    def to_public_dict(self) -> dict[str, Any]:
        """Kompakte Darstellung fuer Bericht und JSON-Ausgabe."""
        return {
            "zeit_utc": self.timestamp_utc.isoformat(),
            "kanal": self.channel,
            "provider": self.provider,
            "event_id": self.event_id,
            "level": self.level,
            "level_text": self.level_label,
            "computer": self.computer,
            "record_id": self.record_id,
            "meldung": self.message,
        }
