"""Uniform event schema.

Principle: store what is language-neutral. Windows translates
``LevelDisplayName``, ``TaskDisplayName``, ``OpcodeDisplayName`` and
``KeywordsDisplayNames``; on mixed German and English systems these fields are
useless for matching. The numeric value is therefore used everywhere here, and
the display name is optional decoration for the report.
"""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Level(IntEnum):
    """Numeric severity levels of the Windows event log."""

    LOG_ALWAYS = 0
    CRITICAL = 1
    ERROR = 2
    WARNING = 3
    INFORMATION = 4
    VERBOSE = 5


LEVEL_LABEL: dict[int, str] = {
    0: "always",
    1: "critical",
    2: "error",
    3: "warning",
    4: "information",
    5: "verbose",
}


def level_label(value: int | None) -> str:
    """Label of a numeric level value."""
    if value is None:
        return "unknown"
    return LEVEL_LABEL.get(int(value), f"level {value}")


class EventRecord(BaseModel):
    """A normalized event, independent of its source."""

    model_config = ConfigDict(extra="forbid")

    timestamp_utc: datetime
    channel: str
    provider: str
    event_id: int
    event_version: int | None = None
    level: int = Level.INFORMATION
    task: int | None = None
    opcode: int | None = None
    keywords: int | None = Field(default=None, description="Bit mask, not the display names.")
    computer: str = ""
    user_sid: str | None = None
    record_id: int | None = Field(
        default=None, description="Pointer into the original .evtx, for the chain of evidence."
    )
    process_id: int | None = None
    thread_id: int | None = None
    message: str | None = Field(default=None, description="Localized. May be missing.")
    properties: list[str | None] = Field(
        default_factory=list, description="Positional EventData values, language-neutral."
    )
    event_data: dict[str, str] | None = Field(
        default=None, description="Named EventData fields; only if XML was requested."
    )
    raw_hash: str = ""
    source_tool: str = ""
    source_ref: str = ""

    # Set by the enricher, not by the collector.
    fingerprint: str | None = None
    boot_session: int | None = None

    @property
    def level_label(self) -> str:
        return level_label(self.level)

    @property
    def key(self) -> str:
        """Provider and id as one key. Event ids are only unique per provider."""
        return f"{self.provider}:{self.event_id}"

    def excerpt(self, limit: int) -> str:
        """Shortened message for prompt and report."""
        text = " ".join((self.message or "").split())
        if len(text) <= limit:
            return text
        return text[: limit - 1].rstrip() + "…"

    def data_value(self, name: str) -> str | None:
        """Named EventData field, if the XML was fetched."""
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
        """Compact representation for report and JSON output."""
        return {
            "time_utc": self.timestamp_utc.isoformat(),
            "channel": self.channel,
            "provider": self.provider,
            "event_id": self.event_id,
            "level": self.level,
            "level_text": self.level_label,
            "computer": self.computer,
            "record_id": self.record_id,
            "message": self.message,
        }
