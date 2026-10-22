"""Streaming-Aggregation: der eigentliche Enricher.

Ein einziger Durchlauf ueber den absteigend zusammengefuehrten Strom erledigt
alles: Fingerprint, Zaehler, Histogramm, Boot-Session, Kontextfenster und
Retention. Das ist Voraussetzung dafuer, dass der Speicherbedarf an der Zahl
verschiedener Fingerprints haengt und nicht an der Zahl der Events.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from ..normalize.schema import EventRecord, level_label
from .boot import BootSession, BootTracker
from .burst import Burst, detect_bursts, hour_key
from .correlate import ContextCollector, ContextWindow
from .fingerprint import fingerprint_for
from .retention import Priority, RetentionReservoir


class FingerprintGroup(BaseModel):
    """Alle Vorkommen eines Fingerprints, verdichtet."""

    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    provider: str
    event_id: int
    channel: str
    level: int
    count: int = 0
    first_seen_utc: datetime
    last_seen_utc: datetime
    hourly: dict[str, int] = Field(default_factory=dict)
    boot_sessions: dict[int, int] = Field(default_factory=dict)
    samples: list[EventRecord] = Field(default_factory=list)
    computers: set[str] = Field(default_factory=set)
    bursts: list[Burst] = Field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.provider}:{self.event_id}"

    @property
    def level_label(self) -> str:
        return level_label(self.level)

    @property
    def distinct_computers(self) -> int:
        return len(self.computers)

    def to_public_dict(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "provider": self.provider,
            "event_id": self.event_id,
            "kanal": self.channel,
            "level": self.level,
            "level_text": self.level_label,
            "anzahl": self.count,
            "erstes_vorkommen_utc": self.first_seen_utc.isoformat(),
            "letztes_vorkommen_utc": self.last_seen_utc.isoformat(),
            "bursts": [burst.model_dump(mode="json") for burst in self.bursts],
            "boot_sitzungen": {str(k): v for k, v in sorted(self.boot_sessions.items())},
            "beispiele": [record.to_public_dict() for record in self.samples],
        }


class EnrichmentResult(BaseModel):
    """Was der Enricher aus einem Lauf herausholt."""

    model_config = ConfigDict(extra="forbid")

    groups: list[FingerprintGroup] = Field(default_factory=list)
    boot_sessions: list[BootSession] = Field(default_factory=list)
    context_windows: list[ContextWindow] = Field(default_factory=list)
    retained: list[EventRecord] = Field(default_factory=list)
    retention_stats: dict[str, int] = Field(default_factory=dict)
    total_events: int = 0
    truncated: bool = False

    @property
    def reduction_rate(self) -> float:
        """Anteil, um den die Deduplizierung die Menge verkleinert hat."""
        if not self.total_events:
            return 0.0
        return 1.0 - (len(self.groups) / self.total_events)

    def group_by_fingerprint(self, fingerprint: str) -> FingerprintGroup | None:
        for group in self.groups:
            if group.fingerprint == fingerprint:
                return group
        return None


class Enricher:
    """Verdichtet einen Event-Strom in einem Durchlauf."""

    def __init__(
        self,
        *,
        samples_per_group: int = 3,
        burst_factor: float = 5.0,
        burst_min_count: int = 10,
        context_window_minutes: int = 5,
        context_max_events: int = 60,
        window_hours: float | None = None,
        retention_limit: int = 200_000,
        retention_error_share: float = 0.6,
        seed: int = 1701,
        rule_keys: Iterable[tuple[str, int]] | None = None,
    ) -> None:
        self.samples_per_group = samples_per_group
        self.burst_factor = burst_factor
        self.burst_min_count = burst_min_count
        self.window_hours = window_hours
        self.rule_keys = set(rule_keys or ())
        self._groups: dict[str, FingerprintGroup] = {}
        self._boot = BootTracker()
        self._context = ContextCollector(
            window_minutes=context_window_minutes, max_events=context_max_events
        )
        self._reservoir = RetentionReservoir(
            limit=retention_limit, error_share=retention_error_share, seed=seed
        )
        self._total = 0

    def _priority(self, record: EventRecord, is_context: bool) -> Priority:
        if (record.provider, record.event_id) in self.rule_keys:
            return Priority.RULE_HIT
        if is_context:
            return Priority.CONTEXT
        if record.level <= 2:
            return Priority.ERROR_LEVEL
        return Priority.OTHER

    def feed(self, record: EventRecord) -> None:
        """Nimmt einen Record aus dem absteigenden Gesamtstrom auf."""
        self._total += 1

        fingerprint = fingerprint_for(record)
        record.fingerprint = fingerprint
        session_index = self._boot.observe(record)
        record.boot_session = session_index

        is_context = self._context.observe(record)
        self._reservoir.offer(record, self._priority(record, is_context))

        group = self._groups.get(fingerprint)
        if group is None:
            group = FingerprintGroup(
                fingerprint=fingerprint,
                provider=record.provider,
                event_id=record.event_id,
                channel=record.channel,
                level=record.level,
                first_seen_utc=record.timestamp_utc,
                last_seen_utc=record.timestamp_utc,
            )
            self._groups[fingerprint] = group

        group.count += 1
        # Absteigender Strom: der erste gesehene Record ist der spaeteste.
        if record.timestamp_utc > group.last_seen_utc:
            group.last_seen_utc = record.timestamp_utc
        if record.timestamp_utc < group.first_seen_utc:
            group.first_seen_utc = record.timestamp_utc
        group.hourly[hour_key(record.timestamp_utc)] = (
            group.hourly.get(hour_key(record.timestamp_utc), 0) + 1
        )
        group.boot_sessions[session_index] = group.boot_sessions.get(session_index, 0) + 1
        if record.computer:
            group.computers.add(record.computer)
        if len(group.samples) < self.samples_per_group:
            group.samples.append(record)
        # Die niedrigste (schwerste) beobachtete Stufe gewinnt.
        group.level = min(group.level, record.level)

    def consume(self, records: Iterable[EventRecord]) -> EnrichmentResult:
        for record in records:
            self.feed(record)
        return self.finish()

    def finish(self) -> EnrichmentResult:
        for group in self._groups.values():
            group.bursts = detect_bursts(
                group.hourly,
                factor=self.burst_factor,
                min_count=self.burst_min_count,
                window_hours=self.window_hours,
            )

        groups = sorted(
            self._groups.values(),
            key=lambda group: (group.level, -group.count, group.provider, group.event_id),
        )
        return EnrichmentResult(
            groups=groups,
            boot_sessions=self._boot.finish(),
            context_windows=self._context.finish(),
            retained=self._reservoir.records(),
            retention_stats=self._reservoir.stats(),
            total_events=self._total,
            truncated=self._reservoir.truncated,
        )
