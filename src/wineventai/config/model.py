"""Konfigurationsmodell. Alle Stellschrauben liegen in YAML, keine im Code."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ChannelConfig(BaseModel):
    """Ein zu erhebender Ereigniskanal."""

    model_config = ConfigDict(extra="forbid")

    name: str
    enabled: bool = True
    days: int | None = Field(
        default=None,
        description="Eigenes Zeitfenster in Tagen; None erbt das globale Fenster.",
    )
    event_ids: list[int] = Field(
        default_factory=list,
        description="Serverseitiger ID-Filter. Leer heisst: ganzer Kanal im Zeitfenster.",
    )
    requires_admin: bool = False
    with_xml: bool = Field(
        default=False,
        description="Event-XML mitschreiben. Teuer, nur wo EventData gebraucht wird.",
    )
    max_retained: int | None = Field(
        default=None,
        description="Eigene Obergrenze fuer behaltene Rohdaten; None erbt den globalen Wert.",
    )


#: Kanaltypen, die Get-WinEvent ohne Sonderbehandlung lesen kann. Analytic- und
#: Debug-Kanaele sind Ablaufprotokolle: meist abgeschaltet, und wenn aktiv, dann
#: nur vorwaerts lesbar - fuer eine Fehlersuche ueber ein Zeitfenster ungeeignet.
SWEEP_LOG_TYPES = ("Administrative", "Operational", "Analytic", "Debug")


class ErrorSweepConfig(BaseModel):
    """Fehler-Sweep: alle aktiven Kanaele, aber nur Kritisch und Fehler.

    Die Kanalliste unter ``channels`` deckt die Kernkanaele vollstaendig ab. Der
    Sweep ergaenzt den Rest des Systems - die mehreren hundert Kanaele, in denen
    Treiber und Komponenten ihre Abstuerze ablegen, ohne dass jemand sie
    einzeln kennt. Gefiltert wird ueber den numerischen Level, nie ueber
    ``LevelDisplayName``: Der ist lokalisiert.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    levels: list[int] = Field(
        default_factory=lambda: [1, 2],
        description="1 = Kritisch, 2 = Fehler, 3 = Warnung. 0 (LogAlways) ist kein Schweregrad.",
    )
    log_types: list[str] = Field(
        default_factory=lambda: ["Administrative", "Operational"],
        description="Welche Kanaltypen der Sweep beruecksichtigt.",
    )
    exclude: list[str] = Field(
        default_factory=list,
        description=(
            "Zusaetzlich auszulassende Kanaele. Die unter 'channels' konfigurierten "
            "Kanaele werden immer ausgelassen, damit nichts doppelt zaehlt."
        ),
    )
    days: int | None = Field(
        default=None,
        description="Eigenes Zeitfenster in Tagen; None erbt das globale Fenster.",
    )
    max_retained_per_channel: int = Field(
        default=5_000,
        ge=1,
        description="Obergrenze BEHALTENER Records je Sweep-Kanal. Gezaehlt wird immer alles.",
    )
    timeout_seconds: float = Field(
        default=600.0,
        gt=0,
        description="Wall-Clock fuer den gesamten Sweep, nicht je Kanal.",
    )

    @field_validator("levels")
    @classmethod
    def _known_levels(cls, value: list[int]) -> list[int]:
        if not value:
            raise ValueError("levels darf nicht leer sein - dann den Sweep abschalten")
        unknown = [level for level in value if level not in {1, 2, 3, 4, 5}]
        if unknown:
            raise ValueError(f"unbekannte Level: {unknown}; erlaubt sind 1 bis 5")
        return sorted(set(value))

    @field_validator("log_types")
    @classmethod
    def _known_log_types(cls, value: list[str]) -> list[str]:
        unknown = [entry for entry in value if entry not in SWEEP_LOG_TYPES]
        if unknown:
            raise ValueError(
                f"unbekannte Kanaltypen: {unknown}; erlaubt: {', '.join(SWEEP_LOG_TYPES)}"
            )
        return value


class CollectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    days: int = 7
    channels: list[ChannelConfig] = Field(default_factory=list)
    error_sweep: ErrorSweepConfig = Field(default_factory=ErrorSweepConfig)
    max_retained_per_channel: int = 200_000
    abort_above_records: int = 5_000_000
    channel_timeout_seconds: float = 120.0
    powershell_preference: list[str] = Field(default_factory=lambda: ["pwsh", "powershell"])
    xml_for: list[str] = Field(
        default_factory=list,
        description="Provider/ID-Paare als 'Provider:ID', fuer die das Event-XML geholt wird.",
    )
    reliability_records: bool = True
    wer_reports: bool = True
    minidump_listing: bool = True
    log_files: bool = False
    disk_health: bool = False
    inventory: bool = False


class EnrichConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    burst_factor: float = 5.0
    burst_min_count: int = 10
    context_window_minutes: int = 5
    context_max_events: int = 60
    samples_per_group: int = 3
    retention_error_share: float = Field(default=0.6, ge=0.0, le=1.0)
    sampling_seed: int = 1701


class RulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overlay_dir: str | None = None
    suppress_noise: bool = True
    security_mode: bool = False


class AiConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    base_url: str = "http://localhost:11434"
    model: str = "qwen2.5:14b-instruct"
    temperature: float = 0.1
    num_ctx: int = 16384
    timeout_seconds: float = 180.0
    max_bundle_tokens: int = 6000
    chars_per_token: float = 3.2
    max_samples_per_finding: int = 3
    message_excerpt_chars: int = 400
    allow_cloud: bool = Field(
        default=False,
        description="Ausdrueckliches Opt-in. Ohne diesen Schalter wird nur localhost akzeptiert.",
    )
    redact: bool = True

    @field_validator("temperature")
    @classmethod
    def _low_temperature(cls, value: float) -> float:
        if value > 1.0:
            raise ValueError("temperature ueber 1.0 ist fuer Diagnosetexte nicht sinnvoll")
        return value


class ProbesConfig(BaseModel):
    """Kontext-Sonden: messen den aktuellen Zustand zu einem Befund.

    Sonden laufen nur auf dem Rechner, von dem der Lauf stammt, und nur im
    lokalen Netz. Es gibt bewusst keinen Schalter fuer einen Internet-Speedtest:
    Der braeche "offline lauffaehig", "keine Telemetrie" (die eigene IP ginge an
    den Anbieter) und "read-only" gleichzeitig - er saettigt die Leitung und
    erzeugt auf einem gestoerten Rechner genau die Stoerung, die man sucht.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    network: bool = True
    services: bool = True
    storage: bool = True
    timeout_seconds: float = Field(
        default=30.0, description="Obergrenze je Sondenaufruf, nicht je Ziel."
    )
    ping_count: int = Field(default=3, ge=1, le=10)
    ping_timeout_ms: int = Field(default=1500, ge=100, le=10_000)


class ReportConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    formats: list[str] = Field(default_factory=lambda: ["html", "md", "json"])
    redacted: bool = False
    raw_appendix_limit: int = 200
    title: str = "WinEventAI Diagnosebericht"


class Config(BaseModel):
    """Vollstaendige Konfiguration eines Laufs."""

    model_config = ConfigDict(extra="forbid")

    collect: CollectConfig = Field(default_factory=CollectConfig)
    enrich: EnrichConfig = Field(default_factory=EnrichConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    ai: AiConfig = Field(default_factory=AiConfig)
    probes: ProbesConfig = Field(default_factory=ProbesConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    log_level: str = "info"

    def channel(self, name: str) -> ChannelConfig | None:
        for entry in self.collect.channels:
            if entry.name.lower() == name.lower():
                return entry
        return None
