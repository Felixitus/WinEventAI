"""Configuration model. Every tuning knob lives in YAML, none in the code."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ChannelConfig(BaseModel):
    """An event channel to collect."""

    model_config = ConfigDict(extra="forbid")

    name: str
    enabled: bool = True
    days: int | None = Field(
        default=None,
        description="Own time window in days; None inherits the global window.",
    )
    event_ids: list[int] = Field(
        default_factory=list,
        description="Server-side id filter. Empty means: whole channel in the time window.",
    )
    requires_admin: bool = False
    with_xml: bool = Field(
        default=False,
        description="Also store the event XML. Expensive; only where EventData is needed.",
    )
    max_retained: int | None = Field(
        default=None,
        description="Own upper limit for retained raw data; None inherits the global value.",
    )


#: Channel types Get-WinEvent can read without special treatment. Analytic and
#: Debug channels are trace logs: usually disabled, and when active, readable
#: only forward - unsuitable for searching errors over a time window.
SWEEP_LOG_TYPES = ("Administrative", "Operational", "Analytic", "Debug")


class ErrorSweepConfig(BaseModel):
    """Error sweep: every active channel, but only critical and error.

    The channel list under ``channels`` covers the core channels completely.
    The sweep adds the rest of the system - the several hundred channels in
    which drivers and components record their crashes without anyone knowing
    them individually. Filtering uses the numeric level, never
    ``LevelDisplayName``: that is localized.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    levels: list[int] = Field(
        default_factory=lambda: [1, 2],
        description="1 = critical, 2 = error, 3 = warning. 0 (LogAlways) is not a severity.",
    )
    log_types: list[str] = Field(
        default_factory=lambda: ["Administrative", "Operational"],
        description="Which channel types the sweep considers.",
    )
    exclude: list[str] = Field(
        default_factory=list,
        description=(
            "Additional channels to skip. The channels configured under 'channels' "
            "are always skipped so nothing is counted twice."
        ),
    )
    days: int | None = Field(
        default=None,
        description="Own time window in days; None inherits the global window.",
    )
    max_retained_per_channel: int = Field(
        default=5_000,
        ge=1,
        description="Upper limit of RETAINED records per sweep channel. Everything is counted.",
    )
    timeout_seconds: float = Field(
        default=600.0,
        gt=0,
        description="Wall clock for the whole sweep, not per channel.",
    )

    @field_validator("levels")
    @classmethod
    def _known_levels(cls, value: list[int]) -> list[int]:
        if not value:
            raise ValueError("levels must not be empty - disable the sweep instead")
        unknown = [level for level in value if level not in {1, 2, 3, 4, 5}]
        if unknown:
            raise ValueError(f"unknown levels: {unknown}; allowed are 1 to 5")
        return sorted(set(value))

    @field_validator("log_types")
    @classmethod
    def _known_log_types(cls, value: list[str]) -> list[str]:
        unknown = [entry for entry in value if entry not in SWEEP_LOG_TYPES]
        if unknown:
            raise ValueError(
                f"unknown channel types: {unknown}; allowed: {', '.join(SWEEP_LOG_TYPES)}"
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
        description="Provider/id pairs as 'Provider:ID' for which the event XML is fetched.",
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


class AiBenchConfig(BaseModel):
    """Acceptance thresholds of ``wineventai ai bench``.

    In the configuration and not in the code, because they are a judgement
    call: whoever accepts more rejected statements for a faster model should
    say so in a file, not in a patch.
    """

    model_config = ConfigDict(extra="forbid")

    #: The model must SUPPORT at least this context, not use it. Below 32k the
    #: split bundles of a busy machine no longer fit with system prompt and
    #: answer.
    min_context_length: int = 32768
    #: Share of statements the evidence check may reject. Above that the
    #: report shows more rejection notes than explanations.
    max_rejected_share: float = Field(default=0.2, ge=0.0, le=1.0)
    #: Passed models whose rejected share is within this distance of the best
    #: one count as equally reliable; among them the fastest is recommended.
    #: The scenarios yield a few dozen statements - one rejection more is
    #: noise, a factor of eight in run time is not. Found by the first live
    #: run: 0/17 vs. 1/16 rejected would otherwise have picked a model that
    #: was 8.5x slower and gave vaguer answers.
    rejection_tolerance: float = Field(default=0.1, ge=0.0, le=1.0)
    #: Separate from ai.timeout_seconds: the first call also loads the model,
    #: which takes minutes for a 30B model from a hard disk.
    timeout_seconds: float = 600.0

    @field_validator("min_context_length")
    @classmethod
    def _positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("min_context_length must be positive")
        return value


class AiConfig(BaseModel):
    """The optional language model layer.

    Everything works without it: the report is built from the rule engine, and
    the AI only explains what the rules already found. ``enabled: true`` with
    an unreachable Ollama is a normal state, not an error.
    """

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
        description=(
            "Explicit opt-in. Without it only localhost is accepted, and models that "
            "Ollama forwards to a remote service are refused."
        ),
    )
    redact: bool = True
    bench: AiBenchConfig = Field(default_factory=AiBenchConfig)

    @field_validator("temperature")
    @classmethod
    def _low_temperature(cls, value: float) -> float:
        if value > 1.0:
            raise ValueError("a temperature above 1.0 makes no sense for diagnostic text")
        return value


class ProbesConfig(BaseModel):
    """Context probes: measure the current state related to a finding.

    Probes only run on the machine the run came from, and only within the local
    network. There is deliberately no switch for an internet speed test: it
    would break "works offline", "no telemetry" (the own IP would go to the
    provider) and "read-only" at the same time - it saturates the line and
    produces on a troubled machine exactly the disturbance one is looking for.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    network: bool = True
    services: bool = True
    storage: bool = True
    timeout_seconds: float = Field(
        default=30.0, description="Upper limit per probe call, not per target."
    )
    ping_count: int = Field(default=3, ge=1, le=10)
    ping_timeout_ms: int = Field(default=1500, ge=100, le=10_000)


class ReportConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    formats: list[str] = Field(default_factory=lambda: ["html", "md", "json"])
    redacted: bool = False
    raw_appendix_limit: int = 200
    title: str = "WinEventAI diagnostic report"


class Config(BaseModel):
    """Complete configuration of a run."""

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
