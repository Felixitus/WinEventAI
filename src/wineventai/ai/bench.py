"""Acceptance test for the model choice: ``wineventai ai bench``.

Until 2.0 the default model was a guess. This module replaces the guess by a
measurement - and it measures what the report will show, not what a prompt
written for a test would show: the fixed scenarios in ``ai/bench_cases.yaml``
go through enrich, rules, redaction, bundle building, the explainer and
correlator calls and the evidence check of ``AiLayer`` unchanged.

The criteria, in this order (HANDOVER, model choice):

1. Context length: the model must SUPPORT ``min_context_length``. Read from
   ``/api/show``; a model that does not report it fails, because "unknown" is
   not "large enough".
2. Valid structured output: every finding must get a schema-valid answer
   (after the one retry the pipeline allows anyway).
3. Evidence: the share of statements the evidence check rejects must stay at
   or below ``max_rejected_share``. A model that answers with NO statement at
   all fails as well - it would evade the check instead of passing it.
4. English: the answers must be English. Measured by a deliberately simple
   stop-word count; it tells English from German and from "something else",
   nothing more, and the report calls it a heuristic.
5. Only then speed. GPU offload is reported, not judged: a model that does
   not fit completely into video memory works, it is just slow.

The bench changes nothing. It recommends a model and prints the line for the
configuration; whether to take it is the user's decision.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ..config import AiConfig
from ..enrich.aggregate import Enricher
from ..normalize.schema import EventRecord
from ..resources import data_dir, read_resource_text
from ..rules.engine import Finding, RuleEngine
from ..rules.loader import load_rules
from .bundles import SystemContext
from .client import CLOUD_TAG_SUFFIXES, CloudCallBlockedError, OllamaClient
from .pipeline import AiLayer
from .redaction import Redactor

CASES_RESOURCE = "ai/bench_cases.yaml"

BenchStatus = Literal["passed", "failed", "not tested"]
Language = Literal["en", "de", "unclear"]

#: Function words that occur in almost every sentence of their language and
#: hardly ever in the other one. "in" and "so" are missing on purpose: they
#: are words in both languages.
_ENGLISH_WORDS = frozenset({
    "the", "and", "is", "are", "was", "were", "of", "to", "that", "this", "with",
    "not", "be", "or", "on", "for", "by", "it", "an", "as", "from", "which", "has",
    "have",
})
_GERMAN_WORDS = frozenset({
    "der", "die", "das", "und", "ist", "sind", "war", "nicht", "ein", "eine", "einen",
    "mit", "von", "zu", "den", "dem", "des", "auf", "wurde", "wurden", "fuer", "oder",
    "auch", "sich",
})
_WORD = re.compile(r"[a-zA-Zäöüß]+")


# --- Scenarios -----------------------------------------------------------------


class BenchEvent(BaseModel):
    """One event of a scenario, time given relative to the scenario end."""

    model_config = ConfigDict(extra="forbid")

    seconds_before: int = Field(ge=0)
    channel: str
    provider: str
    event_id: int
    level: int
    message: str
    properties: list[str] = Field(default_factory=list)


class BenchScenario(BaseModel):
    """A fixed event stream that the model has to explain."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    host: str
    events: list[BenchEvent] = Field(min_length=1)


class BenchCases(BaseModel):
    model_config = ConfigDict(extra="forbid")

    end_utc: datetime
    scenarios: list[BenchScenario] = Field(min_length=1)


def load_cases(text: str | None = None) -> BenchCases:
    """Loads the bundled scenarios, or the given YAML text in tests."""
    payload = yaml.safe_load(text if text is not None else read_resource_text(CASES_RESOURCE))
    return BenchCases.model_validate(payload)


def scenario_records(scenario: BenchScenario, end_utc: datetime) -> list[EventRecord]:
    """Builds the event records of a scenario - descending, like a real stream.

    The enricher relies on the descending order (context before a crash is
    collected by forward buffering), so the bench must not hand it anything
    else.
    """
    records = [
        EventRecord(
            timestamp_utc=end_utc - timedelta(seconds=event.seconds_before),
            channel=event.channel,
            provider=event.provider,
            event_id=event.event_id,
            event_version=0,
            level=event.level,
            computer=scenario.host,
            message=event.message,
            properties=list(event.properties),
            raw_hash=f"bench-{scenario.id}-{index}",
            source_tool="bench",
            source_ref=event.channel,
        )
        for index, event in enumerate(scenario.events)
    ]
    return sorted(records, key=lambda record: record.timestamp_utc, reverse=True)


def scenario_findings(scenario: BenchScenario, end_utc: datetime) -> list[Finding]:
    """Runs a scenario through enrich and the bundled rules - no model involved."""
    engine = RuleEngine(load_rules())
    enrichment = Enricher(window_hours=168).consume(scenario_records(scenario, end_utc))
    return [finding for finding in engine.evaluate(enrichment) if not finding.suppressed]


# --- Results -------------------------------------------------------------------


class ScenarioResult(BaseModel):
    """What one model made of one scenario."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    title: str
    findings_total: int = 0
    findings_answered: int = 0
    statements_total: int = 0
    statements_rejected: int = 0
    invented_event_ids: list[int] = Field(default_factory=list)
    correlation_checked: bool = False
    correlation_rejected: int = 0
    duration_seconds: float = 0.0
    notes: list[str] = Field(default_factory=list)
    #: The answers themselves. Read them: the language heuristic says English
    #: or not, it does not say whether the English is useful.
    answers: list[dict[str, Any]] = Field(default_factory=list)


class ModelBenchResult(BaseModel):
    """Verdict for one model, with the reasons behind it."""

    model_config = ConfigDict(extra="forbid")

    model: str
    status: BenchStatus
    reasons: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    context_length: int | None = None
    parameter_size: str | None = None
    quantization: str | None = None
    gpu_share: float | None = None
    language: Language | None = None
    statements_total: int = 0
    statements_rejected: int = 0
    duration_seconds: float = 0.0
    scenarios: list[ScenarioResult] = Field(default_factory=list)

    @property
    def rejected_share(self) -> float | None:
        if self.statements_total == 0:
            return None
        return self.statements_rejected / self.statements_total


class BenchReport(BaseModel):
    """Overall result. Written as JSON next to the configuration."""

    model_config = ConfigDict(extra="forbid")

    created_utc: datetime
    base_url: str
    num_ctx: int
    min_context_length: int
    max_rejected_share: float
    results: list[ModelBenchResult] = Field(default_factory=list)
    recommended_model: str | None = None
    recommendation: str = ""


# --- Measurements --------------------------------------------------------------


def detect_language(text: str) -> Language:
    """English, German or unclear - by counting function words.

    Deliberately crude, and called a heuristic wherever it is shown. It only
    has to catch the two failures that matter here: a model that falls back to
    German because the event messages were German, and a model that answers in
    a third language. Both end up as "not en".
    """
    words = [word.lower() for word in _WORD.findall(text)]
    english = sum(1 for word in words if word in _ENGLISH_WORDS)
    german = sum(1 for word in words if word in _GERMAN_WORDS)
    if english >= 3 and english >= 2 * german:
        return "en"
    if german >= 3 and german >= 2 * english:
        return "de"
    return "unclear"


def _answer_text(answers: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for answer in answers:
        parts.append(str(answer.get("summary", "")))
        for key in ("hypotheses", "recommended_steps"):
            for statement in answer.get(key) or []:
                parts.append(str(statement.get("statement", "")))
    return " ".join(parts)


def _gpu_share(loaded: tuple[int, int] | None) -> float | None:
    if loaded is None:
        return None
    size, vram = loaded
    return min(1.0, max(0.0, vram / size)) if size else None


def run_scenario(
    layer: AiLayer, scenario: BenchScenario, end_utc: datetime
) -> ScenarioResult:
    """Runs one scenario through the AI layer and counts what the check found."""
    result = ScenarioResult(scenario_id=scenario.id, title=scenario.title)
    findings = scenario_findings(scenario, end_utc)
    result.findings_total = len(findings)
    if not findings:
        result.notes.append("The scenario produced no finding - the model was not asked.")
        return result

    context = SystemContext(
        host=layer.redactor.register_host(scenario.host),
        operating_system="Windows (bench scenario)",
        period_from_utc=(end_utc - timedelta(days=7)).isoformat(),
        period_to_utc=end_utc.isoformat(),
        boot_sessions=1,
    )
    started = time.monotonic()
    ai_result, _ = layer.run(findings, context)
    result.duration_seconds = round(time.monotonic() - started, 1)

    if not ai_result.used:
        result.notes.append(ai_result.unavailable_reason or "The AI layer was not used.")
        return result

    invented: set[int] = set()
    for entry in ai_result.findings:
        if not entry.ok or entry.explanation is None:
            result.notes.append(f"{entry.finding_id}: {entry.note or 'no valid answer'}")
            continue
        result.findings_answered += 1
        result.statements_total += entry.verification.statements_total
        result.statements_rejected += entry.verification.statements_rejected
        invented.update(entry.verification.invented_event_ids)
        result.notes.extend(entry.verification.rejected_reasons)
        result.answers.append(entry.explanation.model_dump(mode="json"))

    if ai_result.correlation is not None:
        result.correlation_checked = True
        result.correlation_rejected = ai_result.correlation_verification.statements_rejected
        result.notes.extend(ai_result.correlation_verification.rejected_reasons)
    elif len(findings) > 1:
        result.notes.extend(ai_result.correlation_verification.rejected_reasons)

    result.invented_event_ids = sorted(invented)
    return result


def judge(result: ModelBenchResult, config: AiConfig) -> ModelBenchResult:
    """Applies the acceptance thresholds. Every failed gate gets its sentence."""
    bench = config.bench
    reasons: list[str] = []

    if result.context_length is None:
        reasons.append(
            "Ollama does not report the context length - "
            f"at least {bench.min_context_length:,} cannot be confirmed."
        )
    elif result.context_length < bench.min_context_length:
        reasons.append(
            f"Context length {result.context_length:,} is below the required "
            f"{bench.min_context_length:,}."
        )

    findings_total = sum(entry.findings_total for entry in result.scenarios)
    answered = sum(entry.findings_answered for entry in result.scenarios)
    if answered < findings_total:
        reasons.append(
            f"No valid structured answer for {findings_total - answered} of "
            f"{findings_total} findings."
        )

    if answered and result.statements_total == 0:
        reasons.append(
            "The answers contain no statement at all - nothing could be checked "
            "against the evidence."
        )

    share = result.rejected_share
    if share is not None and share > bench.max_rejected_share:
        reasons.append(
            f"{share:.0%} of the statements were rejected by the evidence check "
            f"(allowed: {bench.max_rejected_share:.0%})."
        )

    if answered and result.language != "en":
        reasons.append(
            f"The answers are not English (heuristic result: {result.language})."
        )

    if result.gpu_share is not None and result.gpu_share < 0.999:
        result.notes.append(
            f"Only {result.gpu_share:.0%} of the model is in video memory - it works, "
            "but slowly."
        )
    elif result.gpu_share is None:
        result.notes.append("GPU offload not measured (Ollama did not list the model).")

    result.reasons = reasons
    result.status = "failed" if reasons else "passed"
    return result


def bench_model(
    model: str,
    config: AiConfig,
    cases: BenchCases,
    *,
    client_factory: Callable[[str], Any],
) -> ModelBenchResult:
    """Measures one model over all scenarios."""
    result = ModelBenchResult(model=model, status="not tested")
    try:
        client = client_factory(model)
    except CloudCallBlockedError as exc:
        result.reasons.append(str(exc))
        return result

    status = client.status()
    if not status.usable:
        result.reasons.append(status.message(config.base_url, model))
        return result

    details = client.model_details() or {}
    capabilities = details.get("capabilities")
    if isinstance(capabilities, list) and capabilities and "completion" not in capabilities:
        result.reasons.append(
            "The model cannot chat (capabilities: "
            + ", ".join(str(item) for item in capabilities)
            + ") - probably an embedding model."
        )
        return result

    info = details.get("details") or {}
    result.parameter_size = info.get("parameter_size") or None
    result.quantization = info.get("quantization_level") or None
    result.context_length = client.model_context_length()

    for scenario in cases.scenarios:
        layer = AiLayer(config, client=client, kb=None, redactor=Redactor(enabled=True))
        outcome = run_scenario(layer, scenario, cases.end_utc)
        result.scenarios.append(outcome)
        result.statements_total += outcome.statements_total
        result.statements_rejected += outcome.statements_rejected
        result.duration_seconds = round(result.duration_seconds + outcome.duration_seconds, 1)

    # Right after the last call the model is still loaded - only now does
    # /api/ps say how much of it sits in video memory.
    result.gpu_share = _gpu_share(client.loaded_size())
    text = _answer_text([answer for entry in result.scenarios for answer in entry.answers])
    result.language = detect_language(text) if text.strip() else None
    return judge(result, config)


def recommend(
    results: list[ModelBenchResult], *, tolerance: float = 0.1
) -> tuple[str | None, str]:
    """Picks the best passed model: reliable enough first, then speed.

    "Reliable enough" means a rejected share within ``tolerance`` of the best
    passed model. A strict "fewest rejections first" ranks noise: the scenarios
    yield a few dozen statements, and one rejection more decided against a
    model 8.5x faster in the first live run.

    Parameter count is deliberately not a criterion of its own: a larger model
    that is rejected more often is the worse choice for this tool.
    """
    passed = [entry for entry in results if entry.status == "passed"]
    if not passed:
        tested = [entry for entry in results if entry.status != "not tested"]
        if not tested:
            return None, (
                "No model could be tested. Without a model the report comes from the "
                "rule engine."
            )
        return None, (
            "No model passed. The report keeps working from the rule engine; for the "
            "language model either install another one or adjust 'ai.bench' "
            "deliberately."
        )
    lowest = min(entry.rejected_share or 0.0 for entry in passed)
    reliable = [
        entry for entry in passed if (entry.rejected_share or 0.0) <= lowest + tolerance + 1e-9
    ]
    best = min(reliable, key=lambda entry: (entry.duration_seconds, entry.rejected_share or 0.0))
    return best.model, f'Recommended: ai.model: "{best.model}"'


def default_models(probe: Any, *, allow_cloud: bool) -> list[str]:
    """All listed models - without cloud models unless they are allowed."""
    names = probe.list_models()
    if allow_cloud:
        return names
    return [name for name in names if not name.lower().endswith(CLOUD_TAG_SUFFIXES)]


def run_bench(
    config: AiConfig,
    models: list[str],
    *,
    cases: BenchCases | None = None,
    client_factory: Callable[[str], Any] | None = None,
    progress: Callable[[str], None] | None = None,
) -> BenchReport:
    """Runs the bench over the given models. Raises nothing for a failing model."""
    cases = cases or load_cases()

    def make_client(model: str) -> OllamaClient:
        return OllamaClient(
            base_url=config.base_url,
            model=model,
            temperature=config.temperature,
            num_ctx=config.num_ctx,
            timeout_seconds=config.bench.timeout_seconds,
            allow_cloud=config.allow_cloud,
        )

    factory = client_factory or make_client
    report = BenchReport(
        created_utc=datetime.now(UTC),
        base_url=config.base_url,
        num_ctx=config.num_ctx,
        min_context_length=config.bench.min_context_length,
        max_rejected_share=config.bench.max_rejected_share,
    )
    for model in models:
        if progress is not None:
            progress(model)
        report.results.append(bench_model(model, config, cases, client_factory=factory))
    report.recommended_model, report.recommendation = recommend(
        report.results, tolerance=config.bench.rejection_tolerance
    )
    return report


def default_output_path(now: datetime | None = None) -> Path:
    stamp = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H-%M-%SZ")
    return data_dir() / "bench" / f"bench-{stamp}.json"


def write_report(report: BenchReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def format_report(report: BenchReport) -> list[str]:
    """Console lines. "not tested" stays visibly different from "failed"."""
    lines = [
        f"Thresholds: context >= {report.min_context_length:,}, rejected <= "
        f"{report.max_rejected_share:.0%}, answers in English (heuristic)",
        "",
        f"{'Model':<34} {'Status':<11} {'Context':>8} {'Rejected':>9} {'GPU':>5} "
        f"{'Lang':>5} {'Time':>8}",
    ]
    for entry in report.results:
        share = entry.rejected_share
        lines.append(
            f"{entry.model:<34} {entry.status:<11} "
            f"{(f'{entry.context_length:,}' if entry.context_length else 'unknown'):>8} "
            f"{(f'{share:.0%}' if share is not None else '-'):>9} "
            f"{(f'{entry.gpu_share:.0%}' if entry.gpu_share is not None else '-'):>5} "
            f"{entry.language or '-':>5} "
            f"{(f'{entry.duration_seconds:.0f} s' if entry.duration_seconds else '-'):>8}"
        )
        for reason in entry.reasons:
            lines.append(f"    - {reason}")
        for note in entry.notes:
            lines.append(f"    note: {note}")
    lines.append("")
    lines.append(report.recommendation)
    return lines
