"""Flow of the AI layer.

The report must be complete even without a model. Every step here is therefore
built so that its failure does not end the run: Ollama unreachable, schema
violation, uncovered statements - everything ends in a note, not in an
exception.

On the retry, more precisely than in the original blueprint: with a JSON schema
in the ``format`` field, decoding is grammar-bound, so schema violations become
rare. The one allowed retry mainly covers transport errors and older Ollama
versions without schema support. The real line of defense is ``verify.py``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..applog import get_log
from ..config import AiConfig
from ..kb.store import KnowledgeBase
from ..resources import read_resource_text
from ..rules.engine import Finding
from .bundles import FindingBundle, SystemContext, build_bundle, estimate_tokens, fit_to_budget
from .client import CloudCallBlockedError, OllamaClient, OllamaUnavailableError
from .redaction import Redactor
from .schema import CorrelatorOutput, ExplainerOutput, json_schema_for
from .verify import VerificationReport, verify_correlator, verify_explainer

EXPLAINER_PROMPT = "ai/prompts/explainer.en.txt"
CORRELATOR_PROMPT = "ai/prompts/correlator.en.txt"

#: Shown in the report whenever the model is not used. The rule engine output is
#: complete on its own; the sentence says so instead of leaving a gap.
RULES_ONLY_NOTE = "The report is built completely from the rule engine."


class AiFindingResult(BaseModel):
    """Model answer for one finding, including the verification result."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    ok: bool
    explanation: ExplainerOutput | None = None
    verification: VerificationReport = Field(default_factory=VerificationReport)
    note: str | None = None
    prompt_tokens_estimated: int = 0
    prompt_tokens_actual: int | None = None
    parts: int = 1


class AiRunResult(BaseModel):
    """Overall result of the AI layer of one run."""

    model_config = ConfigDict(extra="forbid")

    used: bool = False
    model: str | None = None
    num_ctx: int | None = None
    unavailable_reason: str | None = None
    findings: list[AiFindingResult] = Field(default_factory=list)
    correlation: CorrelatorOutput | None = None
    correlation_verification: VerificationReport = Field(default_factory=VerificationReport)
    started_utc: datetime | None = None
    finished_utc: datetime | None = None

    def for_finding(self, finding_id: str) -> AiFindingResult | None:
        for entry in self.findings:
            if entry.finding_id == finding_id:
                return entry
        return None

    @property
    def rejected_statements(self) -> int:
        total = sum(entry.verification.statements_rejected for entry in self.findings)
        return total + self.correlation_verification.statements_rejected


class AiLayer:
    """Runs explainer and correlator - or reports cleanly why not."""

    def __init__(
        self,
        config: AiConfig,
        *,
        client: OllamaClient | None = None,
        kb: KnowledgeBase | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self.config = config
        self.kb = kb
        self.redactor = redactor or Redactor(enabled=config.redact)
        self._client = client
        self._client_error: str | None = None

    # --- Client --------------------------------------------------------------

    def client(self) -> OllamaClient | None:
        if self._client is not None:
            return self._client
        try:
            self._client = OllamaClient(
                base_url=self.config.base_url,
                model=self.config.model,
                temperature=self.config.temperature,
                num_ctx=self.config.num_ctx,
                timeout_seconds=self.config.timeout_seconds,
                allow_cloud=self.config.allow_cloud,
            )
        except CloudCallBlockedError as exc:
            self._client_error = str(exc)
            return None
        return self._client

    # --- Bundles -------------------------------------------------------------

    def bundles_for(
        self, findings: list[Finding], context: SystemContext
    ) -> dict[str, list[FindingBundle]]:
        """Builds the bundles per finding - several partial bundles on overflow."""
        out: dict[str, list[FindingBundle]] = {}
        for finding in findings:
            if finding.suppressed:
                continue
            bundle = build_bundle(
                finding,
                context=context,
                redactor=self.redactor,
                kb=self.kb,
                max_samples=self.config.max_samples_per_finding,
                excerpt_chars=self.config.message_excerpt_chars,
            )
            parts = fit_to_budget(
                bundle,
                max_tokens=self.config.max_bundle_tokens,
                chars_per_token=self.config.chars_per_token,
            )
            if len(parts) > 1:
                get_log().info(
                    "Bundle split instead of truncated",
                    finding=finding.finding_id,
                    parts=len(parts),
                )
            out[finding.finding_id] = parts
        return out

    # --- Execution -----------------------------------------------------------

    def run(
        self,
        findings: list[Finding],
        context: SystemContext,
    ) -> tuple[AiRunResult, dict[str, list[FindingBundle]]]:
        """Runs the AI layer. Does not raise - failures are reported."""
        log = get_log()
        result = AiRunResult(started_utc=datetime.now(UTC))
        bundles = self.bundles_for(findings, context)

        if not self.config.enabled:
            result.unavailable_reason = f"AI layer disabled by configuration. {RULES_ONLY_NOTE}"
            result.finished_utc = datetime.now(UTC)
            return result, bundles

        client = self.client()
        if client is None:
            result.unavailable_reason = (
                f"{self._client_error or 'No client available.'} {RULES_ONLY_NOTE}"
            )
            log.warn("AI layer not used", reason=result.unavailable_reason)
            result.finished_utc = datetime.now(UTC)
            return result, bundles

        if not client.available():
            # The client tells "service not running" from "model missing" and
            # "model is a cloud model". That distinction belongs in the report,
            # not in a log file: it says what to do.
            reason = getattr(client, "unavailable_reason", lambda: None)() or (
                f"Ollama not reachable at {self.config.base_url}."
            )
            result.unavailable_reason = f"{reason} {RULES_ONLY_NOTE}"
            log.warn("AI layer not used", reason=reason)
            result.finished_utc = datetime.now(UTC)
            return result, bundles

        result.used = True
        result.model = client.model
        result.num_ctx = client.effective_num_ctx()

        system_prompt = read_resource_text(EXPLAINER_PROMPT)
        schema = json_schema_for(ExplainerOutput)

        for finding_id, parts in bundles.items():
            result.findings.append(
                self._explain(client, system_prompt, schema, finding_id, parts)
            )

        result.correlation, result.correlation_verification = self._correlate(client, bundles)
        result.finished_utc = datetime.now(UTC)
        return result, bundles

    def _explain(
        self,
        client: OllamaClient,
        system_prompt: str,
        schema: dict[str, object],
        finding_id: str,
        parts: list[FindingBundle],
    ) -> AiFindingResult:
        log = get_log()
        merged: ExplainerOutput | None = None
        estimated = 0
        actual: int | None = None

        for part in parts:
            user_prompt = part.as_prompt_json()
            # The system prompt counts too: Ollama's prompt_eval_count covers
            # both messages. Estimating the bundle alone made every comparison
            # look ~2.5x off and the calibration warning fired on every call.
            estimated += estimate_tokens(
                system_prompt + user_prompt, self.config.chars_per_token
            )
            parsed, reply_tokens, note = self._call_with_retry(
                client, system_prompt, user_prompt, schema, ExplainerOutput
            )
            if parsed is None:
                return AiFindingResult(
                    finding_id=finding_id,
                    ok=False,
                    note=note,
                    prompt_tokens_estimated=estimated,
                    parts=len(parts),
                )
            if reply_tokens is not None:
                actual = (actual or 0) + reply_tokens
            merged = _merge_explanations(merged, parsed)

        assert merged is not None
        verified, report = verify_explainer(merged, parts, redactor=self.redactor)

        if actual is not None and estimated:
            deviation = abs(actual - estimated) / max(estimated, 1)
            if deviation > 0.4:
                log.warn(
                    "Token estimate deviates clearly - adjust chars_per_token",
                    finding=finding_id,
                    estimated=estimated,
                    actual=actual,
                )

        if report.statements_rejected:
            log.warn(
                "Statements without evidence rejected",
                finding=finding_id,
                count=report.statements_rejected,
            )

        return AiFindingResult(
            finding_id=finding_id,
            ok=True,
            explanation=verified,
            verification=report,
            prompt_tokens_estimated=estimated,
            prompt_tokens_actual=actual,
            parts=len(parts),
        )

    def _correlate(
        self, client: OllamaClient, bundles: dict[str, list[FindingBundle]]
    ) -> tuple[CorrelatorOutput | None, VerificationReport]:
        flat = [part for parts in bundles.values() for part in parts]
        if len(flat) < 2:
            return None, VerificationReport()

        summary = [
            {
                "finding_id": part.finding_id,
                "rule": part.rule,
                "severity": part.severity,
                "provider": part.provider,
                "event_id": part.event_id,
                "count": part.count,
                "first_seen_utc": part.first_seen_utc,
                "last_seen_utc": part.last_seen_utc,
                "sample": part.sample_messages[0] if part.sample_messages else "",
            }
            for part in flat
        ]
        user_prompt = json.dumps({"findings": summary}, ensure_ascii=False, indent=1)
        parsed, _, note = self._call_with_retry(
            client,
            read_resource_text(CORRELATOR_PROMPT),
            user_prompt,
            json_schema_for(CorrelatorOutput),
            CorrelatorOutput,
        )
        if parsed is None:
            report = VerificationReport()
            report.rejected_reasons.append(note or "The correlator returned no valid answer.")
            return None, report
        return verify_correlator(parsed, flat)

    def _call_with_retry(
        self,
        client: OllamaClient,
        system_prompt: str,
        user_prompt: str,
        schema: dict[str, object],
        model_type: type[ExplainerOutput] | type[CorrelatorOutput],
    ) -> tuple[ExplainerOutput | CorrelatorOutput | None, int | None, str | None]:
        """One call, exactly one retry on a schema violation, then fall back."""
        last_error: str | None = None
        for attempt in (1, 2):
            try:
                reply = client.chat_json(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    json_schema=schema,  # type: ignore[arg-type]
                )
            except OllamaUnavailableError as exc:
                return None, None, f"Ollama not reachable during the run: {exc}"

            try:
                return model_type.model_validate_json(reply.content), reply.prompt_tokens, None
            except ValidationError as exc:
                last_error = f"schema violation (attempt {attempt}): {exc.error_count()} errors"
                get_log().warn("Model answer violates the schema", attempt=attempt)
            except ValueError as exc:
                last_error = f"answer was not valid JSON (attempt {attempt}): {exc}"

        return None, None, (last_error or "unknown error") + " - falling back to the rule output."


def _merge_explanations(
    first: ExplainerOutput | None, second: ExplainerOutput
) -> ExplainerOutput:
    """Reduce step of the map-reduce over partial bundles."""
    if first is None:
        return second
    summary = first.summary
    if second.summary and second.summary not in summary:
        summary = f"{summary} {second.summary}".strip()
    return ExplainerOutput(
        summary=summary,
        hypotheses=first.hypotheses + second.hypotheses,
        recommended_steps=first.recommended_steps + second.recommended_steps,
    )
