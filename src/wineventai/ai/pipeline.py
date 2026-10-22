"""Ablauf des KI-Layers.

Der Bericht muss auch ohne Modell vollstaendig entstehen. Deshalb ist jeder
Schritt hier so gebaut, dass sein Ausfall den Lauf nicht beendet: Ollama nicht
erreichbar, Schemaverstoss, ungedeckte Aussagen - alles endet in einem Vermerk,
nicht in einer Ausnahme.

Zum Retry, praeziser als im urspruenglichen Bauplan: Mit einem JSON-Schema im
``format``-Feld ist die Dekodierung grammatikgebunden, Schemaverstoesse werden
also selten. Der eine erlaubte Retry deckt vor allem Transportfehler und aeltere
Ollama-Versionen ohne Schema-Unterstuetzung ab. Die eigentliche
Verteidigungslinie ist ``verify.py``.
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

EXPLAINER_PROMPT = "ai/prompts/explainer.de.txt"
CORRELATOR_PROMPT = "ai/prompts/correlator.de.txt"


class AiFindingResult(BaseModel):
    """Modellantwort zu einem Befund, samt Pruefergebnis."""

    model_config = ConfigDict(extra="forbid")

    befund_id: str
    ok: bool
    explanation: ExplainerOutput | None = None
    verification: VerificationReport = Field(default_factory=VerificationReport)
    note: str | None = None
    prompt_tokens_estimated: int = 0
    prompt_tokens_actual: int | None = None
    parts: int = 1


class AiRunResult(BaseModel):
    """Gesamtergebnis des KI-Layers eines Laufs."""

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

    def for_finding(self, befund_id: str) -> AiFindingResult | None:
        for entry in self.findings:
            if entry.befund_id == befund_id:
                return entry
        return None

    @property
    def rejected_statements(self) -> int:
        total = sum(entry.verification.statements_rejected for entry in self.findings)
        return total + self.correlation_verification.statements_rejected


class AiLayer:
    """Fuehrt Erklaerer und Korrelator aus - oder meldet sauber, warum nicht."""

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

    # --- Buendel -------------------------------------------------------------

    def bundles_for(
        self, findings: list[Finding], context: SystemContext
    ) -> dict[str, list[FindingBundle]]:
        """Baut je Befund die Buendel - bei Ueberlauf mehrere Teilbuendel."""
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
                    "Buendel geteilt statt gekuerzt",
                    befund=finding.finding_id,
                    teile=len(parts),
                )
            out[finding.finding_id] = parts
        return out

    # --- Ausfuehrung ---------------------------------------------------------

    def run(
        self,
        findings: list[Finding],
        context: SystemContext,
    ) -> tuple[AiRunResult, dict[str, list[FindingBundle]]]:
        """Fuehrt den KI-Layer aus. Wirft nicht - Ausfaelle werden gemeldet."""
        log = get_log()
        result = AiRunResult(started_utc=datetime.now(UTC))
        bundles = self.bundles_for(findings, context)

        if not self.config.enabled:
            result.unavailable_reason = "KI-Layer per Konfiguration abgeschaltet."
            result.finished_utc = datetime.now(UTC)
            return result, bundles

        client = self.client()
        if client is None:
            result.unavailable_reason = self._client_error or "Kein Client verfuegbar."
            log.warn("KI-Layer nicht verwendet", grund=result.unavailable_reason)
            result.finished_utc = datetime.now(UTC)
            return result, bundles

        if not client.available():
            # Der Client unterscheidet "Dienst laeuft nicht" von "Modell fehlt".
            # Diese Unterscheidung gehoert in den Bericht, nicht in ein Logfile:
            # Sie sagt, was zu tun ist.
            reason = getattr(client, "unavailable_reason", lambda: None)() or (
                f"Ollama unter {self.config.base_url} nicht erreichbar."
            )
            result.unavailable_reason = (
                f"{reason} Der Bericht entsteht vollstaendig aus der Regel-Engine."
            )
            log.warn("KI-Layer nicht verwendet", grund=reason)
            result.finished_utc = datetime.now(UTC)
            return result, bundles

        result.used = True
        result.model = client.model
        result.num_ctx = client.effective_num_ctx()

        system_prompt = read_resource_text(EXPLAINER_PROMPT)
        schema = json_schema_for(ExplainerOutput)

        for befund_id, parts in bundles.items():
            result.findings.append(
                self._explain(client, system_prompt, schema, befund_id, parts)
            )

        result.correlation, result.correlation_verification = self._correlate(client, bundles)
        result.finished_utc = datetime.now(UTC)
        return result, bundles

    def _explain(
        self,
        client: OllamaClient,
        system_prompt: str,
        schema: dict[str, object],
        befund_id: str,
        parts: list[FindingBundle],
    ) -> AiFindingResult:
        log = get_log()
        merged: ExplainerOutput | None = None
        estimated = 0
        actual: int | None = None

        for part in parts:
            user_prompt = part.as_prompt_json()
            estimated += estimate_tokens(user_prompt, self.config.chars_per_token)
            parsed, reply_tokens, note = self._call_with_retry(
                client, system_prompt, user_prompt, schema, ExplainerOutput
            )
            if parsed is None:
                return AiFindingResult(
                    befund_id=befund_id,
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
                    "Token-Schaetzung weicht deutlich ab - chars_per_token nachziehen",
                    befund=befund_id,
                    geschaetzt=estimated,
                    tatsaechlich=actual,
                )

        if report.statements_rejected:
            log.warn(
                "Aussagen ohne Deckung verworfen",
                befund=befund_id,
                anzahl=report.statements_rejected,
            )

        return AiFindingResult(
            befund_id=befund_id,
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
                "befund_id": part.befund_id,
                "regel": part.regel,
                "severity": part.severity,
                "provider": part.provider,
                "event_id": part.event_id,
                "haeufigkeit": part.haeufigkeit,
                "erstes_vorkommen_utc": part.erstes_vorkommen_utc,
                "letztes_vorkommen_utc": part.letztes_vorkommen_utc,
                "beispiel": part.beispielmeldungen[0] if part.beispielmeldungen else "",
            }
            for part in flat
        ]
        user_prompt = json.dumps({"befunde": summary}, ensure_ascii=False, indent=1)
        parsed, _, note = self._call_with_retry(
            client,
            read_resource_text(CORRELATOR_PROMPT),
            user_prompt,
            json_schema_for(CorrelatorOutput),
            CorrelatorOutput,
        )
        if parsed is None:
            report = VerificationReport()
            report.rejected_reasons.append(note or "Korrelator lieferte keine gueltige Antwort.")
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
        """Ein Aufruf, bei Schemaverstoss genau ein Retry, danach Rueckfall."""
        last_error: str | None = None
        for attempt in (1, 2):
            try:
                reply = client.chat_json(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    json_schema=schema,  # type: ignore[arg-type]
                )
            except OllamaUnavailableError as exc:
                return None, None, f"Ollama waehrend des Laufs nicht erreichbar: {exc}"

            try:
                return model_type.model_validate_json(reply.content), reply.prompt_tokens, None
            except ValidationError as exc:
                last_error = f"Schemaverstoss (Versuch {attempt}): {exc.error_count()} Fehler"
                get_log().warn("Modellantwort verletzt das Schema", versuch=attempt)
            except ValueError as exc:
                last_error = f"Antwort war kein gueltiges JSON (Versuch {attempt}): {exc}"

        return None, None, (last_error or "Unbekannter Fehler") + " - Rueckfall auf Regelausgabe."


def _merge_explanations(
    first: ExplainerOutput | None, second: ExplainerOutput
) -> ExplainerOutput:
    """Reduce-Schritt beim Map-Reduce ueber Teilbuendel."""
    if first is None:
        return second
    summary = first.zusammenfassung
    if second.zusammenfassung and second.zusammenfassung not in summary:
        summary = f"{summary} {second.zusammenfassung}".strip()
    return ExplainerOutput(
        zusammenfassung=summary,
        hypothesen=first.hypothesen + second.hypothesen,
        empfohlene_schritte=first.empfohlene_schritte + second.empfohlene_schritte,
    )
