"""Befund-Buendel: das Einzige, was das Modell zu sehen bekommt.

Nie das Rohlog. Ein Buendel enthaelt den Regeltreffer, Zeitraum, Haeufigkeit,
wenige gekuerzte Beispielmeldungen, den Systemkontext und - nur wenn gesichert -
den passenden Eintrag der Wissensbasis.

Token-Schaetzung ohne externe Bibliothek: ``tiktoken`` laedt seine BPE-Dateien
beim ersten Gebrauch aus dem Netz und waere damit ein Offline-Bruch; ausserdem
waere der Tokenizer fuer ein lokales Modell ohnehin der falsche. Stattdessen
eine konservative Heuristik plus Selbstkalibrierung: Die Ollama-Antwort meldet
mit ``prompt_eval_count`` die real verbrauchten Prompt-Tokens, und die
Abweichung landet im Anwendungslog.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..enrich.burst import hour_label
from ..kb.store import KnowledgeBase
from ..rules.engine import Finding
from .redaction import Redactor


class SystemContext(BaseModel):
    """Knapper Systemkontext, der jedem Buendel beiliegt."""

    model_config = ConfigDict(extra="forbid")

    host: str
    betriebssystem: str
    zeitraum_von_utc: str
    zeitraum_bis_utc: str
    boot_sitzungen: int
    unvollstaendige_quellen: list[str] = Field(default_factory=list)


class FindingBundle(BaseModel):
    """Ein Buendel je Befund-Cluster."""

    model_config = ConfigDict(extra="forbid")

    befund_id: str
    regel: str
    regel_name: str
    severity: str
    provider: str
    event_id: int
    kanal: str
    haeufigkeit: int
    erstes_vorkommen_utc: str
    letztes_vorkommen_utc: str
    bursts: list[str] = Field(default_factory=list)
    beispielmeldungen: list[str] = Field(default_factory=list)
    belegbare_ereignisse: list[dict[str, Any]] = Field(default_factory=list)
    kontext_ereignisse: list[dict[str, Any]] = Field(default_factory=list)
    wissensbasis: dict[str, Any] | None = None
    wissensbasis_status: str = "fehlt"
    systemkontext: SystemContext

    def as_prompt_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), ensure_ascii=False, indent=1)


def estimate_tokens(text: str, chars_per_token: float) -> int:
    """Konservative Schaetzung. Lieber zu gross als zu klein."""
    if chars_per_token <= 0:
        chars_per_token = 3.2
    return int(len(text) / chars_per_token) + 1


def build_bundle(
    finding: Finding,
    *,
    context: SystemContext,
    redactor: Redactor,
    kb: KnowledgeBase | None,
    max_samples: int,
    excerpt_chars: int,
    max_context_events: int = 12,
) -> FindingBundle:
    """Baut das Buendel eines Befunds - redigiert und gekuerzt."""
    samples = finding.group.samples[:max_samples]
    redacted_samples = [redactor.record(sample) for sample in samples]

    kb_entry = kb.get(finding.group.provider, finding.group.event_id) if kb else None
    kb_payload: dict[str, Any] | None = None
    kb_status = "fehlt"
    if kb_entry is not None:
        kb_status = str(kb_entry.confidence)
        if kb_entry.usable_in_prompt:
            kb_payload = {
                "bedeutung": kb_entry.bedeutung.strip(),
                "typische_ursachen": kb_entry.typische_ursachen,
                "checks": kb_entry.checks,
                "quelle": kb_entry.quelle_url,
            }

    context_events = [
        redactor.record(record) for record in finding.context_events[:max_context_events]
    ]

    return FindingBundle(
        befund_id=finding.finding_id,
        regel=finding.rule_id,
        regel_name=finding.rule_name,
        severity=str(finding.severity),
        provider=finding.group.provider,
        event_id=finding.group.event_id,
        kanal=finding.group.channel,
        haeufigkeit=finding.group.count,
        erstes_vorkommen_utc=finding.group.first_seen_utc.isoformat(),
        letztes_vorkommen_utc=finding.group.last_seen_utc.isoformat(),
        bursts=[
            f"{hour_label(burst.hour_utc)}: {burst.count} Vorkommen"
            for burst in finding.group.bursts[:5]
        ],
        beispielmeldungen=[record.excerpt(excerpt_chars) for record in redacted_samples],
        belegbare_ereignisse=[
            {
                "provider": record.provider,
                "event_id": record.event_id,
                "timestamp_utc": record.timestamp_utc.isoformat(),
            }
            for record in redacted_samples
        ],
        kontext_ereignisse=[
            {
                "provider": record.provider,
                "event_id": record.event_id,
                "timestamp_utc": record.timestamp_utc.isoformat(),
                "level": record.level,
                "meldung": record.excerpt(160),
            }
            for record in context_events
        ],
        wissensbasis=kb_payload,
        wissensbasis_status=kb_status,
        systemkontext=context,
    )


def split_bundle(bundle: FindingBundle, parts: int) -> list[FindingBundle]:
    """Teilt ein zu grosses Buendel in Teilbuendel - Map-Reduce statt Abschneiden.

    Geteilt werden Beispiele und Kontext, nicht die Kennzahlen: Jedes Teilbuendel
    behaelt Haeufigkeit und Zeitraum, damit keine Teilaussage entsteht, die den
    Umfang des Befunds falsch darstellt.
    """
    parts = max(parts, 1)
    if parts == 1:
        return [bundle]

    chunks: list[FindingBundle] = []
    sample_size = max(1, len(bundle.beispielmeldungen) // parts)
    context_size = max(1, len(bundle.kontext_ereignisse) // parts)

    for index in range(parts):
        sample_slice = slice(index * sample_size, (index + 1) * sample_size)
        context_slice = slice(index * context_size, (index + 1) * context_size)
        samples = bundle.beispielmeldungen[sample_slice]
        evidence = bundle.belegbare_ereignisse[sample_slice]
        contexts = bundle.kontext_ereignisse[context_slice]
        if not samples and not contexts:
            continue
        chunks.append(
            bundle.model_copy(
                update={
                    "befund_id": f"{bundle.befund_id}#{index + 1}",
                    "beispielmeldungen": samples,
                    "belegbare_ereignisse": evidence,
                    "kontext_ereignisse": contexts,
                }
            )
        )
    return chunks or [bundle]


def fit_to_budget(
    bundle: FindingBundle,
    *,
    max_tokens: int,
    chars_per_token: float,
) -> list[FindingBundle]:
    """Sorgt dafuer, dass jedes Teilbuendel in das Budget passt."""
    text = bundle.as_prompt_json()
    tokens = estimate_tokens(text, chars_per_token)
    if tokens <= max_tokens:
        return [bundle]

    parts = (tokens // max_tokens) + 1
    pieces = split_bundle(bundle, parts)
    if len(pieces) == 1:
        # Nicht weiter teilbar: Beispiele kuerzen statt den Befund zu verlieren.
        shortened = bundle.model_copy(
            update={
                "beispielmeldungen": [
                    text[: max(80, int(max_tokens * chars_per_token / 4))]
                    for text in bundle.beispielmeldungen[:1]
                ],
                "kontext_ereignisse": bundle.kontext_ereignisse[:3],
            }
        )
        return [shortened]
    return pieces


def evidence_index(bundles: list[FindingBundle]) -> set[tuple[str, int]]:
    """Alle Provider/ID-Paare, die im Eingabematerial tatsaechlich vorkommen."""
    index: set[tuple[str, int]] = set()
    for bundle in bundles:
        for entry in bundle.belegbare_ereignisse + bundle.kontext_ereignisse:
            index.add((str(entry["provider"]), int(entry["event_id"])))
    return index
