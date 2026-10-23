"""AI layer: redaction, bundles, verification, failure behavior, cloud guard.

The two most important tests of this project are here: what happens if the
model invents an event id, and what happens if it invents a placeholder? In
both cases the statement must be marked and the rest of the answer kept.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from helpers import FIXTURES, make_record
from wineventai.ai.bundles import (
    FindingBundle,
    SystemContext,
    build_bundle,
    estimate_tokens,
    fit_to_budget,
)
from wineventai.ai.client import CloudCallBlockedError, ModelReply, assert_local
from wineventai.ai.pipeline import AiLayer
from wineventai.ai.redaction import Redactor
from wineventai.ai.schema import ExplainerOutput, json_schema_for
from wineventai.ai.verify import prose_event_ids, verify_explainer
from wineventai.config import AiConfig
from wineventai.enrich.aggregate import Enricher
from wineventai.rules.engine import RuleEngine
from wineventai.rules.loader import load_rules

CONTEXT = SystemContext(
    host="HOST_1",
    operating_system="Windows 11",
    period_from_utc="2026-09-03T12:00:00+00:00",
    period_to_utc="2026-09-10T12:00:00+00:00",
    boot_sessions=2,
)


class FakeClient:
    """Stand-in for Ollama. Returns recorded answers, never touches the network."""

    def __init__(self, responses: list[str], *, reachable: bool = True) -> None:
        self.responses = list(responses)
        self.reachable = reachable
        self.model = "test-model"
        self.calls: list[tuple[str, str]] = []

    def available(self) -> bool:
        return self.reachable

    def effective_num_ctx(self) -> int:
        return 16384

    def chat_json(self, *, system_prompt: str, user_prompt: str, json_schema=None) -> ModelReply:
        self.calls.append((system_prompt, user_prompt))
        content = self.responses.pop(0) if self.responses else "{}"
        return ModelReply(content=content, prompt_tokens=len(user_prompt) // 3,
                          model=self.model)


def _fixture(name: str) -> str:
    return (FIXTURES / "ollama" / name).read_text(encoding="utf-8")


def _findings():
    stream = [
        make_record(minutes_ago=0, provider="Microsoft-Windows-Kernel-Power",
                    event_id=41, level=1, properties=["0", "0", "122"],
                    message="The system has rebooted. User INTERN\\m.schmidt "
                            "from 10.20.30.40."),
        make_record(minutes_ago=2, provider="disk", event_id=153, level=2,
                    properties=["1", "4001"]),
    ]
    enrichment = Enricher(window_hours=168).consume(stream)
    engine = RuleEngine(load_rules())
    return engine.evaluate(enrichment)


# --- Redaction ---------------------------------------------------------------


def test_pseudonyms_are_stable_and_not_blanket() -> None:
    """Blanket asterisks would make the correlator worthless."""
    redactor = Redactor()
    a = redactor.text("Logon of INTERN\\m.schmidt at 10.20.30.40")
    b = redactor.text("Logoff of INTERN\\m.schmidt at 10.20.30.40")

    assert "m.schmidt" not in a
    assert "10.20.30.40" not in a
    assert "USER_1" in a and "USER_1" in b, "same user, same pseudonym"
    assert "IP_1" in a and "IP_1" in b


def test_different_users_get_different_pseudonyms() -> None:
    redactor = Redactor()
    text = redactor.text("INTERN\\anna and INTERN\\bert")
    assert "USER_1" in text and "USER_2" in text


def test_well_known_system_accounts_are_kept() -> None:
    """S-1-5-18 is the same on every Windows and says nothing about people."""
    redactor = Redactor()
    assert "S-1-5-18" in (redactor.text("Account S-1-5-18 has no rights") or "")


def test_restoring_brings_back_the_plain_text() -> None:
    redactor = Redactor()
    pseudonymized = redactor.text("User INTERN\\m.schmidt")
    assert redactor.restore(pseudonymized or "").endswith("m.schmidt")


def test_invented_placeholders_are_detected() -> None:
    redactor = Redactor()
    redactor.text("INTERN\\m.schmidt")
    assert redactor.invented_placeholders("USER_1 did it") == set()
    assert redactor.invented_placeholders("USER_7 did it") == {"USER_7"}


def test_redaction_works_on_the_record_not_on_the_prompt_text() -> None:
    redactor = Redactor()
    record = make_record(message="Error at INTERN\\m.schmidt", computer="WS-4711",
                         user_sid="S-1-5-21-1-2-3-1107")
    redacted = redactor.record(record)

    assert redacted.computer.startswith("HOST_")
    assert redacted.user_sid is not None and redacted.user_sid.startswith("SID_")
    assert "m.schmidt" not in (redacted.message or "")
    assert record.message is not None and "m.schmidt" in record.message, (
        "the original must not be changed"
    )


# --- Bundles -----------------------------------------------------------------


def test_the_bundle_never_contains_the_raw_log() -> None:
    findings = [f for f in _findings() if f.rule_id == "kernel-power-41"]
    bundle = build_bundle(findings[0], context=CONTEXT, redactor=Redactor(), kb=None,
                          max_samples=3, excerpt_chars=200)
    text = bundle.as_prompt_json()

    assert "m.schmidt" not in text
    assert "10.20.30.40" not in text
    assert bundle.citable_events, "evidence must be in the bundle"


def test_an_unverified_knowledge_base_entry_does_not_go_into_the_prompt(tmp_path) -> None:
    """An unverified entry in the context would be worse than none at all."""
    from wineventai.kb.store import KbConfidence, KbEntry, KnowledgeBase

    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.upsert(
        KbEntry(provider="Microsoft-Windows-Kernel-Power", event_id=41,
                meaning="Probably something", confidence=KbConfidence.UNVERIFIED)
    )
    finding = next(f for f in _findings() if f.rule_id == "kernel-power-41")
    bundle = build_bundle(finding, context=CONTEXT, redactor=Redactor(), kb=kb,
                          max_samples=3, excerpt_chars=200)

    assert bundle.knowledge_base is None
    assert bundle.knowledge_base_status == "unverified"
    assert "Probably something" not in bundle.as_prompt_json()


def test_a_bundle_that_is_too_large_is_split_instead_of_truncated() -> None:
    findings = [f for f in _findings() if f.rule_id == "kernel-power-41"]
    bundle = build_bundle(findings[0], context=CONTEXT, redactor=Redactor(), kb=None,
                          max_samples=3, excerpt_chars=200)
    bundle = bundle.model_copy(
        update={
            "sample_messages": ["x" * 500] * 8,
            "citable_events": bundle.citable_events * 8,
        }
    )
    parts = fit_to_budget(bundle, max_tokens=200, chars_per_token=3.2)
    assert len(parts) > 1
    assert all(isinstance(part, FindingBundle) for part in parts)


def test_the_token_estimate_is_conservative() -> None:
    assert estimate_tokens("a" * 320, 3.2) == 101
    assert estimate_tokens("", 3.2) == 1


# --- Verification ------------------------------------------------------------


def test_an_invented_event_id_rejects_only_the_single_statement() -> None:
    """The most important test of the project.

    One bad footnote must not cost three good hypotheses - so the single
    statement is marked, not the whole answer rejected.
    """
    findings = _findings()
    redactor = Redactor()
    bundles = [
        build_bundle(finding, context=CONTEXT, redactor=redactor, kb=None,
                     max_samples=3, excerpt_chars=200)
        for finding in findings
    ]
    output = ExplainerOutput.model_validate_json(_fixture("explainer_invented_id.json"))
    verified, report = verify_explainer(output, bundles, redactor=redactor)

    assert report.statements_rejected == 2
    assert 4321 in report.invented_event_ids
    assert "USER_7" in report.invented_placeholders
    assert all(not statement.verified for statement in verified.hypotheses)
    assert verified.summary, "the answer itself is kept"


def test_a_covered_statement_stays_unchallenged() -> None:
    findings = _findings()
    redactor = Redactor()
    bundles = [
        build_bundle(finding, context=CONTEXT, redactor=redactor, kb=None,
                     max_samples=3, excerpt_chars=200)
        for finding in findings
    ]
    stamp = bundles[0].citable_events[0]["timestamp_utc"]
    payload = {
        "summary": "Unclean restart.",
        "hypotheses": [
            {
                "statement": "The restart was not clean.",
                "evidence": [
                    {
                        "provider": bundles[0].provider,
                        "event_id": bundles[0].event_id,
                        "timestamp_utc": stamp,
                    }
                ],
                "confidence": "medium",
            }
        ],
        "recommended_steps": [],
    }
    verified, report = verify_explainer(
        ExplainerOutput.model_validate(payload), bundles, redactor=redactor
    )
    assert report.clean
    assert verified.hypotheses[0].verified


def test_prose_detection_only_finds_real_event_id_mentions() -> None:
    assert prose_event_ids("Event ID 1001 and EventID 41") == {1001, 41}
    assert prose_event_ids("There were 12 incidents in 3 hours") == set()


def test_a_wrong_timestamp_is_noticed() -> None:
    findings = [f for f in _findings() if f.rule_id == "kernel-power-41"]
    redactor = Redactor()
    bundles = [build_bundle(findings[0], context=CONTEXT, redactor=redactor, kb=None,
                            max_samples=3, excerpt_chars=200)]
    payload = {
        "summary": "Test",
        "hypotheses": [
            {
                "statement": "Something happened.",
                "evidence": [
                    {
                        "provider": bundles[0].provider,
                        "event_id": bundles[0].event_id,
                        "timestamp_utc": datetime(2001, 1, 1, tzinfo=UTC).isoformat(),
                    }
                ],
                "confidence": "high",
            }
        ],
        "recommended_steps": [],
    }
    _, report = verify_explainer(ExplainerOutput.model_validate(payload), bundles)
    assert report.statements_rejected == 1
    assert "timestamp" in report.rejected_reasons[0]


# --- Failure behavior --------------------------------------------------------


def test_without_ollama_the_report_is_built_anyway() -> None:
    layer = AiLayer(AiConfig(), client=FakeClient([], reachable=False))
    result, bundles = layer.run(_findings(), CONTEXT)

    assert result.used is False
    assert result.unavailable_reason is not None
    assert "rule engine" in result.unavailable_reason
    assert bundles, "the bundles are built without a model too and stay traceable"


def test_a_schema_violation_leads_to_exactly_one_retry_and_then_the_fallback() -> None:
    client = FakeClient([_fixture("explainer_schema_violation.json")] * 4)
    layer = AiLayer(AiConfig(), client=client)
    result, _ = layer.run(_findings()[:1], CONTEXT)

    entry = result.findings[0]
    assert entry.ok is False
    assert entry.note is not None and "falling back" in entry.note
    assert len(client.calls) == 2, "exactly one retry, no more"


def test_a_valid_answer_is_taken_over() -> None:
    findings = _findings()[:1]
    client = FakeClient([_fixture("explainer_good.json")] * 3)
    layer = AiLayer(AiConfig(), client=client)
    result, _ = layer.run(findings, CONTEXT)

    entry = result.findings[0]
    assert entry.ok is True
    assert entry.explanation is not None
    assert entry.explanation.summary


def test_the_token_estimate_includes_the_system_prompt() -> None:
    """Ollama's prompt_eval_count counts both messages - the estimate must too.

    Found by the model bench: without the system prompt every call was
    estimated ~2.5x too low and the calibration warning fired every time.
    """
    from wineventai.ai.pipeline import EXPLAINER_PROMPT
    from wineventai.resources import read_resource_text

    findings = _findings()[:1]
    client = FakeClient([_fixture("explainer_good.json")] * 3)
    result, bundles = AiLayer(AiConfig(), client=client).run(findings, CONTEXT)

    config = AiConfig()
    bundle_only = estimate_tokens(
        bundles[findings[0].finding_id][0].as_prompt_json(), config.chars_per_token
    )
    system_only = estimate_tokens(read_resource_text(EXPLAINER_PROMPT), config.chars_per_token)
    assert result.findings[0].prompt_tokens_estimated >= bundle_only + system_only - 1


def test_a_cloud_call_without_opt_in_is_blocked() -> None:
    with pytest.raises(CloudCallBlockedError):
        assert_local("http://ollama.example.com:11434", allow_cloud=False)
    assert_local("http://localhost:11434", allow_cloud=False)
    assert_local("http://ollama.example.com:11434", allow_cloud=True)


def test_the_ai_layer_reports_a_cloud_block_instead_of_raising() -> None:
    layer = AiLayer(AiConfig(base_url="http://somewhere.example.com:11434"))
    result, _ = layer.run(_findings(), CONTEXT)
    assert result.used is False
    assert result.unavailable_reason is not None
    assert "allow_cloud" in result.unavailable_reason


def test_the_schema_contains_no_verification_fields() -> None:
    """The model must not be able to claim its answer was verified."""
    schema = json_schema_for(ExplainerOutput)
    text = str(schema)
    assert "verified" not in text
    assert "verification_note" not in text


def test_the_prompts_ask_for_the_field_names_the_schema_uses() -> None:
    """Prompt and schema are one contract; a renamed field in only one breaks it."""
    from wineventai.resources import read_resource_text

    explainer = read_resource_text("ai/prompts/explainer.en.txt")
    for field in ("summary", "hypotheses", "recommended_steps", "statement",
                  "citable_events", "context_events", "knowledge_base"):
        assert f'"{field}"' in explainer, field
    correlator = read_resource_text("ai/prompts/correlator.en.txt")
    for field in ("incidents", "title", "finding_ids", "rationale", "finding_id"):
        assert f'"{field}"' in correlator, field
