"""Model acceptance test: every gate must fail for its own reason.

The bench decides which model writes the reports, so a gate that lets a bad
model through is worse than no bench at all. Each test here plays one kind of
bad model - inventing, German, silent, broken - and checks that exactly that
gate catches it, with a sentence that says why.
"""

from __future__ import annotations

import json

from wineventai.ai.bench import (
    BenchCases,
    ModelBenchResult,
    default_models,
    detect_language,
    format_report,
    load_cases,
    recommend,
    run_bench,
    scenario_findings,
    write_report,
)
from wineventai.ai.client import ModelReply, OllamaStatus
from wineventai.config import AiConfig, load_config

ENGLISH = {
    "summary": "The event shows that the component failed and this was logged by the system.",
    "statement": "The failure is probably caused by the component that is named in the event.",
}
GERMAN = {
    "summary": "Das Ereignis zeigt, dass die Komponente nicht reagiert hat und der Dienst "
               "beendet wurde.",
    "statement": "Die Ursache ist die Komponente, die in dem Ereignis genannt wird, und "
                 "nicht der Rechner.",
}


class FakeBenchClient:
    """Plays one kind of model. Never touches the network.

    ``behaviour``: good, invent, german, broken, silent.
    """

    def __init__(
        self,
        model: str,
        behaviour: str = "good",
        *,
        context_length: int | None = 131072,
        present: bool = True,
        remote: bool = False,
        capabilities: list[str] | None = None,
        loaded: tuple[int, int] | None = (100, 100),
    ) -> None:
        self.model = model
        self.behaviour = behaviour
        self.context_length = context_length
        self.present = present
        self.remote = remote
        self.capabilities = capabilities if capabilities is not None else ["completion"]
        self.loaded = loaded
        self.prompts: list[str] = []

    def status(self) -> OllamaStatus:
        return OllamaStatus(
            reachable=True, model_present=self.present, models=[self.model],
            remote_model=self.remote,
        )

    def available(self) -> bool:
        return self.status().usable

    def unavailable_reason(self) -> str | None:
        return None if self.available() else self.status().message("http://x", self.model)

    def model_details(self) -> dict:
        return {
            "capabilities": self.capabilities,
            "details": {"parameter_size": "14.8B", "quantization_level": "Q4_K_M"},
        }

    def model_context_length(self) -> int | None:
        return self.context_length

    def effective_num_ctx(self) -> int:
        return 16384

    def loaded_size(self) -> tuple[int, int] | None:
        return self.loaded

    def chat_json(self, *, system_prompt: str, user_prompt: str, json_schema=None) -> ModelReply:
        self.prompts.append(user_prompt)
        payload = json.loads(user_prompt)
        if "findings" in payload:  # correlator
            return ModelReply(content=json.dumps({"incidents": []}))
        if self.behaviour == "broken":
            return ModelReply(content="this is not json")

        events = payload["citable_events"] + payload["context_events"]
        first = events[0]
        evidence = {
            "provider": first["provider"],
            "event_id": 9999 if self.behaviour == "invent" else first["event_id"],
            "timestamp_utc": first["timestamp_utc"],
        }
        texts = GERMAN if self.behaviour == "german" else ENGLISH
        statements = [] if self.behaviour == "silent" else [
            {"statement": texts["statement"], "evidence": [evidence], "confidence": "medium"}
        ]
        answer = {
            "summary": texts["summary"],
            "hypotheses": statements,
            "recommended_steps": statements,
        }
        return ModelReply(content=json.dumps(answer), prompt_tokens=len(user_prompt) // 3)


def _bench(*clients: FakeBenchClient, config: AiConfig | None = None):
    by_name = {client.model: client for client in clients}
    return run_bench(
        config or AiConfig(),
        list(by_name),
        cases=load_cases(),
        client_factory=lambda name: by_name[name],
    )


# --- Scenarios ---------------------------------------------------------------


def test_every_bundled_scenario_produces_at_least_one_finding() -> None:
    """Otherwise the model is never asked and the scenario measures nothing."""
    cases = load_cases()
    for scenario in cases.scenarios:
        assert scenario_findings(scenario, cases.end_utc), scenario.id


def test_scenario_ids_are_unique() -> None:
    ids = [scenario.id for scenario in load_cases().scenarios]
    assert len(ids) == len(set(ids))


def test_the_model_only_sees_redacted_bundles() -> None:
    """The bench takes the real path - including the redaction."""
    client = FakeBenchClient("good:14b")
    _bench(client)
    sent = "\n".join(client.prompts)
    assert "m.schmidt" not in sent
    assert "WS-4711" not in sent
    assert "USER_1" in sent


# --- Gates -------------------------------------------------------------------


def test_a_model_with_covered_english_answers_passes() -> None:
    report = _bench(FakeBenchClient("good:14b"))
    result = report.results[0]
    assert result.status == "passed", result.reasons
    assert result.statements_total > 0
    assert result.statements_rejected == 0
    assert result.language == "en"
    assert report.recommended_model == "good:14b"
    assert 'ai.model: "good:14b"' in report.recommendation


def test_a_model_that_invents_event_ids_fails_on_the_rejected_share() -> None:
    result = _bench(FakeBenchClient("liar:7b", "invent")).results[0]
    assert result.status == "failed"
    assert result.rejected_share == 1.0
    assert any("rejected by the evidence check" in reason for reason in result.reasons)


def test_german_answers_fail_the_language_gate() -> None:
    result = _bench(FakeBenchClient("german:8b", "german")).results[0]
    assert result.status == "failed"
    assert result.language == "de"
    assert any("not English" in reason for reason in result.reasons)


def test_answers_without_statements_fail_instead_of_slipping_through() -> None:
    """Zero statements means zero rejections - the check would be evaded."""
    result = _bench(FakeBenchClient("quiet:3b", "silent")).results[0]
    assert result.status == "failed"
    assert result.statements_rejected == 0
    assert any("no statement at all" in reason for reason in result.reasons)


def test_invalid_json_fails_with_the_number_of_unanswered_findings() -> None:
    result = _bench(FakeBenchClient("broken:1b", "broken")).results[0]
    assert result.status == "failed"
    total = sum(entry.findings_total for entry in result.scenarios)
    assert any(f"for {total} of {total} findings" in reason for reason in result.reasons)


def test_a_too_small_context_fails() -> None:
    result = _bench(FakeBenchClient("small:7b", context_length=8192)).results[0]
    assert result.status == "failed"
    assert any("below the required" in reason for reason in result.reasons)


def test_an_unknown_context_length_is_not_taken_as_large_enough() -> None:
    result = _bench(FakeBenchClient("mystery:7b", context_length=None)).results[0]
    assert result.status == "failed"
    assert any("cannot be confirmed" in reason for reason in result.reasons)


def test_the_thresholds_come_from_the_configuration() -> None:
    lenient = AiConfig.model_validate({"bench": {"min_context_length": 4096}})
    result = _bench(FakeBenchClient("small:7b", context_length=8192), config=lenient).results[0]
    assert result.status == "passed", result.reasons


def test_the_default_configuration_carries_the_bench_thresholds() -> None:
    bench = load_config().ai.bench
    assert bench.min_context_length == 32768
    assert bench.max_rejected_share == 0.2


# --- Not tested is not failed ------------------------------------------------


def test_a_missing_model_is_not_tested_rather_than_failed() -> None:
    result = _bench(FakeBenchClient("gone:14b", present=False)).results[0]
    assert result.status == "not tested"
    assert result.scenarios == []
    assert any("not present" in reason for reason in result.reasons)


def test_a_cloud_model_is_not_tested_without_opt_in() -> None:
    client = FakeBenchClient("glm-5.2:cloud", remote=True)
    result = _bench(client).results[0]
    assert result.status == "not tested"
    assert client.prompts == [], "not a single bundle may reach a cloud model"


def test_an_embedding_model_is_not_tested() -> None:
    result = _bench(FakeBenchClient("nomic-embed-text", capabilities=["embedding"])).results[0]
    assert result.status == "not tested"
    assert any("embedding" in reason for reason in result.reasons)


def test_cloud_models_are_not_benched_by_default() -> None:
    class Probe:
        def list_models(self) -> list[str]:
            return ["gemma4:26b", "glm-5.2:cloud", "qwen3-coder:30b"]

    assert default_models(Probe(), allow_cloud=False) == ["gemma4:26b", "qwen3-coder:30b"]
    assert len(default_models(Probe(), allow_cloud=True)) == 3


def test_without_any_testable_model_there_is_no_recommendation() -> None:
    report = _bench(FakeBenchClient("gone:14b", present=False))
    assert report.recommended_model is None
    assert "rule engine" in report.recommendation


# --- Recommendation and output -----------------------------------------------


def _result(model: str, *, rejected: int, total: int, seconds: float) -> ModelBenchResult:
    return ModelBenchResult(
        model=model, status="passed", statements_total=total,
        statements_rejected=rejected, duration_seconds=seconds,
    )


def test_a_clearly_more_reliable_model_wins_over_a_faster_one() -> None:
    fast = _result("fast:7b", rejected=4, total=20, seconds=30)
    careful = _result("careful:30b", rejected=0, total=20, seconds=300)
    model, _ = recommend([fast, careful], tolerance=0.1)
    assert model == "careful:30b"


def test_one_rejection_more_does_not_outweigh_an_eightfold_speed() -> None:
    """The case from the first live run: 0/17 vs. 1/16, 393 s vs. 46 s."""
    model, _ = recommend(
        [
            _result("deepseek-r1:8b", rejected=0, total=17, seconds=393),
            _result("qwen3-coder:30b", rejected=1, total=16, seconds=46),
        ],
        tolerance=0.1,
    )
    assert model == "qwen3-coder:30b"


def test_without_tolerance_the_fewest_rejections_decide() -> None:
    model, _ = recommend(
        [
            _result("deepseek-r1:8b", rejected=0, total=17, seconds=393),
            _result("qwen3-coder:30b", rejected=1, total=16, seconds=46),
        ],
        tolerance=0.0,
    )
    assert model == "deepseek-r1:8b"


def test_with_equal_rejections_the_faster_model_wins() -> None:
    model, _ = recommend([
        _result("slow:30b", rejected=0, total=20, seconds=300),
        _result("fast:14b", rejected=0, total=20, seconds=60),
    ])
    assert model == "fast:14b"


def test_partial_gpu_offload_is_a_note_not_a_failure() -> None:
    result = _bench(FakeBenchClient("big:30b", loaded=(100, 60))).results[0]
    assert result.status == "passed"
    assert result.gpu_share == 0.6
    assert any("60%" in note for note in result.notes)


def test_unmeasured_gpu_offload_is_said_and_not_left_empty() -> None:
    result = _bench(FakeBenchClient("big:30b", loaded=None)).results[0]
    assert result.gpu_share is None
    assert any("not measured" in note for note in result.notes)


def test_the_console_table_separates_not_tested_from_failed() -> None:
    report = _bench(
        FakeBenchClient("good:14b"),
        FakeBenchClient("liar:7b", "invent"),
        FakeBenchClient("gone:14b", present=False),
    )
    text = "\n".join(format_report(report))
    assert "passed" in text and "failed" in text and "not tested" in text


def test_the_json_result_keeps_the_answers_for_reading(tmp_path) -> None:
    report = _bench(FakeBenchClient("good:14b"))
    path = write_report(report, tmp_path / "bench.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    answers = payload["results"][0]["scenarios"][0]["answers"]
    assert answers and answers[0]["summary"] == ENGLISH["summary"]


def test_own_scenarios_can_be_given_as_yaml() -> None:
    cases = load_cases(
        """
end_utc: "2026-01-15T10:00:00Z"
scenarios:
  - id: one
    title: One crash
    host: PC-1
    events:
      - {seconds_before: 0, channel: System, provider: Microsoft-Windows-Kernel-Power,
         event_id: 41, level: 1, message: "The system has rebooted."}
"""
    )
    assert isinstance(cases, BenchCases)
    assert scenario_findings(cases.scenarios[0], cases.end_utc)


# --- Language heuristic ------------------------------------------------------


def test_the_language_heuristic_tells_english_from_german() -> None:
    assert detect_language(ENGLISH["summary"] + " " + ENGLISH["statement"]) == "en"
    assert detect_language(GERMAN["summary"]) == "de"


def test_text_without_function_words_is_unclear_not_english() -> None:
    assert detect_language("Kernel-Power 41 0xc0000005 ntdll.dll") == "unclear"
    assert detect_language("") == "unclear"
