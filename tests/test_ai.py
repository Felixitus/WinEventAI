"""KI-Layer: Redaction, Buendel, Nachpruefung, Ausfallverhalten.

Die beiden wichtigsten Tests dieses Projekts stehen hier: Was passiert, wenn das
Modell eine Event-ID erfindet, und was passiert, wenn es einen Platzhalter
erfindet? In beiden Faellen muss die Aussage markiert und die restliche Antwort
erhalten bleiben.
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
    betriebssystem="Windows 11",
    zeitraum_von_utc="2026-09-03T12:00:00+00:00",
    zeitraum_bis_utc="2026-09-10T12:00:00+00:00",
    boot_sitzungen=2,
)


class FakeClient:
    """Ollama-Ersatz. Liefert aufgezeichnete Antworten, geht nie ins Netz."""

    def __init__(self, responses: list[str], *, reachable: bool = True) -> None:
        self.responses = list(responses)
        self.reachable = reachable
        self.model = "test-modell"
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
                    message="Das System wurde neu gestartet. Benutzer INTERN\\m.schmidt "
                            "von 10.20.30.40."),
        make_record(minutes_ago=2, provider="disk", event_id=153, level=2,
                    properties=["1", "4001"]),
    ]
    enrichment = Enricher(window_hours=168).consume(stream)
    engine = RuleEngine(load_rules())
    return engine.evaluate(enrichment)


# --- Redaction ---------------------------------------------------------------


def test_pseudonyme_sind_stabil_und_nicht_pauschal() -> None:
    """Pauschale Sternchen wuerden den Korrelator wertlos machen."""
    redactor = Redactor()
    a = redactor.text("Anmeldung von INTERN\\m.schmidt an 10.20.30.40")
    b = redactor.text("Abmeldung von INTERN\\m.schmidt an 10.20.30.40")

    assert "m.schmidt" not in a
    assert "10.20.30.40" not in a
    assert "BENUTZER_1" in a and "BENUTZER_1" in b, "gleicher Benutzer, gleiches Pseudonym"
    assert "IP_1" in a and "IP_1" in b


def test_verschiedene_benutzer_bekommen_verschiedene_pseudonyme() -> None:
    redactor = Redactor()
    text = redactor.text("INTERN\\anna und INTERN\\bert")
    assert "BENUTZER_1" in text and "BENUTZER_2" in text


def test_bekannte_systemkonten_bleiben_erhalten() -> None:
    """S-1-5-18 ist auf jedem Windows dasselbe und sagt nichts ueber Personen."""
    redactor = Redactor()
    assert "S-1-5-18" in (redactor.text("Konto S-1-5-18 hat keine Rechte") or "")


def test_rueckersetzen_stellt_klartext_wieder_her() -> None:
    redactor = Redactor()
    pseudonymisiert = redactor.text("Benutzer INTERN\\m.schmidt")
    assert redactor.restore(pseudonymisiert or "").endswith("m.schmidt")


def test_erfundene_platzhalter_werden_erkannt() -> None:
    redactor = Redactor()
    redactor.text("INTERN\\m.schmidt")
    assert redactor.invented_placeholders("BENUTZER_1 war es") == set()
    assert redactor.invented_placeholders("BENUTZER_7 war es") == {"BENUTZER_7"}


def test_redaction_arbeitet_auf_dem_record_nicht_auf_dem_prompttext() -> None:
    redactor = Redactor()
    record = make_record(message="Fehler bei INTERN\\m.schmidt", computer="WS-4711",
                         user_sid="S-1-5-21-1-2-3-1107")
    redigiert = redactor.record(record)

    assert redigiert.computer.startswith("HOST_")
    assert redigiert.user_sid is not None and redigiert.user_sid.startswith("SID_")
    assert "m.schmidt" not in (redigiert.message or "")
    assert record.message is not None and "m.schmidt" in record.message, (
        "das Original darf nicht veraendert werden"
    )


# --- Buendel -----------------------------------------------------------------


def test_buendel_enthaelt_nie_das_rohlog() -> None:
    findings = [f for f in _findings() if f.rule_id == "kernel-power-41"]
    bundle = build_bundle(findings[0], context=CONTEXT, redactor=Redactor(), kb=None,
                          max_samples=3, excerpt_chars=200)
    text = bundle.as_prompt_json()

    assert "m.schmidt" not in text
    assert "10.20.30.40" not in text
    assert bundle.belegbare_ereignisse, "Belege muessen im Buendel stehen"


def test_ungesicherte_wissensbasis_geht_nicht_in_den_prompt(tmp_path) -> None:
    """Ein unsicherer Eintrag im Kontext waere schlimmer als gar keiner."""
    from wineventai.kb.store import KbConfidence, KbEntry, KnowledgeBase

    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.upsert(
        KbEntry(provider="Microsoft-Windows-Kernel-Power", event_id=41,
                bedeutung="Vermutlich irgendwas", confidence=KbConfidence.UNSICHER)
    )
    finding = next(f for f in _findings() if f.rule_id == "kernel-power-41")
    bundle = build_bundle(finding, context=CONTEXT, redactor=Redactor(), kb=kb,
                          max_samples=3, excerpt_chars=200)

    assert bundle.wissensbasis is None
    assert bundle.wissensbasis_status == "unsicher"
    assert "Vermutlich irgendwas" not in bundle.as_prompt_json()


def test_zu_grosses_buendel_wird_geteilt_statt_gekuerzt() -> None:
    findings = [f for f in _findings() if f.rule_id == "kernel-power-41"]
    bundle = build_bundle(findings[0], context=CONTEXT, redactor=Redactor(), kb=None,
                          max_samples=3, excerpt_chars=200)
    bundle = bundle.model_copy(
        update={
            "beispielmeldungen": ["x" * 500] * 8,
            "belegbare_ereignisse": bundle.belegbare_ereignisse * 8,
        }
    )
    parts = fit_to_budget(bundle, max_tokens=200, chars_per_token=3.2)
    assert len(parts) > 1
    assert all(isinstance(part, FindingBundle) for part in parts)


def test_token_schaetzung_ist_konservativ() -> None:
    assert estimate_tokens("a" * 320, 3.2) == 101
    assert estimate_tokens("", 3.2) == 1


# --- Nachpruefung ------------------------------------------------------------


def test_erfundene_event_id_verwirft_nur_die_einzelne_aussage() -> None:
    """Der wichtigste Test des Projekts.

    Eine schlechte Fussnote darf nicht drei gute Hypothesen kosten - deshalb
    wird das einzelne Statement markiert, nicht die ganze Antwort verworfen.
    """
    findings = _findings()
    redactor = Redactor()
    bundles = [
        build_bundle(finding, context=CONTEXT, redactor=redactor, kb=None,
                     max_samples=3, excerpt_chars=200)
        for finding in findings
    ]
    output = ExplainerOutput.model_validate_json(_fixture("explainer_erfundene_id.json"))
    verified, report = verify_explainer(output, bundles, redactor=redactor)

    assert report.statements_rejected == 2
    assert 4321 in report.invented_event_ids
    assert "BENUTZER_7" in report.invented_placeholders
    assert all(not statement.verified for statement in verified.hypothesen)
    assert verified.zusammenfassung, "die Antwort selbst bleibt erhalten"


def test_gedeckte_aussage_bleibt_unbeanstandet() -> None:
    findings = _findings()
    redactor = Redactor()
    bundles = [
        build_bundle(finding, context=CONTEXT, redactor=redactor, kb=None,
                     max_samples=3, excerpt_chars=200)
        for finding in findings
    ]
    stamp = bundles[0].belegbare_ereignisse[0]["timestamp_utc"]
    payload = {
        "zusammenfassung": "Unsauberer Neustart.",
        "hypothesen": [
            {
                "aussage": "Der Neustart war nicht sauber.",
                "evidence": [
                    {
                        "provider": bundles[0].provider,
                        "event_id": bundles[0].event_id,
                        "timestamp_utc": stamp,
                    }
                ],
                "confidence": "mittel",
            }
        ],
        "empfohlene_schritte": [],
    }
    verified, report = verify_explainer(
        ExplainerOutput.model_validate(payload), bundles, redactor=redactor
    )
    assert report.clean
    assert verified.hypothesen[0].verified


def test_prosa_erkennung_findet_nur_echte_event_id_nennungen() -> None:
    assert prose_event_ids("Event-ID 1001 und EventID 41") == {1001, 41}
    assert prose_event_ids("Es waren 12 Vorfaelle in 3 Stunden") == set()


def test_falscher_zeitstempel_wird_bemerkt() -> None:
    findings = [f for f in _findings() if f.rule_id == "kernel-power-41"]
    redactor = Redactor()
    bundles = [build_bundle(findings[0], context=CONTEXT, redactor=redactor, kb=None,
                            max_samples=3, excerpt_chars=200)]
    payload = {
        "zusammenfassung": "Test",
        "hypothesen": [
            {
                "aussage": "Etwas geschah.",
                "evidence": [
                    {
                        "provider": bundles[0].provider,
                        "event_id": bundles[0].event_id,
                        "timestamp_utc": datetime(2001, 1, 1, tzinfo=UTC).isoformat(),
                    }
                ],
                "confidence": "hoch",
            }
        ],
        "empfohlene_schritte": [],
    }
    _, report = verify_explainer(ExplainerOutput.model_validate(payload), bundles)
    assert report.statements_rejected == 1
    assert "Zeitstempel" in report.rejected_reasons[0]


# --- Ausfallverhalten --------------------------------------------------------


def test_ohne_ollama_entsteht_der_bericht_trotzdem() -> None:
    layer = AiLayer(AiConfig(), client=FakeClient([], reachable=False))
    result, bundles = layer.run(_findings(), CONTEXT)

    assert result.used is False
    assert result.unavailable_reason is not None
    assert bundles, "die Buendel entstehen auch ohne Modell und bleiben nachvollziehbar"


def test_schemaverstoss_fuehrt_zu_genau_einem_retry_und_dann_zum_rueckfall() -> None:
    client = FakeClient([_fixture("explainer_schemaverstoss.json")] * 4)
    layer = AiLayer(AiConfig(), client=client)
    result, _ = layer.run(_findings()[:1], CONTEXT)

    entry = result.findings[0]
    assert entry.ok is False
    assert entry.note is not None and "Rueckfall" in entry.note
    assert len(client.calls) == 2, "genau ein Retry, nicht mehr"


def test_gueltige_antwort_wird_uebernommen() -> None:
    findings = _findings()[:1]
    client = FakeClient([_fixture("explainer_gut.json")] * 3)
    layer = AiLayer(AiConfig(), client=client)
    result, _ = layer.run(findings, CONTEXT)

    entry = result.findings[0]
    assert entry.ok is True
    assert entry.explanation is not None
    assert entry.explanation.zusammenfassung


def test_cloud_aufruf_ohne_opt_in_wird_blockiert() -> None:
    with pytest.raises(CloudCallBlockedError):
        assert_local("http://ollama.example.com:11434", allow_cloud=False)
    assert_local("http://localhost:11434", allow_cloud=False)
    assert_local("http://ollama.example.com:11434", allow_cloud=True)


def test_ai_layer_meldet_cloud_blockade_statt_zu_werfen() -> None:
    layer = AiLayer(AiConfig(base_url="http://irgendwo.example.com:11434"))
    result, _ = layer.run(_findings(), CONTEXT)
    assert result.used is False
    assert result.unavailable_reason is not None
    assert "allow_cloud" in result.unavailable_reason


def test_schema_enthaelt_keine_pruefungsfelder() -> None:
    """Das Modell soll nicht behaupten koennen, seine Antwort sei geprueft."""
    schema = json_schema_for(ExplainerOutput)
    text = str(schema)
    assert "verified" not in text
    assert "verification_note" not in text
