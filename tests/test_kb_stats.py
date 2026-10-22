"""Bestandsaufnahme der Wissensbasis - reine Auswertung, keine Datenbank."""

from __future__ import annotations

from wineventai.kb.stats import compute_stats, format_stats
from wineventai.kb.store import KbConfidence, KbEntry


def entry(event_id: int, **fields: object) -> KbEntry:
    values: dict[str, object] = {
        "provider": "Test",
        "event_id": event_id,
        "bedeutung": "Bedeutung",
        "typische_ursachen": ["Ursache"],
        "checks": ["Pruefung"],
        "quelle_url": "https://learn.microsoft.com/",
        "confidence": KbConfidence.SICHER,
    }
    values.update(fields)
    return KbEntry(**values)  # type: ignore[arg-type]


def test_vollstaendiger_sicherer_eintrag_hat_keine_luecken() -> None:
    stats = compute_stats([entry(1)])

    assert stats.total == 1
    assert stats.usable_in_prompt == 1
    assert stats.without_meaning == []
    assert stats.without_source == []


def test_luecken_werden_mit_schluessel_gelistet_nicht_nur_gezaehlt() -> None:
    stats = compute_stats(
        [
            entry(1, bedeutung=" ", confidence=KbConfidence.LEER),
            entry(2, typische_ursachen=[]),
            entry(3, checks=[]),
        ]
    )

    assert stats.without_meaning == ["Test:1"]
    assert stats.without_causes == ["Test:2"]
    assert stats.without_checks == ["Test:3"]


def test_unsichere_eintraege_zaehlen_nicht_als_im_prompt_verwendbar() -> None:
    stats = compute_stats([entry(1, confidence=KbConfidence.UNSICHER), entry(2)])

    assert stats.usable_in_prompt == 1


def test_sicher_ohne_quellenangabe_wird_als_luecke_gemeldet() -> None:
    stats = compute_stats([entry(1, quelle_url=None)])

    assert stats.without_source == ["Test:1"]


def test_vertrauensstufen_ohne_eintrag_erscheinen_mit_null_statt_gar_nicht() -> None:
    stats = compute_stats([entry(1)])

    assert stats.by_confidence == {"sicher": 1, "unsicher": 0, "leer": 0}


def test_leere_wissensbasis_wird_ohne_division_durch_null_ausgegeben() -> None:
    lines = format_stats(compute_stats([]), "C:/kb.sqlite")

    assert "Eintraege gesamt: 0" in lines
    assert any("Ohne Bedeutung: keine" in line for line in lines)
