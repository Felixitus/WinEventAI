"""Knowledge base: inventory (pure evaluation) and migration of old databases."""

from __future__ import annotations

import json
import sqlite3

from wineventai.kb.stats import compute_stats, format_stats
from wineventai.kb.store import KbConfidence, KbEntry, KnowledgeBase


def entry(event_id: int, **fields: object) -> KbEntry:
    values: dict[str, object] = {
        "provider": "Test",
        "event_id": event_id,
        "meaning": "Meaning",
        "typical_causes": ["Cause"],
        "checks": ["Check"],
        "source_url": "https://learn.microsoft.com/",
        "confidence": KbConfidence.VERIFIED,
    }
    values.update(fields)
    return KbEntry(**values)  # type: ignore[arg-type]


def test_a_complete_verified_entry_has_no_gaps() -> None:
    stats = compute_stats([entry(1)])

    assert stats.total == 1
    assert stats.usable_in_prompt == 1
    assert stats.without_meaning == []
    assert stats.without_source == []


def test_gaps_are_listed_by_key_not_just_counted() -> None:
    stats = compute_stats(
        [
            entry(1, meaning=" ", confidence=KbConfidence.EMPTY),
            entry(2, typical_causes=[]),
            entry(3, checks=[]),
        ]
    )

    assert stats.without_meaning == ["Test:1"]
    assert stats.without_causes == ["Test:2"]
    assert stats.without_checks == ["Test:3"]


def test_unverified_entries_do_not_count_as_usable_in_the_prompt() -> None:
    stats = compute_stats([entry(1, confidence=KbConfidence.UNVERIFIED), entry(2)])

    assert stats.usable_in_prompt == 1


def test_verified_without_source_is_reported_as_a_gap() -> None:
    stats = compute_stats([entry(1, source_url=None)])

    assert stats.without_source == ["Test:1"]


def test_confidence_levels_without_entries_appear_with_zero_instead_of_not_at_all() -> None:
    stats = compute_stats([entry(1)])

    assert stats.by_confidence == {"verified": 1, "unverified": 0, "empty": 0}


def test_an_empty_knowledge_base_is_printed_without_division_by_zero() -> None:
    lines = format_stats(compute_stats([]), "C:/kb.sqlite")

    assert "Entries total: 0" in lines
    assert any("Without meaning: none" in line for line in lines)


def test_a_seed_written_with_german_field_names_still_loads() -> None:
    legacy = KbEntry.model_validate(
        {"provider": "P", "event_id": 1, "bedeutung": "B", "typische_ursachen": ["U"],
         "quelle_url": "https://x", "confidence": "sicher"}
    )

    assert legacy.meaning == "B"
    assert legacy.typical_causes == ["U"]
    assert legacy.source_url == "https://x"
    assert legacy.confidence is KbConfidence.VERIFIED


def test_a_pre_2_0_database_is_migrated_and_keeps_own_entries(tmp_path) -> None:
    """The KB on a user's machine has German column names from earlier versions.

    It must be renamed in place - not recreated - so that entries the user
    added by hand survive, and the bundled entries come back in English.
    """
    path = tmp_path / "kb.sqlite"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE kb_entry (
            provider TEXT NOT NULL, event_id INTEGER NOT NULL,
            bedeutung TEXT NOT NULL DEFAULT '', typische_ursachen TEXT NOT NULL DEFAULT '[]',
            checks TEXT NOT NULL DEFAULT '[]', severity_default TEXT, quelle_url TEXT,
            confidence TEXT NOT NULL DEFAULT 'leer', geprueft_am TEXT, geprueft_von TEXT,
            PRIMARY KEY (provider, event_id)
        );
        CREATE VIRTUAL TABLE kb_fts USING fts5(
            provider, event_id UNINDEXED, bedeutung, typische_ursachen, checks,
            content='kb_entry', content_rowid='rowid'
        );
        """
    )
    conn.execute(
        "INSERT INTO kb_entry (provider, event_id, bedeutung, typische_ursachen, confidence) "
        "VALUES (?, ?, ?, ?, ?)",
        ("Own-Provider", 4711, "Eigene Bedeutung", json.dumps(["x"]), "sicher"),
    )
    conn.execute(
        "INSERT INTO kb_entry (provider, event_id, bedeutung, confidence) VALUES (?, ?, ?, ?)",
        ("EventLog", 6008, "Das vorherige Herunterfahren war unerwartet.", "sicher"),
    )
    conn.commit()
    conn.close()

    kb = KnowledgeBase(path)
    try:
        own = kb.get("Own-Provider", 4711)
        assert own is not None, "an entry the user added must survive the migration"
        assert own.meaning == "Eigene Bedeutung"
        assert own.confidence is KbConfidence.VERIFIED

        seeded = kb.get("EventLog", 6008)
        assert seeded is not None
        assert seeded.meaning.startswith("The previous system shutdown"), (
            "bundled entries are reloaded in English"
        )
        assert kb.search("shutdown"), "the full-text index is rebuilt"
    finally:
        kb.close()


def test_store_creation_seed_and_upsert(tmp_path) -> None:
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    try:
        assert kb.count() == 0
        assert kb.load_seed() > 0
        kernel_power = kb.get("Microsoft-Windows-Kernel-Power", 41)
        assert kernel_power is not None and kernel_power.usable_in_prompt

        kb.upsert(entry(9999, meaning="New meaning"))
        assert kb.get("Test", 9999).meaning == "New meaning"
    finally:
        kb.close()
