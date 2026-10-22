"""Local knowledge base as SQLite with FTS5.

The key is ``(provider, event_id)`` - never ``event_id`` alone. Event ids are
only unique per provider; 1000 exists dozens of times. A table with
``event_id`` as primary key would be the first bug.

``confidence`` has a consequence in the code, not only in the text: an entry
without a verified meaning is NOT embedded in the prompt, and the finding
appears in the report with the note "no verified meaning on record".
"""

from __future__ import annotations

import json
import sqlite3
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..applog import get_log
from ..resources import program_data_dir, resource_path

SEED_RESOURCE = "kb/seed.yaml"
DB_NAME = "kb.sqlite"

SCHEMA = """
CREATE TABLE IF NOT EXISTS kb_entry (
    provider        TEXT NOT NULL,
    event_id        INTEGER NOT NULL,
    meaning         TEXT NOT NULL DEFAULT '',
    typical_causes  TEXT NOT NULL DEFAULT '[]',
    checks          TEXT NOT NULL DEFAULT '[]',
    severity_default TEXT,
    source_url      TEXT,
    confidence      TEXT NOT NULL DEFAULT 'empty',
    checked_on      TEXT,
    checked_by      TEXT,
    PRIMARY KEY (provider, event_id)
);

CREATE VIRTUAL TABLE IF NOT EXISTS kb_fts USING fts5(
    provider, event_id UNINDEXED, meaning, typical_causes, checks,
    content='kb_entry', content_rowid='rowid'
);
"""

#: Column names of databases created before version 2.0.
_LEGACY_COLUMNS: dict[str, str] = {
    "bedeutung": "meaning",
    "typische_ursachen": "typical_causes",
    "quelle_url": "source_url",
    "geprueft_am": "checked_on",
    "geprueft_von": "checked_by",
}

#: Confidence values of databases and seed files created before version 2.0.
_LEGACY_CONFIDENCE: dict[str, str] = {
    "sicher": "verified",
    "unsicher": "unverified",
    "leer": "empty",
}


class KbConfidence(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    EMPTY = "empty"

    @classmethod
    def _missing_(cls, value: object) -> KbConfidence | None:
        if isinstance(value, str):
            current = _LEGACY_CONFIDENCE.get(value.strip().lower())
            if current is not None:
                return cls(current)
        return None


class KbEntry(BaseModel):
    """One entry of the knowledge base."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    event_id: int
    meaning: str = ""
    typical_causes: list[str] = Field(default_factory=list)
    checks: list[str] = Field(default_factory=list)
    severity_default: str | None = None
    source_url: str | None = None
    confidence: KbConfidence = KbConfidence.EMPTY
    checked_on: str | None = None
    checked_by: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _legacy_field_names(cls, data: Any) -> Any:
        """Accepts the German field names of seed files written before 2.0."""
        if not isinstance(data, dict):
            return data
        renamed = dict(data)
        for old, new in _LEGACY_COLUMNS.items():
            if old in renamed and new not in renamed:
                renamed[new] = renamed.pop(old)
        return renamed

    @property
    def key(self) -> str:
        return f"{self.provider}:{self.event_id}"

    @property
    def usable_in_prompt(self) -> bool:
        """Only verified entries go into the prompt.

        An unverified entry in the context would be worse than none at all: the
        model would treat it as fact.
        """
        return self.confidence is KbConfidence.VERIFIED and bool(self.meaning.strip())


class KnowledgeBase:
    """Access to the knowledge base."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        migrated = self._migrate_legacy_schema()
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        if migrated:
            # The bundled entries were German before 2.0. Reloading the seed
            # replaces exactly those keys; entries a user added stay as they are.
            self._rebuild_fts()
            self.load_seed()
            get_log().info("Knowledge base migrated to the 2.0 schema", path=str(self.path))

    def _migrate_legacy_schema(self) -> bool:
        """Renames the German columns of a pre-2.0 database in place.

        Returns True if a migration took place. Renaming instead of recreating
        keeps entries the user added by hand.
        """
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(kb_entry)")}
        if "bedeutung" not in columns:
            return False
        # The FTS table references the old column names; it is rebuilt below.
        self._conn.execute("DROP TABLE IF EXISTS kb_fts")
        for old, new in _LEGACY_COLUMNS.items():
            if old in columns:
                self._conn.execute(f"ALTER TABLE kb_entry RENAME COLUMN {old} TO {new}")
        for old, new in _LEGACY_CONFIDENCE.items():
            self._conn.execute(
                "UPDATE kb_entry SET confidence = ? WHERE confidence = ?", (new, old)
            )
        self._conn.commit()
        return True

    # --- Management ----------------------------------------------------------

    @classmethod
    def default_path(cls) -> Path:
        return program_data_dir() / DB_NAME

    @classmethod
    def open_default(cls, *, seed_if_empty: bool = True) -> KnowledgeBase:
        """Opens the knowledge base and creates it on first start.

        The database is materialized in %PROGRAMDATA% and not kept in the
        package directory: a SQLite file in ``sys._MEIPASS`` is read-only, and
        that is exactly where such tools otherwise fail at the first attempt to
        maintain it.
        """
        kb = cls(cls.default_path())
        if seed_if_empty and kb.count() == 0:
            kb.load_seed()
        return kb

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> KnowledgeBase:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- Writing -------------------------------------------------------------

    def upsert(self, entry: KbEntry) -> None:
        self._conn.execute(
            """
            INSERT INTO kb_entry (provider, event_id, meaning, typical_causes, checks,
                                  severity_default, source_url, confidence, checked_on,
                                  checked_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider, event_id) DO UPDATE SET
                meaning = excluded.meaning,
                typical_causes = excluded.typical_causes,
                checks = excluded.checks,
                severity_default = excluded.severity_default,
                source_url = excluded.source_url,
                confidence = excluded.confidence,
                checked_on = excluded.checked_on,
                checked_by = excluded.checked_by
            """,
            (
                entry.provider,
                entry.event_id,
                entry.meaning,
                json.dumps(entry.typical_causes, ensure_ascii=False),
                json.dumps(entry.checks, ensure_ascii=False),
                entry.severity_default,
                entry.source_url,
                str(entry.confidence),
                entry.checked_on,
                entry.checked_by,
            ),
        )
        self._rebuild_fts()
        self._conn.commit()

    def _rebuild_fts(self) -> None:
        self._conn.execute("INSERT INTO kb_fts(kb_fts) VALUES('rebuild')")

    def load_seed(self, path: Path | None = None) -> int:
        """Loads the bundled verified entries."""
        source = path or resource_path(SEED_RESOURCE)
        payload = yaml.safe_load(source.read_text(encoding="utf-8")) or []
        count = 0
        for raw in payload:
            self.upsert(KbEntry.model_validate(raw))
            count += 1
        return count

    # --- Reading -------------------------------------------------------------

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM kb_entry").fetchone()
        return int(row["n"])

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> KbEntry:
        return KbEntry(
            provider=row["provider"],
            event_id=row["event_id"],
            meaning=row["meaning"],
            typical_causes=json.loads(row["typical_causes"]),
            checks=json.loads(row["checks"]),
            severity_default=row["severity_default"],
            source_url=row["source_url"],
            confidence=KbConfidence(row["confidence"]),
            checked_on=row["checked_on"],
            checked_by=row["checked_by"],
        )

    def get(self, provider: str, event_id: int) -> KbEntry | None:
        row = self._conn.execute(
            "SELECT * FROM kb_entry WHERE provider = ? AND event_id = ?",
            (provider, event_id),
        ).fetchone()
        return self._row_to_entry(row) if row else None

    def all_entries(self) -> list[KbEntry]:
        rows = self._conn.execute(
            "SELECT * FROM kb_entry ORDER BY provider, event_id"
        ).fetchall()
        return [self._row_to_entry(row) for row in rows]

    def search(self, query: str, limit: int = 5) -> list[KbEntry]:
        """Full-text search via FTS5.

        No vector index - for twenty to a few hundred entries that would be
        overkill, and an additional model for embeddings would contradict the
        offline principle.
        """
        cleaned = " ".join(part for part in query.replace('"', " ").split() if part)
        if not cleaned:
            return []
        try:
            rows = self._conn.execute(
                """
                SELECT kb_entry.* FROM kb_fts
                JOIN kb_entry ON kb_entry.rowid = kb_fts.rowid
                WHERE kb_fts MATCH ?
                LIMIT ?
                """,
                (cleaned, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        return [self._row_to_entry(row) for row in rows]

    def mark_checked(self, provider: str, event_id: int, by: str) -> None:
        self._conn.execute(
            "UPDATE kb_entry SET checked_on = ?, checked_by = ? "
            "WHERE provider = ? AND event_id = ?",
            (date.today().isoformat(), by, provider, event_id),
        )
        self._conn.commit()
