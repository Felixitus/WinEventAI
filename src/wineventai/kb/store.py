"""Lokale Wissensbasis als SQLite mit FTS5.

Der Schluessel ist ``(provider, event_id)`` - niemals ``event_id`` allein.
Event-IDs sind nur je Provider eindeutig; 1000 existiert dutzendfach. Eine
Tabelle mit ``event_id`` als Primaerschluessel waere der erste Bug.

``confidence`` hat eine Konsequenz im Code, nicht nur im Text: Ein Eintrag ohne
gesicherte Bedeutung wird NICHT in den Prompt eingebettet, und der Befund
erscheint im Bericht mit dem Vermerk "keine gesicherte Bedeutung hinterlegt".
"""

from __future__ import annotations

import json
import sqlite3
from datetime import date
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ..resources import program_data_dir, resource_path

SEED_RESOURCE = "kb/seed.yaml"
DB_NAME = "kb.sqlite"

SCHEMA = """
CREATE TABLE IF NOT EXISTS kb_entry (
    provider        TEXT NOT NULL,
    event_id        INTEGER NOT NULL,
    bedeutung       TEXT NOT NULL DEFAULT '',
    typische_ursachen TEXT NOT NULL DEFAULT '[]',
    checks          TEXT NOT NULL DEFAULT '[]',
    severity_default TEXT,
    quelle_url      TEXT,
    confidence      TEXT NOT NULL DEFAULT 'leer',
    geprueft_am     TEXT,
    geprueft_von    TEXT,
    PRIMARY KEY (provider, event_id)
);

CREATE VIRTUAL TABLE IF NOT EXISTS kb_fts USING fts5(
    provider, event_id UNINDEXED, bedeutung, typische_ursachen, checks,
    content='kb_entry', content_rowid='rowid'
);
"""


class KbConfidence(StrEnum):
    SICHER = "sicher"
    UNSICHER = "unsicher"
    LEER = "leer"


class KbEntry(BaseModel):
    """Ein Eintrag der Wissensbasis."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    event_id: int
    bedeutung: str = ""
    typische_ursachen: list[str] = Field(default_factory=list)
    checks: list[str] = Field(default_factory=list)
    severity_default: str | None = None
    quelle_url: str | None = None
    confidence: KbConfidence = KbConfidence.LEER
    geprueft_am: str | None = None
    geprueft_von: str | None = None

    @property
    def key(self) -> str:
        return f"{self.provider}:{self.event_id}"

    @property
    def usable_in_prompt(self) -> bool:
        """Nur gesicherte Eintraege gehen in den Prompt.

        Ein unsicherer Eintrag im Kontext waere schlimmer als gar keiner: Das
        Modell wuerde ihn als Tatsache behandeln.
        """
        return self.confidence is KbConfidence.SICHER and bool(self.bedeutung.strip())


class KnowledgeBase:
    """Zugriff auf die Wissensbasis."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # --- Verwaltung ----------------------------------------------------------

    @classmethod
    def default_path(cls) -> Path:
        return program_data_dir() / DB_NAME

    @classmethod
    def open_default(cls, *, seed_if_empty: bool = True) -> KnowledgeBase:
        """Oeffnet die Wissensbasis und legt sie beim ersten Start an.

        Die Datenbank wird nach %PROGRAMDATA% materialisiert und nicht im
        Paketverzeichnis gehalten: Eine SQLite-Datei in ``sys._MEIPASS`` ist
        schreibgeschuetzt, und genau daran scheitern solche Werkzeuge sonst beim
        ersten Pflegeversuch.
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

    # --- Schreiben -----------------------------------------------------------

    def upsert(self, entry: KbEntry) -> None:
        self._conn.execute(
            """
            INSERT INTO kb_entry (provider, event_id, bedeutung, typische_ursachen, checks,
                                  severity_default, quelle_url, confidence, geprueft_am,
                                  geprueft_von)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider, event_id) DO UPDATE SET
                bedeutung = excluded.bedeutung,
                typische_ursachen = excluded.typische_ursachen,
                checks = excluded.checks,
                severity_default = excluded.severity_default,
                quelle_url = excluded.quelle_url,
                confidence = excluded.confidence,
                geprueft_am = excluded.geprueft_am,
                geprueft_von = excluded.geprueft_von
            """,
            (
                entry.provider,
                entry.event_id,
                entry.bedeutung,
                json.dumps(entry.typische_ursachen, ensure_ascii=False),
                json.dumps(entry.checks, ensure_ascii=False),
                entry.severity_default,
                entry.quelle_url,
                str(entry.confidence),
                entry.geprueft_am,
                entry.geprueft_von,
            ),
        )
        self._rebuild_fts()
        self._conn.commit()

    def _rebuild_fts(self) -> None:
        self._conn.execute("INSERT INTO kb_fts(kb_fts) VALUES('rebuild')")

    def load_seed(self, path: Path | None = None) -> int:
        """Laedt die mitgelieferten geprueften Eintraege."""
        source = path or resource_path(SEED_RESOURCE)
        payload = yaml.safe_load(source.read_text(encoding="utf-8")) or []
        count = 0
        for raw in payload:
            self.upsert(KbEntry.model_validate(raw))
            count += 1
        return count

    # --- Lesen ---------------------------------------------------------------

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM kb_entry").fetchone()
        return int(row["n"])

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> KbEntry:
        return KbEntry(
            provider=row["provider"],
            event_id=row["event_id"],
            bedeutung=row["bedeutung"],
            typische_ursachen=json.loads(row["typische_ursachen"]),
            checks=json.loads(row["checks"]),
            severity_default=row["severity_default"],
            quelle_url=row["quelle_url"],
            confidence=KbConfidence(row["confidence"]),
            geprueft_am=row["geprueft_am"],
            geprueft_von=row["geprueft_von"],
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
        """Volltextsuche ueber FTS5.

        Kein Vektorindex - fuer zwanzig bis wenige hundert Eintraege waere das
        ueberzogen, und ein zusaetzliches Modell fuer Einbettungen widerspraeche
        dem Offline-Gedanken.
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
            "UPDATE kb_entry SET geprueft_am = ?, geprueft_von = ? "
            "WHERE provider = ? AND event_id = ?",
            (date.today().isoformat(), by, provider, event_id),
        )
        self._conn.commit()
