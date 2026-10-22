"""Gemeinsame Test-Vorrichtungen.

Zwei Dinge werden hier prozessweit sichergestellt:

1. **Kein Netzzugriff.** Eine ``autouse``-Fixture patcht ``socket.socket`` so,
   dass jeder Verbindungsversuch den Test scheitern laesst. Ohne das faellt ein
   versehentlicher Aufruf gegen ein lokal laufendes Ollama nicht auf - er
   funktioniert dann auf dem Entwicklungsrechner und schlaegt in CI fehl.
2. **Kein Zugriff auf %PROGRAMDATA%.** Konfiguration, Regel-Overlay und
   Wissensbasis landen in einem temporaeren Verzeichnis je Testlauf.
"""

from __future__ import annotations

import socket
from datetime import timedelta
from pathlib import Path

import pytest

from helpers import FIXTURES, WINDOW_END, WINDOW_START
from wineventai.collect.base import SourceResult, SourceStatus
from wineventai.collect.rundir import RunDirectory


class NetworkAccessInTest(RuntimeError):
    """Ein Test hat versucht, das Netz zu benutzen."""


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _blocked(*args: object, **kwargs: object) -> None:
        raise NetworkAccessInTest(
            "Tests duerfen nicht ins Netz. Der KI-Layer wird gemockt."
        )

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)


@pytest.fixture(autouse=True)
def _isolated_data_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> Path:
    directory = tmp_path_factory.mktemp("programdata")
    monkeypatch.setenv("WINEVENTAI_DATA_DIR", str(directory))
    return directory


@pytest.fixture
def fixture_run(tmp_path: Path) -> RunDirectory:
    """Ein Laufverzeichnis, gefuellt aus den echten NDJSON-Fixtures."""
    run = RunDirectory.create(
        root=tmp_path / "runs",
        requested_from=WINDOW_START,
        requested_to=WINDOW_END,
        security_mode=True,
    )
    results: list[SourceResult] = []
    for name, status, covered_from in (
        ("System", SourceStatus.COLLECTED, WINDOW_START),
        ("Application", SourceStatus.COLLECTED, WINDOW_START),
        ("Security", SourceStatus.TIMED_OUT, WINDOW_END - timedelta(days=1, hours=3)),
    ):
        source_id = f"channel:{name}"
        target = run.raw_path(source_id)
        target.write_bytes((FIXTURES / "ndjson" / f"channel_{name}.ndjson").read_bytes())
        results.append(
            SourceResult(
                source_id=source_id,
                status=status,
                requested_from_utc=WINDOW_START,
                requested_to_utc=WINDOW_END,
                covered_from_utc=covered_from,
                covered_to_utc=WINDOW_END,
                records_read=1000,
                records_retained=1000,
                note=None if status is SourceStatus.COLLECTED else "Zeitlimit erreicht.",
            )
        )
    results.append(
        SourceResult(
            source_id="cim:Win32_ReliabilityRecords",
            status=SourceStatus.NOT_LOGGED,
            requested_from_utc=WINDOW_START,
            requested_to_utc=WINDOW_END,
            note="RacTask: disabled.",
        )
    )
    run.write_sources(results)
    return run
