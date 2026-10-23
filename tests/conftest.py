"""Shared test fixtures.

Two things are ensured process-wide here:

1. **No network access.** An ``autouse`` fixture patches ``socket.socket`` so
   that every connection attempt fails the test. Without it an accidental call
   against a locally running Ollama goes unnoticed - it works on the
   development machine and fails in CI.
2. **No access to %LOCALAPPDATA%.** Configuration, rule overlay and knowledge
   base go into a temporary directory per test run.
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
    """A test tried to use the network."""


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _blocked(*args: object, **kwargs: object) -> None:
        raise NetworkAccessInTest(
            "Tests must not use the network. The AI layer is mocked."
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
    """A run directory, filled from the real NDJSON fixtures."""
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
                note=None if status is SourceStatus.COLLECTED else "Time limit reached.",
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
