"""Evidence bundle, run directory, configuration and knowledge base."""

from __future__ import annotations

import json
import zipfile

import pytest
import yaml
from pydantic import ValidationError

from helpers import make_record
from wineventai.analyze import analyze_run
from wineventai.config import load_config
from wineventai.config.loader import _deep_merge
from wineventai.enrich.aggregate import Enricher
from wineventai.evidence.bundle import build_bundle, sha256_file
from wineventai.kb.store import KbConfidence, KbEntry, KnowledgeBase
from wineventai.kb.unknown import collect_unknown, write_unknown_csv
from wineventai.resources import resource_path

# --- Configuration -----------------------------------------------------------


def test_the_defaults_can_be_loaded() -> None:
    config = load_config()
    assert config.collect.days == 7
    assert config.collect.max_retained_per_channel == 200_000
    assert config.ai.base_url.startswith("http://localhost")
    assert config.ai.allow_cloud is False


def test_an_own_file_overrides_only_what_it_names(tmp_path) -> None:
    path = tmp_path / "own.yaml"
    path.write_text(yaml.safe_dump({"collect": {"days": 30}}), encoding="utf-8")
    config = load_config(path)
    assert config.collect.days == 30
    assert config.collect.max_retained_per_channel == 200_000, "the rest stays default"


def test_an_unknown_key_is_rejected(tmp_path) -> None:
    """A typo in the YAML must not silently have no effect."""
    path = tmp_path / "typo.yaml"
    path.write_text(yaml.safe_dump({"collect": {"dayz": 30}}), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(path)


def test_lists_are_replaced_not_merged() -> None:
    merged = _deep_merge({"a": [1, 2, 3], "b": {"x": 1}}, {"a": [9], "b": {"y": 2}})
    assert merged["a"] == [9]
    assert merged["b"] == {"x": 1, "y": 2}


def test_the_security_channel_is_off_by_default() -> None:
    config = load_config()
    security = config.channel("Security")
    assert security is not None
    assert security.enabled is False
    assert security.event_ids, "Security is never read unfiltered"
    assert security.requires_admin is True


# --- Resources ---------------------------------------------------------------


def test_all_bundled_resources_can_be_found() -> None:
    for name in (
        "config/wineventai.default.yaml",
        "collect/scripts/get_events.ps1",
        "collect/scripts/list_channels.ps1",
        "collect/scripts/sweep_errors.ps1",
        "rules/builtin/core_system.yaml",
        "kb/seed.yaml",
        "ai/prompts/explainer.en.txt",
        "ai/prompts/correlator.en.txt",
        "report/templates/report.html.j2",
        "report/assets/report.css",
    ):
        assert resource_path(name).is_file(), name


def test_a_missing_resource_raises_clearly() -> None:
    with pytest.raises(FileNotFoundError):
        resource_path("does/not/exist.txt")


# --- Knowledge base ----------------------------------------------------------


def test_the_key_is_provider_and_event_id(tmp_path) -> None:
    """1000 exists dozens of times - event_id alone would be the first bug."""
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.upsert(KbEntry(provider="Application Error", event_id=1000, meaning="A",
                      confidence=KbConfidence.VERIFIED))
    kb.upsert(KbEntry(provider="MsiInstaller", event_id=1000, meaning="B",
                      confidence=KbConfidence.VERIFIED))

    assert kb.count() == 2
    assert kb.get("Application Error", 1000).meaning == "A"
    assert kb.get("MsiInstaller", 1000).meaning == "B"


def test_the_seed_contains_deliberately_unverified_entries() -> None:
    kb = KnowledgeBase.open_default()
    unverified = [
        entry for entry in kb.all_entries() if entry.confidence is not KbConfidence.VERIFIED
    ]
    assert unverified, (
        "the knowledge base must be allowed to show gaps instead of filling them plausibly"
    )
    assert all(not entry.usable_in_prompt for entry in unverified)


def test_full_text_search_finds_entries() -> None:
    kb = KnowledgeBase.open_default()
    assert kb.search("stop error")


def test_the_work_list_names_pairs_without_a_verified_entry(tmp_path) -> None:
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.upsert(KbEntry(provider="Known", event_id=1, meaning="X",
                      confidence=KbConfidence.VERIFIED))
    stream = [
        make_record(minutes_ago=1, provider="Known", event_id=1, properties=["a"]),
        make_record(minutes_ago=2, provider="Unknown", event_id=42, properties=["b"]),
    ]
    rows = collect_unknown(Enricher(window_hours=168).consume(stream), kb)

    assert [row["provider"] for row in rows] == ["Unknown"]

    target = write_unknown_csv(tmp_path / "unknown_ids.csv", rows)
    text = target.read_text(encoding="utf-8-sig")
    assert "Unknown" in text and "provider;event_id" in text


# --- Evidence ----------------------------------------------------------------


def test_the_bundle_contains_manifest_and_verification_script(fixture_run) -> None:
    analyze_run(fixture_run, load_config(overrides={"ai": {"enabled": False}}))
    target = fixture_run.path / "evidence.zip"
    build_bundle(fixture_run, target)

    with zipfile.ZipFile(target) as archive:
        names = archive.namelist()
        assert "manifest.json" in names
        assert "verify.ps1" in names
        assert any(name.startswith("report/") for name in names)
        manifest = json.loads(archive.read("manifest.json"))

    assert manifest["host"]
    assert manifest["executing_account"]
    assert manifest["command_line"]
    assert manifest["utc_offset_minutes"] is not None
    assert manifest["redacted"] is False
    assert "NOT pseudonymized" in manifest["note"]


def test_the_manifest_keeps_checksums_per_file(fixture_run) -> None:
    analyze_run(fixture_run, load_config(overrides={"ai": {"enabled": False}}))
    target = fixture_run.path / "evidence.zip"
    build_bundle(fixture_run, target)

    with zipfile.ZipFile(target) as archive:
        manifest = json.loads(archive.read("manifest.json"))

    report = next(
        entry for entry in manifest["files"] if entry["name"].startswith("report/")
    )
    assert len(report["sha256"]) == 64
    assert report["size_b"] > 0


def test_a_missing_file_appears_with_its_reason_in_the_manifest(fixture_run) -> None:
    """Instead of an empty ZIP that feigns completeness."""
    target = fixture_run.path / "evidence.zip"
    missing = fixture_run.path / "evtx" / "Security.evtx"
    build_bundle(fixture_run, target, evtx_files=[(missing, "export failed")])

    with zipfile.ZipFile(target) as archive:
        manifest = json.loads(archive.read("manifest.json"))

    entry = next(entry for entry in manifest["files"] if "Security.evtx" in entry["name"])
    assert entry["sha256"] == ""
    assert entry["note"]


def test_the_hash_function_works_on_files(tmp_path) -> None:
    path = tmp_path / "x.bin"
    path.write_bytes(b"abc")
    assert sha256_file(path) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
