"""Evidenz-Bundle, Laufverzeichnis, Konfiguration und Wissensbasis."""

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

# --- Konfiguration -----------------------------------------------------------


def test_vorgaben_lassen_sich_laden() -> None:
    config = load_config()
    assert config.collect.days == 7
    assert config.collect.max_retained_per_channel == 200_000
    assert config.ai.base_url.startswith("http://localhost")
    assert config.ai.allow_cloud is False


def test_eigene_datei_ueberschreibt_nur_das_genannte(tmp_path) -> None:
    path = tmp_path / "eigene.yaml"
    path.write_text(yaml.safe_dump({"collect": {"days": 30}}), encoding="utf-8")
    config = load_config(path)
    assert config.collect.days == 30
    assert config.collect.max_retained_per_channel == 200_000, "der Rest bleibt Vorgabe"


def test_unbekannter_schluessel_wird_abgelehnt(tmp_path) -> None:
    """Ein Tippfehler in der YAML darf nicht still wirkungslos bleiben."""
    path = tmp_path / "tippfehler.yaml"
    path.write_text(yaml.safe_dump({"collect": {"dayz": 30}}), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(path)


def test_listen_werden_ersetzt_nicht_verschmolzen() -> None:
    merged = _deep_merge({"a": [1, 2, 3], "b": {"x": 1}}, {"a": [9], "b": {"y": 2}})
    assert merged["a"] == [9]
    assert merged["b"] == {"x": 1, "y": 2}


def test_security_kanal_ist_per_default_aus() -> None:
    config = load_config()
    security = config.channel("Security")
    assert security is not None
    assert security.enabled is False
    assert security.event_ids, "Security wird nie ungefiltert gelesen"
    assert security.requires_admin is True


# --- Ressourcen --------------------------------------------------------------


def test_alle_mitgelieferten_ressourcen_sind_auffindbar() -> None:
    for name in (
        "config/wineventai.default.yaml",
        "collect/scripts/get_events.ps1",
        "collect/scripts/list_channels.ps1",
        "rules/builtin/core_system.yaml",
        "kb/seed.yaml",
        "ai/prompts/explainer.de.txt",
        "report/templates/bericht.html.j2",
        "report/assets/bericht.css",
    ):
        assert resource_path(name).is_file(), name


def test_fehlende_ressource_wirft_klar() -> None:
    with pytest.raises(FileNotFoundError):
        resource_path("gibt/es/nicht.txt")


# --- Wissensbasis ------------------------------------------------------------


def test_schluessel_ist_provider_und_event_id(tmp_path) -> None:
    """1000 existiert dutzendfach - event_id allein waere der erste Bug."""
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.upsert(KbEntry(provider="Application Error", event_id=1000, bedeutung="A",
                      confidence=KbConfidence.SICHER))
    kb.upsert(KbEntry(provider="MsiInstaller", event_id=1000, bedeutung="B",
                      confidence=KbConfidence.SICHER))

    assert kb.count() == 2
    assert kb.get("Application Error", 1000).bedeutung == "A"
    assert kb.get("MsiInstaller", 1000).bedeutung == "B"


def test_seed_enthaelt_absichtlich_ungepruefte_eintraege() -> None:
    kb = KnowledgeBase.open_default()
    ungeprueft = [
        entry for entry in kb.all_entries() if entry.confidence is not KbConfidence.SICHER
    ]
    assert ungeprueft, (
        "die Wissensbasis muss Luecken zeigen duerfen, statt sie plausibel zu fuellen"
    )
    assert all(not entry.usable_in_prompt for entry in ungeprueft)


def test_volltextsuche_findet_eintraege() -> None:
    kb = KnowledgeBase.open_default()
    assert kb.search("Stoppfehler")


def test_arbeitsliste_nennt_paare_ohne_gesicherten_eintrag(tmp_path) -> None:
    kb = KnowledgeBase(tmp_path / "kb.sqlite")
    kb.upsert(KbEntry(provider="Bekannt", event_id=1, bedeutung="X",
                      confidence=KbConfidence.SICHER))
    stream = [
        make_record(minutes_ago=1, provider="Bekannt", event_id=1, properties=["a"]),
        make_record(minutes_ago=2, provider="Unbekannt", event_id=42, properties=["b"]),
    ]
    rows = collect_unknown(Enricher(window_hours=168).consume(stream), kb)

    assert [row["provider"] for row in rows] == ["Unbekannt"]

    target = write_unknown_csv(tmp_path / "unknown_ids.csv", rows)
    text = target.read_text(encoding="utf-8-sig")
    assert "Unbekannt" in text and "provider;event_id" in text


# --- Evidenz -----------------------------------------------------------------


def test_bundle_enthaelt_manifest_und_pruefskript(fixture_run) -> None:
    analyze_run(fixture_run, load_config(overrides={"ai": {"enabled": False}}))
    target = fixture_run.path / "evidenz.zip"
    build_bundle(fixture_run, target)

    with zipfile.ZipFile(target) as archive:
        names = archive.namelist()
        assert "manifest.json" in names
        assert "verify.ps1" in names
        assert any(name.startswith("bericht/") for name in names)
        manifest = json.loads(archive.read("manifest.json"))

    assert manifest["host"]
    assert manifest["ausfuehrendes_konto"]
    assert manifest["kommandozeile"]
    assert manifest["utc_versatz_minuten"] is not None
    assert manifest["redigiert"] is False
    assert "NICHT pseudonymisiert" in manifest["hinweis"]


def test_manifest_fuehrt_pruefsummen_je_datei(fixture_run) -> None:
    analyze_run(fixture_run, load_config(overrides={"ai": {"enabled": False}}))
    target = fixture_run.path / "evidenz.zip"
    build_bundle(fixture_run, target)

    with zipfile.ZipFile(target) as archive:
        manifest = json.loads(archive.read("manifest.json"))

    bericht = next(
        entry for entry in manifest["dateien"] if entry["name"].startswith("bericht/")
    )
    assert len(bericht["sha256"]) == 64
    assert bericht["size_b"] > 0


def test_fehlende_datei_steht_mit_grund_im_manifest(fixture_run) -> None:
    """Statt eines leeren ZIP, das Vollstaendigkeit vortaeuscht."""
    target = fixture_run.path / "evidenz.zip"
    fehlend = fixture_run.path / "evtx" / "Security.evtx"
    build_bundle(fixture_run, target, evtx_files=[(fehlend, "Export fehlgeschlagen")])

    with zipfile.ZipFile(target) as archive:
        manifest = json.loads(archive.read("manifest.json"))

    eintrag = next(entry for entry in manifest["dateien"] if "Security.evtx" in entry["name"])
    assert eintrag["sha256"] == ""
    assert eintrag["hinweis"]


def test_hashfunktion_arbeitet_auf_dateien(tmp_path) -> None:
    path = tmp_path / "x.bin"
    path.write_bytes(b"abc")
    assert sha256_file(path) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
