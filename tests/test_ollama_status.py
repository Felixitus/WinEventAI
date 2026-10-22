"""Erreichbarkeit von Ollama: Dienst laeuft nicht ist etwas anderes als Modell fehlt.

Bis 1.0.0 wurden beide Faelle in eine Meldung gepresst - ein nicht
heruntergeladenes Modell meldete sich als "nicht erreichbar" und schickte Leute
auf die Suche nach einem Netzwerkproblem, das es nicht gab. Diese Tests halten
die Unterscheidung fest.
"""

from __future__ import annotations

import os

import pytest

from wineventai.ai.client import (
    HttpStatusError,
    OllamaClient,
    OllamaStatus,
    OllamaUnavailableError,
)


def _proxies_in_use(client: OllamaClient) -> dict[str, str]:
    """Welche Proxies der Opener dieses Clients tatsaechlich verwenden wuerde."""
    for handler in client._opener().handlers:
        if type(handler).__name__ == "ProxyHandler":
            return dict(getattr(handler, "proxies", {}))
    return {}


def _client(**kwargs: object) -> OllamaClient:
    defaults: dict[str, object] = {"model": "qwen2.5:14b-instruct", "timeout_seconds": 5.0}
    defaults.update(kwargs)
    return OllamaClient(**defaults)  # type: ignore[arg-type]


def test_dienst_laeuft_nicht(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    monkeypatch.setattr(
        client, "list_models",
        lambda: (_ for _ in ()).throw(OllamaUnavailableError("Connection refused")),
    )
    state = client.status()

    assert state.reachable is False
    assert state.usable is False
    assert "nicht erreichbar" in state.message(client.base_url, client.model)


def test_dienst_laeuft_aber_modell_fehlt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Der Fall, der frueher falsch gemeldet wurde."""
    client = _client()
    monkeypatch.setattr(client, "list_models", lambda: ["llama3.1:8b", "mistral:latest"])
    state = client.status()

    assert state.reachable is True
    assert state.model_present is False
    assert state.usable is False

    text = state.message(client.base_url, client.model)
    assert "nicht erreichbar" not in text, (
        "ein laufender Dienst darf nie als unerreichbar gemeldet werden"
    )
    assert "ollama pull" in text
    assert "llama3.1:8b" in text, "die vorhandenen Modelle gehoeren in die Meldung"


def test_modell_vorhanden(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    monkeypatch.setattr(client, "list_models", lambda: ["qwen2.5:14b-instruct"])
    assert client.status().usable is True
    assert client.unavailable_reason() is None


def test_modell_ohne_tag_trifft_latest(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ollama fuehrt Modelle als name:tag; ohne Tag gilt implizit :latest."""
    client = _client(model="mistral")
    monkeypatch.setattr(client, "list_models", lambda: ["mistral:latest"])
    assert client.status().usable is True


def test_falscher_tag_gilt_nicht_als_treffer(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(model="qwen2.5:14b-instruct")
    monkeypatch.setattr(client, "list_models", lambda: ["qwen2.5:7b-instruct"])
    assert client.status().model_present is False


def test_http_fehler_bedeutet_laeuft_aber(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wer mit einem Fehlercode antwortet, laeuft."""
    client = _client()
    monkeypatch.setattr(
        client, "list_models",
        lambda: (_ for _ in ()).throw(HttpStatusError(404, "/api/tags")),
    )
    state = client.status()
    assert state.reachable is True
    assert state.model_present is False


def test_status_wird_zwischengespeichert(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def fake() -> list[str]:
        calls["n"] += 1
        return ["qwen2.5:14b-instruct"]

    client = _client()
    monkeypatch.setattr(client, "list_models", fake)
    client.status()
    client.status()
    assert calls["n"] == 1, "die Pruefung darf nicht bei jedem Aufruf erneut laufen"
    client.status(refresh=True)
    assert calls["n"] == 2


def test_proxy_wird_fuer_localhost_umgangen(monkeypatch: pytest.MonkeyPatch) -> None:
    """Auf Firmenrechnern die haeufigste Ursache.

    ``urllib`` wertet HTTP_PROXY aus der Umgebung aus - und schickt dann selbst
    eine Anfrage an localhost gegen den Proxy, der sie nicht beantworten kann.
    """
    monkeypatch.setitem(os.environ, "HTTP_PROXY", "http://proxy.intern:8080")
    client = _client(base_url="http://localhost:11434")

    # Ein ProxyHandler mit leerem Wortverzeichnis registriert gar keine
    # Protokoll-Methoden und taucht deshalb nicht in ``handlers`` auf - genau
    # das ist der Beleg: der Standard-ProxyHandler, der die Umgebung liest,
    # wurde verdraengt und kein anderer trat an seine Stelle.
    assert not _proxies_in_use(client), (
        "fuer localhost darf kein Proxy aus der Umgebung greifen"
    )


def test_proxy_bleibt_fuer_entfernte_adressen_wirksam(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein Ollama-Host im LAN soll den konfigurierten Proxy weiter benutzen."""
    monkeypatch.setitem(os.environ, "HTTP_PROXY", "http://proxy.intern:8080")
    client = _client(base_url="http://ollama.intern:11434", allow_cloud=True)

    assert _proxies_in_use(client).get("http") == "http://proxy.intern:8080"


def test_meldung_nennt_die_adresse() -> None:
    state = OllamaStatus(reachable=False, model_present=False, detail="timed out")
    text = state.message("http://127.0.0.1:11434", "irgendein-modell")
    assert "127.0.0.1:11434" in text
    assert "Proxy" in text, "der haeufigste Grund gehoert in die Meldung"
