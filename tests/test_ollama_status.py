"""Ollama reachability: service down, model missing and cloud model are three cases.

Until 1.0.0 the first two were squeezed into one message - a model that had
not been downloaded reported itself as "not reachable" and sent people looking
for a network problem that did not exist. Since 2.0 a model that Ollama only
forwards to a remote service is refused as well, because the event data would
leave the machine although the base URL is localhost.
"""

from __future__ import annotations

import os

import pytest

from wineventai.ai.client import (
    CloudCallBlockedError,
    HttpStatusError,
    OllamaClient,
    OllamaStatus,
    OllamaUnavailableError,
    is_remote_model_entry,
)


def _proxies_in_use(client: OllamaClient) -> dict[str, str]:
    """Which proxies this client's opener would actually use."""
    for handler in client._opener().handlers:
        if type(handler).__name__ == "ProxyHandler":
            return dict(getattr(handler, "proxies", {}))
    return {}


def _client(**kwargs: object) -> OllamaClient:
    defaults: dict[str, object] = {"model": "qwen2.5:14b-instruct", "timeout_seconds": 5.0}
    defaults.update(kwargs)
    return OllamaClient(**defaults)  # type: ignore[arg-type]


def _tags(*names: str, remote: tuple[str, ...] = ()) -> list[dict[str, object]]:
    """``/api/tags`` entries as Ollama 0.40 lists them (observed)."""
    entries: list[dict[str, object]] = [{"name": name, "model": name} for name in names]
    for name in remote:
        entries.append({"name": name, "model": name, "remote_model": name.split(":")[0],
                        "remote_host": "https://ollama.com"})
    return entries


def test_service_not_running(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    monkeypatch.setattr(
        client, "_tags",
        lambda: (_ for _ in ()).throw(OllamaUnavailableError("Connection refused")),
    )
    state = client.status()

    assert state.reachable is False
    assert state.usable is False
    assert "not reachable" in state.message(client.base_url, client.model)


def test_service_running_but_model_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The case that used to be reported wrongly."""
    client = _client()
    monkeypatch.setattr(client, "_tags", lambda: _tags("llama3.1:8b", "mistral:latest"))
    state = client.status()

    assert state.reachable is True
    assert state.model_present is False
    assert state.usable is False

    text = state.message(client.base_url, client.model)
    assert "not reachable" not in text, (
        "a running service must never be reported as unreachable"
    )
    assert "ollama pull" in text
    assert "llama3.1:8b" in text, "the available models belong in the message"


def test_model_present(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    monkeypatch.setattr(client, "_tags", lambda: _tags("qwen2.5:14b-instruct"))
    assert client.status().usable is True
    assert client.unavailable_reason() is None


def test_a_model_without_tag_matches_latest(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ollama lists models as name:tag; without a tag :latest applies implicitly."""
    client = _client(model="mistral")
    monkeypatch.setattr(client, "_tags", lambda: _tags("mistral:latest"))
    assert client.status().usable is True


def test_a_wrong_tag_does_not_count_as_a_hit(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(model="qwen2.5:14b-instruct")
    monkeypatch.setattr(client, "_tags", lambda: _tags("qwen2.5:7b-instruct"))
    assert client.status().model_present is False


def test_an_http_error_means_running_but(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whoever answers with an error code is running."""
    client = _client()
    monkeypatch.setattr(
        client, "_tags",
        lambda: (_ for _ in ()).throw(HttpStatusError(404, "/api/tags")),
    )
    state = client.status()
    assert state.reachable is True
    assert state.model_present is False


def test_the_status_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def fake() -> list[dict[str, object]]:
        calls["n"] += 1
        return _tags("qwen2.5:14b-instruct")

    client = _client()
    monkeypatch.setattr(client, "_tags", fake)
    client.status()
    client.status()
    assert calls["n"] == 1, "the check must not run again on every call"
    client.status(refresh=True)
    assert calls["n"] == 2


def test_a_cloud_model_behind_localhost_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The case found on a real machine: 'glm-5.2:cloud' listed by the local Ollama.

    The base URL is localhost, but the prompt would go to ollama.com. Checking
    the address alone would break the "no cloud call" promise.
    """
    client = _client(model="glm-5.2:cloud")
    monkeypatch.setattr(client, "_tags", lambda: _tags("gemma4:26b", remote=("glm-5.2:cloud",)))
    state = client.status()

    assert state.model_present is True
    assert state.remote_model is True
    assert state.usable is False
    text = state.message(client.base_url, client.model)
    assert "cloud model" in text
    assert "allow_cloud" in text


def test_a_cloud_model_is_also_refused_directly_before_the_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defense in depth: no caller may skip status() and still send data away."""
    client = _client(model="glm-5.2:cloud")
    monkeypatch.setattr(client, "_tags", lambda: _tags(remote=("glm-5.2:cloud",)))

    def must_not_post(*_args, **_kwargs):
        raise AssertionError("no request may be sent for a refused cloud model")

    monkeypatch.setattr(client, "_post", must_not_post)
    with pytest.raises(CloudCallBlockedError):
        client.chat_json(system_prompt="s", user_prompt="u")


def test_with_explicit_opt_in_a_cloud_model_is_usable(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(model="glm-5.2:cloud", allow_cloud=True)
    monkeypatch.setattr(client, "_tags", lambda: _tags(remote=("glm-5.2:cloud",)))
    assert client.status().usable is True


def test_cloud_models_are_not_offered_as_alternatives(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(model="missing:1b")
    monkeypatch.setattr(client, "_tags", lambda: _tags("gemma4:26b", remote=("glm-5.2:cloud",)))
    text = client.status().message(client.base_url, client.model)
    assert "gemma4:26b" in text
    assert "glm-5.2:cloud" not in text


def test_a_cloud_name_suffix_counts_as_remote_even_without_remote_fields() -> None:
    assert is_remote_model_entry({"name": "some-model:cloud"})
    assert is_remote_model_entry({"name": "x", "remote_host": "https://ollama.com"})
    assert not is_remote_model_entry({"name": "qwen2.5:14b-instruct"})


def test_the_proxy_is_bypassed_for_localhost(monkeypatch: pytest.MonkeyPatch) -> None:
    """The most common cause on corporate machines.

    ``urllib`` honors HTTP_PROXY from the environment - and then sends even a
    request to localhost to the proxy, which cannot answer it.
    """
    monkeypatch.setitem(os.environ, "HTTP_PROXY", "http://proxy.intern:8080")
    client = _client(base_url="http://localhost:11434")

    # A ProxyHandler with an empty mapping registers no protocol methods at all
    # and therefore does not show up in ``handlers`` - exactly that is the
    # proof: the default ProxyHandler that reads the environment was displaced
    # and no other took its place.
    assert not _proxies_in_use(client), (
        "no proxy from the environment may apply for localhost"
    )


def test_the_proxy_stays_in_effect_for_remote_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    """An Ollama host in the LAN should keep using the configured proxy."""
    monkeypatch.setitem(os.environ, "HTTP_PROXY", "http://proxy.intern:8080")
    client = _client(base_url="http://ollama.intern:11434", allow_cloud=True)

    assert _proxies_in_use(client).get("http") == "http://proxy.intern:8080"


def test_the_message_names_the_address() -> None:
    state = OllamaStatus(reachable=False, model_present=False, detail="timed out")
    text = state.message("http://127.0.0.1:11434", "some-model")
    assert "127.0.0.1:11434" in text
    assert "proxy" in text, "the most common reason belongs in the message"
