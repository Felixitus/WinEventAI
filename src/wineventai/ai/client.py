"""Connection to the Ollama HTTP API.

Deliberately with ``urllib`` from the standard library instead of an HTTP
library: one dependency less in the PyInstaller bundle, and in tests exactly
one function has to be replaced.

``num_ctx`` is ALWAYS set explicitly. Ollama's default is small and silently
truncates long prompts. Which value that is exactly depends on the Ollama
version - so it is not assumed; instead the model's actual context length is
queried via ``/api/show`` and ``min(model_max, configured)`` is used.

Cloud models behind localhost: recent Ollama versions can list models that run
on ollama.com (``remote_host`` in ``/api/tags``, names like ``glm-5.2:cloud``).
The base URL is then local, but the prompt still leaves the machine. Checking
the address alone would therefore not keep the "no cloud call" promise; the
model itself is checked as well, before the status check and again before
every call.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ..applog import get_log

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}

#: Tag suffixes Ollama uses for models that are executed remotely.
CLOUD_TAG_SUFFIXES = (":cloud", "-cloud")


class OllamaUnavailableError(RuntimeError):
    """Ollama is not reachable. That is a normal state, not a crash."""


class CloudCallBlockedError(RuntimeError):
    """A non-local address or a remote model was configured without explicit opt-in."""


class HttpStatusError(RuntimeError):
    """Ollama answered, but with an error code.

    Deliberately NOT an ``OllamaUnavailableError``: whoever answers is running.
    A 404 on ``/api/show`` means "model not present", not "service not
    reachable" - and exactly that confusion sends people looking for a network
    problem that does not exist.
    """

    def __init__(self, status: int, path: str, body: str = "") -> None:
        super().__init__(f"HTTP {status} on {path}")
        self.status = status
        self.path = path
        self.body = body


@dataclass(slots=True)
class OllamaStatus:
    """Result of the reachability check - separated by cause."""

    reachable: bool
    model_present: bool
    models: list[str] = field(default_factory=list)
    detail: str | None = None
    remote_model: bool = False
    cloud_allowed: bool = False

    @property
    def usable(self) -> bool:
        if self.remote_model and not self.cloud_allowed:
            return False
        return self.reachable and self.model_present

    def message(self, base_url: str, model: str) -> str:
        """One sentence that says what to do - not only what did not work."""
        if self.remote_model and not self.cloud_allowed:
            return (
                f"The model {model!r} is a cloud model: Ollama forwards it to a remote "
                "service, so the event data would leave this machine. It is refused "
                "without 'ai.allow_cloud: true'. Use a local model instead "
                "(e.g. 'ollama pull qwen2.5:14b-instruct')."
            )
        if self.usable:
            return f"Ollama reachable, model {model} present."
        if not self.reachable:
            return (
                f"Ollama not reachable at {base_url}. "
                f"Check: is the service running, is the port right, and is a proxy set "
                f"that intercepts localhost? Details: {self.detail or 'none'}"
            )
        available = ", ".join(self.models[:12]) if self.models else "none"
        return (
            f"Ollama is running, but the model {model!r} is not present there. "
            f"Available: {available}. "
            f"Remedy: 'ollama pull {model}' or set 'ai.model' in the configuration "
            f"to a model that is present."
        )


@dataclass(slots=True)
class ModelReply:
    """Answer of the model including figures."""

    content: str
    prompt_tokens: int | None = None
    eval_tokens: int | None = None
    total_duration_ns: int | None = None
    model: str = ""


def assert_local(base_url: str, allow_cloud: bool) -> None:
    """Prevents cloud calls without explicit opt-in in the configuration file."""
    host = (urlparse(base_url).hostname or "").lower()
    if host in LOCAL_HOSTS or allow_cloud:
        return
    raise CloudCallBlockedError(
        f"The configured address {base_url!r} is not local. A call outside localhost "
        "leaves this system and is therefore only allowed with "
        "'ai.allow_cloud: true' in the configuration."
    )


def is_remote_model_entry(entry: dict[str, Any]) -> bool:
    """True if a ``/api/tags`` entry describes a model that runs remotely.

    ``remote_host`` / ``remote_model`` were observed in Ollama 0.40 for
    ``*:cloud`` models. The name suffix is checked as well, so that an older or
    newer field layout does not silently let such a model through.
    """
    if entry.get("remote_host") or entry.get("remote_model"):
        return True
    name = str(entry.get("name") or entry.get("model") or "").lower()
    return name.endswith(CLOUD_TAG_SUFFIXES)


class OllamaClient:
    """Minimal client for ``/api/chat`` and ``/api/show``."""

    def __init__(
        self,
        *,
        base_url: str = "http://localhost:11434",
        model: str = "qwen2.5:14b-instruct",
        temperature: float = 0.1,
        num_ctx: int = 16384,
        timeout_seconds: float = 180.0,
        allow_cloud: bool = False,
    ) -> None:
        assert_local(base_url, allow_cloud)
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.configured_num_ctx = num_ctx
        self.timeout = timeout_seconds
        self.allow_cloud = allow_cloud
        self._effective_num_ctx: int | None = None
        self._opener_cache: urllib.request.OpenerDirector | None = None
        self._status: OllamaStatus | None = None
        self._details: dict[str, Any] | None = None

    # --- Transport -----------------------------------------------------------

    def _opener(self) -> urllib.request.OpenerDirector:
        """Returns an opener that bypasses every proxy for local addresses.

        ``urllib`` honors ``HTTP_PROXY`` / ``HTTPS_PROXY`` from the
        environment. On corporate machines that is set, and then even a request
        to ``localhost`` goes to the proxy - which of course cannot answer it.
        For local targets the proxy is therefore switched off explicitly.
        """
        if self._opener_cache is not None:
            return self._opener_cache
        host = (urlparse(self.base_url).hostname or "").lower()
        handlers: list[urllib.request.BaseHandler] = []
        if host in LOCAL_HOSTS:
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener_cache = urllib.request.build_opener(*handlers)
        return self._opener_cache

    def _request(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """One HTTP call. ``payload=None`` means GET.

        An HTTP error code is NOT reinterpreted as "not reachable" here:
        whoever answers with 404 is running. That distinction is the whole
        reason for ``HttpStatusError``.
        """
        request = urllib.request.Request(  # noqa: S310 - fixed, configured base URL
            url=f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8") if payload is not None else None,
            headers={"Content-Type": "application/json"},
            method="POST" if payload is not None else "GET",
        )
        try:
            with self._opener().open(request, timeout=timeout or self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")[:400]
            except Exception:  # noqa: BLE001 - the body is only decoration
                body = ""
            raise HttpStatusError(exc.code, path, body) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise OllamaUnavailableError(
                f"Ollama not reachable at {self.base_url}: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise OllamaUnavailableError("Ollama returned no valid JSON answer.") from exc

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request(path, payload)

    # --- Context window ------------------------------------------------------

    def model_details(self) -> dict[str, Any] | None:
        """The ``/api/show`` answer for the configured model, or ``None``.

        Cached: the answer does not change during a run, and the bench and the
        context check would otherwise ask twice.
        """
        if self._details is not None:
            return self._details
        try:
            self._details = self._post("/api/show", {"model": self.model})
        except (OllamaUnavailableError, HttpStatusError):
            return None
        return self._details

    def model_context_length(self) -> int | None:
        """Queries the model's actual context length.

        The key is named differently depending on the architecture
        (``llama.context_length``, ``qwen2.context_length`` ...), so the name
        pattern is searched instead of a fixed key.
        """
        payload = self.model_details()
        if payload is None:
            return None
        info = payload.get("model_info") or {}
        for key, value in info.items():
            if key.endswith("context_length") and isinstance(value, int):
                return value
        return None

    def effective_num_ctx(self) -> int:
        """The value actually set - never larger than the model can do."""
        if self._effective_num_ctx is not None:
            return self._effective_num_ctx
        model_max = self.model_context_length()
        if model_max is None:
            self._effective_num_ctx = self.configured_num_ctx
            get_log().warn(
                "Context length of the model unknown, using the configured value",
                model=self.model,
                num_ctx=self.configured_num_ctx,
            )
        else:
            self._effective_num_ctx = min(model_max, self.configured_num_ctx)
            if model_max < self.configured_num_ctx:
                get_log().warn(
                    "Configured context window larger than the model supports",
                    model=self.model,
                    configured=self.configured_num_ctx,
                    model_max=model_max,
                )
        return self._effective_num_ctx

    # --- Call ----------------------------------------------------------------

    def chat_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        json_schema: dict[str, Any] | None = None,
    ) -> ModelReply:
        """One call with enforced JSON output.

        With ``json_schema`` decoding is grammar-bound. Older Ollama versions
        without schema support fall back to ``"json"``; then the one retry in
        ``pipeline.py`` applies.

        Raises:
            CloudCallBlockedError: if the configured model runs remotely and
                cloud calls are not allowed. Checked here a second time on
                purpose, so that no caller can skip ``status()`` and still send
                event data to a remote service.
        """
        if not self.allow_cloud and self.status().remote_model:
            raise CloudCallBlockedError(self.status().message(self.base_url, self.model))
        payload: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "format": json_schema if json_schema is not None else "json",
            "options": {
                "temperature": self.temperature,
                "num_ctx": self.effective_num_ctx(),
            },
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        try:
            response = self._post("/api/chat", payload)
        except HttpStatusError as exc:
            raise OllamaUnavailableError(
                f"Ollama refused the call ({exc}). {exc.body}".strip()
            ) from exc
        message = response.get("message") or {}
        return ModelReply(
            content=str(message.get("content", "")),
            prompt_tokens=response.get("prompt_eval_count"),
            eval_tokens=response.get("eval_count"),
            total_duration_ns=response.get("total_duration"),
            model=str(response.get("model", self.model)),
        )

    # --- Reachability --------------------------------------------------------

    def _tags(self) -> list[dict[str, Any]]:
        payload = self._request("/api/tags", timeout=min(self.timeout, 15.0))
        models = payload.get("models") or []
        return [entry for entry in models if isinstance(entry, dict)]

    def loaded_size(self) -> tuple[int, int] | None:
        """``(size, size_vram)`` in bytes of the loaded model from ``/api/ps``.

        Only meaningful right after a call, while the model is still loaded.
        ``None`` if Ollama does not list it - that is "not measured", not
        "zero bytes".
        """
        try:
            payload = self._request("/api/ps", timeout=min(self.timeout, 15.0))
        except (OllamaUnavailableError, HttpStatusError):
            return None
        for entry in payload.get("models") or []:
            if not isinstance(entry, dict):
                continue
            if (entry.get("name") or entry.get("model")) == self.model:
                size, vram = entry.get("size"), entry.get("size_vram")
                if isinstance(size, int) and isinstance(vram, int) and size > 0:
                    return size, vram
        return None

    def list_models(self) -> list[str]:
        """Names of the locally listed models."""
        names: list[str] = []
        for entry in self._tags():
            name = entry.get("name") or entry.get("model")
            if isinstance(name, str):
                names.append(name)
        return sorted(names)

    def status(self, *, refresh: bool = False) -> OllamaStatus:
        """Checks separately: is the service running, and is the model present?

        Until version 1.0.0 these two questions were squeezed into one - a
        missing model reported itself as "not reachable" and sent people
        looking for a network problem that did not exist. Since 2.0 a third
        question is answered as well: does the model run locally at all?
        """
        if self._status is not None and not refresh:
            return self._status

        try:
            entries = self._tags()
        except OllamaUnavailableError as exc:
            self._status = OllamaStatus(
                reachable=False, model_present=False, detail=str(exc),
                cloud_allowed=self.allow_cloud,
            )
            return self._status
        except HttpStatusError as exc:
            # The service answers, only this endpoint not as expected.
            self._status = OllamaStatus(
                reachable=True, model_present=False, detail=str(exc),
                cloud_allowed=self.allow_cloud,
            )
            return self._status

        names = sorted(
            str(entry.get("name") or entry.get("model"))
            for entry in entries
            if entry.get("name") or entry.get("model")
        )
        matching = self._matching_entry(entries)
        remote = (
            is_remote_model_entry(matching)
            if matching is not None
            else self.model.strip().lower().endswith(CLOUD_TAG_SUFFIXES)
        )
        self._status = OllamaStatus(
            reachable=True,
            model_present=matching is not None,
            models=[name for name in names if not name.lower().endswith(CLOUD_TAG_SUFFIXES)]
            if not self.allow_cloud
            else names,
            remote_model=remote,
            cloud_allowed=self.allow_cloud,
        )
        return self._status

    def _matching_entry(self, entries: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Finds the ``/api/tags`` entry of the configured model.

        Ollama lists models as ``name:tag``. Without a configured tag
        ``:latest`` applies implicitly - so the prefix is checked as well,
        instead of letting a hit fail on a missing colon.
        """
        wanted = self.model.strip()
        for entry in entries:
            if (entry.get("name") or entry.get("model")) == wanted:
                return entry
        if ":" not in wanted:
            for entry in entries:
                name = str(entry.get("name") or entry.get("model") or "")
                if name.split(":")[0] == wanted:
                    return entry
        return None

    def available(self) -> bool:
        """Usable means: service running AND model present AND model local (or allowed)."""
        return self.status().usable

    def unavailable_reason(self) -> str | None:
        state = self.status()
        if state.usable:
            return None
        return state.message(self.base_url, self.model)
