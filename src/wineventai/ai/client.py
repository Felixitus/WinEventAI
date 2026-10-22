"""Anbindung an die Ollama-HTTP-API.

Bewusst mit ``urllib`` aus der Standardbibliothek statt mit einer HTTP-Bibliothek:
eine Abhaengigkeit weniger im PyInstaller-Bundle, und in Tests ist genau eine
Funktion zu ersetzen.

``num_ctx`` wird IMMER explizit gesetzt. Der Standardwert von Ollama ist klein
und schneidet lange Prompts stillschweigend ab. Welcher Wert das genau ist,
haengt an der Ollama-Version - deshalb wird er nicht angenommen, sondern die
tatsaechliche Kontextlaenge des Modells ueber ``/api/show`` erfragt und
``min(modell_max, konfiguriert)`` verwendet.
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


class OllamaUnavailableError(RuntimeError):
    """Ollama ist nicht erreichbar. Das ist ein normaler Zustand, kein Absturz."""


class CloudCallBlockedError(RuntimeError):
    """Es wurde eine nicht-lokale Adresse konfiguriert, ohne ausdrueckliches Opt-in."""


class HttpStatusError(RuntimeError):
    """Ollama hat geantwortet, aber mit einem Fehlercode.

    Bewusst KEIN ``OllamaUnavailableError``: Wer antwortet, laeuft. Ein 404 auf
    ``/api/show`` heisst "Modell nicht vorhanden", nicht "Dienst nicht
    erreichbar" - und genau diese Verwechslung schickt Leute auf die Suche nach
    einem Netzwerkproblem, das es nicht gibt.
    """

    def __init__(self, status: int, path: str, body: str = "") -> None:
        super().__init__(f"HTTP {status} auf {path}")
        self.status = status
        self.path = path
        self.body = body


@dataclass(slots=True)
class OllamaStatus:
    """Ergebnis der Erreichbarkeitspruefung - getrennt nach Ursache."""

    reachable: bool
    model_present: bool
    models: list[str] = field(default_factory=list)
    detail: str | None = None

    @property
    def usable(self) -> bool:
        return self.reachable and self.model_present

    def message(self, base_url: str, model: str) -> str:
        """Ein Satz, der sagt, was zu tun ist - nicht nur, was nicht ging."""
        if self.usable:
            return f"Ollama erreichbar, Modell {model} vorhanden."
        if not self.reachable:
            return (
                f"Ollama unter {base_url} nicht erreichbar. "
                f"Pruefen: laeuft der Dienst, stimmt der Port, und ist ein Proxy gesetzt, "
                f"der localhost abfaengt? Details: {self.detail or 'keine'}"
            )
        verfuegbar = ", ".join(self.models[:12]) if self.models else "keine"
        return (
            f"Ollama laeuft, aber das Modell {model!r} ist dort nicht vorhanden. "
            f"Verfuegbar: {verfuegbar}. "
            f"Abhilfe: 'ollama pull {model}' oder in der Konfiguration "
            f"'ai.model' auf ein vorhandenes Modell setzen."
        )


@dataclass(slots=True)
class ModelReply:
    """Antwort des Modells samt Kennzahlen."""

    content: str
    prompt_tokens: int | None = None
    eval_tokens: int | None = None
    total_duration_ns: int | None = None
    model: str = ""


def assert_local(base_url: str, allow_cloud: bool) -> None:
    """Verhindert Cloud-Aufrufe ohne ausdrueckliches Opt-in im Konfigurationsfile."""
    host = (urlparse(base_url).hostname or "").lower()
    if host in LOCAL_HOSTS or allow_cloud:
        return
    raise CloudCallBlockedError(
        f"Die konfigurierte Adresse {base_url!r} ist nicht lokal. Ein Aufruf ausserhalb "
        "von localhost verlaesst dieses System und ist deshalb nur mit "
        "'ai.allow_cloud: true' in der Konfiguration erlaubt."
    )


class OllamaClient:
    """Minimaler Client fuer ``/api/chat`` und ``/api/show``."""

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
        self._effective_num_ctx: int | None = None
        self._opener_cache: urllib.request.OpenerDirector | None = None
        self._status: OllamaStatus | None = None

    # --- Transport -----------------------------------------------------------

    def _opener(self) -> urllib.request.OpenerDirector:
        """Liefert einen Opener, der fuer lokale Adressen jeden Proxy umgeht.

        ``urllib`` wertet ``HTTP_PROXY`` bzw. ``HTTPS_PROXY`` aus der Umgebung
        aus. Auf Firmenrechnern ist das gesetzt, und dann laeuft selbst eine
        Anfrage an ``localhost`` gegen den Proxy - der sie natuerlich nicht
        beantworten kann. Fuer lokale Ziele wird der Proxy deshalb ausdruecklich
        abgeschaltet.
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
        """Ein HTTP-Aufruf. ``payload=None`` bedeutet GET.

        Ein HTTP-Fehlercode wird hier NICHT in "nicht erreichbar" umgedeutet:
        Wer mit 404 antwortet, laeuft. Diese Unterscheidung ist der ganze Grund
        fuer ``HttpStatusError``.
        """
        request = urllib.request.Request(  # noqa: S310 - feste, konfigurierte Basis-URL
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
            except Exception:  # noqa: BLE001 - der Koerper ist nur Beiwerk
                body = ""
            raise HttpStatusError(exc.code, path, body) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise OllamaUnavailableError(
                f"Ollama unter {self.base_url} nicht erreichbar: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise OllamaUnavailableError("Ollama lieferte keine gueltige JSON-Antwort.") from exc

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request(path, payload)

    # --- Kontextfenster ------------------------------------------------------

    def model_context_length(self) -> int | None:
        """Fragt die tatsaechliche Kontextlaenge des Modells ab.

        Der Schluessel heisst je nach Architektur anders (``llama.context_length``,
        ``qwen2.context_length`` ...), deshalb wird nach dem Namensmuster gesucht
        statt nach einem festen Schluessel.
        """
        try:
            payload = self._post("/api/show", {"model": self.model})
        except (OllamaUnavailableError, HttpStatusError):
            return None
        info = payload.get("model_info") or {}
        for key, value in info.items():
            if key.endswith("context_length") and isinstance(value, int):
                return value
        return None

    def effective_num_ctx(self) -> int:
        """Der tatsaechlich gesetzte Wert - nie groesser als das Modell kann."""
        if self._effective_num_ctx is not None:
            return self._effective_num_ctx
        model_max = self.model_context_length()
        if model_max is None:
            self._effective_num_ctx = self.configured_num_ctx
            get_log().warn(
                "Kontextlaenge des Modells unbekannt, konfigurierter Wert wird verwendet",
                modell=self.model,
                num_ctx=self.configured_num_ctx,
            )
        else:
            self._effective_num_ctx = min(model_max, self.configured_num_ctx)
            if model_max < self.configured_num_ctx:
                get_log().warn(
                    "Konfiguriertes Kontextfenster groesser als das Modell kann",
                    modell=self.model,
                    konfiguriert=self.configured_num_ctx,
                    modell_max=model_max,
                )
        return self._effective_num_ctx

    # --- Aufruf --------------------------------------------------------------

    def chat_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        json_schema: dict[str, Any] | None = None,
    ) -> ModelReply:
        """Ein Aufruf mit erzwungener JSON-Ausgabe.

        Mit ``json_schema`` ist die Dekodierung grammatikgebunden. Aeltere
        Ollama-Versionen ohne Schema-Unterstuetzung fallen auf ``"json"``
        zurueck; dann greift der eine Retry in ``pipeline.py``.
        """
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
                f"Ollama lehnte den Aufruf ab ({exc}). {exc.body}".strip()
            ) from exc
        message = response.get("message") or {}
        return ModelReply(
            content=str(message.get("content", "")),
            prompt_tokens=response.get("prompt_eval_count"),
            eval_tokens=response.get("eval_count"),
            total_duration_ns=response.get("total_duration"),
            model=str(response.get("model", self.model)),
        )

    # --- Erreichbarkeit ------------------------------------------------------

    def list_models(self) -> list[str]:
        """Namen der lokal vorhandenen Modelle."""
        payload = self._request("/api/tags", timeout=min(self.timeout, 15.0))
        models = payload.get("models") or []
        names: list[str] = []
        for entry in models:
            name = entry.get("name") or entry.get("model")
            if isinstance(name, str):
                names.append(name)
        return sorted(names)

    def status(self, *, refresh: bool = False) -> OllamaStatus:
        """Prueft getrennt: laeuft der Dienst, und ist das Modell vorhanden?

        Diese beiden Fragen wurden bis Version 1.0.0 in eine einzige gepresst -
        ein fehlendes Modell meldete sich als "nicht erreichbar" und schickte
        Leute auf die Suche nach einem Netzwerkproblem, das es nicht gab.
        """
        if self._status is not None and not refresh:
            return self._status

        try:
            models = self.list_models()
        except OllamaUnavailableError as exc:
            self._status = OllamaStatus(
                reachable=False, model_present=False, detail=str(exc)
            )
            return self._status
        except HttpStatusError as exc:
            # Der Dienst antwortet, nur dieser Endpunkt nicht wie erwartet.
            self._status = OllamaStatus(
                reachable=True, model_present=False, detail=str(exc)
            )
            return self._status

        present = self._model_matches(models)
        self._status = OllamaStatus(
            reachable=True, model_present=present, models=models
        )
        return self._status

    def _model_matches(self, models: list[str]) -> bool:
        """Vergleicht den konfigurierten Namen mit den vorhandenen.

        Ollama fuehrt Modelle als ``name:tag``. Ist kein Tag konfiguriert, gilt
        implizit ``:latest`` - deshalb wird auch der Praefix geprueft, statt
        einen Treffer an einem fehlenden Doppelpunkt scheitern zu lassen.
        """
        wanted = self.model.strip()
        if wanted in models:
            return True
        if ":" not in wanted:
            return any(name.split(":")[0] == wanted for name in models)
        return False

    def available(self) -> bool:
        """Nutzbar heisst: Dienst laeuft UND Modell vorhanden."""
        return self.status().usable

    def unavailable_reason(self) -> str | None:
        state = self.status()
        if state.usable:
            return None
        return state.message(self.base_url, self.model)
