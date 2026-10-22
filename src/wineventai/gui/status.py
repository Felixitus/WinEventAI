"""Umgebungspruefung fuer die Statusleiste.

Dieselben Pruefungen wie ``wineventai doctor``, nur als Datenstruktur statt als
Konsolenausgabe. Sie laufen in einem eigenen Thread: Die Ollama-Abfrage geht
ueber das Netz und darf das Fenster beim Start nicht blockieren.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

from PySide6.QtCore import QObject, QThread, Signal

from ..collect.rundir import is_admin
from ..collect.shell import PowerShellNotFoundError, find_powershell
from ..config import Config
from ..config.loader import user_config_path
from ..kb.store import KnowledgeBase
from ..rules.loader import RuleLoadError, load_rules


@dataclass(slots=True)
class Environment:
    """Was das Werkzeug ueber seine Umgebung weiss."""

    platform: str = sys.platform
    admin: bool = False
    powershell: str | None = None
    rules: int = 0
    rules_error: str | None = None
    kb_entries: int = 0
    config_exists: bool = False
    config_path: str = ""

    ollama_reachable: bool = False
    ollama_model_present: bool = False
    ollama_models: list[str] = field(default_factory=list)
    ollama_detail: str | None = None
    ollama_enabled: bool = True
    model_name: str = ""

    @property
    def ready_to_collect(self) -> bool:
        """Ohne PowerShell laesst sich nichts erheben - das ist der harte Blocker."""
        return self.powershell is not None

    def ollama_line(self) -> tuple[str, bool]:
        """Text und ob es ein Problem ist."""
        if not self.ollama_enabled:
            return "Modell: abgeschaltet", False
        if self.ollama_reachable and self.ollama_model_present:
            return f"Modell: {self.model_name}", False
        if self.ollama_reachable:
            return f"Modell {self.model_name} fehlt", True
        return "Ollama nicht erreichbar", True

    def powershell_line(self) -> tuple[str, bool]:
        if self.powershell:
            return "PowerShell: bereit", False
        return "PowerShell fehlt", True

    def admin_line(self) -> tuple[str, bool]:
        if self.admin:
            return "Adminrechte: ja", False
        return "ohne Adminrechte", True

    def tooltip(self) -> str:
        """Die Langfassung - die Statusleiste bleibt kurz, der Tooltip erklaert."""
        zeilen = [
            f"PowerShell: {self.powershell or 'nicht gefunden - Erhebung nicht moeglich'}",
            "Adminrechte: "
            + ("ja" if self.admin else "nein - der Security-Kanal bleibt gesperrt"),
            f"Konfiguration: {self.config_path}"
            + ("" if self.config_exists else "  (nicht vorhanden)"),
        ]
        if not self.ollama_enabled:
            zeilen.append("Sprachmodell: per Konfiguration abgeschaltet")
        elif self.ollama_reachable and self.ollama_model_present:
            zeilen.append(f"Ollama: erreichbar, Modell {self.model_name}")
        elif self.ollama_reachable:
            verfuegbar = ", ".join(self.ollama_models[:6]) or "keine"
            zeilen.append(
                f"Ollama: erreichbar, aber {self.model_name} fehlt. "
                f"Vorhanden: {verfuegbar}"
            )
        else:
            zeilen.append(
                f"Ollama: nicht erreichbar. {self.ollama_detail or ''}".strip()
            )
        return "\n".join(zeilen)


def probe_environment(config: Config) -> Environment:
    """Sammelt den Umgebungszustand. Wirft nicht."""
    env = Environment(admin=is_admin(), model_name=config.ai.model)

    try:
        env.powershell = find_powershell(config.collect.powershell_preference).path
    except PowerShellNotFoundError:
        env.powershell = None

    try:
        env.rules = len(
            load_rules(
                overlay=config.rules.overlay_dir,
                include_security=config.rules.security_mode,
            )
        )
    except RuleLoadError as exc:
        env.rules_error = str(exc)

    try:
        with KnowledgeBase.open_default() as kb:
            env.kb_entries = kb.count()
    except Exception as exc:  # noqa: BLE001 - eine kaputte KB darf den Start nicht toeten
        env.rules_error = env.rules_error or f"Wissensbasis: {exc}"

    path = user_config_path()
    env.config_path = str(path)
    env.config_exists = path.is_file()

    env.ollama_enabled = config.ai.enabled
    if config.ai.enabled:
        _probe_ollama(config, env)
    return env


def _probe_ollama(config: Config, env: Environment) -> None:
    from ..ai.client import CloudCallBlockedError, OllamaClient

    try:
        client = OllamaClient(
            base_url=config.ai.base_url,
            model=config.ai.model,
            num_ctx=config.ai.num_ctx,
            timeout_seconds=8.0,
            allow_cloud=config.ai.allow_cloud,
        )
    except CloudCallBlockedError as exc:
        env.ollama_detail = str(exc)
        return

    state = client.status()
    env.ollama_reachable = state.reachable
    env.ollama_model_present = state.model_present
    env.ollama_models = list(state.models)
    env.ollama_detail = state.detail


class EnvironmentProbe(QObject):
    """Fuehrt ``probe_environment`` im Hintergrund aus."""

    done = Signal(object)

    def __init__(self, config: Config) -> None:
        super().__init__()
        self.config = config

    def run(self) -> None:
        self.done.emit(probe_environment(self.config))


class ProbeHandle:
    """Haelt Thread und Sonde zusammen - dieselbe Klammer wie beim Lauf-Worker."""

    def __init__(self, config: Config) -> None:
        self.probe = EnvironmentProbe(config)
        self.thread = QThread()
        self.probe.moveToThread(self.thread)
        self.thread.started.connect(self.probe.run)
        self.probe.done.connect(self.thread.quit)

    def start(self) -> None:
        self.thread.start()

    def stop(self, timeout_ms: int = 3000) -> None:
        self.thread.quit()
        self.thread.wait(timeout_ms)
