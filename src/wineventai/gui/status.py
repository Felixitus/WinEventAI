"""Environment check for the status bar.

The same checks as ``wineventai doctor``, only as a data structure instead of
console output. They run in a thread of their own: the Ollama query goes over
the network and must not block the window at startup.
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
    """What the tool knows about its environment."""

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
    ollama_remote_model: bool = False
    ollama_models: list[str] = field(default_factory=list)
    ollama_detail: str | None = None
    ollama_enabled: bool = True
    model_name: str = ""

    @property
    def ready_to_collect(self) -> bool:
        """Without PowerShell nothing can be collected - that is the hard blocker."""
        return self.powershell is not None

    @property
    def ollama_usable(self) -> bool:
        return (
            self.ollama_reachable and self.ollama_model_present and not self.ollama_remote_model
        )

    def ollama_line(self) -> tuple[str, bool]:
        """Text and whether it is a problem."""
        if not self.ollama_enabled:
            return "Model: disabled", False
        if self.ollama_remote_model:
            return f"Cloud model {self.model_name} refused", True
        if self.ollama_usable:
            return f"Model: {self.model_name}", False
        if self.ollama_reachable:
            return f"Model {self.model_name} missing", True
        return "No Ollama - rule engine only", True

    def powershell_line(self) -> tuple[str, bool]:
        if self.powershell:
            return "PowerShell: ready", False
        return "PowerShell missing", True

    def admin_line(self) -> tuple[str, bool]:
        if self.admin:
            return "Admin rights: yes", False
        return "without admin rights", True

    def tooltip(self) -> str:
        """The long version - the status bar stays short, the tooltip explains."""
        lines = [
            f"PowerShell: {self.powershell or 'not found - collection not possible'}",
            "Admin rights: "
            + ("yes" if self.admin else "no - the Security channel stays locked"),
            f"Configuration: {self.config_path}"
            + ("" if self.config_exists else "  (not present)"),
        ]
        if not self.ollama_enabled:
            lines.append("Language model: disabled by configuration")
        elif self.ollama_remote_model:
            lines.append(
                f"Ollama: {self.model_name} runs on a remote service. It is refused "
                "without 'ai.allow_cloud: true'; the report is built from the rule engine."
            )
        elif self.ollama_usable:
            lines.append(f"Ollama: reachable, model {self.model_name}")
        elif self.ollama_reachable:
            available = ", ".join(self.ollama_models[:6]) or "none"
            lines.append(
                f"Ollama: reachable, but {self.model_name} is missing. "
                f"Present: {available}"
            )
        else:
            lines.append(
                "Ollama: not reachable. The report is complete without it - it is built "
                f"from the rule engine. {self.ollama_detail or ''}".strip()
            )
        return "\n".join(lines)


def probe_environment(config: Config) -> Environment:
    """Collects the environment state. Does not raise."""
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
    except Exception as exc:  # noqa: BLE001 - a broken KB must not kill the startup
        env.rules_error = env.rules_error or f"Knowledge base: {exc}"

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
    env.ollama_remote_model = state.remote_model and not state.cloud_allowed
    env.ollama_models = list(state.models)
    env.ollama_detail = state.detail


class EnvironmentProbe(QObject):
    """Runs ``probe_environment`` in the background."""

    done = Signal(object)

    def __init__(self, config: Config) -> None:
        super().__init__()
        self.config = config

    def run(self) -> None:
        self.done.emit(probe_environment(self.config))


class ProbeHandle:
    """Keeps thread and probe together - the same clamp as for the run worker."""

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
