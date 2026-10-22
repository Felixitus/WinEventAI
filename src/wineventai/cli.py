"""Command line.

Commands:

* ``collect``  - collect sources, create a run directory
* ``analyze``  - analyze an existing run directory (without collecting again)
* ``run``      - both in one go, the normal case
* ``report``   - rewrite the report of a run directory
* ``evidence`` - pack an evidence bundle as ZIP
* ``doctor``   - check the environment: PowerShell, channels, Ollama, rights
* ``kb``       - show and maintain the knowledge base
* ``config``   - create the configuration and show effective values
* ``gui``      - graphical user interface (needs PySide6)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import typer

from . import __version__
from .analyze import analyze_run, redacted_report, write_report_files
from .applog import configure
from .collect.base import INCONCLUSIVE
from .collect.rundir import RunDirectory, default_runs_root, is_admin
from .collect.runner import CollectionAborted, collect_all, window_for
from .collect.shell import (
    CHANNEL_STATE_LABEL,
    PowerShellNotFoundError,
    ShellInfo,
    find_powershell,
    run_script,
)
from .config import Config, load_config
from .config.loader import user_config_path
from .kb.store import KnowledgeBase
from .rules.loader import RuleLoadError, load_rules, overlay_dir

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "WinEventAI - local Windows diagnostics with a rule engine and an optional "
        "local language model."
    ),
)
kb_app = typer.Typer(no_args_is_help=True, help="Show and maintain the knowledge base.")
app.add_typer(kb_app, name="kb")
config_app = typer.Typer(no_args_is_help=True, help="Create and show the configuration.")
app.add_typer(config_app, name="config")

ConfigOption = Annotated[
    Path | None, typer.Option("--config", "-c", help="Own configuration file.")
]
DaysOption = Annotated[
    int | None,
    typer.Option("--days", "-d", help="Time window in days (default: configuration)."),
]
RunOption = Annotated[Path, typer.Option("--run", "-r", help="Run directory.")]


def _overrides(
    *,
    days: int | None,
    security: bool,
    no_ai: bool,
    show_noise: bool,
    model: str | None,
    ollama_url: str | None,
    no_probes: bool = False,
) -> dict[str, object]:
    out: dict[str, object] = {}
    collect: dict[str, object] = {}
    rules: dict[str, object] = {}
    ai: dict[str, object] = {}
    probes: dict[str, object] = {}

    if days is not None:
        collect["days"] = days
    if security:
        rules["security_mode"] = True
        # The Security channel is disabled by default - in security mode it has
        # to be on, otherwise the check runs into nothing.
        collect["channels"] = None
    if show_noise:
        rules["suppress_noise"] = False
    if no_ai:
        ai["enabled"] = False
    if model:
        ai["model"] = model
    if ollama_url:
        ai["base_url"] = ollama_url
    if no_probes:
        probes["enabled"] = False

    if probes:
        out["probes"] = probes
    if collect:
        collect.pop("channels", None)
        out["collect"] = collect
    if rules:
        out["rules"] = rules
    if ai:
        out["ai"] = ai
    return out


def _enable_security_channel(config: object) -> None:
    """Switches the Security channel on when security mode runs."""
    for entry in config.collect.channels:  # type: ignore[attr-defined]
        if entry.name.lower() == "security":
            entry.enabled = True


def _print_sources(run: RunDirectory) -> None:
    typer.echo("")
    typer.echo("Coverage:")
    for source in run.read_sources():
        marker = "!" if source.status in INCONCLUSIVE else " "
        typer.echo(
            f" {marker} {source.source_id:<52} {str(source.status):<14} "
            f"read {source.records_read:>8}  retained {source.records_retained:>8}"
        )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool, typer.Option("--version", help="Print the version and exit.")
    ] = False,
) -> None:
    if version:
        typer.echo(f"WinEventAI {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


@app.command()
def collect(
    config_path: ConfigOption = None,
    days: DaysOption = None,
    out: Annotated[
        Path | None, typer.Option("--out", help="Root directory for runs.")
    ] = None,
    evtx_dir: Annotated[
        Path | None,
        typer.Option("--evtx-dir", help="Brought-along .evtx exports instead of live collection."),
    ] = None,
    security: Annotated[bool, typer.Option("--security", help="Security mode.")] = False,
) -> None:
    """Collects all configured sources into a new run directory."""
    config = load_config(
        config_path, _overrides(days=days, security=security, no_ai=False,
                                show_noise=False, model=None, ollama_url=None)
    )
    if security:
        _enable_security_channel(config)
    log = configure(config.log_level)

    window_from, window_to = window_for(days or config.collect.days)
    run = RunDirectory.create(
        root=out,
        requested_from=window_from,
        requested_to=window_to,
        security_mode=security,
    )
    log.attach_file(run.applog_path)
    log.info("Run created", directory=str(run.path), admin=is_admin())

    try:
        collect_all(config, run, days=days, evtx_dir=evtx_dir)
    except CollectionAborted as exc:
        typer.secho(f"\nAborted: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc

    _print_sources(run)
    typer.echo(f"\nRun directory: {run.path}")


@app.command()
def analyze(
    run_dir: RunOption,
    config_path: ConfigOption = None,
    no_ai: Annotated[
        bool, typer.Option("--no-ai", help="Analyze without a language model.")
    ] = False,
    no_probes: Annotated[
        bool,
        typer.Option("--no-probes", help="Measure no context probes (no ping, no SMART)."),
    ] = False,
    show_noise: Annotated[
        bool, typer.Option("--show-noise", help="Show findings classified as noise.")
    ] = False,
    security: Annotated[bool, typer.Option("--security", help="Security mode.")] = False,
    model: Annotated[str | None, typer.Option("--model", help="Model name.")] = None,
    ollama_url: Annotated[
        str | None, typer.Option("--ollama-url", help="Base URL of Ollama.")
    ] = None,
    report_redacted: Annotated[
        bool,
        typer.Option(
            "--report-redacted",
            help="Additionally write a pseudonymized version that can be shared.",
        ),
    ] = False,
) -> None:
    """Analyzes an existing run directory - without collecting again."""
    config = load_config(
        config_path,
        _overrides(days=None, security=security, no_ai=no_ai, show_noise=show_noise,
                   model=model, ollama_url=ollama_url, no_probes=no_probes),
    )
    log = configure(config.log_level)
    run = RunDirectory.open(run_dir)
    log.attach_file(run.applog_path)

    try:
        result = analyze_run(run, config)
    except RuleLoadError as exc:
        typer.secho(f"Rules invalid: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc

    if report_redacted:
        from .ai.redaction import Redactor

        redacted_report(result.report, run, config, Redactor(enabled=True))

    _print_summary(result.report, run)


@app.command("run")
def run_all(
    config_path: ConfigOption = None,
    days: DaysOption = None,
    out: Annotated[
        Path | None, typer.Option("--out", help="Root directory for runs.")
    ] = None,
    security: Annotated[bool, typer.Option("--security", help="Security mode.")] = False,
    no_ai: Annotated[
        bool, typer.Option("--no-ai", help="Analyze without a language model.")
    ] = False,
    no_probes: Annotated[
        bool, typer.Option("--no-probes", help="Measure no context probes.")
    ] = False,
    show_noise: Annotated[bool, typer.Option("--show-noise", help="Show noise.")] = False,
    model: Annotated[str | None, typer.Option("--model", help="Model name.")] = None,
    ollama_url: Annotated[str | None, typer.Option("--ollama-url", help="Base URL.")] = None,
    evtx_dir: Annotated[
        Path | None, typer.Option("--evtx-dir", help="Brought-along .evtx exports.")
    ] = None,
) -> None:
    """Collection and analysis in one go. The normal case."""
    config = load_config(
        config_path,
        _overrides(days=days, security=security, no_ai=no_ai, show_noise=show_noise,
                   model=model, ollama_url=ollama_url, no_probes=no_probes),
    )
    if security:
        _enable_security_channel(config)
    log = configure(config.log_level)

    window_from, window_to = window_for(days or config.collect.days)
    run = RunDirectory.create(
        root=out, requested_from=window_from, requested_to=window_to, security_mode=security
    )
    log.attach_file(run.applog_path)
    log.info("Run created", directory=str(run.path), admin=is_admin())

    try:
        collect_all(config, run, days=days, evtx_dir=evtx_dir)
        result = analyze_run(run, config)
    except CollectionAborted as exc:
        typer.secho(f"\nAborted: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc
    except RuleLoadError as exc:
        typer.secho(f"Rules invalid: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc

    _print_sources(run)
    _print_summary(result.report, run)


@app.command()
def report(
    run_dir: RunOption,
    config_path: ConfigOption = None,
) -> None:
    """Rewrites the report of a run directory."""
    config = load_config(config_path)
    configure(config.log_level)
    run = RunDirectory.open(run_dir)
    result = analyze_run(run, config, write_outputs=False)
    written = write_report_files(result.report, run, config)
    for path in written:
        typer.echo(f"written: {path}")


@app.command()
def evidence(
    run_dir: RunOption,
    target: Annotated[Path | None, typer.Option("--out", help="Target file (.zip).")] = None,
    channels: Annotated[
        list[str] | None,
        typer.Option("--channel", help="Channel for the .evtx export. Can be repeated."),
    ] = None,
    config_path: ConfigOption = None,
) -> None:
    """Packs an evidence bundle with original .evtx, report, manifest and verify.ps1."""
    from .evidence.bundle import build_bundle, export_channels

    config = load_config(config_path)
    configure(config.log_level)
    run = RunDirectory.open(run_dir)
    destination = target or run.path / f"evidence_{run.read_meta().run_id}.zip"

    exported: list[tuple[Path, str | None]] = []
    if channels:
        try:
            shell = find_powershell(config.collect.powershell_preference)
        except PowerShellNotFoundError as exc:
            typer.secho(
                f"No .evtx export possible: {exc}\n"
                "The bundle then contains only the normalized extract - "
                "and the manifest says so.",
                fg=typer.colors.YELLOW,
            )
        else:
            exported = export_channels(
                run, list(channels), shell=shell, target_dir=run.path / "evtx"
            )

    path = build_bundle(run, destination, evtx_files=exported)
    typer.echo(f"Evidence bundle: {path}")
    typer.echo("Verify in the extracted directory with verify.ps1.")


@app.command()
def gui(config_path: ConfigOption = None) -> None:
    """Starts the graphical user interface.

    PySide6 is an optional dependency. The command line remains the way for
    servers and software distribution and runs without Qt.
    """
    from .gui import run_gui

    config = load_config(config_path)
    configure(config.log_level)
    raise typer.Exit(code=run_gui(config))


@app.command()
def doctor(
    config_path: ConfigOption = None,
    ollama_url: Annotated[
        str | None,
        typer.Option(
            "--ollama-url", help="Check an address once without changing the configuration."
        ),
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="Model name.")] = None,
) -> None:
    """Checks the environment before anything is analyzed.

    The most important part: matching the configured channels against the ones
    actually present. A filter on a non-existent channel would otherwise report
    'no findings' - the worst kind of error in this tool.

    A missing or unreachable Ollama is NOT an error here: the tool works
    without it. Only a configuration that cannot work (a model that is not
    present, a refused cloud model) sets a non-zero exit code.
    """
    config = load_config(
        config_path,
        _overrides(days=None, security=False, no_ai=False, show_noise=False,
                   model=model, ollama_url=ollama_url),
    )
    configure(config.log_level)
    ok = True

    typer.echo(f"WinEventAI {__version__}")
    typer.echo(f"Platform             : {sys.platform}")
    typer.echo(f"Admin rights         : {'yes' if is_admin() else 'no'}")
    user_cfg = user_config_path()
    if user_cfg.is_file():
        typer.echo(f"Configuration        : {user_cfg}")
    else:
        typer.echo(
            f"Configuration        : {user_cfg} (not present - the bundled defaults apply)"
        )
        typer.echo("                       Create with: wineventai config init")
    typer.echo(f"Rule overlay         : {overlay_dir(config.rules.overlay_dir)}")
    typer.echo(f"Run directories      : {default_runs_root()}")

    try:
        shell = find_powershell(config.collect.powershell_preference)
        typer.echo(f"PowerShell           : {shell.path}")
    except PowerShellNotFoundError as exc:
        typer.secho(f"PowerShell           : NOT FOUND ({exc})", fg=typer.colors.RED)
        shell = None
        ok = False

    try:
        rules = load_rules(
            overlay=config.rules.overlay_dir, include_security=config.rules.security_mode
        )
        typer.echo(f"Rules                : {len(rules)} loaded")
    except RuleLoadError as exc:
        typer.secho(f"Rules                : ERROR {exc}", fg=typer.colors.RED)
        ok = False

    with KnowledgeBase.open_default() as kb:
        typer.echo(f"Knowledge base       : {kb.count()} entries ({kb.path})")

    if not config.probes.enabled:
        typer.echo("Probes               : disabled")
    else:
        active = [
            name
            for name, on in (
                ("network", config.probes.network),
                ("services", config.probes.services),
                ("disks", config.probes.storage),
            )
            if on
        ]
        typer.echo(
            f"Probes               : {', '.join(active) or 'none'} "
            "(local network only, only on the collected machine)"
        )

    from .gui import gui_available

    if gui_available():
        typer.echo("User interface       : available ('wineventai gui')")
    else:
        typer.echo(
            "User interface       : not installed. In the project folder: "
            'pip install -e ".[gui]"'
        )

    if shell is not None:
        typer.echo("\nChannels:")
        available = _list_channels(shell, config)
        for entry in config.collect.channels:
            raw_state = "error" if available is None else available.get(
                entry.name.lower(), "error"
            )
            state = CHANNEL_STATE_LABEL[raw_state]
            if raw_state == "missing":
                ok = False
            flag = "" if entry.enabled else " (disabled)"
            colour = typer.colors.RED if raw_state == "missing" else None
            typer.secho(f"  {entry.name:<52} {state}{flag}", fg=colour)
        if available is not None:
            typer.echo(
                "\n  Note: WHEA-Logger (17/19) and storahci (129) are providers in the\n"
                "  System channel, not channels of their own. Missing channels are\n"
                "  reported as 'not available' and not as 'no findings'."
            )

    typer.echo("")
    if config.ai.enabled:
        from .ai.client import CloudCallBlockedError, OllamaClient

        try:
            client = OllamaClient(
                base_url=config.ai.base_url,
                model=config.ai.model,
                num_ctx=config.ai.num_ctx,
                timeout_seconds=10.0,
                allow_cloud=config.ai.allow_cloud,
            )
        except CloudCallBlockedError as exc:
            typer.secho(f"Ollama               : {exc}", fg=typer.colors.RED)
            ok = False
        else:
            state = client.status()
            if state.remote_model and not state.cloud_allowed:
                typer.echo(f"Ollama               : reachable at {config.ai.base_url}")
                typer.secho(
                    f"Model                : {state.message(config.ai.base_url, config.ai.model)}",
                    fg=typer.colors.RED,
                )
                ok = False
            elif state.usable:
                length = client.model_context_length()
                typer.echo(f"Ollama               : reachable at {config.ai.base_url}")
                typer.echo(
                    f"Model                : {config.ai.model}, context length "
                    f"{length if length else 'unknown'}, used "
                    f"{client.effective_num_ctx()}"
                )
            elif state.reachable:
                # Service running, model missing. That is something completely
                # different from a network problem - and only the second line
                # says what to do.
                typer.echo(f"Ollama               : reachable at {config.ai.base_url}")
                typer.secho(
                    f"Model                : {config.ai.model!r} NOT present",
                    fg=typer.colors.RED,
                )
                typer.echo("Available models     : "
                           + (", ".join(state.models) if state.models else "none"))
                typer.secho(
                    f"  Remedy: 'ollama pull {config.ai.model}' or set 'ai.model' in the "
                    "configuration to a model that is present.",
                    fg=typer.colors.YELLOW,
                )
                ok = False
            else:
                typer.secho(
                    f"Ollama               : not reachable at {config.ai.base_url} - "
                    "reports are built from the rule engine alone.",
                    fg=typer.colors.YELLOW,
                )
                typer.echo(f"  Reason: {state.detail or 'unknown'}")
                _print_connection_hints(config.ai.base_url)
    else:
        typer.echo("Ollama               : disabled by configuration")

    raise typer.Exit(code=0 if ok else 1)


def _print_connection_hints(base_url: str) -> None:
    """The four causes that apply, in this order.

    Deliberately as a checklist and not as a guess: which one it is cannot be
    seen from here, but each can be ruled out in one line.
    """
    import os

    typer.echo("")
    typer.echo("  If Ollama should be running, check in this order:")
    typer.echo("    1. Does Ollama answer at all?     curl http://localhost:11434/api/tags")
    typer.echo("    2. Different port or machine?     'ai.base_url' in the configuration,")
    typer.echo("       or once:                       wineventai doctor --ollama-url <url>")

    proxies = {
        name: os.environ[name]
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY")
        if os.environ.get(name)
    }
    if proxies:
        typer.secho(
            "    3. PROXY SET - on corporate machines the most common cause: "
            + ", ".join(f"{k}={v}" for k, v in proxies.items()),
            fg=typer.colors.YELLOW,
        )
        typer.echo("       WinEventAI bypasses the proxy for localhost since version 1.0.1.")
    else:
        typer.echo("    3. Proxy in the environment:       none set, ruled out.")

    host = (urlparse(base_url).hostname or "").lower()
    if host == "localhost":
        typer.echo("    4. IPv6 versus IPv4:              'localhost' can resolve to ::1,")
        typer.echo("       while Ollama only listens on 127.0.0.1. Then enter")
        typer.echo("       'http://127.0.0.1:11434' in the configuration.")


def _list_channels(shell: ShellInfo, config: Config) -> dict[str, str] | None:
    """Checks every configured channel individually via ``Get-WinEvent -ListLog``.

    ``None`` explicitly means "cannot be checked" and not "none present" -
    exactly the distinction this tool is about throughout.
    """
    from .collect.shell import channel_states_from_lines, join_list_arg

    names = [entry.name for entry in config.collect.channels]
    if not names:
        return {}
    try:
        result = run_script(
            "list_channels.ps1",
            ["-Names", join_list_arg(names)],
            shell=shell,
            timeout_seconds=60.0,
        )
    except OSError:
        return None
    return channel_states_from_lines(result.lines)


@config_app.command("init")
def config_init(
    full: Annotated[
        bool,
        typer.Option(
            "--full",
            help="Write all values active instead of commented out. See the warning below.",
        ),
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite an existing file (keeps a .bak).")
    ] = False,
) -> None:
    """Creates the user configuration in %PROGRAMDATA%.

    It deliberately does not appear by itself on first start: a file nobody
    created is read by nobody - and freezes values anyway.
    """
    from .config.loader import write_user_config

    try:
        path = write_user_config(full=full, force=force)
    except FileExistsError as exc:
        typer.secho(str(exc), fg=typer.colors.YELLOW)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Created: {path}")
    if full:
        typer.secho(
            "Caution: --full writes all values active. That freezes today's defaults - "
            "future corrections of the bundled defaults no longer apply to these keys.",
            fg=typer.colors.YELLOW,
        )
    else:
        typer.echo("Everything is commented out. Only what you uncomment takes effect.")
    typer.echo("Check effective values with: wineventai config show")


@config_app.command("path")
def config_path_cmd() -> None:
    """Shows where the configuration is looked for - and whether it is there."""
    from .config.loader import effective_config_sources

    for name, path, exists in effective_config_sources():
        state = "present" if exists else "not present"
        typer.echo(f"{name:<14} {path}  [{state}]")
    if not user_config_path().is_file():
        typer.echo("\n'wineventai config init' creates the user configuration.")


@config_app.command("show")
def config_show(
    config_path: ConfigOption = None,
    ollama_url: Annotated[
        str | None, typer.Option("--ollama-url", help="Base URL of Ollama.")
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="Model name.")] = None,
    days: DaysOption = None,
) -> None:
    """Shows the EFFECTIVE values after merging all layers.

    The difference to looking at the YAML is the point: this shows what really
    applies - including the command-line switches.
    """
    import yaml as _yaml

    config = load_config(
        config_path,
        _overrides(days=days, security=False, no_ai=False, show_noise=False,
                   model=model, ollama_url=ollama_url),
    )
    typer.echo(
        _yaml.safe_dump(
            config.model_dump(mode="json"), allow_unicode=True, sort_keys=False, indent=2
        )
    )


@kb_app.command("list")
def kb_list() -> None:
    """Shows the entries of the knowledge base."""
    with KnowledgeBase.open_default() as kb:
        for entry in kb.all_entries():
            flag = {"verified": " ", "unverified": "?", "empty": "!"}.get(
                str(entry.confidence), "?"
            )
            typer.echo(
                f" {flag} {entry.provider:<46} {entry.event_id:>6}  "
                f"{str(entry.confidence):<10} {entry.meaning.strip()[:70]}"
            )
        typer.echo(f"\n{kb.count()} entries in {kb.path}")


@kb_app.command("search")
def kb_search(query: Annotated[str, typer.Argument(help="Search term.")]) -> None:
    """Full-text search in the knowledge base."""
    with KnowledgeBase.open_default() as kb:
        hits = kb.search(query, limit=10)
        if not hits:
            typer.echo("No hits.")
            return
        for entry in hits:
            typer.echo(f"{entry.provider}:{entry.event_id} [{entry.confidence}]")
            typer.echo(f"  {entry.meaning.strip()}")


@kb_app.command("unknown")
def kb_unknown(run_dir: RunOption) -> None:
    """Shows the work list of a run: pairs without a verified entry."""
    run = RunDirectory.open(run_dir)
    if not run.unknown_ids_path.is_file():
        typer.echo("No work list present. Run 'analyze' first.")
        raise typer.Exit(code=1)
    typer.echo(run.unknown_ids_path.read_text(encoding="utf-8-sig"))


@kb_app.command("reseed")
def kb_reseed() -> None:
    """Loads the bundled entries into the knowledge base again."""
    with KnowledgeBase.open_default(seed_if_empty=False) as kb:
        count = kb.load_seed()
        typer.echo(f"{count} entries loaded. Total now: {kb.count()}.")


@kb_app.command("stats")
def kb_stats() -> None:
    """Shows how complete the knowledge base is - with a work list of the gaps."""
    from .kb.stats import compute_stats, format_stats

    with KnowledgeBase.open_default() as kb:
        for line in format_stats(compute_stats(kb.all_entries()), str(kb.path)):
            typer.echo(line)


def _print_summary(report_model: object, run: RunDirectory) -> None:
    from .report.model import ReportModel

    assert isinstance(report_model, ReportModel)
    typer.echo("")
    typer.secho(report_model.headline, bold=True)
    typer.echo(
        f"{report_model.total_events:,} events, "
        f"{report_model.distinct_groups:,} fingerprints, "
        f"reduction {report_model.reduction_rate * 100:.1f} %"
    )

    if report_model.has_coverage_problem:
        typer.secho(
            "Caution: the period was not collected completely. "
            "Mind the coverage table in the report.",
            fg=typer.colors.YELLOW,
        )

    for finding in report_model.findings[:10]:
        colour = {
            "critical": typer.colors.RED,
            "error": typer.colors.YELLOW,
        }.get(str(finding.severity))
        typer.secho(
            f"  [{finding.severity:<8}] {finding.rule_name} "
            f"({finding.group.count}x {finding.group.provider}:{finding.group.event_id})",
            fg=colour,
        )

    typer.echo("")
    typer.echo(report_model.ai_note)
    typer.echo(f"Report: {run.report_dir}")


def cli() -> None:  # pragma: no cover - entry point
    app()


if __name__ == "__main__":  # pragma: no cover
    cli()
