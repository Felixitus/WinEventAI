"""Kommandozeile.

Befehle:

* ``collect``  - Quellen erheben, Laufverzeichnis anlegen
* ``analyze``  - vorhandenes Laufverzeichnis auswerten (ohne Neuerhebung)
* ``run``      - beides in einem Zug, der Normalfall
* ``report``   - Bericht aus einem Laufverzeichnis neu schreiben
* ``evidence`` - Evidenz-Bundle als ZIP packen
* ``doctor``   - Umgebung pruefen: PowerShell, Kanaele, Ollama, Rechte
* ``kb``       - Wissensbasis anzeigen und pflegen
* ``config``   - Konfiguration anlegen und wirksame Werte anzeigen
* ``gui``      - grafische Oberflaeche (braucht PySide6)
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
    CHANNEL_STATE_DE,
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
    help="WinEventAI - lokale Windows-Diagnose mit Regel-Engine und lokalem Sprachmodell.",
)
kb_app = typer.Typer(no_args_is_help=True, help="Wissensbasis anzeigen und pflegen.")
app.add_typer(kb_app, name="kb")
config_app = typer.Typer(no_args_is_help=True, help="Konfiguration anlegen und anzeigen.")
app.add_typer(config_app, name="config")

ConfigOption = Annotated[
    Path | None, typer.Option("--config", "-c", help="Eigene Konfigurationsdatei.")
]
DaysOption = Annotated[
    int | None,
    typer.Option("--days", "-d", help="Zeitfenster in Tagen (Default: Konfiguration)."),
]
RunOption = Annotated[Path, typer.Option("--run", "-r", help="Laufverzeichnis.")]


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
        # Der Security-Kanal ist per Default abgeschaltet - im Sicherheitsmodus
        # muss er an, sonst laeuft die Pruefung ins Leere.
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
    """Schaltet den Security-Kanal ein, wenn der Sicherheitsmodus laeuft."""
    for entry in config.collect.channels:  # type: ignore[attr-defined]
        if entry.name.lower() == "security":
            entry.enabled = True


def _print_sources(run: RunDirectory) -> None:
    typer.echo("")
    typer.echo("Abdeckung:")
    for source in run.read_sources():
        marker = "!" if source.status in INCONCLUSIVE else " "
        typer.echo(
            f" {marker} {source.source_id:<52} {str(source.status):<18} "
            f"gelesen {source.records_read:>8}  behalten {source.records_retained:>8}"
        )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool, typer.Option("--version", help="Version ausgeben und beenden.")
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
        Path | None, typer.Option("--out", help="Wurzelverzeichnis fuer Laeufe.")
    ] = None,
    evtx_dir: Annotated[
        Path | None,
        typer.Option("--evtx-dir", help="Mitgebrachte .evtx-Exporte statt Live-Erhebung."),
    ] = None,
    security: Annotated[bool, typer.Option("--security", help="Sicherheitsmodus.")] = False,
) -> None:
    """Erhebt alle konfigurierten Quellen in ein neues Laufverzeichnis."""
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
    log.info("Lauf angelegt", verzeichnis=str(run.path), admin=is_admin())

    try:
        collect_all(config, run, days=days, evtx_dir=evtx_dir)
    except CollectionAborted as exc:
        typer.secho(f"\nAbgebrochen: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc

    _print_sources(run)
    typer.echo(f"\nLaufverzeichnis: {run.path}")


@app.command()
def analyze(
    run_dir: RunOption,
    config_path: ConfigOption = None,
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Ohne Sprachmodell auswerten.")] = False,
    no_probes: Annotated[
        bool,
        typer.Option("--no-probes", help="Keine Kontext-Sonden messen (kein Ping, kein SMART)."),
    ] = False,
    show_noise: Annotated[
        bool, typer.Option("--show-noise", help="Als Rauschen klassifizierte Befunde anzeigen.")
    ] = False,
    security: Annotated[bool, typer.Option("--security", help="Sicherheitsmodus.")] = False,
    model: Annotated[str | None, typer.Option("--model", help="Modellname.")] = None,
    ollama_url: Annotated[
        str | None, typer.Option("--ollama-url", help="Basis-URL von Ollama.")
    ] = None,
    report_redacted: Annotated[
        bool,
        typer.Option(
            "--report-redacted",
            help="Zusaetzlich eine pseudonymisierte, weitergabefaehige Fassung schreiben.",
        ),
    ] = False,
) -> None:
    """Wertet ein vorhandenes Laufverzeichnis aus - ohne neue Erhebung."""
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
        typer.secho(f"Regeln fehlerhaft: {exc}", fg=typer.colors.RED)
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
        Path | None, typer.Option("--out", help="Wurzelverzeichnis fuer Laeufe.")
    ] = None,
    security: Annotated[bool, typer.Option("--security", help="Sicherheitsmodus.")] = False,
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Ohne Sprachmodell auswerten.")] = False,
    no_probes: Annotated[
        bool, typer.Option("--no-probes", help="Keine Kontext-Sonden messen.")
    ] = False,
    show_noise: Annotated[bool, typer.Option("--show-noise", help="Rauschen anzeigen.")] = False,
    model: Annotated[str | None, typer.Option("--model", help="Modellname.")] = None,
    ollama_url: Annotated[str | None, typer.Option("--ollama-url", help="Basis-URL.")] = None,
    evtx_dir: Annotated[
        Path | None, typer.Option("--evtx-dir", help="Mitgebrachte .evtx-Exporte.")
    ] = None,
) -> None:
    """Erhebung und Auswertung in einem Zug. Der Normalfall."""
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
    log.info("Lauf angelegt", verzeichnis=str(run.path), admin=is_admin())

    try:
        collect_all(config, run, days=days, evtx_dir=evtx_dir)
        result = analyze_run(run, config)
    except CollectionAborted as exc:
        typer.secho(f"\nAbgebrochen: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc
    except RuleLoadError as exc:
        typer.secho(f"Regeln fehlerhaft: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc

    _print_sources(run)
    _print_summary(result.report, run)


@app.command()
def report(
    run_dir: RunOption,
    config_path: ConfigOption = None,
) -> None:
    """Schreibt den Bericht eines Laufverzeichnisses neu."""
    config = load_config(config_path)
    configure(config.log_level)
    run = RunDirectory.open(run_dir)
    result = analyze_run(run, config, write_outputs=False)
    written = write_report_files(result.report, run, config)
    for path in written:
        typer.echo(f"geschrieben: {path}")


@app.command()
def evidence(
    run_dir: RunOption,
    target: Annotated[Path | None, typer.Option("--out", help="Zieldatei (.zip).")] = None,
    channels: Annotated[
        list[str] | None,
        typer.Option("--channel", help="Kanal fuer den .evtx-Export. Mehrfach moeglich."),
    ] = None,
    config_path: ConfigOption = None,
) -> None:
    """Packt ein Evidenz-Bundle mit Original-.evtx, Bericht, Manifest und verify.ps1."""
    from .evidence.bundle import build_bundle, export_channels

    config = load_config(config_path)
    configure(config.log_level)
    run = RunDirectory.open(run_dir)
    destination = target or run.path / f"evidenz_{run.read_meta().run_id}.zip"

    exported: list[tuple[Path, str | None]] = []
    if channels:
        try:
            shell = find_powershell(config.collect.powershell_preference)
        except PowerShellNotFoundError as exc:
            typer.secho(
                f"Kein .evtx-Export moeglich: {exc}\n"
                "Das Bundle enthaelt dann nur den normalisierten Auszug - "
                "und das Manifest sagt das auch.",
                fg=typer.colors.YELLOW,
            )
        else:
            exported = export_channels(
                run, list(channels), shell=shell, target_dir=run.path / "evtx"
            )

    path = build_bundle(run, destination, evtx_files=exported)
    typer.echo(f"Evidenz-Bundle: {path}")
    typer.echo("Pruefen im entpackten Verzeichnis mit verify.ps1.")


@app.command()
def gui(config_path: ConfigOption = None) -> None:
    """Startet die grafische Oberflaeche.

    PySide6 ist eine optionale Abhaengigkeit. Die Kommandozeile bleibt der Weg
    fuer Server und Softwareverteilung und laeuft ohne Qt.
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
            "--ollama-url", help="Adresse einmalig pruefen, ohne die Konfiguration zu aendern."
        ),
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="Modellname.")] = None,
) -> None:
    """Prueft die Umgebung, bevor irgendetwas ausgewertet wird.

    Wichtigster Teil: der Abgleich der konfigurierten Kanaele gegen die
    tatsaechlich vorhandenen. Ein Filter auf einen nicht existierenden Kanal
    meldet sonst 'keine Befunde' - die schlimmste Fehlerart in diesem Werkzeug.
    """
    config = load_config(
        config_path,
        _overrides(days=None, security=False, no_ai=False, show_noise=False,
                   model=model, ollama_url=ollama_url),
    )
    configure(config.log_level)
    ok = True

    typer.echo(f"WinEventAI {__version__}")
    typer.echo(f"Plattform            : {sys.platform}")
    typer.echo(f"Adminrechte          : {'ja' if is_admin() else 'nein'}")
    user_cfg = user_config_path()
    if user_cfg.is_file():
        typer.echo(f"Konfiguration        : {user_cfg}")
    else:
        typer.echo(
            f"Konfiguration        : {user_cfg} (nicht vorhanden - es gelten die "
            "mitgelieferten Vorgaben)"
        )
        typer.echo("                       Anlegen mit: wineventai config init")
    typer.echo(f"Regel-Overlay        : {overlay_dir(config.rules.overlay_dir)}")
    typer.echo(f"Laufverzeichnisse    : {default_runs_root()}")

    try:
        shell = find_powershell(config.collect.powershell_preference)
        typer.echo(f"PowerShell           : {shell.path}")
    except PowerShellNotFoundError as exc:
        typer.secho(f"PowerShell           : NICHT GEFUNDEN ({exc})", fg=typer.colors.RED)
        shell = None
        ok = False

    try:
        rules = load_rules(
            overlay=config.rules.overlay_dir, include_security=config.rules.security_mode
        )
        typer.echo(f"Regeln               : {len(rules)} geladen")
    except RuleLoadError as exc:
        typer.secho(f"Regeln               : FEHLER {exc}", fg=typer.colors.RED)
        ok = False

    with KnowledgeBase.open_default() as kb:
        typer.echo(f"Wissensbasis         : {kb.count()} Eintraege ({kb.path})")

    if not config.probes.enabled:
        typer.echo("Sonden               : abgeschaltet")
    else:
        aktiv = [
            name
            for name, an in (
                ("Netz", config.probes.network),
                ("Dienste", config.probes.services),
                ("Datentraeger", config.probes.storage),
            )
            if an
        ]
        typer.echo(
            f"Sonden               : {', '.join(aktiv) or 'keine'} "
            "(nur lokales Netz, nur auf dem erhobenen Rechner)"
        )

    from .gui import gui_available

    if gui_available():
        typer.echo("Oberflaeche          : verfuegbar ('wineventai gui')")
    else:
        typer.echo(
            "Oberflaeche          : nicht installiert. Im Projektordner: "
            'pip install -e ".[gui]"'
        )

    if shell is not None:
        typer.echo("\nKanaele:")
        available = _list_channels(shell, config)
        for entry in config.collect.channels:
            raw_state = "error" if available is None else available.get(
                entry.name.lower(), "error"
            )
            state = CHANNEL_STATE_DE[raw_state]
            if raw_state == "missing":
                ok = False
            flag = "" if entry.enabled else " (abgeschaltet)"
            colour = typer.colors.RED if state == "FEHLT" else None
            typer.secho(f"  {entry.name:<52} {state}{flag}", fg=colour)
        if available is not None:
            typer.echo(
                "\n  Hinweis: WHEA-Logger (17/19) und storahci (129) sind Provider im\n"
                "  System-Kanal, keine eigenen Kanaele. Fehlende Kanaele werden als\n"
                "  'kanal fehlt' gemeldet und nicht als 'keine Befunde'."
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
            if state.usable:
                length = client.model_context_length()
                typer.echo(
                    f"Ollama               : erreichbar unter {config.ai.base_url}"
                )
                typer.echo(
                    f"Modell               : {config.ai.model}, Kontextlaenge "
                    f"{length if length else 'unbekannt'}, verwendet "
                    f"{client.effective_num_ctx()}"
                )
            elif state.reachable:
                # Dienst laeuft, Modell fehlt. Das ist etwas voellig anderes als
                # ein Netzwerkproblem - und nur die zweite Zeile sagt, was zu tun ist.
                typer.echo(f"Ollama               : erreichbar unter {config.ai.base_url}")
                typer.secho(
                    f"Modell               : {config.ai.model!r} NICHT vorhanden",
                    fg=typer.colors.RED,
                )
                typer.echo("Vorhandene Modelle   : "
                           + (", ".join(state.models) if state.models else "keine"))
                typer.secho(
                    f"  Abhilfe: 'ollama pull {config.ai.model}' oder 'ai.model' in der "
                    "Konfiguration auf ein vorhandenes Modell setzen.",
                    fg=typer.colors.YELLOW,
                )
                ok = False
            else:
                typer.secho(
                    f"Ollama               : nicht erreichbar unter {config.ai.base_url}",
                    fg=typer.colors.YELLOW,
                )
                typer.echo(f"  Grund: {state.detail or 'unbekannt'}")
                _print_connection_hints(config.ai.base_url)
    else:
        typer.echo("Ollama               : per Konfiguration abgeschaltet")

    raise typer.Exit(code=0 if ok else 1)


def _print_connection_hints(base_url: str) -> None:
    """Die vier Ursachen, die in dieser Reihenfolge zutreffen.

    Bewusst als Pruefliste und nicht als Vermutung: Welche es ist, sieht man von
    hier aus nicht, aber jede laesst sich in einer Zeile ausschliessen.
    """
    import os

    typer.echo("")
    typer.echo("  Wenn der Dienst laut Dienstverwaltung laeuft, in dieser Reihenfolge pruefen:")
    typer.echo("    1. Antwortet Ollama ueberhaupt?   curl http://localhost:11434/api/tags")
    typer.echo("    2. Anderer Port oder Rechner?     'ai.base_url' in der Konfiguration,")
    typer.echo("       oder einmalig:                 wineventai doctor --ollama-url <url>")

    proxies = {
        name: os.environ[name]
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY")
        if os.environ.get(name)
    }
    if proxies:
        typer.secho(
            "    3. PROXY GESETZT - das ist auf Firmenrechnern die haeufigste Ursache: "
            + ", ".join(f"{k}={v}" for k, v in proxies.items()),
            fg=typer.colors.YELLOW,
        )
        typer.echo("       WinEventAI umgeht den Proxy fuer localhost ab Version 1.0.1.")
    else:
        typer.echo("    3. Proxy in der Umgebung:          keiner gesetzt, scheidet aus.")

    host = (urlparse(base_url).hostname or "").lower()
    if host == "localhost":
        typer.echo("    4. IPv6 gegen IPv4:               'localhost' kann zu ::1 aufloesen,")
        typer.echo("       waehrend Ollama nur auf 127.0.0.1 lauscht. Dann in der")
        typer.echo("       Konfiguration 'http://127.0.0.1:11434' eintragen.")


def _list_channels(shell: ShellInfo, config: Config) -> dict[str, str] | None:
    """Prueft jeden konfigurierten Kanal einzeln ueber ``Get-WinEvent -ListLog``.

    ``None`` heisst ausdruecklich "nicht pruefbar" und nicht "keiner vorhanden" -
    genau die Unterscheidung, um die es in diesem Werkzeug durchgehend geht.
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
            help="Alle Werte aktiv schreiben statt auskommentiert. Siehe Warnung unten.",
        ),
    ] = False,
    force: Annotated[
        bool, typer.Option("--force", help="Vorhandene Datei ueberschreiben (sichert .bak).")
    ] = False,
) -> None:
    """Legt die Benutzerkonfiguration in %PROGRAMDATA% an.

    Sie entsteht bewusst nicht von selbst beim ersten Start: Eine Datei, die
    niemand angelegt hat, liest auch niemand - und friert trotzdem Werte ein.
    """
    from .config.loader import write_user_config

    try:
        path = write_user_config(full=full, force=force)
    except FileExistsError as exc:
        typer.secho(str(exc), fg=typer.colors.YELLOW)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Angelegt: {path}")
    if full:
        typer.secho(
            "Achtung: --full schreibt alle Werte aktiv. Damit frieren Sie die Vorgaben "
            "von heute ein - kuenftige Korrekturen an den mitgelieferten Vorgaben "
            "greifen fuer diese Schluessel nicht mehr.",
            fg=typer.colors.YELLOW,
        )
    else:
        typer.echo("Alles ist auskommentiert. Wirksam wird nur, was Sie einkommentieren.")
    typer.echo("Wirksame Werte pruefen mit: wineventai config show")


@config_app.command("path")
def config_path_cmd() -> None:
    """Zeigt, wo die Konfiguration gesucht wird - und ob sie dort liegt."""
    from .config.loader import effective_config_sources

    for name, path, exists in effective_config_sources():
        state = "vorhanden" if exists else "nicht vorhanden"
        typer.echo(f"{name:<14} {path}  [{state}]")
    if not user_config_path().is_file():
        typer.echo("\n'wineventai config init' legt die Benutzerkonfiguration an.")


@config_app.command("show")
def config_show(
    config_path: ConfigOption = None,
    ollama_url: Annotated[
        str | None, typer.Option("--ollama-url", help="Basis-URL von Ollama.")
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="Modellname.")] = None,
    days: DaysOption = None,
) -> None:
    """Zeigt die WIRKSAMEN Werte nach dem Zusammenfuehren aller Ebenen.

    Der Unterschied zum Anschauen der YAML ist der Punkt: Hier steht, was
    tatsaechlich gilt - inklusive der Schalter von der Kommandozeile.
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
    """Zeigt die Eintraege der Wissensbasis."""
    with KnowledgeBase.open_default() as kb:
        for entry in kb.all_entries():
            flag = {"sicher": " ", "unsicher": "?", "leer": "!"}.get(str(entry.confidence), "?")
            typer.echo(
                f" {flag} {entry.provider:<46} {entry.event_id:>6}  "
                f"{str(entry.confidence):<9} {entry.bedeutung.strip()[:70]}"
            )
        typer.echo(f"\n{kb.count()} Eintraege in {kb.path}")


@kb_app.command("search")
def kb_search(query: Annotated[str, typer.Argument(help="Suchbegriff.")]) -> None:
    """Volltextsuche in der Wissensbasis."""
    with KnowledgeBase.open_default() as kb:
        hits = kb.search(query, limit=10)
        if not hits:
            typer.echo("Keine Treffer.")
            return
        for entry in hits:
            typer.echo(f"{entry.provider}:{entry.event_id} [{entry.confidence}]")
            typer.echo(f"  {entry.bedeutung.strip()}")


@kb_app.command("unknown")
def kb_unknown(run_dir: RunOption) -> None:
    """Zeigt die Arbeitsliste eines Laufs: Paare ohne gesicherten Eintrag."""
    run = RunDirectory.open(run_dir)
    if not run.unknown_ids_path.is_file():
        typer.echo("Keine Arbeitsliste vorhanden. Zuerst 'analyze' ausfuehren.")
        raise typer.Exit(code=1)
    typer.echo(run.unknown_ids_path.read_text(encoding="utf-8-sig"))


@kb_app.command("reseed")
def kb_reseed() -> None:
    """Laedt die mitgelieferten Eintraege erneut in die Wissensbasis."""
    with KnowledgeBase.open_default(seed_if_empty=False) as kb:
        count = kb.load_seed()
        typer.echo(f"{count} Eintraege geladen. Bestand jetzt: {kb.count()}.")


@kb_app.command("stats")
def kb_stats() -> None:
    """Zeigt, wie vollstaendig die Wissensbasis ist - mit Arbeitsliste der Luecken."""
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
        f"{report_model.total_events:,} Ereignisse, "
        f"{report_model.distinct_groups:,} Fingerprints, "
        f"Reduktion {report_model.reduction_rate * 100:.1f} %".replace(",", ".")
    )

    if report_model.has_coverage_problem:
        typer.secho(
            "Achtung: Der Zeitraum wurde nicht vollstaendig erhoben. "
            "Abdeckungstabelle im Bericht beachten.",
            fg=typer.colors.YELLOW,
        )

    for finding in report_model.findings[:10]:
        colour = {
            "kritisch": typer.colors.RED,
            "fehler": typer.colors.YELLOW,
        }.get(str(finding.severity))
        typer.secho(
            f"  [{finding.severity:<8}] {finding.rule_name} "
            f"({finding.group.count}× {finding.group.provider}:{finding.group.event_id})",
            fg=colour,
        )

    typer.echo("")
    typer.echo(report_model.ai_note)
    typer.echo(f"Bericht: {run.report_dir}")


def cli() -> None:  # pragma: no cover - Einstiegspunkt
    app()


if __name__ == "__main__":  # pragma: no cover
    cli()
