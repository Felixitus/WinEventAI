"""Anlegen der Benutzerkonfiguration."""

from __future__ import annotations

import pytest
import yaml

from wineventai.config import load_config
from wineventai.config.loader import (
    commented_out,
    default_config_text,
    effective_config_sources,
    user_config_path,
    write_user_config,
)


def test_datei_wird_nicht_von_selbst_angelegt() -> None:
    """Ein Werkzeug, das ungefragt in %PROGRAMDATA% schreibt, ueberrascht."""
    load_config()
    assert not user_config_path().exists()


def test_init_legt_datei_an() -> None:
    path = write_user_config()
    assert path.is_file()
    assert path == user_config_path()
    text = path.read_text(encoding="utf-8")
    assert "wineventai config show" in text, "der Kopf muss den Weg zur Kontrolle nennen"


def test_angelegte_datei_ist_vollstaendig_auskommentiert() -> None:
    """Damit sie keine Vorgaben einfriert.

    Eine vollstaendige Kopie waere bequemer und schlechter: Sie friert die
    Vorgaben des Installationstags ein, und eine spaetere Korrektur an den
    mitgelieferten Werten greift dann nie.
    """
    path = write_user_config()
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert payload is None, "die frische Datei darf keinen einzigen aktiven Wert setzen"


def test_angelegte_datei_aendert_die_wirksamen_werte_nicht() -> None:
    vorher = load_config()
    write_user_config()
    nachher = load_config()
    assert vorher == nachher


def test_einkommentierter_wert_wird_wirksam() -> None:
    path = write_user_config()
    text = (
        path.read_text(encoding="utf-8")
        .replace("# collect:", "collect:", 1)
        .replace("#   days: 7", "  days: 21", 1)
    )
    path.write_text(text, encoding="utf-8")

    assert load_config().collect.days == 21
    assert load_config().collect.max_retained_per_channel == 200_000, (
        "der Rest bleibt an den mitgelieferten Vorgaben haengen"
    )


def test_full_schreibt_aktive_werte() -> None:
    path = write_user_config(full=True)
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert payload is not None
    assert payload["collect"]["days"] == 7


def test_zweiter_aufruf_ohne_force_wird_abgelehnt() -> None:
    write_user_config()
    with pytest.raises(FileExistsError):
        write_user_config()


def test_force_sichert_die_bisherige_fassung() -> None:
    path = write_user_config()
    path.write_text("collect:\n  days: 3\n", encoding="utf-8")

    write_user_config(force=True)
    backup = path.with_suffix(path.suffix + ".bak")
    assert backup.is_file()
    assert "days: 3" in backup.read_text(encoding="utf-8")


def test_kommentare_und_leerzeilen_bleiben_erhalten() -> None:
    """Die Erklaerungen in der Vorgabedatei sind der halbe Wert der Datei."""
    original = default_config_text()
    result = commented_out(original)

    assert "# Mitgelieferte Vorgabewerte" in result
    assert result.count("\n\n") > 3, "die Gliederung durch Leerzeilen bleibt"
    for line in result.splitlines():
        if line.strip():
            assert line.lstrip().startswith("#"), f"nicht auskommentiert: {line!r}"


def test_quellenliste_meldet_fehlende_datei() -> None:
    quellen = dict((name, exists) for name, _, exists in effective_config_sources())
    assert quellen["mitgeliefert"] is True
    assert quellen["benutzer"] is False

    write_user_config()
    quellen = dict((name, exists) for name, _, exists in effective_config_sources())
    assert quellen["benutzer"] is True


def test_vergessener_elternschluessel_bricht_sichtbar_ab() -> None:
    """Die haeufigste Bedienfalle beim Einkommentieren.

    Wer nur die Wertzeile einkommentiert und den Elternschluessel vergisst,
    setzt den Wert auf oberster Ebene. Das MUSS mit einer klaren Meldung
    abbrechen und darf nicht still wirkungslos bleiben - deshalb steht
    'extra=forbid' im Konfigurationsmodell.
    """
    from pydantic import ValidationError

    path = write_user_config()
    text = path.read_text(encoding="utf-8").replace("#   days: 7", "  days: 30", 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValidationError) as excinfo:
        load_config()
    assert "days" in str(excinfo.value)


def test_einstiegspunkt_kommt_ohne_relative_importe_aus() -> None:
    """PyInstaller startet __main__.py als Skript ohne Paket - relative Importe scheitern dort."""
    import ast
    from pathlib import Path

    import wineventai

    source = (Path(wineventai.__file__).parent / "__main__.py").read_text(encoding="utf-8")
    relative = [
        node for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.level > 0
    ]
    assert relative == []


def test_nur_die_gui_exe_startet_die_oberflaeche() -> None:
    from wineventai.__main__ import wants_gui

    assert wants_gui(r"C:\Programme\wineventai\wineventai-gui.exe", frozen=True)
    assert not wants_gui(r"C:\Programme\wineventai\wineventai.exe", frozen=True)
    assert not wants_gui(r"C:\Python\python.exe", frozen=False)
