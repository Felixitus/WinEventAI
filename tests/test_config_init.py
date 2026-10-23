"""Creating the user configuration, and the entry point."""

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


def test_the_file_is_not_created_on_its_own() -> None:
    """A tool that writes into %LOCALAPPDATA% unasked is a surprise."""
    load_config()
    assert not user_config_path().exists()


def test_init_creates_the_file() -> None:
    path = write_user_config()
    assert path.is_file()
    assert path == user_config_path()
    text = path.read_text(encoding="utf-8")
    assert "wineventai config show" in text, "the header must point to the way to check"


def test_the_created_file_is_completely_commented_out() -> None:
    """So that it does not freeze any defaults.

    A complete copy would be more convenient and worse: it freezes the defaults
    of the installation day, and a later correction of the bundled values then
    never takes effect.
    """
    path = write_user_config()
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert payload is None, "the fresh file must not set a single active value"


def test_the_created_file_does_not_change_the_effective_values() -> None:
    before = load_config()
    write_user_config()
    after = load_config()
    assert before == after


def test_an_uncommented_value_takes_effect() -> None:
    path = write_user_config()
    text = (
        path.read_text(encoding="utf-8")
        .replace("# collect:", "collect:", 1)
        .replace("#   days: 7", "  days: 21", 1)
    )
    path.write_text(text, encoding="utf-8")

    assert load_config().collect.days == 21
    assert load_config().collect.max_retained_per_channel == 200_000, (
        "the rest stays tied to the bundled defaults"
    )


def test_full_writes_active_values() -> None:
    path = write_user_config(full=True)
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert payload is not None
    assert payload["collect"]["days"] == 7


def test_a_second_call_without_force_is_refused() -> None:
    write_user_config()
    with pytest.raises(FileExistsError):
        write_user_config()


def test_force_backs_up_the_previous_version() -> None:
    path = write_user_config()
    path.write_text("collect:\n  days: 3\n", encoding="utf-8")

    write_user_config(force=True)
    backup = path.with_suffix(path.suffix + ".bak")
    assert backup.is_file()
    assert "days: 3" in backup.read_text(encoding="utf-8")


def test_comments_and_blank_lines_are_kept() -> None:
    """The explanations in the defaults file are half its value."""
    original = default_config_text()
    result = commented_out(original)

    assert "# Bundled defaults" in result
    assert result.count("\n\n") > 3, "the structure by blank lines stays"
    for line in result.splitlines():
        if line.strip():
            assert line.lstrip().startswith("#"), f"not commented out: {line!r}"


def test_the_source_list_reports_a_missing_file() -> None:
    sources = dict((name, exists) for name, _, exists in effective_config_sources())
    assert sources["bundled"] is True
    assert sources["user"] is False

    write_user_config()
    sources = dict((name, exists) for name, _, exists in effective_config_sources())
    assert sources["user"] is True


def test_a_forgotten_parent_key_fails_visibly() -> None:
    """The most common usage trap when uncommenting.

    Whoever uncomments only the value line and forgets the parent key sets the
    value at the top level. That MUST fail with a clear message and must not
    silently do nothing - which is why 'extra=forbid' is in the config model.
    """
    from pydantic import ValidationError

    path = write_user_config()
    text = path.read_text(encoding="utf-8").replace("#   days: 7", "  days: 30", 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValidationError) as excinfo:
        load_config()
    assert "days" in str(excinfo.value)


def test_the_entry_point_uses_no_relative_imports() -> None:
    """PyInstaller starts __main__.py as a script - relative imports fail there."""
    import ast
    from pathlib import Path

    import wineventai

    source = (Path(wineventai.__file__).parent / "__main__.py").read_text(encoding="utf-8")
    relative = [
        node for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.level > 0
    ]
    assert relative == []


def test_only_the_gui_exe_starts_the_user_interface() -> None:
    from wineventai.__main__ import wants_gui

    assert wants_gui(r"C:\Program Files\wineventai\wineventai-gui.exe", frozen=True)
    assert not wants_gui(r"C:\Program Files\wineventai\wineventai.exe", frozen=True)
    assert not wants_gui(r"C:\Python\python.exe", frozen=False)


def test_unprintable_characters_do_not_crash_redirected_output() -> None:
    """U+200E from a Windows message ended 'kb unknown' when redirected."""
    import io

    from wineventai.console import harden_console_streams

    buffer = io.BytesIO()
    stream = io.TextIOWrapper(buffer, encoding="cp1252")
    harden_console_streams(stream)
    stream.write("C:/Users/\u200eapp.exe")
    stream.flush()
    assert buffer.getvalue() == b"C:/Users/?app.exe"


def test_the_data_folder_is_per_user_and_not_shared(monkeypatch) -> None:
    """Below ProgramData every user may plant files that an admin would load."""
    import sys

    from wineventai import resources

    monkeypatch.delenv("WINEVENTAI_DATA_DIR", raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\someone\AppData\Local")
    path = resources.data_dir()
    assert str(path).startswith(r"C:\Users\someone\AppData\Local")
    assert "ProgramData" not in str(path)


def test_the_old_shared_folder_is_never_reported_under_a_test_override() -> None:
    from wineventai.resources import legacy_shared_data

    assert legacy_shared_data() is None
