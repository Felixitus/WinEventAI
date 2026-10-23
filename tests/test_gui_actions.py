"""Everything a double-click user needs without a command line.

Admin restart, the start parameter it passes on, and the buttons for a finished
run. The UAC prompt itself cannot be tested; the command it would start can.
"""

from __future__ import annotations

import pytest

pytest.importorskip("PySide6", reason='The user interface is optional (pip install -e ".[gui]")')

from PySide6.QtWidgets import QApplication  # noqa: E402

from wineventai.config import load_config  # noqa: E402
from wineventai.gui.elevation import (  # noqa: E402
    SECURITY_FLAG,
    relaunch_command,
    wants_security_mode,
)
from wineventai.gui.status import Environment  # noqa: E402


@pytest.fixture(scope="session")
def qapp() -> QApplication:
    return QApplication.instance() or QApplication([])


# --- Admin restart -----------------------------------------------------------


def test_the_exe_restarts_itself_without_extra_arguments() -> None:
    program, parameters = relaunch_command(
        frozen=True, executable=r"C:\Apps\WinEventAI\wineventai-gui.exe", security=False
    )
    assert program.endswith("wineventai-gui.exe")
    assert parameters == ""


def test_from_source_the_interpreter_starts_the_gui_module() -> None:
    program, parameters = relaunch_command(
        frozen=False, executable=r"C:\Python313\python.exe", security=False
    )
    assert program.endswith("python.exe")
    assert parameters == "-m wineventai gui"


def test_the_security_tick_survives_the_restart() -> None:
    _, parameters = relaunch_command(frozen=True, executable="x.exe", security=True)
    assert parameters == SECURITY_FLAG
    assert wants_security_mode(["wineventai-gui.exe", SECURITY_FLAG])
    assert not wants_security_mode(["wineventai-gui.exe"])


def test_the_admin_button_only_appears_where_it_can_help() -> None:
    assert Environment(platform="win32", admin=False).can_elevate
    assert not Environment(platform="win32", admin=True).can_elevate
    assert not Environment(platform="linux", admin=False).can_elevate


# --- Window ------------------------------------------------------------------


def _window(**kwargs):
    from wineventai.gui.main_window import MainWindow

    window = MainWindow(load_config(overrides={"ai": {"enabled": False}}), **kwargs)
    if window._probe:
        window._probe.stop()
    return window


def test_the_window_opens_with_security_mode_when_asked(qapp) -> None:
    window = _window(security=True)
    assert window.check_security.isChecked()
    window.close()


def test_run_actions_stay_hidden_until_there_is_a_run(qapp) -> None:
    """An empty window must not offer actions that cannot work yet."""
    window = _window()
    assert window.actions_row.isHidden()
    window.close()


def test_a_finished_run_shows_the_actions(qapp, fixture_run) -> None:
    from wineventai.analyze import analyze_run

    window = _window()
    result = analyze_run(fixture_run, load_config(overrides={"ai": {"enabled": False}}))
    window._on_finished(fixture_run, result)
    assert not window.actions_row.isHidden()
    assert window.button_evidence.isEnabled()
    window.close()


def test_the_admin_button_follows_the_environment(qapp) -> None:
    window = _window()
    window._apply_environment(Environment(platform="win32", admin=False))
    assert not window.button_admin.isHidden()
    window._apply_environment(Environment(platform="win32", admin=True))
    assert window.button_admin.isHidden()
    window.close()


def test_the_old_shared_folder_is_mentioned_in_the_log(qapp) -> None:
    window = _window()
    window._apply_environment(Environment(legacy_note="old folder note"))
    assert "old folder note" in window.log_view.toPlainText()
    window.close()
