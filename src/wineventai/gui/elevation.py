"""Restart with administrator rights - via the UAC prompt, not a command line.

The Security channel and the security mode need admin rights. Until 2.3.0 the
only way to get them was "right-click, run as administrator" or an elevated
console - both things the target group of a double-click tool does not do.

How it works: ``ShellExecuteW`` with the verb ``runas`` starts the same program
again; Windows shows the UAC prompt. The current window closes only once the
new process has been started - if the user declines the prompt, nothing is
lost.

What it deliberately does not do: elevate itself inside the running process
(impossible on Windows), or keep a non-elevated "helper" talking to an elevated
one. One process, one set of rights, visible in the status bar.

The command construction is a pure function so that it can be tested without
Windows and without a UAC prompt.
"""

from __future__ import annotations

import subprocess
import sys

#: Passed to the new process so that the tick the user set is not lost.
SECURITY_FLAG = "--security"

#: ShellExecuteW returns a value above 32 on success; ERROR_CANCELLED when the
#: user declines the UAC prompt.
SHELL_EXECUTE_OK = 32


def relaunch_command(*, frozen: bool, executable: str, security: bool) -> tuple[str, str]:
    """Program and parameter string for the elevated restart.

    Frozen (the EXE): the GUI EXE starts itself. From source: the interpreter
    with ``-m wineventai gui`` - ``sys.argv[0]`` would be a path to
    ``__main__.py`` or a pip launcher and is not reliable for that.
    """
    arguments: list[str] = [] if frozen else ["-m", "wineventai", "gui"]
    if security:
        arguments.append(SECURITY_FLAG)
    return executable, subprocess.list2cmdline(arguments)


def relaunch_elevated(*, security: bool) -> bool:
    """Starts the program again with the UAC prompt. True if it was started."""
    if sys.platform != "win32":
        return False
    import ctypes

    program, parameters = relaunch_command(
        frozen=bool(getattr(sys, "frozen", False)),
        executable=sys.executable,
        security=security,
    )
    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", program, parameters or None, None, 1
        )
    except (AttributeError, OSError):
        return False
    return int(result) > SHELL_EXECUTE_OK


def wants_security_mode(argv: list[str]) -> bool:
    """True if the program was started with the security flag."""
    return SECURITY_FLAG in argv[1:]
