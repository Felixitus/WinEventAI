"""Console output that survives redirection.

A module of its own and not part of ``cli.py``: the CLI imports half the
package including ``urllib``/``ssl``, and this function must be usable - and
testable - without any of that.
"""

from __future__ import annotations

import sys


def harden_console_streams(*streams: object) -> None:
    """Replaces unprintable characters instead of crashing on them.

    Windows messages carry characters such as U+200E (left-to-right mark) in
    file paths and names. A console window prints them, but as soon as the
    output is redirected - to a file, a pipe, a ticket system - Python writes
    with the ANSI code page, and one such character ended ``kb unknown`` with
    a UnicodeEncodeError and no output at all. A '?' in a work list is
    harmless; a crash is not. The encoding itself stays as it is, because
    whoever reads the redirected output expects the code page of the machine.
    """
    for stream in streams or (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (ValueError, OSError):
            # A closed or special stream: nothing to harden, nothing to break.
            continue
