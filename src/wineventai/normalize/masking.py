"""Masking of variable parts for the fingerprint.

Two events of the same type differ in numbers, GUIDs, handles and paths. For
deduplication that has to go, otherwise every incident gets its own
fingerprint.

Important: this masking is *not* the redaction for the language model. It is
only used for comparison and never output. Redaction lives in ``ai.redaction``
and works with stable pseudonyms.
"""

from __future__ import annotations

import re

_GUID = re.compile(
    r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?"
)
_SID = re.compile(r"\bS-1-(?:\d+-){1,14}\d+\b")
_HEX = re.compile(r"\b0[xX][0-9a-fA-F]+\b")
_WINPATH = re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|]*")
_UNCPATH = re.compile(r"\\\\[^\s\"'<>|]+")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_NUMBER = re.compile(r"\b\d+\b")
_WS = re.compile(r"\s+")

# Order matters: specific before general. Numbers last, otherwise the number
# replacement would tear apart GUIDs and IP addresses first.
_STEPS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_GUID, "<guid>"),
    (_SID, "<sid>"),
    (_MAC, "<mac>"),
    (_IPV4, "<ip>"),
    (_UNCPATH, "<unc>"),
    (_WINPATH, "<path>"),
    (_HEX, "<hex>"),
    (_NUMBER, "<n>"),
)


def mask_text(text: str) -> str:
    """Replaces variable parts with placeholders and normalizes whitespace."""
    if not text:
        return ""
    masked = text
    for pattern, placeholder in _STEPS:
        masked = pattern.sub(placeholder, masked)
    return _WS.sub(" ", masked).strip().casefold()


def mask_properties(properties: list[str | None]) -> str:
    """Masks the positional property vector of an event.

    The property vector is the language-neutral substance of an event; the
    message text is only its translation. That makes it the better basis for
    the fingerprint on mixed-language systems.
    """
    parts = []
    for value in properties:
        parts.append("" if value is None else mask_text(str(value)))
    return "".join(parts)
