"""Maskierung variabler Bestandteile fuer den Fingerprint.

Zwei Ereignisse desselben Typs unterscheiden sich in Zahlen, GUIDs, Handles und
Pfaden. Fuer die Deduplizierung muss das weg, sonst hat jeder Vorfall seinen
eigenen Fingerprint.

Wichtig: Diese Maskierung ist *nicht* die Redaction fuer das Sprachmodell. Sie
dient nur dem Vergleich und wird nie ausgegeben. Die Redaction steht in
``ai.redaction`` und arbeitet mit stabilen Pseudonymen.
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

# Reihenfolge ist relevant: Spezifisches vor Allgemeinem. Zahlen zuletzt,
# sonst zerlegt der Zahlen-Ersatz vorher GUIDs und IP-Adressen.
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
    """Ersetzt variable Bestandteile durch Platzhalter und normalisiert Leerraum."""
    if not text:
        return ""
    masked = text
    for pattern, placeholder in _STEPS:
        masked = pattern.sub(placeholder, masked)
    return _WS.sub(" ", masked).strip().casefold()


def mask_properties(properties: list[str | None]) -> str:
    """Maskiert den positionalen Property-Vektor eines Events.

    Der Property-Vektor ist die sprachneutrale Substanz eines Ereignisses; der
    Meldungstext ist nur seine Uebersetzung. Deshalb ist er die bessere
    Grundlage fuer den Fingerprint auf gemischten Systemen.
    """
    parts = []
    for value in properties:
        parts.append("" if value is None else mask_text(str(value)))
    return "".join(parts)
