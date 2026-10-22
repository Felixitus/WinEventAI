"""Redaction vor jedem Prompt - mit stabilen Pseudonymen.

Pauschale Sternchen waeren hier ein Denkfehler: Sie zerstoeren genau die
Information, fuer die es den "Korrelator" gibt, naemlich ob zwei Befunde
dasselbe Konto oder denselben Host betreffen. Ersetzt wird deshalb konsistent
je Lauf - ``BENUTZER_1``, ``HOST_1``, ``SID_1`` - mit einer Zuordnungstabelle,
die nur im Speicher lebt.

Zwei Details, die leicht untergehen:

* Ersetzt wird auf dem ``EventRecord`` nach der Normalisierung, nicht per
  Suchen-und-Ersetzen im fertigen Prompttext. Sonst erwischt man Teilzeichenketten.
* Beim Rueckersetzen wird geprueft, ob das Modell Platzhalter ERFUNDEN hat. Ein
  ``BENUTZER_7``, den es im Buendel nie gab, ist ein Halluzinationssignal.
"""

from __future__ import annotations

import re

from ..normalize.schema import EventRecord

_SID = re.compile(r"\bS-1-(?:\d+-){1,14}\d+\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_USERPATH = re.compile(r"(?i)\b([A-Z]:\\Users\\)([^\\\s\"'<>|]+)")
_DOMAIN_USER = re.compile(r"\b([A-Za-z0-9_-]{2,32})\\([A-Za-z0-9._-]{2,32})\b")
_PLACEHOLDER = re.compile(r"\b(BENUTZER|HOST|SID|IP|MAC|DOMAENE)_(\d+)\b")

#: Konten, die auf jedem Windows gleich heissen und nichts ueber Personen sagen.
_WELL_KNOWN_ACCOUNTS = {
    "system", "local service", "network service", "lokaler dienst",
    "netzwerkdienst", "nt authority", "nt-autoritaet", "administrator",
    "administratoren", "administrators", "users", "benutzer",
}

_WELL_KNOWN_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}


class Redactor:
    """Ersetzt personenbezogene Bestandteile durch stabile Pseudonyme."""

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled
        self._maps: dict[str, dict[str, str]] = {
            "BENUTZER": {},
            "HOST": {},
            "SID": {},
            "IP": {},
            "MAC": {},
            "DOMAENE": {},
        }

    # --- Zuordnung -----------------------------------------------------------

    def _token(self, kind: str, value: str) -> str:
        table = self._maps[kind]
        key = value.casefold()
        if key not in table:
            table[key] = f"{kind}_{len(table) + 1}"
        return table[key]

    def mapping(self) -> dict[str, str]:
        """Platzhalter -> Originalwert. Bleibt lokal, wandert nie in ein Bundle."""
        out: dict[str, str] = {}
        for kind, table in self._maps.items():
            for original, token in table.items():
                out[token] = original
            _ = kind
        return out

    def known_placeholders(self) -> set[str]:
        return set(self.mapping())

    # --- Ersetzen ------------------------------------------------------------

    def register_host(self, host: str) -> str:
        if not host:
            return ""
        return self._token("HOST", host.split(".")[0])

    def text(self, value: str | None) -> str | None:
        """Redigiert einen Freitext."""
        if value is None or not self.enabled:
            return value

        def sid_sub(match: re.Match[str]) -> str:
            found = match.group(0)
            if found in _WELL_KNOWN_SIDS:
                return found
            return self._token("SID", found)

        def userpath_sub(match: re.Match[str]) -> str:
            return match.group(1) + self._token("BENUTZER", match.group(2))

        def domain_user_sub(match: re.Match[str]) -> str:
            domain, user = match.group(1), match.group(2)
            if domain.casefold() in _WELL_KNOWN_ACCOUNTS:
                return match.group(0)
            return f"{self._token('DOMAENE', domain)}\\{self._token('BENUTZER', user)}"

        result = _SID.sub(sid_sub, value)
        result = _MAC.sub(lambda m: self._token("MAC", m.group(0)), result)
        result = _IPV4.sub(lambda m: self._token("IP", m.group(0)), result)
        result = _IPV6.sub(lambda m: self._token("IP", m.group(0)), result)
        result = _USERPATH.sub(userpath_sub, result)
        result = _DOMAIN_USER.sub(domain_user_sub, result)

        # Bekannte Hostnamen zuletzt, damit sie nicht Teile anderer Treffer zerlegen.
        for original, token in sorted(
            self._maps["HOST"].items(), key=lambda item: -len(item[0])
        ):
            result = re.sub(rf"\b{re.escape(original)}\b", token, result, flags=re.IGNORECASE)
        return result

    def record(self, record: EventRecord) -> EventRecord:
        """Liefert eine redigierte Kopie eines Events."""
        if not self.enabled:
            return record
        if record.computer:
            self.register_host(record.computer)
        return record.model_copy(
            update={
                "computer": self._token("HOST", record.computer.split(".")[0])
                if record.computer
                else "",
                "user_sid": (
                    record.user_sid
                    if record.user_sid in _WELL_KNOWN_SIDS
                    else (self._token("SID", record.user_sid) if record.user_sid else None)
                ),
                "message": self.text(record.message),
                "properties": [self.text(value) for value in record.properties],
                "event_data": (
                    {key: self.text(value) or "" for key, value in record.event_data.items()}
                    if record.event_data
                    else None
                ),
            }
        )

    # --- Rueckersetzen -------------------------------------------------------

    def restore(self, value: str) -> str:
        """Setzt Platzhalter wieder in Klartext um - fuer den vollstaendigen Bericht."""
        mapping = self.mapping()
        result = value
        for token, original in sorted(mapping.items(), key=lambda item: -len(item[0])):
            result = result.replace(token, original)
        return result

    def invented_placeholders(self, value: str) -> set[str]:
        """Platzhalter im Text, die es im Buendel nie gab.

        Das ist ein eigenstaendiges Halluzinationssignal und wird genauso
        behandelt wie eine fehlgeschlagene Evidenzpruefung.
        """
        known = self.known_placeholders()
        found = {f"{match.group(1)}_{match.group(2)}" for match in _PLACEHOLDER.finditer(value)}
        return found - known
