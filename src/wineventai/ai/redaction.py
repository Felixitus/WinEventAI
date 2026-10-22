"""Redaction before every prompt - with stable pseudonyms.

Blanket asterisks would be a mistake in reasoning here: they destroy exactly
the information the "correlator" exists for, namely whether two findings
concern the same account or the same host. Replacement is therefore consistent
per run - ``USER_1``, ``HOST_1``, ``SID_1`` - with a mapping table that only
lives in memory.

Two details that are easily missed:

* Replacement happens on the ``EventRecord`` after normalization, not by
  search-and-replace in the finished prompt text. Otherwise substrings get hit.
* When restoring, it is checked whether the model INVENTED placeholders. A
  ``USER_7`` that never existed in the bundle is a hallucination signal.
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
_PLACEHOLDER = re.compile(r"\b(USER|HOST|SID|IP|MAC|DOMAIN)_(\d+)\b")

#: Accounts with the same name on every Windows that say nothing about people.
#: The German spellings are what a German Windows writes into its events.
_WELL_KNOWN_ACCOUNTS = {
    "system", "local service", "network service", "lokaler dienst",
    "netzwerkdienst", "nt authority", "nt-autoritaet", "administrator",
    "administratoren", "administrators", "users", "benutzer",
}

_WELL_KNOWN_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}


class Redactor:
    """Replaces personal parts with stable pseudonyms."""

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled
        self._maps: dict[str, dict[str, str]] = {
            "USER": {},
            "HOST": {},
            "SID": {},
            "IP": {},
            "MAC": {},
            "DOMAIN": {},
        }

    # --- Mapping -------------------------------------------------------------

    def _token(self, kind: str, value: str) -> str:
        table = self._maps[kind]
        key = value.casefold()
        if key not in table:
            table[key] = f"{kind}_{len(table) + 1}"
        return table[key]

    def mapping(self) -> dict[str, str]:
        """Placeholder -> original value. Stays local, never goes into a bundle."""
        out: dict[str, str] = {}
        for kind, table in self._maps.items():
            for original, token in table.items():
                out[token] = original
            _ = kind
        return out

    def known_placeholders(self) -> set[str]:
        return set(self.mapping())

    # --- Replacing -----------------------------------------------------------

    def register_host(self, host: str) -> str:
        if not host:
            return ""
        return self._token("HOST", host.split(".")[0])

    def text(self, value: str | None) -> str | None:
        """Redacts a free text."""
        if value is None or not self.enabled:
            return value

        def sid_sub(match: re.Match[str]) -> str:
            found = match.group(0)
            if found in _WELL_KNOWN_SIDS:
                return found
            return self._token("SID", found)

        def userpath_sub(match: re.Match[str]) -> str:
            return match.group(1) + self._token("USER", match.group(2))

        def domain_user_sub(match: re.Match[str]) -> str:
            domain, user = match.group(1), match.group(2)
            if domain.casefold() in _WELL_KNOWN_ACCOUNTS:
                return match.group(0)
            return f"{self._token('DOMAIN', domain)}\\{self._token('USER', user)}"

        result = _SID.sub(sid_sub, value)
        result = _MAC.sub(lambda m: self._token("MAC", m.group(0)), result)
        result = _IPV4.sub(lambda m: self._token("IP", m.group(0)), result)
        result = _IPV6.sub(lambda m: self._token("IP", m.group(0)), result)
        result = _USERPATH.sub(userpath_sub, result)
        result = _DOMAIN_USER.sub(domain_user_sub, result)

        # Known host names last, so they do not tear apart parts of other hits.
        for original, token in sorted(
            self._maps["HOST"].items(), key=lambda item: -len(item[0])
        ):
            result = re.sub(rf"\b{re.escape(original)}\b", token, result, flags=re.IGNORECASE)
        return result

    def record(self, record: EventRecord) -> EventRecord:
        """Returns a redacted copy of an event."""
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

    # --- Restoring -----------------------------------------------------------

    def restore(self, value: str) -> str:
        """Turns placeholders back into plain text - for the full report."""
        mapping = self.mapping()
        result = value
        for token, original in sorted(mapping.items(), key=lambda item: -len(item[0])):
            result = result.replace(token, original)
        return result

    def invented_placeholders(self, value: str) -> set[str]:
        """Placeholders in the text that never existed in the bundle.

        This is a hallucination signal of its own and is treated exactly like a
        failed evidence check.
        """
        known = self.known_placeholders()
        found = {f"{match.group(1)}_{match.group(2)}" for match in _PLACEHOLDER.finditer(value)}
        return found - known
