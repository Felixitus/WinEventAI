"""Fingerprint zur Deduplizierung.

Abweichung vom urspruenglichen Bauplan, mit Begruendung: Dort war der
Fingerprint als ``provider + event_id + normalisierte Meldung`` definiert. Auf
gemischten deutschen und englischen Systemen erzeugt derselbe Vorfall dann zwei
verschiedene Fingerprints, weil der Meldungstext uebersetzt ist.

Deshalb hier: ``provider + event_id + event_version + Hash(maskierter
Property-Vektor)``. Der Property-Vektor ist die sprachneutrale Substanz eines
Ereignisses; der Meldungstext ist nur seine Uebersetzung. Nur wenn keine
Properties vorliegen, wird ersatzweise die maskierte Meldung herangezogen - und
das wird im Fingerprint kenntlich gemacht, damit der Unterschied sichtbar
bleibt.
"""

from __future__ import annotations

import hashlib

from ..normalize.masking import mask_properties, mask_text
from ..normalize.schema import EventRecord


def fingerprint_for(record: EventRecord) -> str:
    """Berechnet den Fingerprint eines Events."""
    if any(value for value in record.properties):
        basis = mask_properties(record.properties)
        kind = "p"
    else:
        basis = mask_text(record.message or "")
        kind = "m"

    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
    version = record.event_version if record.event_version is not None else "-"
    return f"{record.provider}|{record.event_id}|{version}|{kind}{digest}"


def describe_fingerprint(fingerprint: str) -> dict[str, str]:
    """Zerlegt einen Fingerprint wieder in seine lesbaren Bestandteile."""
    provider, _, rest = fingerprint.partition("|")
    event_id, _, rest = rest.partition("|")
    version, _, digest = rest.partition("|")
    return {
        "provider": provider,
        "event_id": event_id,
        "version": version,
        "basis": "properties" if digest.startswith("p") else "meldungstext",
        "digest": digest[1:],
    }
