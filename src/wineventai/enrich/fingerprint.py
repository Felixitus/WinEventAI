"""Fingerprint for deduplication.

Deviation from the original blueprint, with reason: there the fingerprint was
defined as ``provider + event_id + normalized message``. On mixed German and
English systems the same incident then produces two different fingerprints,
because the message text is translated.

Hence here: ``provider + event_id + event_version + hash(masked property
vector)``. The property vector is the language-neutral substance of an event;
the message text is only its translation. Only if there are no properties is
the masked message used as a substitute - and that is marked in the
fingerprint so the difference stays visible.
"""

from __future__ import annotations

import hashlib

from ..normalize.masking import mask_properties, mask_text
from ..normalize.schema import EventRecord


def fingerprint_for(record: EventRecord) -> str:
    """Computes the fingerprint of an event."""
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
    """Splits a fingerprint back into its readable parts."""
    provider, _, rest = fingerprint.partition("|")
    event_id, _, rest = rest.partition("|")
    version, _, digest = rest.partition("|")
    return {
        "provider": provider,
        "event_id": event_id,
        "version": version,
        "basis": "properties" if digest.startswith("p") else "message text",
        "digest": digest[1:],
    }
