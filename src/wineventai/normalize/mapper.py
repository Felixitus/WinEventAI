"""Mapping a collector NDJSON line onto ``EventRecord``.

The short keys (``t``, ``ch``, ``pr`` ...) are intentional: with a few hundred
thousand lines per run they noticeably save disk and parse time, and the
mapping lives in exactly one place - here.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from xml.etree import ElementTree

if TYPE_CHECKING:  # pragma: no cover - only for type annotations
    from .schema import EventRecord

_EVENTDATA_TAG = re.compile(r"\{.*\}")


class NormalizationError(ValueError):
    """A line could not be converted into the event schema."""


def _parse_timestamp(value: Any) -> datetime:
    """Reads the timestamp as UTC.

    The PowerShell script already formats ISO-8601 with ``Z``. The branch for
    ``/Date(...)/`` catches exports produced elsewhere with ``ConvertTo-Json`` on
    Windows PowerShell 5.1 - that is exactly how ``DateTime`` serializes there.
    """
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value:
        raise NormalizationError("Timestamp missing")

    legacy = re.fullmatch(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/", value)
    if legacy:
        return datetime.fromtimestamp(int(legacy.group(1)) / 1000.0, tz=UTC)

    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise NormalizationError(f"Timestamp not readable: {value!r}") from exc
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def parse_event_data_xml(xml_text: str | None) -> dict[str, str] | None:
    """Extracts the named ``<Data Name="...">`` fields from the event XML.

    These names come from the provider manifest and are language-neutral -
    unlike the rendered message text. They are the right way to get at the stop
    code of a 1001 or the logon type of a 4624.
    """
    if not xml_text:
        return None
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return None

    result: dict[str, str] = {}
    for element in root.iter():
        tag = _EVENTDATA_TAG.sub("", element.tag)
        if tag != "Data":
            continue
        name = element.get("Name")
        if not name:
            continue
        result[name] = (element.text or "").strip()
    return result or None


def record_from_mapping(
    data: dict[str, Any],
    *,
    source_tool: str,
    source_ref: str,
    raw_line: str | None = None,
) -> EventRecord:
    """Builds an ``EventRecord`` from the parsed NDJSON line."""
    from .schema import EventRecord

    provider = _as_str(data.get("pr")) or "unknown"
    event_id = _as_int(data.get("id"))
    if event_id is None:
        raise NormalizationError("Event id missing or not numeric")

    properties_raw = data.get("pv") or []
    if not isinstance(properties_raw, list):
        properties_raw = [properties_raw]
    properties = [_as_str(item) for item in properties_raw]

    canonical = raw_line if raw_line is not None else json.dumps(data, sort_keys=True,
                                                                 ensure_ascii=False)
    raw_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return EventRecord(
        timestamp_utc=_parse_timestamp(data.get("t")),
        channel=_as_str(data.get("ch")) or source_ref,
        provider=provider,
        event_id=event_id,
        event_version=_as_int(data.get("ver")),
        level=_as_int(data.get("lvl")) if _as_int(data.get("lvl")) is not None else 4,
        task=_as_int(data.get("tsk")),
        opcode=_as_int(data.get("op")),
        keywords=_as_int(data.get("kw")),
        computer=_as_str(data.get("cmp")) or "",
        user_sid=_as_str(data.get("sid")),
        record_id=_as_int(data.get("rec")),
        process_id=_as_int(data.get("pid")),
        thread_id=_as_int(data.get("tid")),
        message=_as_str(data.get("msg")),
        properties=properties,
        event_data=parse_event_data_xml(_as_str(data.get("xml"))),
        raw_hash=raw_hash,
        source_tool=source_tool,
        source_ref=source_ref,
    )


def record_from_line(
    line: str,
    *,
    source_tool: str,
    source_ref: str,
) -> EventRecord:
    """Parses an NDJSON line and normalizes it."""
    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        raise NormalizationError(f"Line is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise NormalizationError("Line is not a JSON object")
    return record_from_mapping(
        data, source_tool=source_tool, source_ref=source_ref, raw_line=line
    )
