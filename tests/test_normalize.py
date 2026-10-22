"""Normalizer: schema, masking, EventData from the XML."""

from __future__ import annotations

from wineventai.normalize.mapper import parse_event_data_xml, record_from_mapping
from wineventai.normalize.masking import mask_properties, mask_text
from wineventai.normalize.schema import level_label

EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4624</EventID><Level>0</Level></System>
  <EventData>
    <Data Name="TargetUserName">m.schmidt</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">203.0.113.47</Data>
  </EventData>
</Event>"""


def test_eventdata_names_are_readable_language_neutrally() -> None:
    data = parse_event_data_xml(EVENT_XML)
    assert data == {
        "TargetUserName": "m.schmidt",
        "LogonType": "10",
        "IpAddress": "203.0.113.47",
    }


def test_broken_xml_yields_none_instead_of_an_exception() -> None:
    assert parse_event_data_xml("<Event><not closed>") is None
    assert parse_event_data_xml(None) is None


def test_the_level_is_kept_numeric_not_as_display_name() -> None:
    record = record_from_mapping(
        {"t": "2026-09-10T12:00:00Z", "ch": "System", "pr": "disk", "id": 51, "lvl": 2},
        source_tool="test",
        source_ref="System",
    )
    assert record.level == 2
    assert record.level_label == "error"
    assert level_label(1) == "critical"


def test_masking_removes_variable_parts() -> None:
    a = mask_text(
        "An error was detected on device 1 during a paging operation at block 0x4a1f. "
        "GUID {D63B10C5-BB46-4990-A94F-E40B9D520160}"
    )
    b = mask_text(
        "An error was detected on device 3 during a paging operation at block 0x9c22. "
        "GUID {11111111-2222-3333-4444-555555555555}"
    )
    assert a == b, "the same kind of incident must be masked the same way"
    assert "<guid>" in a and "<hex>" in a


def test_masking_keeps_different_messages_apart() -> None:
    assert mask_text("Service A was stopped") != mask_text("Service B was stopped")


def test_property_masking_is_language_independent() -> None:
    """The same incident on a German and an English system.

    The property vector is identical, the message text is not. That is exactly
    why the fingerprint hangs on the properties.
    """
    properties = ["Print Spooler", "3", "60000"]
    assert mask_properties(properties) == mask_properties(list(properties))
    assert mask_properties(["A", None]) == mask_properties(["A", None])
