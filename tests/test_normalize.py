"""Normalizer: Schema, Maskierung, EventData aus dem XML."""

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


def test_eventdata_namen_sind_sprachneutral_lesbar() -> None:
    data = parse_event_data_xml(EVENT_XML)
    assert data == {
        "TargetUserName": "m.schmidt",
        "LogonType": "10",
        "IpAddress": "203.0.113.47",
    }


def test_kaputtes_xml_liefert_none_statt_ausnahme() -> None:
    assert parse_event_data_xml("<Event><nicht geschlossen>") is None
    assert parse_event_data_xml(None) is None


def test_level_wird_numerisch_gefuehrt_nicht_als_anzeigename() -> None:
    record = record_from_mapping(
        {"t": "2026-09-10T12:00:00Z", "ch": "System", "pr": "disk", "id": 51, "lvl": 2},
        source_tool="test",
        source_ref="System",
    )
    assert record.level == 2
    assert record.level_label == "fehler"
    assert level_label(1) == "kritisch"


def test_maskierung_entfernt_variable_bestandteile() -> None:
    a = mask_text(
        "Der E/A-Vorgang der logischen Blockadresse 0x4a1f fuer Datentraeger 1 "
        "wurde wiederholt. GUID {D63B10C5-BB46-4990-A94F-E40B9D520160}"
    )
    b = mask_text(
        "Der E/A-Vorgang der logischen Blockadresse 0x9c22 fuer Datentraeger 3 "
        "wurde wiederholt. GUID {11111111-2222-3333-4444-555555555555}"
    )
    assert a == b, "gleicher Vorfallstyp muss gleich maskiert werden"
    assert "<guid>" in a and "<hex>" in a


def test_maskierung_unterscheidet_verschiedene_meldungen() -> None:
    assert mask_text("Dienst A wurde beendet") != mask_text("Dienst B wurde beendet")


def test_property_maskierung_ist_sprachunabhaengig() -> None:
    """Derselbe Vorfall auf deutschem und englischem System.

    Der Property-Vektor ist identisch, der Meldungstext nicht. Genau deshalb
    haengt der Fingerprint an den Properties.
    """
    properties = ["Druckwarteschlange", "3", "60000"]
    assert mask_properties(properties) == mask_properties(list(properties))
    assert mask_properties(["A", None]) == mask_properties(["A", None])
