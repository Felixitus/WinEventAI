"""Tests der Kontext-Sonden.

Die Testgrenze liegt bei ``read_payloads``: Alles ab dort ist reine Auswertung
und laeuft ohne Windows und ohne PowerShell. Was hier NICHT geprueft werden
kann, sind die drei ``.ps1``-Dateien selbst - die beweisen sich nur auf einem
Zielsystem, und das steht so in der Standdokumentation.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from helpers import WINDOW_END, make_record
from wineventai.config import Config
from wineventai.enrich.aggregate import FingerprintGroup
from wineventai.probes import network, services, storage
from wineventai.probes.base import ProbeBearing, ProbeResult, ProbeStatus
from wineventai.probes.runner import ProbeRunner
from wineventai.probes.shell import read_payloads
from wineventai.rules.engine import Finding
from wineventai.rules.schema import Severity


def payloads(*items: dict[str, object], status: dict[str, object] | None = None):
    lines = [json.dumps(item, ensure_ascii=False) for item in items]
    lines.append(json.dumps({"__status": status or {"probe": "test", "exception": None}}))
    return read_payloads(lines)


def make_finding(
    *,
    provider: str,
    event_id: int,
    rule_id: str = "regel-1",
    minutes_ago: int = 5,
    properties: list[str | None] | None = None,
) -> Finding:
    sample = make_record(
        provider=provider, event_id=event_id, minutes_ago=minutes_ago, properties=properties
    )
    group = FingerprintGroup(
        fingerprint=f"{provider}|{event_id}|0|pabcdef0123456789",
        provider=provider,
        event_id=event_id,
        channel="System",
        level=2,
        count=12,
        first_seen_utc=sample.timestamp_utc - timedelta(hours=1),
        last_seen_utc=sample.timestamp_utc,
        samples=[sample],
    )
    return Finding(
        rule_id=rule_id,
        rule_name="Testregel",
        rule_source="builtin",
        severity=Severity.FEHLER,
        group=group,
    )


# --- Grundbegriffe -----------------------------------------------------------


def test_zeitvorbehalt_wird_mit_dem_abstand_deutlicher():
    jetzt = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
    frisch = ProbeResult(
        probe_id="netz",
        title="T",
        status=ProbeStatus.OK,
        measured_utc=jetzt,
        finding_last_seen_utc=jetzt - timedelta(minutes=10),
    )
    alt = frisch.model_copy(update={"finding_last_seen_utc": jetzt - timedelta(days=5)})

    assert "kurz nach" in frisch.age_note()
    assert "5 Tage" in alt.age_note()
    assert "sagt diese Messung nichts" in alt.age_note()


def test_nicht_gemessene_zustaende_gelten_nicht_als_messung():
    for status in (
        ProbeStatus.FAILED,
        ProbeStatus.NOT_APPLICABLE,
        ProbeStatus.NO_PERMISSION,
        ProbeStatus.TIMED_OUT,
        ProbeStatus.DISABLED,
        ProbeStatus.UNAVAILABLE,
    ):
        result = ProbeResult(probe_id="x", title="T", status=status)
        assert result.measured is False
    assert ProbeResult(probe_id="x", title="T", status=ProbeStatus.OK).measured is True


# --- Netzsonde ---------------------------------------------------------------


def test_netz_toter_dns_server_stuetzt_den_befund():
    result = network.interpret(
        payloads(
            {
                "kind": "ziel",
                "rolle": "dns",
                "adresse": "192.168.1.1",
                "privat": True,
                "uebersprungen": False,
                "gesendet": 3,
                "empfangen": 0,
                "fehler": "TimedOut",
            }
        ),
        ["dns"],
    )[0]

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS
    assert "antworten nicht" in result.summary


def test_netz_ping_allein_entlastet_den_dns_dienst_nicht():
    """Ein Host, der auf ICMP antwortet, kann einen toten DNS-Dienst haben."""
    result = network.interpret(
        payloads(
            {
                "kind": "ziel",
                "rolle": "dns",
                "adresse": "192.168.1.1",
                "privat": True,
                "uebersprungen": False,
                "gesendet": 3,
                "empfangen": 3,
                "schnitt_ms": 1.0,
            }
        ),
        ["dns"],
    )[0]

    assert result.status is ProbeStatus.OK
    assert result.bearing is ProbeBearing.INCONCLUSIVE
    assert "Namensabfrage wurde nicht" in result.summary


def test_netz_ping_gut_aber_namensabfrage_scheitert_ist_der_kernfall():
    result = network.interpret(
        payloads(
            {
                "kind": "ziel",
                "rolle": "dns",
                "adresse": "10.0.0.53",
                "privat": True,
                "uebersprungen": False,
                "gesendet": 3,
                "empfangen": 3,
                "schnitt_ms": 0.8,
            },
            {
                "kind": "dnsabfrage",
                "server": "10.0.0.53",
                "name": "WS-4711",
                "erfolg": False,
                "fehler": "System.ComponentModel.Win32Exception",
            },
        ),
        ["dns"],
    )[0]

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS
    assert "1014" in result.summary


def test_netz_oeffentliche_adresse_wird_nicht_gemessen():
    result = network.interpret(
        payloads(
            {
                "kind": "ziel",
                "rolle": "dns",
                "adresse": "8.8.8.8",
                "privat": False,
                "uebersprungen": True,
                "grund": "oeffentlich",
            }
        ),
        ["dns"],
    )[0]

    assert result.status is ProbeStatus.NOT_APPLICABLE
    assert "nur im lokalen Netz" in result.summary


def test_netz_ohne_eintrag_ist_nicht_anwendbar_und_nicht_unauffaellig():
    result = network.interpret(
        payloads({"kind": "leer", "rolle": "dhcp", "grund": "Keine Schnittstelle per DHCP."}),
        ["dhcp"],
    )[0]

    assert result.status is ProbeStatus.NOT_APPLICABLE
    assert result.measured is False


def test_netz_findet_sein_ziel_ueber_provider_und_id():
    probe = network.NetworkProbe.__new__(network.NetworkProbe)
    dns = make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)
    fremd = make_finding(provider="EventLog", event_id=1014)

    assert probe.target_for(dns) == "dns"
    assert probe.target_for(fremd) is None


# --- Dienstsonde -------------------------------------------------------------


def test_dienst_gestoppt_und_automatisch_stuetzt_den_befund():
    result = services.interpret(
        payloads(
            {
                "kind": "dienst",
                "gesucht": "Druckwarteschlange",
                "gefunden": True,
                "name": "Spooler",
                "anzeigename": "Druckwarteschlange",
                "zustand": "Stopped",
                "starttyp": "Auto",
            }
        ),
        ["Druckwarteschlange"],
    )[0]

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS


def test_dienst_laeuft_spricht_gegen_den_befund():
    result = services.interpret(
        payloads(
            {
                "kind": "dienst",
                "gesucht": "Druckwarteschlange",
                "gefunden": True,
                "name": "Spooler",
                "zustand": "Running",
                "starttyp": "Auto",
            }
        ),
        ["Druckwarteschlange"],
    )[0]

    assert result.status is ProbeStatus.OK
    assert result.bearing is ProbeBearing.WEAKENS


def test_dienst_deaktiviert_ist_selbst_ein_befund():
    result = services.interpret(
        payloads(
            {
                "kind": "dienst",
                "gesucht": "Windows Update",
                "gefunden": True,
                "name": "wuauserv",
                "zustand": "Stopped",
                "starttyp": "Disabled",
            }
        ),
        ["Windows Update"],
    )[0]

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS
    assert "Deaktiviert" in result.summary


def test_dienst_manuell_gestoppt_ist_der_vorgesehene_zustand():
    result = services.interpret(
        payloads(
            {
                "kind": "dienst",
                "gesucht": "Diagnoserichtliniendienst",
                "gefunden": True,
                "name": "DPS",
                "zustand": "Stopped",
                "starttyp": "Manual",
            }
        ),
        ["Diagnoserichtliniendienst"],
    )[0]

    assert result.status is ProbeStatus.OK
    assert result.bearing is ProbeBearing.INCONCLUSIVE


def test_dienst_nicht_gefunden_nennt_die_sprachfassung_als_moeglichkeit():
    result = services.interpret(
        payloads({"kind": "dienst", "gesucht": "Print Spooler", "gefunden": False}),
        ["Print Spooler"],
    )[0]

    assert result.status is ProbeStatus.NOT_APPLICABLE
    assert "Sprachfassung" in result.summary


def test_dienst_ziel_kommt_aus_der_ersten_property():
    """SCM 7031 traegt den Anzeigenamen in properties[0] - nicht den Dienstnamen."""
    probe = services.ServiceProbe.__new__(services.ServiceProbe)
    finding = make_finding(
        provider="Service Control Manager",
        event_id=7031,
        properties=["Druckwarteschlange", "1", "60000"],
    )
    assert probe.target_for(finding) == "Druckwarteschlange"


# --- Datentraegersonde -------------------------------------------------------


def test_datentraeger_gesund_entlastet_ausdruecklich_nicht():
    result = storage.interpret(
        payloads(
            {
                "kind": "datentraeger",
                "name": "Samsung SSD 980",
                "medium": "SSD",
                "gesundheit": "Healthy",
                "groesse_b": 1_000_204_886_016,
                "lesefehler": 0,
                "schreibfehler": 0,
                "zaehler_da": True,
            },
            {"kind": "smart", "instanz": "SCSI\\Disk", "ausfall_vorhergesagt": False},
        )
    )

    assert result.status is ProbeStatus.OK
    assert result.bearing is ProbeBearing.INCONCLUSIVE
    assert "schliesst einen Defekt nicht aus" in result.summary


def test_datentraeger_fehlerzaehler_stuetzt_trotz_gesundem_gesamtstatus():
    result = storage.interpret(
        payloads(
            {
                "kind": "datentraeger",
                "name": "WDC WD10",
                "gesundheit": "Healthy",
                "lesefehler": 12,
                "schreibfehler": 3,
                "zaehler_da": True,
            }
        )
    )

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS
    assert "15" in result.summary


def test_datentraeger_vorhergesagter_ausfall_traegt_den_zuordnungsvorbehalt():
    result = storage.interpret(
        payloads(
            {"kind": "datentraeger", "name": "WDC WD10", "gesundheit": "Warning"},
            {"kind": "smart", "instanz": "SCSI\\Disk", "ausfall_vorhergesagt": True},
        )
    )

    assert result.status is ProbeStatus.WARN
    assert result.bearing is ProbeBearing.SUPPORTS
    assert any("Device\\HarddiskN" in zeile for zeile in result.details)


def test_datentraeger_ohne_werte_ist_nicht_messbar():
    result = storage.interpret(payloads({"kind": "hinweis", "text": "Get-PhysicalDisk fehlt"}))
    assert result.status is ProbeStatus.UNAVAILABLE
    assert result.measured is False


# --- Runner ------------------------------------------------------------------


class FakeProbe:
    """Eine Sonde, die nicht misst, sondern liefert, was der Test vorgibt."""

    probe_id = "netz"
    title = "Netzpfad und Namensaufloesung"

    def __init__(self, results: list[ProbeResult]) -> None:
        self.results = results
        self.calls: list[dict[str, list[Finding]]] = []

    def target_for(self, finding: Finding) -> str | None:
        return "dns" if finding.group.event_id == 1014 else None

    def run(self, targets):
        self.calls.append(targets)
        return list(self.results)


def local_runner(config: Config, probes) -> ProbeRunner:
    """Runner, der die Plattformpruefung nicht braucht."""

    class Runner(ProbeRunner):
        def blocked_reason(self) -> str | None:
            return None

    return Runner(config, run_host="WS-4711", local_host="WS-4711", probes=probes)


def test_runner_startet_eine_sonde_einmal_fuer_viele_befunde():
    probe = FakeProbe(
        [
            ProbeResult(
                probe_id="netz", title="DNS", status=ProbeStatus.OK, target="dns",
                bearing=ProbeBearing.WEAKENS,
            )
        ]
    )
    findings = [
        make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014, rule_id=f"r{i}")
        for i in range(4)
    ]

    gemessen = local_runner(Config(), [probe]).attach(findings)

    assert len(probe.calls) == 1
    assert gemessen == 1
    assert all(len(f.probes) == 1 for f in findings)


def test_runner_stuft_ein_spricht_dagegen_bei_altem_befund_ab():
    """Der Zeitabstand hat eine Folge im Code, nicht nur einen Satz darunter."""
    ergebnis = ProbeResult(
        probe_id="netz",
        title="DNS",
        status=ProbeStatus.OK,
        target="dns",
        bearing=ProbeBearing.WEAKENS,
        measured_utc=WINDOW_END,
    )
    frisch = make_finding(
        provider="Microsoft-Windows-DNS-Client", event_id=1014, minutes_ago=10
    )
    alt = make_finding(
        provider="Microsoft-Windows-DNS-Client", event_id=1014, rule_id="r2", minutes_ago=60 * 30
    )

    local_runner(Config(), [FakeProbe([ergebnis])]).attach([frisch, alt])

    assert frisch.probes[0].bearing is ProbeBearing.WEAKENS
    assert alt.probes[0].bearing is ProbeBearing.INCONCLUSIVE


def test_runner_stuft_ein_stuetzt_nicht_ab():
    """Ein Dienst, der heute noch steht, stuetzt den Ausfall von vorgestern."""
    ergebnis = ProbeResult(
        probe_id="netz",
        title="DNS",
        status=ProbeStatus.WARN,
        target="dns",
        bearing=ProbeBearing.SUPPORTS,
        measured_utc=WINDOW_END,
    )
    alt = make_finding(
        provider="Microsoft-Windows-DNS-Client", event_id=1014, minutes_ago=60 * 72
    )

    local_runner(Config(), [FakeProbe([ergebnis])]).attach([alt])

    assert alt.probes[0].bearing is ProbeBearing.SUPPORTS


def test_runner_misst_nicht_auf_einem_fremden_rechner():
    """Der Lauf eines Servers, ausgewertet am Arbeitsplatz - der Normalfall im 2nd Level."""
    findings = [make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)]
    runner = ProbeRunner(Config(), run_host="SRV-DC01", local_host="WS-4711")

    gemessen = runner.attach(findings)

    assert gemessen == 0
    assert len(findings[0].probes) == 1
    assert findings[0].probes[0].status is ProbeStatus.UNAVAILABLE
    assert "SRV-DC01" in findings[0].probes[0].summary


def test_runner_akzeptiert_fqdn_gegen_kurznamen():
    runner = ProbeRunner(Config(), run_host="ws-4711.intern.example", local_host="WS-4711")
    grund = runner.blocked_reason()
    # Auf Nicht-Windows bleibt die Plattformpruefung stehen; der Rechnername
    # darf jedenfalls nicht der Grund sein.
    assert grund is None or "Windows" in grund


def test_abgeschaltete_sonde_bleibt_in_der_karte_sichtbar():
    config = Config()
    config.probes.network = False
    findings = [make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)]

    local_runner(config, []).attach(findings)

    assert len(findings[0].probes) == 1
    assert findings[0].probes[0].status is ProbeStatus.DISABLED


def test_ganz_abgeschaltete_sonden_erzeugen_keinen_eintrag():
    config = Config()
    config.probes.enabled = False
    findings = [make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)]

    local_runner(config, []).attach(findings)

    assert findings[0].probes == []


def test_eine_abstuerzende_sonde_toetet_den_lauf_nicht():
    class Kaputt(FakeProbe):
        def run(self, targets):
            raise RuntimeError("Zugriff verweigert")

    findings = [make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)]
    local_runner(Config(), [Kaputt([])]).attach(findings)

    assert findings[0].probes[0].status is ProbeStatus.UNAVAILABLE
    assert "RuntimeError" in (findings[0].probes[0].detail_error or "")


def test_sonden_landen_in_der_json_ausgabe_des_befunds():
    findings = [make_finding(provider="Microsoft-Windows-DNS-Client", event_id=1014)]
    local_runner(
        Config(),
        [
            FakeProbe(
                [
                    ProbeResult(
                        probe_id="netz", title="DNS", status=ProbeStatus.OK, target="dns",
                        summary="ok",
                    )
                ]
            )
        ],
    ).attach(findings)

    ausgabe = findings[0].to_public_dict()
    assert ausgabe["sonden"][0]["sonde"] == "netz"
    assert "zeitvorbehalt" in ausgabe["sonden"][0]


# --- Leseschicht -------------------------------------------------------------


def test_read_payloads_ueberliest_kaputte_zeilen_und_findet_den_status():
    ergebnis = read_payloads(
        [
            '{"kind":"ziel","rolle":"dns"}',
            "das ist kein JSON",
            "",
            '{"__status":{"probe":"netz","exception":"System.UnauthorizedAccessException"}}',
        ]
    )

    assert len(ergebnis.items) == 1
    assert ergebnis.parse_errors == 1
    assert ergebnis.exception == "System.UnauthorizedAccessException"


@pytest.mark.parametrize(
    ("provider", "event_id", "erwartet"),
    [
        ("disk", 153, "alle"),
        ("storahci", 129, "alle"),
        ("Ntfs", 55, "alle"),
        ("EventLog", 6005, None),
    ],
)
def test_datentraegersonde_haengt_an_den_richtigen_befunden(provider, event_id, erwartet):
    probe = storage.StorageProbe.__new__(storage.StorageProbe)
    finding = make_finding(provider=provider, event_id=event_id)
    assert probe.target_for(finding) == erwartet
