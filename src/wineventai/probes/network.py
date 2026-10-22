"""Netzsonde: Erreichbarkeit von DNS-Server, Gateway und DHCP-Server.

Diese Sonde beantwortet die Frage, die ein Buendel DNS-Client 1014 aufwirft:
Steht der Pfad zur Namensaufloesung ueberhaupt? Sie beantwortet sie fuer JETZT -
der Zeitvorbehalt aus ``base.py`` gilt hier besonders, weil eine Netzstoerung
das fluechtigste aller Symptome ist.

Zwei Messungen, und die Reihenfolge ist wichtig:

1. ICMP an die eingetragenen Server. Billig, aber schwach: Ein Rechner, der auf
   Ping antwortet, kann einen toten DNS-Dienst haben.
2. Eine echte Namensabfrage an denselben Server. Gefragt wird nach dem eigenen
   Rechnernamen - kein fremder Name verlaesst dabei das Haus, und die Frage
   trifft trotzdem den Dienst und nicht nur den Host.

Faellt Schritt 2 aus, weil ``Resolve-DnsName`` fehlt, bleibt die Aussage
ausdruecklich schwach. Sie wird dann nicht aufgewertet.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..applog import get_log
from ..collect.shell import ShellInfo, join_list_arg
from .base import (
    ProbeBearing,
    ProbeResult,
    ProbeStatus,
    failed_result,
    timed_out_result,
)
from .shell import ProbePayloads, run_probe_script

if TYPE_CHECKING:  # pragma: no cover
    from ..rules.engine import Finding

PROBE_ID = "netz"
TITLE = "Netzpfad und Namensaufloesung"

#: Welcher Befund welche Rolle messen laesst. Schluessel ist Provider (klein)
#: plus Event-ID - nie die ID allein, die ist nur je Provider eindeutig.
ROLE_FOR: dict[tuple[str, int], str] = {
    ("microsoft-windows-dns-client", 1014): "dns",
    ("dnsapi", 1014): "dns",
    ("dns client events", 1014): "dns",
    ("microsoft-windows-dhcp-client", 1003): "dhcp",
    ("dhcp-client", 1003): "dhcp",
    ("dhcp", 1003): "dhcp",
    ("tcpip", 4227): "gateway",
    ("tcpip", 4231): "gateway",
    ("microsoft-windows-tcpip", 4227): "gateway",
    ("microsoft-windows-tcpip", 4231): "gateway",
    ("netbt", 4321): "gateway",
}

ROLE_TITLE: dict[str, str] = {
    "dns": "DNS-Server erreichbar",
    "gateway": "Standardgateway erreichbar",
    "dhcp": "DHCP-Server erreichbar",
}

ROLE_LABEL: dict[str, str] = {"dns": "DNS-Server", "gateway": "Gateway", "dhcp": "DHCP-Server"}


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


class NetworkProbe:
    """Misst die lokale Netzinfrastruktur - und nur diese."""

    probe_id = PROBE_ID
    title = TITLE

    def __init__(
        self,
        shell: ShellInfo,
        *,
        timeout_seconds: float = 25.0,
        ping_count: int = 3,
        ping_timeout_ms: int = 1500,
    ) -> None:
        self.shell = shell
        self.timeout_seconds = timeout_seconds
        self.ping_count = ping_count
        self.ping_timeout_ms = ping_timeout_ms

    def target_for(self, finding: Finding) -> str | None:
        return ROLE_FOR.get((finding.group.provider.lower(), finding.group.event_id))

    def run(self, targets: dict[str, list[Finding]]) -> list[ProbeResult]:
        roles = sorted(targets)
        if not roles:
            return []

        args = [
            "-Role",
            join_list_arg(roles),
            "-Count",
            str(self.ping_count),
            "-TimeoutMs",
            str(self.ping_timeout_ms),
        ]
        run = run_probe_script(
            "probe_network.ps1", args, shell=self.shell, timeout_seconds=self.timeout_seconds
        )
        if run.timed_out:
            return [timed_out_result(PROBE_ID, TITLE, run.duration_seconds)]
        if run.payloads.exception or (run.returncode != 0 and not run.payloads.items):
            get_log().warn(
                "Netzsonde fehlgeschlagen",
                ausnahme=run.payloads.exception,
                code=run.returncode,
            )
            return [
                failed_result(
                    PROBE_ID,
                    TITLE,
                    "Die Netzkonfiguration liess sich nicht lesen.",
                    error=run.payloads.exception or run.stderr.strip()[:200] or None,
                )
            ]

        return interpret(run.payloads, roles, duration_seconds=run.duration_seconds)


def interpret(
    payloads: ProbePayloads, roles: list[str], *, duration_seconds: float = 0.0
) -> list[ProbeResult]:
    """Baut je Rolle ein Ergebnis. Rein - kein Prozess, kein Netz, testbar."""
    results: list[ProbeResult] = []
    ziele = payloads.of_kind("ziel")
    leer = {str(item.get("rolle")): str(item.get("grund", "")) for item in payloads.of_kind("leer")}
    abfragen = payloads.of_kind("dnsabfrage")
    hinweise = [str(item.get("text", "")) for item in payloads.of_kind("hinweis")]

    for role in roles:
        eigene = [item for item in ziele if item.get("rolle") == role]
        titel = ROLE_TITLE.get(role, TITLE)

        if not eigene:
            grund = leer.get(role) or "Fuer diese Rolle ist auf dem System nichts eingetragen."
            results.append(
                ProbeResult(
                    probe_id=PROBE_ID,
                    title=titel,
                    status=ProbeStatus.NOT_APPLICABLE,
                    target=role,
                    summary=grund,
                    duration_seconds=duration_seconds,
                )
            )
            continue

        gemessen = [item for item in eigene if not item.get("uebersprungen")]
        uebersprungen = [item for item in eigene if item.get("uebersprungen")]
        details = [_target_line(item) for item in eigene]

        if not gemessen:
            results.append(
                ProbeResult(
                    probe_id=PROBE_ID,
                    title=titel,
                    status=ProbeStatus.NOT_APPLICABLE,
                    target=role,
                    summary=(
                        f"Alle eingetragenen {ROLE_LABEL.get(role, role)} liegen ausserhalb der "
                        "privaten Adressbereiche. Diese Sonde misst nur im lokalen Netz."
                    ),
                    details=details,
                    duration_seconds=duration_seconds,
                )
            )
            continue

        tot = [item for item in gemessen if _as_int(item.get("empfangen")) == 0]
        teilweise = [
            item
            for item in gemessen
            if 0 < _as_int(item.get("empfangen")) < _as_int(item.get("gesendet"), 1)
        ]

        if role == "dns":
            results.append(
                _dns_result(gemessen, tot, teilweise, abfragen, details, hinweise, duration_seconds)
            )
        else:
            results.append(
                _ping_result(role, titel, gemessen, tot, teilweise, details, duration_seconds)
            )

        if uebersprungen:
            # Kein eigener Befundeintrag - aber es muss sichtbar bleiben, dass
            # ein Teil der Konfiguration ungemessen blieb.
            results[-1].details.append(
                f"{len(uebersprungen)} Adresse(n) uebersprungen, weil sie ausserhalb des "
                "lokalen Netzes liegen."
            )

    return results


def _target_line(item: dict[str, object]) -> str:
    adresse = str(item.get("adresse", "?"))
    adapter = str(item.get("adapter") or "").strip()
    zusatz = f" ({adapter})" if adapter else ""

    if item.get("uebersprungen"):
        return f"{adresse}{zusatz}: nicht gemessen - oeffentliche Adresse"

    gesendet = _as_int(item.get("gesendet"))
    empfangen = _as_int(item.get("empfangen"))
    if empfangen == 0:
        fehler = str(item.get("fehler") or "keine Antwort")
        return f"{adresse}{zusatz}: {gesendet} Versuche, keine Antwort ({fehler})"

    schnitt = item.get("schnitt_ms")
    zeit = f", im Schnitt {schnitt} ms" if schnitt is not None else ""
    return f"{adresse}{zusatz}: {empfangen} von {gesendet} beantwortet{zeit}"


def _ping_result(
    role: str,
    titel: str,
    gemessen: list[dict[str, object]],
    tot: list[dict[str, object]],
    teilweise: list[dict[str, object]],
    details: list[str],
    duration_seconds: float,
) -> ProbeResult:
    label = ROLE_LABEL.get(role, role)
    if tot:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=titel,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target=role,
            summary=(
                f"{len(tot)} von {len(gemessen)} eingetragenen {label} antworten nicht."
            ),
            details=details,
            duration_seconds=duration_seconds,
        )
    if teilweise:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=titel,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target=role,
            summary=f"Paketverluste auf dem Weg zu {label}.",
            details=details,
            duration_seconds=duration_seconds,
        )
    return ProbeResult(
        probe_id=PROBE_ID,
        title=titel,
        status=ProbeStatus.OK,
        bearing=ProbeBearing.WEAKENS,
        target=role,
        summary=f"Alle eingetragenen {label} antworten ohne Verlust.",
        details=details,
        duration_seconds=duration_seconds,
    )


def _dns_result(
    gemessen: list[dict[str, object]],
    tot: list[dict[str, object]],
    teilweise: list[dict[str, object]],
    abfragen: list[dict[str, object]],
    details: list[str],
    hinweise: list[str],
    duration_seconds: float,
) -> ProbeResult:
    titel = ROLE_TITLE["dns"]
    alle_details = list(details)
    for eintrag in abfragen:
        alle_details.append(_query_line(eintrag))
    alle_details.extend(hinweise)

    fehlgeschlagen = [item for item in abfragen if not item.get("erfolg")]

    if tot:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=titel,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target="dns",
            summary=f"{len(tot)} von {len(gemessen)} DNS-Servern antworten nicht.",
            details=alle_details,
            duration_seconds=duration_seconds,
        )

    if fehlgeschlagen:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=titel,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target="dns",
            summary=(
                f"{len(fehlgeschlagen)} von {len(abfragen)} DNS-Servern beantworten zwar ICMP, "
                "aber keine Namensabfrage. Genau dieses Bild erzeugt Ereignis 1014."
            ),
            details=alle_details,
            duration_seconds=duration_seconds,
        )

    if not abfragen:
        # Nur ICMP gemessen. Das reicht ausdruecklich nicht fuer eine Entwarnung:
        # Ein Host, der auf Ping antwortet, kann einen toten DNS-Dienst haben.
        return ProbeResult(
            probe_id=PROBE_ID,
            title=titel,
            status=ProbeStatus.OK,
            bearing=ProbeBearing.INCONCLUSIVE,
            target="dns",
            summary=(
                "Die DNS-Server antworten auf ICMP. Eine Namensabfrage wurde nicht "
                "durchgefuehrt, daher ist ueber den DNS-Dienst selbst nichts gesagt."
            ),
            details=alle_details,
            duration_seconds=duration_seconds,
        )

    if teilweise:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=titel,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target="dns",
            summary=(
                "Namensabfragen gelingen, aber der Weg zum DNS-Server verliert Pakete."
            ),
            details=alle_details,
            duration_seconds=duration_seconds,
        )

    return ProbeResult(
        probe_id=PROBE_ID,
        title=titel,
        status=ProbeStatus.OK,
        bearing=ProbeBearing.WEAKENS,
        target="dns",
        summary="Alle DNS-Server antworten und loesen den eigenen Rechnernamen auf.",
        details=alle_details,
        duration_seconds=duration_seconds,
    )


def _query_line(item: dict[str, object]) -> str:
    server = str(item.get("server", "?"))
    if item.get("erfolg"):
        dauer = item.get("dauer_ms")
        antwort = item.get("antwort")
        teile = [f"Namensabfrage an {server}: beantwortet"]
        if antwort:
            teile.append(f"({antwort})")
        if dauer is not None:
            teile.append(f"in {dauer} ms")
        return " ".join(teile)
    return f"Namensabfrage an {server}: fehlgeschlagen ({item.get('fehler') or 'ohne Angabe'})"
