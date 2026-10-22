"""Ausfuehrung der Sonden und Zuordnung zu den Befunden.

Drei Dinge entscheidet dieser Runner, und alle drei sind wichtiger als die
Messung selbst:

**Ob ueberhaupt gemessen werden darf.** Die Auswertung laeuft auf einem
Laufverzeichnis, nicht auf einem Rechner. Wer den Lauf eines Servers auf seinem
Arbeitsplatz auswertet - der Normalfall im 2nd Level - bekaeme sonst die
Netzwerte seines eigenen Rechners in die Karte eines fremden Befunds
geschrieben. Deshalb prueft der Runner den Rechnernamen aus den Kopfdaten gegen
den lokalen und misst bei Abweichung nichts.

**Wie oft gemessen wird.** Eine Sonde bekommt alle Ziele auf einmal und wird
genau einmal gestartet. Zwoelf Befunde zu DNS-Zeitueberschreitungen ergeben
einen PowerShell-Aufruf, nicht zwoelf.

**Was ein Ergebnis fuer den einzelnen Befund bedeutet.** Dasselbe Messergebnis
haengt an Befunden unterschiedlichen Alters. Ein "spricht dagegen" wird deshalb
zu "sagt dazu nichts" abgestuft, sobald zwischen Messung und letztem Vorkommen
mehr als eine Stunde liegt - der Zeitabstand hat damit eine Folge im Code und
steht nicht bloss als Satz darunter. Ein "stuetzt den Befund" wird nicht
abgestuft: Ein Dienst, der heute noch steht, stuetzt den Ausfall von vorgestern
sehr wohl.
"""

from __future__ import annotations

import socket
import sys
from datetime import timedelta
from typing import TYPE_CHECKING

from ..applog import get_log
from ..collect.shell import PowerShellNotFoundError, ShellInfo, find_powershell
from ..config.model import Config
from .base import (
    Probe,
    ProbeBearing,
    ProbeResult,
    disabled_result,
    unavailable_result,
)
from .network import ROLE_FOR, NetworkProbe
from .services import SERVICE_EVENTS, ServiceProbe
from .storage import STORAGE_EVENTS, StorageProbe

if TYPE_CHECKING:  # pragma: no cover
    from ..rules.engine import Finding

#: Ab diesem Abstand entkraeftet eine Messung nichts mehr.
FRESHNESS = timedelta(hours=1)

ALL_PROBE_TITLES: dict[str, str] = {
    "netz": NetworkProbe.title,
    "dienst": ServiceProbe.title,
    "datentraeger": StorageProbe.title,
}

#: Welche Provider/ID-Paare welche Sonde anfordern. Dieselbe Grundlage wie
#: ``target_for``, nur ohne Sondenobjekt - denn wenn gar nicht gemessen werden
#: kann, gibt es keine Sonde, wohl aber Befunde, die den Grund erfahren muessen.
CANDIDATE_KEYS: dict[str, frozenset[tuple[str, int]]] = {
    "netz": frozenset(ROLE_FOR),
    "dienst": SERVICE_EVENTS,
    "datentraeger": STORAGE_EVENTS,
}


def build_probes(config: Config, shell: ShellInfo) -> list[Probe]:
    """Erzeugt die eingeschalteten Sonden."""
    probes: list[Probe] = []
    settings = config.probes
    if settings.network:
        probes.append(
            NetworkProbe(
                shell,
                timeout_seconds=settings.timeout_seconds,
                ping_count=settings.ping_count,
                ping_timeout_ms=settings.ping_timeout_ms,
            )
        )
    if settings.services:
        probes.append(ServiceProbe(shell, timeout_seconds=settings.timeout_seconds))
    if settings.storage:
        probes.append(StorageProbe(shell, timeout_seconds=settings.timeout_seconds))
    return probes


def _short_host(name: str) -> str:
    return name.split(".", 1)[0].strip().casefold()


def _disabled_probe_ids(config: Config) -> list[str]:
    settings = config.probes
    off = []
    if not settings.network:
        off.append("netz")
    if not settings.services:
        off.append("dienst")
    if not settings.storage:
        off.append("datentraeger")
    return off


class ProbeRunner:
    """Fuehrt die Sonden aus und haengt die Ergebnisse an die Befunde."""

    def __init__(
        self,
        config: Config,
        *,
        run_host: str,
        local_host: str | None = None,
        shell: ShellInfo | None = None,
        probes: list[Probe] | None = None,
    ) -> None:
        self.config = config
        self.run_host = run_host
        self.local_host = local_host if local_host is not None else socket.gethostname()
        self._shell = shell
        self._probes = probes

    # --- Vorbedingungen ------------------------------------------------------

    def blocked_reason(self) -> str | None:
        """Warum ueberhaupt nicht gemessen werden kann. ``None`` heisst: es geht."""
        # Der Rechnername kommt vor der Plattform: Wer den Lauf eines Servers
        # woanders auswertet, soll das erfahren und nicht bloss lesen, dass die
        # Sonden hier nicht laufen.
        if _short_host(self.run_host) != _short_host(self.local_host):
            return (
                f"Der Lauf stammt von '{self.run_host}', ausgewertet wird auf "
                f"'{self.local_host}'. Eine Messung wuerde den falschen Rechner "
                "beschreiben und unterbleibt deshalb."
            )
        if sys.platform != "win32":
            return (
                "Sonden messen Windows-Zustaende und laufen nur auf Windows. "
                f"Dieses System meldet sich als '{sys.platform}'."
            )
        if self._probes is None and self._shell is None:
            try:
                self._shell = find_powershell(self.config.collect.powershell_preference)
            except PowerShellNotFoundError as exc:
                return str(exc)
        return None

    # --- Ausfuehrung ---------------------------------------------------------

    def attach(self, findings: list[Finding]) -> int:
        """Misst und haengt die Ergebnisse an. Liefert die Zahl der Messungen."""
        if not self.config.probes.enabled or not findings:
            return 0

        log = get_log()
        grund = self.blocked_reason()
        if grund is not None:
            self._attach_blocked(findings, grund)
            log.info("Sonden uebersprungen", grund=grund)
            return 0

        probes = self._probes
        if probes is None:
            if self._shell is None:  # pragma: no cover - blocked_reason hat sie beschafft
                return 0
            probes = build_probes(self.config, self._shell)
        self._attach_switched_off(findings)

        gemessen = 0
        for probe in probes:
            targets: dict[str, list[Finding]] = {}
            for finding in findings:
                target = probe.target_for(finding)
                if target:
                    targets.setdefault(target, []).append(finding)
            if not targets:
                continue

            log.info("Sonde laeuft", sonde=probe.probe_id, ziele=len(targets))
            try:
                results = probe.run(targets)
            except Exception as exc:  # noqa: BLE001 - eine Sonde darf den Lauf nie toeten
                log.warn("Sonde abgebrochen", sonde=probe.probe_id, fehler=str(exc))
                results = [
                    unavailable_result(
                        probe.probe_id,
                        ALL_PROBE_TITLES.get(probe.probe_id, probe.title),
                        "Die Messung brach mit einem unerwarteten Fehler ab.",
                        error=f"{type(exc).__name__}: {exc}",
                    )
                ]

            gemessen += self._distribute(results, targets, findings)
        return gemessen

    def _distribute(
        self,
        results: list[ProbeResult],
        targets: dict[str, list[Finding]],
        findings: list[Finding],
    ) -> int:
        """Ordnet Messergebnisse den Befunden zu, die sie angefordert haben."""
        alle_angefragt = [f for gruppe in targets.values() for f in gruppe]
        gemessen = 0

        for result in results:
            if result.target is not None and result.target in targets:
                empfaenger = targets[result.target]
            else:
                # Ergebnisse ohne Ziel - Abbruch, Zeitueberschreitung, Ausfall -
                # gehen an jeden Befund, der diese Sonde angefordert hatte.
                empfaenger = alle_angefragt

            for finding in empfaenger:
                finding.probes.append(self._for_finding(result, finding))
            if result.measured:
                gemessen += 1

        _ = findings
        return gemessen

    @staticmethod
    def _for_finding(result: ProbeResult, finding: Finding) -> ProbeResult:
        kopie = result.model_copy(
            update={
                "finding_id": finding.finding_id,
                "finding_last_seen_utc": finding.group.last_seen_utc,
            }
        )
        if kopie.bearing is ProbeBearing.WEAKENS:
            abstand = kopie.age
            if abstand is None or abstand > FRESHNESS:
                kopie.bearing = ProbeBearing.INCONCLUSIVE
        return kopie

    def _attach_blocked(self, findings: list[Finding], grund: str) -> None:
        """Haengt an jeden Befund, der eine Sonde angefordert haette, den Grund."""
        for probe_id, titel in ALL_PROBE_TITLES.items():
            if probe_id in _disabled_probe_ids(self.config):
                continue
            for finding in self._candidates(findings, probe_id):
                finding.probes.append(
                    self._for_finding(unavailable_result(probe_id, titel, grund), finding)
                )

    def _attach_switched_off(self, findings: list[Finding]) -> None:
        """Eine einzeln abgeschaltete Sonde bleibt in der Befundkarte sichtbar.

        Ein "hier wurde nichts gemessen" ist eine Information; ein leeres Feld
        ist eine Einladung, es fuer ein Messergebnis zu halten.
        """
        for probe_id in _disabled_probe_ids(self.config):
            titel = ALL_PROBE_TITLES[probe_id]
            for finding in self._candidates(findings, probe_id):
                finding.probes.append(
                    self._for_finding(
                        disabled_result(
                            probe_id, titel, "Diese Sonde ist in der Konfiguration abgeschaltet."
                        ),
                        finding,
                    )
                )

    @staticmethod
    def _candidates(findings: list[Finding], probe_id: str) -> list[Finding]:
        """Welche Befunde diese Sonde angefordert haetten - ohne sie zu bauen."""
        keys = CANDIDATE_KEYS.get(probe_id, frozenset())
        return [
            finding
            for finding in findings
            if (finding.group.provider.lower(), finding.group.event_id) in keys
        ]
