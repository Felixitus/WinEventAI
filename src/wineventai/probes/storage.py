"""Datentraegersonde: Gesundheitswerte, SMART-Gesamtstatus, Belegung.

Diese Sonde meldet ALLE Datentraeger, nicht den einen aus dem Befund. Die
Meldung von disk 51/153 nennt eine Geraeteangabe der Form
``\\Device\\Harddisk3\\DR3``; diese Nummer laesst sich nicht zuverlaessig auf
ein PhysicalDisk-Objekt abbilden - sie haengt an der Erkennungsreihenfolge und
stimmt bei RAID- und Mehrpfad-Konfigurationen ohnehin nicht. Ein falsch
zugeordneter Datentraeger waere schlimmer als gar keiner, deshalb steht der
Vorbehalt im Ergebnistext.

Und ein zweiter Vorbehalt, der genauso wichtig ist: Ein sauberer
SMART-Gesamtstatus entlastet einen Datentraeger nicht. Er sagt nur, dass keiner
der ueberwachten Schwellwerte gerissen ist. Deshalb ist ein unauffaelliges
Ergebnis hier ausdruecklich "sagt dazu nichts" und nicht "spricht dagegen" -
anders als bei einem Dienst, der nachweislich laeuft.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..applog import get_log
from ..collect.shell import ShellInfo
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

PROBE_ID = "datentraeger"
TITLE = "Zustand der Datentraeger"
TARGET = "alle"

#: Befunde, die eine Datentraegermessung rechtfertigen.
STORAGE_EVENTS: frozenset[tuple[str, int]] = frozenset(
    {
        ("disk", 7),
        ("disk", 11),
        ("disk", 51),
        ("disk", 52),
        ("disk", 153),
        ("storahci", 129),
        ("stornvme", 129),
        ("iastora", 129),
        ("iastorac", 129),
        ("ntfs", 55),
        ("ntfs", 98),
        ("ntfs", 137),
        ("microsoft-windows-ntfs", 55),
        ("microsoft-windows-ntfs", 98),
        ("volsnap", 25),
        ("volmgr", 46),
    }
)

#: Ab hier ist der freie Platz eines Volumes selbst eine Fehlerquelle.
LOW_SPACE_PERCENT = 10.0

ZUORDNUNG_VORBEHALT = (
    "Welcher dieser Datentraeger zum Befund gehoert, ist offen: Die Geraeteangabe "
    "in der Ereignismeldung (\\Device\\HarddiskN) laesst sich nicht zuverlaessig "
    "auf ein Geraet abbilden."
)


def _as_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


class StorageProbe:
    """Liest Gesundheits- und Belegungswerte der Datentraeger."""

    probe_id = PROBE_ID
    title = TITLE

    def __init__(self, shell: ShellInfo, *, timeout_seconds: float = 30.0) -> None:
        self.shell = shell
        self.timeout_seconds = timeout_seconds

    def target_for(self, finding: Finding) -> str | None:
        key = (finding.group.provider.lower(), finding.group.event_id)
        return TARGET if key in STORAGE_EVENTS else None

    def run(self, targets: dict[str, list[Finding]]) -> list[ProbeResult]:
        if not targets:
            return []

        run = run_probe_script(
            "probe_storage.ps1", [], shell=self.shell, timeout_seconds=self.timeout_seconds
        )
        if run.timed_out:
            return [timed_out_result(PROBE_ID, TITLE, run.duration_seconds)]
        if run.payloads.exception or (run.returncode != 0 and not run.payloads.items):
            get_log().warn(
                "Datentraegersonde fehlgeschlagen",
                ausnahme=run.payloads.exception,
                code=run.returncode,
            )
            return [
                failed_result(
                    PROBE_ID,
                    TITLE,
                    "Die Datentraegerwerte liessen sich nicht lesen.",
                    target=TARGET,
                    error=run.payloads.exception or run.stderr.strip()[:200] or None,
                )
            ]

        return [interpret(run.payloads, duration_seconds=run.duration_seconds)]


def interpret(payloads: ProbePayloads, *, duration_seconds: float = 0.0) -> ProbeResult:
    """Fasst Datentraeger, SMART und Volumes zu einem Ergebnis zusammen."""
    disks = payloads.of_kind("datentraeger")
    smart = payloads.of_kind("smart")
    volumes = payloads.of_kind("volume")
    hinweise = [str(item.get("text", "")) for item in payloads.of_kind("hinweis")]

    if not disks and not smart and not volumes:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.UNAVAILABLE,
            target=TARGET,
            summary=(
                "Auf diesem System liessen sich keine Datentraegerwerte lesen. "
                "Bei virtuellen Maschinen und hinter RAID-Controllern ist das der Normalfall."
            ),
            details=hinweise,
            duration_seconds=duration_seconds,
        )

    details = [_disk_line(disk) for disk in disks]
    details.extend(_smart_line(item) for item in smart)
    details.extend(_volume_line(item) for item in volumes if _volume_line(item))
    details.extend(hinweise)

    krank = [d for d in disks if str(d.get("gesundheit", "")).lower() not in ("healthy", "")]
    fehlerzaehler = [d for d in disks if _error_count(d) > 0]
    vorhergesagt = [s for s in smart if s.get("ausfall_vorhergesagt")]
    eng = [v for v in volumes if _low_space(v)]

    if vorhergesagt or krank:
        betroffen = {str(d.get("name")) for d in krank}
        betroffen |= {str(s.get("instanz")) for s in vorhergesagt}
        anzahl = len(betroffen)
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target=TARGET,
            summary=(
                f"{anzahl} Datentraeger meldet einen nicht gesunden Zustand. "
                "Vor jedem weiteren Test gehoert die Datensicherung geprueft."
            ),
            details=[*details, ZUORDNUNG_VORBEHALT],
            duration_seconds=duration_seconds,
        )

    if fehlerzaehler:
        gesamt = sum(_error_count(d) for d in fehlerzaehler)
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target=TARGET,
            summary=(
                f"Der Gesamtstatus ist unauffaellig, aber die Zuverlaessigkeitszaehler "
                f"stehen bei {gesamt} Lese-/Schreibfehlern."
            ),
            details=[*details, ZUORDNUNG_VORBEHALT],
            duration_seconds=duration_seconds,
        )

    if eng:
        namen = ", ".join(str(v.get("laufwerk") or v.get("bezeichnung")) for v in eng)
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.INCONCLUSIVE,
            target=TARGET,
            summary=(
                f"Alle Datentraeger melden sich gesund, aber auf {namen} sind weniger "
                f"als {LOW_SPACE_PERCENT:.0f} Prozent frei."
            ),
            details=details,
            duration_seconds=duration_seconds,
        )

    return ProbeResult(
        probe_id=PROBE_ID,
        title=TITLE,
        status=ProbeStatus.OK,
        # Bewusst nicht "spricht dagegen": Ein sauberer SMART-Status ist kein
        # Gesundheitszeugnis. Datentraeger fallen regelmaessig aus, ohne dass
        # vorher ein Schwellwert gerissen ist.
        bearing=ProbeBearing.INCONCLUSIVE,
        target=TARGET,
        summary=(
            "Alle Datentraeger melden sich gesund und ohne Fehlerzaehler. Das "
            "schliesst einen Defekt nicht aus - SMART meldet nur gerissene "
            "Schwellwerte, und E/A-Fehler entstehen auch an Kabel und Controller."
        ),
        details=details,
        duration_seconds=duration_seconds,
    )


def _error_count(disk: dict[str, object]) -> int:
    return (_as_int(disk.get("lesefehler")) or 0) + (_as_int(disk.get("schreibfehler")) or 0)


def _gb(value: object) -> str | None:
    zahl = _as_int(value)
    if zahl is None:
        return None
    return f"{zahl / 1024 ** 3:.0f} GB"


def _disk_line(disk: dict[str, object]) -> str:
    teile = [str(disk.get("name") or "Datentraeger")]
    if disk.get("medium"):
        teile.append(str(disk.get("medium")))
    groesse = _gb(disk.get("groesse_b"))
    if groesse:
        teile.append(groesse)
    kopf = " · ".join(teile)

    zusatz = [f"Gesundheit: {disk.get('gesundheit') or 'unbekannt'}"]
    if not disk.get("zaehler_da"):
        zusatz.append("keine Zuverlaessigkeitszaehler verfuegbar")
    else:
        zusatz.append(
            f"Lesefehler {_as_int(disk.get('lesefehler')) or 0}, "
            f"Schreibfehler {_as_int(disk.get('schreibfehler')) or 0}"
        )
        stunden = _as_int(disk.get("betriebsstunden"))
        if stunden:
            zusatz.append(f"{stunden} Betriebsstunden")
        temperatur = _as_int(disk.get("temperatur_c"))
        if temperatur:
            zusatz.append(f"{temperatur} °C")
    return f"{kopf} — " + ", ".join(zusatz)


def _smart_line(item: dict[str, object]) -> str:
    zustand = "Ausfall vorhergesagt" if item.get("ausfall_vorhergesagt") else "unauffaellig"
    return f"SMART-Gesamtstatus {item.get('instanz') or ''}: {zustand}".strip()


def _low_space(volume: dict[str, object]) -> bool:
    groesse = _as_int(volume.get("groesse_b")) or 0
    frei = _as_int(volume.get("frei_b"))
    if not groesse or frei is None:
        return False
    return (frei / groesse) * 100.0 < LOW_SPACE_PERCENT


def _volume_line(volume: dict[str, object]) -> str:
    name = volume.get("laufwerk") or volume.get("bezeichnung")
    if not name:
        return ""
    groesse = _as_int(volume.get("groesse_b")) or 0
    frei = _as_int(volume.get("frei_b"))
    if not groesse or frei is None:
        return f"Volume {name}: Belegung unbekannt"
    anteil = (frei / groesse) * 100.0
    return (
        f"Volume {name} ({volume.get('dateisystem') or '?'}): "
        f"{_gb(frei)} von {_gb(groesse)} frei ({anteil:.0f} %)"
    )
