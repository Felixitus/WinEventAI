"""Kontext-Sonden: gemeinsame Begriffe.

Eine Sonde misst den aktuellen Zustand eines Systems, um einen Befund zu
erklaeren oder zu entkraeften. Sie ist kein freistehendes Werkzeug: Jede Sonde
haengt an einem Befund und erscheint in dessen Karte.

**Der Vorbehalt, der jede Sonde begleitet.** Eine Sonde misst JETZT. Der Befund
entstand DAMALS. Ein Ping, der heute durchgeht, sagt nichts ueber eine
Namensaufloesung, die vor fuenf Tagen in eine Zeitueberschreitung lief. Deshalb
ist der Zeitabstand ein Feld im Modell und kein Textbaustein - genau wie
"nicht protokolliert" beim Sicherheitsmodus ein Status ist und keine Fussnote.
Wer eine gruene Sonde als Entwarnung liest, zieht sonst denselben falschen
Schluss wie bei "keine Befunde" auf einem nicht erhobenen Kanal.

Alle Sonden sind read-only und bleiben im lokalen Netz. Kein Speedtest gegen
einen Internet-Dienst: Der braeche "offline lauffaehig", "keine Telemetrie"
(die eigene IP ginge an den Anbieter) und "read-only" (er saettigt die Leitung
und erzeugt auf einem gestoerten Rechner genau die Stoerung, die man sucht).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # pragma: no cover
    # Absichtlich nur zur Typpruefung: ``rules.engine`` importiert ``ProbeResult``,
    # um es an den Befund zu haengen. Ein Laufzeitimport in die Gegenrichtung
    # waere ein Zirkel. Die Sonden brauchen ``Finding`` ohnehin nur als
    # Typangabe - dank ``from __future__ import annotations`` bleibt sie Text.
    from ..rules.engine import Finding


class ProbeStatus(StrEnum):
    OK = "unauffaellig"
    WARN = "auffaellig"
    FAILED = "fehlgeschlagen"
    NOT_APPLICABLE = "nicht anwendbar"
    NO_PERMISSION = "keine rechte"
    TIMED_OUT = "abgebrochen"
    DISABLED = "abgeschaltet"
    UNAVAILABLE = "nicht messbar"


#: Zustaende, in denen die Sonde nichts ausgesagt hat. Ein "unauffaellig" ist
#: eine Messung; alles hier ist das Fehlen einer Messung - und das darf im
#: Bericht nie wie eine Entwarnung aussehen.
NO_MEASUREMENT: frozenset[ProbeStatus] = frozenset(
    {
        ProbeStatus.FAILED,
        ProbeStatus.NOT_APPLICABLE,
        ProbeStatus.NO_PERMISSION,
        ProbeStatus.TIMED_OUT,
        ProbeStatus.DISABLED,
        ProbeStatus.UNAVAILABLE,
    }
)


class ProbeBearing(StrEnum):
    """Was die Messung fuer den Befund bedeutet."""

    SUPPORTS = "stuetzt den Befund"
    WEAKENS = "spricht dagegen"
    INCONCLUSIVE = "sagt dazu nichts"


class ProbeResult(BaseModel):
    """Das Ergebnis einer Messung, bezogen auf einen Befund."""

    model_config = ConfigDict(extra="forbid")

    probe_id: str
    title: str
    status: ProbeStatus
    bearing: ProbeBearing = ProbeBearing.INCONCLUSIVE
    summary: str = ""
    details: list[str] = Field(default_factory=list)
    target: str | None = None
    finding_id: str | None = None
    measured_utc: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finding_last_seen_utc: datetime | None = None
    duration_seconds: float = 0.0
    detail_error: str | None = None

    @property
    def measured(self) -> bool:
        """True, wenn tatsaechlich gemessen wurde."""
        return self.status not in NO_MEASUREMENT

    @property
    def age(self) -> timedelta | None:
        """Abstand zwischen Messung und letztem Vorkommen des Befunds."""
        if self.finding_last_seen_utc is None:
            return None
        return self.measured_utc - self.finding_last_seen_utc

    def age_note(self) -> str:
        """Der Zeitvorbehalt im Klartext.

        Steht in jeder Darstellung einer Sonde. Je groesser der Abstand, desto
        deutlicher die Formulierung - bei mehreren Tagen ist die Messung fuer
        den Befund praktisch wertlos, und das soll dastehen.
        """
        abstand = self.age
        if abstand is None:
            return "Gemessen jetzt; ein Bezug zum Zeitpunkt des Befunds ist nicht belegt."

        stunden = abstand.total_seconds() / 3600.0
        if stunden < 1:
            return "Gemessen kurz nach dem letzten Vorkommen."
        if stunden < 24:
            return (
                f"Gemessen {stunden:.0f} Stunden nach dem letzten Vorkommen - "
                "der Zustand kann sich seitdem geaendert haben."
            )
        tage = stunden / 24.0
        return (
            f"Gemessen {tage:.0f} Tage nach dem letzten Vorkommen. Ueber den "
            "Zustand zum Zeitpunkt des Befunds sagt diese Messung nichts."
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "sonde": self.probe_id,
            "titel": self.title,
            "status": str(self.status),
            "bedeutung": str(self.bearing),
            "gemessen": self.measured,
            "zusammenfassung": self.summary,
            "details": self.details,
            "ziel": self.target,
            "befund_id": self.finding_id,
            "gemessen_utc": self.measured_utc.isoformat(),
            "zeitvorbehalt": self.age_note(),
            "dauer_s": round(self.duration_seconds, 2),
            "fehler": self.detail_error,
        }


class Probe(Protocol):
    """Schnittstelle jeder Sonde.

    ``target_for`` ist der Kern der Entscheidung "Kontext-Sonde statt
    Werkzeugkasten": Eine Sonde laeuft nur, wenn ein Befund sie anfordert, und
    sie weiss aus dem Befund, WAS sie messen soll.
    """

    probe_id: str
    title: str

    def target_for(self, finding: Finding) -> str | None:
        """Was diese Sonde fuer diesen Befund messen wuerde. ``None`` = nichts."""
        ...

    def run(self, targets: dict[str, list[Finding]]) -> list[ProbeResult]:
        """Misst alle angeforderten Ziele und ordnet die Ergebnisse zu."""
        ...


def disabled_result(probe_id: str, title: str, grund: str) -> ProbeResult:
    return ProbeResult(
        probe_id=probe_id,
        title=title,
        status=ProbeStatus.DISABLED,
        summary=grund,
    )


def unavailable_result(
    probe_id: str, title: str, grund: str, *, error: str | None = None
) -> ProbeResult:
    return ProbeResult(
        probe_id=probe_id,
        title=title,
        status=ProbeStatus.UNAVAILABLE,
        summary=grund,
        detail_error=error,
    )


def failed_result(
    probe_id: str, title: str, grund: str, *, target: str | None = None, error: str | None = None
) -> ProbeResult:
    return ProbeResult(
        probe_id=probe_id,
        title=title,
        status=ProbeStatus.FAILED,
        summary=grund,
        target=target,
        detail_error=error,
    )


def timed_out_result(probe_id: str, title: str, seconds: float) -> ProbeResult:
    return ProbeResult(
        probe_id=probe_id,
        title=title,
        status=ProbeStatus.TIMED_OUT,
        summary=(
            f"Die Messung wurde nach {seconds:.0f} Sekunden abgebrochen. "
            "Was bis dahin gelesen wurde, reicht fuer keine Aussage."
        ),
        duration_seconds=seconds,
    )
