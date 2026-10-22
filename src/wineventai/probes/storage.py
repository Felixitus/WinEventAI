"""Storage probe: health values, overall SMART status, usage.

This probe reports ALL disks, not the one from the finding. The message of disk
51/153 names a device in the form ``\\Device\\Harddisk3\\DR3``; this number
cannot be mapped reliably onto a PhysicalDisk object - it depends on the
detection order and is wrong with RAID and multipath configurations anyway. A
wrongly attributed disk would be worse than none at all, so the caveat is in
the result text.

And a second caveat that is just as important: a clean overall SMART status
does not exonerate a disk. It only says that none of the monitored thresholds
was crossed. An unremarkable result here is therefore explicitly "says nothing
about it" and not "speaks against it" - unlike a service that demonstrably
runs.
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

PROBE_ID = "storage"
TITLE = "State of the disks"
TARGET = "all"

#: Findings that justify a disk measurement.
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

#: From here on the free space of a volume is itself a source of errors.
LOW_SPACE_PERCENT = 10.0

ATTRIBUTION_CAVEAT = (
    "Which of these disks belongs to the finding is open: the device reference "
    "in the event message (\\Device\\HarddiskN) cannot be mapped reliably onto a "
    "device."
)


def _as_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


class StorageProbe:
    """Reads health and usage values of the disks."""

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
                "Storage probe failed",
                exception=run.payloads.exception,
                code=run.returncode,
            )
            return [
                failed_result(
                    PROBE_ID,
                    TITLE,
                    "The disk values could not be read.",
                    target=TARGET,
                    error=run.payloads.exception or run.stderr.strip()[:200] or None,
                )
            ]

        return [interpret(run.payloads, duration_seconds=run.duration_seconds)]


def interpret(payloads: ProbePayloads, *, duration_seconds: float = 0.0) -> ProbeResult:
    """Combines disks, SMART and volumes into one result."""
    disks = payloads.of_kind("disk")
    smart = payloads.of_kind("smart")
    volumes = payloads.of_kind("volume")
    notes = [str(item.get("text", "")) for item in payloads.of_kind("note")]

    if not disks and not smart and not volumes:
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.UNAVAILABLE,
            target=TARGET,
            summary=(
                "No disk values could be read on this system. For virtual machines "
                "and behind RAID controllers that is the normal case."
            ),
            details=notes,
            duration_seconds=duration_seconds,
        )

    details = [_disk_line(disk) for disk in disks]
    details.extend(_smart_line(item) for item in smart)
    details.extend(_volume_line(item) for item in volumes if _volume_line(item))
    details.extend(notes)

    unhealthy = [d for d in disks if str(d.get("health", "")).lower() not in ("healthy", "")]
    with_errors = [d for d in disks if _error_count(d) > 0]
    predicted = [s for s in smart if s.get("failure_predicted")]
    tight = [v for v in volumes if _low_space(v)]

    if predicted or unhealthy:
        affected = {str(d.get("name")) for d in unhealthy}
        affected |= {str(s.get("instance")) for s in predicted}
        count = len(affected)
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target=TARGET,
            summary=(
                f"{count} disk(s) report an unhealthy state. "
                "Check the backup before any further test."
            ),
            details=[*details, ATTRIBUTION_CAVEAT],
            duration_seconds=duration_seconds,
        )

    if with_errors:
        total = sum(_error_count(d) for d in with_errors)
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.SUPPORTS,
            target=TARGET,
            summary=(
                f"The overall status is unremarkable, but the reliability counters "
                f"stand at {total} read/write errors."
            ),
            details=[*details, ATTRIBUTION_CAVEAT],
            duration_seconds=duration_seconds,
        )

    if tight:
        names = ", ".join(str(v.get("drive") or v.get("label")) for v in tight)
        return ProbeResult(
            probe_id=PROBE_ID,
            title=TITLE,
            status=ProbeStatus.WARN,
            bearing=ProbeBearing.INCONCLUSIVE,
            target=TARGET,
            summary=(
                f"All disks report healthy, but less than {LOW_SPACE_PERCENT:.0f} percent "
                f"is free on {names}."
            ),
            details=details,
            duration_seconds=duration_seconds,
        )

    return ProbeResult(
        probe_id=PROBE_ID,
        title=TITLE,
        status=ProbeStatus.OK,
        # Deliberately not "speaks against it": a clean SMART status is no
        # certificate of health. Disks regularly fail without any threshold
        # having been crossed before.
        bearing=ProbeBearing.INCONCLUSIVE,
        target=TARGET,
        summary=(
            "All disks report healthy and without error counters. That does not "
            "rule out a defect - SMART only reports crossed thresholds, and I/O "
            "errors also arise at cables and controllers."
        ),
        details=details,
        duration_seconds=duration_seconds,
    )


def _error_count(disk: dict[str, object]) -> int:
    return (_as_int(disk.get("read_errors")) or 0) + (_as_int(disk.get("write_errors")) or 0)


def _gb(value: object) -> str | None:
    number = _as_int(value)
    if number is None:
        return None
    return f"{number / 1024 ** 3:.0f} GB"


def _disk_line(disk: dict[str, object]) -> str:
    parts = [str(disk.get("name") or "Disk")]
    if disk.get("media"):
        parts.append(str(disk.get("media")))
    size = _gb(disk.get("size_b"))
    if size:
        parts.append(size)
    head = " · ".join(parts)

    extra = [f"Health: {disk.get('health') or 'unknown'}"]
    if not disk.get("counters_available"):
        extra.append("no reliability counters available")
    else:
        extra.append(
            f"read errors {_as_int(disk.get('read_errors')) or 0}, "
            f"write errors {_as_int(disk.get('write_errors')) or 0}"
        )
        hours = _as_int(disk.get("power_on_hours"))
        if hours:
            extra.append(f"{hours} power-on hours")
        temperature = _as_int(disk.get("temperature_c"))
        if temperature:
            extra.append(f"{temperature} °C")
    return f"{head} — " + ", ".join(extra)


def _smart_line(item: dict[str, object]) -> str:
    state = "failure predicted" if item.get("failure_predicted") else "unremarkable"
    return f"Overall SMART status {item.get('instance') or ''}: {state}".strip()


def _low_space(volume: dict[str, object]) -> bool:
    size = _as_int(volume.get("size_b")) or 0
    free = _as_int(volume.get("free_b"))
    if not size or free is None:
        return False
    return (free / size) * 100.0 < LOW_SPACE_PERCENT


def _volume_line(volume: dict[str, object]) -> str:
    name = volume.get("drive") or volume.get("label")
    if not name:
        return ""
    size = _as_int(volume.get("size_b")) or 0
    free = _as_int(volume.get("free_b"))
    if not size or free is None:
        return f"Volume {name}: usage unknown"
    share = (free / size) * 100.0
    return (
        f"Volume {name} ({volume.get('file_system') or '?'}): "
        f"{_gb(free)} of {_gb(size)} free ({share:.0f} %)"
    )
