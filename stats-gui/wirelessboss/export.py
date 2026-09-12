"""One-click CSV export of the current device list - all devices, plus
access-point-only and client-only breakouts, timestamped so repeated
exports don't clobber each other."""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from .models import DeviceKind, WifiDevice

FIELDNAMES = [
    "mac", "name", "kind", "standard", "band", "channel", "frequency_mhz",
    "encryption", "signal_dbm", "signal_max_dbm", "manuf", "bssid",
    "client_count", "packets", "data_bytes", "first_seen", "last_seen",
    "latitude", "longitude",
]


def _row(dev: WifiDevice) -> dict:
    def iso(ts):
        if not ts:
            return ""
        try:
            return datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="seconds")
        except (OSError, OverflowError, ValueError):
            return ""

    return {
        "mac": dev.mac,
        "name": dev.name,
        "kind": dev.kind.value,
        "standard": dev.standard.value,
        "band": dev.band,
        "channel": dev.channel,
        "frequency_mhz": dev.frequency_mhz,
        "encryption": dev.encryption,
        "signal_dbm": dev.signal_dbm if dev.signal_dbm is not None else "",
        "signal_max_dbm": dev.signal_max_dbm if dev.signal_max_dbm is not None else "",
        "manuf": dev.manuf,
        "bssid": dev.bssid,
        "client_count": dev.client_count,
        "packets": dev.packets,
        "data_bytes": dev.data_bytes,
        "first_seen": iso(dev.first_seen),
        "last_seen": iso(dev.last_seen),
        "latitude": dev.latitude if dev.latitude is not None else "",
        "longitude": dev.longitude if dev.longitude is not None else "",
    }


def _write_csv(path: Path, devices: list[WifiDevice]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for dev in devices:
            writer.writerow(_row(dev))


def export_csv(devices: list[WifiDevice], export_root: Path) -> dict[str, Path]:
    """Writes all_devices.csv / access_points.csv / clients.csv into a fresh
    timestamped subfolder of export_root. Returns {label: path}."""
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_dir = Path(export_root) / stamp
    out_dir.mkdir(parents=True, exist_ok=True)

    aps = [d for d in devices if d.kind == DeviceKind.ACCESS_POINT]
    clients = [d for d in devices if d.kind == DeviceKind.CLIENT]

    paths = {
        "all_devices": out_dir / "all_devices.csv",
        "access_points": out_dir / "access_points.csv",
        "clients": out_dir / "clients.csv",
    }
    _write_csv(paths["all_devices"], devices)
    _write_csv(paths["access_points"], aps)
    _write_csv(paths["clients"], clients)

    return paths
