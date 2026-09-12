"""Aggregates the current device list into dashboard-ready summary stats."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .models import DeviceKind, WifiDevice, WirelessStandard

RSSI_BUCKETS = [
    ("-30 to 0", -30, 0),
    ("-50 to -30", -50, -30),
    ("-60 to -50", -60, -50),
    ("-70 to -60", -70, -60),
    ("-80 to -70", -80, -70),
    ("-100 to -80", -100, -80),
]

# Representative single-stream PHY ceiling per standard, for a "what kind of
# speed is this device capable of" reference table. Real negotiated
# per-device throughput isn't reliably exposed by Kismet's device summary
# (see classify.py's _max_rate note) - these are standard ceilings, not
# measurements, and are labelled as such everywhere they're shown.
THEORETICAL_MAX_MBPS = {
    WirelessStandard.B: 11,
    WirelessStandard.A: 54,
    WirelessStandard.G: 54,
    WirelessStandard.N: 150,
    WirelessStandard.AC: 866,
    WirelessStandard.AX: 1200,
    WirelessStandard.BE: 2400,
}

NEW_DEVICE_WINDOW_SEC = 300


def _channel_sort_key(channel: str):
    try:
        return (0, int(channel))
    except (ValueError, TypeError):
        return (1, channel or "")


@dataclass
class DeviceStats:
    total: int = 0
    access_points: int = 0
    clients: int = 0
    other: int = 0
    open_networks: int = 0
    new_devices: int = 0

    kind_counts: dict[str, int] = field(default_factory=dict)
    standard_counts: dict[str, int] = field(default_factory=dict)
    band_counts: dict[str, int] = field(default_factory=dict)
    encryption_counts: dict[str, int] = field(default_factory=dict)
    top_manufacturers: list[tuple[str, int]] = field(default_factory=list)
    rssi_histogram: list[tuple[str, int]] = field(default_factory=list)

    # Manufacturer breakdown scoped per device kind, e.g.
    # {"Access Point": [("Cisco Meraki", 6), ("Ruckus", 11), ("Ubiquiti", 2)]}
    manuf_by_kind: dict[str, list[tuple[str, int]]] = field(default_factory=dict)

    # Channel utilization split by band, sorted by channel number where possible.
    channels_24: list[tuple[str, int]] = field(default_factory=list)
    channels_5_6: list[tuple[str, int]] = field(default_factory=list)

    # (standard label, device count, theoretical max Mbps or None)
    speed_table: list[tuple[str, int, "int | None"]] = field(default_factory=list)

    # Access points ranked by associated client count.
    top_aps_by_clients: list[tuple[str, str, int]] = field(default_factory=list)  # (name, mac, count)


def compute_stats(devices: list[WifiDevice], top_n_manuf: int = 10, top_n_aps: int = 8) -> DeviceStats:
    stats = DeviceStats(total=len(devices))
    now = time.time()

    kind_counts: dict[str, int] = {}
    standard_counts: dict[str, int] = {}
    band_counts: dict[str, int] = {}
    encryption_counts: dict[str, int] = {}
    manuf_counts: dict[str, int] = {}
    manuf_by_kind_counts: dict[str, dict[str, int]] = {}
    channel_counts: dict[str, int] = {}
    rssi_buckets = {label: 0 for label, _, _ in RSSI_BUCKETS}
    standard_device_counts: dict[WirelessStandard, int] = {}

    for dev in devices:
        kind_counts[dev.kind.value] = kind_counts.get(dev.kind.value, 0) + 1
        if dev.kind == DeviceKind.ACCESS_POINT:
            stats.access_points += 1
            if dev.encryption == "Open":
                stats.open_networks += 1
        elif dev.kind == DeviceKind.CLIENT:
            stats.clients += 1
        else:
            stats.other += 1

        if dev.first_seen and (now - dev.first_seen) <= NEW_DEVICE_WINDOW_SEC:
            stats.new_devices += 1

        if dev.standard != WirelessStandard.UNKNOWN:
            standard_counts[dev.standard.value] = standard_counts.get(dev.standard.value, 0) + 1
            standard_device_counts[dev.standard] = standard_device_counts.get(dev.standard, 0) + 1

        if dev.band:
            band_counts[dev.band] = band_counts.get(dev.band, 0) + 1

        enc = dev.encryption or "Unknown"
        encryption_counts[enc] = encryption_counts.get(enc, 0) + 1

        if dev.manuf:
            manuf_counts[dev.manuf] = manuf_counts.get(dev.manuf, 0) + 1
            per_kind = manuf_by_kind_counts.setdefault(dev.kind.value, {})
            per_kind[dev.manuf] = per_kind.get(dev.manuf, 0) + 1

        if dev.channel:
            channel_counts[dev.channel] = channel_counts.get(dev.channel, 0) + 1

        if dev.signal_dbm is not None:
            for label, lo, hi in RSSI_BUCKETS:
                if lo <= dev.signal_dbm < hi or (hi == 0 and dev.signal_dbm == 0):
                    rssi_buckets[label] += 1
                    break

    stats.kind_counts = kind_counts
    stats.standard_counts = standard_counts
    stats.band_counts = band_counts
    stats.encryption_counts = encryption_counts
    stats.top_manufacturers = sorted(manuf_counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n_manuf]
    stats.rssi_histogram = [(label, rssi_buckets[label]) for label, _, _ in RSSI_BUCKETS]

    stats.manuf_by_kind = {
        kind: sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top_n_manuf]
        for kind, counts in manuf_by_kind_counts.items()
    }

    channels_24, channels_5_6 = [], []
    for channel, count in sorted(channel_counts.items(), key=lambda kv: _channel_sort_key(kv[0])):
        try:
            ch_num = int(channel)
        except (ValueError, TypeError):
            ch_num = None
        if ch_num is not None and ch_num <= 14:
            channels_24.append((channel, count))
        else:
            channels_5_6.append((channel, count))
    stats.channels_24 = channels_24
    stats.channels_5_6 = channels_5_6

    stats.speed_table = sorted(
        (
            (std.value, count, THEORETICAL_MAX_MBPS.get(std))
            for std, count in standard_device_counts.items()
        ),
        key=lambda row: row[1],
        reverse=True,
    )

    aps = [d for d in devices if d.kind == DeviceKind.ACCESS_POINT and d.client_count > 0]
    aps.sort(key=lambda d: d.client_count, reverse=True)
    stats.top_aps_by_clients = [(d.name, d.mac, d.client_count) for d in aps[:top_n_aps]]

    return stats


def sorted_manufacturers(devices: list[WifiDevice]) -> list[str]:
    """Distinct manufacturers seen so far, alphabetical - for populating the filter dropdown."""
    return sorted({d.manuf for d in devices if d.manuf})
