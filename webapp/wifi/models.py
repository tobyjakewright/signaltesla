"""Normalized Wi-Fi device shape, independent of Kismet's raw JSON field
names - adapted (trimmed) from a prior project's WirelessBOSS dashboard.
Only kismet_client.py/classify.py touch Kismet's dotted field names."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class DeviceKind(str, Enum):
    ACCESS_POINT = "Access Point"
    CLIENT = "Client"
    AD_HOC = "Ad-Hoc"
    BRIDGE = "Bridge"
    UNKNOWN = "Unknown"


class WirelessStandard(str, Enum):
    A = "802.11a"
    B = "802.11b"
    G = "802.11g"
    N = "802.11n (Wi-Fi 4)"
    AC = "802.11ac (Wi-Fi 5)"
    AX = "802.11ax (Wi-Fi 6/6E)"
    UNKNOWN = "Unknown"


@dataclass
class WifiDevice:
    mac: str
    name: str = ""
    kind: DeviceKind = DeviceKind.UNKNOWN
    standard: WirelessStandard = WirelessStandard.UNKNOWN
    channel: str = ""
    band: str = ""                      # "2.4GHz" / "5GHz" / "6GHz"
    encryption: str = ""                # "Open" / "WPA2-PSK" / ...
    signal_dbm: Optional[int] = None
    manuf: str = ""
    client_count: int = 0               # for APs
    packets: int = 0
    last_seen: Optional[float] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


@dataclass
class GpsFix:
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    fix_quality: int = 0                # 0 = no fix, 2 = 2D, 3 = 3D
    satellites: int = 0
