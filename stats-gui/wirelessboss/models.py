"""Data models WirelessBOSS uses internally, independent of Kismet's raw JSON shape.

Keeping a normalized model here means the GUI/table/map code never touches
Kismet's `kismet.device.base.*` dotted field names directly - only
`kismet_client.py` (Wi-Fi) and future `ble/` providers (Bluetooth) do.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class DeviceKind(str, Enum):
    ACCESS_POINT = "Access Point"
    CLIENT = "Client"
    AD_HOC = "Ad-Hoc"
    BRIDGE = "Bridge"
    BLE = "BLE"
    UNKNOWN = "Unknown"


class WirelessStandard(str, Enum):
    A = "802.11a"
    B = "802.11b"
    G = "802.11g"
    N = "802.11n (Wi-Fi 4)"
    AC = "802.11ac (Wi-Fi 5)"
    AX = "802.11ax (Wi-Fi 6/6E)"
    BE = "802.11be (Wi-Fi 7)"
    UNKNOWN = "Unknown"


@dataclass
class WifiDevice:
    mac: str
    name: str = ""                      # SSID for APs, manuf/name fallback otherwise
    kind: DeviceKind = DeviceKind.UNKNOWN
    standard: WirelessStandard = WirelessStandard.UNKNOWN
    channel: str = ""
    frequency_mhz: int = 0
    band: str = ""                      # "2.4GHz" / "5GHz" / "6GHz"
    encryption: str = ""                # "Open" / "WEP" / "WPA2-PSK" / "WPA3-SAE" ...
    signal_dbm: Optional[int] = None    # RSSI, most recent
    signal_max_dbm: Optional[int] = None
    max_rate_mbps: Optional[float] = None
    manuf: str = ""
    bssid: str = ""                     # associated AP, for client devices
    client_count: int = 0               # for APs
    packets: int = 0
    data_bytes: int = 0
    first_seen: Optional[float] = None  # unix epoch
    last_seen: Optional[float] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_m: Optional[float] = None
    alert: str = ""                     # non-empty if Kismet flagged this device
    raw: dict = field(default_factory=dict)  # original Kismet JSON, for the inspector pane

    @property
    def has_location(self) -> bool:
        return self.latitude is not None and self.longitude is not None and (
            self.latitude != 0 or self.longitude != 0
        )


@dataclass
class BleDevice:
    """Normalized BLE sighting shared by sniffer providers and legacy views."""
    address: str
    name: str = ""
    rssi: Optional[int] = None
    address_type: str = ""              # "public" / "random"
    manuf: str = ""
    services: list = field(default_factory=list)
    last_seen: Optional[float] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    raw: dict = field(default_factory=dict)


@dataclass
class GpsFix:
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_m: Optional[float] = None
    speed_mps: Optional[float] = None
    heading_deg: Optional[float] = None
    fix_quality: int = 0                # 0 = no fix, 2 = 2D, 3 = 3D
    satellites: int = 0
