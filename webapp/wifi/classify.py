"""Turns a raw Kismet device JSON record into a normalized WifiDevice.

Adapted (trimmed) from a prior project's WirelessBOSS dashboard - kept
because it's genuinely basic, portable logic with no special dependency
beyond Kismet's own REST API.

Kismet's schema has nested sub-objects whose exact leaf key names vary a
little by version. `_dig` tries a list of candidate paths and returns the
first hit, so this degrades gracefully instead of crashing if a field is
missing - worth double-checking against a live
`/devices/views/all/devices.json` response if fields show up empty.
"""
from __future__ import annotations

from typing import Any

from .models import DeviceKind, WifiDevice, WirelessStandard

_CRYPT_LABELS = {
    1: "WEP",
    2: "WPA",
    4: "WPA-PSK",
    8: "WPA-AES",
    16: "WPA-TKIP",
    32: "WPA2",
    64: "WPA2-PSK",
    128: "WPA3",
    256: "WPA3-SAE",
}


def _dig(d: Any, *paths: Any) -> Any:
    """Try each candidate path against d, return the first non-None hit.

    Kismet's JSON uses whole dotted strings as literal object keys (e.g.
    `{"kismet.device.base.macaddr": "..."}`), NOT real nested dicts split
    on ".". Each candidate is either a single literal key, or a
    tuple/list of literal keys applied one real dict-level at a time.
    """
    for path in paths:
        keys = path if isinstance(path, (list, tuple)) else (path,)
        cur = d
        ok = True
        for key in keys:
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                ok = False
                break
        if ok and cur is not None:
            return cur
    return None


def _band_from_freq(freq_mhz: int) -> str:
    if not freq_mhz:
        return ""
    if freq_mhz < 2500:
        return "2.4GHz"
    if freq_mhz < 5900:
        return "5GHz"
    if freq_mhz < 7200:
        return "6GHz"
    return ""


def _encryption_label(raw: dict) -> str:
    crypt = _dig(raw, "kismet.device.base.crypt")
    if isinstance(crypt, str) and crypt:
        return crypt
    if isinstance(crypt, int):
        if crypt == 0:
            return "Open"
        labels = [name for bit, name in _CRYPT_LABELS.items() if crypt & bit]
        return "/".join(sorted(set(labels))) if labels else f"Unknown (0x{crypt:x})"
    return "Unknown"


def _device_kind(raw: dict) -> DeviceKind:
    type_str = (_dig(raw, "kismet.device.base.type") or "").lower()
    if "ap" in type_str or "access point" in type_str or "master" in type_str:
        return DeviceKind.ACCESS_POINT
    if "bridge" in type_str:
        return DeviceKind.BRIDGE
    if "ad-hoc" in type_str or "adhoc" in type_str:
        return DeviceKind.AD_HOC
    if "client" in type_str or "wi-fi device" in type_str:
        return DeviceKind.CLIENT
    return DeviceKind.UNKNOWN


def _wireless_standard(raw: dict, band: str) -> WirelessStandard:
    """Best-effort from HT/VHT/HE capability markers, else a guess from band."""
    ssid_map = _dig(raw, ("dot11.device", "dot11.device.advertised_ssid_map")) or {}
    has_ht = has_vht = has_he = False
    if isinstance(ssid_map, dict):
        for ssid in ssid_map.values():
            if _dig(ssid, "dot11.advertisedssid.ht_capabilities", "dot11.advertisedssid.ht_mode"):
                has_ht = True
            if _dig(ssid, "dot11.advertisedssid.vht_capabilities", "dot11.advertisedssid.vht_mode"):
                has_vht = True
            if _dig(ssid, "dot11.advertisedssid.he_capabilities", "dot11.advertisedssid.he_mode"):
                has_he = True

    if has_he or band == "6GHz":
        return WirelessStandard.AX
    if has_vht and band == "5GHz":
        return WirelessStandard.AC
    if has_ht:
        return WirelessStandard.N
    if band == "5GHz":
        return WirelessStandard.A
    if band == "2.4GHz":
        return WirelessStandard.G
    return WirelessStandard.UNKNOWN


def parse_device(raw: dict) -> WifiDevice:
    mac = _dig(raw, "kismet.device.base.macaddr") or "??:??:??:??:??:??"
    # Kismet reports this field in kHz (e.g. 2412000 for channel 1).
    freq = int(_dig(raw, "kismet.device.base.frequency") or 0) // 1000
    band = _band_from_freq(freq)

    signal_obj = _dig(raw, "kismet.device.base.signal") or {}
    last_signal = _dig(signal_obj, "kismet.common.signal.last_signal") or _dig(
        signal_obj, "kismet.common.signal.last_signal_dbm"
    )

    loc_obj = _dig(raw, "kismet.device.base.location") or {}
    avg_loc = _dig(loc_obj, "kismet.common.location.avg_loc") or {}
    geopoint = _dig(avg_loc, "kismet.common.location.geopoint")
    lat = lon = None
    if isinstance(geopoint, (list, tuple)) and len(geopoint) == 2:
        lon, lat = geopoint[0], geopoint[1]  # Kismet stores [lon, lat]

    ssid = ""
    ssid_map = _dig(raw, ("dot11.device", "dot11.device.advertised_ssid_map")) or {}
    if isinstance(ssid_map, dict) and ssid_map:
        first = next(iter(ssid_map.values()))
        ssid = _dig(first, "dot11.advertisedssid.ssid") or ""

    name = (
        ssid
        or _dig(raw, "kismet.device.base.commonname")
        or _dig(raw, "kismet.device.base.name")
        or mac
    )

    client_map = _dig(raw, ("dot11.device", "dot11.device.client_map")) or {}
    client_count = len(client_map) if isinstance(client_map, dict) else 0

    return WifiDevice(
        mac=mac,
        name=name,
        kind=_device_kind(raw),
        standard=_wireless_standard(raw, band),
        channel=str(_dig(raw, "kismet.device.base.channel") or ""),
        band=band,
        encryption=_encryption_label(raw),
        signal_dbm=int(last_signal) if last_signal not in (None, 0) else None,
        manuf=_dig(raw, "kismet.device.base.manuf") or "",
        client_count=client_count,
        packets=int(_dig(raw, "kismet.device.base.packets.total") or 0),
        last_seen=_dig(raw, "kismet.device.base.last_time"),
        latitude=lat,
        longitude=lon,
    )
