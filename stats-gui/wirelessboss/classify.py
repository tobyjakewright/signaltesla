"""Turns a raw Kismet device JSON record into a normalized WifiDevice.

Kismet's schema has a lot of nested sub-objects whose exact leaf key
names vary a little by version. `_dig` tries a list of candidate paths
and returns the first hit, so this stays useful even if one alias is
wrong for a given Kismet build - worth double-checking against a live
`/devices/views/all/devices.json` response if fields show up empty.
"""
from __future__ import annotations

from typing import Any, Optional

from .models import DeviceKind, WifiDevice, WirelessStandard

# Kismet crypt bitmask -> human label, common bits (see kis_dot11_phy.h).
# Treated as best-effort labelling, not authoritative.
_CRYPT_LABELS = {
    0: "Open",
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
    on ".". So each candidate here is either a single literal key
    (a plain string, looked up directly - do not split it), or, when
    descending through more than one real dict level (e.g. into the
    `dot11.device` sub-object and then a dotted key inside it), a
    tuple/list of literal keys applied one dict-level at a time.
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
    if freq_mhz < 1000:
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
        labels = [name for bit, name in _CRYPT_LABELS.items() if bit and crypt & bit]
        return "/".join(sorted(set(labels))) if labels else f"Unknown (0x{crypt:x})"
    # Fall back to the strongest crypt string across advertised SSIDs.
    ssid_map = _dig(raw, ("dot11.device", "dot11.device.advertised_ssid_map")) or {}
    strings = set()
    if isinstance(ssid_map, dict):
        for ssid in ssid_map.values():
            s = _dig(ssid, "dot11.advertisedssid.crypt_string")
            if s:
                strings.add(s)
    return "/".join(sorted(strings)) if strings else "Unknown"


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
    """Best-effort: look for HT/VHT/HE capability markers on advertised SSIDs,
    otherwise fall back to a reasonable guess from the band alone."""
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

    if has_he:
        return WirelessStandard.AX
    if has_vht and band == "5GHz":
        return WirelessStandard.AC
    if has_ht:
        return WirelessStandard.N
    if band == "6GHz":
        # 6GHz is AX/BE-only in practice even without an explicit HE marker.
        return WirelessStandard.AX
    if band == "5GHz":
        return WirelessStandard.A
    if band == "2.4GHz":
        return WirelessStandard.G
    return WirelessStandard.UNKNOWN


def _max_rate(raw: dict) -> Optional[float]:
    rate = _dig(raw, ("dot11.device", "dot11.device.client_map"))
    # Kismet doesn't expose a single clean "negotiated rate" field on the
    # base device consistently across versions; leaving this as a hook -
    # populate it from per-packet dot11.packet.datarate in a future pass
    # that reads the packet capture feed rather than the device summary.
    return None


def parse_device(raw: dict) -> WifiDevice:
    mac = _dig(raw, "kismet.device.base.macaddr") or "??:??:??:??:??:??"
    # Kismet reports this field in kHz (e.g. 2412000 for channel 1), not MHz.
    freq = int(_dig(raw, "kismet.device.base.frequency") or 0) // 1000
    band = _band_from_freq(freq)

    signal_obj = _dig(raw, "kismet.device.base.signal") or {}
    last_signal = _dig(signal_obj, "kismet.common.signal.last_signal") or _dig(
        signal_obj, "kismet.common.signal.last_signal_dbm"
    )
    max_signal = _dig(signal_obj, "kismet.common.signal.max_signal") or _dig(
        signal_obj, "kismet.common.signal.max_signal_dbm"
    )

    loc_obj = _dig(raw, "kismet.device.base.location") or {}
    avg_loc = _dig(loc_obj, "kismet.common.location.avg_loc") or {}
    geopoint = _dig(avg_loc, "kismet.common.location.geopoint")
    alt = _dig(avg_loc, "kismet.common.location.alt")
    lat = lon = None
    if isinstance(geopoint, (list, tuple)) and len(geopoint) == 2:
        lon, lat = geopoint[0], geopoint[1]  # Kismet stores [lon, lat]

    ssid = ""
    ssid_map = _dig(raw, ("dot11.device", "dot11.device.advertised_ssid_map")) or {}
    if isinstance(ssid_map, dict) and ssid_map:
        first = next(iter(ssid_map.values()))
        ssid = _dig(first, "dot11.advertisedssid.ssid") or ""

    bssid = _dig(raw, ("dot11.device", "dot11.device.last_bssid")) or ""

    name = (
        ssid
        or _dig(raw, "kismet.device.base.commonname")
        or _dig(raw, "kismet.device.base.name")
        or mac
    )

    kind = _device_kind(raw)
    standard = _wireless_standard(raw, band)

    client_map = _dig(raw, ("dot11.device", "dot11.device.client_map")) or {}
    client_count = len(client_map) if isinstance(client_map, dict) else 0

    return WifiDevice(
        mac=mac,
        name=name,
        kind=kind,
        standard=standard,
        channel=str(_dig(raw, "kismet.device.base.channel") or ""),
        frequency_mhz=freq,
        band=band,
        encryption=_encryption_label(raw),
        signal_dbm=int(last_signal) if last_signal not in (None, 0) else None,
        signal_max_dbm=int(max_signal) if max_signal not in (None, 0) else None,
        max_rate_mbps=_max_rate(raw),
        manuf=_dig(raw, "kismet.device.base.manuf") or "",
        bssid=bssid,
        client_count=client_count,
        packets=int(_dig(raw, "kismet.device.base.packets.total") or 0),
        data_bytes=int(_dig(raw, "kismet.device.base.datasize") or 0),
        first_seen=_dig(raw, "kismet.device.base.first_time"),
        last_seen=_dig(raw, "kismet.device.base.last_time"),
        latitude=lat,
        longitude=lon,
        altitude_m=alt,
        raw=raw,
    )
