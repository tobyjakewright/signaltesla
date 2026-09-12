"""Minimal reader for the WCH BLE Analyzer Pro's JSON-lines output.

This is deliberately basic: it does NOT reimplement the full BLE link-layer
parser (connection following, encryption/MIC, extended advertising) that a
prior project built around this same driver. It only pulls out what a
simple "nearby BLE devices" list needs - address, advertised name,
manufacturer, RSSI, channel, last-seen - from ordinary advertising PDUs.

Stateless by design: every call re-reads a bounded tail of the JSON-lines
file and rebuilds the device list from just that window. No in-memory
cache, so it works correctly regardless of how many gunicorn workers are
running (an in-memory dict would silently diverge between workers).
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

# Legacy advertising PDU types that carry a 6-byte AdvA address followed by
# AD-structure data - the common "nearby device" broadcasts. CONNECT_IND,
# SCAN_REQ, and extended advertising are intentionally not decoded here.
_ADV_TYPES_WITH_AD_DATA = {0x00, 0x02, 0x04, 0x06}

# A small offline subset of Bluetooth SIG company identifiers - an unknown
# value still displays fine as "Company 0xNNNN".
_COMPANY_NAMES = {
    0x0006: "Microsoft",
    0x000F: "Broadcom",
    0x004C: "Apple",
    0x0059: "Nordic Semiconductor",
    0x0075: "Samsung",
    0x0087: "Garmin",
    0x00E0: "Google",
    0x038F: "Xiaomi",
    0x0499: "Ruuvi",
}


def _decode_pdu(pdu_hex: str) -> dict[str, str]:
    """Best-effort address/name/manufacturer from a legacy advertising PDU.
    Returns an empty dict if this isn't a PDU shape we handle."""
    try:
        raw = bytes.fromhex(pdu_hex)
    except (ValueError, TypeError):
        return {}
    if len(raw) < 8:  # header + length + at least a 6-byte address
        return {}

    pdu_type = raw[0] & 0x0F
    if pdu_type not in _ADV_TYPES_WITH_AD_DATA:
        return {}

    length = raw[1]
    payload = raw[2 : 2 + length]
    if len(payload) < 6:
        return {}

    address = ":".join(f"{b:02X}" for b in reversed(payload[:6]))
    ad_data = payload[6:]

    name = ""
    manufacturer = ""
    offset = 0
    while offset < len(ad_data):
        ad_len = ad_data[offset]
        offset += 1
        if ad_len == 0 or offset + ad_len > len(ad_data):
            break
        ad_type = ad_data[offset]
        value = ad_data[offset + 1 : offset + ad_len]
        if ad_type in (0x08, 0x09):  # shortened / complete local name
            decoded = value.decode("utf-8", errors="replace").rstrip("\x00")
            if ad_type == 0x09 or not name:
                name = decoded
        elif ad_type == 0xFF and len(value) >= 2:  # manufacturer data
            company_id = int.from_bytes(value[:2], "little")
            manufacturer = _COMPANY_NAMES.get(company_id, f"Company 0x{company_id:04X}")
        offset += ad_len

    return {"address": address, "name": name, "manufacturer": manufacturer}


def _tail_lines(path: str, window_bytes: int) -> list[str]:
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    with open(path, "rb") as f:
        start = max(0, size - window_bytes)
        f.seek(start)
        chunk = f.read()
    lines = chunk.split(b"\n")
    if start > 0:
        lines = lines[1:]  # drop a possibly-truncated first line
    return [line.decode("utf-8", errors="replace") for line in lines if line.strip()]


def recent_devices(
    jsonl_path: str, window_bytes: int = 262_144, max_age_sec: float = 120.0
) -> list[dict[str, Any]]:
    """Nearby BLE devices seen in the tail of the capture's JSON-lines log,
    newest first. Re-derived fresh on every call - see module docstring."""
    now = time.time()
    devices: dict[str, dict[str, Any]] = {}
    for line in _tail_lines(jsonl_path, window_bytes):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        pdu_hex = record.get("pdu_hex") or record.get("raw_hex") or ""
        decoded = _decode_pdu(pdu_hex)
        address = decoded.get("address")
        if not address:
            continue
        ts = record.get("host_timestamp") or now
        if now - ts > max_age_sec:
            continue
        existing = devices.get(address)
        if existing is None or ts >= existing["last_seen"]:
            devices[address] = {
                "address": address,
                "name": decoded.get("name") or (existing or {}).get("name", ""),
                "manufacturer": decoded.get("manufacturer") or (existing or {}).get("manufacturer", ""),
                "rssi": record.get("rssi"),
                "channel": record.get("channel"),
                "last_seen": ts,
            }
    return sorted(devices.values(), key=lambda d: d["last_seen"], reverse=True)
