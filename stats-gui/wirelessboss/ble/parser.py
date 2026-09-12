"""Decode WCH JSON-lines records into beginner-friendly BLE packet data.

The WCH firmware captures the primary advertising channels and, after a
CONNECT_IND, natively follows that connection across data channels 0-36.
The driver marks each record as ``advertising`` or ``data`` so the same two
header bits are never ambiguously decoded as both an advertising PDU type and
a data-channel LLID.

Every public parser is defensive.  A truncated or otherwise malformed PDU
returns the information that could be recovered together with ``malformed``
and ``errors`` instead of raising from the capture-reader thread.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


PDU_TYPE_NAMES: dict[int, str] = {
    0x00: "ADV_IND",
    0x01: "ADV_DIRECT_IND",
    0x02: "ADV_NONCONN_IND",
    0x03: "SCAN_REQ",
    0x04: "SCAN_RSP",
    0x05: "CONNECT_IND",
    0x06: "ADV_SCAN_IND",
    0x07: "ADV_EXT_IND",
}

PDU_PURPOSES: dict[int, str] = {
    0x00: "Connectable and scannable advertisement: announces a device that can accept a connection.",
    0x01: "Directed advertisement: asks one specific target device to connect.",
    0x02: "Non-connectable advertisement: broadcasts information without accepting scans or connections.",
    0x03: "Scan request: a scanner asks an advertiser for its additional scan-response data.",
    0x04: "Scan response: the advertiser returns extra identity or service information to a scanner.",
    0x05: "Connection indication: an initiator proposes the timing and channel map for a BLE connection.",
    0x06: "Scannable advertisement: broadcasts presence and allows a scanner to request more information.",
    0x07: "Extended advertisement: BLE 5 advertising metadata that may point to a secondary data channel.",
}

DATA_LLID_NAMES: dict[int, str] = {
    0x00: "LL_RESERVED",
    0x01: "LL_CONTINUATION",
    0x02: "LL_DATA",
    0x03: "LL_CONTROL",
}

DATA_LLID_PURPOSES: dict[int, str] = {
    0x00: "Reserved data-channel packet type.",
    0x01: "Continuation or empty link-layer packet; carries a continued fragment or acknowledges traffic without new application data.",
    0x02: "Start or complete L2CAP data packet; carries Bluetooth protocol or application data.",
    0x03: "Link Layer control packet; manages the connection itself rather than application data.",
}

# Bluetooth Core Link Layer control opcodes.  Keep the short, precise purpose
# text in-process so packet explanations still work on an offline Kali system.
LL_CONTROL_NAMES: dict[int, str] = {
    0x00: "LL_CONNECTION_UPDATE_IND",
    0x01: "LL_CHANNEL_MAP_IND",
    0x02: "LL_TERMINATE_IND",
    0x03: "LL_ENC_REQ",
    0x04: "LL_ENC_RSP",
    0x05: "LL_START_ENC_REQ",
    0x06: "LL_START_ENC_RSP",
    0x07: "LL_UNKNOWN_RSP",
    0x08: "LL_FEATURE_REQ",
    0x09: "LL_FEATURE_RSP",
    0x0A: "LL_PAUSE_ENC_REQ",
    0x0B: "LL_PAUSE_ENC_RSP",
    0x0C: "LL_VERSION_IND",
    0x0D: "LL_REJECT_IND",
    0x0E: "LL_PERIPHERAL_FEATURE_REQ",
    0x0F: "LL_CONNECTION_PARAM_REQ",
    0x10: "LL_CONNECTION_PARAM_RSP",
    0x11: "LL_REJECT_EXT_IND",
    0x12: "LL_PING_REQ",
    0x13: "LL_PING_RSP",
    0x14: "LL_LENGTH_REQ",
    0x15: "LL_LENGTH_RSP",
    0x16: "LL_PHY_REQ",
    0x17: "LL_PHY_RSP",
    0x18: "LL_PHY_UPDATE_IND",
    0x19: "LL_MIN_USED_CHANNELS_IND",
    0x1A: "LL_CTE_REQ",
    0x1B: "LL_CTE_RSP",
    0x1C: "LL_PERIODIC_SYNC_IND",
    0x1D: "LL_CLOCK_ACCURACY_REQ",
    0x1E: "LL_CLOCK_ACCURACY_RSP",
    0x1F: "LL_CIS_REQ",
    0x20: "LL_CIS_RSP",
    0x21: "LL_CIS_IND",
    0x22: "LL_CIS_TERMINATE_IND",
    0x23: "LL_POWER_CONTROL_REQ",
    0x24: "LL_POWER_CONTROL_RSP",
    0x25: "LL_POWER_CHANGE_IND",
}

LL_CONTROL_PURPOSES: dict[int, str] = {
    0x00: "Changes connection timing parameters at a scheduled event.",
    0x01: "Replaces the connection's data-channel map at a scheduled event.",
    0x02: "Ends the connection and supplies a reason code.",
    0x03: "Central supplies encryption material and requests encrypted traffic.",
    0x04: "Peripheral supplies its part of the encryption material.",
    0x05: "Requests the transition to encrypted link-layer traffic.",
    0x06: "Confirms the transition to encrypted link-layer traffic.",
    0x07: "Reports that the peer did not recognise a control opcode.",
    0x08: "Central asks which Link Layer features the peer supports.",
    0x09: "Reports supported Link Layer features.",
    0x0A: "Requests a temporary pause in link-layer encryption.",
    0x0B: "Acknowledges a temporary pause in link-layer encryption.",
    0x0C: "Reports Link Layer version, company, and implementation information.",
    0x0D: "Rejects the most recent control procedure with a reason code.",
    0x0E: "Peripheral asks which Link Layer features the central supports.",
    0x0F: "Proposes new connection timing parameters.",
    0x10: "Replies to a connection-parameter proposal.",
    0x11: "Rejects a named control procedure with a reason code.",
    0x12: "Checks that the encrypted connection is still responsive.",
    0x13: "Replies to a Link Layer ping.",
    0x14: "Proposes maximum data length and transmission time.",
    0x15: "Replies with maximum data length and transmission time.",
    0x16: "Proposes PHYs for the connected link.",
    0x17: "Replies with supported PHY choices.",
    0x18: "Schedules a connected-link PHY change.",
    0x19: "Reports the minimum number of channels the peer should use.",
    0x1A: "Requests a constant-tone extension for direction finding.",
    0x1B: "Replies to a constant-tone-extension request.",
    0x1C: "Transfers periodic-advertising synchronisation over the connection.",
    0x1D: "Requests a sleep-clock-accuracy update.",
    0x1E: "Reports updated sleep-clock accuracy.",
    0x1F: "Proposes a connected isochronous stream.",
    0x20: "Replies to a connected isochronous stream proposal.",
    0x21: "Schedules a connected isochronous stream.",
    0x22: "Terminates a connected isochronous stream.",
    0x23: "Requests connected-link transmit-power changes.",
    0x24: "Replies with connected-link power-control information.",
    0x25: "Reports a connected-link power change.",
}

AD_TYPE_NAMES: dict[int, str] = {
    0x01: "Flags",
    0x02: "Incomplete 16-bit Service UUIDs",
    0x03: "Complete 16-bit Service UUIDs",
    0x04: "Incomplete 32-bit Service UUIDs",
    0x05: "Complete 32-bit Service UUIDs",
    0x06: "Incomplete 128-bit Service UUIDs",
    0x07: "Complete 128-bit Service UUIDs",
    0x08: "Shortened Local Name",
    0x09: "Complete Local Name",
    0x0A: "TX Power Level",
    0x12: "Peripheral Connection Interval Range",
    0x16: "Service Data - 16-bit UUID",
    0x19: "Appearance",
    0x20: "Service Data - 32-bit UUID",
    0x21: "Service Data - 128-bit UUID",
    0x24: "URI",
    0xFF: "Manufacturer Specific Data",
}

# A compact offline subset of the Bluetooth SIG company identifier list.  An
# unknown value remains useful and is displayed as "Company 0xNNNN".
COMPANY_NAMES: dict[int, str] = {
    0x0006: "Microsoft",
    0x000F: "Broadcom Corporation",
    0x004C: "Apple, Inc.",
    0x0059: "Nordic Semiconductor ASA",
    0x0075: "Samsung Electronics Co. Ltd.",
    0x0087: "Garmin International, Inc.",
    0x00E0: "Google",
    0x038F: "Xiaomi Communications Co Ltd",
    0x0499: "Ruuvi Innovations Ltd.",
}

SERVICE_NAMES_16: dict[int, str] = {
    0x1800: "Generic Access",
    0x1801: "Generic Attribute",
    0x1802: "Immediate Alert",
    0x1803: "Link Loss",
    0x1804: "TX Power",
    0x1805: "Current Time",
    0x180A: "Device Information",
    0x180D: "Heart Rate",
    0x180F: "Battery Service",
    0x1810: "Blood Pressure",
    0x1812: "Human Interface Device",
    0x1816: "Cycling Speed and Cadence",
    0x1818: "Cycling Power",
    0x181A: "Environmental Sensing",
    0x181C: "User Data",
    0x181D: "Weight Scale",
    0x1826: "Fitness Machine",
}

FLAG_NAMES: dict[int, str] = {
    0x01: "Limited Discoverable",
    0x02: "General Discoverable",
    0x04: "BR/EDR Not Supported",
    0x08: "Simultaneous LE and BR/EDR (Controller)",
    0x10: "Simultaneous LE and BR/EDR (Host)",
}

SCA_RANGES = {
    0: "251-500 ppm",
    1: "151-250 ppm",
    2: "101-150 ppm",
    3: "76-100 ppm",
    4: "51-75 ppm",
    5: "31-50 ppm",
    6: "21-30 ppm",
    7: "0-20 ppm",
}


def _as_int(value: Any, default: int | None = None) -> int | None:
    try:
        if value is None:
            return default
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float | None = None) -> float | None:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalised = value.strip().lower()
        if normalised in {"1", "true", "yes", "on", "valid", "decrypted"}:
            return True
        if normalised in {"0", "false", "no", "off", "invalid", "encrypted"}:
            return False
    return default


def _normalise_fixed_hex(value: Any, octets: int) -> str:
    if isinstance(value, int):
        if 0 <= value < (1 << (octets * 8)):
            return f"{value:0{octets * 2}X}"
        return ""
    text = str(value or "").strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    compact = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(compact) != octets * 2:
        return ""
    return compact.upper()


def _ble_crc24(pdu: bytes, init: int) -> bytes:
    """Reconstruct the three de-whitened on-air CRC octets.

    This matches the Bluetooth bit order used by the capture driver.  It is a
    compatibility fallback for older JSON producers; current records already
    include their driver-reconstructed CRC.
    """

    def reverse8(value: int) -> int:
        value = ((value >> 4) | (value << 4)) & 0xFF
        value = ((value & 0xCC) >> 2) | ((value & 0x33) << 2)
        return ((value & 0xAA) >> 1) | ((value & 0x55) << 1)

    state = (
        reverse8(init & 0xFF)
        | (reverse8((init >> 8) & 0xFF) << 8)
        | (reverse8((init >> 16) & 0xFF) << 16)
    )
    for value in pdu:
        data = value
        for _ in range(8):
            feedback = (state ^ data) & 1
            state >>= 1
            if feedback:
                state ^= 0xDA6000
            data >>= 1
    return bytes((state & 0xFF, (state >> 8) & 0xFF, (state >> 16) & 0xFF))


def _normalise_address(value: Any) -> str:
    if value is None:
        return ""
    compact = re.sub(r"[^0-9A-Fa-f]", "", str(value))
    if len(compact) != 12:
        return str(value).strip().upper()
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2)).upper()


def format_ble_address(wire_bytes: bytes | bytearray | memoryview) -> str:
    """Format a six-byte on-air BLE address in conventional display order."""
    raw = bytes(wire_bytes)
    if len(raw) != 6:
        return ""
    return ":".join(f"{octet:02X}" for octet in reversed(raw))


def _address_subtype(wire_address: bytes, random_address: bool) -> str:
    if not random_address or len(wire_address) != 6:
        return ""
    top = (wire_address[5] >> 6) & 0x03
    return {
        0b00: "non-resolvable private",
        0b01: "resolvable private",
        0b10: "reserved",
        0b11: "static",
    }[top]


def _display_address_subtype(address: str, random_address: bool) -> str:
    if not random_address:
        return ""
    try:
        display = bytes.fromhex(address.replace(":", ""))
    except ValueError:
        return ""
    return _address_subtype(bytes(reversed(display)), True) if len(display) == 6 else ""


def _uuid16(value: int) -> str:
    name = SERVICE_NAMES_16.get(value)
    return f"{name} (0x{value:04X})" if name else f"0x{value:04X}"


def _uuid32(raw: bytes) -> str:
    return f"0x{int.from_bytes(raw, 'little'):08X}"


def _uuid128(raw: bytes) -> str:
    # Bluetooth UUIDs are transmitted least-significant octet first.
    h = bytes(reversed(raw)).hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _decode_uuid_list(data: bytes, width: int, errors: list[str]) -> list[str]:
    if len(data) % width:
        errors.append(
            f"Service UUID list has {len(data)} bytes, not a multiple of {width}."
        )
    values: list[str] = []
    for offset in range(0, len(data) - (len(data) % width), width):
        raw = data[offset : offset + width]
        if width == 2:
            values.append(_uuid16(int.from_bytes(raw, "little")))
        elif width == 4:
            values.append(_uuid32(raw))
        else:
            values.append(_uuid128(raw))
    return values


def parse_ad_structures(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Parse a legacy/extended advertising-data byte sequence.

    Returns aggregate name/manufacturer/services fields alongside the complete
    list of decoded AD structures.  Malformed tail data is retained as an
    error rather than discarded silently.
    """
    raw = bytes(data)
    structures: list[dict[str, Any]] = []
    errors: list[str] = []
    services: list[str] = []
    complete_name = ""
    shortened_name = ""
    manufacturer = ""
    manufacturer_id: int | None = None
    offset = 0

    while offset < len(raw):
        length = raw[offset]
        offset += 1
        if length == 0:
            # Zero is an ordinary terminator; non-zero padding after it is
            # unusual but not dangerous and remains visible in raw_hex.
            break
        if offset + length > len(raw):
            errors.append(
                f"AD structure at byte {offset - 1} declares {length} byte(s), "
                f"but only {len(raw) - offset} remain."
            )
            break

        ad_type = raw[offset]
        value = raw[offset + 1 : offset + length]
        item: dict[str, Any] = {
            "type_code": ad_type,
            "type_name": AD_TYPE_NAMES.get(ad_type, f"Unknown AD type 0x{ad_type:02X}"),
            "length": length,
            "data_hex": value.hex().upper(),
        }

        if ad_type == 0x01 and value:
            flags = value[0]
            item["flags"] = [name for bit, name in FLAG_NAMES.items() if flags & bit]
        elif ad_type in (0x02, 0x03):
            item["services"] = _decode_uuid_list(value, 2, errors)
            services.extend(item["services"])
        elif ad_type in (0x04, 0x05):
            item["services"] = _decode_uuid_list(value, 4, errors)
            services.extend(item["services"])
        elif ad_type in (0x06, 0x07):
            item["services"] = _decode_uuid_list(value, 16, errors)
            services.extend(item["services"])
        elif ad_type in (0x08, 0x09):
            item["name"] = value.decode("utf-8", errors="replace").rstrip("\x00")
            if ad_type == 0x09:
                complete_name = item["name"]
            elif not shortened_name:
                shortened_name = item["name"]
        elif ad_type == 0x0A and value:
            item["tx_power_dbm"] = int.from_bytes(value[:1], "little", signed=True)
        elif ad_type == 0x12 and len(value) >= 4:
            low = int.from_bytes(value[0:2], "little")
            high = int.from_bytes(value[2:4], "little")
            item["minimum_ms"] = low * 1.25
            item["maximum_ms"] = high * 1.25
        elif ad_type == 0x16 and len(value) >= 2:
            uuid = _uuid16(int.from_bytes(value[:2], "little"))
            item["service"] = uuid
            item["service_data_hex"] = value[2:].hex().upper()
            services.append(uuid)
        elif ad_type == 0x20 and len(value) >= 4:
            uuid = _uuid32(value[:4])
            item["service"] = uuid
            item["service_data_hex"] = value[4:].hex().upper()
            services.append(uuid)
        elif ad_type == 0x21 and len(value) >= 16:
            uuid = _uuid128(value[:16])
            item["service"] = uuid
            item["service_data_hex"] = value[16:].hex().upper()
            services.append(uuid)
        elif ad_type == 0x19 and len(value) >= 2:
            item["appearance"] = int.from_bytes(value[:2], "little")
        elif ad_type == 0x24:
            item["uri"] = value.decode("utf-8", errors="replace")
        elif ad_type == 0xFF:
            if len(value) >= 2:
                company_id = int.from_bytes(value[:2], "little")
                company_name = COMPANY_NAMES.get(company_id, f"Company 0x{company_id:04X}")
                item["company_id"] = company_id
                item["company_id_hex"] = f"0x{company_id:04X}"
                item["company"] = company_name
                item["manufacturer_data_hex"] = value[2:].hex().upper()
                if manufacturer_id is None:
                    manufacturer_id = company_id
                    manufacturer = company_name
            else:
                errors.append("Manufacturer-specific AD structure is missing its 2-byte company ID.")

        structures.append(item)
        offset += length

    # Preserve first-seen ordering while removing duplicate services.
    unique_services = list(dict.fromkeys(services))
    return {
        "name": complete_name or shortened_name,
        "manufacturer": manufacturer,
        "manufacturer_id": manufacturer_id,
        "services": unique_services,
        "ad_structures": structures,
        "ad_raw_hex": raw.hex().upper(),
        "errors": errors,
    }


def _take_extended_field(
    fields: bytes,
    cursor: int,
    size: int,
    label: str,
    errors: list[str],
) -> tuple[bytes, int]:
    end = cursor + size
    if end > len(fields):
        errors.append(
            f"ADV_EXT_IND says {label} is present, but its extended header is truncated."
        )
        return fields[cursor:], len(fields)
    return fields[cursor:end], end


def _parse_extended(payload: bytes, errors: list[str]) -> tuple[dict[str, Any], bytes]:
    details: dict[str, Any] = {
        "capture_note": (
            "The analyzer can natively follow a legacy CONNECT_IND onto connected "
            "data channels. AuxPtr is a different mechanism: it points to secondary "
            "advertising, which is decoded here but is not automatically followed."
        )
    }
    if not payload:
        errors.append("ADV_EXT_IND has no extended-header length byte.")
        return details, b""

    first = payload[0]
    ext_length = first & 0x3F
    adv_mode = (first >> 6) & 0x03
    details["extended_header_length"] = ext_length
    details["advertising_mode"] = {
        0: "non-connectable and non-scannable",
        1: "connectable",
        2: "scannable",
        3: "reserved",
    }[adv_mode]
    details["connectable"] = adv_mode == 1
    details["scannable"] = adv_mode == 2

    data_offset = 1 + ext_length
    if data_offset > len(payload):
        errors.append(
            f"ADV_EXT_IND declares a {ext_length}-byte extended header, "
            f"but only {max(0, len(payload) - 1)} byte(s) follow."
        )
        data_offset = len(payload)

    if ext_length == 0:
        return details, payload[1:]

    header = payload[1:data_offset]
    if not header:
        errors.append("ADV_EXT_IND extended header is missing its flags byte.")
        return details, payload[data_offset:]

    flags = header[0]
    details["flags"] = flags
    details["fields_present"] = [
        name
        for bit, name in enumerate(
            ["AdvA", "TargetA", "CTEInfo", "ADI", "AuxPtr", "SyncInfo", "TxPower", "RFU"]
        )
        if flags & (1 << bit)
    ]
    fields = header[1:]
    cursor = 0

    if flags & 0x01:
        value, cursor = _take_extended_field(fields, cursor, 6, "AdvA", errors)
        if len(value) == 6:
            details["advertiser_address"] = format_ble_address(value)
    if flags & 0x02:
        value, cursor = _take_extended_field(fields, cursor, 6, "TargetA", errors)
        if len(value) == 6:
            details["target_address"] = format_ble_address(value)
    if flags & 0x04:
        value, cursor = _take_extended_field(fields, cursor, 1, "CTEInfo", errors)
        if value:
            details["cte_info"] = value[0]
    if flags & 0x08:
        value, cursor = _take_extended_field(fields, cursor, 2, "ADI", errors)
        if len(value) == 2:
            adi = int.from_bytes(value, "little")
            details["adi"] = {
                "sid": (adi >> 12) & 0x0F,
                "did": adi & 0x0FFF,
            }
    if flags & 0x10:
        value, cursor = _take_extended_field(fields, cursor, 3, "AuxPtr", errors)
        if len(value) == 3:
            channel = value[0] & 0x3F
            unit_us = 300 if value[0] & 0x80 else 30
            aux_offset = value[1] | ((value[2] & 0x1F) << 8)
            aux_phy_code = (value[2] >> 5) & 0x07
            details["aux_ptr"] = {
                "channel": channel,
                "frequency_mhz": 2404 + 2 * channel if 0 <= channel <= 10 else (
                    2428 + 2 * (channel - 11) if 11 <= channel <= 36 else None
                ),
                "clock_accuracy": "0-50 ppm" if value[0] & 0x40 else "51-500 ppm",
                "offset_units_us": unit_us,
                "offset": aux_offset,
                "offset_us": aux_offset * unit_us,
                "phy": {0: "LE 1M", 1: "LE 2M", 2: "LE Coded"}.get(
                    aux_phy_code, f"reserved ({aux_phy_code})"
                ),
            }
    if flags & 0x20:
        value, cursor = _take_extended_field(fields, cursor, 18, "SyncInfo", errors)
        if len(value) == 18:
            details["sync_info_hex"] = value.hex().upper()
    if flags & 0x40:
        value, cursor = _take_extended_field(fields, cursor, 1, "TxPower", errors)
        if value:
            details["tx_power_dbm"] = int.from_bytes(value, "little", signed=True)
    if flags & 0x80:
        details["rfu_present"] = True

    if cursor < len(fields):
        details["unparsed_extended_header_hex"] = fields[cursor:].hex().upper()
    return details, payload[data_offset:]


def _parse_connect_ind(ll_data: bytes, errors: list[str]) -> dict[str, Any]:
    details: dict[str, Any] = {
        "metadata_only": False,
        "followed_by_firmware": True,
        "capture_note": (
            "The analyzer firmware uses these parameters to follow this connection "
            "across data channels 0-36; matching packets are labelled with this "
            "connection's access address, endpoints, and direction."
        ),
    }
    if len(ll_data) < 22:
        errors.append(
            f"CONNECT_IND LLData needs 22 bytes; only {len(ll_data)} were captured."
        )
        details["raw_hex"] = ll_data.hex().upper()
        return details

    access_address = int.from_bytes(ll_data[0:4], "little")
    crc_init = int.from_bytes(ll_data[4:7], "little")
    win_size = ll_data[7]
    win_offset = int.from_bytes(ll_data[8:10], "little")
    interval = int.from_bytes(ll_data[10:12], "little")
    latency = int.from_bytes(ll_data[12:14], "little")
    timeout = int.from_bytes(ll_data[14:16], "little")
    channel_map_raw = ll_data[16:21]
    channel_map = int.from_bytes(channel_map_raw, "little")
    hop_sca = ll_data[21]
    hop = hop_sca & 0x1F
    sca = (hop_sca >> 5) & 0x07

    details.update(
        {
            "access_address": f"{access_address:08X}",
            "crc_init": f"{crc_init:06X}",
            "window_size_units": win_size,
            "window_size_ms": win_size * 1.25,
            "window_offset_units": win_offset,
            "window_offset_ms": win_offset * 1.25,
            "interval_units": interval,
            "interval_ms": interval * 1.25,
            "latency": latency,
            "supervision_timeout_units": timeout,
            "supervision_timeout_ms": timeout * 10,
            "channel_map_hex": channel_map_raw.hex().upper(),
            "data_channels": [channel for channel in range(37) if channel_map & (1 << channel)],
            "hop_increment": hop,
            "sleep_clock_accuracy": SCA_RANGES[sca],
        }
    )
    if len(ll_data) > 22:
        details["trailing_hex"] = ll_data[22:].hex().upper()
    return details


def _coerce_pdu(value: Any) -> tuple[bytes, str | None]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value), None
    if not isinstance(value, str):
        return b"", "PDU is not bytes or a hexadecimal string."
    compact = value.strip().replace(" ", "").replace(":", "").replace("-", "")
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if not compact:
        return b"", "PDU is empty."
    if len(compact) % 2:
        return b"", "PDU hexadecimal string has an odd number of digits."
    try:
        return bytes.fromhex(compact), None
    except ValueError:
        return b"", "PDU contains non-hexadecimal characters."


def _pdu_direction(pdu_type: int) -> str:
    if pdu_type in (0x00, 0x01, 0x02, 0x06, 0x07):
        return "advertiser to scanners"
    if pdu_type == 0x03:
        return "scanner to advertiser"
    if pdu_type == 0x04:
        return "advertiser to scanner"
    if pdu_type == 0x05:
        return "initiator to advertiser"
    return "unknown"


def _data_direction(source: Mapping[str, Any]) -> str:
    name = str(source.get("direction_name") or "").strip().lower()
    code = _as_int(source.get("direction"), 0)
    if name == "initiator_to_advertiser" or code == 1:
        return "initiator to advertiser (central → peripheral)"
    if name == "advertiser_to_initiator" or code == 2:
        return "advertiser to initiator (peripheral → central)"
    return "unknown"


def _decode_data_control(payload: bytes, errors: list[str]) -> dict[str, Any]:
    details: dict[str, Any] = {}
    if not payload:
        errors.append("LL control packet is missing its opcode.")
        return details

    opcode = payload[0]
    body = payload[1:]
    details.update(
        {
            "opcode": opcode,
            "opcode_hex": f"0x{opcode:02X}",
            "name": LL_CONTROL_NAMES.get(opcode, f"LL_CONTROL_0x{opcode:02X}"),
            "purpose": LL_CONTROL_PURPOSES.get(
                opcode,
                "Link Layer control procedure not named by this offline decoder.",
            ),
            "parameters_hex": body.hex().upper(),
        }
    )

    # Decode the high-value fields a beginner is most likely to inspect.  Raw
    # parameters remain available for every opcode and truncated packets never
    # escape the reader thread as exceptions.
    if opcode == 0x00 and len(body) >= 11:
        details.update(
            {
                "window_size_ms": body[0] * 1.25,
                "window_offset_ms": int.from_bytes(body[1:3], "little") * 1.25,
                "interval_ms": int.from_bytes(body[3:5], "little") * 1.25,
                "latency": int.from_bytes(body[5:7], "little"),
                "supervision_timeout_ms": int.from_bytes(body[7:9], "little") * 10,
                "instant": int.from_bytes(body[9:11], "little"),
            }
        )
    elif opcode == 0x01 and len(body) >= 7:
        channel_map = int.from_bytes(body[:5], "little")
        details["data_channels"] = [
            channel for channel in range(37) if channel_map & (1 << channel)
        ]
        details["instant"] = int.from_bytes(body[5:7], "little")
    elif opcode in (0x02, 0x0D) and body:
        details["reason_code"] = body[0]
        details["reason_hex"] = f"0x{body[0]:02X}"
    elif opcode == 0x03 and len(body) >= 22:
        details.update(
            {
                "rand_hex": body[0:8].hex().upper(),
                "ediv": int.from_bytes(body[8:10], "little"),
                "skdm_hex": body[10:18].hex().upper(),
                "ivm_hex": body[18:22].hex().upper(),
            }
        )
    elif opcode == 0x04 and len(body) >= 12:
        details["skds_hex"] = body[0:8].hex().upper()
        details["ivs_hex"] = body[8:12].hex().upper()
    elif opcode == 0x0C and len(body) >= 5:
        details.update(
            {
                "version": body[0],
                "company_id": int.from_bytes(body[1:3], "little"),
                "subversion": int.from_bytes(body[3:5], "little"),
            }
        )
    elif opcode in (0x14, 0x15) and len(body) >= 8:
        details.update(
            {
                "max_rx_octets": int.from_bytes(body[0:2], "little"),
                "max_rx_time_us": int.from_bytes(body[2:4], "little"),
                "max_tx_octets": int.from_bytes(body[4:6], "little"),
                "max_tx_time_us": int.from_bytes(body[6:8], "little"),
            }
        )
    elif opcode in (0x16, 0x17) and len(body) >= 2:
        details["tx_phys"] = body[0]
        details["rx_phys"] = body[1]
    elif opcode == 0x18 and len(body) >= 4:
        details["m_to_s_phy"] = body[0]
        details["s_to_m_phy"] = body[1]
        details["instant"] = int.from_bytes(body[2:4], "little")
    return details


def _data_packet_identity(
    header0: int | None,
    payload: bytes,
    *,
    encrypted: bool,
    decrypted: bool,
    errors: list[str],
) -> tuple[int, str, str, dict[str, Any]]:
    llid = (header0 & 0x03) if header0 is not None else -1
    details: dict[str, Any] = {
        "llid": llid,
        "nesn": bool(header0 & 0x04) if header0 is not None else None,
        "sn": bool(header0 & 0x08) if header0 is not None else None,
        "more_data": bool(header0 & 0x10) if header0 is not None else None,
        "cte_info_present": bool(header0 & 0x20) if header0 is not None else None,
    }
    if encrypted and not decrypted and payload:
        details["ciphertext_hex"] = payload.hex().upper()
        return (
            llid,
            "LL_ENCRYPTED",
            "Encrypted link-layer payload. Supply the connection LTK to name and decode its contents.",
            details,
        )
    if llid == 0x01 and not payload:
        return (
            llid,
            "LL_EMPTY",
            "Empty link-layer packet; acknowledges traffic and keeps the connection event active.",
            details,
        )
    if llid == 0x03:
        control = _decode_data_control(payload, errors)
        details["control"] = control
        name = str(control.get("name") or "LL_CONTROL")
        purpose = str(control.get("purpose") or DATA_LLID_PURPOSES[0x03])
        return llid, name, purpose, details
    return (
        llid,
        DATA_LLID_NAMES.get(llid, "LL_RESERVED"),
        DATA_LLID_PURPOSES.get(llid, "Unknown data-channel LLID."),
        details,
    )


def parse_wch_packet(record: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Normalize and decode one JSON object emitted by ``wch_capture -J``."""
    source: Mapping[str, Any] = record if isinstance(record, Mapping) else {}
    errors: list[str] = []
    raw, raw_error = _coerce_pdu(source.get("pdu_hex", source.get("raw_hex", b"")))
    if raw_error:
        errors.append(raw_error)
    elif not raw:
        errors.append("PDU is empty.")

    supplied_host_ts = _as_float(source.get("host_timestamp"))
    host_ts_us = _as_int(source.get("host_timestamp_us"))
    if supplied_host_ts is None and host_ts_us is not None:
        supplied_host_ts = host_ts_us / 1_000_000.0

    link_layer = str(source.get("link_layer") or "advertising").strip().lower()
    if link_layer not in {"advertising", "data"}:
        errors.append(f"Unknown link layer {link_layer!r}; treating it as advertising.")
        link_layer = "advertising"
    is_data = link_layer == "data"

    supplied_type = _as_int(source.get("type_code"))
    header0 = raw[0] if raw else None
    pdu_type = (header0 & (0x03 if is_data else 0x0F)) if header0 is not None else (
        supplied_type if supplied_type is not None else -1
    )
    type_name = PDU_TYPE_NAMES.get(pdu_type, f"RFU_0x{pdu_type & 0xFF:02X}")
    purpose = PDU_PURPOSES.get(
        pdu_type,
        "Reserved advertising PDU type; no purpose is assigned by the Bluetooth specification.",
    )
    if supplied_type is not None and header0 is not None and supplied_type != pdu_type:
        errors.append(
            f"Driver type code {supplied_type} disagrees with "
            f"{'LLID' if is_data else 'PDU header type'} {pdu_type}."
        )

    declared_length = raw[1] if len(raw) >= 2 else None
    if raw and len(raw) < 2:
        errors.append("PDU is missing its length byte.")
    payload = b""
    trailing = b""
    if declared_length is not None:
        available = max(0, len(raw) - 2)
        payload = raw[2 : 2 + min(declared_length, available)]
        if declared_length > available:
            errors.append(
                f"PDU declares {declared_length} payload byte(s), but only {available} were captured."
            )
        elif declared_length < available:
            trailing = raw[2 + declared_length :]
            errors.append(
                f"PDU has {len(trailing)} byte(s) after its declared payload length."
            )

    tx_add = bool(header0 & 0x40) if header0 is not None and not is_data else False
    rx_add = bool(header0 & 0x80) if header0 is not None and not is_data else False
    access_address = _normalise_fixed_hex(source.get("access_address"), 4)
    if source.get("access_address") not in (None, "") and not access_address:
        errors.append("Access address must be exactly four hexadecimal bytes.")
    if not access_address and not is_data:
        access_address = "8E89BED6"
    crc_init = _normalise_fixed_hex(source.get("crc_init"), 3)
    if source.get("crc_init") not in (None, "") and not crc_init:
        errors.append("CRCInit must be exactly three hexadecimal bytes.")
    if not crc_init and not is_data:
        crc_init = "555555"
    supplied_crc = _normalise_fixed_hex(source.get("crc"), 3)
    if source.get("crc") not in (None, "") and not supplied_crc:
        errors.append("CRC must be exactly three hexadecimal bytes.")
    reconstructed_crc = supplied_crc
    if not reconstructed_crc and raw and crc_init:
        reconstructed_crc = _ble_crc24(raw, int(crc_init, 16)).hex().upper()

    encrypted = _as_bool(source.get("encrypted"), False)
    decrypted = _as_bool(source.get("decrypted"), False)
    mic_value = source.get("mic_valid")
    mic_valid = _as_bool(mic_value) if mic_value is not None else None
    mic_checked = _as_bool(source.get("mic_checked"), mic_value is not None)
    retransmission = _as_bool(source.get("retransmission"), False)

    data_details: dict[str, Any] = {}
    if is_data:
        pdu_type, type_name, purpose, data_details = _data_packet_identity(
            header0,
            payload,
            encrypted=encrypted,
            decrypted=decrypted,
            errors=errors,
        )

    direction = _data_direction(source) if is_data else _pdu_direction(pdu_type)
    initiator = _normalise_address(source.get("initiator"))
    advertiser = _normalise_address(source.get("advertiser"))
    src = _normalise_address(source.get("src"))
    dst = _normalise_address(source.get("dst"))
    if is_data and (not src or not dst):
        if direction.startswith("initiator to"):
            src = src or initiator
            dst = dst or advertiser
        elif direction.startswith("advertiser to"):
            src = src or advertiser
            dst = dst or initiator

    aa_wire_hex = (
        int(access_address, 16).to_bytes(4, "little").hex().upper()
        if access_address
        else ""
    )
    raw_frame_hex = aa_wire_hex + raw.hex().upper() + reconstructed_crc
    crc_note = (
        "driver-reconstructed CRC"
        if supplied_crc
        else "parser-reconstructed CRC" if reconstructed_crc else "CRC unavailable"
    )
    raw_note = (
        "Wireshark-frame bytes: dynamic access address + decrypted PDU + CRC "
        "reconstructed from the captured encrypted PDU before its MIC was removed."
        if decrypted
        else (
            "Wireshark-frame bytes: dynamic access address + exact PDU + "
            f"{crc_note}. Hardware accepted the packet before the CRC was rebuilt."
        )
    )
    result: dict[str, Any] = {
        "host_timestamp": supplied_host_ts,
        "host_timestamp_us": host_ts_us,
        "device_timestamp_us": _as_int(source.get("device_timestamp_us")),
        "mcu_index": _as_int(source.get("mcu_index")),
        "usb_bus": _as_int(source.get("usb_bus")),
        "usb_address": _as_int(source.get("usb_address")),
        "channel": _as_int(source.get("channel")),
        "raw_channel": _as_int(source.get("raw_channel")),
        "device_flags": _as_int(source.get("device_flags")),
        "phy": str(source.get("phy") or ""),
        "link_layer": link_layer,
        "rssi": _as_int(source.get("rssi")),
        "access_address": access_address,
        "crc_init": crc_init,
        "crc": reconstructed_crc,
        "crc_reconstructed": bool(reconstructed_crc),
        "crc_source": crc_note,
        "type_code": pdu_type,
        "type_name": type_name,
        "purpose": purpose,
        "direction": direction,
        "direction_code": _as_int(source.get("direction")),
        "direction_name": str(source.get("direction_name") or ""),
        "src": src,
        "dst": dst,
        "initiator": initiator,
        "advertiser": advertiser,
        "address_type": ("random" if tx_add else "public") if not is_data else "",
        "target_address_type": ("random" if rx_add else "public") if not is_data else "",
        "encrypted": encrypted,
        "decrypted": decrypted,
        "mic_valid": mic_valid,
        "mic_checked": mic_checked,
        "retransmission": retransmission,
        "packet_counter": _as_int(source.get("packet_counter")),
        "decrypt_status": str(source.get("decrypt_status") or ""),
        "sequence_class": _as_int(source.get("sequence_class")),
        "header": {
            "raw": header0,
            "tx_add": tx_add,
            "rx_add": rx_add,
            "channel_selection_2": (
                bool(header0 & 0x20) if header0 is not None and not is_data else False
            ),
            "declared_payload_length": declared_length,
        },
        "name": "",
        "manufacturer": "",
        "manufacturer_id": None,
        "services": [],
        "ad_structures": [],
        # These describe the transmitting/source device.  CONNECT_IND is
        # transmitted by an initiator, and SCAN_REQ by a scanner, so neither
        # makes that source connectable/scannable.
        "connectable": not is_data and pdu_type in (0x00, 0x01),
        "scannable": not is_data and pdu_type in (0x00, 0x04, 0x06),
        "details": {"data": data_details} if is_data else {},
        "pdu_hex": raw.hex().upper(),
        "raw_hex": raw_frame_hex,
        "raw_note": raw_note,
        "pdu_length": len(raw),
        "payload_hex": payload.hex().upper(),
        "trailing_hex": trailing.hex().upper(),
        "malformed": False,
        "errors": errors,
    }

    ad_data = b""
    source_wire = b""
    target_wire = b""

    if not is_data and pdu_type in (0x00, 0x02, 0x04, 0x06):
        if len(payload) < 6:
            errors.append(f"{type_name} is missing its 6-byte advertiser address.")
        else:
            source_wire = payload[:6]
            result["src"] = format_ble_address(source_wire)
            ad_data = payload[6:]
    elif not is_data and pdu_type == 0x01:
        if len(payload) < 12:
            errors.append("ADV_DIRECT_IND needs advertiser and target addresses (12 bytes).")
        else:
            source_wire, target_wire = payload[:6], payload[6:12]
            result["src"] = format_ble_address(source_wire)
            result["dst"] = format_ble_address(target_wire)
    elif not is_data and pdu_type == 0x03:
        if len(payload) < 12:
            errors.append("SCAN_REQ needs scanner and advertiser addresses (12 bytes).")
        else:
            source_wire, target_wire = payload[:6], payload[6:12]
            result["src"] = format_ble_address(source_wire)
            result["dst"] = format_ble_address(target_wire)
    elif not is_data and pdu_type == 0x05:
        if len(payload) < 12:
            errors.append("CONNECT_IND needs initiator and advertiser addresses (12 bytes).")
        else:
            source_wire, target_wire = payload[:6], payload[6:12]
            result["src"] = format_ble_address(source_wire)
            result["dst"] = format_ble_address(target_wire)
            result["initiator"] = result["src"]
            result["advertiser"] = result["dst"]
            result["details"]["connection"] = _parse_connect_ind(payload[12:], errors)
    elif not is_data and pdu_type == 0x07:
        extended, ad_data = _parse_extended(payload, errors)
        result["details"]["extended"] = extended
        # The driver's generic source field is the first six payload bytes;
        # for extended advertising those are not necessarily an address.
        result["src"] = ""
        result["dst"] = ""
        if extended.get("advertiser_address"):
            result["src"] = extended["advertiser_address"]
        if extended.get("target_address"):
            result["dst"] = extended["target_address"]
        result["connectable"] = bool(extended.get("connectable"))
        result["scannable"] = bool(extended.get("scannable"))

    if source_wire:
        result["address_subtype"] = _address_subtype(source_wire, tx_add)
    else:
        result["address_subtype"] = _display_address_subtype(result["src"], tx_add)
    if target_wire:
        result["target_address_subtype"] = _address_subtype(target_wire, rx_add)
    else:
        result["target_address_subtype"] = ""
    if not result["src"]:
        result["address_type"] = ""
        result["address_subtype"] = ""
    if not result["dst"]:
        result["target_address_type"] = ""
        result["target_address_subtype"] = ""

    if ad_data:
        ad = parse_ad_structures(ad_data)
        result.update(
            {
                "name": ad["name"],
                "manufacturer": ad["manufacturer"],
                "manufacturer_id": ad["manufacturer_id"],
                "services": ad["services"],
                "ad_structures": ad["ad_structures"],
                "ad_raw_hex": ad["ad_raw_hex"],
            }
        )
        errors.extend(ad["errors"])
    else:
        result["ad_raw_hex"] = ""

    result["malformed"] = bool(errors)
    # Signal-analysis aliases keep BLE and Wi-Fi packet rows interchangeable.
    result["ts"] = result["host_timestamp"]
    result["type"] = result["type_name"]
    result["protocol"] = "BLE"
    result["length"] = result["pdu_length"]
    endpoints = result["src"]
    if result["dst"]:
        endpoints = f"{endpoints} → {result['dst']}" if endpoints else result["dst"]
    identity = result["name"] or result["manufacturer"]
    summary = [result["type_name"]]
    if endpoints:
        summary.append(endpoints)
    if identity:
        summary.append(identity)
    if result["channel"] is not None:
        summary.append(f"channel {result['channel']}")
    result["info"] = " · ".join(summary)
    return result


def parse_packet(record: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Short alias used by providers and tests."""
    return parse_wch_packet(record)


def decode_pdu(
    pdu: bytes | bytearray | memoryview | str,
    **metadata: Any,
) -> dict[str, Any]:
    """Decode a PDU directly while accepting optional WCH metadata fields."""
    return parse_wch_packet({**metadata, "pdu_hex": pdu})


__all__ = [
    "AD_TYPE_NAMES",
    "COMPANY_NAMES",
    "DATA_LLID_NAMES",
    "DATA_LLID_PURPOSES",
    "LL_CONTROL_NAMES",
    "LL_CONTROL_PURPOSES",
    "PDU_PURPOSES",
    "PDU_TYPE_NAMES",
    "decode_pdu",
    "format_ble_address",
    "parse_ad_structures",
    "parse_packet",
    "parse_wch_packet",
]
