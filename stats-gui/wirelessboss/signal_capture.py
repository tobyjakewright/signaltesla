"""Live, Wireshark-like packet feed backed by Kismet and tshark.

Kismet already owns the monitor interface and channel hopping for
WirelessBOSS.  This module consumes Kismet's live pcapng endpoint and lets
``tshark`` do the protocol dissection instead of attempting to decode 802.11
frames a second time in Python::

    Kismet /pcap/all_packets.pcapng -> tshark -T ek -> bounded packet deque

The manager is deliberately independent of FastAPI.  A server route can call
``start``/``stop`` and poll ``get_packets`` from any thread.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import threading
import time
from collections import deque
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

import requests

if TYPE_CHECKING:
    from .config import AppConfig

log = logging.getLogger(__name__)

PCAP_PATH = "/pcap/all_packets.pcapng"
TSHARK_COMMAND = ("tshark", "-l", "-n", "-r", "-", "-Y", "wlan", "-T", "ek", "-x")


_KEY_CLEAN_RE = re.compile(r"[^a-z0-9]+")
_NUMBER_RE = re.compile(r"[-+]?\d+(?:\.\d+)?")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _normalise_key(value: object) -> str:
    return _KEY_CLEAN_RE.sub("_", str(value).lower()).strip("_")


def _flatten_fields(value: Any) -> dict[str, list[Any]]:
    """Flatten an EK document while retaining duplicate/suffix field names.

    Wireshark versions have emitted both nested EK fields such as
    ``layers.wlan.wlan_wlan_sa`` and flatter variants.  Indexing the full path
    *and* each raw key makes the parser tolerant of both without tying it to a
    particular tshark package shipped by Kali.
    """

    fields: dict[str, list[Any]] = {}

    def add(key: str, item: Any) -> None:
        normalised = _normalise_key(key)
        if normalised:
            fields.setdefault(normalised, []).append(item)

    def visit(item: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                key_s = str(key)
                child_path = path + (key_s,)
                if isinstance(child, (dict, list)):
                    visit(child, child_path)
                else:
                    add(key_s, child)
                    add("_".join(child_path), child)
        elif isinstance(item, list):
            # EK "raw" fields are commonly arrays whose first member is the
            # hex payload.  Keep the array as well as visiting object members.
            if path:
                add(path[-1], item)
                add("_".join(path), item)
            for child in item:
                if isinstance(child, (dict, list)):
                    visit(child, path)

    visit(value)
    return fields


def _scalar(value: Any) -> Any:
    """Return the useful scalar from Wireshark's scalar-or-array EK values."""

    if isinstance(value, list):
        if not value:
            return None
        # With -x, raw fields are [hex, offset, length, bitmask, field type].
        return _scalar(value[0])
    if isinstance(value, dict):
        for candidate in ("value", "show", "showname"):
            if candidate in value:
                return _scalar(value[candidate])
        return None
    return value


def _lookup(fields: dict[str, list[Any]], *candidates: str) -> Any:
    """Find a field by EK name, preferring exact names over path suffixes."""

    wanted = [_normalise_key(candidate) for candidate in candidates]
    for key in wanted:
        values = fields.get(key)
        if values:
            value = _scalar(values[0])
            if value not in (None, ""):
                return value

    # A nested document may prefix the layer and full path.  Require an
    # underscore boundary so a short candidate cannot match an unrelated key.
    for key in wanted:
        suffix = "_" + key
        for actual, values in fields.items():
            if actual.endswith(suffix) and values:
                value = _scalar(values[0])
                if value not in (None, ""):
                    return value
    return None


def _as_int(value: Any) -> Optional[int]:
    value = _scalar(value)
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    try:
        # Wireshark often renders enum values as 0xNN.
        hex_match = re.search(r"0x[0-9a-fA-F]+", text)
        if hex_match:
            return int(hex_match.group(0), 16)
        number = _NUMBER_RE.search(text)
        return int(float(number.group(0))) if number else None
    except (TypeError, ValueError, OverflowError):
        return None


def _as_float(value: Any) -> Optional[float]:
    value = _scalar(value)
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)):
            return float(value)
        number = _NUMBER_RE.search(str(value))
        return float(number.group(0)) if number else None
    except (TypeError, ValueError, OverflowError):
        return None


def _timestamp(value: Any) -> float:
    """Normalise EK seconds/milliseconds/microseconds/nanoseconds to epoch s."""

    value = _scalar(value)
    if value is None:
        return time.time()
    text = str(value).strip()
    # Do not mistake the year at the front of an ISO timestamp for epoch
    # seconds; only use the numeric path when the complete value is numeric.
    numeric = _as_float(value) if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", text) else None
    if numeric is not None:
        absolute = abs(numeric)
        if absolute >= 1e17:  # nanoseconds
            return numeric / 1e9
        if absolute >= 1e14:  # microseconds
            return numeric / 1e6
        if absolute >= 1e11:  # milliseconds
            return numeric / 1e3
        return numeric
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return time.time()


def _address(value: Any) -> str:
    text = str(_scalar(value) or "").strip().lower().replace("-", ":")
    return text if text not in ("none", "null") else ""


def _frequency_mhz(value: Any) -> Optional[int]:
    number = _as_float(value)
    if number is None or number <= 0:
        return None
    # Some dissectors expose Hz while radiotap normally exposes MHz.
    if number >= 1_000_000:
        number /= 1_000_000
    return int(round(number))


def _channel_from_frequency(freq: Optional[int]) -> Optional[int]:
    if freq is None:
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 5935:
        return 2
    if 5955 <= freq <= 7115:  # 6 GHz
        return (freq - 5950) // 5
    if 5000 <= freq <= 5895:  # 5 GHz (including 4.9 GHz public safety overlap)
        return (freq - 5000) // 5
    if 58320 <= freq <= 70200:  # 802.11ad/ay
        return (freq - 56160) // 2160
    return None


_MANAGEMENT_TYPES = {
    0: "Association Request",
    1: "Association Response",
    2: "Reassociation Request",
    3: "Reassociation Response",
    4: "Probe Request",
    5: "Probe Response",
    8: "Beacon",
    9: "ATIM",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
    13: "Action",
    14: "Action No Ack",
}

_CONTROL_TYPES = {
    2: "Trigger",
    7: "Control Wrapper",
    8: "Block Ack Request",
    9: "Block Ack",
    10: "PS-Poll",
    11: "RTS",
    12: "CTS",
    13: "ACK",
    14: "CF-End",
    15: "CF-End + CF-Ack",
}

_DATA_TYPES = {
    0: "Data",
    1: "Data + CF-Ack",
    2: "Data + CF-Poll",
    3: "Data + CF-Ack + CF-Poll",
    4: "Null Data",
    5: "CF-Ack",
    6: "CF-Poll",
    7: "CF-Ack + CF-Poll",
    8: "QoS Data",
    9: "QoS Data + CF-Ack",
    10: "QoS Data + CF-Poll",
    11: "QoS Data + CF-Ack + CF-Poll",
    12: "QoS Null",
    14: "QoS CF-Poll",
    15: "QoS CF-Ack + CF-Poll",
}


def _frame_type(fields: dict[str, list[Any]]) -> str:
    frame_type = _as_int(_lookup(fields, "wlan_fc_type", "wlan_wlan_fc_type"))
    subtype = _as_int(_lookup(fields, "wlan_fc_subtype", "wlan_wlan_fc_subtype"))
    combined = _as_int(
        _lookup(fields, "wlan_fc_type_subtype", "wlan_wlan_fc_type_subtype")
    )
    if combined is not None:
        # The combined display-filter field is (type << 4) | subtype.
        if frame_type is None:
            frame_type = (combined >> 4) & 0x3
        if subtype is None:
            subtype = combined & 0xF

    if frame_type == 0:
        return _MANAGEMENT_TYPES.get(subtype, "Management")
    if frame_type == 1:
        return _CONTROL_TYPES.get(subtype, "Control")
    if frame_type == 2:
        return _DATA_TYPES.get(subtype, "Data")
    if frame_type == 3:
        return "Extension"
    return "802.11"


def _protocol(fields: dict[str, list[Any]]) -> str:
    column = _lookup(
        fields,
        "_ws_col_protocol",
        "ws_col_protocol",
        "col_protocol",
    )
    if column:
        return str(column).strip()

    protocols = str(
        _lookup(fields, "frame_protocols", "frame_frame_protocols") or ""
    ).lower()
    labels = (
        ("eapol", "EAPOL"),
        ("dhcpv6", "DHCPv6"),
        ("dhcp", "DHCP"),
        ("bootp", "DHCP"),
        ("mdns", "mDNS"),
        ("dns", "DNS"),
        ("tls", "TLS"),
        ("quic", "QUIC"),
        ("tcp", "TCP"),
        ("udp", "UDP"),
        ("arp", "ARP"),
        ("icmpv6", "ICMPv6"),
        ("icmp", "ICMP"),
        ("ipv6", "IPv6"),
        ("ip", "IPv4"),
        ("llc", "LLC"),
    )
    parts = set(filter(None, re.split(r"[:,]", protocols)))
    for needle, label in labels:
        if needle in parts:
            return label
    return "802.11"


_PURPOSES = {
    "Association Request": "A client asks to join an access point.",
    "Association Response": "An access point accepts or rejects a client's join request.",
    "Reassociation Request": "A client asks to move an existing connection to this access point.",
    "Reassociation Response": "An access point answers a client's roaming request.",
    "Probe Request": "A client searches for nearby wireless networks.",
    "Probe Response": "An access point answers a client's network search.",
    "Beacon": "An access point advertises its network, capabilities, and timing.",
    "ATIM": "An ad-hoc station announces buffered data to another station.",
    "Disassociation": "One side ends the Wi-Fi association while retaining authentication state.",
    "Authentication": "A station begins or continues 802.11 authentication.",
    "Deauthentication": "One side ends 802.11 authentication and the connection.",
    "Action": "Carries a Wi-Fi management action such as roaming or radio measurement.",
    "Action No Ack": "Carries a Wi-Fi management action that does not require acknowledgement.",
    "Trigger": "Coordinates uplink transmissions from Wi-Fi 6/6E/7 clients.",
    "Block Ack Request": "Requests acknowledgement for a block of received frames.",
    "Block Ack": "Acknowledges a block of recently received frames.",
    "PS-Poll": "A power-saving client asks the access point for buffered traffic.",
    "RTS": "Reserves airtime before sending data (request to send).",
    "CTS": "Grants reserved airtime to a sender (clear to send).",
    "ACK": "Confirms successful receipt of a frame.",
    "CF-End": "Ends a contention-free transmission period.",
    "Data": "Carries user or network-layer data over Wi-Fi.",
    "Null Data": "Updates connection or power-save state without carrying user data.",
    "QoS Data": "Carries prioritised user or network-layer data.",
    "QoS Null": "Updates QoS or power-save state without carrying user data.",
    "Management": "Manages discovery, authentication, association, or roaming.",
    "Control": "Coordinates reliable use of the wireless medium.",
    "Extension": "Carries an extended 802.11 frame format.",
    "802.11": "An IEEE 802.11 wireless frame.",
}

_PROTOCOL_PURPOSES = {
    "EAPOL": "Carries WPA/WPA2/WPA3 authentication or key-exchange messages.",
    "ARP": "Maps an IPv4 address to a local network hardware address.",
    "DHCP": "Assigns or renews network configuration such as an IP address.",
    "DHCPv6": "Assigns or renews IPv6 network configuration.",
    "DNS": "Looks up a host or service name.",
    "mDNS": "Discovers names and services on the local network.",
    "ICMP": "Carries IPv4 diagnostics or error reporting, such as ping.",
    "ICMPv6": "Carries IPv6 diagnostics, errors, or neighbour discovery.",
    "TCP": "Carries a reliable, ordered application data stream.",
    "UDP": "Carries a connectionless application datagram.",
    "TLS": "Carries encrypted application traffic.",
    "QUIC": "Carries an encrypted, low-latency application connection over UDP.",
}


def _purpose(frame_type: str, protocol: str) -> str:
    return _PROTOCOL_PURPOSES.get(protocol, _PURPOSES.get(frame_type, _PURPOSES["802.11"]))


def _raw_hex(fields: dict[str, list[Any]]) -> str:
    candidates = (
        "frame_raw",
        "frame_frame_raw",
        "wlan_raw",
        "wlan_wlan_raw",
    )
    value = _lookup(fields, *candidates)
    if value is None:
        # Account for version-specific raw field names, but only select fields
        # explicitly marked raw to avoid treating an ordinary data string as a
        # full packet.
        for key, values in fields.items():
            if key.endswith("_raw") or key == "raw":
                if values:
                    value = _scalar(values[0])
                    if value is not None:
                        break
    text = str(value or "")
    compact = re.sub(r"[\s:.-]", "", text)
    if not compact or len(compact) % 2 or not _HEX_RE.fullmatch(compact):
        return ""
    return compact.lower()


def parse_ek_packet(payload: str | bytes | dict[str, Any]) -> Optional[dict[str, Any]]:
    """Parse one tshark EK document into a compact Wireshark-like record.

    Elasticsearch bulk ``index`` metadata lines return ``None``.  ``seq`` is
    assigned by :class:`SignalCaptureManager` when the packet enters its
    bounded buffer.
    """

    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    if isinstance(payload, str):
        payload = payload.strip()
        if not payload:
            return None
        try:
            document = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            return None
    elif isinstance(payload, dict):
        document = payload
    else:
        return None

    if not isinstance(document, dict) or "index" in document or "layers" not in document:
        return None

    fields = _flatten_fields(document)
    frame_type = _frame_type(fields)
    protocol = _protocol(fields)
    frequency = _frequency_mhz(
        _lookup(
            fields,
            "wlan_radio_frequency",
            "wlan_radio_wlan_radio_frequency",
            "radiotap_channel_freq",
            "radiotap_radiotap_channel_freq",
        )
    )
    channel = _as_int(
        _lookup(
            fields,
            "wlan_radio_channel",
            "wlan_radio_wlan_radio_channel",
            "wlan_channel",
            "wlan_wlan_channel",
        )
    )
    if channel is None:
        channel = _channel_from_frequency(frequency)

    ts_value = _lookup(fields, "frame_time_epoch", "frame_frame_time_epoch", "timestamp")
    src = _address(
        _lookup(fields, "wlan_sa", "wlan_wlan_sa", "wlan_ta", "wlan_wlan_ta")
    )
    dst = _address(
        _lookup(fields, "wlan_da", "wlan_wlan_da", "wlan_ra", "wlan_wlan_ra")
    )
    bssid = _address(_lookup(fields, "wlan_bssid", "wlan_wlan_bssid"))
    length = _as_int(_lookup(fields, "frame_len", "frame_frame_len")) or 0
    rssi = _as_int(
        _lookup(
            fields,
            "wlan_radio_signal_dbm",
            "wlan_radio_wlan_radio_signal_dbm",
            "radiotap_dbm_antsignal",
            "radiotap_radiotap_dbm_antsignal",
        )
    )
    info_value = _lookup(fields, "_ws_col_info", "ws_col_info", "col_info")
    info = str(info_value).strip() if info_value else ""
    if not info:
        endpoints = " -> ".join(part for part in (src, dst) if part)
        info = f"{frame_type}{': ' + endpoints if endpoints else ''}"

    return {
        "ts": _timestamp(ts_value),
        "src": src,
        "dst": dst,
        "bssid": bssid,
        "type": frame_type,
        "protocol": protocol,
        "channel": channel,
        "frequency": frequency,
        # Lowercase is the web API's canonical spelling.  Keep the requested
        # Wireshark-style uppercase alias for compatibility with older callers.
        "rssi": rssi,
        "RSSI": rssi,
        "length": length,
        "info": info,
        "purpose": _purpose(frame_type, protocol),
        "raw_hex": _raw_hex(fields),
    }


class SignalCaptureManager:
    """Thread-safe manager for Kismet's live Wi-Fi packet stream."""

    def __init__(
        self,
        cfg: AppConfig,
        max_packets: Optional[int] = None,
        reconnect_min_sec: float = 1.0,
        reconnect_max_sec: float = 10.0,
    ):
        self.cfg = cfg
        signal_cfg = getattr(cfg, "signal_analysis", None)
        if max_packets is None:
            if isinstance(signal_cfg, dict):
                max_packets = signal_cfg.get("max_packets", 5000)
            else:
                max_packets = getattr(signal_cfg, "max_packets", 5000)
        try:
            configured_capacity = int(max_packets)
        except (TypeError, ValueError):
            configured_capacity = 5000
        self.max_packets = max(1, configured_capacity)
        self.endpoint = f"{cfg.kismet.url.rstrip('/')}{PCAP_PATH}"
        self._reconnect_min_sec = max(0.05, float(reconnect_min_sec))
        self._reconnect_max_sec = max(self._reconnect_min_sec, float(reconnect_max_sec))

        self._lock = threading.RLock()
        self._packets: deque[dict[str, Any]] = deque(maxlen=self.max_packets)
        self._next_seq = 1
        self._packets_total = 0
        self._parse_errors = 0

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._process: Optional[subprocess.Popen] = None
        self._response: Optional[requests.Response] = None
        self._session: Optional[requests.Session] = None

        self._state = "stopped"
        self._last_error = ""
        self._tshark_stderr: deque[str] = deque(maxlen=30)
        self._kismet_reachable: Optional[bool] = None
        self._kismet_error = ""
        self._last_probe_ts = 0.0
        self._last_packet_ts: Optional[float] = None
        self._started_ts: Optional[float] = None
        self._reconnect_count = 0

    def _new_session(self) -> requests.Session:
        session = requests.Session()
        if self.cfg.kismet.apikey:
            session.headers["KISMET"] = self.cfg.kismet.apikey
        elif self.cfg.kismet.username:
            session.auth = (self.cfg.kismet.username, self.cfg.kismet.password)
        return session

    def _configured_tshark(self) -> str:
        signal_cfg = getattr(self.cfg, "signal_analysis", None)
        if isinstance(signal_cfg, dict):
            configured_value = signal_cfg.get("tshark_path", "")
        else:
            configured_value = getattr(signal_cfg, "tshark_path", "")
        configured = str(configured_value or "").strip()
        return configured or TSHARK_COMMAND[0]

    def _resolve_tshark(self) -> Optional[str]:
        """Resolve the configured binary name or absolute path if executable."""

        return shutil.which(self._configured_tshark())

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(self._thread and self._thread.is_alive() and not self._stop_event.is_set())

    def _probe_kismet(self, timeout: float = 2.0) -> bool:
        session = self._new_session()
        try:
            response = session.get(
                f"{self.cfg.kismet.url.rstrip('/')}/system/status.json",
                timeout=timeout,
            )
            response.raise_for_status()
            reachable = True
            error = ""
        except requests.RequestException as exc:
            reachable = False
            error = str(exc)
        finally:
            session.close()
        with self._lock:
            self._kismet_reachable = reachable
            self._kismet_error = error
            self._last_probe_ts = time.time()
        return reachable

    def get_status(self, refresh: bool = True) -> dict[str, Any]:
        """Return dependency, connection, buffer, and error state.

        When capture is stopped, the Kismet reachability check is cached for
        two seconds so a UI may poll this method frequently without causing a
        new HTTP request for every browser poll.
        """

        tshark_path = self._resolve_tshark()
        configured_tshark = self._configured_tshark()
        with self._lock:
            active = bool(self._thread and self._thread.is_alive())
            stale_probe = time.time() - self._last_probe_ts >= 2.0
        if refresh and not active and stale_probe:
            self._probe_kismet()

        with self._lock:
            running = bool(
                self._thread and self._thread.is_alive() and not self._stop_event.is_set()
            )
            return {
                "available": bool(tshark_path and self._kismet_reachable),
                "tshark_available": bool(tshark_path),
                "executable_available": bool(tshark_path),
                "tshark_path": tshark_path or configured_tshark,
                "kismet_reachable": bool(self._kismet_reachable),
                "reachable": bool(self._kismet_reachable),
                "kismet_error": self._kismet_error,
                "running": running,
                "state": self._state,
                "packet_count": len(self._packets),
                "packets_total": self._packets_total,
                "buffer_capacity": self.max_packets,
                "oldest_seq": self._packets[0]["seq"] if self._packets else None,
                "latest_seq": self._packets[-1]["seq"] if self._packets else None,
                "last_packet_ts": self._last_packet_ts,
                "started_ts": self._started_ts,
                "reconnect_count": self._reconnect_count,
                "parse_errors": self._parse_errors,
                "last_error": self._last_error,
                "error": self._last_error,
                "tshark_stderr": "\n".join(self._tshark_stderr),
                "endpoint": self.endpoint,
            }

    # Convenient spelling for route code and interactive use.
    def status(self, refresh: bool = True) -> dict[str, Any]:
        return self.get_status(refresh=refresh)

    def start(self) -> tuple[bool, str]:
        """Start the background stream.  Safe and idempotent across threads."""

        tshark_path = self._resolve_tshark()
        with self._lock:
            if self._thread and self._thread.is_alive():
                if self._stop_event.is_set():
                    return False, "Signal capture is still stopping."
                return True, "Signal capture is already running."
            if not tshark_path:
                self._state = "error"
                configured = self._configured_tshark()
                if configured != TSHARK_COMMAND[0]:
                    self._last_error = f"Configured tshark executable was not found: {configured}"
                else:
                    self._last_error = (
                        "'tshark' isn't on PATH. Install it with: sudo apt install tshark"
                    )
                return False, self._last_error

            self._stop_event = threading.Event()
            self._state = "connecting"
            self._last_error = ""
            self._tshark_stderr.clear()
            self._started_ts = time.time()
            self._reconnect_count = 0
            self._thread = threading.Thread(
                target=self._worker,
                name="wirelessboss-signal-capture",
                daemon=True,
            )
            self._thread.start()
        return True, "Signal capture starting..."

    def stop(self, timeout_sec: float = 6.0) -> tuple[bool, str]:
        """Stop HTTP streaming and tshark, closing every pipe deterministically."""

        with self._lock:
            thread = self._thread
            if not thread or not thread.is_alive():
                self._thread = None
                self._state = "stopped"
                return True, "Signal capture is already stopped."
            self._state = "stopping"
            self._stop_event.set()
            response = self._response
            session = self._session
            process = self._process

        # Closing the socket and process outside the state lock unblocks both
        # requests.iter_content and tshark pipe I/O without deadlocking readers.
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
        self._terminate_process(process)

        if thread is not threading.current_thread():
            thread.join(max(0.1, timeout_sec))
        with self._lock:
            if thread.is_alive():
                return False, (
                    "Signal capture is still stopping; its network read will time out shortly."
                )
            if self._thread is thread:
                self._thread = None
            self._state = "stopped"
        return True, "Signal capture stopped."

    def clear(self) -> int:
        """Clear the in-memory display buffer and return the number removed.

        Sequence numbers intentionally remain monotonic so clients holding an
        ``after`` cursor cannot become stuck after a clear.
        """

        with self._lock:
            removed = len(self._packets)
            self._packets.clear()
            return removed

    def get_packets(
        self,
        after: Optional[int] = None,
        address: Optional[str] = None,
        channel: Optional[int | str] = None,
        type: Optional[str] = None,
        limit: int = 500,
        packet_type: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return buffered packets, optionally filtered for incremental polling.

        ``after`` is an exclusive sequence cursor.  Without a cursor the newest
        ``limit`` matching packets are returned; with a cursor the oldest next
        page is returned so callers cannot skip a backlog.
        """

        try:
            after_seq = int(after) if after is not None else None
        except (TypeError, ValueError):
            after_seq = None
        try:
            result_limit = max(1, min(int(limit), self.max_packets))
        except (TypeError, ValueError):
            result_limit = min(500, self.max_packets)
        address_filter = str(address or "").strip().lower().replace("-", ":")
        channel_filter = str(channel).strip().lower() if channel not in (None, "") else ""
        type_filter = str(packet_type if packet_type is not None else (type or "")).strip().lower()

        with self._lock:
            snapshot = list(self._packets)

        matches: list[dict[str, Any]] = []
        for packet in snapshot:
            if after_seq is not None and packet["seq"] <= after_seq:
                continue
            if address_filter and address_filter not in (
                str(packet.get("src") or "").lower(),
                str(packet.get("dst") or "").lower(),
                str(packet.get("bssid") or "").lower(),
            ):
                continue
            if channel_filter and str(packet.get("channel") or "").lower() != channel_filter:
                continue
            if type_filter:
                packet_labels = {
                    str(packet.get("type") or "").lower(),
                    str(packet.get("protocol") or "").lower(),
                }
                if type_filter not in packet_labels:
                    continue
            matches.append(dict(packet))

        if after_seq is None and len(matches) > result_limit:
            return matches[-result_limit:]
        return matches[:result_limit]

    def _record_packet(self, packet: dict[str, Any]) -> None:
        with self._lock:
            record = dict(packet)
            record["seq"] = self._next_seq
            self._next_seq += 1
            self._packets_total += 1
            self._last_packet_ts = record["ts"]
            self._packets.append(record)

    def _parse_stdout(self, process: subprocess.Popen) -> None:
        stdout = process.stdout
        if stdout is None:
            return
        try:
            for line in iter(stdout.readline, b""):
                if self._stop_event.is_set() and not line:
                    break
                packet = parse_ek_packet(line)
                if packet is not None:
                    self._record_packet(packet)
                elif line.strip() and not self._is_ek_index_line(line):
                    with self._lock:
                        self._parse_errors += 1
        except (OSError, ValueError):
            if not self._stop_event.is_set():
                log.debug("tshark stdout reader ended unexpectedly", exc_info=True)

    @staticmethod
    def _is_ek_index_line(line: bytes) -> bool:
        try:
            value = json.loads(line)
            return isinstance(value, dict) and "index" in value
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            return False

    def _read_stderr(self, process: subprocess.Popen) -> None:
        stderr = process.stderr
        if stderr is None:
            return
        try:
            for line in iter(stderr.readline, b""):
                text = line.decode("utf-8", errors="replace").strip()
                if text:
                    with self._lock:
                        self._tshark_stderr.append(text)
        except (OSError, ValueError):
            pass

    @staticmethod
    def _terminate_process(process: Optional[subprocess.Popen]) -> None:
        if process is None:
            return
        if process.stdin is not None:
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass
        if process.poll() is None:
            try:
                # EOF normally lets tshark finish dissecting bytes already in
                # its pipe.  Give it a short drain window before signalling it
                # so a Kismet reconnect does not discard the final packet.
                process.wait(timeout=0.75)
            except subprocess.TimeoutExpired:
                try:
                    process.terminate()
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                        process.wait(timeout=1.0)
                    except (OSError, subprocess.SubprocessError):
                        pass
                except OSError:
                    pass
            except OSError:
                pass

    def _worker(self) -> None:
        delay = self._reconnect_min_sec
        while not self._stop_event.is_set():
            try:
                self._capture_once()
                if not self._stop_event.is_set():
                    raise RuntimeError("Kismet's live packet stream ended.")
            except Exception as exc:
                if self._stop_event.is_set():
                    break
                message = str(exc).strip() or exc.__class__.__name__
                with self._lock:
                    had_live_stream = self._state == "capturing"
                    self._last_error = message
                    self._state = "reconnecting"
                    self._reconnect_count += 1
                    if isinstance(exc, requests.RequestException):
                        self._kismet_reachable = False
                        self._kismet_error = message
                        self._last_probe_ts = time.time()
                if had_live_stream:
                    # A healthy connection may last hours. Do not carry an old
                    # pre-connection exponential delay into its eventual retry.
                    delay = self._reconnect_min_sec
                log.warning("Signal capture interrupted; reconnecting: %s", message)
                if self._stop_event.wait(delay):
                    break
                delay = min(self._reconnect_max_sec, delay * 2)
                continue
            delay = self._reconnect_min_sec

        with self._lock:
            self._state = "stopped"
            self._process = None
            self._response = None
            self._session = None

    def _capture_once(self) -> None:
        session = self._new_session()
        response: Optional[requests.Response] = None
        process: Optional[subprocess.Popen] = None
        stdout_thread: Optional[threading.Thread] = None
        stderr_thread: Optional[threading.Thread] = None
        feeder_thread: Optional[threading.Thread] = None
        with self._lock:
            self._session = session
            self._state = "connecting"

        try:
            response = session.get(
                self.endpoint,
                stream=True,
                timeout=(5.0, 30.0),
                headers={
                    "Accept": "application/octet-stream",
                    "Accept-Encoding": "identity",
                },
            )
            response.raise_for_status()
            if self._stop_event.is_set():
                return

            tshark_path = self._resolve_tshark()
            if not tshark_path:
                raise FileNotFoundError(
                    f"Configured tshark executable was not found: {self._configured_tshark()}"
                )
            process = subprocess.Popen(
                [tshark_path, *TSHARK_COMMAND[1:]],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
            with self._lock:
                self._response = response
                self._process = process
                self._kismet_reachable = True
                self._kismet_error = ""
                self._last_probe_ts = time.time()
                self._last_error = ""
                self._state = "capturing"

            stdout_thread = threading.Thread(
                target=self._parse_stdout,
                args=(process,),
                name="wirelessboss-tshark-output",
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=self._read_stderr,
                args=(process,),
                name="wirelessboss-tshark-errors",
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()

            assert process.stdin is not None
            feeder_done = threading.Event()
            feeder_errors: list[Exception] = []

            def feed_tshark() -> None:
                try:
                    for chunk in response.iter_content(chunk_size=64 * 1024):
                        if self._stop_event.is_set():
                            break
                        if not chunk:
                            continue
                        if process.poll() is not None:
                            raise BrokenPipeError(
                                f"tshark exited with code {process.returncode}"
                            )
                        process.stdin.write(chunk)
                except Exception as exc:
                    if not self._stop_event.is_set():
                        feeder_errors.append(exc)
                finally:
                    try:
                        process.stdin.close()
                    except (OSError, ValueError):
                        pass
                    feeder_done.set()

            feeder_thread = threading.Thread(
                target=feed_tshark,
                name="wirelessboss-kismet-pcap-stream",
                daemon=True,
            )
            feeder_thread.start()

            # Polling the child independently of the HTTP reader means a
            # crashed tshark is noticed immediately even when Kismet's stream
            # is currently quiet and iter_content is blocked awaiting bytes.
            while not self._stop_event.is_set():
                return_code = process.poll()
                if return_code is not None:
                    if feeder_errors:
                        exc = feeder_errors[0]
                        if isinstance(exc, requests.RequestException):
                            raise exc
                    detail = "\n".join(self._tshark_stderr) or f"exit code {return_code}"
                    if feeder_done.is_set() and return_code == 0:
                        raise RuntimeError("Kismet's live packet stream ended.")
                    raise RuntimeError(f"tshark stopped unexpectedly: {detail}")
                if feeder_done.wait(0.2):
                    if feeder_errors:
                        exc = feeder_errors[0]
                        if isinstance(exc, requests.RequestException):
                            raise exc
                        raise RuntimeError(f"Kismet packet stream failed: {exc}") from exc
                    raise RuntimeError("Kismet's live packet stream ended.")
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            self._terminate_process(process)
            if feeder_thread and feeder_thread is not threading.current_thread():
                feeder_thread.join(timeout=2.0)
            if stdout_thread and stdout_thread is not threading.current_thread():
                stdout_thread.join(timeout=2.0)
            if stderr_thread and stderr_thread is not threading.current_thread():
                stderr_thread.join(timeout=2.0)
            session.close()
            with self._lock:
                if self._response is response:
                    self._response = None
                if self._process is process:
                    self._process = None
                if self._session is session:
                    self._session = None


__all__ = ["SignalCaptureManager", "parse_ek_packet", "PCAP_PATH", "TSHARK_COMMAND"]
