"""Thread-safe process manager for the WCH BLE Analyzer Pro Linux driver."""
from __future__ import annotations

from collections import Counter, OrderedDict, deque
from collections.abc import Mapping
import copy
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import threading
import time
from typing import Any

from ..models import BleDevice
from .parser import parse_wch_packet
from .provider import BleDeviceCallback, BleProvider


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLED_DRIVER = PROJECT_ROOT / "BLE-Analyzer-pro-linux-capture-main" / "wch_capture"
DRIVER_CAPABILITY_MARKER = "wirelessboss-native-follow-v1"
VALID_ADV_CHANNELS = (0, 37, 38, 39)
VALID_PHY_ARGUMENTS = ("1", "2", "S8", "S2")
START_READY_TIMEOUT_SECONDS = 8.0
READER_JOIN_TIMEOUT_SECONDS = 1.0


@lru_cache(maxsize=16)
def _probe_driver_capabilities(path: str, mtime_ns: int, size: int) -> bool:
    """Reject the stale pre-rebuild ELF shipped with the original driver.

    The cache key includes file identity metadata, so rebuilding in place
    automatically invalidates the result without spawning a process on every
    two-second status poll.
    """
    del mtime_ns, size
    try:
        result = subprocess.run(
            [path, "-V"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=2.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and DRIVER_CAPABILITY_MARKER in result.stdout


def discover_wch_driver(configured_path: str | os.PathLike[str] | None = None) -> Path | None:
    """Find an executable ``wch_capture`` without invoking a shell."""
    candidates: list[Path] = []
    if configured_path:
        candidates.append(Path(configured_path).expanduser())
    # The Kali updater rebuilds the bundled source in place. Prefer that
    # compatible binary over a potentially older /usr/local installation.
    candidates.append(BUNDLED_DRIVER)
    installed = shutil.which("wch_capture")
    if installed:
        candidates.append(Path(installed))

    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                resolved = candidate.resolve()
                stat = resolved.stat()
                if _probe_driver_capabilities(
                    str(resolved), stat.st_mtime_ns, stat.st_size
                ):
                    return resolved
        except OSError:
            continue
    return None


def _normalise_address(address: Any) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", str(address or ""))
    if len(compact) == 12:
        return ":".join(compact[i : i + 2] for i in range(0, 12, 2)).upper()
    return str(address or "").strip().upper()


def _normalise_phy(phy: Any) -> str | None:
    if isinstance(phy, bool):
        return None
    value = str(phy).strip().upper().replace(" ", "")
    aliases = {
        "1": "1",
        "1M": "1",
        "LE1M": "1",
        "2": "2",
        "2M": "2",
        "LE2M": "2",
        "S8": "S8",
        "CODED-S8": "S8",
        "LECODEDS=8": "S8",
        "S2": "S2",
        "CODED-S2": "S2",
        "LECODEDS=2": "S2",
    }
    return aliases.get(value)


def _normalise_filter_address(address: Any) -> str | None:
    if address is None or str(address).strip() == "":
        return ""
    compact = re.sub(r"[^0-9A-Fa-f]", "", str(address))
    if len(compact) != 12:
        return None
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2)).upper()


def _normalise_ltk(ltk: Any) -> str | None:
    if ltk is None or str(ltk).strip() == "":
        return ""
    compact = re.sub(r"[\s:_-]", "", str(ltk).strip())
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if len(compact) != 32 or any(char not in "0123456789abcdefABCDEF" for char in compact):
        return None
    return compact.upper()


def _count_usb_mcus() -> int:
    """Count WCH 1a86:8009 functions from Linux sysfs (zero elsewhere)."""
    root = Path("/sys/bus/usb/devices")
    try:
        devices = list(root.iterdir())
    except OSError:
        return 0
    count = 0
    for device in devices:
        try:
            vendor = (device / "idVendor").read_text().strip().lower()
            product = (device / "idProduct").read_text().strip().lower()
        except OSError:
            continue
        if vendor == "1a86" and product == "8009":
            count += 1
    return count


def _rssi_trend(history: list[dict[str, Any]]) -> str:
    """Return a deliberately coarse direction signal, resistant to BLE noise."""
    values = [sample.get("rssi") for sample in history[-12:]]
    values = [float(value) for value in values if isinstance(value, (int, float))]
    if len(values) < 4:
        return "unknown"
    split = len(values) // 2
    delta = sum(values[split:]) / len(values[split:]) - sum(values[:split]) / split
    if delta >= 3.0:
        return "closer"
    if delta <= -3.0:
        return "away"
    return "steady"


class WchBleManager(BleProvider):
    """Own ``wch_capture`` and maintain bounded BLE UI snapshots.

    ``channel=0`` is the normal mode: the driver assigns channels 37, 38 and
    39 across the analyzer's three MCUs.  Passing 37, 38 or 39 pins every MCU
    to that one primary advertising channel.  After a matching CONNECT_IND,
    each radio's firmware follows the connection on data channels 0-36.
    """

    def __init__(
        self,
        driver_path: str | os.PathLike[str] | None = None,
        capture_dir: str | os.PathLike[str] | None = None,
        max_packets: int = 5_000,
        max_rssi_samples: int = 300,
        max_devices: int = 2_048,
    ) -> None:
        self._configured_driver = str(driver_path or "")
        self._capture_dir = Path(capture_dir or PROJECT_ROOT).expanduser()
        self._max_packets = max(1, int(max_packets))
        self._max_rssi_samples = max(1, int(max_rssi_samples))
        self._max_devices = max(1, int(max_devices))

        # Serialize whole start/stop transitions.  The state lock alone cannot
        # protect the gap between checking the current process and spawning a
        # replacement, because Popen and the startup handshake happen outside
        # short snapshot critical sections.
        self._lifecycle_lock = threading.RLock()
        self._lock = threading.RLock()
        self._process: subprocess.Popen[str] | None = None
        self._reader_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._wait_thread: threading.Thread | None = None
        self._callback: BleDeviceCallback | None = None
        self._packets: deque[dict[str, Any]] = deque(maxlen=self._max_packets)
        self._devices: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._stderr_lines: deque[str] = deque(maxlen=100)
        self._sequence = 0
        self._packet_count = 0
        self._channel_counts: Counter[int] = Counter()
        self._packet_type_counts: Counter[str] = Counter()
        self._link_layer_counts: Counter[str] = Counter()
        self._connection_access_addresses: set[str] = set()
        self._connections_announced = 0
        self._encrypted_packets = 0
        self._decrypted_packets = 0
        self._mic_valid_packets = 0
        self._mic_failed_packets = 0
        self._retransmissions = 0
        self._dropped_packets = 0
        self._parse_errors = 0
        self._started_at: float | None = None
        self._stopped_at: float | None = None
        self._capture_file = ""
        self._driver_used = ""
        self._error = ""
        self._exit_code: int | None = None
        self._pid: int | None = None
        self._channel = 0
        self._phy = "1"
        self._initiator_filter = ""
        self._advertiser_filter = ""
        self._ltk_configured = False
        self._usb_mcu_count = 0
        self._active_mcu_count: int | None = None
        self._stop_requested = False

    @property
    def display_name(self) -> str:
        return "WCH BLE Analyzer Pro"

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._process is not None and self._process.poll() is None

    @property
    def capture_file(self) -> str:
        with self._lock:
            return self._capture_file

    @property
    def driver_path(self) -> str:
        driver = discover_wch_driver(self._configured_driver)
        return str(driver) if driver else ""

    def start(
        self,
        on_device: BleDeviceCallback | int | None = None,
        channel: int = 0,
        phy: str | int = "1",
        initiator: str = "",
        advertiser: str = "",
        ltk: str = "",
    ) -> tuple[bool, str]:
        """Start a PCAP + JSON-lines capture.

        ``on_device`` is optional for the web manager, but keeps compatibility
        with the original :class:`BleProvider` callback interface.  For older
        callers, ``start(37)`` is accepted as shorthand for ``channel=37``.
        Filters are conventional display-order MAC addresses; ``ltk`` is an
        optional 16-byte key represented by 32 hexadecimal digits.
        """
        with self._lifecycle_lock:
            return self._start_serialized(
                on_device=on_device,
                channel=channel,
                phy=phy,
                initiator=initiator,
                advertiser=advertiser,
                ltk=ltk,
            )

    def _start_serialized(
        self,
        on_device: BleDeviceCallback | int | None = None,
        channel: int = 0,
        phy: str | int = "1",
        initiator: str = "",
        advertiser: str = "",
        ltk: str = "",
    ) -> tuple[bool, str]:
        if isinstance(on_device, int) and not isinstance(on_device, bool):
            if channel != 0:
                return False, "Channel was supplied twice."
            channel = on_device
            on_device = None
        try:
            channel = int(channel)
        except (TypeError, ValueError):
            return False, "Channel must be 0, 37, 38, or 39."
        if channel not in VALID_ADV_CHANNELS:
            return False, "BLE advertising channel must be 0 (all), 37, 38, or 39."
        phy_argument = _normalise_phy(phy)
        if phy_argument is None:
            return False, "BLE PHY must be 1, 2, S8, or S2."
        initiator_filter = _normalise_filter_address(initiator)
        if initiator_filter is None:
            return False, "Initiator MAC must contain exactly 12 hexadecimal digits."
        advertiser_filter = _normalise_filter_address(advertiser)
        if advertiser_filter is None:
            return False, "Advertiser MAC must contain exactly 12 hexadecimal digits."
        ltk_argument = _normalise_ltk(ltk)
        if ltk_argument is None:
            return False, "LTK must contain exactly 32 hexadecimal digits (16 bytes)."

        driver = discover_wch_driver(self._configured_driver)
        if driver is None:
            with self._lock:
                self._error = (
                    "A compatible native-follow wch_capture was not found. Rebuild the "
                    "bundled driver on Kali with setup/install_ble_analyzer.sh."
                )
            return False, self._error

        with self._lock:
            if self._process is not None and self._process.poll() is None:
                return False, "BLE capture is already running."

        try:
            self._capture_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            with self._lock:
                self._error = f"Cannot create BLE capture directory: {exc}"
            return False, self._error

        stamp = time.strftime("%Y%m%d-%H%M%S")
        suffix = time.time_ns() % 1_000_000_000
        capture_path = self._capture_dir / f"wirelessboss-ble-{stamp}-{suffix:09d}.pcap"
        args = [
            str(driver),
            "-J",
            "-w",
            str(capture_path),
            "-p",
            phy_argument,
            "-c",
            str(channel),
        ]
        if initiator_filter:
            args.extend(["-i", initiator_filter])
        if advertiser_filter:
            args.extend(["-a", advertiser_filter])
        if ltk_argument:
            args.extend(["-k", ltk_argument])

        try:
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            with self._lock:
                self._error = f"Could not start wch_capture: {exc}"
            return False, self._error

        with self._lock:
            self._process = process
            self._callback = on_device if callable(on_device) else None
            self._started_at = time.time()
            self._stopped_at = None
            self._capture_file = str(capture_path)
            self._driver_used = str(driver)
            self._error = ""
            self._exit_code = None
            self._pid = process.pid
            self._channel = channel
            self._phy = phy_argument
            self._initiator_filter = initiator_filter
            self._advertiser_filter = advertiser_filter
            self._ltk_configured = bool(ltk_argument)
            self._usb_mcu_count = _count_usb_mcus()
            self._active_mcu_count = None
            self._stop_requested = False
            self._stderr_lines.clear()

        ready_event = threading.Event()
        reader_thread = threading.Thread(
            target=self._read_stdout, args=(process,), name="wch-ble-json", daemon=True
        )
        stderr_thread = threading.Thread(
            target=self._read_stderr,
            args=(process, ready_event),
            name="wch-ble-stderr",
            daemon=True,
        )
        wait_thread = threading.Thread(
            target=self._wait_for_exit,
            args=(process, ready_event, reader_thread, stderr_thread),
            name="wch-ble-wait",
            daemon=True,
        )
        with self._lock:
            self._reader_thread = reader_thread
            self._stderr_thread = stderr_thread
            self._wait_thread = wait_thread
        reader_thread.start()
        stderr_thread.start()
        wait_thread.start()

        if not ready_event.wait(START_READY_TIMEOUT_SECONDS):
            with self._lock:
                if self._process is process:
                    self._error = (
                        "Timed out waiting for an analyzer radio to confirm capture startup."
                    )
                message = self._error
            stopped, _flushed, stop_error = self._stop_process(process)
            if not stopped:
                with self._lock:
                    self._error = f"{message} {stop_error}".strip()
                    message = self._error
            wait_thread.join(READER_JOIN_TIMEOUT_SECONDS)
            return False, message

        with self._lock:
            running = self._process is process and process.poll() is None
            active_mcu_count = self._active_mcu_count if running else 0
            if not running or not active_mcu_count:
                if not self._error:
                    self._error = (
                        "wch_capture exited before any analyzer radio confirmed startup."
                    )
                message = self._error

        if not running or not active_mcu_count:
            if running:
                self._stop_process(process)
            wait_thread.join(READER_JOIN_TIMEOUT_SECONDS)
            return False, message

        mode = "channels 37, 38 and 39" if channel == 0 else f"channel {channel}"
        return True, (
            f"BLE capture started on {mode} using PHY {phy_argument}; "
            f"CONNECT_IND packets are followed across data channels 0-36; "
            f"PCAP: {capture_path.name}"
        )

    def stop(self) -> tuple[bool, str]:
        """Ask the CLI to flush and exit, escalating only if it is stuck."""
        with self._lifecycle_lock:
            return self._stop_serialized()

    def _stop_serialized(self) -> tuple[bool, str]:
        with self._lock:
            process = self._process
            wait_thread = self._wait_thread
            self._stop_requested = True
        if process is None or process.poll() is not None:
            return True, "BLE capture is already stopped."

        ok, flushed, error = self._stop_process(process)
        if wait_thread is not None and wait_thread is not threading.current_thread():
            wait_thread.join(READER_JOIN_TIMEOUT_SECONDS)
        if not ok:
            with self._lock:
                self._error = error
            return False, self._error
        if flushed:
            return True, "BLE capture stopped; the PCAP file was flushed."
        return True, "BLE capture was killed; the PCAP file may not have been flushed."

    @staticmethod
    def _stop_process(process: subprocess.Popen[str]) -> tuple[bool, bool, str]:
        """Stop one known process and report whether graceful PCAP cleanup ran."""
        if process.poll() is not None:
            return True, True, ""
        try:
            process.send_signal(signal.SIGINT)
        except OSError as exc:
            return False, False, f"Could not signal wch_capture: {exc}"
        try:
            process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            pass
        else:
            return True, True, ""

        try:
            process.terminate()
        except OSError as exc:
            return False, False, f"Could not terminate wch_capture: {exc}"
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass
        else:
            # SIGTERM is handled by the CLI and takes the same cleanup path as
            # SIGINT, so its PCAP footer/buffers are still flushed.
            return True, True, ""

        try:
            process.kill()
            process.wait(timeout=2.0)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, False, f"Could not kill wch_capture: {exc}"
        return True, False, ""

    pause = stop

    def _read_stdout(self, process: subprocess.Popen[str]) -> None:
        stream = process.stdout
        if stream is None:
            return
        for line in stream:
            with self._lock:
                if self._process is not process:
                    return
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, TypeError) as exc:
                with self._lock:
                    if self._process is not process:
                        return
                    self._parse_errors += 1
                    self._error = f"Invalid JSON from wch_capture: {exc}"
                continue
            self._ingest_record(record, expected_process=process)

    def _read_stderr(
        self,
        process: subprocess.Popen[str],
        ready_event: threading.Event | None = None,
    ) -> None:
        stream = process.stderr
        if stream is None:
            return
        found_pattern = re.compile(r"Found\s+(\d+)\s+MCU", re.IGNORECASE)
        started_pattern = re.compile(r"Started\s+(\d+)\s+MCU", re.IGNORECASE)
        active_pattern = re.compile(r"Active\s+(\d+)\s+MCU", re.IGNORECASE)
        for line in stream:
            line = line.rstrip("\r\n")
            if not line:
                continue
            confirmed_ready = False
            with self._lock:
                if self._process is not process:
                    return
                self._stderr_lines.append(line)
                found = found_pattern.search(line)
                if found:
                    self._usb_mcu_count = int(found.group(1))
                started = started_pattern.search(line)
                if started:
                    self._active_mcu_count = int(started.group(1))
                    confirmed_ready = self._active_mcu_count > 0
                active = active_pattern.search(line)
                if active:
                    self._active_mcu_count = int(active.group(1))
                lower = line.lower()
                if (
                    "no wch ble analyzer" in lower
                    or "could not open any device" in lower
                    or "libusb_init:" in lower
                    or "read error" in lower
                    or "analyzer disconnected" in lower
                    or "start_capture" in lower
                    or "no analyzer radio" in lower
                ):
                    self._error = line
            if confirmed_ready and ready_event is not None:
                ready_event.set()

    def _wait_for_exit(
        self,
        process: subprocess.Popen[str],
        ready_event: threading.Event | None = None,
        reader_thread: threading.Thread | None = None,
        stderr_thread: threading.Thread | None = None,
    ) -> None:
        exit_code = process.wait()
        for thread in (reader_thread, stderr_thread):
            if thread is not None and thread is not threading.current_thread():
                thread.join(READER_JOIN_TIMEOUT_SECONDS)
        with self._lock:
            if self._process is process:
                self._process = None
                self._stopped_at = time.time()
                self._exit_code = exit_code
                if exit_code != 0 and not self._stop_requested and not self._error:
                    self._error = f"wch_capture exited unexpectedly with status {exit_code}."
        if ready_event is not None:
            ready_event.set()

    def ingest_record(self, record: Mapping[str, Any]) -> dict[str, Any]:
        """Decode and store a record; public to support replay/testing."""
        packet = self._ingest_record(record)
        assert packet is not None
        return packet

    def _ingest_record(
        self,
        record: Mapping[str, Any],
        expected_process: subprocess.Popen[str] | None = None,
    ) -> dict[str, Any] | None:
        packet = parse_wch_packet(record)
        callback: BleDeviceCallback | None
        callback_device: BleDevice | None = None
        now = packet.get("host_timestamp")
        if not isinstance(now, (int, float)):
            now = time.time()
            packet["host_timestamp"] = now
        packet["ts"] = now

        with self._lock:
            if expected_process is not None and self._process is not expected_process:
                return None
            self._sequence += 1
            packet["seq"] = self._sequence
            if len(self._packets) == self._packets.maxlen:
                self._dropped_packets += 1
            self._packets.append(packet)
            self._packet_count += 1
            if isinstance(packet.get("channel"), int):
                self._channel_counts[packet["channel"]] += 1
            self._packet_type_counts[str(packet.get("type_name") or "UNKNOWN")] += 1
            link_layer = str(packet.get("link_layer") or "unknown")
            self._link_layer_counts[link_layer] += 1
            if link_layer == "data":
                access_address = str(packet.get("access_address") or "")
                if access_address:
                    self._connection_access_addresses.add(access_address)
            if packet.get("type_name") == "CONNECT_IND":
                self._connections_announced += 1
            if packet.get("encrypted"):
                self._encrypted_packets += 1
            if packet.get("decrypted"):
                self._decrypted_packets += 1
            if packet.get("mic_valid") is True:
                self._mic_valid_packets += 1
            if packet.get("mic_checked") and packet.get("mic_valid") is False:
                self._mic_failed_packets += 1
            if packet.get("retransmission"):
                self._retransmissions += 1
            if packet.get("malformed"):
                self._parse_errors += 1

            address = _normalise_address(packet.get("src"))
            if address and address != "00:00:00:00:00:00":
                device = self._devices.get(address)
                if device is None:
                    if len(self._devices) >= self._max_devices:
                        self._devices.popitem(last=False)
                    device = {
                        "address": address,
                        "name": "",
                        "address_type": packet.get("address_type") or "",
                        "address_subtype": packet.get("address_subtype") or "",
                        "manufacturer": "",
                        "rssi": None,
                        "channels_seen": set(),
                        "packets": 0,
                        "data_packets": 0,
                        "decrypted_packets": 0,
                        "connection_active": False,
                        "data_channels_seen": set(),
                        "connection_access_addresses": set(),
                        "last_seen": now,
                        "rssi_history": deque(maxlen=self._max_rssi_samples),
                        "packet_types": Counter(),
                        "services": set(),
                        "connectable": False,
                        "scannable": False,
                    }
                    self._devices[address] = device
                else:
                    self._devices.move_to_end(address)

                if packet.get("name"):
                    device["name"] = packet["name"]
                if packet.get("manufacturer"):
                    device["manufacturer"] = packet["manufacturer"]
                if packet.get("address_type"):
                    device["address_type"] = packet["address_type"]
                if packet.get("address_subtype"):
                    device["address_subtype"] = packet["address_subtype"]
                device["services"].update(packet.get("services") or [])
                device["packets"] += 1
                if packet.get("link_layer") == "data":
                    device["data_packets"] += 1
                    device["connection_active"] = True
                    if isinstance(packet.get("channel"), int):
                        device["data_channels_seen"].add(packet["channel"])
                    if packet.get("access_address"):
                        device["connection_access_addresses"].add(
                            packet["access_address"]
                        )
                if packet.get("decrypted"):
                    device["decrypted_packets"] += 1
                device["last_seen"] = now
                device["connectable"] = bool(
                    device["connectable"] or packet.get("connectable")
                )
                device["scannable"] = bool(
                    device["scannable"] or packet.get("scannable")
                )
                packet_name = str(packet.get("type_name") or "UNKNOWN")
                device["packet_types"][packet_name] += 1
                channel = packet.get("channel")
                if isinstance(channel, int):
                    device["channels_seen"].add(channel)
                rssi = packet.get("rssi")
                if isinstance(rssi, int):
                    device["rssi"] = rssi
                    device["rssi_history"].append(
                        {"timestamp": now, "rssi": rssi, "channel": channel}
                    )

                snapshot = self._device_snapshot(device)
                callback_device = BleDevice(
                    address=address,
                    name=snapshot["name"],
                    rssi=snapshot["rssi"],
                    address_type=snapshot["address_type"],
                    manuf=snapshot["manufacturer"],
                    services=snapshot["services"],
                    last_seen=snapshot["last_seen"],
                    raw=snapshot,
                )
            callback = self._callback

        if callback is not None and callback_device is not None:
            try:
                callback(callback_device)
            except Exception:
                # A GUI callback must never kill the capture reader.
                pass
        return copy.deepcopy(packet)

    def _device_snapshot(self, device: Mapping[str, Any]) -> dict[str, Any]:
        history = [dict(sample) for sample in device["rssi_history"]]
        return {
            "address": device["address"],
            "name": device["name"],
            "address_type": device["address_type"],
            "address_subtype": device["address_subtype"],
            "manufacturer": device["manufacturer"],
            "rssi": device["rssi"],
            "trend": _rssi_trend(history),
            "channels_seen": sorted(device["channels_seen"]),
            "packets": device["packets"],
            "data_packets": device["data_packets"],
            "decrypted_packets": device["decrypted_packets"],
            "connection_active": bool(device["connection_active"]),
            "connected": bool(device["connection_active"]),
            "following": bool(device["connection_active"]),
            "data_channels_seen": sorted(device["data_channels_seen"]),
            "data_channels": sorted(device["data_channels_seen"]),
            "connection_access_addresses": sorted(
                device["connection_access_addresses"]
            ),
            "last_seen": device["last_seen"],
            "rssi_history": history,
            "packet_types": dict(device["packet_types"]),
            "services": sorted(device["services"]),
            "connectable": bool(device["connectable"]),
            "scannable": bool(device["scannable"]),
        }

    def devices(self) -> list[dict[str, Any]]:
        with self._lock:
            snapshots = [self._device_snapshot(device) for device in self._devices.values()]
        return sorted(snapshots, key=lambda item: item["last_seen"] or 0, reverse=True)

    def device(self, address: str) -> dict[str, Any] | None:
        wanted = _normalise_address(address)
        with self._lock:
            found = self._devices.get(wanted)
            return self._device_snapshot(found) if found is not None else None

    def rssi_history(self, address: str) -> list[dict[str, Any]]:
        snapshot = self.device(address)
        return snapshot["rssi_history"] if snapshot else []

    def packets(
        self,
        after: int = 0,
        address: str | None = None,
        channel: int | None = None,
        packet_type: str | int | None = None,
        limit: int = 500,
        **aliases: Any,
    ) -> list[dict[str, Any]]:
        """Return the last ``limit`` packets matching all supplied filters."""
        if packet_type is None and "type" in aliases:
            packet_type = aliases["type"]
        try:
            after = int(after)
        except (TypeError, ValueError):
            after = 0
        try:
            limit = max(1, min(int(limit), self._max_packets))
        except (TypeError, ValueError):
            limit = min(500, self._max_packets)
        wanted_address = _normalise_address(address) if address else ""
        try:
            wanted_channel = int(channel) if channel is not None else None
        except (TypeError, ValueError):
            wanted_channel = None

        with self._lock:
            source = copy.deepcopy(list(self._packets))
        matches: list[dict[str, Any]] = []
        for packet in source:
            if packet["seq"] <= after:
                continue
            if wanted_address and wanted_address not in {
                _normalise_address(packet.get("src")),
                _normalise_address(packet.get("dst")),
            }:
                continue
            if wanted_channel is not None and packet.get("channel") != wanted_channel:
                continue
            if packet_type is not None:
                if isinstance(packet_type, int):
                    if packet.get("type_code") != packet_type:
                        continue
                else:
                    wanted_type = str(packet_type).strip().upper()
                    if wanted_type.isdigit():
                        if packet.get("type_code") != int(wanted_type):
                            continue
                    elif str(packet.get("type_name", "")).upper() != wanted_type:
                        continue
            matches.append(packet)
        return matches[-limit:]

    def clear(self) -> dict[str, int]:
        """Clear only bounded in-memory views; the PCAP on disk is untouched."""
        with self._lock:
            removed = {"devices": len(self._devices), "packets": len(self._packets)}
            self._devices.clear()
            self._packets.clear()
            self._packet_count = 0
            self._channel_counts.clear()
            self._packet_type_counts.clear()
            self._link_layer_counts.clear()
            self._connection_access_addresses.clear()
            self._connections_announced = 0
            self._encrypted_packets = 0
            self._decrypted_packets = 0
            self._mic_valid_packets = 0
            self._mic_failed_packets = 0
            self._retransmissions = 0
            self._dropped_packets = 0
            self._parse_errors = 0
        return removed

    def stats(self) -> dict[str, Any]:
        with self._lock:
            devices = [self._device_snapshot(device) for device in self._devices.values()]
            packets = list(self._packets)
            packet_count = self._packet_count
            channel_counts = Counter(self._channel_counts)
            type_counts = Counter(self._packet_type_counts)
            link_layer_counts = Counter(self._link_layer_counts)
            followed_connections = len(self._connection_access_addresses)
            connections_announced = self._connections_announced
            encrypted_packets = self._encrypted_packets
            decrypted_packets = self._decrypted_packets
            mic_valid_packets = self._mic_valid_packets
            mic_failed_packets = self._mic_failed_packets
            retransmissions = self._retransmissions
            parse_errors = self._parse_errors
            dropped = self._dropped_packets
        rssis = [device["rssi"] for device in devices if isinstance(device["rssi"], int)]
        strongest = max(devices, key=lambda item: item["rssi"] or -999, default=None)
        now = time.time()
        active_devices = sum(
            1
            for device in devices
            if isinstance(device["last_seen"], (int, float)) and now - device["last_seen"] <= 10
        )
        named_devices = sum(1 for device in devices if device["name"])
        return {
            "devices_found": len(devices),
            "total_devices": len(devices),
            "active_devices": active_devices,
            "named_devices": named_devices,
            "packet_count": packet_count,
            "total_packets": packet_count,
            "packets_buffered": len(packets),
            "dropped_from_buffer": dropped,
            "parse_errors": parse_errors,
            "average_rssi": round(sum(rssis) / len(rssis), 1) if rssis else None,
            "strongest_device": strongest,
            "channel_counts": dict(sorted(channel_counts.items())),
            "packet_types": dict(type_counts.most_common()),
            "link_layers": dict(link_layer_counts),
            "advertising_packets": link_layer_counts.get("advertising", 0),
            "data_packets": link_layer_counts.get("data", 0),
            "connections_announced": connections_announced,
            "followed_connections": followed_connections,
            "connections_followed": followed_connections,
            "encrypted_packets": encrypted_packets,
            "decrypted_packets": decrypted_packets,
            "mic_valid_packets": mic_valid_packets,
            "mic_failed_packets": mic_failed_packets,
            "retransmissions": retransmissions,
        }

    def status(self) -> dict[str, Any]:
        driver = discover_wch_driver(self._configured_driver)
        sysfs_count = _count_usb_mcus()
        # On Linux sysfs is authoritative, including a real zero after an
        # unplug.  Other platforms retain the count parsed from CLI stderr.
        has_usb_sysfs = Path("/sys/bus/usb/devices").is_dir()
        with self._lock:
            running = self._process is not None and self._process.poll() is None
            channel = self._channel
            usb_mcu_count = sysfs_count if has_usb_sysfs else self._usb_mcu_count
            active_mcu_count = self._active_mcu_count if running else 0
            active_channels = (
                [37, 38, 39][: min(3, max(0, active_mcu_count or 0))]
                if running and channel == 0
                else [channel] if running and (active_mcu_count or 0) > 0
                else []
            )
            return {
                "driver_ready": driver is not None,
                "driver_path": str(driver) if driver else "",
                "running": running,
                "pid": self._pid if running else None,
                "usb_mcu_count": usb_mcu_count,
                "active_mcu_count": active_mcu_count,
                "capture_file": self._capture_file,
                "error": self._error,
                "packet_count": self._packet_count,
                "channel_mode": "all" if channel == 0 else str(channel),
                "channel": channel,
                "channels": active_channels,
                "configured_channels": [37, 38, 39] if channel == 0 else [channel],
                "phy": self._phy,
                "native_connection_following": True,
                "data_channels_supported": list(range(37)),
                "data_channels_seen": sorted(
                    channel for channel in self._channel_counts if 0 <= channel < 37
                ),
                "followed_connections": len(self._connection_access_addresses),
                "connections_followed": len(self._connection_access_addresses),
                "data_packets": self._link_layer_counts.get("data", 0),
                "decrypted_packets": self._decrypted_packets,
                "mic_failed_packets": self._mic_failed_packets,
                "initiator_filter": self._initiator_filter,
                "advertiser_filter": self._advertiser_filter,
                "ltk_configured": self._ltk_configured,
                "started_at": self._started_at,
                "stopped_at": self._stopped_at,
                "exit_code": self._exit_code,
                "parse_errors": self._parse_errors,
                "stderr": list(self._stderr_lines),
            }

    # Snapshot aliases make route code self-documenting without duplicating
    # state or exposing mutable internal containers.
    get_status = status
    get_stats = stats
    get_devices = devices
    get_packets = packets
    clear_history = clear


# Naming aliases for callers that prefer provider terminology.
WchBleProvider = WchBleManager


__all__ = [
    "BUNDLED_DRIVER",
    "VALID_ADV_CHANNELS",
    "WchBleManager",
    "WchBleProvider",
    "discover_wch_driver",
]
