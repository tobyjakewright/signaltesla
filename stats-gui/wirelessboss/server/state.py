"""Shared application state for the web server.

A single background thread polls Kismet (same cadence/logic the old PyQt
PollWorker used) and updates this in-memory snapshot; FastAPI route
handlers just read it - no per-request Kismet calls, so many browser
tabs/clients can poll the API cheaply. A second lightweight piece,
ToolRunner, wraps aireplay-ng the same way the old ToolsPanel did
(subprocess + captured output), just exposed over HTTP instead of Qt
signals.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Optional

from .. import capture_control
from ..ble.wch_provider import WchBleManager
from ..config import AppConfig
from ..kismet_client import KismetClient
from ..models import GpsFix, WifiDevice
from ..signal_capture import SignalCaptureManager
from ..stats import compute_stats, sorted_manufacturers
from ..storage_stats import StorageMonitor, StorageStats


@dataclass
class Snapshot:
    devices: list[WifiDevice] = field(default_factory=list)
    gps: Optional[GpsFix] = None
    kismet_connected: bool = False
    capture_running: bool = False
    storage: StorageStats = field(
        default_factory=lambda: StorageStats(0, 0, 0, 0, 0, 0, 0, None, None)
    )
    last_poll_ts: float = 0.0


class ToolRunner:
    """aireplay-ng wrapper: same authorization gate and actions as the old
    desktop ToolsPanel, driven over HTTP instead of Qt signals/buttons."""

    def __init__(self):
        self._lock = threading.Lock()
        self.authorized = False
        self.process: Optional[subprocess.Popen] = None
        self.output_lines: list[str] = []
        self._reader_thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        with self._lock:
            return self.process is not None and self.process.poll() is None

    def set_authorized(self, value: bool) -> None:
        with self._lock:
            self.authorized = value

    _mac_re = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    _iface_re = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")

    @classmethod
    def validate_deauth_request(
        cls, iface: str, bssid: str, client_mac: str, count: int
    ) -> Optional[str]:
        """Return a beginner-readable validation error without starting a tool."""
        if not cls._iface_re.fullmatch(iface or ""):
            return "Invalid monitor interface name"
        if not cls._mac_re.fullmatch(bssid or ""):
            return "Target BSSID must be a full MAC address"
        if client_mac and not cls._mac_re.fullmatch(client_mac):
            return "Target client must be a full MAC address"
        if count < 1 or count > 20:
            return "Deauth count must be between 1 and 20 for a bounded lab test"
        return None

    def _start(self, args: list[str], preface: Optional[list[str]] = None) -> tuple[bool, str]:
        with self._lock:
            if self.process is not None and self.process.poll() is None:
                return False, "A tool is already running. Stop it first."
            if not self.authorized:
                return False, (
                    "Not authorized - tick the authorization checkbox on the Wi-Fi Lab "
                    "page first (once per server run)."
                )
            self.output_lines = [*(preface or []), f"$ {' '.join(args)}"]
            try:
                self.process = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                proc = self.process
            except FileNotFoundError:
                self.output_lines.append("'aireplay-ng' isn't on PATH - is aircrack-ng installed?")
                self.process = None
                return False, "aireplay-ng not found"

        def reader():
            if proc.stdout is None:
                return
            for line in proc.stdout:
                with self._lock:
                    if self.process is proc:
                        self.output_lines.append(line.rstrip("\n"))
            with self._lock:
                if self.process is proc:
                    self.output_lines.append("[process finished]")

        self._reader_thread = threading.Thread(target=reader, daemon=True)
        self._reader_thread.start()
        return True, "started"

    def run_deauth(self, iface: str, bssid: str, client_mac: str, count: int) -> tuple[bool, str]:
        error = self.validate_deauth_request(iface, bssid, client_mac, count)
        if error:
            return False, error
        args = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
        if client_mac:
            args += ["-c", client_mac]
        args.append(iface)
        return self._start(args)

    def run_handshake_capture(self, iface: str, bssid: str, client_mac: str, count: int) -> tuple[bool, str]:
        error = self.validate_deauth_request(iface, bssid, client_mac, count)
        if error:
            return False, error
        args = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
        if client_mac:
            args += ["-c", client_mac]
        args.append(iface)
        return self._start(args, [
            "--- Guided reconnect capture ---",
            "A short, bounded deauthentication burst asks your lab client to reconnect.",
            "Keep Kismet capture running; the EAPOL exchange is written to its .pcapng.",
            "Signal Analysis can show EAPOL frames live, or open the file in Wireshark with filter: eapol",
        ])

    def run_injection_test(self, iface: str) -> tuple[bool, str]:
        if not self._iface_re.fullmatch(iface or ""):
            return False, "Invalid monitor interface name"
        return self._start(["aireplay-ng", "-9", iface])

    def stop(self) -> tuple[bool, str]:
        with self._lock:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                return True, "stopped"
            return True, "nothing running"

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "authorized": self.authorized,
                "running": self.process is not None and self.process.poll() is None,
                "output": "\n".join(self.output_lines[-500:]),
            }


class AppState:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.client = KismetClient(cfg)
        self.storage_monitor = StorageMonitor(Path(cfg.storage.capture_dir), cfg.storage.history_window_sec)
        self.tools = ToolRunner()
        self.ble = WchBleManager(
            driver_path=cfg.ble.driver_path,
            capture_dir=cfg.storage.capture_dir,
            max_packets=cfg.ble.max_packets,
            max_rssi_samples=cfg.ble.max_rssi_samples,
        )
        self.signal = SignalCaptureManager(
            cfg,
            max_packets=cfg.signal_analysis.max_packets,
        )
        self.start_ts = time.time()

        self._lock = threading.Lock()
        self._snapshot = Snapshot()
        self._alerts: list[dict] = []
        self._alert_keys: set[str] = set()
        self._known_manufs: set[str] = set()
        self._dashboard_reset_ts = 0.0
        self._dashboard_packet_baseline: dict[str, int] = {}
        self._dashboard_data_baseline: dict[str, int] = {}
        self._signal_started_kismet = False

        # Manual location logging: for no-GPS wardriving, the user clicks the
        # map at their current spot and every currently-visible device with
        # no real Kismet-derived location gets tagged with it. This is
        # WirelessBOSS's own overlay, layered on top of Kismet's device data
        # at serve time - it never writes into Kismet's own records.
        self.manual_self_position: Optional[tuple[float, float]] = None
        self._manual_device_positions: dict[str, tuple[float, float, float]] = {}

        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.stop_signal_analysis()
        self.ble.stop()
        self.tools.stop()

    def _poll_loop(self) -> None:
        while self._running:
            reachable = self.client.is_reachable()
            devices: list[WifiDevice] = []
            gps = None
            alerts_raw: list[dict] = []
            if reachable:
                try:
                    devices = self.client.get_devices()
                    gps = self.client.get_gps()
                    alerts_raw = self.client.get_alerts()
                except Exception:
                    pass

            capture_running = capture_control.is_running()
            storage = self.storage_monitor.sample()

            with self._lock:
                self._snapshot = Snapshot(
                    devices=devices, gps=gps, kismet_connected=reachable,
                    capture_running=capture_running, storage=storage,
                    last_poll_ts=time.time(),
                )
                for m in sorted_manufacturers(devices):
                    self._known_manufs.add(m)
                for alert in alerts_raw:
                    ts = alert.get("kismet.alert.timestamp")
                    header = alert.get("kismet.alert.header", "ALERT")
                    text = alert.get("kismet.alert.text", "")
                    key = f"{ts}:{header}:{text}"
                    if key not in self._alert_keys:
                        self._alert_keys.add(key)
                        self._alerts.insert(0, {"ts": ts, "header": header, "text": text})
                self._alerts = self._alerts[:500]

            time.sleep(self.cfg.poll_interval_sec)

    def get_snapshot(self) -> Snapshot:
        with self._lock:
            return self._snapshot

    def get_alerts(self) -> list[dict]:
        with self._lock:
            return list(self._alerts)

    def clear_alerts(self) -> None:
        with self._lock:
            self._alerts = []

    def reset_dashboard(self) -> float:
        """Start a fresh, non-destructive dashboard session.

        Kismet keeps its own device cache and capture files untouched.  The
        web view records the current packet/data counters as a baseline and
        only exposes devices that Kismet sees again after this timestamp.
        That makes every dashboard counter zero immediately, then allows the
        new session to fill naturally as fresh radio activity arrives.
        """
        with self._lock:
            reset_ts = time.time()
            self._dashboard_reset_ts = reset_ts
            self._dashboard_packet_baseline = {
                dev.mac: dev.packets for dev in self._snapshot.devices
            }
            self._dashboard_data_baseline = {
                dev.mac: dev.data_bytes for dev in self._snapshot.devices
            }
            self._alerts = []
            return reset_ts

    def _dashboard_devices(self) -> list[WifiDevice]:
        with self._lock:
            devices = list(self._snapshot.devices)
            reset_ts = self._dashboard_reset_ts
            packet_baseline = dict(self._dashboard_packet_baseline)
            data_baseline = dict(self._dashboard_data_baseline)

        if reset_ts <= 0:
            return devices

        fresh: list[WifiDevice] = []
        for dev in devices:
            if dev.last_seen is None or dev.last_seen <= reset_ts:
                continue
            fresh.append(replace(
                dev,
                packets=max(0, dev.packets - packet_baseline.get(dev.mac, 0)),
                data_bytes=max(0, dev.data_bytes - data_baseline.get(dev.mac, 0)),
            ))
        return fresh

    def get_stats(self):
        return compute_stats(self._dashboard_devices())

    def get_manufacturers(self) -> list[str]:
        with self._lock:
            return sorted(self._known_manufs)

    def set_manual_location(self, lat: float, lon: float) -> int:
        """Records the user's manually-placed position and tags every
        currently-visible device that has no real location with it.
        Returns how many devices got tagged."""
        now = time.time()
        with self._lock:
            self.manual_self_position = (lat, lon)
            tagged = 0
            for dev in self._snapshot.devices:
                if not dev.has_location:
                    self._manual_device_positions[dev.mac] = (lat, lon, now)
                    tagged += 1
            return tagged

    def get_manual_self_position(self) -> Optional[tuple[float, float]]:
        with self._lock:
            return self.manual_self_position

    def manual_macs(self) -> set[str]:
        with self._lock:
            return set(self._manual_device_positions.keys())

    def devices_with_manual_overlay(self) -> list[WifiDevice]:
        """Current device list with manually-logged positions merged in for
        devices that have no real Kismet-derived location."""
        devices = self._dashboard_devices()
        with self._lock:
            overlay = dict(self._manual_device_positions)
        if not overlay:
            return devices
        out = []
        for dev in devices:
            if not dev.has_location and dev.mac in overlay:
                lat, lon, _ts = overlay[dev.mac]
                dev = replace(dev, latitude=lat, longitude=lon)
            out.append(dev)
        return out

    def start_capture(self) -> tuple[bool, str]:
        log_path = Path.home() / ".local/share/wirelessboss/kismet.log"
        return capture_control.start(Path(self.cfg.storage.capture_dir), log_path)

    def stop_capture(self) -> tuple[bool, str]:
        return capture_control.stop()

    def ensure_kismet_ready(self, timeout_sec: float = 10.0) -> tuple[bool, str, bool]:
        """Ensure Kismet is running *and* its authenticated API is ready.

        Returns ``(ok, message, started_here)``.  Active Wi-Fi workflows use
        this before transmitting so the reconnect/EAPOL exchange cannot happen
        before the recorder and live packet endpoint are available.
        """
        started_here = False
        if not capture_control.is_running():
            ok, message = self.start_capture()
            if not ok:
                return False, message, False
            started_here = True

        deadline = time.monotonic() + max(0.25, timeout_sec)
        while time.monotonic() < deadline:
            if not capture_control.is_running():
                time.sleep(0.25)
                continue
            if self.client.is_reachable():
                return True, "Kismet capture and API are ready.", started_here
            time.sleep(0.25)

        if not capture_control.is_running():
            return False, "Kismet did not stay running. Check its service log.", started_here
        return (
            False,
            "Kismet is running but its API did not become ready. Check the configured API credentials and service log.",
            started_here,
        )

    def start_signal_analysis(self) -> tuple[bool, str, bool]:
        """Start the Wi-Fi live feed, starting Kismet when needed."""
        if self.signal.running:
            return True, "Wi-Fi live packet feed is already running.", False
        signal_status = self.signal.status(refresh=False)
        if not signal_status.get("tshark_available"):
            return False, "TShark is not available. Install it with: sudo apt install tshark", False

        ready, message, started_kismet = self.ensure_kismet_ready()
        if not ready:
            if started_kismet:
                self.stop_capture()
            return False, message, started_kismet

        ok, signal_message = self.signal.start()
        if not ok:
            if started_kismet:
                self.stop_capture()
            return False, signal_message, started_kismet
        with self._lock:
            self._signal_started_kismet = started_kismet
        if started_kismet:
            signal_message = "Kismet recording started automatically; Wi-Fi live packet feed starting."
        return True, signal_message, started_kismet

    def stop_signal_analysis(self, stop_kismet: bool = False) -> tuple[bool, str, bool]:
        """Stop the feed and optionally the underlying Kismet capture.

        Explicit Signal Analysis Stop/Pause actions pass ``stop_kismet=True``.
        Application shutdown only stops Kismet when this manager started it.
        """
        ok, message = self.signal.stop()
        if not ok:
            return False, message, False
        with self._lock:
            stop_owned_kismet = self._signal_started_kismet
            self._signal_started_kismet = False
        kismet_was_running = capture_control.is_running()
        should_stop_kismet = kismet_was_running and (stop_kismet or stop_owned_kismet)
        if should_stop_kismet:
            capture_ok, capture_message = self.stop_capture()
            if not capture_ok:
                return False, f"Live feed stopped, but Kismet could not be stopped: {capture_message}", True
            message = "Wi-Fi live feed and Kismet capture stopped. Existing packet rows were preserved."
        else:
            message = "Wi-Fi live feed stopped. Kismet recording, if already running, continues."
        return True, message, should_stop_kismet
