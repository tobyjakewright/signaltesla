"""WirelessBOSS configuration.

Loaded from ~/.config/wirelessboss/config.yaml on first run; a default file
is written if none exists so the app is usable out of the box against a
default local Kismet install.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

import yaml

CONFIG_DIR = Path(os.path.expanduser("~/.config/wirelessboss"))
CONFIG_PATH = CONFIG_DIR / "config.yaml"

# Where the launcher `cd`s to before running Kismet, so kismetdb log files
# land here by default. Used to size up capture storage on the dashboard.
PROJECT_DIR = Path(__file__).resolve().parent.parent

DEFAULT_CONFIG = {
    "kismet": {
        "url": "http://localhost:2501",
        "username": "wirelessboss",
        "password": "",
        # Alternative to user/pass: an API key generated in Kismet's web UI
        # (System -> API Keys). If set, it is sent as KISMET header.
        "apikey": "",
    },
    "poll_interval_sec": 2.0,
    "gpsd": {
        "host": "localhost",
        "port": 2947,
    },
    "map": {
        # Points at WirelessBOSS's own local tile server (wirelessboss/tile_server.py),
        # which serves pre-fetched tiles from tiles_dir - no network needed once
        # you've run scripts/download_offline_tiles.py for your area. Point this at
        # a remote URL instead (e.g. https://tile.openstreetmap.org/{z}/{x}/{y}.png)
        # only if you're fine requiring internet while out driving.
        "tile_url": "http://127.0.0.1:8765/{z}/{x}/{y}.png",
        "tiles_dir": str(Path.home() / ".local/share/wirelessboss/tiles"),
        "tile_port": 8765,
        "attribution": "© OpenStreetMap contributors",
    },
    "monitor_interface": "wlan0mon",
    "ble": {
        # Leave blank to prefer the bundled driver rebuilt by the Kali updater,
        # then fall back to wch_capture on PATH.
        "driver_path": "",
        # Bounded in-memory history; the complete session is still written
        # to a Wireshark-compatible PCAP in storage.capture_dir.
        "max_packets": 5000,
        "max_rssi_samples": 300,
    },
    "signal_analysis": {
        # Leave blank to find tshark on PATH.  Signal Analysis consumes
        # Kismet's live PCAP-NG stream, so tshark needs no capture privileges.
        "tshark_path": "",
        "max_packets": 5000,
    },
    # Port the web UI (wirelessboss/server) listens on - localhost only.
    "web_port": 8080,
    "tools": {
        # Require an explicit on-screen authorization confirmation before
        # any injection action (deauth, injection test) is allowed to run.
        "require_authorization_prompt": True,
    },
    "storage": {
        # Directory the dashboard scans for *.kismet / *.kismetdb files to
        # size up capture storage. Matches where wirelessboss-launcher.sh
        # cd's to before running Kismet. Change this if you set Kismet's
        # own log_prefix to somewhere else.
        "capture_dir": str(PROJECT_DIR),
        "history_window_sec": 300,
    },
}


@dataclass
class KismetConfig:
    url: str = "http://localhost:2501"
    username: str = "wirelessboss"
    password: str = ""
    apikey: str = ""


@dataclass
class GpsdConfig:
    host: str = "localhost"
    port: int = 2947


@dataclass
class MapConfig:
    tile_url: str = "http://127.0.0.1:8765/{z}/{x}/{y}.png"
    tiles_dir: str = str(Path.home() / ".local/share/wirelessboss/tiles")
    tile_port: int = 8765
    attribution: str = "© OpenStreetMap contributors"


@dataclass
class ToolsConfig:
    require_authorization_prompt: bool = True


@dataclass
class BleConfig:
    driver_path: str = ""
    max_packets: int = 5000
    max_rssi_samples: int = 300


@dataclass
class SignalAnalysisConfig:
    tshark_path: str = ""
    max_packets: int = 5000


@dataclass
class StorageConfig:
    capture_dir: str = str(PROJECT_DIR)
    history_window_sec: float = 300.0


@dataclass
class AppConfig:
    kismet: KismetConfig = field(default_factory=KismetConfig)
    gpsd: GpsdConfig = field(default_factory=GpsdConfig)
    map: MapConfig = field(default_factory=MapConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)
    ble: BleConfig = field(default_factory=BleConfig)
    signal_analysis: SignalAnalysisConfig = field(default_factory=SignalAnalysisConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    poll_interval_sec: float = 2.0
    monitor_interface: str = "wlan0mon"
    web_port: int = 8080


def load_config() -> AppConfig:
    if not CONFIG_PATH.exists():
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(yaml.safe_dump(DEFAULT_CONFIG, sort_keys=False))
        raw = DEFAULT_CONFIG
    else:
        raw = yaml.safe_load(CONFIG_PATH.read_text()) or {}

    kismet = KismetConfig(**{**asdict(KismetConfig()), **raw.get("kismet", {})})
    gpsd = GpsdConfig(**{**asdict(GpsdConfig()), **raw.get("gpsd", {})})
    map_cfg = MapConfig(**{**asdict(MapConfig()), **raw.get("map", {})})
    tools = ToolsConfig(**{**asdict(ToolsConfig()), **raw.get("tools", {})})
    ble = BleConfig(**{**asdict(BleConfig()), **raw.get("ble", {})})
    signal_analysis = SignalAnalysisConfig(
        **{**asdict(SignalAnalysisConfig()), **raw.get("signal_analysis", {})}
    )
    storage = StorageConfig(**{**asdict(StorageConfig()), **raw.get("storage", {})})
    capture_dir_override = os.environ.get("WIRELESSBOSS_CAPTURE_DIR")
    if capture_dir_override:
        storage.capture_dir = capture_dir_override

    return AppConfig(
        kismet=kismet,
        gpsd=gpsd,
        map=map_cfg,
        tools=tools,
        ble=ble,
        signal_analysis=signal_analysis,
        storage=storage,
        poll_interval_sec=float(raw.get("poll_interval_sec", 2.0)),
        monitor_interface=raw.get("monitor_interface", "wlan0mon"),
        web_port=int(raw.get("web_port", 8080)),
    )
