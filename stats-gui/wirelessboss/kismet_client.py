"""Thin REST client for the Kismet server.

Kismet does the hard part (monitor mode setup, channel hopping, 802.11
parsing, GPS tagging, storage). This module just pulls normalized
`WifiDevice` / `GpsFix` snapshots out of its REST API on a poll cycle.

NOTE ON FIELD NAMES: Kismet's REST field names below (kismet.device.base.*,
dot11.device.*, dot11.advertisedssid.*) match the documented Kismet REST
API as of Kismet 2023-era releases. Kismet does not version this schema
strictly - if a field comes back missing on your install, open
http://localhost:2501/devices/views/all/devices.json in a browser (or
`curl -u user:pass ...`) while a device is visible and compare field
names; adjust FIELD_LIST / classify.py accordingly. All lookups in this
module use dict.get() with fallbacks so an unexpected schema degrades
gracefully instead of crashing.
"""
from __future__ import annotations

import logging
from typing import Optional

import requests

from .config import AppConfig
from .models import GpsFix, WifiDevice
from . import classify

log = logging.getLogger(__name__)

# Fields we ask Kismet to return per-device. Requesting an explicit list
# (rather than the full device object) keeps polling fast even with
# hundreds of devices in view.
# Whole nested sub-objects are requested (rather than deep dotted leaf
# paths) since Kismet's field-simplification key naming for deep paths is
# not reliably documented; drilling into a known sub-object defensively
# in classify.py is more robust than guessing an exact leaf key.
FIELD_LIST = [
    "kismet.device.base.macaddr",
    "kismet.device.base.name",
    "kismet.device.base.commonname",
    "kismet.device.base.type",
    "kismet.device.base.phyname",
    "kismet.device.base.manuf",
    "kismet.device.base.channel",
    "kismet.device.base.frequency",
    "kismet.device.base.signal",
    "kismet.device.base.packets.total",
    "kismet.device.base.datasize",
    "kismet.device.base.first_time",
    "kismet.device.base.last_time",
    "kismet.device.base.location",
    "kismet.device.base.crypt",
    "dot11.device",
]


class KismetClient:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.session = requests.Session()
        if cfg.kismet.apikey:
            self.session.headers["KISMET"] = cfg.kismet.apikey
        elif cfg.kismet.username:
            self.session.auth = (cfg.kismet.username, cfg.kismet.password)
        self.base_url = cfg.kismet.url.rstrip("/")

    def _get(self, path: str, **kwargs):
        resp = self.session.get(f"{self.base_url}{path}", timeout=5, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, json_body: dict, **kwargs):
        resp = self.session.post(f"{self.base_url}{path}", json=json_body, timeout=8, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def is_reachable(self) -> bool:
        try:
            self._get("/system/status.json")
            return True
        except requests.RequestException:
            return False

    def get_devices(self) -> list[WifiDevice]:
        """Return every device Kismet currently knows about, normalized."""
        try:
            raw_devices = self._post(
                "/devices/views/all/devices.json",
                {"fields": FIELD_LIST},
            )
        except requests.RequestException as exc:
            log.warning("Kismet device poll failed: %s", exc)
            return []

        devices = []
        for raw in raw_devices:
            try:
                devices.append(classify.parse_device(raw))
            except Exception:
                log.exception("Failed to parse a Kismet device record, skipping")
        return devices

    def get_gps(self) -> Optional[GpsFix]:
        try:
            raw = self._get("/gps/location.json")
        except requests.RequestException:
            return None
        try:
            fix = raw.get("kismet.gps.location.fix", 0) or 0
            lon_lat = raw.get("kismet.gps.location.geopoint") or [None, None]
            return GpsFix(
                latitude=lon_lat[1] if len(lon_lat) == 2 else None,
                longitude=lon_lat[0] if len(lon_lat) == 2 else None,
                altitude_m=raw.get("kismet.gps.location.alt"),
                speed_mps=raw.get("kismet.gps.location.speed"),
                heading_deg=raw.get("kismet.gps.location.heading"),
                fix_quality=int(fix),
                satellites=int(raw.get("kismet.gps.location.satellites", 0) or 0),
            )
        except Exception:
            log.exception("Failed to parse GPS fix")
            return None

    def get_alerts(self) -> list[dict]:
        try:
            raw = self._get("/alerts/last-time/0.json")
            return raw.get("kismet.alert.list", raw if isinstance(raw, list) else [])
        except requests.RequestException:
            return []
