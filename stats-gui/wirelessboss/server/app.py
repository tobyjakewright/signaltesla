"""FastAPI app factory: REST API + serves the web UI's static files."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import capture_control
from ..config import AppConfig
from ..export import export_csv
from ..models import WifiDevice
from ..tile_server import TileServer
from .state import AppState

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
CAPTURE_FILE_SUFFIXES = (".kismet", ".kismetdb", ".pcapng", ".pcap")


def device_to_dict(dev: WifiDevice, manual: bool = False) -> dict:
    return {
        "mac": dev.mac,
        "name": dev.name,
        "kind": dev.kind.value,
        "standard": dev.standard.value,
        "channel": dev.channel,
        "frequency_mhz": dev.frequency_mhz,
        "band": dev.band,
        "encryption": dev.encryption,
        "signal_dbm": dev.signal_dbm,
        "signal_max_dbm": dev.signal_max_dbm,
        "manuf": dev.manuf,
        "bssid": dev.bssid,
        "client_count": dev.client_count,
        "packets": dev.packets,
        "data_bytes": dev.data_bytes,
        "first_seen": dev.first_seen,
        "last_seen": dev.last_seen,
        "latitude": dev.latitude,
        "longitude": dev.longitude,
        "has_location": dev.has_location,
        "location_source": "manual" if manual else ("gps" if dev.has_location else None),
        "raw": dev.raw,
    }


class DeauthRequest(BaseModel):
    bssid: str
    client_mac: str = ""
    count: int = Field(default=5, ge=1, le=20)
    iface: Optional[str] = None


class AuthorizeRequest(BaseModel):
    authorized: bool


class ManualLocationRequest(BaseModel):
    lat: float
    lon: float


class BleStartRequest(BaseModel):
    # 0 means the normal three-radio arrangement: 37 + 38 + 39 together.
    channel: Literal[0, 37, 38, 39] = Field(
        default=0,
        description="0 uses all three primary advertising channels.",
    )
    phy: Literal["1", "2", "S8", "S2"] = Field(
        default="1",
        description="BLE PHY: 1M, 2M, or LE Coded at S=8/S=2.",
    )
    initiator: str = Field(
        default="",
        max_length=17,
        description="Optional initiator/central MAC filter.",
    )
    advertiser: str = Field(
        default="",
        max_length=17,
        description="Optional advertiser/peripheral MAC filter.",
    )
    ltk: str = Field(
        default="",
        max_length=50,
        repr=False,
        description="Optional 16-byte Long Term Key as 32 hexadecimal digits.",
    )


def create_app(cfg: AppConfig) -> FastAPI:
    app = FastAPI(title="WirelessBOSS")
    state = AppState(cfg)
    state.start()

    tile_server = TileServer(Path(cfg.map.tiles_dir), cfg.map.tile_port)
    tile_server.start()

    @app.on_event("shutdown")
    def _shutdown():
        state.stop()
        tile_server.stop()

    # ---- status / devices / stats -------------------------------------

    @app.get("/api/status")
    def status():
        snap = state.get_snapshot()
        gps = snap.gps
        gps_fix = bool(gps and gps.fix_quality and gps.latitude is not None)
        manual_pos = state.get_manual_self_position()
        effective_fix = gps_fix or manual_pos is not None
        if gps_fix:
            lat, lon = gps.latitude, gps.longitude
            fix_type = "3D Fix" if gps.fix_quality == 3 else "2D Fix"
        elif manual_pos:
            lat, lon = manual_pos
            fix_type = "Manual"
        else:
            lat = lon = None
            fix_type = ""
        return {
            "kismet_connected": snap.kismet_connected,
            "capture_running": snap.capture_running,
            "gps_fix": effective_fix,
            "gps_fix_type": fix_type,
            "gps_lat": lat,
            "gps_lon": lon,
            "gps_satellites": gps.satellites if gps else 0,
            "device_count": len(snap.devices),
            "last_poll_ts": snap.last_poll_ts,
            "monitor_interface": cfg.monitor_interface,
            "map_tile_url": cfg.map.tile_url,
            "map_attribution": cfg.map.attribution,
            "server_uptime_sec": time.time() - state.start_ts,
        }

    @app.get("/api/devices")
    def devices():
        manual_macs = state.manual_macs()
        return [device_to_dict(d, manual=d.mac in manual_macs) for d in state.devices_with_manual_overlay()]

    @app.post("/api/location/manual")
    def set_manual_location(req: ManualLocationRequest):
        tagged = state.set_manual_location(req.lat, req.lon)
        return {"ok": True, "tagged": tagged}

    @app.get("/api/manufacturers")
    def manufacturers():
        return state.get_manufacturers()

    @app.get("/api/stats")
    def stats():
        s = state.get_stats()
        return {
            "total": s.total, "access_points": s.access_points, "clients": s.clients,
            "other": s.other, "open_networks": s.open_networks, "new_devices": s.new_devices,
            "kind_counts": s.kind_counts, "standard_counts": s.standard_counts,
            "band_counts": s.band_counts, "encryption_counts": s.encryption_counts,
            "top_manufacturers": s.top_manufacturers, "rssi_histogram": s.rssi_histogram,
            "manuf_by_kind": s.manuf_by_kind, "channels_24": s.channels_24,
            "channels_5_6": s.channels_5_6, "speed_table": s.speed_table,
            "top_aps_by_clients": s.top_aps_by_clients,
        }

    @app.post("/api/dashboard/reset")
    def dashboard_reset():
        reset_ts = state.reset_dashboard()
        return {
            "ok": True,
            "reset_ts": reset_ts,
            "message": "Dashboard reset. Kismet capture files were not changed.",
        }

    @app.get("/api/storage")
    def storage():
        st = state.get_snapshot().storage
        return {
            "capture_bytes": st.capture_bytes, "file_count": st.file_count,
            "pcap_bytes": st.pcap_bytes, "pcap_file_count": st.pcap_file_count,
            "disk_total_bytes": st.disk_total_bytes, "disk_used_bytes": st.disk_used_bytes,
            "disk_free_bytes": st.disk_free_bytes, "growth_bytes_per_sec": st.growth_bytes_per_sec,
            "eta_seconds": st.eta_seconds,
        }

    @app.get("/api/alerts")
    def alerts():
        return state.get_alerts()

    @app.post("/api/alerts/clear")
    def alerts_clear():
        state.clear_alerts()
        return {"ok": True}

    # ---- capture control -------------------------------------------------

    @app.post("/api/capture/start")
    def capture_start():
        ok, msg = state.start_capture()
        return {"ok": ok, "message": msg}

    @app.post("/api/capture/stop")
    def capture_stop():
        ok, msg = state.stop_capture()
        return {"ok": ok, "message": msg}

    # ---- WCH BLE Analyzer Pro -------------------------------------------

    @app.get("/api/ble/status")
    def ble_status():
        return state.ble.status()

    @app.get("/api/ble/stats")
    def ble_stats():
        return state.ble.stats()

    @app.get("/api/ble/devices")
    def ble_devices():
        return state.ble.devices()

    @app.get("/api/ble/packets")
    def ble_packets(
        after: int = 0,
        address: Optional[str] = None,
        channel: Optional[int] = None,
        packet_type: Optional[str] = Query(default=None, alias="type"),
        limit: int = Query(default=500, ge=1, le=5000),
    ):
        return state.ble.packets(
            after=after,
            address=address,
            channel=channel,
            packet_type=packet_type,
            limit=limit,
        )

    @app.post("/api/ble/start")
    def ble_start(req: BleStartRequest):
        ok, msg = state.ble.start(
            channel=req.channel,
            phy=req.phy,
            initiator=req.initiator,
            advertiser=req.advertiser,
            ltk=req.ltk,
        )
        return {"ok": ok, "message": msg, "status": state.ble.status()}

    @app.post("/api/ble/stop")
    def ble_stop():
        ok, msg = state.ble.stop()
        return {"ok": ok, "message": msg, "status": state.ble.status()}

    @app.post("/api/ble/clear")
    def ble_clear():
        removed = state.ble.clear()
        return {
            "ok": True,
            "removed": removed,
            "message": "Cleared the BLE device and packet views. The PCAP file was not changed.",
        }

    # ---- live Wi-Fi packet dissection ----------------------------------

    @app.get("/api/signal/status")
    def signal_status():
        return state.signal.status()

    @app.get("/api/signal/packets")
    def signal_packets(
        after: int = 0,
        address: Optional[str] = None,
        channel: Optional[int] = None,
        packet_type: Optional[str] = Query(default=None, alias="type"),
        limit: int = Query(default=500, ge=1, le=5000),
    ):
        return state.signal.get_packets(
            after=after,
            address=address,
            channel=channel,
            packet_type=packet_type,
            limit=limit,
        )

    @app.post("/api/signal/start")
    def signal_start():
        ok, msg, kismet_started = state.start_signal_analysis()
        return {
            "ok": ok,
            "message": msg,
            "kismet_started": kismet_started,
            "status": state.signal.status(refresh=False),
        }

    @app.post("/api/signal/stop")
    def signal_stop():
        ok, msg, kismet_stopped = state.stop_signal_analysis(stop_kismet=True)
        return {
            "ok": ok,
            "message": msg,
            "kismet_stopped": kismet_stopped,
            "status": state.signal.status(refresh=False),
        }

    @app.post("/api/signal/clear")
    def signal_clear():
        removed = state.signal.clear()
        return {
            "ok": True,
            "removed": removed,
            "message": f"Cleared {removed} Wi-Fi packet row(s). Capture files were not changed.",
        }

    # ---- tools (deauth / handshake / injection test) -----------------

    @app.get("/api/tools/status")
    def tools_status():
        return state.tools.snapshot()

    @app.post("/api/tools/authorize")
    def tools_authorize(req: AuthorizeRequest):
        state.tools.set_authorized(req.authorized)
        return {"ok": True, "authorized": req.authorized}

    @app.post("/api/tools/deauth")
    def tools_deauth(req: DeauthRequest):
        iface = req.iface or cfg.monitor_interface
        ok, msg = state.tools.run_deauth(iface, req.bssid, req.client_mac, req.count)
        return {"ok": ok, "message": msg}

    @app.post("/api/tools/handshake")
    def tools_handshake(req: DeauthRequest):
        iface = req.iface or cfg.monitor_interface
        validation_error = state.tools.validate_deauth_request(
            iface, req.bssid, req.client_mac, req.count
        )
        if validation_error:
            return {"ok": False, "message": validation_error}
        if not state.tools.snapshot()["authorized"]:
            return {
                "ok": False,
                "message": (
                    "Not authorized - tick the authorization checkbox on the "
                    "Wi-Fi Lab page first (once per server run)."
                ),
            }

        ready, capture_message, capture_started = state.ensure_kismet_ready()
        if not ready:
            if capture_started:
                state.stop_capture()
            return {
                "ok": False,
                "message": f"Reconnect test not sent: {capture_message}",
                "capture_started": False,
            }
        ok, msg = state.tools.run_handshake_capture(iface, req.bssid, req.client_mac, req.count)
        if ok and capture_started:
            msg = "Kismet recording started automatically; reconnect test started."
        return {"ok": ok, "message": msg, "capture_started": capture_started}

    @app.post("/api/tools/injection_test")
    def tools_injection_test(iface: Optional[str] = None):
        ok, msg = state.tools.run_injection_test(iface or cfg.monitor_interface)
        return {"ok": ok, "message": msg}

    @app.post("/api/tools/stop")
    def tools_stop():
        ok, msg = state.tools.stop()
        return {"ok": ok, "message": msg}

    # ---- export ---------------------------------------------------------

    @app.post("/api/export/csv")
    def export_csv_route():
        devices_now = state.get_snapshot().devices
        if not devices_now:
            return JSONResponse({"ok": False, "message": "No devices captured yet."}, status_code=400)
        export_root = Path(cfg.storage.capture_dir) / "wirelessboss-exports"
        paths = export_csv(devices_now, export_root)
        return {
            "ok": True,
            "folder": str(paths["all_devices"].parent),
            "count": len(devices_now),
            "files": [p.name for p in paths.values()],
        }

    # ---- capture files (list / download / clear) -------------------------

    @app.get("/api/files")
    def list_files():
        d = Path(cfg.storage.capture_dir)
        out = []
        if d.exists():
            for suffix in CAPTURE_FILE_SUFFIXES:
                for f in d.glob(f"*{suffix}"):
                    try:
                        st = f.stat()
                    except OSError:
                        continue
                    out.append({
                        "name": f.name,
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                        "kind": (
                            "ble-pcap" if f.name.startswith("wirelessboss-ble-")
                            else "pcap" if suffix in (".pcapng", ".pcap")
                            else "kismetdb"
                        ),
                    })
        out.sort(key=lambda r: r["mtime"], reverse=True)
        return out

    @app.get("/api/files/download/{filename}")
    def download_file(filename: str):
        # filename comes from a path segment, so FastAPI's routing already
        # rejects anything containing "/" - this check is defense in depth,
        # and guards against a bare ".."/"." request or an absolute-path
        # string that Path("/x") / filename could otherwise resolve oddly.
        if "/" in filename or "\\" in filename or filename in (".", ".."):
            return JSONResponse({"ok": False, "message": "Invalid filename."}, status_code=400)
        target = Path(cfg.storage.capture_dir) / filename
        if not target.is_file():
            return JSONResponse({"ok": False, "message": "File not found."}, status_code=404)
        if target.suffix not in CAPTURE_FILE_SUFFIXES:
            return JSONResponse({"ok": False, "message": "Not a capture file."}, status_code=400)
        return FileResponse(str(target), filename=target.name, media_type="application/octet-stream")

    @app.post("/api/data/clear")
    def clear_data():
        if state.ble.is_running:
            return {
                "ok": False,
                "message": "Stop BLE capture first - the analyzer PCAP is still open.",
                "removed": 0,
            }
        ok, msg, removed = capture_control.clear_capture_files(Path(cfg.storage.capture_dir))
        return {"ok": ok, "message": msg, "removed": removed}

    # ---- static web UI --------------------------------------------------

    app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")
    assets_dir = Path(__file__).resolve().parent.parent / "assets"
    app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/")
    def index():
        return FileResponse(str(WEB_DIR / "index.html"))

    return app
