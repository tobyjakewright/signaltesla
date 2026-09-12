import dataclasses
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

from ble.reader import recent_devices as ble_recent_devices
from wifi.kismet_client import KismetClient

app = Flask(__name__)

KISMET_HTTP_PORT = os.environ.get("KISMET_HTTP_PORT", "2501")
NOVNC_PORT = os.environ.get("NOVNC_PORT", "6080")
KISMET_LOG_DIR = Path(os.environ.get("KISMET_LOG_DIR", "/home/pi/captures"))
AP_SSID = os.environ.get("AP_SSID", "WarDriving")

KISMET_URL = os.environ.get("KISMET_URL", f"http://localhost:{KISMET_HTTP_PORT}")
KISMET_USER = os.environ.get("KISMET_USER", "wardriving")
KISMET_PASS = os.environ.get("KISMET_PASS", "")
BLE_JSONL_PATH = os.environ.get(
    "BLE_JSONL_PATH", str(KISMET_LOG_DIR / "ble-live.jsonl")
)

kismet = KismetClient(KISMET_URL, KISMET_USER, KISMET_PASS)


def request_host_only():
    """Host the browser used to reach us, without the port - so the
    dedicated-UI links below work whether we're accessed via the AP IP,
    ethernet, or localhost, without hardcoding an address."""
    return request.host.split(":")[0]


@app.route("/")
def index():
    return redirect(url_for("launcher"))


@app.route("/launcher")
def launcher():
    host = request_host_only()
    return render_template(
        "launcher.html",
        ssid=AP_SSID,
        kismet_url=f"http://{host}:{KISMET_HTTP_PORT}/",
        vnc_url=f"http://{host}:{NOVNC_PORT}/vnc.html?autoconnect=true&resize=scale",
        stats_url=url_for("stats"),
    )


@app.route("/stats")
def stats():
    return render_template("stats.html")


def _wifi_device_dict(device) -> dict:
    d = dataclasses.asdict(device)
    d["kind"] = device.kind.value
    d["standard"] = device.standard.value
    return d


@app.route("/api/wifi-devices")
def api_wifi_devices():
    return jsonify([_wifi_device_dict(d) for d in kismet.get_devices()])


@app.route("/api/ble-devices")
def api_ble_devices():
    return jsonify(ble_recent_devices(BLE_JSONL_PATH))


@app.route("/api/alerts")
def api_alerts():
    return jsonify(kismet.get_alerts())


@app.route("/api/status")
def api_status():
    reachable = kismet.is_reachable()
    devices = kismet.get_devices() if reachable else []
    gps = kismet.get_gps() if reachable else None
    ble_count = len(ble_recent_devices(BLE_JSONL_PATH))
    return jsonify(
        {
            "kismet_reachable": reachable,
            "wifi_device_count": len(devices),
            "ap_count": sum(1 for d in devices if d.kind.value == "Access Point"),
            "client_count": sum(1 for d in devices if d.kind.value == "Client"),
            "ble_device_count": ble_count,
            "gps": dataclasses.asdict(gps) if gps else None,
        }
    )


def _list_capture_files():
    if not KISMET_LOG_DIR.exists():
        return []
    files = []
    for p in sorted(KISMET_LOG_DIR.iterdir()):
        if not p.is_file():
            continue
        stat = p.stat()
        files.append(
            {
                "name": p.name,
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                "modified": datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC"),
            }
        )
    return files


@app.route("/export")
def export():
    return render_template("export.html", files=_list_capture_files())


@app.route("/export/download/<path:filename>")
def export_download(filename):
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(404)
    target = (KISMET_LOG_DIR / safe_name).resolve()
    try:
        target.relative_to(KISMET_LOG_DIR.resolve())
    except ValueError:
        abort(404)
    if not target.is_file():
        abort(404)
    return send_file(target, as_attachment=True)


@app.route("/export/download-all")
def export_download_all():
    if not KISMET_LOG_DIR.exists():
        abort(404)
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()
    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in KISMET_LOG_DIR.iterdir():
            if p.is_file():
                zf.write(p, arcname=p.name)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    response = send_file(
        tmp.name,
        as_attachment=True,
        download_name=f"wardriving-captures-{stamp}.zip",
    )

    def _cleanup(_exc=None):
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    response.call_on_close(_cleanup)
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("WEB_APP_PORT", "8090")))
