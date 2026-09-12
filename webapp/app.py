import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.utils import secure_filename

app = Flask(__name__)

KISMET_HTTP_PORT = os.environ.get("KISMET_HTTP_PORT", "2501")
NOVNC_PORT = os.environ.get("NOVNC_PORT", "6080")
KISMET_LOG_DIR = Path(os.environ.get("KISMET_LOG_DIR", "/home/pi/captures"))
AP_SSID = os.environ.get("AP_SSID", "WarDriving")


def request_host_only():
    """Host the browser used to reach us, without the port - so iframe
    links work whether we're accessed via the AP IP, ethernet, or
    localhost, without hardcoding an address."""
    return request.host.split(":")[0]


@app.route("/")
def index():
    return redirect(url_for("launcher"))


@app.route("/launcher")
def launcher():
    return render_template("launcher.html", ssid=AP_SSID)


@app.route("/kismet")
def kismet():
    host = request_host_only()
    kismet_url = f"http://{host}:{KISMET_HTTP_PORT}/"
    return render_template("kismet.html", kismet_url=kismet_url)


@app.route("/pi")
def desktop():
    host = request_host_only()
    novnc_url = (
        f"http://{host}:{NOVNC_PORT}/vnc.html"
        "?autoconnect=true&resize=scale&reconnect=true"
    )
    return render_template("desktop.html", novnc_url=novnc_url)


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
    app.run(host="127.0.0.1", port=int(os.environ.get("WEB_APP_PORT", "8080")))
