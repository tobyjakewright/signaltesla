"""Live wardriving map: every geolocated device gets a marker, updated in place each poll.

Fully offline: Leaflet's JS/CSS are vendored locally (wirelessboss/assets/leaflet/)
and inlined directly into the page instead of loaded from a CDN, the self-location
marker is pure CSS (no marker-icon.png dependency), and tiles come from
WirelessBOSS's own local tile server (tile_server.py) reading pre-fetched tiles
(see scripts/download_offline_tiles.py) - no network access needed once you've
cached tiles for your area.
"""
from __future__ import annotations

import json
from pathlib import Path

from PyQt6.QtCore import QUrl
from PyQt6.QtWidgets import QWidget, QVBoxLayout

try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    HAVE_WEBENGINE = True
except ImportError:  # pragma: no cover - degrade gracefully if not installed
    HAVE_WEBENGINE = False

from ..config import AppConfig
from ..models import WifiDevice

_ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets" / "leaflet"

# Plain string tokens, not str.format()/%-formatting: the inlined leaflet.js/
# leaflet.css content is full of literal "{"/"}"/"%" characters that either
# formatting mechanism would misinterpret (see the same lesson learned in
# dashboard_view.py for Chart.js).
_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<style>
__WB_LEAFLET_CSS__
html, body, #map { height: 100%; margin: 0; padding: 0; background: #111; }
.wb-self-marker {
  width: 16px; height: 16px; border-radius: 50%;
  background: #4fc3f7; border: 2px solid #ffffff;
  box-shadow: 0 0 0 rgba(79, 195, 247, 0.6);
  animation: wb-pulse 2s infinite;
}
@keyframes wb-pulse {
  0%   { box-shadow: 0 0 0 0 rgba(79, 195, 247, 0.6); }
  70%  { box-shadow: 0 0 0 14px rgba(79, 195, 247, 0); }
  100% { box-shadow: 0 0 0 0 rgba(79, 195, 247, 0); }
}
</style>
<script>
__WB_LEAFLET_JS__
</script>
</head>
<body>
<div id="map"></div>
<script>
var map = L.map('map').setView([0, 0], 3);
L.tileLayer('__WB_TILE_URL__', {
  maxZoom: 19,
  attribution: '__WB_ATTRIBUTION__'
}).addTo(map);

var markers = {};
var selfMarker = null;
var haveFirstFix = false;

var wbSelfIcon = L.divIcon({
  className: 'wb-self-marker-wrap',
  html: '<div class="wb-self-marker"></div>',
  iconSize: [16, 16],
  iconAnchor: [8, 8]
});

function wb_upsertMarker(mac, lat, lon, popupHtml, colorClass) {
  var color = colorClass || '#3388ff';
  if (markers[mac]) {
    markers[mac].setLatLng([lat, lon]);
    markers[mac].setPopupContent(popupHtml);
    markers[mac].setStyle({color: color, fillColor: color});
  } else {
    var m = L.circleMarker([lat, lon], {
      radius: 6, color: color, fillColor: color, fillOpacity: 0.8, weight: 1
    }).addTo(map);
    m.bindPopup(popupHtml);
    markers[mac] = m;
  }
}

function wb_removeMarker(mac) {
  if (markers[mac]) { map.removeLayer(markers[mac]); delete markers[mac]; }
}

function wb_clearMarkers() {
  Object.keys(markers).forEach(function(mac) { map.removeLayer(markers[mac]); });
  markers = {};
}

function wb_setSelfLocation(lat, lon) {
  if (selfMarker) {
    selfMarker.setLatLng([lat, lon]);
  } else {
    selfMarker = L.marker([lat, lon], {icon: wbSelfIcon, title: 'You are here'}).addTo(map);
  }
  if (!haveFirstFix) {
    map.setView([lat, lon], 16);
    haveFirstFix = true;
  }
}
</script>
</body>
</html>
"""


def _read_asset(name: str) -> str:
    path = _ASSETS_DIR / name
    if not path.exists():
        return f"/* missing asset: {path} - re-run the vendoring step (see README offline setup) */"
    return path.read_text()


class MapView(QWidget):
    def __init__(self, cfg: AppConfig, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        if HAVE_WEBENGINE:
            self.web = QWebEngineView()
            html = (
                _HTML_TEMPLATE
                .replace("__WB_LEAFLET_CSS__", _read_asset("leaflet.css"))
                .replace("__WB_LEAFLET_JS__", _read_asset("leaflet.js"))
                .replace("__WB_TILE_URL__", cfg.map.tile_url)
                .replace("__WB_ATTRIBUTION__", cfg.map.attribution)
            )
            self.web.setHtml(html, QUrl("https://wirelessboss.local/"))
            layout.addWidget(self.web)
        else:  # pragma: no cover
            from PyQt6.QtWidgets import QLabel
            layout.addWidget(QLabel(
                "Map view unavailable: PyQt6-WebEngine is not installed.\n"
                "On Kali: sudo apt install python3-pyqt6.qtwebengine"
            ))
            self.web = None

    def _run_js(self, script: str) -> None:
        if self.web is not None:
            self.web.page().runJavaScript(script)

    def update_devices(self, devices: list[WifiDevice]) -> None:
        if self.web is None:
            return
        for dev in devices:
            if not dev.has_location:
                continue
            color = self._color_for(dev)
            popup = self._popup_html(dev)
            script = "wb_upsertMarker(%s, %s, %s, %s, %s);" % (
                json.dumps(dev.mac),
                json.dumps(dev.latitude),
                json.dumps(dev.longitude),
                json.dumps(popup),
                json.dumps(color),
            )
            self._run_js(script)

    def update_self_location(self, lat: float, lon: float) -> None:
        self._run_js(f"wb_setSelfLocation({lat}, {lon});")

    def clear(self) -> None:
        self._run_js("wb_clearMarkers();")

    @staticmethod
    def _color_for(dev: WifiDevice) -> str:
        if dev.encryption == "Open":
            return "#e53935"   # red: open network, stands out
        from ..models import DeviceKind
        if dev.kind == DeviceKind.ACCESS_POINT:
            return "#1e88e5"   # blue
        return "#8e24aa"       # purple: client/other

    @staticmethod
    def _popup_html(dev: WifiDevice) -> str:
        return (
            f"<b>{dev.name}</b><br>"
            f"{dev.mac}<br>"
            f"{dev.kind.value} · {dev.standard.value}<br>"
            f"Ch {dev.channel} ({dev.band}) · {dev.encryption}<br>"
            f"RSSI: {dev.signal_dbm if dev.signal_dbm is not None else '-'} dBm"
        )
