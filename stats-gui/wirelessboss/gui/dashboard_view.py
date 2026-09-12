"""Stat-heavy overview dashboard: tiles + charts, rendered via Chart.js in an
embedded QWebEngineView (same proven approach as the Leaflet map view).

Chart.js is vendored locally (wirelessboss/assets/chartjs/) and inlined
directly into the page - no CDN, so the dashboard renders with zero
network access, same as the map."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QUrl
from PyQt6.QtWidgets import QWidget, QVBoxLayout

try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    HAVE_WEBENGINE = True
except ImportError:  # pragma: no cover
    HAVE_WEBENGINE = False

from .. import storage_stats
from ..stats import DeviceStats

_PALETTE = ["#4fc3f7", "#e53935", "#66bb6a", "#f9a825", "#ab47bc", "#26a69a", "#ff7043", "#78909c"]
_ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets" / "chartjs"


def _read_chartjs() -> str:
    path = _ASSETS_DIR / "chart.umd.js"
    if not path.exists():
        return "console.error('missing chart.umd.js asset - re-run the vendoring step');"
    return path.read_text()


_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<script>
__WB_CHARTJS__
</script>
<style>
  :root {
    --bg: #0d1420; --card: #16202e; --card-border: #223047;
    --text: #e6edf3; --muted: #8fa3bb; --accent: #4fc3f7;
    --green: #66bb6a; --amber: #f9a825; --red: #e53935;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; background: var(--bg); color: var(--text);
               font-family: -apple-system, "Segoe UI", Roboto, sans-serif; }
  body { padding: 16px; overflow-y: auto; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em;
       color: var(--muted); margin: 24px 0 10px; display: flex; align-items: center; gap: 8px; }
  h2:first-of-type { margin-top: 0; }
  h2 .hint { text-transform: none; letter-spacing: normal; font-size: 11px; color: #5b6b81; }
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
  .tile { background: var(--card); border: 1px solid var(--card-border); border-radius: 10px;
          padding: 14px 16px; }
  .tile .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
                 color: var(--muted); margin-bottom: 6px; }
  .tile .value { font-size: 26px; font-weight: 600; }
  .tile .sub { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; }
  .charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }
  .chart-card { background: var(--card); border: 1px solid var(--card-border); border-radius: 10px;
                padding: 14px 16px; }
  .chart-card .title { font-size: 13px; color: var(--muted); margin-bottom: 8px; }
  .chart-card canvas { max-height: 220px; }
  .progress { height: 8px; border-radius: 4px; background: #223047; overflow: hidden; margin-top: 8px; }
  .progress > div { height: 100%; background: var(--accent); }
  ul.rank-list { list-style: none; margin: 0; padding: 0; }
  ul.rank-list li { display: flex; justify-content: space-between; padding: 4px 0;
                      border-bottom: 1px solid var(--card-border); font-size: 13px; gap: 8px; }
  ul.rank-list li:last-child { border-bottom: none; }
  ul.rank-list .count { color: var(--muted); flex-shrink: 0; }
  ul.rank-list .name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .cards-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
  table.stat-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.stat-table th { text-align: left; color: var(--muted); font-weight: 500; font-size: 11px;
                         text-transform: uppercase; letter-spacing: 0.05em; padding: 4px 6px;
                         border-bottom: 1px solid var(--card-border); }
  table.stat-table td { padding: 6px; border-bottom: 1px solid var(--card-border); }
  table.stat-table tr:last-child td { border-bottom: none; }
  .empty-note { color: #5b6b81; font-size: 12px; font-style: italic; }
</style>
</head>
<body>

<h2>Status <span class="hint" id="t-updated"></span></h2>
<div class="tiles">
  <div class="tile"><div class="label">Kismet</div>
    <div class="value" id="t-kismet"><span class="dot" id="dot-kismet"></span>-</div></div>
  <div class="tile"><div class="label">Recording</div>
    <div class="value" id="t-capture"><span class="dot" id="dot-capture"></span>-</div>
    <div class="sub">kismetdb + pcap</div></div>
  <div class="tile"><div class="label">GPS</div>
    <div class="value" id="t-gps"><span class="dot" id="dot-gps"></span>-</div>
    <div class="sub" id="t-gps-sub"></div></div>
  <div class="tile"><div class="label">Alerts</div><div class="value" id="t-alerts">0</div></div>
</div>

<h2>Devices</h2>
<div class="tiles">
  <div class="tile"><div class="label">Total Devices</div><div class="value" id="t-total">0</div></div>
  <div class="tile"><div class="label">Access Points</div><div class="value" id="t-aps">0</div></div>
  <div class="tile"><div class="label">Clients</div><div class="value" id="t-clients">0</div></div>
  <div class="tile"><div class="label">Open Networks</div><div class="value" id="t-open">0</div></div>
  <div class="tile"><div class="label">New (5 min)</div><div class="value" id="t-new">0</div></div>
</div>

<h2>Storage</h2>
<div class="tiles">
  <div class="tile"><div class="label">kismetdb Size</div><div class="value" id="t-capsize">-</div>
    <div class="sub" id="t-capfiles"></div></div>
  <div class="tile"><div class="label">PCAP Size (Wireshark)</div><div class="value" id="t-pcapsize">-</div>
    <div class="sub" id="t-pcapfiles"></div></div>
  <div class="tile"><div class="label">Disk Free</div><div class="value" id="t-diskfree">-</div>
    <div class="progress"><div id="t-diskbar" style="width:0%"></div></div></div>
  <div class="tile"><div class="label">Capture Growth</div><div class="value" id="t-growth">-</div></div>
  <div class="tile"><div class="label">Time to Full</div><div class="value" id="t-eta">-</div></div>
</div>

<h2>Breakdown</h2>
<div class="charts">
  <div class="chart-card"><div class="title">Device Type</div><canvas id="c-kind"></canvas></div>
  <div class="chart-card"><div class="title">Wireless Standard</div><canvas id="c-standard"></canvas></div>
  <div class="chart-card"><div class="title">Band</div><canvas id="c-band"></canvas></div>
  <div class="chart-card"><div class="title">Encryption</div><canvas id="c-encryption"></canvas></div>
  <div class="chart-card"><div class="title">Signal Strength (RSSI)</div><canvas id="c-rssi"></canvas></div>
</div>

<h2>Channel Utilization</h2>
<div class="charts">
  <div class="chart-card"><div class="title">2.4GHz Channels</div><canvas id="c-ch24"></canvas></div>
  <div class="chart-card"><div class="title">5GHz / 6GHz Channels</div><canvas id="c-ch5"></canvas></div>
</div>

<h2>Manufacturers by Category</h2>
<div class="cards-grid" id="manuf-by-kind"></div>

<h2>Wireless Standards <span class="hint">theoretical PHY ceiling, not measured throughput</span></h2>
<div class="chart-card">
  <table class="stat-table" id="speed-table">
    <thead><tr><th>Standard</th><th>Devices</th><th>Theoretical Max</th></tr></thead>
    <tbody></tbody>
  </table>
</div>

<h2>Top Access Points by Client Count</h2>
<div class="chart-card">
  <ul class="rank-list" id="top-aps"></ul>
</div>

<script>
const PALETTE = __WB_PALETTE_JSON__;
Chart.defaults.color = '#8fa3bb';
Chart.defaults.borderColor = '#223047';

const charts = {};

function ensureDonut(id) {
  if (charts[id]) return charts[id];
  const ctx = document.getElementById(id).getContext('2d');
  charts[id] = new Chart(ctx, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE, borderWidth: 0 }] },
    options: { plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 10 } } } } }
  });
  return charts[id];
}

function ensureBar(id, horizontal) {
  if (charts[id]) return charts[id];
  const ctx = document.getElementById(id).getContext('2d');
  charts[id] = new Chart(ctx, {
    type: 'bar',
    data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE[0] }] },
    options: {
      indexAxis: horizontal ? 'y' : 'x',
      plugins: { legend: { display: false } },
      scales: { x: { grid: { color: '#1c2635' } }, y: { grid: { color: '#1c2635' }, beginAtZero: true, ticks: { precision: 0 } } }
    }
  });
  return charts[id];
}

function setDonutData(id, obj) {
  const chart = ensureDonut(id);
  chart.data.labels = Object.keys(obj);
  chart.data.datasets[0].data = Object.values(obj);
  chart.update('none');
}

function setBarData(id, labels, values, horizontal) {
  const chart = ensureBar(id, horizontal);
  chart.data.labels = labels;
  chart.data.datasets[0].data = values;
  chart.update('none');
}

function setDot(elId, color) {
  document.getElementById(elId).style.background = color;
}

function renderRankList(elId, pairs, emptyText) {
  const el = document.getElementById(elId);
  el.innerHTML = '';
  if (!pairs || pairs.length === 0) {
    el.innerHTML = '<li class="empty-note">' + emptyText + '</li>';
    return;
  }
  pairs.forEach(function(pair) {
    const li = document.createElement('li');
    li.innerHTML = '<span class="name">' + pair[0] + '</span><span class="count">' + pair[1] + '</span>';
    el.appendChild(li);
  });
}

function wb_update(data) {
  document.getElementById('t-updated').textContent = data.last_updated ? ('updated ' + data.last_updated) : '';

  document.getElementById('t-kismet').innerHTML =
    '<span class="dot" id="dot-kismet"></span>' + (data.kismet_connected ? 'Connected' : 'Unreachable');
  setDot('dot-kismet', data.kismet_connected ? 'var(--green)' : 'var(--red)');

  document.getElementById('t-capture').innerHTML =
    '<span class="dot" id="dot-capture"></span>' + (data.capture_running ? 'Recording' : 'Stopped');
  setDot('dot-capture', data.capture_running ? 'var(--green)' : 'var(--muted)');

  document.getElementById('t-gps').innerHTML =
    '<span class="dot" id="dot-gps"></span>' + (data.gps_fix ? (data.gps_fix_type || 'Fix') : 'No fix');
  setDot('dot-gps', data.gps_fix ? 'var(--green)' : 'var(--amber)');
  document.getElementById('t-gps-sub').textContent = data.gps_sub || '';

  document.getElementById('t-alerts').textContent = data.alerts;

  document.getElementById('t-total').textContent = data.total;
  document.getElementById('t-aps').textContent = data.access_points;
  document.getElementById('t-clients').textContent = data.clients;
  document.getElementById('t-open').textContent = data.open_networks;
  document.getElementById('t-new').textContent = data.new_devices;

  document.getElementById('t-capsize').textContent = data.capture_size;
  document.getElementById('t-capfiles').textContent = data.capture_files;
  document.getElementById('t-pcapsize').textContent = data.pcap_size;
  document.getElementById('t-pcapfiles').textContent = data.pcap_files;
  document.getElementById('t-diskfree').textContent = data.disk_free;
  document.getElementById('t-diskbar').style.width = data.disk_used_pct + '%';
  document.getElementById('t-growth').textContent = data.growth_rate;
  document.getElementById('t-eta').textContent = data.eta;

  setDonutData('c-kind', data.kind_counts);
  setBarData('c-standard', Object.keys(data.standard_counts), Object.values(data.standard_counts), false);
  setDonutData('c-band', data.band_counts);
  setDonutData('c-encryption', data.encryption_counts);
  setBarData('c-rssi', data.rssi_labels, data.rssi_values, false);

  setBarData('c-ch24', data.channels_24.map(p => p[0]), data.channels_24.map(p => p[1]), false);
  setBarData('c-ch5', data.channels_5_6.map(p => p[0]), data.channels_5_6.map(p => p[1]), false);

  const mbk = document.getElementById('manuf-by-kind');
  mbk.innerHTML = '';
  const kinds = Object.keys(data.manuf_by_kind);
  if (kinds.length === 0) {
    mbk.innerHTML = '<div class="chart-card"><span class="empty-note">No manufacturer data yet.</span></div>';
  } else {
    kinds.forEach(function(kind) {
      const card = document.createElement('div');
      card.className = 'chart-card';
      const title = document.createElement('div');
      title.className = 'title';
      title.textContent = kind;
      card.appendChild(title);
      const ul = document.createElement('ul');
      ul.className = 'rank-list';
      const id = 'manuf-' + kind.replace(/[^a-zA-Z0-9]/g, '-');
      ul.id = id;
      card.appendChild(ul);
      mbk.appendChild(card);
      renderRankList(id, data.manuf_by_kind[kind], 'No manufacturer data');
    });
  }

  const speedBody = document.querySelector('#speed-table tbody');
  speedBody.innerHTML = '';
  if (data.speed_table.length === 0) {
    speedBody.innerHTML = '<tr><td colspan="3" class="empty-note">No devices with a known standard yet.</td></tr>';
  } else {
    data.speed_table.forEach(function(row) {
      const tr = document.createElement('tr');
      const maxTxt = row[2] ? (row[2] + ' Mbps') : 'unknown';
      tr.innerHTML = '<td>' + row[0] + '</td><td>' + row[1] + '</td><td>' + maxTxt + '</td>';
      speedBody.appendChild(tr);
    });
  }

  renderRankList('top-aps', data.top_aps_by_clients.map(r => [r[0] + ' (' + r[1] + ')', r[2]]),
                  'No access points with associated clients yet.');
}
</script>
</body>
</html>
"""


class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        if HAVE_WEBENGINE:
            self.web = QWebEngineView()
            # .replace(), not %-formatting: the template's CSS/JS (and the
            # inlined Chart.js source) is full of literal "%"/"{"/"}"
            # characters that %-formatting or str.format() would misparse.
            html = (
                _HTML_TEMPLATE
                .replace("__WB_CHARTJS__", _read_chartjs())
                .replace("__WB_PALETTE_JSON__", json.dumps(_PALETTE))
            )
            self.web.setHtml(html, QUrl("https://wirelessboss.local/"))
            layout.addWidget(self.web)
        else:  # pragma: no cover
            from PyQt6.QtWidgets import QLabel
            layout.addWidget(QLabel(
                "Dashboard unavailable: PyQt6-WebEngine is not installed.\n"
                "On Kali: sudo apt install python3-pyqt6.qtwebengine"
            ))
            self.web = None

    def update_stats(
        self,
        stats: DeviceStats,
        storage: "storage_stats.StorageStats",
        kismet_connected: bool,
        capture_running: bool,
        gps_fix: bool,
        gps_fix_type: str,
        gps_sub: str,
        alerts_count: int,
    ) -> None:
        if self.web is None:
            return

        disk_used_pct = 0.0
        if storage.disk_total_bytes:
            disk_used_pct = round(100 * storage.disk_used_bytes / storage.disk_total_bytes, 1)

        payload = {
            "last_updated": datetime.now().strftime("%H:%M:%S"),
            "kismet_connected": kismet_connected,
            "capture_running": capture_running,
            "gps_fix": gps_fix,
            "gps_fix_type": gps_fix_type,
            "gps_sub": gps_sub,
            "alerts": alerts_count,
            "total": stats.total,
            "access_points": stats.access_points,
            "clients": stats.clients,
            "open_networks": stats.open_networks,
            "new_devices": stats.new_devices,
            "capture_size": storage_stats.fmt_bytes(storage.capture_bytes),
            "capture_files": f"{storage.file_count} file(s)",
            "pcap_size": storage_stats.fmt_bytes(storage.pcap_bytes),
            "pcap_files": f"{storage.pcap_file_count} file(s)",
            "disk_free": storage_stats.fmt_bytes(storage.disk_free_bytes),
            "disk_used_pct": disk_used_pct,
            "growth_rate": (
                storage_stats.fmt_bytes(storage.growth_bytes_per_sec) + "/s"
                if storage.growth_bytes_per_sec else "N/A"
            ),
            "eta": storage_stats.fmt_duration(storage.eta_seconds),
            "kind_counts": stats.kind_counts,
            "standard_counts": stats.standard_counts,
            "band_counts": stats.band_counts,
            "encryption_counts": stats.encryption_counts,
            "rssi_labels": [label for label, _ in stats.rssi_histogram],
            "rssi_values": [count for _, count in stats.rssi_histogram],
            "manuf_by_kind": stats.manuf_by_kind,
            "channels_24": stats.channels_24,
            "channels_5_6": stats.channels_5_6,
            "speed_table": stats.speed_table,
            "top_aps_by_clients": stats.top_aps_by_clients,
        }
        self.web.page().runJavaScript(f"wb_update({json.dumps(payload)});")
