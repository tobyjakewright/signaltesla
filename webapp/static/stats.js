(function () {
  "use strict";

  const tabs = document.querySelectorAll(".tab");
  const views = document.querySelectorAll(".view");
  tabs.forEach((tab) =>
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.setAttribute("aria-selected", String(t === tab)));
      views.forEach((v) => v.toggleAttribute("data-active", v.dataset.view === tab.dataset.tab));
    })
  );

  function timeAgo(unixSeconds) {
    if (!unixSeconds) return "-";
    const seconds = Math.max(0, Math.floor(Date.now() / 1000 - unixSeconds));
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    return `${Math.floor(seconds / 3600)}h ago`;
  }

  function cell(text) {
    const td = document.createElement("td");
    td.textContent = text === undefined || text === null || text === "" ? "-" : text;
    return td;
  }

  // Shared by refreshStatus/refreshWifi so both can update their own slice
  // of the stat tiles without one clobbering the other - wifi_device_count/
  // ap_count/client_count are derived client-side from the SAME device
  // list /api/wifi-devices already fetches, rather than /api/status paying
  // for its own separate (expensive) Kismet device query for the same
  // numbers every poll.
  const latestStats = {
    kismet_reachable: false,
    wifi_device_count: 0,
    ap_count: 0,
    client_count: 0,
    ble_device_count: 0,
    gps: null,
  };

  function renderStatTiles() {
    const gps = latestStats.gps;
    const gpsText = gps && gps.fix_quality >= 2
      ? `${gps.fix_quality === 3 ? "3D" : "2D"} fix - ${gps.satellites} sats`
      : "No fix";
    const tiles = [
      ["Kismet", latestStats.kismet_reachable ? "Connected" : "Unreachable"],
      ["Wi-Fi Devices", latestStats.wifi_device_count],
      ["Access Points", latestStats.ap_count],
      ["Clients", latestStats.client_count],
      ["BLE Devices", latestStats.ble_device_count],
      ["GPS", gpsText],
    ];
    const grid = document.getElementById("stat-tiles");
    grid.innerHTML = "";
    for (const [label, value] of tiles) {
      const tile = document.createElement("div");
      tile.className = "stat-tile";
      const v = document.createElement("div");
      v.className = "stat-value";
      v.textContent = value;
      const l = document.createElement("div");
      l.className = "stat-label";
      l.textContent = label;
      tile.append(v, l);
      grid.appendChild(tile);
    }
  }

  async function refreshStatus() {
    try {
      const r = await fetch("/api/status");
      const s = await r.json();
      latestStats.kismet_reachable = s.kismet_reachable;
      latestStats.ble_device_count = s.ble_device_count;
      latestStats.gps = s.gps;
      renderStatTiles();
    } catch (e) {
      /* Kismet or the network hiccuping shouldn't spam the console every poll. */
    }
  }

  async function refreshWifi() {
    try {
      const r = await fetch("/api/wifi-devices");
      const devices = await r.json();
      latestStats.wifi_device_count = devices.length;
      latestStats.ap_count = devices.filter((d) => d.kind === "Access Point").length;
      latestStats.client_count = devices.filter((d) => d.kind === "Client").length;
      renderStatTiles();

      const tbody = document.querySelector("#wifi-table tbody");
      tbody.innerHTML = "";
      for (const d of devices) {
        const tr = document.createElement("tr");
        tr.append(
          cell(d.name),
          cell(d.mac),
          cell(d.kind),
          cell(d.standard),
          cell(`${d.band || "-"} / ${d.channel || "-"}`),
          cell(d.encryption),
          cell(d.signal_dbm !== null ? `${d.signal_dbm} dBm` : "-"),
          cell(d.client_count),
          cell(timeAgo(d.last_seen))
        );
        tbody.appendChild(tr);
      }
      document.getElementById("wifi-empty").hidden = devices.length > 0;
    } catch (e) {
      /* transient - next poll will retry */
    }
  }

  async function refreshBle() {
    try {
      const r = await fetch("/api/ble-devices");
      const devices = await r.json();
      const tbody = document.querySelector("#ble-table tbody");
      tbody.innerHTML = "";
      for (const d of devices) {
        const tr = document.createElement("tr");
        tr.append(
          cell(d.name),
          cell(d.address),
          cell(d.manufacturer),
          cell(d.rssi !== null ? `${d.rssi} dBm` : "-"),
          cell(d.channel),
          cell(timeAgo(d.last_seen))
        );
        tbody.appendChild(tr);
      }
      document.getElementById("ble-empty").hidden = devices.length > 0;
    } catch (e) {
      /* transient - next poll will retry */
    }
  }

  async function refreshAlerts() {
    try {
      const r = await fetch("/api/alerts");
      const alerts = await r.json();
      const list = document.getElementById("alert-list");
      list.innerHTML = "";
      for (const a of alerts.slice(-50).reverse()) {
        const li = document.createElement("li");
        const header = a.header || a["kismet.alert.header"] || "Alert";
        const text = a.text || a["kismet.alert.text"] || "";
        li.textContent = text ? `${header}: ${text}` : header;
        list.appendChild(li);
      }
      document.getElementById("alerts-empty").hidden = alerts.length > 0;
    } catch (e) {
      /* transient - next poll will retry */
    }
  }

  function refreshAll() {
    refreshStatus();
    refreshWifi();
    refreshBle();
    refreshAlerts();
  }

  refreshAll();
  setInterval(refreshAll, 5000);
})();
