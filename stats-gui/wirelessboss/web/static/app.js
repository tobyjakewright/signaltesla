const PALETTE = ["#99B968", "#C3AA6B", "#E1554E", "#8D73CF", "#A7C96C"];
const KIND_ORDER = ["Access Point", "Client", "Ad-Hoc", "Bridge", "Unknown"];
const BAND_ORDER = ["2.4GHz", "5GHz", "6GHz"];
const TAB_TITLES = {
  dashboard: "Dashboard", devices: "Devices", map: "Map", alerts: "Alerts",
  ble: "BLE Analysis", signal: "Signal Analysis", tools: "Wi-Fi Lab",
};
const THEME_KEY = "wirelessboss-theme";

let devices = [];
let stats = emptyStats();
let storage = {};
let status = {};
let alerts = [];
let paused = false;
let selectedMac = null;
let sortKey = "name", sortDir = 1;
let mapInited = false, map = null, markers = {}, selfMarker = null, haveFirstFix = false;
let statsHistory = [];    // {ts, total, access_points, clients, open_networks}
let activityHistory = []; // {ts, total} - total packets across all devices

let bleStatus = {}, bleStats = {}, bleDevices = [], blePackets = [];
let blePaused = false, blePacketAfter = 0, selectedBleAddress = null, bleRequestGeneration = 0;
let signalStatus = {}, signalPackets = [];
let signalPaused = false, signalPacketAfter = 0, selectedSignalSeq = null;
let signalSourceGeneration = 0, signalCapturePausedSource = null, signalActionPending = false, pollLoopRunning = false;

const BLE_CHANNEL_COLORS = { 37: "#99b968", 38: "#c3aa6b", 39: "#8d73cf" };
const PACKET_PURPOSES = {
  ADV_IND: "Connectable, scannable advertisement announcing a device",
  ADV_DIRECT_IND: "Directed advertisement intended for one known peer",
  ADV_NONCONN_IND: "Broadcast-only advertisement; no connection requested",
  ADV_SCAN_IND: "Scannable advertisement that does not accept a connection",
  SCAN_REQ: "Scanner asks an advertiser for more information",
  SCAN_RSP: "Advertiser replies with extra name or service data",
  CONNECT_IND: "Central requests a BLE connection and supplies timing parameters",
  CONNECT_REQ: "Central requests a BLE connection and supplies timing parameters",
  AUX_ADV_IND: "Extended advertising points to data on a secondary channel",
  AUX_CONNECT_REQ: "Connection request sent as part of extended advertising",
  LL_EMPTY: "Empty connected-data packet; acknowledges traffic without carrying a new payload",
  LL_CONTINUATION: "Continuation fragment of an L2CAP message, or an empty Link Layer acknowledgement",
  LL_DATA: "Link Layer data within an established connection",
  LL_RESERVED: "Reserved Link Layer data-channel packet type",
  LL_CONTROL: "Link Layer control packet that manages the active connection",
  LL_CONNECTION_UPDATE_IND: "Changes connection timing at a scheduled connection event",
  LL_CHANNEL_MAP_IND: "Replaces the connection's data-channel map at a scheduled event",
  LL_TERMINATE_IND: "Ends the BLE connection and supplies a reason code",
  LL_ENC_REQ: "Central supplies its encryption material and requests an encrypted link",
  LL_ENC_RSP: "Peripheral supplies its part of the encryption material",
  LL_START_ENC_REQ: "Requests the transition to encrypted Link Layer traffic",
  LL_START_ENC_RSP: "Confirms the transition to encrypted Link Layer traffic",
  LL_UNKNOWN_RSP: "Reports that the peer did not recognise a Link Layer control opcode",
  LL_FEATURE_REQ: "Central asks which Link Layer features the peer supports",
  LL_FEATURE_RSP: "Reports the Link Layer features this peer supports",
  LL_PAUSE_ENC_REQ: "Requests a temporary pause in Link Layer encryption",
  LL_PAUSE_ENC_RSP: "Acknowledges a temporary pause in Link Layer encryption",
  LL_VERSION_IND: "Reports Link Layer version, company, and implementation information",
  LL_REJECT_IND: "Rejects the most recent control procedure with a reason code",
  LL_PERIPHERAL_FEATURE_REQ: "Peripheral asks which Link Layer features the central supports",
  LL_CONNECTION_PARAM_REQ: "Proposes new connection timing parameters",
  LL_CONNECTION_PARAM_RSP: "Replies to a connection-parameter proposal",
  LL_REJECT_EXT_IND: "Rejects a named control procedure with a reason code",
  LL_PING_REQ: "Checks that an encrypted connection is still responsive",
  LL_PING_RSP: "Replies to a Link Layer ping",
  LL_LENGTH_REQ: "Proposes maximum connected-data length and transmission time",
  LL_LENGTH_RSP: "Replies with maximum connected-data length and transmission time",
  LL_PHY_REQ: "Proposes PHY choices for the connected link",
  LL_PHY_RSP: "Replies with supported PHY choices",
  LL_PHY_UPDATE_IND: "Schedules a connected-link PHY change",
  LL_MIN_USED_CHANNELS_IND: "Reports the minimum number of data channels the peer should use",
  LL_CTE_REQ: "Requests a constant-tone extension for direction finding",
  LL_CTE_RSP: "Replies to a constant-tone-extension request",
  LL_PERIODIC_SYNC_IND: "Transfers periodic-advertising synchronization over the connection",
  LL_CLOCK_ACCURACY_REQ: "Requests a sleep-clock-accuracy update",
  LL_CLOCK_ACCURACY_RSP: "Reports updated sleep-clock accuracy",
  LL_CIS_REQ: "Proposes a connected isochronous stream",
  LL_CIS_RSP: "Replies to a connected isochronous stream proposal",
  LL_CIS_IND: "Schedules a connected isochronous stream",
  LL_CIS_TERMINATE_IND: "Terminates a connected isochronous stream",
  LL_POWER_CONTROL_REQ: "Requests connected-link transmit-power changes",
  LL_POWER_CONTROL_RSP: "Replies with connected-link power-control information",
  LL_POWER_CHANGE_IND: "Reports a connected-link transmit-power change",
  DATA: "Payload or control data within an established connection",
  BEACON: "Wi-Fi access point announces its network and capabilities",
  PROBE_REQ: "Wi-Fi client asks which networks are nearby",
  PROBE_RESP: "Wi-Fi access point answers a probe request",
  AUTH: "Wi-Fi authentication management exchange",
  ASSOC_REQ: "Wi-Fi client requests association with an access point",
  ASSOC_RESP: "Wi-Fi access point accepts or rejects association",
  DEAUTH: "Wi-Fi management frame ends an authenticated relationship",
  EAPOL: "Wi-Fi key-management message, often part of a WPA handshake",
};

function emptyStats() {
  return {
    total: 0, access_points: 0, clients: 0, other: 0, open_networks: 0, new_devices: 0,
    kind_counts: {}, standard_counts: {}, band_counts: {}, encryption_counts: {},
    top_manufacturers: [], rssi_histogram: [], manuf_by_kind: {}, channels_24: [],
    channels_5_6: [], speed_table: [], top_aps_by_clients: [],
  };
}

// ---- helpers ------------------------------------------------------------

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s === undefined || s === null ? "" : String(s);
  return d.innerHTML;
}

function fmtBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0; n = Math.abs(n);
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(1) + " " + units[i];
}

function fmtDuration(s) {
  if (s === null || s === undefined || s <= 0) return "N/A";
  if (s < 60) return Math.round(s) + "s";
  const m = s / 60;
  if (m < 60) return Math.round(m) + "m";
  const h = m / 60;
  if (h < 48) return h.toFixed(1) + "h";
  return (h / 24).toFixed(1) + "d";
}

function fmtHMS(s) {
  if (s === null || s === undefined) return "-";
  s = Math.floor(s);
  const h = String(Math.floor(s / 3600)).padStart(2, "0");
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const sec = String(s % 60).padStart(2, "0");
  return `${h}:${m}:${sec}`;
}

function fmtCount(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
  return String(n);
}

function fmtTime(ts, withDate) {
  if (!ts) return "-";
  const d = new Date(ts * 1000);
  return withDate ? d.toLocaleString() : d.toLocaleTimeString();
}

function dateFromAny(value) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number") return new Date(value > 1e12 ? value : value * 1000);
  if (/^\d+(\.\d+)?$/.test(String(value))) {
    const n = Number(value);
    return new Date(n > 1e12 ? n : n * 1000);
  }
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function fmtPacketTime(value, withDate) {
  const d = dateFromAny(value);
  if (!d) return "-";
  const base = withDate ? d.toLocaleString() : d.toLocaleTimeString([], { hour12: false });
  return withDate ? base : `${base}.${String(d.getMilliseconds()).padStart(3, "0")}`;
}

function fmtLastSeen(value) {
  const d = dateFromAny(value);
  if (!d) return "-";
  const sec = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (sec < 4) return "now";
  if (sec < 60) return `${Math.round(sec)}s ago`;
  if (sec < 3600) return `${Math.round(sec / 60)}m ago`;
  return d.toLocaleString();
}

function arrayFromPayload(payload, key) {
  if (Array.isArray(payload)) return payload;
  if (payload && Array.isArray(payload[key])) return payload[key];
  return [];
}

async function fetchJSON(url, options) {
  const r = await fetch(url, options);
  let body = {};
  try { body = await r.json(); } catch (_) { /* an empty response is still handled below */ }
  if (!r.ok) throw new Error(body.message || body.error || `${r.status} ${r.statusText}`);
  return body;
}

function queryString(params) {
  const q = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && String(v).trim() !== "") q.set(k, v);
  });
  return q.toString();
}

function packetType(packet) {
  const type = String(packet.type || packet.subtype || "");
  const protocol = String(packet.protocol || "");
  const genericProtocols = new Set(["", "BLE", "802.11", "WLAN"]);
  if (type && !genericProtocols.has(protocol.toUpperCase()) && protocol.toUpperCase() !== type.toUpperCase()) {
    return `${protocol} · ${type}`;
  }
  return type || protocol || "Unknown";
}

function packetPurpose(packet) {
  if (packet.purpose) return String(packet.purpose);
  const key = packetType(packet).toUpperCase().split("·").pop().trim().replace(/[ -]+/g, "_");
  return PACKET_PURPOSES[key] || "Protocol packet; select it to inspect the decoded fields";
}

function packetDirection(packet) {
  const directionCode = Number(packet.direction_code);
  const source = packet.direction_name || (Number.isFinite(directionCode) && directionCode > 0 ? directionCode : packet.direction);
  const raw = String(source ?? "").trim().toLowerCase();
  if (["1", "initiator_to_advertiser", "initiator to advertiser", "central_to_peripheral", "central to peripheral"].includes(raw)) {
    return "Central → peripheral";
  }
  if (["2", "advertiser_to_initiator", "advertiser to initiator", "peripheral_to_central", "peripheral to central"].includes(raw)) {
    return "Peripheral → central";
  }
  if (raw && !["0", "unknown", "none", "null"].includes(raw)) return raw.replaceAll("_", " ");
  return "Unknown";
}

function isBlePacket(packet) {
  return String(packet.protocol || "").toUpperCase() === "BLE" || !!packet.link_layer || !!packet.access_address ||
    /^(?:ADV|SCAN|CONNECT|AUX_|LL_)/.test(String(packet.type || packet.type_name || "").toUpperCase());
}

function packetSecurity(packet) {
  const details = packet.details && typeof packet.details === "object" ? packet.details : {};
  const isTrue = value => value === true || value === 1 || ["true", "yes", "valid", "decrypted"].includes(String(value || "").toLowerCase());
  const decrypted = isTrue(packet.decrypted) || isTrue(packet.is_decrypted) || isTrue(details.decrypted);
  const encrypted = decrypted || isTrue(packet.encrypted) || isTrue(packet.is_encrypted) || isTrue(packet.encrypted_payload) || isTrue(details.encrypted) ||
    String(packet.encrypted || "").toLowerCase() === "encrypted" ||
    String(packet.encryption || "").toLowerCase() === "encrypted";
  const micValid = isTrue(packet.mic_valid) || isTrue(details.mic_valid);
  if (decrypted) return { label: micValid ? "Decrypted · MIC valid" : "Decrypted", cls: "decrypted" };
  if (encrypted) return { label: "Encrypted", cls: "encrypted" };
  return { label: isBlePacket(packet) ? "Plain" : "—", cls: "plain" };
}

function securityChip(packet) {
  const security = packetSecurity(packet);
  return `<span class="security-chip ${security.cls}">${esc(security.label)}</span>`;
}

function yesNoUnknown(value) {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return "Unknown";
}

function mergePackets(existing, incoming, limit) {
  const byKey = new Map();
  [...existing, ...incoming].forEach((p, i) => {
    const key = p.seq !== undefined && p.seq !== null
      ? `s:${p.seq}`
      : `p:${p.ts || ""}:${p.src || ""}:${p.dst || ""}:${p.type || ""}:${p.raw_hex || p.pdu_hex || ""}:${i}`;
    byKey.set(key, p);
  });
  return [...byKey.values()].sort((a, b) => {
    const av = Number(a.seq), bv = Number(b.seq);
    if (Number.isFinite(av) && Number.isFinite(bv)) return av - bv;
    return (dateFromAny(a.ts)?.getTime() || 0) - (dateFromAny(b.ts)?.getTime() || 0);
  }).slice(-limit);
}

function latestSequence(packets, fallback) {
  return packets.reduce((max, p) => {
    const n = Number(p.seq);
    return Number.isFinite(n) ? Math.max(max, n) : max;
  }, fallback || 0);
}

function objToPairs(obj) {
  return Object.entries(obj || {}).sort((a, b) => b[1] - a[1]);
}

function rssiClass(v) {
  if (v === null || v === undefined) return "";
  if (v >= -50) return "rssi-strong";
  if (v >= -70) return "rssi-med";
  return "rssi-weak";
}

function signalBarsHTML(dbm) {
  let cls = "s1";
  if (dbm >= -50) cls = "s4";
  else if (dbm >= -65) cls = "s3";
  else if (dbm >= -80) cls = "s2";
  return `<span class="signal-bars ${cls}"><i></i><i></i><i></i><i></i></span>`;
}

function showToast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => { el.hidden = true; }, 4000);
}

function applyTheme(theme) {
  const selected = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = selected;
  const btn = document.getElementById("btn-theme");
  if (btn) {
    const isLight = selected === "light";
    const label = isLight ? "Switch to dark theme" : "Switch to light theme";
    btn.setAttribute("aria-pressed", String(isLight));
    btn.setAttribute("aria-label", label);
    btn.title = label;
  }
}

function initTheme() {
  let saved = "dark";
  try {
    saved = localStorage.getItem(THEME_KEY) || "dark";
  } catch (_) { /* private browsing can disable localStorage */ }
  applyTheme(saved);
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  applyTheme(next);
  try { localStorage.setItem(THEME_KEY, next); } catch (_) { /* preference remains for this tab */ }
}

// ---- dashboard chart helpers ---------------------------------------------

function donutSVG(pairs) {
  const total = pairs.reduce((s, [, v]) => s + v, 0) || 1;
  const r = 15.9155, circ = 100, sw = 4.5;
  // Two of the specified colors (olive/khaki) sit close enough in hue that
  // adjacent segments blend into one blob without an explicit boundary -
  // inset each segment slightly so a sliver of the track color always
  // separates it from its neighbors, regardless of how close the hues are.
  const gap = pairs.length > 1 ? 1.4 : 0;
  let cursor = 0;
  let circles = `<circle cx="18" cy="18" r="${r}" fill="none" stroke="var(--border)" stroke-width="${sw}"/>`;
  pairs.forEach(([, v], i) => {
    const pct = (v / total) * 100;
    const visible = Math.max(pct - gap, 0.3);
    const inset = (pct - visible) / 2;
    const offset = circ - (cursor + inset);
    circles += `<circle cx="18" cy="18" r="${r}" fill="none" stroke="${PALETTE[i % PALETTE.length]}" ` +
      `stroke-width="${sw}" stroke-linecap="round" ` +
      `stroke-dasharray="${visible.toFixed(2)} ${(circ - visible).toFixed(2)}" ` +
      `stroke-dashoffset="${offset.toFixed(2)}" transform="rotate(-90 18 18)"/>`;
    cursor += pct;
  });
  return `<svg viewBox="0 0 36 36" width="112" height="112" style="flex-shrink:0">${circles}</svg>`;
}

function donutLegend(pairs) {
  const total = pairs.reduce((s, [, v]) => s + v, 0) || 1;
  return "<ul class=\"donut-legend\">" + pairs.map(([label, v], i) => {
    const pct = Math.round((v / total) * 100);
    return `<li><span class="swatch" style="background:${PALETTE[i % PALETTE.length]}"></span>` +
      `<span class="name">${esc(label)}</span><span class="num">${v} (${pct}%)</span></li>`;
  }).join("") + "</ul>";
}

function donutBlock(pairs) {
  if (!pairs.length) return emptyNote();
  return `<div class="donut-row">${donutSVG(pairs)}${donutLegend(pairs)}</div>`;
}

function barChart(pairs) {
  if (!pairs.length) return emptyNote();
  const max = Math.max(...pairs.map(([, v]) => v), 1);
  return "<div class=\"bar-chart\">" + pairs.map(([label, v]) =>
    `<div class="bar-row"><span class="bl">${esc(label)}</span>` +
    `<div class="bar-track"><div class="bar-fill" style="width:${((v / max) * 100).toFixed(0)}%"></div></div>` +
    `<span class="bv">${v}</span></div>`
  ).join("") + "</div>";
}

function chartCard(title, inner) {
  return `<div class="chart-card"><div class="title">${esc(title)}</div>${inner}</div>`;
}
function emptyNote() { return '<span class="empty-note">No data yet.</span>'; }
function rankItem(name, count) { return `<li><span class="name">${esc(name)}</span><span class="count">${count}</span></li>`; }
const TILE_ICONS = {
  devices: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="5" y="3" width="14" height="18" rx="2"/><path d="M8 7h8M8 10h5M8 14h3M15 14h1M8 17h3M15 17h1"/></svg>',
  wifi: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><path d="M3 8.5a14 14 0 0 1 18 0M6.5 12a9 9 0 0 1 11 0M10 15.5a4 4 0 0 1 4 0"/><circle cx="12" cy="19" r="1" fill="currentColor" stroke="none"/></svg>',
  clients: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="9" cy="8" r="3"/><path d="M3.5 19v-1.5A4.5 4.5 0 0 1 8 13h2a4.5 4.5 0 0 1 4.5 4.5V19M16 6.5a3 3 0 0 1 0 5.8M17 14a4 4 0 0 1 3.5 4v1"/></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></svg>',
  clock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></svg>',
};
function tile(label, value, opts) {
  opts = opts || {};
  const icon = TILE_ICONS[opts.icon] || TILE_ICONS.devices;
  return `<div class="tile"><div class="tile-icon${opts.danger ? " danger" : ""}">${icon}</div><div class="tile-copy">` +
    `<div class="label">${esc(label)}</div><div class="value"${opts.style ? ` style="${opts.style}"` : ""}>${esc(value)}</div>` +
    (opts.trend || "") + `</div></div>`;
}
function cell(k, v) { return `<div class="cell"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`; }

// ---- trend deltas (stat tiles) ---------------------------------------

function updateStatsHistory() {
  const now = Date.now();
  statsHistory.push({
    ts: now, total: stats.total, access_points: stats.access_points,
    clients: stats.clients, open_networks: stats.open_networks, new_devices: stats.new_devices,
  });
  const cutoff = now - 5 * 60 * 1000;
  statsHistory = statsHistory.filter(p => p.ts >= cutoff);
}

function trendHTML(key) {
  if (statsHistory.length < 2) return "";
  const baseline = statsHistory[0][key];
  const current = stats[key];
  let pct, dir;
  if (baseline === 0 && current === 0) { pct = 0; dir = "flat"; }
  else if (baseline === 0) { pct = 100; dir = "up"; }
  else { pct = Math.round(((current - baseline) / baseline) * 100); dir = pct > 0 ? "up" : pct < 0 ? "down" : "flat"; }
  const arrow = dir === "up" ? "↑" : dir === "down" ? "↓" : "→";
  return `<div class="trend ${dir}">${arrow} ${Math.abs(pct)}% vs last 5 min</div>`;
}

// ---- live capture activity sparkline -----------------------------------

function updateActivityHistory() {
  const totalPackets = devices.reduce((s, d) => s + (d.packets || 0), 0);
  const now = Date.now();
  activityHistory.push({ ts: now, total: totalPackets });
  const cutoff = now - 60000;
  activityHistory = activityHistory.filter(p => p.ts >= cutoff);
}

function renderActivity() {
  const el = document.getElementById("d-activity");
  if (activityHistory.length < 2) { el.innerHTML = '<span class="empty-note">Collecting data...</span>'; return; }
  const deltas = [];
  for (let i = 1; i < activityHistory.length; i++) {
    deltas.push(Math.max(0, activityHistory[i].total - activityHistory[i - 1].total));
  }
  const max = Math.max(...deltas, 1);
  const w = 600, h = 140, n = deltas.length;
  const stepX = n > 1 ? w / (n - 1) : w;
  const points = deltas.map((v, i) => [i * stepX, h - (v / max) * (h - 10) - 5]);
  const pathLine = points.map((p, i) => (i === 0 ? "M" : "L") + p[0].toFixed(1) + "," + p[1].toFixed(1)).join(" ");
  const pathArea = pathLine + ` L${points[points.length - 1][0].toFixed(1)},${h} L0,${h} Z`;
  const yTicks = [max, Math.round((max * 2) / 3), Math.round(max / 3), 0];
  el.innerHTML = `
    <div class="sparkline-wrap">
      <div class="sparkline-yaxis">${yTicks.map(t => `<span>${fmtCount(t)}</span>`).join("")}</div>
      <div class="sparkline-plot">
        <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
          <defs><linearGradient id="wb-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#748754" stop-opacity="0.45"/>
            <stop offset="100%" stop-color="#748754" stop-opacity="0"/>
          </linearGradient></defs>
          <path d="${pathArea}" fill="url(#wb-grad)" stroke="none"/>
          <path d="${pathLine}" fill="none" stroke="#748754" stroke-width="2"/>
        </svg>
        <div class="sparkline-axis"><span>-60s</span><span>-40s</span><span>-20s</span><span>Now</span></div>
      </div>
    </div>`;
}

// ---- rendering ------------------------------------------------------------

function renderStatusChips() {
  const kismetDot = document.getElementById("sb-dot-kismet");
  kismetDot.className = "dot " + (status.kismet_connected ? "ok" : "bad");
  document.getElementById("sb-kismet").textContent = status.kismet_connected ? "Kismet Connected" : "Kismet Unreachable";

  const gpsDot = document.getElementById("sb-dot-gps");
  gpsDot.className = "dot " + (status.gps_fix ? "ok" : "warn");
  document.getElementById("sb-gps").textContent = status.gps_fix ? (status.gps_fix_type || "GPS Fix") : "No GPS Fix";

  document.getElementById("sb-iface").textContent = "Interface: " + (status.monitor_interface || "-");

  const capBtn = document.getElementById("btn-capture");
  capBtn.textContent = status.capture_running ? "Stop Capture" : "Start Capture";
  capBtn.classList.toggle("recording", !!status.capture_running);

  document.getElementById("mode-chip").textContent = status.capture_running ? "Recording" : "Monitor Mode";
}

function renderStatusStrip() {
  const totalPackets = devices.reduce((s, d) => s + (d.packets || 0), 0);
  document.getElementById("d-status-strip").innerHTML = [
    cell("Interface", status.monitor_interface || "-"),
    cell("Mode", status.capture_running ? "Recording" : "Monitor"),
    cell("Uptime", fmtHMS(status.server_uptime_sec)),
    cell("Disk Free", `${fmtBytes(storage.disk_free_bytes)} / ${fmtBytes(storage.disk_total_bytes)}`),
    cell("Packets Captured", fmtCount(totalPackets)),
  ].join("");
}

function renderDashboard() {
  document.getElementById("d-devices-tiles").innerHTML =
    tile("Total Devices", stats.total, { icon: "devices", trend: trendHTML("total") }) +
    tile("Access Points", stats.access_points, { icon: "wifi", trend: trendHTML("access_points") }) +
    tile("Clients", stats.clients, { icon: "clients", trend: trendHTML("clients") }) +
    tile("Open Networks", stats.open_networks, { icon: "lock", danger: stats.open_networks > 0, style: stats.open_networks > 0 ? "color:var(--rust)" : "", trend: trendHTML("open_networks") }) +
    tile("New (5 min)", stats.new_devices, { icon: "clock", trend: trendHTML("new_devices") });

  document.getElementById("d-charts").innerHTML =
    chartCard("Device Type", donutBlock(objToPairs(stats.kind_counts))) +
    chartCard("Encryption", donutBlock(objToPairs(stats.encryption_counts))) +
    chartCard("Band", donutBlock(objToPairs(stats.band_counts))) +
    chartCard("Signal Strength (RSSI)", barChart(stats.rssi_histogram));

  renderTopApsTable();

  document.getElementById("d-channels").innerHTML = `
    <div><div class="sub-title">2.4GHz Channels</div>${barChart(stats.channels_24)}</div>
    <div><div class="sub-title">5GHz / 6GHz Channels</div>${barChart(stats.channels_5_6)}</div>`;

  renderActivity();
  renderRecentAlerts();

  const kinds = Object.keys(stats.manuf_by_kind || {});
  document.getElementById("d-manuf").innerHTML = kinds.length
    ? kinds.map(k => chartCard(k, "<ul class=\"rank-list\">" +
        stats.manuf_by_kind[k].map(([name, c]) => rankItem(name, c)).join("") + "</ul>")).join("")
    : '<div class="card"><span class="empty-note">No manufacturer data yet.</span></div>';

  const speedBody = stats.speed_table.length
    ? stats.speed_table.map(([std, count, max]) =>
        `<tr><td>${esc(std)}</td><td>${count}</td><td>${max ? max + " Mbps" : "unknown"}</td></tr>`).join("")
    : '<tr><td colspan="3" class="empty-note">No devices with a known standard yet.</td></tr>';
  document.querySelector("#d-speed-table tbody").innerHTML = speedBody;
}

function renderTopApsTable() {
  const aps = devices.filter(d => d.kind === "Access Point")
    .sort((a, b) => b.client_count - a.client_count).slice(0, 5);
  const tbody = document.querySelector("#d-top-aps-table tbody");
  tbody.innerHTML = aps.length ? aps.map(d => `
    <tr data-mac="${esc(d.mac)}">
      <td>${esc(d.mac)}</td><td>${esc(d.channel || "-")}</td><td>${d.client_count}</td>
      <td>${esc(d.encryption || "-")}</td>
      <td>${signalBarsHTML(d.signal_dbm ?? -100)}${d.signal_dbm ?? "-"} dBm</td>
    </tr>`).join("") : '<tr><td colspan="5" class="empty-note">No access points yet.</td></tr>';
  tbody.querySelectorAll("tr[data-mac]").forEach(tr => tr.addEventListener("click", () => {
    switchTab("devices");
    selectDevice(tr.dataset.mac);
  }));
}

function renderRecentAlerts() {
  const el = document.getElementById("d-recent-alerts");
  const recent = alerts.slice(0, 5);
  el.innerHTML = recent.length ? recent.map(a => {
    const crit = /DEAUTH|SPOOF|ATTACK|FLOOD/i.test(a.header || "");
    return `<li><span><span class="alert-icon ${crit ? "crit" : ""}"></span>${esc(a.header)}</span>` +
      `<span class="count">${a.ts ? fmtTime(a.ts) : ""}</span></li>`;
  }).join("") : '<li class="empty-note">No alerts yet.</li>';
}

// ---- filters (cascading, with counts) ------------------------------------

function getFilterValues() {
  return {
    text: document.getElementById("f-search").value.toLowerCase().trim(),
    kind: document.getElementById("f-kind").value,
    manuf: document.getElementById("f-manuf").value,
    band: document.getElementById("f-band").value,
    minRssi: parseInt(document.getElementById("f-rssi").value, 10),
    openOnly: document.getElementById("f-open").checked,
    namedOnly: document.getElementById("f-named").checked,
  };
}

function matchesFilters(d, f, exclude) {
  if (f.kind && exclude !== "kind" && d.kind !== f.kind) return false;
  if (f.manuf && exclude !== "manuf" && d.manuf !== f.manuf) return false;
  if (f.band && exclude !== "band" && d.band !== f.band) return false;
  if (exclude !== "rssi" && !isNaN(f.minRssi) && f.minRssi > -100) {
    if (d.signal_dbm === null || d.signal_dbm === undefined || d.signal_dbm < f.minRssi) return false;
  }
  if (f.openOnly && exclude !== "open" && d.kind === "Access Point" && d.encryption !== "Open") return false;
  if (f.namedOnly && exclude !== "named" && (!d.name || d.name === d.mac)) return false;
  if (f.text && exclude !== "text") {
    const hay = [d.name, d.mac, d.manuf, d.encryption, d.kind, d.standard, d.bssid].join(" ").toLowerCase();
    if (!hay.includes(f.text)) return false;
  }
  return true;
}

function filteredDevices() {
  const f = getFilterValues();
  return devices.filter(d => matchesFilters(d, f, null));
}

function countBy(list, keyFn) {
  const counts = new Map();
  list.forEach(d => {
    const k = keyFn(d);
    if (!k) return;
    counts.set(k, (counts.get(k) || 0) + 1);
  });
  return counts;
}

function orderedKeys(counts, preferredOrder) {
  const keys = [...counts.keys()];
  const known = preferredOrder.filter(k => counts.has(k));
  const rest = keys.filter(k => !preferredOrder.includes(k)).sort();
  return [...known, ...rest];
}

function rebuildSelect(id, allLabel, orderedValues, counts) {
  const sel = document.getElementById(id);
  const current = sel.value;
  const html = [`<option value="">${esc(allLabel)}</option>`];
  let stillValid = current === "";
  orderedValues.forEach(v => {
    const c = counts.get(v) || 0;
    if (c === 0) return;
    if (v === current) stillValid = true;
    html.push(`<option value="${esc(v)}">${esc(v)} (${c})</option>`);
  });
  sel.innerHTML = html.join("");
  sel.value = stillValid ? current : "";
}

function updateFilterOptions() {
  const f = getFilterValues();

  const kindPool = devices.filter(d => matchesFilters(d, f, "kind"));
  rebuildSelect("f-kind", "All types", orderedKeys(countBy(kindPool, d => d.kind), KIND_ORDER), countBy(kindPool, d => d.kind));

  const manufPool = devices.filter(d => matchesFilters(d, f, "manuf"));
  rebuildSelect("f-manuf", "All manufacturers", orderedKeys(countBy(manufPool, d => d.manuf), []), countBy(manufPool, d => d.manuf));

  const bandPool = devices.filter(d => matchesFilters(d, f, "band"));
  rebuildSelect("f-band", "All bands", orderedKeys(countBy(bandPool, d => d.band), BAND_ORDER), countBy(bandPool, d => d.band));
}

function renderDeviceTable() {
  updateFilterOptions();
  const rows = filteredDevices();
  rows.sort((a, b) => {
    let av = a[sortKey], bv = b[sortKey];
    if (av === null || av === undefined) av = typeof bv === "number" ? -Infinity : "";
    if (bv === null || bv === undefined) bv = typeof av === "number" ? -Infinity : "";
    if (typeof av === "string") { av = av.toLowerCase(); bv = String(bv).toLowerCase(); }
    return av < bv ? -sortDir : av > bv ? sortDir : 0;
  });
  document.getElementById("device-table-body").innerHTML = rows.map(d => `
    <tr data-mac="${esc(d.mac)}" class="${d.mac === selectedMac ? "selected" : ""}">
      <td>${esc(d.name)}</td><td>${esc(d.mac)}</td><td>${esc(d.kind)}</td>
      <td>${esc(d.standard)}</td><td>${esc(d.band || "-")}</td><td>${esc(d.channel || "-")}</td>
      <td>${esc(d.encryption || "-")}</td><td class="${rssiClass(d.signal_dbm)}">${d.signal_dbm ?? ""}</td>
      <td>${d.client_count}</td><td title="${esc(d.manuf)}">${esc(d.manuf || "-")}</td>
      <td>${d.packets}</td><td>${fmtTime(d.last_seen)}</td>
    </tr>`).join("");
  document.querySelectorAll("#device-table-body tr").forEach(tr => {
    tr.addEventListener("click", () => selectDevice(tr.dataset.mac));
  });
  document.getElementById("btn-export").textContent = `Export CSV (${devices.length})`;
  renderWifiLabApPicker();
}

function renderAlerts() {
  const list = document.getElementById("alert-list");
  list.innerHTML = alerts.length
    ? alerts.map(a => `<li><span class="alert-time">${a.ts ? fmtTime(a.ts, true) : ""}</span>${esc(a.header)}: ${esc(a.text)}</li>`).join("")
    : '<li class="empty-note">No alerts yet.</li>';
  const badge = document.getElementById("alerts-badge");
  if (alerts.length) { badge.hidden = false; badge.textContent = alerts.length; } else badge.hidden = true;
}

// ---- inspector -----------------------------------------------------------

function selectDevice(mac) {
  selectedMac = mac;
  renderDeviceTable();
  updateInspector();
  document.getElementById("inspector").classList.add("open");
}

function insTarget() {
  const d = devices.find(x => x.mac === selectedMac);
  if (!d) return null;
  if (d.kind === "Access Point") return { bssid: d.mac, client_mac: "" };
  if (d.kind === "Client" && d.bssid) return { bssid: d.bssid, client_mac: d.mac };
  return null;
}

function updateInspector() {
  const d = devices.find(x => x.mac === selectedMac);
  const actions = document.getElementById("ins-actions");
  if (!d) {
    document.getElementById("ins-title").textContent = "No device selected";
    document.getElementById("ins-table").innerHTML = "";
    actions.hidden = true;
    return;
  }
  document.getElementById("ins-title").textContent = d.name;
  const rows = [
    ["MAC", d.mac], ["Type", d.kind], ["Standard", d.standard],
    ["Band / Channel", `${d.band || "-"} / ch ${d.channel || "-"}`],
    ["Frequency", d.frequency_mhz ? d.frequency_mhz + " MHz" : "-"],
    ["Encryption", d.encryption || "-"], ["Manufacturer", d.manuf || "-"],
    ["RSSI (last/max)", `${d.signal_dbm ?? "-"} dBm / ${d.signal_max_dbm ?? "-"} dBm`],
    ["Client count", d.client_count], ["Associated BSSID", d.bssid || "-"],
    ["Packets", d.packets], ["Data", fmtBytes(d.data_bytes)],
    ["First seen", fmtTime(d.first_seen, true)], ["Last seen", fmtTime(d.last_seen, true)],
    ["Location", d.has_location ? `${d.latitude.toFixed(6)}, ${d.longitude.toFixed(6)}` : "No GPS fix recorded"],
  ];
  document.getElementById("ins-table").innerHTML = rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("");
  actions.hidden = insTarget() === null;
}

async function quickAction(kind) {
  const t = insTarget();
  if (!t) return;
  document.getElementById("t-bssid").value = t.bssid;
  document.getElementById("t-client").value = t.client_mac;
  switchTab("tools");
  const url = kind === "deauth" ? "/api/tools/deauth" : "/api/tools/handshake";
  const r = await fetch(url, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      bssid: t.bssid, client_mac: t.client_mac,
      count: Math.max(1, Math.min(20, parseInt(document.getElementById("t-count").value || "5", 10))),
      iface: document.getElementById("t-iface").value,
    }),
  });
  const j = await r.json();
  if (!j.ok) showToast(j.message);
  refreshToolsStatus();
}

// ---- map -------------------------------------------------------------

let placingLocation = false;

function initMap() {
  if (mapInited || !status.map_tile_url) return;
  mapInited = true;
  map = L.map("map").setView([0, 0], 3);
  L.tileLayer(status.map_tile_url, { maxZoom: 19, attribution: status.map_attribution || "" }).addTo(map);
  map.on("click", async e => {
    if (!placingLocation) return;
    setPlacingLocation(false);
    const r = await fetch("/api/location/manual", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ lat: e.latlng.lat, lon: e.latlng.lng }),
    });
    const j = await r.json();
    showToast(j.tagged ? `Logged your position - tagged ${j.tagged} device(s) with no prior location.` : "Logged your position.");
    await refreshDevices();
  });
  updateMapMarkers();
}

function setPlacingLocation(on) {
  placingLocation = on;
  document.getElementById("btn-place-location").classList.toggle("armed", on);
  document.getElementById("map").style.cursor = on ? "crosshair" : "";
}

function updateMapMarkers() {
  if (!mapInited) return;
  const seen = new Set();
  devices.forEach(d => {
    if (!d.has_location) return;
    seen.add(d.mac);
    const manual = d.location_source === "manual";
    const color = d.encryption === "Open" ? "#C0594E" : (d.kind === "Access Point" ? "#7C8C5A" : "#917F53");
    const style = { color, fillColor: color, dashArray: manual ? "3,3" : null };
    const popup = `<b>${esc(d.name)}</b><br>${esc(d.mac)}<br>${esc(d.kind)} · ${esc(d.standard)}<br>` +
      `Ch ${esc(d.channel)} (${esc(d.band)}) · ${esc(d.encryption)}<br>RSSI: ${d.signal_dbm ?? "-"} dBm` +
      (manual ? "<br><i>Approximate - manually logged position</i>" : "");
    if (markers[d.mac]) {
      markers[d.mac].setLatLng([d.latitude, d.longitude]);
      markers[d.mac].setPopupContent(popup);
      markers[d.mac].setStyle(style);
    } else {
      const m = L.circleMarker([d.latitude, d.longitude], { radius: 6, weight: manual ? 2 : 1, fillOpacity: 0.8, ...style }).addTo(map);
      m.bindPopup(popup);
      markers[d.mac] = m;
    }
  });
  Object.keys(markers).forEach(mac => {
    if (!seen.has(mac)) { map.removeLayer(markers[mac]); delete markers[mac]; }
  });
}

function updateSelfMarker() {
  if (!mapInited || !status.gps_fix) return;
  const lat = status.gps_lat, lon = status.gps_lon;
  if (selfMarker) {
    selfMarker.setLatLng([lat, lon]);
  } else {
    const icon = L.divIcon({ className: "wb-self", html: '<div class="wb-self-dot"></div>', iconSize: [16, 16], iconAnchor: [8, 8] });
    selfMarker = L.marker([lat, lon], { icon, title: "You are here" }).addTo(map);
  }
  if (!haveFirstFix) { map.setView([lat, lon], 16); haveFirstFix = true; }
}

// ---- BLE analysis -------------------------------------------------------

function bleChannels(device) {
  const value = device.channels_seen ?? device.advertising_channels_seen ?? device.advertising_channels;
  let channels = [];
  if (Array.isArray(value)) channels = value;
  else if (value && typeof value === "object") channels = Object.keys(value).filter(k => value[k] !== false && value[k] !== 0);
  else if (value !== undefined && value !== null) channels = String(value).split(/[,/\s]+/);
  return [...new Set(channels.map(Number).filter(n => [37, 38, 39].includes(n)))].sort();
}

function bleDataChannels(device) {
  const values = [device.data_channels_seen, device.data_channels, device.channels_seen];
  const channels = [];
  values.forEach(value => {
    if (Array.isArray(value)) channels.push(...value);
    else if (value && typeof value === "object") channels.push(...Object.keys(value).filter(k => value[k] !== false && value[k] !== 0));
    else if (value !== undefined && value !== null) channels.push(...String(value).split(/[,/\s]+/));
  });
  return [...new Set(channels.map(Number).filter(n => Number.isInteger(n) && n >= 0 && n <= 36))].sort((a, b) => a - b);
}

function bleChannelCoverage(device) {
  const primary = bleChannels(device);
  const data = bleDataChannels(device);
  const primaryHtml = primary.map(ch => `<span class="channel-chip ch${ch}" title="Primary advertising channel ${ch}">${ch}</span>`).join("");
  const dataHtml = data.length
    ? `<span class="channel-chip data-channel" title="${data.length} followed data channel${data.length === 1 ? "" : "s"}: ${esc(data.join(", "))}">D${data.length}</span>`
    : "";
  return primaryHtml || dataHtml ? `${primaryHtml}${dataHtml}` : "—";
}

function bleChannelColor(channel) {
  const numeric = channel === null || channel === undefined || channel === "" ? NaN : Number(channel);
  return BLE_CHANNEL_COLORS[channel] || (Number.isInteger(numeric) && numeric >= 0 && numeric <= 36 ? "#e1554e" : "#99b968");
}

function firstNumber(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== "" && Number.isFinite(Number(value))) return Number(value);
  }
  return 0;
}

function normaliseBlePhy(value) {
  const text = String(value ?? "1").trim().toUpperCase().replace(/^LE\s*/, "").replace(/[\s=_-]+/g, "");
  if (["1", "1M"].includes(text)) return "1";
  if (["2", "2M"].includes(text)) return "2";
  if (["S8", "CODEDS8", "40"].includes(text)) return "S8";
  if (["S2", "CODEDS2", "80"].includes(text)) return "S2";
  return "1";
}

function blePhyLabel(value) {
  const phy = normaliseBlePhy(value);
  return phy === "1" ? "LE 1M" : phy === "2" ? "LE 2M" : `LE Coded ${phy}`;
}

function normaliseBleMac(input, label) {
  const raw = input.value.trim();
  input.setCustomValidity("");
  if (!raw) return "";
  let compact = "";
  if (/^[0-9a-f]{12}$/i.test(raw)) compact = raw;
  else if (/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(raw)) compact = raw.replaceAll(":", "");
  else if (/^(?:[0-9a-f]{2}-){5}[0-9a-f]{2}$/i.test(raw)) compact = raw.replaceAll("-", "");
  if (!compact) {
    document.getElementById("ble-advanced").open = true;
    input.setCustomValidity(`${label} must contain 12 hex digits, normally AA:BB:CC:DD:EE:FF.`);
    input.reportValidity();
    throw new Error(`${label} is not a valid BLE MAC address.`);
  }
  const formatted = compact.toUpperCase().match(/.{2}/g).join(":");
  input.value = formatted;
  return formatted;
}

function bleCapturePayload() {
  const ltkInput = document.getElementById("ble-ltk");
  const ltk = ltkInput.value.trim();
  ltkInput.setCustomValidity("");
  if (ltk && !/^[0-9a-f]{32}$/i.test(ltk)) {
    document.getElementById("ble-advanced").open = true;
    ltkInput.setCustomValidity("The LTK must be exactly 32 hexadecimal characters (16 bytes).");
    ltkInput.reportValidity();
    throw new Error("LTK must be exactly 32 hexadecimal characters.");
  }
  const rawChannel = document.getElementById("ble-channel").value;
  const payload = {
    channel: rawChannel === "all" ? 0 : Number(rawChannel),
    phy: document.getElementById("ble-phy").value,
  };
  const advertiser = normaliseBleMac(document.getElementById("ble-advertiser"), "Advertiser MAC");
  const initiator = normaliseBleMac(document.getElementById("ble-initiator"), "Initiator MAC");
  if (advertiser) payload.advertiser = advertiser;
  if (initiator) payload.initiator = initiator;
  if (ltk) payload.ltk = ltk.toUpperCase();
  return payload;
}

function bleServices(device) {
  const value = device.services;
  if (Array.isArray(value)) return value.map(String);
  if (value && typeof value === "object") return Object.keys(value);
  if (typeof value === "string" && value.trim()) return value.split(/[,;]+/).map(s => s.trim()).filter(Boolean);
  return [];
}

function normalizeRssiHistory(device) {
  const raw = Array.isArray(device.rssi_history) ? device.rssi_history : [];
  const syntheticTs = index => Date.now() / 1000 - (raw.length - index - 1) * 2;
  const points = raw.map((item, index) => {
    if (typeof item === "number") return { ts: syntheticTs(index), rssi: item, channel: null };
    if (Array.isArray(item)) {
      if (item.length >= 3) return { ts: item[0], rssi: Number(item[1]), channel: Number(item[2]) };
      if (item.length === 2 && Number(item[0]) < 0) return { ts: syntheticTs(index), rssi: Number(item[0]), channel: Number(item[1]) };
      return { ts: item[0], rssi: Number(item[1]), channel: null };
    }
    if (item && typeof item === "object") {
      return {
        ts: item.ts ?? item.timestamp ?? item.time ?? index,
        rssi: Number(item.rssi ?? item.signal_dbm ?? item.dbm),
        channel: Number(item.channel ?? item.ch),
      };
    }
    return null;
  }).filter(p => p && Number.isFinite(p.rssi));
  if (!points.length && device.rssi !== null && device.rssi !== undefined && Number.isFinite(Number(device.rssi))) {
    points.push({ ts: Date.now() / 1000, rssi: Number(device.rssi), channel: bleChannels(device)[0] || null });
  }
  return points.slice(-120);
}

function trendLabel(device) {
  const trend = device.trend;
  if (typeof trend === "number") {
    if (trend > 1.5) return { label: "Getting closer", cls: "closer" };
    if (trend < -1.5) return { label: "Moving away", cls: "away" };
    return { label: "Steady", cls: "steady" };
  }
  const text = String(trend || "").toLowerCase();
  if (/closer|approach|rising|stronger|up/.test(text)) return { label: "Getting closer", cls: "closer" };
  if (/away|farther|falling|weaker|down/.test(text)) return { label: "Moving away", cls: "away" };
  const points = normalizeRssiHistory(device);
  if (points.length > 2) {
    const delta = points[points.length - 1].rssi - points[0].rssi;
    if (delta > 3) return { label: "Getting closer", cls: "closer" };
    if (delta < -3) return { label: "Moving away", cls: "away" };
  }
  return { label: "Steady", cls: "steady" };
}

function bleStatTile(label, value, sub) {
  return `<div class="ble-stat"><span>${esc(label)}</span><b>${esc(value ?? 0)}</b>${sub ? `<small>${esc(sub)}</small>` : ""}</div>`;
}

function renderBleStatus() {
  const s = bleStatus || {};
  const ready = !!s.driver_ready;
  const units = Number(s.usb_mcu_count || 0);
  const running = !!s.running;
  const activeUnits = running
    ? Number(s.active_mcu_count === undefined || s.active_mcu_count === null ? units : s.active_mcu_count)
    : 0;
  const failed = !!s.error || !!s._ui_error;
  const completeHardware = units >= 3;
  const dot = document.getElementById("ble-driver-dot");
  dot.className = `dot ${failed && activeUnits < 1 ? "bad" : running && activeUnits >= 3 ? "ok" : ready && completeHardware && !failed ? "ok" : "warn"}`;
  const card = document.getElementById("ble-hardware-card");
  card.classList.toggle("capture-error", failed && units < 1);
  card.classList.toggle("capture-ready", ready && completeHardware && !failed && (!running || activeUnits >= 3));
  let title = "Analyzer not ready";
  let detail = "Connect the WCH BLE AnalyzerPro and confirm the Linux driver can access its USB interface.";
  if (running) {
    title = failed || activeUnits < 3 ? "BLE capture running with reduced coverage" : "BLE capture is running";
    detail = s.channel_mode === "all"
      ? `Listening with ${activeUnits} of 3 radios${activeUnits >= 3 ? " simultaneously on primary channels 37, 38, and 39" : "; check the driver log and USB access for full primary-channel coverage"}. Observed CONNECT_IND sessions are followed natively across data channels 0–36.`
      : `All available radios are pinned to primary channel ${s.channel_mode || "selected"}; connections first observed there are followed across data channels 0–36.`;
    if (failed) detail += ` Driver detail: ${s.error || s._ui_error}`;
  } else if (ready && completeHardware && failed) {
    title = "Analyzer reconnected · retry available";
    detail = `The three radios are visible again. The previous attempt reported: ${s.error || s._ui_error}`;
  } else if (ready && completeHardware) {
    title = "Analyzer connected and ready";
    detail = "All three USB radios are ready for simultaneous primary-channel discovery and firmware-native connection following.";
  } else if (ready && units > 0) {
    title = `Analyzer partially connected · ${units}/3 radios`;
    detail = "Capture can run, but all-channel coverage will be incomplete. Check the cable, hub, and udev permissions.";
  } else if (failed) {
    title = "BLE analyzer needs attention";
    detail = s.error || s._ui_error;
  } else if (ready) {
    title = "Driver ready · analyzer not found";
    detail = "The driver is available, but no compatible WCH USB MCU is visible. Check the cable and udev permissions.";
  }
  document.getElementById("ble-driver-title").textContent = title;
  document.getElementById("ble-driver-detail").textContent = detail;
  const captureName = s.capture_file ? String(s.capture_file).split(/[\\/]/).pop() : "Not recording";
  const selectedPhy = running && s.phy !== undefined ? normaliseBlePhy(s.phy) : document.getElementById("ble-phy").value;
  document.getElementById("ble-hardware-meta").innerHTML =
    `<span><b>${ready ? "Ready" : "Not ready"}</b>Driver</span>` +
    `<span><b>${units}/3${running ? ` · ${activeUnits} active` : ""}</b>USB radios</span>` +
    `<span><b>${esc(blePhyLabel(selectedPhy))}</b>Radio PHY</span>` +
    `<span title="${esc(s.capture_file || "")}"><b>${esc(captureName)}</b>Capture file</span>`;
  const mode = String(s.channel_mode ?? "");
  if (running && ["all", "37", "38", "39"].includes(mode)) document.getElementById("ble-channel").value = mode;
  if (running && s.phy !== undefined) document.getElementById("ble-phy").value = normaliseBlePhy(s.phy);
  if (running) {
    const advertiser = s.advertiser_filter ?? s.advertiser;
    const initiator = s.initiator_filter ?? s.initiator;
    if (advertiser) document.getElementById("ble-advertiser").value = String(advertiser);
    if (initiator) document.getElementById("ble-initiator").value = String(initiator);
  }
  // A previous unplug/start error is kept for diagnosis, but must not trap a
  // newly reconnected analyzer in a disabled state.
  document.getElementById("ble-start").disabled = running || !ready || units < 1;
  document.getElementById("ble-stop").disabled = !running;
  ["ble-channel", "ble-phy", "ble-advertiser", "ble-initiator", "ble-ltk"].forEach(id => {
    document.getElementById(id).disabled = running;
  });
}

function renderBleStats() {
  const s = bleStats || {};
  const strongest = s.strongest_device;
  let strongestValue = "—", strongestSub = "No signal yet";
  if (strongest && typeof strongest === "object") {
    strongestValue = strongest.rssi !== undefined ? `${strongest.rssi} dBm` : (strongest.name || strongest.address || "—");
    strongestSub = strongest.name || strongest.address || "Strongest current device";
  } else if (strongest) {
    strongestValue = strongest;
    strongestSub = "Strongest current device";
  }
  const counts = s.channel_counts || {};
  const channelSummary = `37: ${counts[37] ?? counts["37"] ?? 0} · 38: ${counts[38] ?? counts["38"] ?? 0} · 39: ${counts[39] ?? counts["39"] ?? 0}`;
  const totalPackets = firstNumber(s.total_packets, s.packet_count);
  const connections = firstNumber(s.connections_followed, s.followed_connections, s.connection_count, s.connections, s.connected_devices);
  const dataPackets = firstNumber(s.data_packets, s.connected_packets, s.connection_packets, s.link_data_packets);
  const decryptedPackets = firstNumber(s.decrypted_packets, s.decrypted_count);
  const advertisingPackets = firstNumber(s.advertising_packets, s.advertisement_packets,
    dataPackets || totalPackets ? Math.max(0, totalPackets - dataPackets) : 0);
  document.getElementById("ble-stat-tiles").innerHTML =
    bleStatTile("Devices found", s.total_devices ?? bleDevices.length, `${fmtCount(firstNumber(s.active_devices))} active recently`) +
    bleStatTile("Connections followed", fmtCount(connections), "CONNECT_IND sessions") +
    bleStatTile("Connected data", fmtCount(dataPackets), "Data channels 0–36") +
    bleStatTile("Decrypted", fmtCount(decryptedPackets), "Validated with supplied LTK") +
    bleStatTile("Advertising", fmtCount(advertisingPackets), "Primary-channel PDUs") +
    bleStatTile("All packets", fmtCount(totalPackets), "Decoded Link Layer PDUs") +
    bleStatTile("Strongest signal", strongestValue, strongestSub) +
    bleStatTile("Primary coverage", channelSummary, "Packets on 37 / 38 / 39");
}

function renderBleDevices() {
  const search = document.getElementById("ble-device-search").value.toLowerCase().trim();
  const rows = bleDevices.filter(d => {
    if (!search) return true;
    return [d.name, d.address, d.manufacturer, d.address_type, ...bleServices(d)].join(" ").toLowerCase().includes(search);
  }).sort((a, b) => Number(b.rssi ?? -999) - Number(a.rssi ?? -999));
  const tbody = document.querySelector("#ble-device-table tbody");
  tbody.innerHTML = rows.length ? rows.map(d => {
    const trend = trendLabel(d);
    const address = d.address || "Unknown";
    return `<tr data-address="${esc(address)}" class="${address === selectedBleAddress ? "selected" : ""}">` +
      `<td><b>${esc(d.name || "Unnamed device")}</b><small>${esc(d.address_type || "")}</small></td>` +
      `<td><code>${esc(address)}</code></td><td>${esc(d.manufacturer || "Unknown")}</td>` +
      `<td class="${rssiClass(d.rssi)}">${signalBarsHTML(Number(d.rssi ?? -100))}${d.rssi ?? "—"} dBm</td>` +
      `<td><span class="trend-pill ${trend.cls}">${esc(trend.label)}</span></td>` +
      `<td>${bleChannelCoverage(d)}</td>` +
      `<td>${fmtCount(d.packets || 0)}</td><td>${fmtLastSeen(d.last_seen)}</td></tr>`;
  }).join("") : '<tr><td colspan="8" class="empty-note">No BLE devices match this view yet. Start capture and keep the analyzer near your test device.</td></tr>';
  tbody.querySelectorAll("tr[data-address]").forEach(tr => tr.addEventListener("click", () => selectBleDevice(tr.dataset.address)));
  renderBleFocus();
}

function renderRssiChart(device) {
  const points = normalizeRssiHistory(device);
  if (points.length < 2) return '<div class="empty-chart">Waiting for at least two signal readings…</div>';
  const w = 720, h = 180, left = 43, right = 12, top = 12, bottom = 27;
  const values = points.map(p => p.rssi);
  const min = Math.max(-110, Math.floor((Math.min(...values) - 5) / 10) * 10);
  const max = Math.min(-10, Math.ceil((Math.max(...values) + 5) / 10) * 10);
  const range = Math.max(10, max - min);
  const x = i => left + (i / (points.length - 1)) * (w - left - right);
  const y = value => top + ((max - value) / range) * (h - top - bottom);
  const ticks = Array.from({ length: 4 }, (_, i) => Math.round(max - (range * i) / 3));
  const grid = ticks.map(v => `<line x1="${left}" y1="${y(v)}" x2="${w - right}" y2="${y(v)}"/><text x="${left - 7}" y="${y(v) + 4}">${v}</text>`).join("");
  const segments = points.slice(1).map((p, i) => {
    const previous = points[i];
    const color = bleChannelColor(p.channel ?? previous.channel);
    return `<line x1="${x(i)}" y1="${y(previous.rssi)}" x2="${x(i + 1)}" y2="${y(p.rssi)}" stroke="${color}"/>`;
  }).join("");
  const dots = points.map((p, i) => `<circle cx="${x(i)}" cy="${y(p.rssi)}" r="2.3" fill="${bleChannelColor(p.channel)}"/>`).join("");
  const firstLabel = fmtPacketTime(points[0].ts);
  const lastLabel = fmtPacketTime(points[points.length - 1].ts);
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-label="RSSI history in dBm"><g class="rssi-grid">${grid}</g>` +
    `<g class="rssi-lines">${segments}${dots}</g><g class="rssi-time"><text x="${left}" y="${h - 5}">${esc(firstLabel)}</text>` +
    `<text x="${w - right}" y="${h - 5}" text-anchor="end">${esc(lastLabel)}</text></g></svg>`;
}

function packetMixPairs(device) {
  const mix = device.packet_types;
  if (Array.isArray(mix)) {
    return mix.map(item => Array.isArray(item) ? [String(item[0]), Number(item[1]) || 0] : [String(item.type || item.name || "Unknown"), Number(item.count) || 0]);
  }
  if (mix && typeof mix === "object") return Object.entries(mix).map(([k, v]) => [k, Number(v) || 0]);
  const counts = {};
  blePackets.forEach(p => { const type = packetType(p); counts[type] = (counts[type] || 0) + 1; });
  return Object.entries(counts);
}

function findBleDevice(address) {
  const wanted = String(address || "").toLowerCase();
  return bleDevices.find(d => String(d.address || "").toLowerCase() === wanted);
}

function renderBleFocus() {
  const device = findBleDevice(selectedBleAddress);
  document.getElementById("ble-empty-focus").hidden = !!device;
  document.getElementById("ble-focus-content").hidden = !device;
  document.getElementById("ble-focused-packets-card").hidden = !device;
  if (!device) return;
  document.getElementById("ble-focus-name").textContent = device.name || "Unnamed BLE device";
  document.getElementById("ble-focus-address").textContent = device.address || "Unknown address";
  const services = bleServices(device);
  const dataPackets = firstNumber(device.data_packets, device.connected_packets, device.connection_packets);
  const decryptedPackets = firstNumber(device.decrypted_packets, device.decrypted_count);
  const following = device.connection_active === true || device.connected === true || device.following === true;
  const connectionState = following ? "Following now" : dataPackets > 0 ? "Captured" : "Not observed yet";
  document.getElementById("ble-device-facts").innerHTML =
    `<div><span>Manufacturer</span><b>${esc(device.manufacturer || "Unknown")}</b></div>` +
    `<div><span>Address type</span><b>${esc(device.address_type || "Unknown")}</b></div>` +
    `<div><span>Connectable</span><b>${yesNoUnknown(device.connectable)}</b></div>` +
    `<div><span>Scannable</span><b>${yesNoUnknown(device.scannable)}</b></div>` +
    `<div><span>Connection</span><b>${esc(connectionState)}</b></div>` +
    `<div><span>Connected data</span><b>${fmtCount(dataPackets)} packets</b></div>` +
    `<div><span>Decrypted</span><b>${fmtCount(decryptedPackets)} packets</b></div>` +
    `<div><span>Data channels</span><b>${bleDataChannels(device).length || 0} seen</b></div>` +
    `<div class="wide-fact"><span>Advertised services</span><b>${services.length ? services.map(esc).join(" · ") : "None decoded yet"}</b></div>`;
  const history = normalizeRssiHistory(device);
  const trend = trendLabel(device);
  let summary = trend.label;
  if (history.length > 1) {
    const delta = history[history.length - 1].rssi - history[0].rssi;
    summary += ` · ${delta >= 0 ? "+" : ""}${delta.toFixed(0)} dB in view`;
  }
  document.getElementById("ble-rssi-summary").textContent = summary;
  document.getElementById("ble-rssi-chart").innerHTML = renderRssiChart(device);
  const pairs = packetMixPairs(device).sort((a, b) => b[1] - a[1]).slice(0, 8);
  document.getElementById("ble-packet-mix").innerHTML = pairs.length ? barChart(pairs) : emptyNote();
  renderBleFocusedPackets();
}

function renderBleFocusedPackets() {
  const body = document.getElementById("ble-focused-packets");
  if (!selectedBleAddress) { body.innerHTML = ""; return; }
  const rows = blePackets.slice().reverse();
  body.innerHTML = rows.length ? rows.map(p => {
    const source = p.src || "—", destination = p.dst || "—";
    return `<tr title="${esc(p.info || packetPurpose(p))}"><td>${esc(p.seq ?? "—")}</td><td>${esc(fmtPacketTime(p.ts))}</td>` +
      `<td><span class="protocol-chip">${esc(packetType(p))}</span></td><td>${esc(packetPurpose(p))}</td>` +
      `<td>${esc(p.channel ?? "—")}</td><td class="${rssiClass(p.rssi)}">${p.rssi ?? "—"}</td>` +
      `<td>${esc(packetDirection(p))}</td><td>${securityChip(p)}</td>` +
      `<td><code>${esc(source)}</code> → <code>${esc(destination)}</code></td><td>${esc(p.length ?? "—")}</td></tr>`;
  }).join("") : '<tr><td colspan="10" class="empty-note">Waiting for packets from this address. Rotating private addresses can make a device appear under a new row.</td></tr>';
}

function selectBleDevice(address) {
  if (address === "Unknown") return;
  bleRequestGeneration += 1;
  selectedBleAddress = address;
  blePackets = [];
  blePacketAfter = 0;
  renderBleDevices();
  refreshBlePackets().catch(() => {});
}

async function refreshBleStatus() {
  try {
    bleStatus = await fetchJSON("/api/ble/status");
  } catch (e) {
    bleStatus = { ...bleStatus, _ui_error: `BLE service unavailable: ${e.message}` };
  }
  renderBleStatus();
}

async function refreshBleStats() {
  if (blePaused) return;
  const generation = bleRequestGeneration;
  let nextStats;
  try { nextStats = await fetchJSON("/api/ble/stats"); } catch (_) { return; }
  if (generation !== bleRequestGeneration) return;
  bleStats = nextStats;
  renderBleStats();
}

async function refreshBleDevices() {
  if (blePaused) return;
  const generation = bleRequestGeneration;
  let nextDevices;
  try { nextDevices = arrayFromPayload(await fetchJSON("/api/ble/devices"), "devices"); } catch (_) { return; }
  if (generation !== bleRequestGeneration) return;
  bleDevices = nextDevices;
  if (selectedBleAddress && !findBleDevice(selectedBleAddress)) {
    // Keep the focus address so its packet feed remains useful even if it has just gone quiet.
  }
  renderBleDevices();
}

async function refreshBlePackets() {
  if (blePaused || !selectedBleAddress) return;
  const generation = bleRequestGeneration;
  const address = selectedBleAddress;
  const qs = queryString({ after: blePacketAfter, address, limit: 500 });
  let incoming;
  try { incoming = arrayFromPayload(await fetchJSON(`/api/ble/packets?${qs}`), "packets"); } catch (_) { return; }
  if (generation !== bleRequestGeneration || selectedBleAddress !== address) return;
  blePackets = mergePackets(blePackets, incoming, 500);
  blePacketAfter = latestSequence(incoming, blePacketAfter);
  renderBleFocusedPackets();
  const device = findBleDevice(selectedBleAddress);
  if (device && (!device.packet_types || !Object.keys(device.packet_types).length)) renderBleFocus();
}

// ---- signal analysis ----------------------------------------------------

function renderSignalBleProfile() {
  const profile = document.getElementById("signal-ble-profile");
  const source = document.getElementById("signal-source").value;
  profile.hidden = source !== "ble";
  if (source !== "ble") return;
  const rawChannel = document.getElementById("ble-channel").value;
  const channelLabel = rawChannel === "all" ? "All 3 primary channels" : `Primary channel ${rawChannel}`;
  const advertiser = document.getElementById("ble-advertiser").value.trim() || String(bleStatus.advertiser_filter || "").trim();
  const initiator = document.getElementById("ble-initiator").value.trim() || String(bleStatus.initiator_filter || "").trim();
  const hasLtk = !!document.getElementById("ble-ltk").value.trim() || bleStatus.ltk_loaded === true || bleStatus.ltk_configured === true;
  const targetLabel = advertiser || initiator ? "targeted connection follow" : "follow any connection";
  document.getElementById("signal-ble-profile-title").textContent = `${channelLabel} · ${blePhyLabel(document.getElementById("ble-phy").value)} · ${targetLabel}`;
  const targetDetails = [];
  if (advertiser) targetDetails.push(`advertiser ${advertiser}`);
  if (initiator) targetDetails.push(`initiator ${initiator}`);
  document.getElementById("signal-ble-profile-detail").textContent =
    `Firmware-native following begins when CONNECT_IND is observed${targetDetails.length ? ` for ${targetDetails.join(" and ")}` : ""}; ${hasLtk ? "an optional LTK is loaded locally" : "no decryption key is loaded"}.`;
}

function renderSignalStatus() {
  const s = signalStatus || {};
  const source = document.getElementById("signal-source").value;
  renderSignalBleProfile();
  const running = !!s.running;
  // A capture can also be restarted from its dedicated BLE/Wi-Fi control.
  // In that case the server is authoritative and the local paused marker is stale.
  if (running && signalCapturePausedSource === source) signalCapturePausedSource = null;
  const capturePaused = signalCapturePausedSource === source;
  const failed = !!s.error || !!s._ui_error;
  document.getElementById("signal-status-dot").className = `dot ${capturePaused ? "warn" : failed ? "bad" : running ? "ok" : "warn"}`;
  document.getElementById("signal-status-title").textContent = capturePaused ? "Capture paused" : failed ? "Capture service unavailable" : running ? "Live capture running" : "Capture stopped";
  const detail = capturePaused
    ? `The ${source.toUpperCase()} source is stopped and packet rows are preserved. Resume when you are ready.${failed ? ` Last source error: ${s.error || s._ui_error}` : ""}`
    : failed ? (s.error || s._ui_error) : running
    ? `${fmtCount(s.packet_count ?? signalPackets.length)} packets · ${String(s.source || document.getElementById("signal-source").value).toUpperCase()} source${s.capture_file ? ` · ${String(s.capture_file).split(/[\\/]/).pop()}` : ""}`
    : "Choose a source and start a packet feed.";
  document.getElementById("signal-status-detail").textContent = detail;
  const dependencyBlocked = source === "ble"
    ? s.driver_ready === false || Number(s.usb_mcu_count || 0) < 1
    : s.tshark_available === false;
  // Retain the error for diagnosis, but allow a retry after a transient
  // Kismet/USB failure once the required local dependency is available.
  const capturePauseButton = document.getElementById("signal-pause-capture");
  capturePauseButton.textContent = capturePaused ? "Resume capture" : "Pause capture";
  capturePauseButton.disabled = signalActionPending || (capturePaused ? dependencyBlocked : !running);
  document.getElementById("signal-start").disabled = signalActionPending || running || capturePaused || dependencyBlocked;
  document.getElementById("signal-stop").disabled = signalActionPending || (!running && !capturePaused);
  document.getElementById("signal-clear").disabled = signalActionPending;
  document.getElementById("signal-source").disabled = signalActionPending;
}

function signalApiBase() {
  return document.getElementById("signal-source").value === "ble" ? "/api/ble" : "/api/signal";
}

function filteredSignalPackets() {
  const address = document.getElementById("signal-address").value.toLowerCase().trim();
  const channel = document.getElementById("signal-channel").value.trim();
  const minRssiRaw = document.getElementById("signal-rssi").value.trim();
  const minRssi = minRssiRaw === "" ? null : Number(minRssiRaw);
  const type = document.getElementById("signal-type").value.toLowerCase().trim();
  const text = document.getElementById("signal-text").value.toLowerCase().trim();
  return signalPackets.filter(p => {
    if (address && ![p.src, p.dst, p.bssid, p.address].join(" ").toLowerCase().includes(address)) return false;
    if (channel && String(p.channel ?? "") !== channel) return false;
    if (minRssi !== null && (!Number.isFinite(Number(p.rssi)) || Number(p.rssi) < minRssi)) return false;
    if (type && !packetType(p).toLowerCase().includes(type)) return false;
    if (text && ![p.src, p.dst, p.bssid, p.type, p.protocol, p.purpose, p.info,
      p.access_address, p.address_type, p.address_subtype, p.target_address_type,
      p.target_address_subtype, p.name, p.manufacturer, p.raw_note, p.raw_hex, p.pdu_hex,
      p.link_layer, p.phy, p.direction, p.direction_name, packetDirection(p), packetSecurity(p).label,
      JSON.stringify(p.services || []), JSON.stringify(p.header || {}), JSON.stringify(p.details || {}),
      JSON.stringify(p.ad_structures || []), JSON.stringify(p.errors || [])].join(" ").toLowerCase().includes(text)) return false;
    return true;
  });
}

function signalPacketClass(packet) {
  const type = packetType(packet).toUpperCase();
  if (/ADV|BEACON|PROBE/.test(type)) return "packet-discovery";
  if (/CONNECT|ASSOC|AUTH|EAPOL|LL_(CONTROL|ENC|START_ENC|PHY|LENGTH|FEATURE|CHANNEL_MAP|CONNECTION)/.test(type)) return "packet-session";
  if (/DEAUTH|ERROR|MALFORM/.test(type)) return "packet-warning";
  return "";
}

function renderSignalPackets() {
  const rows = filteredSignalPackets().slice().reverse();
  document.getElementById("signal-packet-count").textContent = `${rows.length} shown · ${signalPackets.length} buffered`;
  const body = document.getElementById("signal-packet-body");
  body.innerHTML = rows.length ? rows.map(p => `<tr data-seq="${esc(p.seq)}" class="${signalPacketClass(p)} ${String(p.seq) === String(selectedSignalSeq) ? "selected" : ""}">` +
    `<td>${esc(p.seq ?? "—")}</td><td>${esc(fmtPacketTime(p.ts))}</td><td><code>${esc(p.src || "—")}</code></td>` +
    `<td><code>${esc(p.dst || "—")}</code></td><td><span class="protocol-chip">${esc(packetType(p))}</span></td>` +
    `<td>${esc(p.channel ?? "—")}</td><td class="${rssiClass(p.rssi)}">${p.rssi ?? "—"}</td>` +
    `<td>${esc(packetDirection(p))}</td><td>${securityChip(p)}</td><td>${esc(p.length ?? "—")}</td>` +
    `<td class="info-cell">${esc(p.info || packetPurpose(p))}</td></tr>`).join("") :
    '<tr><td colspan="11" class="empty-note">No packets match the current display filter.</td></tr>';
  body.querySelectorAll("tr[data-seq]").forEach(tr => tr.addEventListener("click", () => selectSignalPacket(tr.dataset.seq)));
  if (selectedSignalSeq !== null) {
    const selected = signalPackets.find(p => String(p.seq) === String(selectedSignalSeq));
    if (selected) renderSignalPacketDetail(selected);
  }
}

function hexDump(value) {
  const clean = String(value || "").replace(/[^0-9a-f]/gi, "");
  if (!clean) return "Raw bytes were not supplied for this packet.";
  const bytes = clean.match(/.{1,2}/g) || [];
  const lines = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const row = bytes.slice(offset, offset + 16);
    const hex = row.join(" ").padEnd(47, " ");
    const ascii = row.map(b => { const n = parseInt(b, 16); return n >= 32 && n <= 126 ? String.fromCharCode(n) : "."; }).join("");
    lines.push(`${offset.toString(16).padStart(4, "0")}  ${hex}  |${ascii}|`);
  }
  return lines.join("\n");
}

function renderSignalPacketDetail(packet) {
  const security = packetSecurity(packet);
  const radio = [`Channel ${packet.channel ?? "—"}`];
  if (packet.raw_channel !== undefined && packet.raw_channel !== null && Number(packet.raw_channel) !== Number(packet.channel)) radio.push(`raw event byte ${packet.raw_channel}`);
  if (packet.phy) radio.push(String(packet.phy));
  radio.push(`RSSI ${packet.rssi ?? "—"} dBm`);
  const fields = [
    ["Frame", packet.seq ?? "—"], ["Arrival time", fmtPacketTime(packet.ts, true)],
    ["Capture source", signalStatus.source || document.getElementById("signal-source").value.toUpperCase()],
    ["Protocol / type", packetType(packet)], ["Purpose", packetPurpose(packet)],
    ["Source", packet.src || "—"], ["Destination", packet.dst || "—"],
    ["Direction", packetDirection(packet)], ["Security", security.label],
    ["Link layer", packet.link_layer || (isBlePacket(packet) ? (Number(packet.channel) <= 36 ? "data" : "advertising") : "802.11")],
    ["BSSID", packet.bssid || "—"],
    ["Radio", radio.join(" · ")],
    ["Captured length", packet.length !== undefined ? `${packet.length} bytes` : "—"],
    ["Decoded info", packet.info || "No additional decoded fields"],
  ];
  const decoded = {};
  ["access_address", "address_type", "address_subtype", "target_address_type", "target_address_subtype",
    "name", "manufacturer", "services", "header", "details", "ad_structures", "errors", "raw_note",
    "crc", "crc_init", "crc_reconstructed", "device_flags", "sequence_class", "initiator", "advertiser",
    "decrypted", "encrypted", "mic_valid", "packet_counter"].forEach(key => {
    const value = packet[key];
    if (value !== undefined && value !== null && value !== "" && (!Array.isArray(value) || value.length)) decoded[key] = value;
  });
  const protocolFields = Object.keys(decoded).length
    ? `<details class="decoded-tree" open><summary>Protocol fields</summary><pre>${esc(JSON.stringify(decoded, null, 2))}</pre></details>`
    : "";
  document.getElementById("signal-packet-detail").innerHTML = `<div class="detail-title">Decoded packet</div>` +
    fields.map(([k, v], index) => `<div class="detail-field ${index === 2 || index === 5 ? "detail-group-start" : ""}"><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join("") + protocolFields;
  document.getElementById("signal-hex-dump").textContent = hexDump(packet.raw_hex || packet.pdu_hex);
}

function selectSignalPacket(seq) {
  selectedSignalSeq = seq;
  const packet = signalPackets.find(p => String(p.seq) === String(seq));
  if (packet) renderSignalPacketDetail(packet);
  renderSignalPackets();
}

function resetSignalFeed(render) {
  signalPackets = [];
  signalPacketAfter = 0;
  selectedSignalSeq = null;
  if (render !== false) {
    renderSignalPackets();
    document.getElementById("signal-packet-detail").innerHTML = '<span class="empty-note">Select a packet to inspect its decoded fields.</span>';
    document.getElementById("signal-hex-dump").textContent = "No packet selected.";
  }
}

async function refreshSignalStatus() {
  if (signalActionPending) return;
  const source = document.getElementById("signal-source").value;
  const generation = signalSourceGeneration;
  const apiBase = source === "ble" ? "/api/ble" : "/api/signal";
  try {
    const nextStatus = await fetchJSON(`${apiBase}/status`);
    if (generation !== signalSourceGeneration || document.getElementById("signal-source").value !== source) return;
    signalStatus = { ...nextStatus, source };
  } catch (e) {
    if (generation !== signalSourceGeneration || document.getElementById("signal-source").value !== source) return;
    signalStatus = { ...signalStatus, _ui_error: `Signal service unavailable: ${e.message}` };
  }
  renderSignalStatus();
}

async function refreshSignalPackets() {
  if (signalPaused || signalActionPending) return;
  const source = document.getElementById("signal-source").value;
  const generation = signalSourceGeneration;
  const apiBase = source === "ble" ? "/api/ble" : "/api/signal";
  const qs = queryString({
    after: signalPacketAfter,
    address: document.getElementById("signal-address").value,
    channel: document.getElementById("signal-channel").value,
    type: document.getElementById("signal-type").value,
    source,
    limit: 1000,
  });
  let incoming;
  try { incoming = arrayFromPayload(await fetchJSON(`${apiBase}/packets?${qs}`), "packets"); } catch (_) { return; }
  if (generation !== signalSourceGeneration || document.getElementById("signal-source").value !== source) return;
  signalPackets = mergePackets(signalPackets, incoming, 1500);
  signalPacketAfter = latestSequence(incoming, signalPacketAfter);
  renderSignalPackets();
}

function followBleInSignal() {
  if (!selectedBleAddress) return;
  if (signalActionPending) {
    showToast("Wait for the current Signal Analysis action to finish, then follow the device again.");
    return;
  }
  signalSourceGeneration += 1;
  document.getElementById("signal-source").value = "ble";
  document.getElementById("signal-address").value = selectedBleAddress;
  document.getElementById("signal-channel").value = "";
  document.getElementById("signal-rssi").value = "";
  document.getElementById("signal-type").value = "";
  document.getElementById("signal-text").value = "";
  resetSignalFeed();
  switchTab("signal");
  refreshSignalStatus().catch(() => {});
  refreshSignalPackets().catch(() => {});
}

function renderWifiLabApPicker() {
  const picker = document.getElementById("t-ap-picker");
  if (!picker) return;
  const current = picker.value;
  const aps = devices.filter(d => d.kind === "Access Point").sort((a, b) => String(a.name || a.mac).localeCompare(String(b.name || b.mac)));
  picker.innerHTML = '<option value="">Select an access point…</option>' + aps.map(d =>
    `<option value="${esc(d.mac)}">${esc(d.name || "Unnamed AP")} · ${esc(d.mac)} · ch ${esc(d.channel || "?")} · ${esc(d.signal_dbm ?? "?")} dBm</option>`
  ).join("");
  if (aps.some(d => d.mac === current)) picker.value = current;
}

// ---- tabs --------------------------------------------------------------

function switchTab(name) {
  document.querySelectorAll(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".panel").forEach(p => p.classList.toggle("active", p.id === "panel-" + name));
  document.getElementById("page-title").textContent = TAB_TITLES[name] || name;
  const captureContext = name !== "ble" && name !== "signal";
  document.getElementById("mode-chip").hidden = !captureContext;
  document.getElementById("btn-capture").hidden = !captureContext;
  document.getElementById("btn-dashboard-reset").hidden = name !== "dashboard";
  document.querySelector("main").scrollTop = 0;
  if (name === "map") { initMap(); setTimeout(() => map && map.invalidateSize(), 50); }
}

// ---- polling -----------------------------------------------------------

async function refreshStatus() {
  const r = await fetch("/api/status");
  status = await r.json();
  renderStatusChips();
  if (!mapInited) initMap();
  updateSelfMarker();
  if (!document.getElementById("t-iface").value) document.getElementById("t-iface").value = status.monitor_interface || "";
}

async function refreshDevices() {
  const r = await fetch("/api/devices");
  devices = await r.json();
  renderDeviceTable();
  updateMapMarkers();
  updateActivityHistory();
  if (selectedMac) updateInspector();
}

async function refreshStats() {
  const r = await fetch("/api/stats");
  stats = await r.json();
  updateStatsHistory();
  renderDashboard();
}

async function refreshStorage() {
  const r = await fetch("/api/storage");
  storage = await r.json();
}

async function refreshAlerts() {
  const r = await fetch("/api/alerts");
  alerts = await r.json();
  renderAlerts();
}

async function refreshToolsStatus() {
  const r = await fetch("/api/tools/status");
  const t = await r.json();
  document.getElementById("t-authorize").checked = t.authorized;
  const out = document.getElementById("tool-output");
  out.textContent = t.output;
  out.scrollTop = out.scrollHeight;
}

async function refreshFiles() {
  const r = await fetch("/api/files");
  const files = await r.json();
  renderFilesTable(files);
}

async function resetDashboardSession() {
  const btn = document.getElementById("btn-dashboard-reset");
  btn.disabled = true;
  btn.classList.add("loading");
  try {
    const r = await fetch("/api/dashboard/reset", { method: "POST" });
    const j = await r.json();
    if (!r.ok || !j.ok) throw new Error(j.message || "Dashboard reset failed");

    paused = false;
    document.getElementById("btn-pause").textContent = "Pause View";
    document.getElementById("btn-pause").classList.remove("active");
    devices = [];
    stats = emptyStats();
    alerts = [];
    statsHistory = [];
    activityHistory = [];
    selectedMac = null;
    document.getElementById("inspector").classList.remove("open");
    if (mapInited) {
      Object.keys(markers).forEach(mac => map.removeLayer(markers[mac]));
      markers = {};
    }
    renderDeviceTable();
    renderDashboard();
    renderAlerts();
    renderStatusStrip();

    await Promise.all([refreshDevices(), refreshStats(), refreshAlerts()]);
    renderStatusStrip();
    showToast(j.message);
  } catch (e) {
    showToast(e.message || "Dashboard reset failed");
  } finally {
    btn.disabled = false;
    btn.classList.remove("loading");
  }
}

function renderFilesTable(files) {
  const tbody = document.querySelector("#d-files-table tbody");
  tbody.innerHTML = files.length ? files.map(f => `
    <tr>
      <td>${esc(f.name)}</td><td>${f.kind === "ble-pcap" ? "BLE PCAP" : f.kind === "pcap" ? "PCAP" : "Kismet DB"}</td>
      <td>${fmtBytes(f.size)}</td><td>${fmtTime(f.mtime, true)}</td>
      <td><a class="link" href="/api/files/download/${encodeURIComponent(f.name)}">Download</a></td>
    </tr>`).join("") : '<tr><td colspan="5" class="empty-note">No capture files yet.</td></tr>';
}

async function pollLoop() {
  if (pollLoopRunning) return;
  pollLoopRunning = true;
  try {
    try {
      await refreshStatus();
      if (!paused) {
        await Promise.all([refreshDevices(), refreshStats(), refreshStorage(), refreshAlerts(), refreshFiles()]);
        renderStatusStrip();
      }
      await refreshToolsStatus();
    } catch (e) {
      console.error("poll failed", e);
    }
    await Promise.allSettled([
      refreshBleStatus(), refreshBleStats(), refreshBleDevices(), refreshBlePackets(),
      refreshSignalStatus(), refreshSignalPackets(),
    ]);
  } finally {
    pollLoopRunning = false;
  }
}

// ---- wiring --------------------------------------------------------------

window.addEventListener("DOMContentLoaded", () => {
  initTheme();
  renderBleStatus();
  renderBleStats();
  renderBleDevices();
  renderSignalStatus();
  renderSignalPackets();
  document.getElementById("btn-theme").addEventListener("click", toggleTheme);
  document.getElementById("btn-dashboard-reset").addEventListener("click", resetDashboardSession);
  document.getElementById("tabs").addEventListener("click", e => {
    const btn = e.target.closest(".nav-item");
    if (btn) switchTab(btn.dataset.tab);
  });
  document.querySelectorAll(".link[data-tab]").forEach(a => a.addEventListener("click", () => {
    switchTab(a.dataset.tab);
    if (a.dataset.kind) {
      document.getElementById("f-kind").value = a.dataset.kind;
      renderDeviceTable();
    }
  }));

  ["f-search", "f-rssi"].forEach(id => document.getElementById(id).addEventListener("input", renderDeviceTable));
  ["f-kind", "f-manuf", "f-band", "f-open", "f-named"].forEach(id => document.getElementById(id).addEventListener("change", renderDeviceTable));
  document.querySelectorAll("#device-table thead th").forEach(th => th.addEventListener("click", () => {
    const key = th.dataset.key;
    if (sortKey === key) sortDir *= -1; else { sortKey = key; sortDir = 1; }
    renderDeviceTable();
  }));

  document.getElementById("btn-pause").addEventListener("click", () => {
    paused = !paused;
    const btn = document.getElementById("btn-pause");
    btn.textContent = paused ? "Resume View" : "Pause View";
    btn.classList.toggle("active", paused);
  });

  document.getElementById("btn-clear").addEventListener("click", () => {
    if (!confirm("Clear the device table, map, and dashboard in WirelessBOSS?\n\nKismet keeps capturing in the background - devices may reappear on the next refresh unless the view is paused.")) return;
    devices = [];
    selectedMac = null;
    renderDeviceTable();
    document.getElementById("inspector").classList.remove("open");
    if (mapInited) { Object.keys(markers).forEach(mac => map.removeLayer(markers[mac])); markers = {}; }
    stats = emptyStats();
    statsHistory = [];
    activityHistory = [];
    renderDashboard();
  });

  document.getElementById("btn-export").addEventListener("click", async () => {
    const r = await fetch("/api/export/csv", { method: "POST" });
    const j = await r.json();
    showToast(j.ok ? `Exported ${j.count} devices to ${j.folder}` : j.message);
  });

  document.getElementById("btn-clear-alerts").addEventListener("click", async () => {
    await fetch("/api/alerts/clear", { method: "POST" });
    alerts = [];
    renderAlerts();
  });

  document.getElementById("btn-clear-data").addEventListener("click", async () => {
    if (!confirm("Permanently delete all captured kismetdb and pcap files on disk?\n\nThis cannot be undone, and capture must be stopped first (Kismet holds these files open while recording).")) return;
    const r = await fetch("/api/data/clear", { method: "POST" });
    const j = await r.json();
    showToast(j.message);
    refreshFiles();
  });

  document.getElementById("btn-place-location").addEventListener("click", () => {
    setPlacingLocation(!placingLocation);
  });

  document.getElementById("btn-capture").addEventListener("click", async () => {
    const url = status.capture_running ? "/api/capture/stop" : "/api/capture/start";
    const r = await fetch(url, { method: "POST" });
    const j = await r.json();
    showToast(j.message);
  });

  document.getElementById("ins-close").addEventListener("click", () => {
    document.getElementById("inspector").classList.remove("open");
    selectedMac = null;
    renderDeviceTable();
  });
  document.getElementById("ins-deauth").addEventListener("click", () => quickAction("deauth"));
  document.getElementById("ins-handshake").addEventListener("click", () => quickAction("handshake"));

  document.getElementById("ble-device-search").addEventListener("input", renderBleDevices);
  document.getElementById("ble-follow-signal").addEventListener("click", followBleInSignal);
  ["ble-channel", "ble-phy", "ble-advertiser", "ble-initiator", "ble-ltk"].forEach(id => {
    document.getElementById(id).addEventListener("input", renderSignalBleProfile);
    document.getElementById(id).addEventListener("change", renderSignalBleProfile);
  });
  document.getElementById("signal-configure-ble").addEventListener("click", () => {
    document.getElementById("ble-advanced").open = true;
    switchTab("ble");
  });
  document.getElementById("ble-start").addEventListener("click", async () => {
    try {
      const result = await fetchJSON("/api/ble/start", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bleCapturePayload()),
      });
      showToast(result.message || "BLE capture started.");
      await refreshBleStatus();
    } catch (e) { showToast(e.message); }
  });
  document.getElementById("ble-stop").addEventListener("click", async () => {
    try {
      const result = await fetchJSON("/api/ble/stop", { method: "POST" });
      showToast(result.message || "BLE capture stopped.");
      await refreshBleStatus();
    } catch (e) { showToast(e.message); }
  });
  document.getElementById("ble-pause").addEventListener("click", () => {
    bleRequestGeneration += 1;
    blePaused = !blePaused;
    const btn = document.getElementById("ble-pause");
    btn.textContent = blePaused ? "Resume view" : "Pause view";
    btn.classList.toggle("active", blePaused);
    showToast(blePaused ? "BLE view paused; the analyzer continues capturing." : "BLE live view resumed.");
    if (!blePaused) {
      refreshBleStats().catch(() => {});
      refreshBleDevices().catch(() => {});
      refreshBlePackets().catch(() => {});
    }
  });
  document.getElementById("ble-clear").addEventListener("click", async () => {
    if (!confirm("Clear the BLE device and packet buffers for this session?\n\nThis does not disconnect or transmit to any BLE device.")) return;
    bleRequestGeneration += 1;
    try {
      const result = await fetchJSON("/api/ble/clear", { method: "POST" });
      bleRequestGeneration += 1;
      bleDevices = []; blePackets = []; bleStats = {}; blePacketAfter = 0; selectedBleAddress = null;
      renderBleStats(); renderBleDevices();
      showToast(result.message || "BLE session cleared.");
    } catch (e) { showToast(e.message); }
  });

  document.getElementById("signal-start").addEventListener("click", async () => {
    if (signalActionPending) return;
    const source = document.getElementById("signal-source").value;
    const apiBase = signalApiBase();
    signalActionPending = true;
    signalSourceGeneration += 1;
    renderSignalStatus();
    let refreshAfter = false;
    try {
      const options = { method: "POST" };
      if (source === "ble") {
        options.headers = { "Content-Type": "application/json" };
        options.body = JSON.stringify(bleCapturePayload());
      }
      const result = await fetchJSON(`${apiBase}/start`, options);
      if (apiBase !== signalApiBase()) return;
      if (result.ok === false) {
        showToast(result.message || `Could not start ${source.toUpperCase()} capture.`);
        return;
      }
      signalSourceGeneration += 1;
      showToast(result.message || `${source.toUpperCase()} signal capture started.`);
      signalCapturePausedSource = null;
      if (result.status) signalStatus = { ...result.status, source };
      refreshAfter = true;
    } catch (e) { showToast(e.message); }
    finally {
      signalActionPending = false;
      renderSignalStatus();
    }
    if (refreshAfter) await refreshSignalStatus();
  });
  document.getElementById("signal-stop").addEventListener("click", async () => {
    if (signalActionPending) return;
    const source = document.getElementById("signal-source").value;
    if (signalCapturePausedSource === source) {
      signalSourceGeneration += 1;
      signalCapturePausedSource = null;
      renderSignalStatus();
      showToast("Paused capture ended. The preserved packet rows remain available.");
      return;
    }
    const apiBase = signalApiBase();
    signalActionPending = true;
    signalSourceGeneration += 1;
    renderSignalStatus();
    let refreshAfter = false;
    try {
      const result = await fetchJSON(`${apiBase}/stop`, { method: "POST" });
      if (apiBase !== signalApiBase()) return;
      if (result.ok === false) {
        showToast(result.message || "Could not stop Signal Analysis capture.");
        return;
      }
      signalSourceGeneration += 1;
      showToast(result.message || "Signal capture stopped.");
      signalCapturePausedSource = null;
      if (result.status) signalStatus = { ...result.status, source };
      refreshAfter = true;
    } catch (e) { showToast(e.message); }
    finally {
      signalActionPending = false;
      renderSignalStatus();
    }
    if (refreshAfter) await refreshSignalStatus();
  });
  document.getElementById("signal-pause-capture").addEventListener("click", async () => {
    if (signalActionPending) return;
    const source = document.getElementById("signal-source").value;
    const apiBase = signalApiBase();
    const resuming = signalCapturePausedSource === source;
    signalActionPending = true;
    signalSourceGeneration += 1;
    renderSignalStatus();
    let refreshAfter = false;
    try {
      let options = { method: "POST" };
      if (resuming && source === "ble") {
        options = {
          ...options,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(bleCapturePayload()),
        };
      }
      const action = resuming ? "start" : "stop";
      const result = await fetchJSON(`${apiBase}/${action}`, options);
      if (apiBase !== signalApiBase()) return;
      if (result.ok === false) {
        showToast(result.message || `Could not ${resuming ? "resume" : "pause"} capture.`);
        return;
      }
      signalSourceGeneration += 1;
      signalCapturePausedSource = resuming ? null : source;
      if (result.status) signalStatus = { ...result.status, source };
      showToast(resuming
        ? (result.message || "Capture resumed in a new file segment.")
        : "Capture paused. Packet rows are preserved; no new source packets will be recorded.");
      refreshAfter = true;
    } catch (e) { showToast(e.message); }
    finally {
      signalActionPending = false;
      renderSignalStatus();
    }
    if (refreshAfter) await refreshSignalStatus();
  });
  document.getElementById("signal-pause").addEventListener("click", () => {
    signalSourceGeneration += 1;
    signalPaused = !signalPaused;
    const btn = document.getElementById("signal-pause");
    btn.textContent = signalPaused ? "Resume view" : "Pause view";
    btn.classList.toggle("active", signalPaused);
    showToast(signalPaused
      ? (signalStatus.running ? "Packet view paused; capture continues in the background." : "Packet view paused; the selected source capture is stopped.")
      : "Live packet view resumed.");
    if (!signalPaused) refreshSignalPackets().catch(() => {});
  });
  document.getElementById("signal-clear").addEventListener("click", async () => {
    if (signalActionPending) return;
    const clearingBle = document.getElementById("signal-source").value === "ble";
    const clearMessage = clearingBle
      ? "Clear the BLE packet buffer, nearby-device list, and BLE statistics?\n\nCapture files are not deleted."
      : "Clear the live Wi-Fi packet buffer?\n\nCapture files are not deleted.";
    if (!confirm(clearMessage)) return;
    signalActionPending = true;
    signalSourceGeneration += 1;
    if (clearingBle) bleRequestGeneration += 1;
    const apiBase = signalApiBase();
    renderSignalStatus();
    try {
      const result = await fetchJSON(`${apiBase}/clear`, { method: "POST" });
      if (apiBase !== signalApiBase()) return;
      signalSourceGeneration += 1;
      if (clearingBle) bleRequestGeneration += 1;
      resetSignalFeed();
      signalStatus = { ...signalStatus, packet_count: 0 };
      if (clearingBle) {
        bleDevices = []; blePackets = []; bleStats = {}; blePacketAfter = 0; selectedBleAddress = null;
        renderBleStats(); renderBleDevices();
      }
      showToast(result.message || "Signal packet buffer cleared.");
    } catch (e) { showToast(e.message); }
    finally {
      signalActionPending = false;
      renderSignalStatus();
    }
  });
  document.getElementById("signal-source").addEventListener("change", () => {
    signalSourceGeneration += 1;
    signalCapturePausedSource = null;
    ["signal-address", "signal-channel", "signal-rssi", "signal-type", "signal-text"].forEach(id => {
      document.getElementById(id).value = "";
    });
    resetSignalFeed();
    signalStatus = {};
    renderSignalStatus();
    refreshSignalStatus().catch(() => {});
    refreshSignalPackets().catch(() => {});
  });
  let signalFilterTimer = null;
  ["signal-address", "signal-channel", "signal-type"].forEach(id => document.getElementById(id).addEventListener("input", () => {
    clearTimeout(signalFilterTimer);
    signalFilterTimer = setTimeout(() => {
      signalSourceGeneration += 1;
      resetSignalFeed();
      refreshSignalPackets().catch(() => {});
    }, 180);
  }));
  ["signal-text", "signal-rssi"].forEach(id => document.getElementById(id).addEventListener("input", renderSignalPackets));

  document.getElementById("t-ap-picker").addEventListener("change", e => {
    document.getElementById("t-bssid").value = e.target.value;
  });

  document.getElementById("t-authorize").addEventListener("change", async e => {
    await fetch("/api/tools/authorize", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ authorized: e.target.checked }),
    });
  });
  function toolsPayload() {
    return {
      bssid: document.getElementById("t-bssid").value,
      client_mac: document.getElementById("t-client").value,
      count: Math.max(1, Math.min(20, parseInt(document.getElementById("t-count").value || "5", 10))),
      iface: document.getElementById("t-iface").value,
    };
  }
  document.getElementById("btn-deauth").addEventListener("click", async () => {
    const r = await fetch("/api/tools/deauth", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(toolsPayload()) });
    const j = await r.json(); if (!j.ok) showToast(j.message);
    refreshToolsStatus();
  });
  document.getElementById("btn-handshake").addEventListener("click", async () => {
    const r = await fetch("/api/tools/handshake", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(toolsPayload()) });
    const j = await r.json(); if (!j.ok) showToast(j.message);
    refreshToolsStatus();
  });
  document.getElementById("btn-injtest").addEventListener("click", async () => {
    const iface = encodeURIComponent(document.getElementById("t-iface").value);
    const r = await fetch(`/api/tools/injection_test?iface=${iface}`, { method: "POST" });
    const j = await r.json(); if (!j.ok) showToast(j.message);
    refreshToolsStatus();
  });
  document.getElementById("btn-tool-stop").addEventListener("click", async () => {
    await fetch("/api/tools/stop", { method: "POST" });
    refreshToolsStatus();
  });

  pollLoop();
  setInterval(pollLoop, 2000);
});
