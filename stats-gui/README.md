# WirelessBOSS

A local wireless-analysis workbench for Kali Linux, built for authorized
testing with an Alfa AWUS036AXML and the three-radio WCH BLE Analyzer Pro.
It launches like Kismet's own web UI: start a local server and open a
browser. The app combines a Wi-Fi dashboard, guided lab tools, beginner-
friendly BLE discovery, live Wireshark-style packet inspection, and
CSV/PCAP export.

**Authorized/white-hat use only.** Only scan, capture, or inject against
networks you own or have explicit written authorization to test.

## Architecture

Kismet does the hard, safety-critical part - monitor mode setup, channel
hopping, 802.11 frame parsing/classification, GPS tagging, and storage
(kismetdb/SQLite) - via its REST API. WirelessBOSS is a small local web
server (FastAPI) that polls that API and serves a browser UI: a live
dashboard, a sortable/filterable device table, a map, an alerts feed,
and one-click deauth/handshake/injection-test tools.

```
Alfa AWUS036AXML --monitor mode--> Kismet (headless) --REST API--> WirelessBOSS server --HTTP--> your browser
                                       |                                |
                                    gpsd (GPS)                TShark + Wi-Fi Lab tools
                                                                        ^
 WCH BLE Analyzer Pro --USB/libusb--> wch_capture --JSON + BLE PCAP-----|
```

```
wirelessboss/
  config.py            # ~/.config/wirelessboss/config.yaml loader
  models.py             # normalized WifiDevice / BleDevice / GpsFix
  kismet_client.py       # Kismet REST polling
  classify.py             # raw Kismet JSON -> WifiDevice (standard/band/encryption/etc.)
  stats.py                 # device list -> dashboard aggregates (charts, manuf-by-kind, channels...)
  storage_stats.py          # kismetdb/pcap size + disk growth/time-to-full
  capture_control.py         # start/stop the Kismet process itself
  export.py                   # CSV export
  tile_server.py                # local offline map-tile HTTP server
  ble/parser.py                   # BLE PDU / advertising-data decoder
  ble/wch_provider.py             # WCH subprocess, devices, RSSI + packet rings
  signal_capture.py               # Kismet PCAP-NG -> TShark live Wi-Fi packets
  server/                          # <- the web backend (primary interface)
    main.py                          # entry point: python -m wirelessboss.server.main
    app.py                            # FastAPI app + REST routes, serves web/
    state.py                           # background Kismet-polling thread + shared state, tool runner
  web/                              # <- the web frontend (primary interface)
    index.html                        # SPA shell (Dashboard/Devices/BLE/Signal/Map/Alerts/Wi-Fi Lab)
    static/app.js                      # polling, rendering, filters, charts (no build step, vanilla JS)
    static/style.css                    # dark theme
  gui/                              # legacy PyQt6 desktop app - optional, see below
setup/
  install_kismet.sh    # one-time host setup (apt packages, venv, kismet group, aireplay-ng capabilities)
  install_desktop_launcher.sh  # installs the app-drawer icon
  kismet_site.conf.example
scripts/
  start_kismet.sh
  download_offline_tiles.py
assets/
  leaflet/, chartjs/      # vendored libraries (see Offline / field use below)
wirelessboss-web-launcher.sh   # app-drawer entry point: starts Kismet + the web server, opens your browser
```

**About the legacy PyQt6 desktop app** (`wirelessboss/app.py`,
`wirelessboss/gui/`): the original version of WirelessBOSS was a native
Qt desktop app. It's still in the repo and still works
(`./.venv/bin/python -m wirelessboss.app`, needs the optional PyQt6
dependencies - see `requirements.txt`), but the web UI is now the
primary, actively developed interface - cleaner layout, way more room
for data, and no Qt/WebEngine dependency to install. All the
non-UI logic (`kismet_client.py`, `classify.py`, `stats.py`,
`storage_stats.py`, `capture_control.py`, `export.py`, `tile_server.py`,
`config.py`) is shared by both and has zero PyQt dependency.

## One-command install or upgrade on Kali

Extract the transfer package into a new folder on the Kali machine, open a
terminal in that folder, and run this as your normal desktop user:

```bash
./install.sh
```

The installer downloads all required Kali packages, stages and tests the new
version, backs up the old app/driver/services/launcher, rebuilds the WCH driver
from source, installs the current udev rule, recreates the Python environment,
and validates the local `/api/status` endpoint before declaring success. It
preserves `~/.config/wirelessboss`, `~/.kismet`, `/etc/kismet/kismet_site.conf`,
`/etc/default/gpsd`, captures, offline map tiles, and arbitrary old source
folders. The canonical app is installed under
`~/.local/share/wirelessboss/app`; timestamped rollback material is kept under
`~/.local/share/wirelessboss/backups/`.

Useful options:

```bash
./install.sh --no-start
./install.sh --old-install /path/to/old/WIFI-BOSS
```

To build a deterministic transfer-ready archive from this source tree:

```bash
python3 setup/build_kali_package.py
```

This creates `dist/WirelessBOSS-Kali-Installer.tar.gz` plus a SHA-256 file.
The archive deliberately excludes old archives, captures, virtual environments,
object files, and any prebuilt `wch_capture`; the driver is rebuilt on Kali.

Useful diagnostics on Kali:

```bash
systemctl --user status wirelessboss-web.service wirelessboss-kismet.service
journalctl --user -u wirelessboss-web.service -n 100
journalctl --user -u wirelessboss-kismet.service -n 100
```

## Setup (on the Kali machine)

The web UI, parsers, process lifecycle, and driver build are tested off-hardware.
Real RF capture still depends on Kali, Kismet, and the attached adapters, so run
the hardware smoke checks below on the target machine before relying on a session.

```bash
git clone <this repo> WIFI-BOSS && cd WIFI-BOSS
./install.sh
```

That installs Kismet, gpsd, aircrack-ng, TShark, libusb, OpenSSL headers and build tools;
compiles the WCH driver for the current Kali machine; installs its udev rule;
grants `aireplay-ng` the raw-socket capabilities it needs; creates the Python
environment; and drops a starter `kismet_site.conf` into `/etc/kismet/`.

It also makes 5 GHz capture work and persist: it sets the Wi-Fi regulatory
domain and installs a boot-time `wifi-regdom.service` for it (pass
`--country GB` / `--country US` / etc., or set `WIRELESSBOSS_WIFI_COUNTRY`;
default is whatever the box is already on, else `GB`), adds the
region-appropriate 5 GHz channel list to the Kismet `source=` line, and
tells NetworkManager to stop managing the capture radio (otherwise it
fights Kismet for channel control and the scan sticks on one channel).

If Wi-Fi is already configured and you only need the new BLE/Signal support:

```bash
./setup/install_ble_analyzer.sh
```

Then:

1. Plug in the AWUS036AXML, find its interface name with `iw dev` (often
   `wlan0` if it's the only wireless adapter, `wlan1` if there's a
   built-in one too).
2. Edit `/etc/kismet/kismet_site.conf` (sudo required - **this file is
   only read from `/etc/kismet/`, not `~/.kismet/`**, despite what some
   Kismet docs suggest for other versions) and set the interface name in
   the `source=` line. The starter config's `source=` line already carries
   an explicit `channels="..."` list - **keep it**: without it Kismet's
   auto channel enumeration for the AXML's MT7921AU chip only hops 2.4 GHz,
   so the quick-start button and the Kismet service only ever see 2.4 GHz
   APs. Trim/extend the list to your regulatory domain (`iw reg get`).
   Upgrades add this list to an existing config automatically (a
   timestamped `.bak` is kept); restart Kismet afterwards.
3. First run needs REST API credentials - set them directly rather than
   going through the web UI flow:
   ```bash
   cat > ~/.kismet/kismet_httpd.conf <<EOF
   httpd_username=wirelessboss
   httpd_password=change-me
   EOF
   ```
4. Put the same username/password into
   `~/.config/wirelessboss/config.yaml` (written on first WirelessBOSS run,
   under the `kismet:` section).
5. Launch from the app-drawer icon (installed via
   `setup/install_desktop_launcher.sh`) - it starts Kismet if it isn't
   already running, starts WirelessBOSS's own web server, and opens your
   browser to it automatically. Or do it by hand:
   ```bash
   kismet --no-ncurses &                            # if not already running
   ./.venv/bin/python -m wirelessboss.server.main &  # then open http://127.0.0.1:8080/
   ```
6. Plug in the WCH analyzer and run `lsusb -d 1a86:8009`. A healthy Analyzer
   Pro appears as three MCU devices. Open **BLE Analysis** and choose
   **Start capture**; the default uses one radio on each of channels
   37/38/39 and saves a standard BLE PCAP automatically.

Recent Kismet builds also have a native `wch-btle-0` datasource. WirelessBOSS
uses the bundled driver directly so it can provide its beginner device/RSSI
model consistently on Kali versions where that helper is absent. Do not enable
the same analyzer in Kismet while a WirelessBOSS BLE session is running—only
one process can claim its USB interfaces. See the
[Kismet WCH datasource documentation](https://kismetwireless.net/docs/readme/datasources/bluetooth-wch-ble-analyzer-pro/)
for the alternative setup.

GPS: plug in your GPS module, point `gpsd` at its device (`/etc/default/gpsd`
or `sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock`), and Kismet will tag
every device with a location automatically as long as it has a fix.

## What's in the web UI

- **Dashboard tab**: stat tiles (devices, APs, clients, open networks, new
  devices in the last 5 min, alerts, GPS/Kismet/recording status),
  charts for device type / wireless standard / band / encryption / RSSI
  distribution, channel utilization split by band, manufacturer
  breakdown *per device category* (e.g. Access Points: Cisco Meraki 6,
  Ruckus 11, Ubiquiti 2 - not one flat mixed list), a theoretical-speed
  reference table per wireless standard, and top APs by client count.
  Charts are hand-rolled inline SVG/CSS (no charting library needed at
  all, not even a vendored one).
- **Devices tab**: sortable/filterable table - name/SSID, MAC, AP vs.
  client vs. ad-hoc, wireless standard (b/g/n/ac/ax/be, best-effort from
  HT/VHT/HE capability flags), band/channel, encryption, RSSI
  (color-coded), client count, manufacturer, packets, last seen.
  Free-text search plus type / manufacturer / band (2.4/5/6GHz) /
  min-RSSI / open-networks-only / named-devices-only filters (the last
  one hides anything showing its bare MAC as a name - cloaked APs,
  unidentified clients). Click a row to open the inspector panel with
  the full raw Kismet record and one-click **Deauth**/**Capture
  Handshake** buttons for that device.
- **BLE Analysis tab**: starts/stops the bundled WCH Linux capture tool,
  checks the driver and three USB radios, and listens to all three primary
  advertising channels at once. A radio which receives `CONNECT_IND` follows
  that connection natively across data channels 0–36. It turns packets into a beginner
  view with device names, address/privacy type, manufacturer-data owner,
  advertised services, connectable/scannable state, channel coverage,
  packet mix, RSSI trend and a per-channel signal graph. Select a device to
  correlate packets where it is either sender or target. Advanced controls
  select 1M/2M/Coded PHY, peer filters, and an optional known LTK for live
  AES-CCM decryption.
- **Signal Analysis tab**: a bounded, live Wireshark-style table with
  start/stop, **Pause Capture** (the source stops and resume opens a new
  segment), **Pause View** (recording continues), address/channel/type/
  RSSI filters, plain-English frame purposes, decoded details and full hex
  bytes. BLE rows come from the WCH provider. Wi-Fi rows come from Kismet's
  live PCAP-NG endpoint and are dissected by TShark—the same dissector
  engine used by Wireshark—without competing for the monitor interface.
- **Map tab**: every geolocated device gets a marker, colored by
  open/AP/client; your own GPS position shows as a pulsing dot. Fully
  offline-capable - see below.
- **Alerts tab**: Kismet's built-in alert feed (rogue APs, known attack
  signatures, etc.), with a Clear Alerts button.
- **Wi-Fi Lab tab**: guided `aireplay-ng` injection-readiness / bounded
  deauth / reconnect-capture workflows, a captured-AP picker that fills
  the BSSID for first-time users, a reference panel, and a single
  session-level authorization checkbox. Tick it once and every one-click
  action elsewhere (the Devices table, the inspector panel) fires
  immediately - genuinely one click, no repeat confirmation, no tab
  switching required to see it happen (it switches you to Wi-Fi Lab
  automatically so you can watch the live `aireplay-ng` output).
- **Pause View**: freezes the table/map/dashboard so you can inspect
  what's captured so far without new rows scrolling everything around.
  Kismet keeps capturing in the background regardless - this only pauses
  what the browser is fetching/rendering.
- **Clear View**: resets the browser's own table/map/dashboard (with a
  confirmation prompt). Doesn't touch kismetdb/pcap files on disk or
  Kismet's own device cache - devices may reappear next refresh unless
  paused too.
- **Start/Stop Capture** (top-right on the Wi-Fi overview pages): starts or stops
  the Kismet process itself (`wirelessboss/capture_control.py`,
  pgrep/kill-based, works whether WirelessBOSS or you started Kismet).
  This is also what starts/stops PCAP recording, since Kismet writes
  kismetdb and pcapng together - see below.
- **PCAP recording for Wireshark**: `setup/kismet_site.conf.example` sets
  `log_types=kismetdb,pcapng`, so every capture session produces a
  standard `.pcapng` file directly usable in Wireshark, no conversion
  needed. The dashboard's Storage section tracks kismetdb size and pcap
  size separately, plus combined disk growth rate and time-to-full.
- **One-click CSV export**: writes `all_devices.csv`, `access_points.csv`,
  and `clients.csv` into a timestamped folder under
  `<capture_dir>/wirelessboss-exports/`.

## Development checks

After installing `requirements.txt` in a virtual environment, the hardware-free
regression checks are:

```bash
python -m unittest discover -s tests -v
python -m compileall -q wirelessboss
node --check wirelessboss/web/static/app.js
bash -n install.sh setup/install_or_upgrade.sh setup/install_kismet.sh \
  setup/install_ble_analyzer.sh scripts/start_kismet.sh setup/update_kali_web.sh
python3 setup/build_kali_package.py
```

The WCH source is also built with strict compiler warnings during development.
On Kali, finish with the real-hardware smoke test: confirm three `1a86:8009`
devices with `lsusb`, start an all-channel BLE capture, verify advertising
packets on 37/38/39, create an owned test connection, verify data packets on
0–36, then open the saved PCAP in Wireshark. If testing decryption, use an LTK
exported from your own endpoint and verify MIC-valid plaintext. No software-only
test can replace that USB/RF check.

## Offline / field use

This is out-and-about software - it needs to work with zero internet
while you're actually driving around.

- **No CDN dependencies anywhere.** The web UI's charts are hand-rolled
  inline SVG/CSS (no charting library at all). The map uses Leaflet,
  vendored locally in `wirelessboss/assets/leaflet/` and served by
  WirelessBOSS's own server (`/assets/leaflet/...`) - never loaded from
  a CDN. The self-location marker is pure CSS (a pulsing dot), not
  Leaflet's default image-based icon.
- **Map tiles come from WirelessBOSS's own local tile server**
  (`wirelessboss/tile_server.py`), reading pre-fetched tiles from
  `~/.local/share/wirelessboss/tiles` (configurable via
  `map.tiles_dir`/`map.tile_port` in `config.yaml`). A missing tile is
  just a blank square, not an error - exactly like a normal offline map.
- **Pre-fetch tiles for your area while you still have internet**
  (home/office wifi, before heading out):
  ```bash
  python3 scripts/download_offline_tiles.py \
    --south 51.48 --north 51.52 --west -0.15 --east -0.08 \
    --min-zoom 12 --max-zoom 16
  ```
  Get the bounding box from any map site (right-click → "what's here" /
  copy coordinates for two corners of your area). Re-run it for a new
  area whenever you need one - already-cached tiles are skipped. This
  respects OpenStreetMap's tile usage policy (rate-limited, real
  User-Agent, and it refuses to fetch more than 4000 tiles in one run
  unless you pass `--allow-large`) - keep areas town-sized, not
  country-sized, and see the script's docstring for the full policy
  notes if you're fetching a lot.
- **Everything else** (Kismet, gpsd, aircrack-ng, kismetdb/pcap logging,
  the WirelessBOSS web server itself) runs entirely on the Kali box with
  no external calls during normal operation - your browser only ever
  talks to `127.0.0.1`.

If you're fine requiring internet while driving (e.g. always tethered),
you can instead point `map.tile_url` in `config.yaml` straight at a
remote tile provider like `https://tile.openstreetmap.org/{z}/{x}/{y}.png` -
but the local tile server is the default because this is meant to work
with no signal.

## Current BLE boundaries and roadmap

- **Connection following**: the official v1.53 command/receive protocol is now
  implemented. Three radios monitor primary channels 37/38/39 and firmware
  natively follows captured legacy `CONNECT_IND` traffic across data channels
  0–36. The host labels the dynamic Access Address, CRCInit, peers, direction,
  LL control purpose and reconstructed CRC. PHY and peer filters use the exact
  vendor AA81 fields.
- **Encryption**: supplying a known 128-bit LTK enables host-side session-key
  derivation and live AES-CCM/MIC verification. The key is never sent to the
  analyzer. Passive LE Secure Connections key recovery from a passkey alone is
  not possible; export the LTK from an endpoint you control.
- **BLE 5 extended payloads**: the primary `ADV_EXT_IND` and its `AuxPtr`
  can be identified, but the secondary payload on channels 0–36 is not yet
  followed. Do not confuse "all three channels" with all 40 BLE channels.
- **Capture fidelity**: the receiver strips the CRC octets after validating
  them; the PCAP contains a deterministic host-reconstructed BLE CRC-24 and is
  marked valid only when the hardware error marker is clear.
  Its three MCU clocks are unsynchronised, so cross-channel order is based
  on host receipt time and is unsuitable for forensic microsecond timing.
- **Streaming transport**: packet tables currently use bounded incremental
  REST polling. A local WebSocket/SSE path would reduce latency further for
  very dense captures; complete data already remains in PCAP/PCAP-NG.
- **Negotiated data rate**: `classify.py` has a `_max_rate` hook that's
  currently a stub - Kismet doesn't cleanly expose a single "current
  rate" on the device summary; this needs per-packet `dot11.packet.datarate`
  from the packet feed. The Dashboard's speed table shows theoretical
  per-standard ceilings in the meantime, clearly labelled as such.
- **Export**: kismetdb already logs everything to SQLite for GIS/KML
  export via Kismet's own tooling (`kismetdb_to_*` scripts ship with
  Kismet) - a server-side "Export session" action that shells out to
  those is a natural next step alongside the existing CSV export.

## Notes on field-name accuracy

`kismet_client.py` / `classify.py` request whole Kismet sub-objects
(`kismet.device.base.signal`, `kismet.device.base.location`, `dot11.device`)
rather than guessing deep leaf-field paths, and every lookup falls back
gracefully if a field is missing. That said, Kismet's exact nested key
names can drift a little between versions - if you see blank
standard/RSSI/location columns against a live device, open
`http://localhost:2501/devices/views/all/devices.json` in a browser
while that device is visible, compare the JSON shape against
`classify.py`'s `_dig(...)` calls, and adjust the candidate key names.
