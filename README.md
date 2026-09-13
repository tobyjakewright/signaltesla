# SignalTesla — Pi 5 Wardriving Rig

A one-command provisioning repo that turns a fresh Raspberry Pi OS (64-bit,
**with Desktop**) install into a self-contained Wi-Fi + BLE wardriving rig
with GPS tagging, Kismet, a lightweight custom dashboard, and a minimal
web launcher — plus a hotspot your Tesla can join the same way it joins a
wireless CarPlay dongle.

## Hardware this targets

| Role | Hardware | Notes |
|---|---|---|
| Compute | Raspberry Pi 5 | Raspberry Pi OS (Bookworm/Trixie), **Desktop** variant, not Lite |
| Wi-Fi wardriving capture | Alfa AWUS036AXML | MediaTek mt7921u chipset, 2.4/5/6GHz |
| BLE capture | WCH BLE Analyzer Pro | `ble-driver/` - built from source on the Pi |
| GPS | VK-162 USB GPS (u-blox 7) | Tags every Wi-Fi hit with lat/lon |
| Tesla-facing hotspot | Pi 5's onboard Wi-Fi | Hosts the "WarDriving" AP the car joins |

## What it sets up

- Onboard Wi-Fi hosts a **"WarDriving" AP** at `192.168.3.1/24` with its
  own DHCP server (hostapd + dnsmasq), scoped so it doesn't interfere with
  anything else on the Pi.
- The Alfa adapter is pinned to a stable interface name and handed to
  **Kismet** as the wardriving capture source, with the explicit 5GHz
  channel list its MT7921AU chipset needs (see "Vanilla Raspberry Pi OS
  adaptation" below) - Kismet puts it into monitor mode itself, runs as a
  normal system service, and its REST API is what the custom dashboard
  polls.
- **gpsd** reads the VK-162 and feeds GPS into Kismet so every SSID is
  geotagged.
- **`ble-driver/`** is the WCH BLE Analyzer Pro's own libusb driver
  (`wch_capture`) - compiled from source on the Pi and run as a plain
  always-on capture. It writes a timestamped `.pcap` plus a JSON-lines
  feed that the dashboard's BLE tab tails.
- A single **Flask app**, reverse-proxied by nginx on port 80:
  - `/launcher` — four buttons that forward straight to each dedicated
    UI (no wrapper chrome, no iframes - browser back/history returns you):
    **Kismet**, **VNC over Web**, **Custom Stats GUI**, **Export**
  - `/stats` — the custom dashboard (Dashboard / Wi-Fi Devices / BLE
    Devices / Alerts tabs)
  - `/export` — lists and downloads capture files (per-file or one ZIP)
- **wayvnc + noVNC** for the VNC-over-Web button (wayvnc, not x11vnc,
  because the desktop is `rpd-labwc` - a Wayland compositor - which
  x11vnc cannot attach to at all), plus **Onboard** (an
  on-screen keyboard) configured to auto-show whenever a text field is
  focused anywhere in that same desktop session - including inside the
  VNC view, since Onboard runs on the Pi itself and VNC just mirrors
  whatever's on its screen.
- Wi-Fi regulatory domain set to **GB** (unlocks 5GHz/6GHz channels).
- Everything above is a plain system-level systemd service, so it all
  comes back on every boot with no manual steps and no per-user session
  dependency.

## The custom stats GUI - what it is and isn't

The `/stats` dashboard's visual layout (dark theme, tab strip, stat
tiles, sortable device tables) and its Wi-Fi-side backend logic
(`webapp/wifi/`) are adapted from a prior project of mine, WirelessBOSS -
but **that project's application itself is not vendored or run here**.
What's actually in this repo:

- `webapp/wifi/kismet_client.py`, `classify.py`, `models.py` - a thin,
  portable REST client that polls Kismet and normalizes its device JSON.
  No special dependency beyond Kismet's own API; kept close to the
  original since it's genuinely simple, well-behaved logic.
- `webapp/ble/reader.py` - a **new, much smaller** BLE reader I wrote for
  this rig. It decodes just enough of a BLE advertising PDU (address,
  advertised name, manufacturer) to populate a simple device list. It
  does not track connections, PHYs, or decryption - see below.
- `webapp/templates/stats.html` + `static/stats.js` - a fresh, small
  (~200 line) implementation of the same visual language as the rest of
  this app's UI, sized to 4 tabs instead of the original's 7.

**What the stats GUI leaves out on purpose**, versus the WirelessBOSS
project it's inspired by:
- **Wi-Fi Lab** (deauth / injection-readiness tools) - an active,
  authorization-gated offensive capability; out of scope for "basic."
- **Signal Analysis** (live Wireshark-style packet dissection via tshark)
  - a heavier feature with its own process-lifecycle management.
- **BLE connection-following, PHY/LTK selection, and decryption** - the
  original's `ble/wch_provider.py` is a real process-lifecycle manager
  with threaded start/stop, filters, and AES-CCM decryption tracking.
  This rig just runs `wch_capture` continuously and reads its output.
- **Map / offline tiles** - GPS tagging of captures still happens
  (gpsd → Kismet), there's just no live map view in `/stats`.

Say if you want any of these back - each is addable without reviving the
whole original app, since Kismet and the WCH driver already produce
everything they'd need.

## Quickstart

1. Flash Raspberry Pi OS **with Desktop** (not Lite) to the SD card. In
   Raspberry Pi Imager's OS customization (the gear icon), set your
   hostname, username/password, and enable SSH — you'll need to know
   that username, though `install.sh` also auto-detects it.
2. Boot the Pi, get it on your home network (ethernet is easiest for
   first setup), and SSH in.
3. Clone this repo and run the installer:
   ```
   git clone <your-fork-url> wardriving-rig
   cd wardriving-rig
   sudo ./install.sh
   ```
4. Read the summary it prints, then `sudo reboot`.
5. On the Tesla's own touchscreen: Controls → Wi-Fi → join **"WarDriving"**
   using the passphrase from `config/rig.conf` (`AP_PASSPHRASE`). This one
   step Tesla makes you do by hand — the AP can't push it to the car.
6. Join the same "WarDriving" network with your phone or laptop and open
   `http://192.168.3.1/launcher`.

Re-running `sudo ./install.sh` any time (e.g. after editing
`config/rig.conf`) is safe — every step is idempotent.

## Vanilla Raspberry Pi OS adaptation

Every dependency here has been checked against plain Debian/Raspberry Pi
OS, not assumed from a Kali-oriented starting point:

- **Kismet** is genuinely not in Debian's own repos (only Kali ships it
  directly) - `install.sh` adds Kismet's own official apt repo
  (`kismetwireless.net`, which publishes both `bookworm` and `trixie`
  builds) rather than assuming `apt install kismet` works.
- **The WCH BLE Analyzer Pro driver** (`ble-driver/`) is plain, portable
  C11 against `libusb-1.0` and `libcrypto` via pkg-config - no x86 or
  Kali-specific code. It's compiled fresh on the Pi's own ARM64 toolchain
  by `install.sh` (verified: builds clean and its own vector test suite
  passes on both x86_64 and arm64 during development).
- **The MT7921AU 5GHz channel-list requirement**: Kismet's automatic
  channel enumeration for this specific chipset only hops 2.4GHz unless
  given an explicit `channels="..."` list - `kismet/kismet_site.conf.tmpl`
  bakes in the ETSI/UK list already; see the comment there if you need
  the US/Canada UNII-3 high channels added.
- Everything else (`gpsd`, `hostapd`, `dnsmasq`, `nginx`, `wayvnc`,
  `novnc`, `websockify`, `onboard`, `build-essential`, `libusb-1.0-0-dev`,
  `libssl-dev`) is a standard Debian/Raspberry Pi OS package - no
  substitution needed.

## Configuration

All tunables live in `config/rig.conf` (created from
`config/rig.conf.example` on first run). Notably:

- `AP_PASSPHRASE` (Wi-Fi hotspot) / `VNC_PASSWORD` / `KISMET_PASS` —
  `install.sh` asks for each of these interactively on first run (input
  hidden, like a password prompt); press Enter with nothing typed to get
  a random one instead. `VNC_PASSWORD` is used as wayvnc's plain
  username+password auth (`RIG_USER` / `VNC_PASSWORD`, no length limit -
  unlike the old x11vnc setup, which only honored the first 8 characters
  of a classic VNC password).
- `AP_INTERFACE` / `MON_INTERFACE` — stable names assigned by udev
  (`udev/10-wardriving-*.link`), matched by driver (`brcmfmac` for
  onboard Wi-Fi, `mt7921u` for the Alfa) rather than `wlan0`/`wlan1`,
  since USB enumeration order isn't guaranteed across reboots.
- `KISMET_LOG_DIR` — where Kismet's kismetdb/pcapng and the BLE driver's
  pcap/JSON-lines all land; what `/export` lists.

`config/rig.conf` is gitignored — only the `.example` template is meant
to be committed, so none of your real credentials ends up in a GitHub
repo. wayvnc's own credentials live outside this repo entirely, in
`~/.config/wayvnc/config` under `RIG_USER`'s home directory.

## Pushing this to GitHub

This repo has no remote configured yet. To publish it:
```
git add -A
git commit -m "Initial wardriving rig"
gh repo create <name> --private --source=. --push
```
(or create the repo on github.com and `git remote add origin <url> && git push -u origin main`).
Then on the Pi: `git clone <url> wardriving-rig && cd wardriving-rig && sudo ./install.sh`.

## Known caveats — read before you rely on this in the car

**mt7921u monitor mode / packet injection.** The Alfa AWUS036AXML's
in-kernel `mt7921u` driver has historically had limited or no monitor-mode
injection support (RX-only monitor mode has been more reliable than TX).
Kismet will still do passive wardriving capture fine either way, but if
you need injection for anything, check `iw list | grep -A8 "Supported
interface modes"` on your specific kernel build first — don't assume it
without checking, driver support here has been a moving target.

**On-screen keyboard auto-show.** Onboard is installed and its
auto-show setting is preset during install, but that preset is applied
blind (no desktop session exists yet at install time, since you're
SSH'd in), so it may not stick on every OS version. If a text field
doesn't bring the keyboard up after rebooting, open Onboard Settings on
the desktop directly and enable "Auto-show when editing text" by hand.

**Tesla auto-loading a page from the AP.** Third-party wireless CarPlay
adapters get their video onto the Tesla's screen using an undocumented,
reverse-engineered mechanism that isn't publicly specified by Tesla and
has varied by adapter and Tesla software version. This repo gets you the
concrete, verifiable part — the Pi hosting an AP the Tesla can join, with
its own DHCP server, at an address range (`192.168.3.0/24`) chosen not to
collide with Tesla's own internal ranges. Whether the Tesla's screen
auto-displays anything from it isn't something this repo can guarantee;
treat that part as experimental and verify it yourself against your
car's current software version. Regardless, once joined, your phone/
laptop can always reach `http://192.168.3.1/launcher` normally.

**BLE JSON-lines log growth.** `ble-live.jsonl` (used by the stats GUI's
BLE tab) grows for as long as the capture service runs between reboots -
there's no log rotation. It's read efficiently (only the last ~256KB is
ever parsed per request), so this only matters for disk space on a very
long uninterrupted run; the timestamped `.pcap` file is the real capture
record regardless.

## Responsible use

Everything here operates on hardware you own: your Pi, your Tesla, your
adapters. Passive Wi-Fi/BLE wardriving (receiving broadcast beacons and
advertisements) is generally legal in the UK and most jurisdictions —
the line to stay on the right side of is not *associating with or using*
networks that aren't yours. This rig doesn't do that; the only network it
connects to as a client is your own car.

## Troubleshooting

```
iw dev                                  # confirm wlan_ap and wlan_mon both exist
systemctl status hostapd dnsmasq wardriving-ap-netconfig nginx
systemctl status kismet wardriving-ble wardriving-web wardriving-novnc
pgrep -a wayvnc                         # wayvnc runs inside the desktop session, not as a system service
journalctl -u kismet -n 100
journalctl -u wardriving-ble -n 100
lsusb -d 1a86:8009                      # WCH analyzer - 3 devices expected
cgps -s                                 # GPS fix (needs clear sky view)
```

If `wlan_ap`/`wlan_mon` don't show up: `dmesg | grep -iE 'brcmfmac|mt7921'`
to confirm both Wi-Fi devices were detected, then `udevadm trigger` and
reboot.

## Repo layout

```
install.sh                  one-shot installer (idempotent)
config/rig.conf.example      all tunables - copy to rig.conf and edit
udev/                        stable interface/device naming
hostapd/, dnsmasq/           AP + DHCP config templates
kismet/                      Kismet site config template (5GHz channel fix)
nginx/                       reverse proxy for the launcher
systemd/                     unit files for every service this installs
ble-driver/                  WCH BLE Analyzer Pro's own libusb driver source
webapp/                      Flask app: /launcher, /stats, /export
  wifi/                        Kismet REST polling + device classification
  ble/                         BLE JSON-lines reader (basic - see above)
scripts/                     helpers install.sh calls
```
