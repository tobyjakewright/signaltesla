# SignalTesla — Pi 5 Wardriving Rig

A one-command provisioning repo that turns a fresh Raspberry Pi OS (64-bit,
**with Desktop**) install into a self-contained Wi-Fi + BLE wardriving rig
with GPS tagging, Kismet, a full WirelessBOSS analysis dashboard, and a
minimal web launcher — plus a hotspot your Tesla can join the same way it
joins a wireless CarPlay dongle.

## Hardware this targets

| Role | Hardware | Notes |
|---|---|---|
| Compute | Raspberry Pi 5 | Raspberry Pi OS (Bookworm/Trixie), **Desktop** variant, not Lite |
| Wi-Fi wardriving capture | Alfa AWUS036AXML | MediaTek mt7921u chipset, 2.4/5/6GHz |
| BLE capture | WCH BLE Analyzer Pro | Own libusb driver, vendored under `stats-gui/` |
| GPS | VK-162 USB GPS (u-blox 7) | Tags every Wi-Fi/BLE hit with lat/lon |
| Tesla-facing hotspot | Pi 5's onboard Wi-Fi | Hosts the "WarDriving" AP the car joins |

## What it sets up

- Onboard Wi-Fi hosts a **"WarDriving" AP** at `192.168.3.1/24` with its
  own DHCP server (hostapd + dnsmasq), scoped so it doesn't interfere with
  anything else on the Pi.
- The Alfa adapter is pinned to a stable interface name and handed to
  **Kismet** as the wardriving capture source (Kismet puts it into
  monitor mode itself).
- **gpsd** reads the VK-162 and feeds GPS into Kismet/WirelessBOSS so
  every SSID/BLE device is geotagged.
- **stats-gui/** is a vendored copy of your own WirelessBOSS project - it owns
  Kismet's actual Wi-Fi source config (including the 5GHz channel-list
  workaround the AXML's MT7921AU chip needs), builds and runs the WCH BLE
  Analyzer Pro's driver from source, and serves the full dashboard
  (devices table, BLE analysis, live signal view, map, Wi-Fi Lab). See
  "How the stats GUI is wired in" below.
- A minimal **Flask web launcher**, reverse-proxied by nginx on port 80,
  at `/launcher` - four buttons that forward straight to each dedicated
  UI (no wrapper chrome, no iframes - browser back/history is how you
  return to it):
  - **Kismet** → the live Kismet UI directly
  - **VNC over Web** → noVNC, touch-controlled
  - **Custom Stats GUI** → the WirelessBOSS dashboard
  - **Export** → lists and downloads capture files (per-file or one ZIP)
- **x11vnc + noVNC** for the VNC-over-Web button, plus **Onboard** (an
  on-screen keyboard) configured to auto-show whenever a text field is
  focused anywhere in that same desktop session - including inside the
  VNC view, since Onboard runs on the Pi itself and VNC just mirrors
  whatever's on its screen.
- Wi-Fi regulatory domain set to **GB** (unlocks 5GHz/6GHz channels).
- Everything above is enabled as systemd services (system-level for the
  AP/VNC/launcher, user-level `systemctl --user` for Kismet and the
  stats GUI, kept alive via `loginctl enable-linger`), so it all comes
  back on every boot with no manual steps.

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
   Partway through, it hands off to the vendored stats GUI installer
   (`stats-gui/install.sh`), which asks for **your own sudo password a
   second time** - that's expected, it manages its own apt/pip/driver
   install as your normal user, not root.
4. Read the summary it prints, then `sudo reboot`.
5. On the Tesla's own touchscreen: Controls → Wi-Fi → join **"WarDriving"**
   using the passphrase from `config/rig.conf` (`AP_PASSPHRASE`). This one
   step Tesla makes you do by hand — the AP can't push it to the car.
6. Join the same "WarDriving" network with your phone or laptop and open
   `http://192.168.3.1/launcher`.

Re-running `sudo ./install.sh` any time (e.g. after editing
`config/rig.conf`) is safe — every step is idempotent.

## How the stats GUI is wired in

`stats-gui/` is a vendored copy of your WirelessBOSS project (its Python
package, the WCH driver source, its own `install.sh`), not a rewrite.
`install.sh` in this repo:

1. Installs `kismet` itself first, from **Kismet's own apt repo**
   (`kismetwireless.net`) - Debian doesn't carry `kismet` in its own
   repos at all, only Kali does, so this is the one genuinely
   Kali-specific gap in WirelessBOSS's own installer. Its actual package
   list otherwise (gpsd, aircrack-ng, tshark, libusb/openssl dev headers,
   etc.) is standard Debian and needs no substitute. The WCH driver
   itself (`stats-gui/BLE-Analyzer-pro-linux-capture-main/`) is plain
   portable C11 + libusb - it's compiled fresh on the Pi by `make`, no
   x86/Kali assumptions in it at all.
2. Seeds `/etc/kismet/kismet_site.conf` from
   `stats-gui/setup/kismet_site.conf.example` with the Alfa's stable
   interface name (`wlan_mon`) substituted in, before the stats GUI
   installer runs - so its own logic (telling NetworkManager to leave
   that interface alone, adding the region's 5GHz channel list) sees the
   real interface name.
3. Generates a random Kismet REST API password once
   (`config/kismet_rest_password`, gitignored) and writes it to both
   `~/.kismet/kismet_httpd.conf` and `~/.config/wirelessboss/config.yaml`
   so the dashboard can talk to Kismet without you doing that by hand.
4. Runs `stats-gui/install.sh --country GB` as your user (`su -`) - this
   is the real WirelessBOSS installer: it apt-installs its own
   dependencies, builds and installs the WCH driver + udev rule, sets up
   `~/.local/share/wirelessboss/` as the canonical install (captures
   live at `~/.local/share/wirelessboss/captures` - `KISMET_LOG_DIR` in
   `config/rig.conf` is kept in sync with this automatically, so
   `/export` and the dashboard's own storage stats agree), and installs
   its own `systemctl --user` services (`wirelessboss-web.service`,
   `wirelessboss-kismet.service`).
5. Patches the generated `wirelessboss-web.service` to run through
   `stats-gui/wirelessboss_lan_runner.py` instead of
   `wirelessboss.server.main` - upstream binds `127.0.0.1` only
   (deliberately, for a normal laptop setup); this rig needs it reachable
   from the whole `192.168.3.0/24` AP network, so the runner just calls
   the same `create_app()`/`load_config()` with `host="0.0.0.0"` instead.
   Nothing in the vendored source is modified, so a future WirelessBOSS
   update is still a clean copy over `stats-gui/`.

If you update WirelessBOSS itself, re-copy the new version's `wirelessboss/`,
`setup/`, `BLE-Analyzer-pro-linux-capture-main/`, `requirements.txt`,
`install.sh`, and the two launcher scripts into `stats-gui/` (leave
`wirelessboss_lan_runner.py` - that one's this rig's own file), then
re-run `sudo ./install.sh` here.

## Configuration

All tunables live in `config/rig.conf` (created from
`config/rig.conf.example` on first run). Notably:

- `AP_PASSPHRASE` / `VNC_PASSWORD` — auto-generated randomly on first run
  if left at their placeholder values; check `config/rig.conf` after
  install to see what was generated. Classic VNC auth only honors the
  **first 8 characters** of `VNC_PASSWORD` - keep it to 8 if you want to
  type the whole thing and have it matter.
- `AP_INTERFACE` / `MON_INTERFACE` — stable names assigned by udev
  (`udev/10-wardriving-*.link`), matched by driver (`brcmfmac` for
  onboard Wi-Fi, `mt7921u` for the Alfa) rather than `wlan0`/`wlan1`,
  since USB enumeration order isn't guaranteed across reboots.
- `KISMET_LOG_DIR` — auto-managed to match wherever the stats GUI writes
  captures; a hand-edit gets overwritten on the next `install.sh` run.

`config/rig.conf`, `config/vncpasswd`, and `config/kismet_rest_password`
are gitignored — only the `.example` template is meant to be committed,
so none of your real credentials ends up in a GitHub repo.

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

## Responsible use

Everything here operates on hardware you own: your Pi, your Tesla, your
adapters. Passive Wi-Fi/BLE wardriving (receiving broadcast beacons and
advertisements) is generally legal in the UK and most jurisdictions —
the line to stay on the right side of is not *associating with or using*
networks that aren't yours. This rig doesn't do that; the only network it
connects to as a client is your own car. WirelessBOSS's Wi-Fi Lab tools
(deauth, injection tests) are gated behind an explicit on-screen
authorization checkbox for the same reason - only use them against
networks you own or have written authorization to test.

## Troubleshooting

```
iw dev                                  # confirm wlan_ap and wlan_mon both exist
systemctl status hostapd dnsmasq wardriving-ap-netconfig nginx
systemctl status wardriving-web wardriving-vnc wardriving-novnc
systemctl --user -M <your-user>@ status wirelessboss-web wirelessboss-kismet
journalctl --user -M <your-user>@ -u wirelessboss-web -n 100
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
nginx/                       reverse proxy for the launcher
systemd/                     unit files for every service this installs
webapp/                      the Flask launcher (/launcher, /export)
stats-gui/                   vendored WirelessBOSS (Kismet dashboard + BLE driver)
scripts/                     helpers install.sh calls
```
