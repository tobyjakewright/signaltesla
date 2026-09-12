# SignalTesla — Pi 5 Wardriving Rig

A one-command provisioning repo that turns a fresh Raspberry Pi OS (64-bit,
**with Desktop**) install into a self-contained Wi-Fi + BLE wardriving rig
with GPS tagging, Kismet, and a touch-friendly web launcher — plus a
hotspot your Tesla can join the same way it joins a wireless CarPlay
dongle.

## Hardware this targets

| Role | Hardware | Notes |
|---|---|---|
| Compute | Raspberry Pi 5 | Raspberry Pi OS (Bookworm/Trixie), **Desktop** variant, not Lite |
| Wi-Fi wardriving capture | Alfa AWUS036AXML | MediaTek mt7921u chipset, 2.4/5/6GHz |
| BLE capture | WCH BLE Analyzer Pro | See "BLE sniffer caveats" below |
| GPS | VK-162 USB GPS (u-blox 7) | Tags every Wi-Fi/BLE hit with lat/lon |
| Tesla-facing hotspot | Pi 5's onboard Wi-Fi | Hosts the "WarDriving" AP the car joins |

## What it sets up

- Onboard Wi-Fi hosts a **"WarDriving" AP** at `192.168.3.1/24` with its
  own DHCP server (hostapd + dnsmasq), scoped so it doesn't interfere with
  anything else on the Pi.
- The Alfa adapter is pinned to a stable interface name and handed to
  **Kismet** as the wardriving capture source (Kismet puts it into
  monitor mode itself).
- **gpsd** reads the VK-162 and feeds GPS into Kismet so every SSID/BLE
  device is geotagged.
- A **Flask web launcher**, reverse-proxied by nginx on port 80, with:
  - `/launcher` — landing page with three big buttons
  - `/kismet` — embeds the live Kismet UI (also has a direct-link fallback)
  - `/pi` — embeds a noVNC view of the Pi's own desktop, touch-controllable
  - `/export` — lists and downloads capture files (per-file or one ZIP)
- **x11vnc + noVNC** so the Desktop button actually works from a browser.
- Wi-Fi regulatory domain set to **GB** (unlocks 5GHz/6GHz channels).
- Everything above is enabled as systemd services, so it all comes back
  on every boot with no manual steps.

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

## Configuration

All tunables live in `config/rig.conf` (created from
`config/rig.conf.example` on first run). Notably:

- `AP_PASSPHRASE` / `VNC_PASSWORD` — auto-generated randomly on first run
  if left at their placeholder values; check `config/rig.conf` after
  install to see what was generated.
- `AP_INTERFACE` / `MON_INTERFACE` — stable names assigned by udev
  (`udev/10-wardriving-*.link`), matched by driver (`brcmfmac` for
  onboard Wi-Fi, `mt7921u` for the Alfa) rather than `wlan0`/`wlan1`,
  since USB enumeration order isn't guaranteed across reboots.
- `KISMET_LOG_DIR` — where captures land and what `/export` lists.

`config/rig.conf` and `config/vncpasswd` are gitignored — only the
`.example` template is meant to be committed, so your real passphrase
never ends up in a GitHub repo.

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

**BLE sniffer (WCH BLE Analyzer Pro).** This install assumes it enumerates
as a standard Bluetooth HCI adapter, in which case `hciconfig -a` will
show it and Kismet's `linuxbluetooth` source (already configured in
`kismet/kismet_site.conf.tmpl`) just works. If it instead shows up as a
vendor-specific USB device needing proprietary capture software, Kismet's
generic BLE source won't see it — capture with the vendor tool separately
and drop the resulting files into `KISMET_LOG_DIR` so they still show up
under `/export`. Check with `dmesg` and `hciconfig -a` right after
plugging it in and adjust `BLE_HCI` in `config/rig.conf` if needed.

**Tesla auto-loading a page from the AP.** Third-party wireless CarPlay
adapters get their video onto the Tesla's screen using an undocumented,
reverse-engineered mechanism that isn't publicly specified by Tesla and
has varied by adapter and Tesla software version. This repo gets you the
concrete, verifiable part — the Pi hosting an AP the Tesla can join, with
its own DHCP server, at an address range (`192.168.3.0/24`) chosen not to
collide with Tesla's own internal ranges — and serves the launcher UI on
port 80 at the gateway address in case the car's software does try to
load something there. Whether the Tesla's screen actually auto-displays
it isn't something this repo can guarantee; treat that part as
experimental and verify it yourself against your car's current software
version. Regardless, once joined, your phone/laptop can always reach
`http://192.168.3.1/launcher` normally.

## Responsible use

Everything here operates on hardware you own: your Pi, your Tesla, your
adapters. Passive Wi-Fi/BLE wardriving (receiving broadcast beacons and
advertisements) is generally legal in the UK and most jurisdictions —
the line to stay on the right side of is not *associating with or using*
networks that aren't yours. This rig doesn't do that; the only network it
connects to as a client is your own car.

## Troubleshooting

```
iw dev                     # confirm wlan_ap and wlan_mon both exist
systemctl status hostapd dnsmasq wardriving-ap-netconfig
journalctl -u kismet -f
hciconfig -a                # BLE adapter present?
cgps -s                     # GPS fix (needs clear sky view)
systemctl status wardriving-web wardriving-vnc wardriving-novnc nginx
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
kismet/                      Kismet site config template
nginx/                       reverse proxy for the launcher
systemd/                     unit files for every service this installs
webapp/                      the Flask launcher (/launcher /kismet /pi /export)
scripts/                     helpers install.sh calls
```
