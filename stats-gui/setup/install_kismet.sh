#!/usr/bin/env bash
# One-time host setup for WirelessBOSS on Kali Linux.
# Run as your normal user (it will sudo where needed) - do not run this
# whole script as root, or the "kismet" group membership step is pointless.
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as your normal user, not root (it uses sudo internally)." >&2
  exit 1
fi

echo "==> Installing Kismet, gpsd, and dependencies"
sudo apt update
sudo env DEBIAN_FRONTEND=noninteractive apt install -y \
  kismet gpsd gpsd-clients \
  python3-pip python3-venv \
  aircrack-ng tshark \
  build-essential pkg-config libusb-1.0-0-dev libssl-dev usbutils

echo "==> Adding $USER to the kismet group (so the web server can start Kismet without sudo)"
sudo usermod -aG kismet "$USER"

echo "==> Enabling gpsd (edit /etc/default/gpsd for your GPS device, e.g. /dev/ttyUSB0 or /dev/ttyACM0)"
sudo systemctl enable gpsd
sudo systemctl restart gpsd || echo "gpsd not started - plug in your GPS module and re-run: sudo systemctl restart gpsd"

echo "==> Granting aireplay-ng raw-socket capabilities (so deauth/injection work without running as root)"
if command -v aireplay-ng >/dev/null 2>&1; then
  sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v aireplay-ng)"
  echo "    Note: this resets if aircrack-ng is later updated via apt - re-run this setcap line if"
  echo "    deauth/injection start failing with 'Operation not permitted' after a system update."
fi

echo "==> Building and installing the WCH BLE Analyzer Pro Linux capture tool"
DRIVER_DIR="$(cd "$(dirname "$0")/../BLE-Analyzer-pro-linux-capture-main" && pwd)"
make -C "$DRIVER_DIR" clean all
sudo make -C "$DRIVER_DIR" install
sudo groupadd -f plugdev
sudo usermod -aG plugdev "$USER"
sudo udevadm control --reload-rules
sudo udevadm trigger
echo "    If the analyzer is already connected, unplug/replug it after setup."

echo "==> Setting up a Python venv for WirelessBOSS"
cd "$(dirname "$0")/.."
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt

# Kismet only checks /etc/kismet/ for kismet_site.conf (NOT ~/.kismet/,
# despite what some upstream docs suggest) - install the starter config
# there so it's picked up automatically, without clobbering an existing one.
if [ ! -f /etc/kismet/kismet_site.conf ]; then
  echo "==> Installing a starter kismet_site.conf to /etc/kismet/ (edit its source= line next)"
  sudo cp setup/kismet_site.conf.example /etc/kismet/kismet_site.conf
else
  echo "==> /etc/kismet/kismet_site.conf already exists, leaving it as-is"
fi

# Also drop it in ~/.kismet/ for reference/editing convenience - not read
# from there, but a handy local copy to diff against if you tweak it.
mkdir -p ~/.kismet
[ -f ~/.kismet/kismet_site.conf ] || cp setup/kismet_site.conf.example ~/.kismet/kismet_site.conf

cat <<'EOF'

Setup complete. Next steps:

1. Log out/in so the kismet and plugdev group memberships take effect.
2. Plug in the Alfa AWUS036AXML and identify its interface name:
     iw dev
   It usually shows up as wlan0 or wlan1 - confirm with:
     ip link | grep -i wlan
3. Edit /etc/kismet/kismet_site.conf (sudo) and set the `source=` line's
   interface name to match, then start Kismet:
     kismet --no-ncurses
   (Kismet puts the interface into monitor mode itself - you do not need
   to run airmon-ng first.)
4. First Kismet run on a fresh install requires REST API credentials.
   Fastest way to set them (skips the web UI flow):
     cat > ~/.kismet/kismet_httpd.conf <<CREDS
     httpd_username=wirelessboss
     httpd_password=change-me
     CREDS
5. Launch WirelessBOSS's web server, then open http://127.0.0.1:8080/ in a browser:
     ./.venv/bin/python -m wirelessboss.server.main
   Or use the app-drawer launcher: setup/install_desktop_launcher.sh installs
   one that starts Kismet, starts the web server, and opens the browser for you.

First launch writes a default config to ~/.config/wirelessboss/config.yaml -
put the same kismet.username / kismet.password there that you set in
~/.kismet/kismet_httpd.conf above.

BLE Analyzer check:
     lsusb -d 1a86:8009
   should print three devices. The BLE Analysis page starts the bundled
   driver and records a Wireshark-compatible .pcap automatically.
EOF
