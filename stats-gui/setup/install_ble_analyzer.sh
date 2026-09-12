#!/usr/bin/env bash
# Install only WCH BLE Analyzer Pro support on a Kali host that already has
# WirelessBOSS and Kismet configured.
set -Eeuo pipefail

if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as your normal Kali desktop user, not root." >&2
  exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRIVER_DIR="$PROJECT_DIR/BLE-Analyzer-pro-linux-capture-main"

echo "==> Installing BLE build/runtime dependencies"
sudo apt update
sudo env DEBIAN_FRONTEND=noninteractive apt install -y \
  build-essential pkg-config libusb-1.0-0-dev libssl-dev usbutils tshark

echo "==> Building the driver for this Kali machine"
make -C "$DRIVER_DIR" clean all
sudo make -C "$DRIVER_DIR" install

echo "==> Enabling non-root access to the analyzer radios"
sudo groupadd -f plugdev
sudo usermod -aG plugdev "$USER"
sudo udevadm control --reload-rules
sudo udevadm trigger

echo
echo "BLE Analyzer support installed."
echo "Unplug/replug the analyzer, then log out and back in once."
echo "A healthy unit shows three lines here:"
echo "  lsusb -d 1a86:8009"
