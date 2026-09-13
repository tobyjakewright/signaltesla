#!/usr/bin/env bash
# One-shot installer for the wardriving rig: Kismet, GPS (gpsd), Wi-Fi
# monitor-mode capture, BLE capture, a "WarDriving" hotspot + DHCP server
# for the Tesla to join, a touch-friendly web launcher, and noVNC desktop
# access. Re-running this script is safe - every step is idempotent.
#
# Usage (on the Pi, as root):
#   sudo ./install.sh
set -euo pipefail

# ---------------------------------------------------------------------------
# Preamble
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "Run this as root: sudo ./install.sh" >&2
  exit 1
fi

log() { echo -e "\n\033[1;32m==> $*\033[0m"; }
warn() { echo -e "\033[1;33m!! $*\033[0m" >&2; }

REPO_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/wardriving-rig"

# Re-copy ourselves to a stable install path so unit files' hardcoded
# /opt/wardriving-rig references are always valid, regardless of where
# you cloned the repo.
if [[ "$REPO_SRC" != "$INSTALL_DIR" ]]; then
  log "Copying repo to ${INSTALL_DIR}"
  mkdir -p "$INSTALL_DIR"
  rsync -a --delete --exclude ".git" "$REPO_SRC"/ "$INSTALL_DIR"/
  exec "$INSTALL_DIR/install.sh" "$@"
fi

cd "$INSTALL_DIR"

# Figure out the real (non-root) user this rig runs as - "pi" is no
# longer a safe assumption since Raspberry Pi Imager now asks you to
# pick your own username.
DETECTED_USER="${SUDO_USER:-}"
if [[ -z "$DETECTED_USER" || "$DETECTED_USER" == "root" ]]; then
  DETECTED_USER="$(logname 2>/dev/null || true)"
fi

# ---------------------------------------------------------------------------
# rig.conf bootstrap
# ---------------------------------------------------------------------------
if [[ ! -f config/rig.conf ]]; then
  log "First run: creating config/rig.conf from the example"
  cp config/rig.conf.example config/rig.conf
  if [[ -n "$DETECTED_USER" ]]; then
    sed -i "s/^RIG_USER=.*/RIG_USER=\"${DETECTED_USER}\"/" config/rig.conf
  fi
fi

gen_secret() { tr -dc 'A-Za-z0-9' </dev/urandom | head -c16; }

# Escapes a value for safe use as a sed replacement string. Without this,
# a user-typed passphrase containing '/', '&', or '\' breaks the s/// syntax
# outright, which - under `set -e` - kills the whole install silently right
# at that line (this bit us: an AP/VNC password with a '/' in it).
sed_escape() { printf '%s' "$1" | sed -e 's/[\/&\\]/\\&/g'; }

# Interactively asks for a secret on a real terminal (input hidden, like a
# password prompt); echoes nothing to stdout but the typed value itself, so
# it's safe to capture with $(...). Returns 1 (no output) if there's no
# terminal attached or the user just presses Enter, so the caller can fall
# back to auto-generating one instead of hanging.
prompt_secret() {
  local prompt_text="$1" min_len="$2" value
  [[ -t 0 ]] || return 1
  while true; do
    read -rsp "${prompt_text}: " value
    echo >&2
    if [[ -z "$value" ]]; then
      return 1
    fi
    if [[ ${#value} -lt $min_len ]]; then
      echo "Needs at least ${min_len} characters - try again (or leave it blank to auto-generate one)." >&2
      continue
    fi
    printf '%s' "$value"
    return 0
  done
}

# shellcheck disable=SC1091
if grep -q '^AP_PASSPHRASE="ChangeThisPassphrase123"' config/rig.conf; then
  if NEW_PASS="$(prompt_secret "Wi-Fi hotspot (AP) passphrase for \"${AP_SSID:-WarDriving}\" - 8-63 chars, blank to auto-generate" 8)"; then
    log "Using the Wi-Fi hotspot passphrase you entered"
  else
    NEW_PASS="$(gen_secret)"
    log "Generated a random AP_PASSPHRASE (left blank, or no terminal attached)"
  fi
  sed -i "s/^AP_PASSPHRASE=.*/AP_PASSPHRASE=\"$(sed_escape "$NEW_PASS")\"/" config/rig.conf
fi
if grep -q '^VNC_PASSWORD="ChangeThisVncPw"' config/rig.conf; then
  if NEW_VNC="$(prompt_secret "VNC (remote desktop) password - only the first 8 characters count, blank to auto-generate" 4)"; then
    log "Using the VNC password you entered"
  else
    NEW_VNC="$(gen_secret)"
    log "Generated a random VNC_PASSWORD (left blank, or no terminal attached)"
  fi
  sed -i "s/^VNC_PASSWORD=.*/VNC_PASSWORD=\"$(sed_escape "$NEW_VNC")\"/" config/rig.conf
fi
if grep -q '^KISMET_PASS="ChangeThisKismetRestPw"' config/rig.conf; then
  NEW_KISMET_PASS="$(gen_secret)"
  sed -i "s/^KISMET_PASS=.*/KISMET_PASS=\"${NEW_KISMET_PASS}\"/" config/rig.conf
  log "Generated a random KISMET_PASS (was left at the placeholder value)"
fi

set -a
# shellcheck disable=SC1091
source config/rig.conf
set +a

if [[ -z "${RIG_USER:-}" ]] || ! id "$RIG_USER" >/dev/null 2>&1; then
  echo "Could not determine a valid non-root user for RIG_USER." >&2
  echo "Edit config/rig.conf and set RIG_USER to your login user, then re-run." >&2
  exit 1
fi
RIG_HOME="$(getent passwd "$RIG_USER" | cut -d: -f6)"

log "Installing for user: ${RIG_USER}  |  AP: ${AP_SSID} @ ${AP_IP}"

# ---------------------------------------------------------------------------
# Base packages
# ---------------------------------------------------------------------------
log "apt update"
apt-get update -y

log "Installing base packages"
apt-get install -y \
  git curl wget rsync gettext-base \
  python3 python3-venv python3-pip \
  iw rfkill wireless-regdb \
  hostapd dnsmasq nginx \
  gpsd gpsd-clients \
  net-tools usbutils dnsutils \
  tcpdump \
  build-essential pkg-config libusb-1.0-0-dev libssl-dev \
  x11vnc novnc websockify \
  onboard \
  unzip zip

# crda was dropped from Debian on newer releases (regdb handling moved
# into the kernel) - install it opportunistically, don't fail if it's gone.
apt-get install -y crda || warn "crda package not available (expected on newer Debian/Raspberry Pi OS - the kernel + wireless-regdb handle this now)."

# ---------------------------------------------------------------------------
# Regulatory domain -> GB (unlocks 5GHz/6GHz channels)
# ---------------------------------------------------------------------------
log "Setting Wi-Fi regulatory domain to ${AP_COUNTRY}"
raspi-config nonint do_wifi_country "$AP_COUNTRY" || true
iw reg set "$AP_COUNTRY" || true
if [[ -f /etc/default/crda ]]; then
  sed -i "s/^REGDOMAIN=.*/REGDOMAIN=${AP_COUNTRY}/" /etc/default/crda || true
fi
rfkill unblock wifi || true

# ---------------------------------------------------------------------------
# mt7921 firmware for the Alfa AWUS036AXML (best-effort - package name
# varies by OS release, so we try a few and don't fail the install if
# none match; the mainline kernel driver may already include it).
# ---------------------------------------------------------------------------
log "Attempting to install MediaTek mt7921u firmware"
FW_INSTALLED=0
for pkg in firmware-mediatek firmware-linux-nonfree linux-firmware; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    apt-get install -y "$pkg" && FW_INSTALLED=1 && break
  fi
done
if [[ "$FW_INSTALLED" -eq 0 ]]; then
  warn "No mt7921 firmware package found by name - check 'dmesg | grep -i mt7921' after plugging in the Alfa adapter."
fi

# ---------------------------------------------------------------------------
# Stable interface / device naming (udev + systemd-network .link files)
# ---------------------------------------------------------------------------
log "Installing udev rules and .link files for stable device naming"
install -m 0644 udev/99-wardriving-gps.rules /etc/udev/rules.d/99-wardriving-gps.rules
install -m 0644 udev/10-wardriving-mon.link /etc/systemd/network/10-wardriving-mon.link
install -m 0644 udev/10-wardriving-ap.link /etc/systemd/network/10-wardriving-ap.link
udevadm control --reload
udevadm trigger || true

# ---------------------------------------------------------------------------
# Keep NetworkManager off the AP interface - hostapd/dnsmasq own it
# ---------------------------------------------------------------------------
log "Marking ${AP_INTERFACE} unmanaged by NetworkManager"
mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/99-wardriving-unmanaged.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:${AP_INTERFACE}
EOF
systemctl reload NetworkManager 2>/dev/null || true

# ---------------------------------------------------------------------------
# Render hostapd / dnsmasq / kismet / nginx / systemd configs from rig.conf
# ---------------------------------------------------------------------------
log "Rendering configs from config/rig.conf"
chmod +x scripts/render-configs.sh scripts/ap-netconfig.sh
./scripts/render-configs.sh

mkdir -p "$KISMET_LOG_DIR"
chown "$RIG_USER":"$RIG_USER" "$KISMET_LOG_DIR"

# hostapd needs to be pointed at our rendered conf file
touch /etc/default/hostapd
if grep -q '^DAEMON_CONF=' /etc/default/hostapd; then
  sed -i 's|^DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
else
  echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' >> /etc/default/hostapd
fi

# ---------------------------------------------------------------------------
# AP networking + hostapd/dnsmasq systemd units
# ---------------------------------------------------------------------------
log "Installing AP netconfig + hostapd/dnsmasq overrides"
install -m 0644 systemd/wardriving-ap-netconfig.service /etc/systemd/system/wardriving-ap-netconfig.service
mkdir -p /etc/systemd/system/hostapd.service.d /etc/systemd/system/dnsmasq.service.d
install -m 0644 systemd/hostapd.service.d/override.conf /etc/systemd/system/hostapd.service.d/override.conf
install -m 0644 systemd/dnsmasq.service.d/override.conf /etc/systemd/system/dnsmasq.service.d/override.conf

systemctl unmask hostapd dnsmasq || true
systemctl daemon-reload
systemctl enable wardriving-ap-netconfig.service hostapd.service dnsmasq.service
systemctl restart wardriving-ap-netconfig.service || warn "AP netconfig failed - is ${AP_INTERFACE} present yet? Check 'ip link' and 'journalctl -u wardriving-ap-netconfig'. This resolves itself on reboot once udev has renamed the interface."
systemctl restart hostapd.service dnsmasq.service || warn "hostapd/dnsmasq failed to (re)start - check 'journalctl -u hostapd -u dnsmasq'."

# ---------------------------------------------------------------------------
# Kismet (official repo + signing key)
# ---------------------------------------------------------------------------
# Kismet isn't in Debian's own repos at all - only Kali ships it directly.
# This is the one genuinely Kali-specific gap in a Wi-Fi/BLE wardriving
# stack like this one; everything else below is standard Debian/Raspberry
# Pi OS packages. Pull Kismet from its own official apt repo instead.
install_kismet() {
  command -v kismet >/dev/null 2>&1 && return 0
  local codename
  codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
  curl -fsSL https://www.kismetwireless.net/repos/kismet-release.gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/kismet-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/kismet-archive-keyring.gpg] https://www.kismetwireless.net/repos/apt/release/${codename} ${codename} main" \
    > /etc/apt/sources.list.d/kismet.list
  apt-get update -y
  apt-get install -y kismet
}

log "Installing Kismet (from Kismet's own apt repo - not in Debian's)"
if install_kismet; then
  usermod -aG kismet "$RIG_USER"
  systemctl enable kismet.service
  systemctl restart kismet.service || warn "Kismet failed to start - check 'journalctl -u kismet' (often the source interface isn't up yet on first boot - it should come up after a reboot)."
else
  warn "Kismet install failed - check network access to kismetwireless.net, then re-run 'sudo ./install.sh' (it's safe to re-run)."
fi

log "Setting up Kismet's REST API credentials"
install -d -o "$RIG_USER" -g "$RIG_USER" -m 0700 "${RIG_HOME}/.kismet"
cat > "${RIG_HOME}/.kismet/kismet_httpd.conf" <<EOF
httpd_username=${KISMET_USER}
httpd_password=${KISMET_PASS}
EOF
chown "$RIG_USER":"$RIG_USER" "${RIG_HOME}/.kismet/kismet_httpd.conf"
chmod 600 "${RIG_HOME}/.kismet/kismet_httpd.conf"
systemctl restart kismet.service 2>/dev/null || true

# ---------------------------------------------------------------------------
# GPS (VK-162 via gpsd)
# ---------------------------------------------------------------------------
log "Configuring gpsd for the VK-162 GPS on ${GPS_DEVICE}"
cat > /etc/default/gpsd <<EOF
START_DAEMON="true"
USBAUTO="true"
DEVICES="${GPS_DEVICE}"
GPSD_OPTIONS="-n"
EOF
systemctl enable gpsd.socket gpsd.service
systemctl restart gpsd.socket gpsd.service || warn "gpsd failed to start - is the VK-162 plugged in? Check 'ls -l /dev/gps0' and 'cgps'."

# ---------------------------------------------------------------------------
# BLE capture (WCH BLE Analyzer Pro) - build its libusb driver from source
# and run it as a plain always-on capture. This is the only piece that
# talks to that specific hardware; the custom stats GUI's BLE tab just
# tails its JSON-lines output (see webapp/ble/reader.py).
# ---------------------------------------------------------------------------
log "Building the WCH BLE Analyzer Pro driver"
make -C ble-driver clean all
install -Dm0755 ble-driver/wch_capture /usr/local/bin/wch_capture
install -Dm0644 ble-driver/99-wch-ble-analyzer.rules /etc/udev/rules.d/99-wch-ble-analyzer.rules
udevadm control --reload-rules
udevadm trigger --subsystem-match=usb || true

install -m 0644 systemd/wardriving-ble.service /etc/systemd/system/wardriving-ble.service
chmod +x scripts/run-ble-capture.sh
systemctl daemon-reload
systemctl enable wardriving-ble.service
systemctl restart wardriving-ble.service || warn "BLE capture failed to start - is the WCH analyzer plugged in? Check 'lsusb -d 1a86:8009' (should show 3 devices) and 'journalctl -u wardriving-ble'."

log "Setting up the on-screen keyboard (auto-shows when a text field is focused)"
mkdir -p /etc/xdg/autostart
cat > /etc/xdg/autostart/onboard-autostart.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Onboard
Exec=onboard
X-GNOME-Autostart-enabled=true
EOF
su - "$RIG_USER" -c "dbus-launch --exit-with-session gsettings set org.onboard auto-show enabled true" 2>/dev/null \
  || warn "Couldn't preset Onboard's auto-show setting (no desktop session yet, or schema differs by version). After first boot, enable it by hand: Onboard Settings -> Auto-show when editing text. Onboard also mirrors into the noVNC view, since it's just another window in the same desktop session."

# ---------------------------------------------------------------------------
# Desktop environment + VNC + noVNC (for the /pi touchscreen view)
# ---------------------------------------------------------------------------
log "Checking for a desktop environment"
if ! dpkg -l | grep -qE 'raspberrypi-ui-mods|task-lxde-desktop'; then
  warn "No desktop environment detected - installing raspberrypi-ui-mods (this is a big download)."
  apt-get install -y raspberrypi-ui-mods lightdm || warn "Desktop install failed - the Desktop button in the launcher won't work until one is installed manually."
fi
raspi-config nonint do_boot_behaviour B4 || true   # boot to desktop, autologin

log "Setting the VNC password"
mkdir -p "${INSTALL_DIR}/config"
x11vnc -storepasswd "$VNC_PASSWORD" "${INSTALL_DIR}/config/vncpasswd"
chmod 600 "${INSTALL_DIR}/config/vncpasswd"

# (wardriving-vnc.service and wardriving-web.service were already rendered
#  straight into /etc/systemd/system by render-configs.sh)
install -m 0644 systemd/wardriving-novnc.service /etc/systemd/system/wardriving-novnc.service
systemctl daemon-reload
systemctl enable wardriving-vnc.service wardriving-novnc.service
systemctl restart wardriving-vnc.service wardriving-novnc.service || warn "VNC/noVNC failed to start on first run - normal before the first reboot into the desktop. It should come up after 'sudo reboot'."

# ---------------------------------------------------------------------------
# Web launcher (Flask + gunicorn behind nginx)
# ---------------------------------------------------------------------------
log "Setting up the web launcher"
python3 -m venv "${INSTALL_DIR}/webapp/.venv"
"${INSTALL_DIR}/webapp/.venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/webapp/.venv/bin/pip" install --quiet -r "${INSTALL_DIR}/webapp/requirements.txt"

systemctl daemon-reload
systemctl enable wardriving-web.service
systemctl restart wardriving-web.service

log "Configuring nginx"
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/wardriving /etc/nginx/sites-enabled/wardriving
nginx -t
systemctl enable nginx
systemctl restart nginx

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
log "Install complete"
cat <<SUMMARY

--------------------------------------------------------------------
  Wardriving rig installed.

  Hotspot:       SSID "${AP_SSID}"  (password in config/rig.conf)
  Gateway/IP:    ${AP_IP}
  Launcher:      http://${AP_IP}/launcher   (4 buttons, each forwards
                  straight to the dedicated UI below - no wrapper page)
    Kismet:            :${KISMET_HTTP_PORT}  (REST login "${KISMET_USER}",
                        password in config/rig.conf)
    VNC over Web:      :${NOVNC_PORT}
    Custom Stats GUI:  /stats (part of the same launcher app)
    Export:            /export

  Next steps:
   1. Reboot: sudo reboot
      (needed for the regulatory domain, desktop autologin, and the
      on-screen keyboard to all take effect)
   2. On the Tesla's own touchscreen, go to Wi-Fi settings and join
      "${AP_SSID}" like any other network (enter the passphrase from
      config/rig.conf). This is the one part Tesla makes you do by hand.
   3. Join the same "${AP_SSID}" network with your phone/laptop and open
      http://${AP_IP}/launcher
   4. Verify hardware:
      - iw dev                    (should show ${AP_INTERFACE} and ${MON_INTERFACE})
      - lsusb -d 1a86:8009        (WCH analyzer - should show 3 devices)
      - cgps -s                   (GPS fix, needs a clear sky view)
      - journalctl -u kismet -u wardriving-ble -f
                                  (capture sources coming up)

  See README.md for what's still experimental (Tesla auto-load behavior,
  on-screen keyboard auto-show) and what the custom stats GUI leaves out
  on purpose.
--------------------------------------------------------------------
SUMMARY
