#!/usr/bin/env bash
# Safe, in-place WirelessBOSS installer/upgrader for Kali Linux.
#
# The new application and driver are built and tested in a staging directory
# before the existing canonical install is moved. User configuration, captures,
# and offline tiles live outside the replaced app directory and are never
# deleted. If a later step fails, the previous app/service/launcher files and
# system driver are restored where practical.
set -Eeuo pipefail
IFS=$'\n\t'

INSTALLER_VERSION="1.0"
CAPABILITY_MARKER="wirelessboss-native-follow-v1"
AUTO_START=1
LEGACY_INSTALL=""
WIFI_COUNTRY="${WIRELESSBOSS_WIFI_COUNTRY:-}"
INSTALL_COMPLETE=0
APP_SWITCHED=0
DRIVER_INSTALLED=0
SERVICES_WRITTEN=0
STAGE_DIR=""
PREVIOUS_APP_PRESENT=0
USER_SYSTEMD_AVAILABLE=0
OLD_WEB_ACTIVE=0
OLD_KISMET_ACTIVE=0
OLD_WEB_ENABLED=0
GROUP_REFRESH_REQUIRED=0
HEALTH_PID=""

usage() {
  cat <<'EOF'
WirelessBOSS Kali installer/upgrader

Usage:
  ./install.sh [--no-start] [--old-install PATH]

Options:
  --no-start         Install and enable WirelessBOSS, run a brief health check,
                     then leave the web service stopped.
  --old-install PATH Import capture files from an arbitrary legacy checkout.
                     That directory is never changed or deleted.
  --country XX       Wi-Fi regulatory domain to set and persist (2-letter
                     code, e.g. GB, US). Also settable via the
                     WIRELESSBOSS_WIFI_COUNTRY env var. Default: the domain
                     the box is already on, else GB.
  -h, --help         Show this help.

Run this as your normal Kali desktop user. The installer uses sudo only for
APT packages, the WCH driver/udev rule, groups, and host service integration.

Preserved during an upgrade:
  ~/.config/wirelessboss/                 application configuration
  ~/.local/share/wirelessboss/captures/   PCAP/Kismet captures
  ~/.local/share/wirelessboss/tiles/      offline map tiles
  ~/.local/share/wirelessboss/backups/    timestamped rollback backups
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-start)
      AUTO_START=0
      ;;
    --old-install)
      [ "$#" -ge 2 ] || {
        echo "--old-install requires a directory path" >&2
        exit 2
      }
      LEGACY_INSTALL="$2"
      shift
      ;;
    --old-install=*)
      LEGACY_INSTALL="${1#*=}"
      ;;
    --country)
      [ "$#" -ge 2 ] || { echo "--country requires a 2-letter code (e.g. GB, US)" >&2; exit 2; }
      WIFI_COUNTRY="$2"
      shift
      ;;
    --country=*)
      WIFI_COUNTRY="${1#*=}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ -t 1 ]; then
  BOLD=$'\033[1m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  RED=$'\033[31m'
  RESET=$'\033[0m'
else
  BOLD=""
  GREEN=""
  YELLOW=""
  RED=""
  RESET=""
fi

step() {
  printf '\n%s==> %s%s\n' "$BOLD" "$*" "$RESET"
}

ok() {
  printf '%s[OK]%s %s\n' "$GREEN" "$RESET" "$*"
}

warn() {
  printf '%s[WARN]%s %s\n' "$YELLOW" "$RESET" "$*" >&2
}

die() {
  printf '%s[ERROR]%s %s\n' "$RED" "$RESET" "$*" >&2
  exit 1
}

if [ "$(id -u)" -eq 0 ]; then
  die "Run this as your normal Kali desktop user, not root. It invokes sudo when required."
fi

for required in bash realpath tar find cp mv mkdir date id sudo flock; do
  command -v "$required" >/dev/null 2>&1 || die "Missing required command: $required"
done

if [ "$(uname -s)" != "Linux" ] || ! command -v apt-get >/dev/null 2>&1; then
  die "This installer is for Kali/Debian Linux systems with apt-get."
fi

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${ID_LIKE:-}" in
    kali:*|debian:*|*:debian*) ;;
    *) warn "This does not identify as Kali/Debian (${PRETTY_NAME:-unknown}); continuing because apt-get is available." ;;
  esac
fi

SOURCE_DIR="$(realpath -m "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)")"
DATA_HOME="$(realpath -m "${XDG_DATA_HOME:-$HOME/.local/share}")"
CONFIG_HOME="$(realpath -m "${XDG_CONFIG_HOME:-$HOME/.config}")"
INSTALL_ROOT="$DATA_HOME/wirelessboss"
INSTALL_DIR="$INSTALL_ROOT/app"
CAPTURE_DIR="$INSTALL_ROOT/captures"
TILES_DIR="$INSTALL_ROOT/tiles"
BACKUP_ROOT="$INSTALL_ROOT/backups"
UNIT_DIR="$CONFIG_HOME/systemd/user"
APPS_DIR="$DATA_HOME/applications"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR=""
USER_UID="$(id -u)"
USER_GID="$(id -g)"
DRIVER_REL="BLE-Analyzer-pro-linux-capture-main"
DRIVER_DIR="$INSTALL_DIR/$DRIVER_REL"
OLD_APP_BACKUP=""

[ "${DATA_HOME#/}" != "$DATA_HOME" ] || die "XDG_DATA_HOME must resolve to an absolute path."
[ "${CONFIG_HOME#/}" != "$CONFIG_HOME" ] || die "XDG_CONFIG_HOME must resolve to an absolute path."
[ "$INSTALL_DIR" != "/" ] || die "Refusing a root-directory install target."
[ "$(basename "$INSTALL_DIR")" = "app" ] || die "Refusing unexpected install path: $INSTALL_DIR"
[ "$(basename "$(dirname "$INSTALL_DIR")")" = "wirelessboss" ] || die "Refusing unexpected install path: $INSTALL_DIR"
[ "$(dirname "$INSTALL_ROOT")" = "$DATA_HOME" ] || die "Refusing install root outside XDG_DATA_HOME: $INSTALL_ROOT"
[ "$SOURCE_DIR" != "$(realpath -m "$INSTALL_ROOT")" ] || die "Extract the installer into its own folder; do not run it from $INSTALL_ROOT."
case "$SOURCE_DIR/" in
  "$INSTALL_DIR/"|"$INSTALL_DIR/"*)
    die "Run the upgrader from a newly extracted package outside $INSTALL_DIR."
    ;;
esac

if [ -n "$LEGACY_INSTALL" ]; then
  [ -d "$LEGACY_INSTALL" ] || die "Legacy install directory does not exist: $LEGACY_INSTALL"
  LEGACY_INSTALL="$(realpath -m "$LEGACY_INSTALL")"
  [ "$LEGACY_INSTALL" != "/" ] || die "Refusing / as a legacy install directory."
fi

for expected in \
  "$SOURCE_DIR/requirements.txt" \
  "$SOURCE_DIR/wirelessboss/server/main.py" \
  "$SOURCE_DIR/$DRIVER_REL/Makefile" \
  "$SOURCE_DIR/$DRIVER_REL/wch_capture.c"; do
  [ -f "$expected" ] || die "The installer package is incomplete; missing $expected"
done

mkdir -p "$INSTALL_ROOT" "$CAPTURE_DIR" "$TILES_DIR" "$BACKUP_ROOT" "$UNIT_DIR" "$APPS_DIR"
exec 9>"$INSTALL_ROOT/.install.lock"
flock -n 9 || die "Another WirelessBOSS installer is already running for this user."
BACKUP_DIR="$(mktemp -d "$BACKUP_ROOT/upgrade-$STAMP.XXXXXX")"
OLD_APP_BACKUP="$BACKUP_DIR/app"

restore_user_file() {
  local backup="$1"
  local destination="$2"
  local failed_name="$3"
  if [ -e "$destination" ] || [ -L "$destination" ]; then
    mkdir -p "$BACKUP_DIR/failed-new-files"
    mv "$destination" "$BACKUP_DIR/failed-new-files/$failed_name" 2>/dev/null || true
  fi
  if [ -e "$backup" ] || [ -L "$backup" ]; then
    mkdir -p "$(dirname "$destination")"
    cp -a "$backup" "$destination" 2>/dev/null || true
  fi
}

rollback_on_error() {
  local code=$?
  trap - EXIT INT TERM
  if [ "$code" -eq 0 ] || [ "$INSTALL_COMPLETE" -eq 1 ]; then
    exit "$code"
  fi

  set +e
  printf '\n%s[ERROR]%s Installation failed. Restoring the previous version...\n' "$RED" "$RESET" >&2

  if [ "$USER_SYSTEMD_AVAILABLE" -eq 1 ]; then
    systemctl --user stop wirelessboss-web.service >/dev/null 2>&1 || true
  elif [ -n "$HEALTH_PID" ]; then
    kill "$HEALTH_PID" >/dev/null 2>&1 || true
    wait "$HEALTH_PID" >/dev/null 2>&1 || true
  fi

  if [ "$SERVICES_WRITTEN" -eq 1 ]; then
    # Remove the newly enabled wants-link while its unit file still exists.
    # On a fresh install, disabling after moving the unit can leave a dangling
    # default.target.wants symlink on some systemd releases.
    if [ "$USER_SYSTEMD_AVAILABLE" -eq 1 ]; then
      systemctl --user disable wirelessboss-web.service >/dev/null 2>&1 || true
    fi
    restore_user_file "$BACKUP_DIR/user-services/wirelessboss-web.service" \
      "$UNIT_DIR/wirelessboss-web.service" "wirelessboss-web.service"
    restore_user_file "$BACKUP_DIR/user-services/wirelessboss-kismet.service" \
      "$UNIT_DIR/wirelessboss-kismet.service" "wirelessboss-kismet.service"
    restore_user_file "$BACKUP_DIR/desktop/wirelessboss.desktop" \
      "$APPS_DIR/wirelessboss.desktop" "wirelessboss.desktop"
    restore_user_file "$BACKUP_DIR/desktop/wirelessboss-web.desktop" \
      "$APPS_DIR/wirelessboss-web.desktop" "wirelessboss-web.desktop"
  fi

  if [ "$APP_SWITCHED" -eq 1 ]; then
    if [ -d "$INSTALL_DIR" ]; then
      mv "$INSTALL_DIR" "$BACKUP_DIR/failed-new-app" || true
    fi
    if [ "$PREVIOUS_APP_PRESENT" -eq 1 ] && [ -d "$OLD_APP_BACKUP" ]; then
      mv "$OLD_APP_BACKUP" "$INSTALL_DIR" || true
    fi
  elif [ -n "$STAGE_DIR" ] && [ -d "$STAGE_DIR" ]; then
    mv "$STAGE_DIR" "$BACKUP_DIR/failed-stage" || true
  fi
  if [ "$PREVIOUS_APP_PRESENT" -eq 1 ] && \
     [ -d "$OLD_APP_BACKUP" ] && [ ! -d "$INSTALL_DIR" ]; then
    mv "$OLD_APP_BACKUP" "$INSTALL_DIR" || true
  fi

  if [ "$DRIVER_INSTALLED" -eq 1 ]; then
    if [ -f "$BACKUP_DIR/system/wch_capture" ]; then
      sudo install -m 0755 "$BACKUP_DIR/system/wch_capture" /usr/local/bin/wch_capture || true
    elif sudo test -e /usr/local/bin/wch_capture; then
      sudo mkdir -p "$BACKUP_DIR/failed-new-system"
      sudo mv /usr/local/bin/wch_capture "$BACKUP_DIR/failed-new-system/wch_capture" || true
    fi
    if [ -f "$BACKUP_DIR/system/99-wch-ble-analyzer.rules" ]; then
      sudo install -m 0644 "$BACKUP_DIR/system/99-wch-ble-analyzer.rules" \
        /etc/udev/rules.d/99-wch-ble-analyzer.rules || true
    elif sudo test -e /etc/udev/rules.d/99-wch-ble-analyzer.rules; then
      sudo mkdir -p "$BACKUP_DIR/failed-new-system"
      sudo mv /etc/udev/rules.d/99-wch-ble-analyzer.rules \
        "$BACKUP_DIR/failed-new-system/99-wch-ble-analyzer.rules" || true
    fi
    sudo chown -R "$USER_UID:$USER_GID" "$BACKUP_DIR/failed-new-system" >/dev/null 2>&1 || true
    sudo udevadm control --reload-rules >/dev/null 2>&1 || true
  fi

  if [ "$USER_SYSTEMD_AVAILABLE" -eq 1 ]; then
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    if [ "$OLD_WEB_ENABLED" -eq 1 ]; then
      systemctl --user enable wirelessboss-web.service >/dev/null 2>&1 || true
    else
      systemctl --user disable wirelessboss-web.service >/dev/null 2>&1 || true
    fi
    if [ "$OLD_WEB_ACTIVE" -eq 1 ]; then
      systemctl --user start wirelessboss-web.service >/dev/null 2>&1 || true
    fi
    if [ "$OLD_KISMET_ACTIVE" -eq 1 ]; then
      systemctl --user start wirelessboss-kismet.service >/dev/null 2>&1 || true
    fi
  fi

  warn "The previous app was restored where available. Failure evidence is in: $BACKUP_DIR"
  exit "$code"
}
trap rollback_on_error EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

step "Checking sudo access"
sudo -v
ok "sudo access confirmed"

step "Installing Kali packages and build dependencies"
sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  kismet gpsd gpsd-clients \
  python3 python3-pip python3-venv \
  aircrack-ng tshark \
  build-essential pkg-config libusb-1.0-0-dev libssl-dev \
  usbutils udev curl ca-certificates desktop-file-utils libcap2-bin procps \
  xdg-utils iw iproute2 dbus-user-session libnotify-bin util-linux

for required in python3 make pkg-config curl systemctl udevadm lsusb kismet tshark; do
  command -v "$required" >/dev/null 2>&1 || die "Package installation completed but $required is still unavailable."
done
pkg-config --exists libusb-1.0 || die "libusb-1.0 development metadata is unavailable."
pkg-config --exists libcrypto || die "OpenSSL libcrypto development metadata is unavailable."
ok "Required packages are installed"

step "Staging the new WirelessBOSS application"
STAGE_DIR="$(mktemp -d "$INSTALL_ROOT/.staging-$STAMP.XXXXXX")"
tar -C "$SOURCE_DIR" \
  --exclude='./.git' \
  --exclude='./.venv' \
  --exclude='./dist' \
  --exclude='./__pycache__' \
  --exclude='*/__pycache__' \
  --exclude='*.pyc' \
  --exclude='*.kismet' \
  --exclude='*.kismetdb' \
  --exclude='*.pcap' \
  --exclude='*.pcapng' \
  --exclude='*.zip' \
  --exclude='*.tar.gz' \
  --exclude='*.tgz' \
  --exclude="./$DRIVER_REL/wch_capture" \
  --exclude="./$DRIVER_REL/*.o" \
  -cf - . | tar -C "$STAGE_DIR" -xf -

[ -f "$STAGE_DIR/$DRIVER_REL/wch_capture.c" ] || die "Staging omitted the WCH driver source."
[ ! -e "$STAGE_DIR/$DRIVER_REL/wch_capture" ] || die "A stale prebuilt WCH driver entered the staging copy."
ok "Clean source staged at $STAGE_DIR"

step "Building and validating the WCH BLE Analyzer Pro driver"
make -C "$STAGE_DIR/$DRIVER_REL" clean all
make -C "$STAGE_DIR/$DRIVER_REL" test
STAGED_DRIVER_VERSION="$($STAGE_DIR/$DRIVER_REL/wch_capture -V)"
case "$STAGED_DRIVER_VERSION" in
  *"$CAPABILITY_MARKER"*) ;;
  *) die "Built wch_capture does not contain required capability marker: $CAPABILITY_MARKER" ;;
esac
ok "$STAGED_DRIVER_VERSION"

step "Backing up the current installation"
mkdir -p "$BACKUP_DIR/user-services" "$BACKUP_DIR/desktop" "$BACKUP_DIR/system"
for service_file in wirelessboss-web.service wirelessboss-kismet.service; do
  if [ -e "$UNIT_DIR/$service_file" ] || [ -L "$UNIT_DIR/$service_file" ]; then
    cp -a "$UNIT_DIR/$service_file" "$BACKUP_DIR/user-services/$service_file"
  fi
done
for desktop_file in wirelessboss.desktop wirelessboss-web.desktop; do
  if [ -e "$APPS_DIR/$desktop_file" ] || [ -L "$APPS_DIR/$desktop_file" ]; then
    cp -a "$APPS_DIR/$desktop_file" "$BACKUP_DIR/desktop/$desktop_file"
  fi
done
if sudo test -f /usr/local/bin/wch_capture; then
  sudo cp -a /usr/local/bin/wch_capture "$BACKUP_DIR/system/wch_capture"
fi
if sudo test -f /etc/udev/rules.d/99-wch-ble-analyzer.rules; then
  sudo cp -a /etc/udev/rules.d/99-wch-ble-analyzer.rules \
    "$BACKUP_DIR/system/99-wch-ble-analyzer.rules"
fi
sudo chown -R "$USER_UID:$USER_GID" "$BACKUP_DIR/system"

cat > "$BACKUP_DIR/README.txt" <<EOF
WirelessBOSS upgrade backup created $STAMP

Previous app (when present): $OLD_APP_BACKUP
Preserved config:             $CONFIG_HOME/wirelessboss
Preserved captures:           $CAPTURE_DIR
Preserved offline tiles:      $TILES_DIR

The installer automatically restores this backup if the transaction fails.
Keep this directory until the upgraded app has passed your Kali hardware test.
EOF
ok "Backup created at $BACKUP_DIR"

preserve_capture_tree() {
  local root="$1"
  local label="$2"
  local import_root="$CAPTURE_DIR/imported-$STAMP/$label"
  local found=0
  local source_file relative destination
  [ -d "$root" ] || return 0
  while IFS= read -r -d '' source_file; do
    relative="${source_file#"$root"/}"
    destination="$import_root/$relative"
    mkdir -p "$(dirname "$destination")"
    cp -n -- "$source_file" "$destination"
    found=1
  done < <(find "$root" -type f \( \
    -name '*.kismet' -o -name '*.kismetdb' -o -name '*.pcap' -o -name '*.pcapng' \
  \) -print0)
  if [ "$found" -eq 1 ]; then
    ok "Copied embedded capture files from $root to $import_root"
  fi
}

# Captures in the canonical captures directory are never moved. These imports
# rescue files saved inside legacy application/source folders before switching.
preserve_capture_tree "$SOURCE_DIR" source-folder
if [ -d "$INSTALL_DIR" ] && [ "$(realpath -m "$INSTALL_DIR")" != "$SOURCE_DIR" ]; then
  preserve_capture_tree "$INSTALL_DIR" previous-app
fi
if [ -n "$LEGACY_INSTALL" ] && \
   [ "$LEGACY_INSTALL" != "$SOURCE_DIR" ] && \
   [ "$LEGACY_INSTALL" != "$(realpath -m "$INSTALL_DIR")" ]; then
  preserve_capture_tree "$LEGACY_INSTALL" selected-legacy-install
fi

if systemctl --user show-environment >/dev/null 2>&1; then
  USER_SYSTEMD_AVAILABLE=1
  systemctl --user is-active --quiet wirelessboss-web.service && OLD_WEB_ACTIVE=1 || true
  systemctl --user is-active --quiet wirelessboss-kismet.service && OLD_KISMET_ACTIVE=1 || true
  systemctl --user is-enabled --quiet wirelessboss-web.service && OLD_WEB_ENABLED=1 || true
fi

step "Stopping the old WirelessBOSS version"
if [ "$USER_SYSTEMD_AVAILABLE" -eq 1 ]; then
  systemctl --user stop wirelessboss-web.service wirelessboss-kismet.service >/dev/null 2>&1 || true
fi
# Only stop processes owned by the installing desktop user. Root-owned or
# other-user captures are deliberately left alone and reported later.
pkill -u "$USER_UID" -f '[p]ython(3)? .*wirelessboss\.server\.main' >/dev/null 2>&1 || true
pkill -u "$USER_UID" -f '[p]ython(3)? .*wirelessboss\.app' >/dev/null 2>&1 || true
pkill -u "$USER_UID" -x wch_capture >/dev/null 2>&1 || true
for _ in $(seq 1 20); do
  if ! pgrep -u "$USER_UID" -x wch_capture >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if pgrep -u "$USER_UID" -x wch_capture >/dev/null 2>&1; then
  die "A user-owned wch_capture process did not stop; close it and rerun the installer."
fi
ok "Old user-owned WirelessBOSS processes stopped"

step "Switching to the new application"
if [ -d "$INSTALL_DIR" ]; then
  PREVIOUS_APP_PRESENT=1
  mv "$INSTALL_DIR" "$OLD_APP_BACKUP"
fi
mv "$STAGE_DIR" "$INSTALL_DIR"
STAGE_DIR=""
APP_SWITCHED=1
chmod +x \
  "$INSTALL_DIR/install.sh" \
  "$INSTALL_DIR/wirelessboss-service-launcher.sh" \
  "$INSTALL_DIR/wirelessboss-web-launcher.sh" \
  "$INSTALL_DIR/setup/install_or_upgrade.sh" \
  "$INSTALL_DIR/setup/update_kali_web.sh" \
  "$INSTALL_DIR/setup/install_ble_analyzer.sh"
ok "Application installed at $INSTALL_DIR"

step "Creating and testing the Python environment"
# Virtual environments embed their absolute location in console-script
# shebangs, so create this only after the app reaches its final path.
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/python" -m pip install --upgrade pip wheel
"$INSTALL_DIR/.venv/bin/python" -m pip install -r "$INSTALL_DIR/requirements.txt"
"$INSTALL_DIR/.venv/bin/python" -m compileall -q "$INSTALL_DIR/wirelessboss"
(
  cd "$INSTALL_DIR"
  ./.venv/bin/python -m unittest discover -s tests -v
)
PYTHONPATH="$INSTALL_DIR" "$INSTALL_DIR/.venv/bin/python" -c \
  'from wirelessboss.server.app import create_app; from wirelessboss.ble.wch_provider import DRIVER_CAPABILITY_MARKER; assert callable(create_app) and DRIVER_CAPABILITY_MARKER'
ok "Python environment and regression tests passed"

# A legacy config may point at captures stored outside the old application.
# Import those files collision-safely while leaving every original untouched.
CONFIGURED_CAPTURE_DIR="$(PYTHONPATH="$INSTALL_DIR" "$INSTALL_DIR/.venv/bin/python" -c \
  'from wirelessboss.config import load_config; print(load_config().storage.capture_dir)' 2>/dev/null || true)"
if [ -n "$CONFIGURED_CAPTURE_DIR" ] && [ -d "$CONFIGURED_CAPTURE_DIR" ]; then
  CONFIGURED_CAPTURE_DIR="$(realpath -m "$CONFIGURED_CAPTURE_DIR")"
  if [ "$CONFIGURED_CAPTURE_DIR" != "$(realpath -m "$CAPTURE_DIR")" ] && \
     [ "$CONFIGURED_CAPTURE_DIR" != "$SOURCE_DIR" ] && \
     { [ -z "$LEGACY_INSTALL" ] || [ "$CONFIGURED_CAPTURE_DIR" != "$LEGACY_INSTALL" ]; }; then
    preserve_capture_tree "$CONFIGURED_CAPTURE_DIR" configured-capture-folder
  fi
fi

step "Installing the rebuilt WCH driver and USB permissions"
DRIVER_INSTALLED=1
sudo install -Dm0755 "$DRIVER_DIR/wch_capture" /usr/local/bin/wch_capture
sudo install -Dm0644 "$DRIVER_DIR/99-wch-ble-analyzer.rules" \
  /etc/udev/rules.d/99-wch-ble-analyzer.rules
INSTALLED_DRIVER_VERSION="$(/usr/local/bin/wch_capture -V)"
case "$INSTALLED_DRIVER_VERSION" in
  *"$CAPABILITY_MARKER"*) ;;
  *) die "Installed /usr/local/bin/wch_capture failed capability validation." ;;
esac
INSTALL_USER="$(id -un)"
sudo groupadd -f plugdev
if ! id -nG "$INSTALL_USER" | tr ' ' '\n' | grep -Fxq plugdev; then
  GROUP_REFRESH_REQUIRED=1
fi
sudo usermod -aG plugdev "$INSTALL_USER"
if getent group kismet >/dev/null 2>&1; then
  if ! id -nG "$INSTALL_USER" | tr ' ' '\n' | grep -Fxq kismet; then
    GROUP_REFRESH_REQUIRED=1
  fi
  sudo usermod -aG kismet "$INSTALL_USER"
fi
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=usb
sudo udevadm settle --timeout=5 || true
ok "$INSTALLED_DRIVER_VERSION"

if command -v aireplay-ng >/dev/null 2>&1; then
  sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v aireplay-ng)"
fi

# Retire the old Access Point / Wi-Fi Hotspot modes if a previous install
# left their system units, polkit rules, or sudoers drop-in behind.
RETIRED_HOTSPOT=0
for unit in wirelessboss-ap.service wirelessboss-hotspot.service; do
  if systemctl list-unit-files "$unit" >/dev/null 2>&1 && systemctl cat "$unit" >/dev/null 2>&1; then
    RETIRED_HOTSPOT=1
    sudo systemctl disable --now "$unit" >/dev/null 2>&1 || true
    sudo rm -f "/etc/systemd/system/$unit"
  fi
done
for f in /etc/polkit-1/rules.d/49-wirelessboss-ap.rules \
         /etc/polkit-1/rules.d/49-wirelessboss-hotspot.rules \
         /etc/sudoers.d/wirelessboss-hotspot \
         /etc/sysctl.d/99-wirelessboss-hotspot.conf \
         /etc/tmpfiles.d/wirelessboss-ap.conf \
         /etc/tmpfiles.d/wirelessboss-hotspot.conf \
         /usr/local/lib/wirelessboss/wirelessboss-ap-run \
         /usr/local/lib/wirelessboss/wirelessboss-hotspot-run; do
  [ -e "$f" ] && { RETIRED_HOTSPOT=1; sudo rm -f "$f"; }
done
if [ "$RETIRED_HOTSPOT" -eq 1 ]; then
  step "Removed retired Access Point / Wi-Fi Hotspot mode system files"
  sudo systemctl daemon-reload
  sudo rmdir /var/lib/wirelessboss/ap /var/lib/wirelessboss/hotspot 2>/dev/null || true
  warn "Left ~/.config/wirelessboss/portal and hotspot-*.json in place; delete by hand if you want."
fi

# --- Wi-Fi radio configuration (regdomain + channel list + NM hand-off) ------
# These three settings are what makes 5 GHz actually work and survive a
# reboot on the AXML/MT7921AU. Resolve the country once: --country flag /
# WIRELESSBOSS_WIFI_COUNTRY env win; otherwise reuse the domain the box is
# already set to (if it's a real 2-letter code, not the "00" world default);
# otherwise fall back to GB.
CURRENT_REG="$( { iw reg get 2>/dev/null || true; } | sed -nE 's/^country ([A-Z]{2}):.*/\1/p' | head -n1)"
if [ -z "$WIFI_COUNTRY" ]; then
  if [ -n "$CURRENT_REG" ] && [ "$CURRENT_REG" != "00" ]; then
    WIFI_COUNTRY="$CURRENT_REG"
  else
    WIFI_COUNTRY="GB"
  fi
fi
case "$WIFI_COUNTRY" in
  [A-Z][A-Z]) ;;
  *) warn "Ignoring invalid Wi-Fi country '$WIFI_COUNTRY'; using GB."; WIFI_COUNTRY="GB" ;;
esac

# US/CA/etc. get the UNII-3 high channels (149-165); ETSI regions (GB and
# most of Europe) do not, but do get UNII-2 (52-64) and UNII-2e (100-140),
# which Kismet scans passively.
case "$WIFI_COUNTRY" in
  US|CA|MX|BR|AU|NZ|TW|CO|CL)
    KISMET_5GHZ_CHANNELS='1,6,11,36,40,44,48,52,56,60,64,100,104,108,112,116,132,136,140,149,153,157,161,165' ;;
  *)
    KISMET_5GHZ_CHANNELS='1,6,11,36,40,44,48,52,56,60,64,100,104,108,112,116,132,136,140' ;;
esac

if [ ! -f /etc/kismet/kismet_site.conf ]; then
  step "Installing a starter Kismet configuration"
  sudo install -Dm0644 "$INSTALL_DIR/setup/kismet_site.conf.example" \
    /etc/kismet/kismet_site.conf
  warn "Edit /etc/kismet/kismet_site.conf and set its source= interface before Wi-Fi capture."
fi

step "Persisting Wi-Fi regulatory domain ($WIFI_COUNTRY)"
sudo iw reg set "$WIFI_COUNTRY" 2>/dev/null || warn "Runtime 'iw reg set $WIFI_COUNTRY' failed; the boot-time service below still applies it."
printf '%s\n' \
  '[Unit]' \
  'Description=Set the Wi-Fi regulatory domain for WirelessBOSS' \
  'Before=NetworkManager.service wpa_supplicant.service' \
  'Wants=network-pre.target' \
  '' \
  '[Service]' \
  'Type=oneshot' \
  'RemainAfterExit=yes' \
  "ExecStart=/usr/sbin/iw reg set $WIFI_COUNTRY" \
  '' \
  '[Install]' \
  'WantedBy=multi-user.target' \
  | sudo tee /etc/systemd/system/wifi-regdom.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now wifi-regdom.service >/dev/null 2>&1 || warn "Could not enable wifi-regdom.service."
ok "wifi-regdom.service installed and enabled"

# Keep NetworkManager off the Kismet capture radio - if NM manages it, it
# fights Kismet for channel control and the scan gets stuck on one channel.
KISMET_WIFI_IFACE="$( { grep -hoE '^[[:space:]]*source=[A-Za-z0-9._-]+' /etc/kismet/kismet_site.conf 2>/dev/null || true; } | head -n1 | sed -E 's/.*source=//')"
if [ -n "$KISMET_WIFI_IFACE" ]; then
  step "Telling NetworkManager to ignore the capture radio ($KISMET_WIFI_IFACE)"
  printf '%s\n' \
    '# Installed by WirelessBOSS: the Kismet capture radio is driven by' \
    '# Kismet itself, not NetworkManager.' \
    '[keyfile]' \
    "unmanaged-devices=interface-name:${KISMET_WIFI_IFACE};interface-name:${KISMET_WIFI_IFACE}mon" \
    | sudo tee /etc/NetworkManager/conf.d/90-wirelessboss-unmanage.conf >/dev/null
  if command -v nmcli >/dev/null 2>&1; then
    sudo systemctl reload NetworkManager 2>/dev/null || true
    sudo nmcli device set "$KISMET_WIFI_IFACE" managed no 2>/dev/null || true
  fi
  ok "NetworkManager will leave $KISMET_WIFI_IFACE alone"
fi

if ! grep -qE '^[[:space:]]*source=[^#]*channels=' /etc/kismet/kismet_site.conf &&
   { grep -qE '^[[:space:]]*source=[^#]*type=linuxwifi' /etc/kismet/kismet_site.conf ||
     grep -qE '^[[:space:]]*source=[a-zA-Z0-9._-]+[[:space:]]*(#.*)?$' /etc/kismet/kismet_site.conf; }; then
  # Configs from before dual-band support had no channels= on the Wi-Fi
  # source, so Kismet only hopped 2.4 GHz for the MT7921AU. Add the
  # region-appropriate channel list to the Wi-Fi source line in place
  # (timestamped backup kept).
  step "Adding 5 GHz channels to the existing Kismet source line"
  BACKUP="/etc/kismet/kismet_site.conf.bak.$(date +%Y%m%d%H%M%S)"
  sudo cp -a /etc/kismet/kismet_site.conf "$BACKUP"
  if sudo python3 - "$KISMET_5GHZ_CHANNELS" <<'PY'
import sys
path = "/etc/kismet/kismet_site.conf"
chans = sys.argv[1]
out, changed = [], False
for line in open(path, encoding="utf-8").read().splitlines(keepends=True):
    s = line.strip()
    if (not changed and s.startswith("source=") and "channels=" not in s
            and ("type=linuxwifi" in s or "type=" not in s)):
        eol = "\n" if line.endswith("\n") else ""
        body = line[:-1] if eol else line
        code, hash_, comment = body.partition("#")
        code = code.rstrip()
        sep = "," if ":" in code.split("=", 1)[1] else ":"
        code = f'{code}{sep}channels="{chans}"'
        line = code + ((" " + hash_ + comment) if hash_ else "") + eol
        changed = True
    out.append(line)
open(path, "w", encoding="utf-8").write("".join(out))
sys.exit(0 if changed else 1)
PY
  then
    ok "Channel list for $WIFI_COUNTRY added; restart Kismet to pick it up"
  else
    sudo rm -f "$BACKUP"
    warn "Could not auto-edit the Kismet source line - add channels=\"$KISMET_5GHZ_CHANNELS\" to it by hand for 5 GHz."
  fi
fi

step "Installing user services and application launcher"
KISMET_BIN="$(command -v kismet)"
SERVICES_WRITTEN=1
cat > "$UNIT_DIR/wirelessboss-kismet.service" <<EOF
[Unit]
Description=Kismet capture service for WirelessBOSS
After=network.target

[Service]
Type=simple
WorkingDirectory=$CAPTURE_DIR
ExecStart="$KISMET_BIN" --no-ncurses
Restart=no
TimeoutStopSec=20

[Install]
WantedBy=default.target
EOF

cat > "$UNIT_DIR/wirelessboss-web.service" <<EOF
[Unit]
Description=WirelessBOSS local web dashboard
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONUNBUFFERED=1
Environment="WIRELESSBOSS_CAPTURE_DIR=$CAPTURE_DIR"
ExecStart="$INSTALL_DIR/.venv/bin/python" -m wirelessboss.server.main
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF

for old_desktop in "$APPS_DIR/wirelessboss.desktop" "$APPS_DIR/wirelessboss-web.desktop"; do
  if [ -e "$old_desktop" ] || [ -L "$old_desktop" ]; then
    mv "$old_desktop" "$BACKUP_DIR/desktop/replaced-$(basename "$old_desktop")"
  fi
done
cat > "$APPS_DIR/wirelessboss-web.desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=WirelessBOSS Web
Comment=Start Kismet and the WirelessBOSS Wi-Fi/BLE analysis dashboard
Exec="$INSTALL_DIR/wirelessboss-service-launcher.sh"
Icon=$INSTALL_DIR/assets/wirelessboss-icon.svg
Terminal=false
Categories=Network;Security;
Keywords=WiFi;BLE;Kismet;Wireshark;Wireless;
StartupNotify=true
EOF
chmod +x "$APPS_DIR/wirelessboss-web.desktop"

if [ "$USER_SYSTEMD_AVAILABLE" -eq 1 ]; then
  systemctl --user daemon-reload
  systemctl --user enable wirelessboss-web.service >/dev/null
else
  warn "The per-user systemd manager is unavailable. Service files were installed; log out/in before launching."
fi
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
fi

WEB_PORT="$(WIRELESSBOSS_CAPTURE_DIR="$CAPTURE_DIR" "$INSTALL_DIR/.venv/bin/python" -c \
  'from wirelessboss.config import load_config; print(load_config().web_port)')"

step "Validating the installed web service"
if [ "$USER_SYSTEMD_AVAILABLE" -eq 1 ]; then
  systemctl --user restart wirelessboss-web.service
else
  (
    cd "$INSTALL_DIR"
    exec env WIRELESSBOSS_CAPTURE_DIR="$CAPTURE_DIR" \
      "$INSTALL_DIR/.venv/bin/python" -m wirelessboss.server.main \
      >"$BACKUP_DIR/install-health.log" 2>&1
  ) &
  HEALTH_PID="$!"
fi

WEB_READY=0
HEALTH_RESPONSE="$BACKUP_DIR/install-health-status.json"
for _ in $(seq 1 30); do
  HEALTH_PROCESS_ALIVE=0
  if [ "$USER_SYSTEMD_AVAILABLE" -eq 1 ]; then
    systemctl --user is-active --quiet wirelessboss-web.service && HEALTH_PROCESS_ALIVE=1 || true
  elif [ -n "$HEALTH_PID" ] && kill -0 "$HEALTH_PID" >/dev/null 2>&1; then
    HEALTH_PROCESS_ALIVE=1
  fi
  if [ "$HEALTH_PROCESS_ALIVE" -eq 1 ] && \
     curl -fsS --max-time 1 "http://127.0.0.1:$WEB_PORT/api/status" \
      -o "$HEALTH_RESPONSE" 2>/dev/null; then
    if "$INSTALL_DIR/.venv/bin/python" -c \
      'import json,sys; data=json.load(open(sys.argv[1], encoding="utf-8")); required={"kismet_connected","device_count","monitor_interface","server_uptime_sec"}; assert required <= data.keys() and 0 <= float(data["server_uptime_sec"]) < 45' \
      "$HEALTH_RESPONSE" >/dev/null 2>&1; then
      WEB_READY=1
      break
    fi
  fi
  sleep 0.5
done
[ "$WEB_READY" -eq 1 ] || die "The web service did not answer on port $WEB_PORT."
ok "WirelessBOSS answered at http://127.0.0.1:$WEB_PORT/api/status"

if [ "$AUTO_START" -eq 0 ]; then
  if [ "$USER_SYSTEMD_AVAILABLE" -eq 1 ]; then
    systemctl --user stop wirelessboss-web.service
    if [ "$OLD_KISMET_ACTIVE" -eq 1 ]; then
      systemctl --user start wirelessboss-kismet.service || \
        warn "The previously active Kismet service could not be restarted."
    fi
  elif [ -n "$HEALTH_PID" ]; then
    kill "$HEALTH_PID" >/dev/null 2>&1 || true
    wait "$HEALTH_PID" >/dev/null 2>&1 || true
  fi
elif [ "$USER_SYSTEMD_AVAILABLE" -eq 1 ]; then
  if ! pgrep -x kismet >/dev/null 2>&1 && [ -f /etc/kismet/kismet_site.conf ]; then
    systemctl --user start wirelessboss-kismet.service || \
      warn "Kismet did not start. Review: journalctl --user -u wirelessboss-kismet.service -n 80"
  fi
  ok "WirelessBOSS is running at http://127.0.0.1:$WEB_PORT/"
else
  if [ -n "$HEALTH_PID" ]; then
    kill "$HEALTH_PID" >/dev/null 2>&1 || true
    wait "$HEALTH_PID" >/dev/null 2>&1 || true
  fi
  warn "The app passed its health check but cannot stay service-managed until the user systemd session is available."
fi

if pgrep -x wch_capture >/dev/null 2>&1; then
  OTHER_DRIVER_PROCESSES="$(ps -o user=,pid=,command= -C wch_capture 2>/dev/null || true)"
  if [ -n "$OTHER_DRIVER_PROCESSES" ]; then
    warn "A wch_capture process remains (possibly root/another user); it was not killed:"
    printf '%s\n' "$OTHER_DRIVER_PROCESSES" >&2
  fi
fi

USB_RADIOS="$( { lsusb -d 1a86:8009 2>/dev/null || true; } | wc -l | tr -d ' ')"
if [ "$USB_RADIOS" = "3" ]; then
  ok "Detected all three WCH analyzer radios"
else
  warn "Detected $USB_RADIOS of 3 WCH analyzer radios. Plug/replug the analyzer after installation."
fi

INSTALL_COMPLETE=1
trap - EXIT INT TERM

printf '\n%sWirelessBOSS installation complete.%s\n' "$BOLD" "$RESET"
printf '  App:       %s\n' "$INSTALL_DIR"
printf '  Driver:    %s\n' "$INSTALLED_DRIVER_VERSION"
printf '  Captures:  %s (preserved)\n' "$CAPTURE_DIR"
printf '  Tiles:     %s (preserved)\n' "$TILES_DIR"
printf '  Config:    %s/wirelessboss (preserved)\n' "$CONFIG_HOME"
printf '  Backup:    %s\n' "$BACKUP_DIR"
printf '  Web:       http://127.0.0.1:%s/\n' "$WEB_PORT"
printf '  Wi-Fi:     regdomain %s + NM hand-off persisted (wifi-regdom.service)\n' "$WIFI_COUNTRY"
printf '  Logs:      journalctl --user -u wirelessboss-web.service -f\n'
if [ "$AUTO_START" -eq 0 ]; then
  printf '  Start:     systemctl --user start wirelessboss-web.service\n'
fi
if [ "$GROUP_REFRESH_REQUIRED" -eq 1 ]; then
  printf '\n%sLog out and back in once, then unplug/replug the WCH analyzer.%s\n' "$YELLOW" "$RESET"
fi
