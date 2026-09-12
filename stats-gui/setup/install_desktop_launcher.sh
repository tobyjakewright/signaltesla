#!/usr/bin/env bash
# Installs a .desktop entry so WirelessBOSS shows up in the application
# menu/drawer like a normal app. User-local (~/.local/share/applications),
# no root needed.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$APPS_DIR"

chmod +x "$PROJECT_DIR/wirelessboss-web-launcher.sh"

cat > "$APPS_DIR/wirelessboss.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=WirelessBOSS
Comment=Wardriving, Wi-Fi & BLE recon (Kismet-powered) - web UI
Exec=$PROJECT_DIR/wirelessboss-web-launcher.sh
Icon=$PROJECT_DIR/assets/wirelessboss-icon.svg
Terminal=true
Categories=Network;Security;
StartupNotify=true
EOF

chmod +x "$APPS_DIR/wirelessboss.desktop"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APPS_DIR" || true
fi

echo "Installed: $APPS_DIR/wirelessboss.desktop"
echo "WirelessBOSS should now show up in your app menu/drawer - search for 'WirelessBOSS'."
echo "If it doesn't appear immediately: log out/in, or run 'xdg-desktop-menu forceupdate'."
