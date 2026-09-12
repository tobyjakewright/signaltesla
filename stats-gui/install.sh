#!/usr/bin/env bash
# One-command Kali installer/upgrader. Keep this file at the package root so a
# downloaded WirelessBOSS archive can be installed with: ./install.sh
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$ROOT_DIR/setup/install_or_upgrade.sh" "$@"
