#!/usr/bin/env bash
# Backward-compatible entry point retained for older WirelessBOSS instructions.
# The comprehensive installer now handles dependencies, backup, driver rebuild,
# service migration, health validation, and automatic rollback.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT_DIR/setup/install_or_upgrade.sh" "$@"
