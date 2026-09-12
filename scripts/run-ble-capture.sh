#!/usr/bin/env bash
# Runs the WCH BLE Analyzer Pro driver as a plain always-on capture: a
# fresh timestamped .pcap each start, plus an ever-growing ble-live.jsonl
# that the custom stats GUI's BLE tab tails for a simple nearby-devices
# view (see webapp/ble/reader.py). No start/stop control, no PHY/LTK/
# connection-following options - see README "What the stats GUI leaves out".
set -euo pipefail

: "${KISMET_LOG_DIR:?KISMET_LOG_DIR not set - is EnvironmentFile=config/rig.conf wired up?}"
mkdir -p "$KISMET_LOG_DIR"

STAMP="$(date +%Y%m%d-%H%M%S)"
exec /usr/local/bin/wch_capture -J -w "${KISMET_LOG_DIR}/ble-${STAMP}.pcap" \
  >> "${KISMET_LOG_DIR}/ble-live.jsonl"
