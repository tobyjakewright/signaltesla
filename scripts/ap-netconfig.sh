#!/usr/bin/env bash
# Assigns the static AP address to the onboard Wi-Fi interface before
# hostapd/dnsmasq start. Run as root via wardriving-ap-netconfig.service.
set -euo pipefail

: "${AP_INTERFACE:?AP_INTERFACE not set - is EnvironmentFile=config/rig.conf wired up?}"
: "${AP_IP:?AP_IP not set}"
: "${AP_PREFIX:?AP_PREFIX not set}"

# Wait for the renamed interface to exist (udev .link rename can lag a
# beat behind boot).
for _ in $(seq 1 30); do
  if ip link show "$AP_INTERFACE" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

ip link set "$AP_INTERFACE" down
ip addr flush dev "$AP_INTERFACE"
ip addr add "${AP_IP}/${AP_PREFIX}" dev "$AP_INTERFACE"
ip link set "$AP_INTERFACE" up

echo "AP interface ${AP_INTERFACE} configured as ${AP_IP}/${AP_PREFIX}"
