#!/usr/bin/env bash
# Renders every *.tmpl in this repo into its real system location, using
# config/rig.conf as the source of truth. Safe to re-run any time you
# change rig.conf - just re-run install.sh, which calls this.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="${REPO_DIR}/config/rig.conf"

if [[ ! -f "$CONF" ]]; then
  echo "config/rig.conf not found - run install.sh first, it bootstraps it." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$CONF"
set +a

if ! command -v envsubst >/dev/null 2>&1; then
  echo "envsubst not found - install.sh should have installed gettext-base." >&2
  exit 1
fi

render() {
  local tmpl="$1" out="$2" vars="$3"
  mkdir -p "$(dirname "$out")"
  envsubst "$vars" < "$tmpl" > "$out"
  echo "rendered ${out}"
}

render "${REPO_DIR}/hostapd/hostapd.conf.tmpl" \
  /etc/hostapd/hostapd.conf \
  '${AP_INTERFACE} ${AP_SSID} ${AP_CHANNEL_24} ${AP_COUNTRY} ${AP_PASSPHRASE}'

render "${REPO_DIR}/dnsmasq/wardriving.conf.tmpl" \
  /etc/dnsmasq.d/wardriving.conf \
  '${AP_INTERFACE} ${DHCP_RANGE_START} ${DHCP_RANGE_END} ${DHCP_LEASE_TIME} ${AP_IP}'

render "${REPO_DIR}/kismet/kismet_site.conf.tmpl" \
  /etc/kismet/kismet_site.conf \
  '${MON_INTERFACE} ${GPS_DEVICE} ${KISMET_LOG_DIR} ${KISMET_HTTP_PORT}'

render "${REPO_DIR}/nginx/wardriving.conf.tmpl" \
  /etc/nginx/sites-available/wardriving \
  '${WEB_HTTP_PORT} ${WEB_APP_PORT}'

# NOTE: these two only pre-render RIG_USER. WEB_APP_PORT / VNC_DISPLAY_NUM /
# VNC_PORT are left as literal ${VAR} in the output - systemd itself
# expands those at service-start time via EnvironmentFile=rig.conf.
render "${REPO_DIR}/systemd/wardriving-web.service.tmpl" \
  /etc/systemd/system/wardriving-web.service \
  '${RIG_USER}'

render "${REPO_DIR}/systemd/wardriving-vnc.service.tmpl" \
  /etc/systemd/system/wardriving-vnc.service \
  '${RIG_USER}'

echo "Config render complete."
