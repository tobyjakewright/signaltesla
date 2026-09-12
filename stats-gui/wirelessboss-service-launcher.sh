#!/usr/bin/env bash
# Desktop entry point for the service-managed WirelessBOSS web UI.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$APP_DIR/.venv/bin/python"
WEB_SERVICE="wirelessboss-web.service"
KISMET_SERVICE="wirelessboss-kismet.service"

notify_error() {
  local message="$1"
  if command -v notify-send >/dev/null 2>&1; then
    notify-send --urgency=critical "WirelessBOSS" "$message"
  fi
  echo "$message" >&2
}

if [ ! -x "$PYTHON" ]; then
  notify_error "WirelessBOSS is not fully installed. Run setup/update_kali_web.sh from the new source folder."
  exit 1
fi

export WIRELESSBOSS_CAPTURE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/wirelessboss/captures"
PORT="$($PYTHON -c 'from wirelessboss.config import load_config; print(load_config().web_port)' 2>/dev/null || echo 8080)"

if ! systemctl --user daemon-reload; then
  notify_error "The user service manager is unavailable. Log out and back in, then try WirelessBOSS Web again."
  exit 1
fi

# Reuse a Kismet instance that the user or system already started. Otherwise
# start the dedicated user service installed by update_kali_web.sh.
if ! pgrep -x kismet >/dev/null 2>&1; then
  if ! systemctl --user start "$KISMET_SERVICE"; then
    notify_error "Kismet did not start. Check: journalctl --user -u $KISMET_SERVICE -n 80"
  fi
fi

if ! systemctl --user start "$WEB_SERVICE"; then
  notify_error "The WirelessBOSS web service did not start. Check: journalctl --user -u $WEB_SERVICE -n 80"
  exit 1
fi

for _ in $(seq 1 30); do
  if curl -fsS --max-time 1 "http://127.0.0.1:$PORT/api/status" >/dev/null 2>&1; then
    xdg-open "http://127.0.0.1:$PORT/" >/dev/null 2>&1 &
    exit 0
  fi
  sleep 0.5
done

notify_error "WirelessBOSS did not answer on port $PORT. Check: journalctl --user -u $WEB_SERVICE -n 80"
exit 1
