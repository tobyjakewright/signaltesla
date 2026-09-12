#!/usr/bin/env bash
# App-drawer entry point: starts Kismet (if not already running, same as
# before) and WirelessBOSS's own web server, waits for both, then opens
# your browser to it - the same two-step experience as Kismet's own web
# UI (start server, open browser), just with a much richer dashboard.
#
# Kismet is started detached (nohup) so it survives independently of this
# window, same as always. The web server is NOT detached - closing this
# terminal (or Ctrl+C) stops it, same as closing Kismet's own console
# would stop Kismet. Kismet itself keeps running either way.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

LOG_DIR="$HOME/.local/share/wirelessboss"
mkdir -p "$LOG_DIR"

kismet_up() {
  curl -fsS --max-time 2 http://localhost:2501/system/status.json >/dev/null 2>&1
}

if ! kismet_up; then
  if ! command -v kismet >/dev/null 2>&1; then
    echo "Kismet isn't installed yet. Run ./install.sh first to install it"
    echo "and its dependencies, then relaunch WirelessBOSS."
    read -rp "Press Enter to close..." _
    exit 1
  fi

  if [ ! -f /etc/kismet/kismet_site.conf ]; then
    echo "Kismet isn't configured yet - installing a starter config"
    echo "(sudo required) so Kismet can start; edit the source= line in"
    echo "/etc/kismet/kismet_site.conf afterwards to set your Alfa adapter's"
    echo "interface name for actual capture."
    sudo install -Dm0644 setup/kismet_site.conf.example /etc/kismet/kismet_site.conf ||
      echo "Couldn't install a starter config - continuing without one; Kismet's REST API will still come up, but no capture source will be configured."
  fi

  echo "Starting Kismet in the background (log: $LOG_DIR/kismet.log)..."
  nohup kismet --no-ncurses >"$LOG_DIR/kismet.log" 2>&1 &
  echo -n "Waiting for Kismet's REST API to come up"
  for _ in $(seq 1 20); do
    kismet_up && { echo " - up."; break; }
    echo -n "."
    sleep 1
  done
  echo
else
  echo "Kismet is already running - reusing it."
fi

if [ ! -x ./.venv/bin/python ]; then
  echo "Error: .venv is missing (./.venv/bin/python not found)."
  echo "Run: python3 -m venv --system-site-packages .venv && ./.venv/bin/pip install -r requirements.txt"
  read -rp "Press Enter to close..." _
  exit 1
fi

PORT="$(./.venv/bin/python -c 'from wirelessboss.config import load_config; print(load_config().web_port)' 2>/dev/null || echo 8080)"

echo "Starting WirelessBOSS web server on port $PORT..."
./.venv/bin/python -m wirelessboss.server.main &
WEB_PID=$!

echo -n "Waiting for WirelessBOSS to come up"
for _ in $(seq 1 20); do
  curl -fsS --max-time 1 "http://127.0.0.1:$PORT/api/status" >/dev/null 2>&1 && { echo " - up."; break; }
  echo -n "."
  sleep 1
done
echo

xdg-open "http://127.0.0.1:$PORT/" >/dev/null 2>&1 &

echo "WirelessBOSS is running at http://127.0.0.1:$PORT/"
echo "Close this window (or Ctrl+C) to stop the web server. Kismet keeps running."
wait "$WEB_PID"
