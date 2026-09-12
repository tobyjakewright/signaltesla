#!/usr/bin/env bash
# Convenience launcher: starts Kismet headless (no ncurses UI), so
# WirelessBOSS's GUI is the only UI you look at.
#
# With no arguments, relies on /etc/kismet/kismet_site.conf's source= line
# (the normal path). Pass an interface name to override it for a one-off
# run: ./scripts/start_kismet.sh wlan0
#
# The explicit channels list is needed for 5 GHz - Kismet's auto channel
# enumeration for the AXML's MT7921AU only finds 2.4 GHz otherwise. Keep it
# in sync with the source= line in setup/kismet_site.conf.example.
set -euo pipefail
# ETSI/UK default. In the US etc. append ,149,153,157,161,165 (or just rely
# on /etc/kismet/kismet_site.conf, which the updater keeps in sync).
CHANNELS="${KISMET_CHANNELS:-1,6,11,36,40,44,48,52,56,60,64,100,104,108,112,116,132,136,140}"
if [ "$#" -ge 1 ]; then
  exec kismet --no-ncurses -c "$1:channels=\"$CHANNELS\""
else
  exec kismet --no-ncurses
fi
