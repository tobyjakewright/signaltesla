#!/usr/bin/env python3
"""Runs WirelessBOSS bound to 0.0.0.0 instead of upstream's 127.0.0.1-only
default, so it's reachable from the WarDriving AP network (the rig's whole
point), not just from the Pi itself. Kept as a separate entry point rather
than editing wirelessboss/server/main.py so this stays a clean vendor copy
that upstream changes can drop straight over.

install.sh points the WirelessBOSS installer's generated
wirelessboss-web.service at this file instead of `-m wirelessboss.server.main`.
"""
from __future__ import annotations

import sys

import uvicorn

from wirelessboss.config import load_config
from wirelessboss.server.app import create_app


def main() -> int:
    cfg = load_config()
    app = create_app(cfg)
    uvicorn.run(app, host="0.0.0.0", port=cfg.web_port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
