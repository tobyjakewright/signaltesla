"""WirelessBOSS web server entry point.

python -m wirelessboss.server.main

Starts the FastAPI app (Kismet polling + REST API + the web UI's static
files) on http://127.0.0.1:<port>. wirelessboss-launcher.sh runs this,
waits for it to come up, then opens a browser - the same two-step
experience as running `kismet` and opening its own web UI.
"""
from __future__ import annotations

import sys

import uvicorn

from ..config import load_config
from .app import create_app


def main() -> int:
    cfg = load_config()
    app = create_app(cfg)
    uvicorn.run(app, host="127.0.0.1", port=cfg.web_port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
