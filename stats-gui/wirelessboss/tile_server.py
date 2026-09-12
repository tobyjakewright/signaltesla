"""Tiny localhost HTTP server for offline map tiles.

Serves pre-downloaded tiles from a local directory laid out as the
standard {z}/{x}/{y}.png slippy-map convention - the same layout
scripts/download_offline_tiles.py writes and that most offline tile
tools/MBTiles-to-directory converters produce. Leaflet's tileLayer just
points at this instead of a remote CDN, so the map works with zero
network access once tiles have been pre-fetched (see that script's
docstring for how to do that while you still have internet).

A missing tile is a normal 404, not an error - Leaflet just leaves that
square blank, exactly like a slow/failed remote tile load would.
"""
from __future__ import annotations

import logging
import threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

log = logging.getLogger(__name__)


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - matches base signature
        pass  # don't spam stdout for every tile request


class TileServer:
    def __init__(self, tiles_dir: Path, port: int = 8765):
        self.tiles_dir = Path(tiles_dir)
        self.port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._httpd is not None:
            return
        self.tiles_dir.mkdir(parents=True, exist_ok=True)

        directory = str(self.tiles_dir)

        class Handler(_QuietHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=directory, **kwargs)

        try:
            self._httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        except OSError as exc:
            log.warning("Could not start local tile server on port %s: %s", self.port, exc)
            self._httpd = None
            return

        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    @property
    def is_running(self) -> bool:
        return self._httpd is not None

    def tile_count(self) -> int:
        if not self.tiles_dir.exists():
            return 0
        return sum(1 for _ in self.tiles_dir.rglob("*.png"))
