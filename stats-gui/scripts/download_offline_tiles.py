#!/usr/bin/env python3
"""Pre-fetch OpenStreetMap tiles for offline wardriving.

Run this ON THE KALI MACHINE (it needs internet - home/office wifi, or
tethered) for the area you'll be driving around. WirelessBOSS's map then
reads tiles from the local cache via its own offline tile server
(wirelessboss/tile_server.py) - no network needed while you're out.

IMPORTANT - OpenStreetMap's tile usage policy (see
https://operations.osmfoundation.org/policies/tiles/): the public tile.
openstreetmap.org servers are for light use, need a real identifying
User-Agent (this script sets one - edit CONTACT below), must not be
hammered, and bulk/heavy downloading should really go through your own
tile server or a commercial provider (Thunderforest, MapTiler, Mapbox,
etc). This script rate-limits to ~2 requests/second and refuses to run
over a hard tile-count cap unless you pass --allow-large.

A whole country at STREET-LEVEL detail is not something the public
server can reasonably serve (the UK at z1-14 is ~560,000 tiles, ~86
hours) - that would cross into the bulk-scraping territory the policy
explicitly asks you not to do. A country-wide OVERVIEW (low zoom, "where
am I in the country" context rather than street detail) is a completely
different, much lighter request - the built-in --region preset below
defaults to exactly that scope, and stays under the safe tile cap.

Built-in region overview (low zoom, ~20-30 min, safe by default):
    python3 scripts/download_offline_tiles.py --region uk

Custom area at street level, e.g. wherever you're actually driving today
(zoom 12-16) - layers on top of the region overview with no conflict,
since tile paths are unique per z/x/y:
    python3 scripts/download_offline_tiles.py \\
        --south 51.48 --north 51.52 --west -0.15 --east -0.08 \\
        --min-zoom 12 --max-zoom 16
"""
from __future__ import annotations

import argparse
import math
import sys
import time
import urllib.request
from pathlib import Path

# Identify yourself per OSM's tile usage policy - edit this to something
# that actually identifies you/this install if you're fetching a lot.
CONTACT = "WirelessBOSS-offline-tile-fetch (personal wardriving use)"

DEFAULT_OUT_DIR = Path.home() / ".local/share/wirelessboss/tiles"
DEFAULT_TILE_SERVER = "https://tile.openstreetmap.org"
RATE_LIMIT_SEC = 0.55  # ~2 req/s, per OSM's light-use guidance
HARD_TILE_CAP = 4000

# Bounding boxes for --region, deliberately paired with a low default zoom
# range (country/regional overview, not street level) to stay light-use.
REGION_PRESETS = {
    "uk": {"south": 49.9, "north": 60.9, "west": -8.6, "east": 1.8, "default_zoom": (1, 10)},
}


def deg2tile(lat_deg: float, lon_deg: float, zoom: int) -> tuple[int, int]:
    lat_rad = math.radians(lat_deg)
    n = 2.0 ** zoom
    x = int((lon_deg + 180.0) / 360.0 * n)
    y = int((1.0 - math.log(math.tan(lat_rad) + 1 / math.cos(lat_rad)) / math.pi) / 2.0 * n)
    return x, y


def tiles_for_bbox(south, west, north, east, zoom) -> list[tuple[int, int, int]]:
    x0, y0 = deg2tile(north, west, zoom)   # top-left
    x1, y1 = deg2tile(south, east, zoom)   # bottom-right
    tiles = []
    for x in range(min(x0, x1), max(x0, x1) + 1):
        for y in range(min(y0, y1), max(y0, y1) + 1):
            tiles.append((zoom, x, y))
    return tiles


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--region", choices=sorted(REGION_PRESETS),
                     help="Use a built-in bounding box (low-zoom overview) instead of --south/--north/--west/--east.")
    ap.add_argument("--south", type=float)
    ap.add_argument("--north", type=float)
    ap.add_argument("--west", type=float)
    ap.add_argument("--east", type=float)
    ap.add_argument("--min-zoom", type=int, default=None)
    ap.add_argument("--max-zoom", type=int, default=None)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    ap.add_argument("--tile-server", default=DEFAULT_TILE_SERVER,
                     help="Base URL of a {z}/{x}/{y}.png tile server (default: OSM's own - light use only).")
    ap.add_argument("--allow-large", action="store_true",
                     help=f"Allow more than {HARD_TILE_CAP} tiles in one run.")
    args = ap.parse_args()

    if args.region:
        preset = REGION_PRESETS[args.region]
        south, north, west, east = preset["south"], preset["north"], preset["west"], preset["east"]
        default_min, default_max = preset["default_zoom"]
    elif None not in (args.south, args.north, args.west, args.east):
        south, north, west, east = args.south, args.north, args.west, args.east
        default_min, default_max = 12, 16
    else:
        print("Error: pass --region uk, or all four of --south/--north/--west/--east.", file=sys.stderr)
        return 1

    min_zoom = args.min_zoom if args.min_zoom is not None else default_min
    max_zoom = args.max_zoom if args.max_zoom is not None else default_max

    if south >= north or west >= east:
        print("Error: south must be < north, and west must be < east.", file=sys.stderr)
        return 1

    all_tiles = []
    for zoom in range(min_zoom, max_zoom + 1):
        all_tiles.extend(tiles_for_bbox(south, west, north, east, zoom))

    print(f"This will fetch {len(all_tiles)} tiles across zoom {min_zoom}-{max_zoom}")
    print(f"from {args.tile_server} into {args.out_dir}")
    print(f"at ~{1 / RATE_LIMIT_SEC:.1f} req/s -> about {len(all_tiles) * RATE_LIMIT_SEC / 60:.1f} minutes.\n")
    print("Per OSM's tile usage policy: light use only, real User-Agent required,")
    print("no bulk/heavy scraping of the public servers - keep areas small.\n")

    if len(all_tiles) > HARD_TILE_CAP and not args.allow_large:
        print(f"Refusing to fetch {len(all_tiles)} tiles (> {HARD_TILE_CAP} cap). "
              "Shrink the bbox/zoom range, or pass --allow-large if you're sure "
              "(and ideally pointing --tile-server at your own server, not OSM's).",
              file=sys.stderr)
        return 1

    reply = input("Proceed? [y/N] ").strip().lower()
    if reply != "y":
        print("Cancelled.")
        return 0

    opener = urllib.request.build_opener()
    opener.addheaders = [("User-Agent", CONTACT)]

    fetched = skipped = failed = 0
    for i, (z, x, y) in enumerate(all_tiles, 1):
        out_path = args.out_dir / str(z) / str(x) / f"{y}.png"
        if out_path.exists():
            skipped += 1
            continue
        out_path.parent.mkdir(parents=True, exist_ok=True)
        url = f"{args.tile_server}/{z}/{x}/{y}.png"
        try:
            with opener.open(url, timeout=10) as resp:
                out_path.write_bytes(resp.read())
            fetched += 1
        except Exception as exc:  # noqa: BLE001 - keep going, report at the end
            failed += 1
            print(f"  failed {url}: {exc}", file=sys.stderr)
        if i % 20 == 0 or i == len(all_tiles):
            print(f"  [{i}/{len(all_tiles)}] fetched={fetched} skipped(cached)={skipped} failed={failed}")
        time.sleep(RATE_LIMIT_SEC)

    print(f"\nDone. {fetched} fetched, {skipped} already cached, {failed} failed.")
    print(f"Tiles are in {args.out_dir} - WirelessBOSS's local tile server reads from here automatically.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
