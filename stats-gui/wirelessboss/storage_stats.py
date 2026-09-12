"""Tracks kismetdb + pcap capture size and disk space, and estimates
time-to-full from the observed growth rate."""
from __future__ import annotations

import shutil
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class StorageStats:
    capture_bytes: int          # kismetdb (.kismet/.kismetdb) total
    file_count: int
    pcap_bytes: int             # .pcapng total - what you'd open in Wireshark
    pcap_file_count: int
    disk_total_bytes: int
    disk_used_bytes: int
    disk_free_bytes: int
    growth_bytes_per_sec: Optional[float]   # combined kismetdb + pcap growth
    eta_seconds: Optional[float]


class StorageMonitor:
    """Sums kismetdb and pcapng file sizes in `capture_dir` and tracks growth
    over a rolling window to estimate seconds until the disk fills up."""

    def __init__(self, capture_dir: Path, history_window_sec: float = 300.0):
        self.capture_dir = Path(capture_dir)
        self.history_window_sec = history_window_sec
        self._history: deque[tuple[float, int]] = deque()

    def _sum_glob(self, patterns: tuple[str, ...]) -> tuple[int, int]:
        total = 0
        count = 0
        if self.capture_dir.exists():
            for pattern in patterns:
                for f in self.capture_dir.glob(pattern):
                    try:
                        total += f.stat().st_size
                        count += 1
                    except OSError:
                        pass
        return total, count

    def sample(self) -> StorageStats:
        now = time.time()
        capture_bytes, file_count = self._sum_glob(("*.kismet", "*.kismetdb"))
        pcap_bytes, pcap_file_count = self._sum_glob(("*.pcapng", "*.pcap"))
        combined = capture_bytes + pcap_bytes

        self._history.append((now, combined))
        while self._history and now - self._history[0][0] > self.history_window_sec:
            self._history.popleft()

        growth_rate = None
        if len(self._history) >= 2:
            t0, b0 = self._history[0]
            dt = now - t0
            if dt > 1:
                growth_rate = (combined - b0) / dt

        try:
            usage = shutil.disk_usage(self.capture_dir if self.capture_dir.exists() else Path.home())
            disk_total, disk_used, disk_free = usage.total, usage.used, usage.free
        except OSError:
            disk_total = disk_used = disk_free = 0

        eta_seconds = None
        if growth_rate and growth_rate > 0 and disk_free > 0:
            eta_seconds = disk_free / growth_rate

        return StorageStats(
            capture_bytes=capture_bytes,
            file_count=file_count,
            pcap_bytes=pcap_bytes,
            pcap_file_count=pcap_file_count,
            disk_total_bytes=disk_total,
            disk_used_bytes=disk_used,
            disk_free_bytes=disk_free,
            growth_bytes_per_sec=growth_rate,
            eta_seconds=eta_seconds,
        )


def fmt_bytes(n: float) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def fmt_duration(seconds: Optional[float]) -> str:
    if seconds is None or seconds <= 0:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.0f}m"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f}h"
    days = hours / 24
    return f"{days:.1f}d"
