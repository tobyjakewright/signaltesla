"""Start/stop control for the Kismet process itself.

Deliberately process-level (pgrep/kill) rather than trying to drive
Kismet's per-datasource pause/resume REST commands - those command names
vary enough across Kismet versions that guessing wrong would silently do
nothing. Starting/stopping the whole process is unambiguous: while
Kismet isn't running, nothing is being captured or logged, which is what
"start/stop recording" means to the user. Works whether WirelessBOSS
started Kismet itself or it was already running from a previous session.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

KISMET_USER_SERVICE = "wirelessboss-kismet.service"


def _systemctl_user(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["systemctl", "--user", *args], capture_output=True, text=True, timeout=12
    )


def _user_service_installed() -> bool:
    try:
        return _systemctl_user("cat", KISMET_USER_SERVICE).returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError):
        return False


def _user_service_active() -> bool:
    try:
        return _systemctl_user("is-active", "--quiet", KISMET_USER_SERVICE).returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError):
        return False


def kismet_pid() -> Optional[int]:
    try:
        result = subprocess.run(
            ["pgrep", "-x", "kismet"], capture_output=True, text=True, timeout=2
        )
    except (OSError, subprocess.SubprocessError):
        return None
    pids = [int(p) for p in result.stdout.split() if p.strip().isdigit()]
    return pids[0] if pids else None


def is_running() -> bool:
    return kismet_pid() is not None


def start(capture_dir: Path, log_path: Path) -> tuple[bool, str]:
    if is_running():
        return True, "Kismet is already running."
    if _user_service_installed():
        try:
            result = _systemctl_user("start", KISMET_USER_SERVICE)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"Failed to start the Kismet user service: {exc}"
        if result.returncode == 0:
            return True, "Kismet service starting..."
        detail = result.stderr.strip() or result.stdout.strip() or "unknown systemd error"
        return False, f"Failed to start the Kismet user service: {detail}"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        capture_dir.mkdir(parents=True, exist_ok=True)
        with open(log_path, "ab") as log_file:
            subprocess.Popen(
                ["kismet", "--no-ncurses"],
                cwd=str(capture_dir),
                stdout=log_file,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        return True, "Kismet starting..."
    except FileNotFoundError:
        return False, "'kismet' isn't on PATH - is it installed? (setup/install_kismet.sh)"
    except OSError as exc:
        return False, f"Failed to start Kismet: {exc}"


def stop(timeout_sec: float = 8.0) -> tuple[bool, str]:
    if _user_service_active():
        try:
            result = _systemctl_user("stop", KISMET_USER_SERVICE)
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"Failed to stop the Kismet user service: {exc}"
        if result.returncode == 0:
            return True, "Stopping the Kismet service..."
        detail = result.stderr.strip() or result.stdout.strip() or "unknown systemd error"
        return False, f"Failed to stop the Kismet user service: {detail}"
    pid = kismet_pid()
    if pid is None:
        return True, "Kismet isn't running."
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        return False, f"Failed to signal Kismet (pid {pid}): {exc}"
    deadline = time.monotonic() + max(0.1, timeout_sec)
    while time.monotonic() < deadline:
        if not is_running():
            return True, f"Kismet stopped (pid {pid})."
        time.sleep(0.1)
    return False, (
        f"Kismet did not stop within {timeout_sec:g} seconds (pid {pid}). "
        "Check its service log before starting a new capture segment."
    )


CAPTURE_FILE_GLOBS = ("*.kismet", "*.kismetdb", "*.pcapng", "*.pcap")


def clear_capture_files(capture_dir: Path) -> tuple[bool, str, int]:
    """Permanently deletes kismetdb/pcap files in capture_dir. Refuses while
    Kismet is running, since it holds those files open while recording."""
    if is_running():
        return False, "Stop Capture first - Kismet has these files open while recording.", 0
    removed = 0
    for pattern in CAPTURE_FILE_GLOBS:
        for f in Path(capture_dir).glob(pattern):
            try:
                f.unlink()
                removed += 1
            except OSError:
                pass
    return True, f"Removed {removed} file(s).", removed
