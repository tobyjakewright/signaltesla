#!/usr/bin/env python3
"""Build a deterministic, transfer-ready WirelessBOSS Kali installer."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
from pathlib import Path
import tarfile
import tempfile


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "dist" / "WirelessBOSS-Kali-Installer.tar.gz"
DRIVER_DIR = "BLE-Analyzer-pro-linux-capture-main"
CAPTURE_SUFFIXES = {".kismet", ".kismetdb", ".pcap", ".pcapng"}
ARCHIVE_SUFFIXES = {".zip", ".tgz", ".gz", ".bz2", ".xz"}
EXCLUDED_PARTS = {".git", ".venv", "__pycache__", "__MACOSX", "dist"}


def excluded(relative: Path) -> bool:
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return True
    if relative.name in {".DS_Store", "wch_capture"} or relative.suffix in {".pyc", ".o"}:
        return True
    lower_name = relative.name.lower()
    if relative.suffix.lower() in CAPTURE_SUFFIXES | ARCHIVE_SUFFIXES or lower_name.endswith(
        (".tar.gz", ".tar.bz2", ".tar.xz")
    ):
        return True
    if relative.parts and relative.parts[0] == DRIVER_DIR:
        if relative.name == "wch_capture" or relative.suffix == ".o":
            return True
    return False


def archive_paths() -> list[Path]:
    paths: list[Path] = []
    for directory, dirnames, filenames in os.walk(PROJECT_ROOT):
        root = Path(directory)
        relative_root = root.relative_to(PROJECT_ROOT)
        dirnames[:] = sorted(
            name for name in dirnames if not excluded(relative_root / name)
        )
        for dirname in dirnames:
            paths.append(relative_root / dirname)
        for filename in sorted(filenames):
            relative = relative_root / filename
            if not excluded(relative):
                paths.append(relative)
    return sorted(set(paths), key=lambda path: path.as_posix())


def build(output: Path, epoch: int) -> tuple[Path, str]:
    required = [
        PROJECT_ROOT / "install.sh",
        PROJECT_ROOT / "requirements.txt",
        PROJECT_ROOT / DRIVER_DIR / "Makefile",
        PROJECT_ROOT / DRIVER_DIR / "wch_capture.c",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise SystemExit("Package source is incomplete; missing: " + ", ".join(missing))

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    paths = archive_paths()
    if Path("install.sh") not in paths:
        raise SystemExit("Refusing to build an archive without top-level install.sh")

    with tempfile.NamedTemporaryFile(
        prefix=f".{output.name}.", dir=output.parent, delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)

    try:
        with temporary_path.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for relative in paths:
                        source = PROJECT_ROOT / relative
                        info = archive.gettarinfo(str(source), arcname=relative.as_posix())
                        info.uid = 0
                        info.gid = 0
                        info.uname = "root"
                        info.gname = "root"
                        info.mtime = epoch
                        info.pax_headers = {}
                        if info.isfile():
                            with source.open("rb") as handle:
                                archive.addfile(info, handle)
                        else:
                            archive.addfile(info)
        os.replace(temporary_path, output)
        output.chmod(0o644)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    checksum = output.with_name(output.name + ".sha256")
    checksum.write_text(f"{digest}  {output.name}\n", encoding="utf-8")

    with tarfile.open(output, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        names = set(members)
    required_members = {
        "install.sh",
        "requirements.txt",
        f"{DRIVER_DIR}/Makefile",
        f"{DRIVER_DIR}/wch_capture.c",
    }
    if not required_members.issubset(names):
        raise SystemExit("Archive verification failed: required installer files are missing")
    if f"{DRIVER_DIR}/wch_capture" in names:
        raise SystemExit("Archive verification failed: stale compiled wch_capture was included")
    for executable in ("install.sh", "setup/install_or_upgrade.sh"):
        if not members[executable].mode & 0o111:
            raise SystemExit(f"Archive verification failed: {executable} is not executable")
    return output, digest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a deterministic transfer-ready WirelessBOSS Kali .tar.gz"
    )
    parser.add_argument(
        "output",
        nargs="?",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"output archive (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()
    try:
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    except ValueError as error:
        raise SystemExit("SOURCE_DATE_EPOCH must be an integer") from error
    output, digest = build(args.output, epoch)
    print(f"Built:  {output}")
    print(f"SHA256: {digest}")
    print("Kali:   extract into an empty folder, then run ./install.sh")


if __name__ == "__main__":
    main()
