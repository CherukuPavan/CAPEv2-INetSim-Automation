#!/usr/bin/env python3
"""Read-only local Windows ISO/archive metadata (no extract, mount or execution).

Designed for downloaded 7z/ZIP/ISO candidates for CAPEv2 analysis VMs.
SHA256 identifies a file but does not establish Microsoft authenticity or
malware safety. Report stores only basename, size and hash; no archive paths.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat

MAGICS = (
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "empty ZIP archive"),
    (b"PK\x07\x08", "ZIP-spanned archive"),
)
INCOMPLETE = (".crdownload", ".part", ".partial", ".download", ".tmp")


def inspect(path: Path) -> dict[str, object]:
    if path.is_symlink():
        raise ValueError("Refusing symlink input")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Input is not a regular file")
    if info.st_size == 0:
        raise ValueError("File is empty")
    name = path.name
    lowered = name.lower()
    if any(lowered.endswith(ext) for ext in INCOMPLETE):
        raise ValueError("Download appears incomplete; wait for browser to finish")
    # O_NOFOLLOW protects against racing replacement of the filename by a symlink.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as file:
        first = file.read(8)
        # ISO9660 primary volume descriptor identifier sits at byte 32769.
        # This validates a structural marker, NOT Microsoft authenticity.
        file.seek(16 * 2048 + 1)
        pvd_identifier = file.read(5)
        file.seek(0)
        digest = hashlib.sha256()
        total = 0
        for block in iter(lambda: file.read(4 * 1024 * 1024), b""):
            total += len(block)
            digest.update(block)
        final_info = os.fstat(file.fileno())
    if (total != info.st_size or final_info.st_size != info.st_size
            or final_info.st_mtime_ns != info.st_mtime_ns
            or final_info.st_ino != info.st_ino):
        raise ValueError("File changed during hashing; retry on completed download")
    detected = "unknown"
    for magic, label in MAGICS:
        if first.startswith(magic):
            detected = label
            break
    if detected == "unknown" and lowered.endswith(".iso"):
        detected = ("ISO9660 descriptor detected (not authenticated)"
                    if pvd_identifier == b"CD001"
                    else "possible ISO (extension only; signature not authenticated)")
    return {
        "file_basename": name,
        "bytes": total,
        "sha256": digest.hexdigest(),
        "header_format": detected,
        "iso9660_pvd_detected": pvd_identifier == b"CD001",
        "extension": path.suffix.lower(),
        "trust_status": "UNVERIFIED",
        "contents_examined": False,
        "archive_extracted": False,
        "iso_boot_tested": False,
        "note": ("A locally computed SHA256 is NOT proof of Microsoft origin. "
                 "Do not execute included software or attach any sample VM to NAT. "
                 "Archive contents and publisher provenance require separate review."),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file", type=Path, help="Downloaded completed .7z, .zip or .iso file")
    p.add_argument("--report", type=Path, default=None,
                   help="New private JSON report path, default under home")
    args = p.parse_args()
    target = args.file.expanduser().absolute()
    try:
        data = inspect(target)
    except (OSError, ValueError) as exc:
        p.error(type(exc).__name__ + ": " + str(exc))
    if args.report is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path.home() / ("CAPEv2_WindowsMedia_" + timestamp + "_" + str(os.getpid()) + ".json")
    else:
        out = args.report.expanduser().absolute()
    if out.is_symlink() or out.exists():
        p.error("Refusing overwrite/symlink report")
    out.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, sort_keys=True)
        fp.write("\n")
    print("Private media report saved:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
