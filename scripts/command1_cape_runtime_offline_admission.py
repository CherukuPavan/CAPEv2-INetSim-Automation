#!/usr/bin/env python3
"""Read-only CAPE Python wheelhouse integrity admission before any installation.

The wheelhouse + lock come from a separately reviewed, pinned, disposable
build. Validate every byte against an externally approved MANIFEST SHA256.
This module does not download, execute pip, create a venv, install software,
touch libvirt, access Drive or weaken host confinement. Only the read-only
plan is available until the offline runtime install and scoped rollback are
separately physically accepted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,125}\Z")
VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*(?:[a-z0-9.+_-]{0,40})\Z")
WHEEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}\.whl\Z")
MAX_MANIFEST = 1024 * 1024
MAX_LOCK = 2 * 1024 * 1024
MAX_WHEELS = 350
MAX_WHEEL_SIZE = 600 * 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024 * 1024


class AdmissionBlocked(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise AdmissionBlocked(reason)


def read_regular(path, maximum):
    p = Path(path)
    need(p.is_absolute() and not any(x.is_symlink() for x in
                                    (p, *p.parents)),
         "Untrusted path/symlink")
    info = p.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
         0 < info.st_size <= maximum, "Not a supported regular file")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        seen = os.fstat(fd)
        need((seen.st_dev, seen.st_ino, seen.st_size) ==
             (info.st_dev, info.st_ino, info.st_size),
             "File identity changed before verification")
        digest = hashlib.sha256()
        data = bytearray()
        while len(data) < info.st_size:
            part = os.read(fd, min(1024 * 1024, info.st_size - len(data)))
            need(part, "Incomplete read")
            digest.update(part)
            data.extend(part)
        need(os.fstat(fd).st_size == info.st_size,
             "File changed during inspection")
        return bytes(data), digest.hexdigest()
    finally:
        os.close(fd)


def safe_wheel(p, expected_length, expected_sha):
    """Stream wheel SHA256 without buffering hundreds of MB in memory."""
    need(type(expected_length) is int and
         0 < expected_length <= MAX_WHEEL_SIZE and
         type(expected_sha) is str and SHA256.fullmatch(expected_sha),
         "Untrusted package hash/size")
    target = Path(p)
    need(target.is_absolute() and
         not any(x.is_symlink() for x in (target, *target.parents)),
         "Untrusted path/symlink")
    prior = target.lstat()
    need(stat.S_ISREG(prior.st_mode) and prior.st_nlink == 1 and
         prior.st_size == expected_length,
         "Wheel byte count or SHA256 mismatch")
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with os.fdopen(fd, "rb", closefd=True) as src:
            actual_stat = os.fstat(src.fileno())
            need((actual_stat.st_dev, actual_stat.st_ino, actual_stat.st_size) ==
                 (prior.st_dev, prior.st_ino, prior.st_size),
                 "Wheel changed before opening")
            digest = hashlib.sha256()
            remaining = prior.st_size
            while remaining:
                block = src.read(min(1024 * 1024, remaining))
                need(block, "Wheel truncated during SHA256 read")
                digest.update(block)
                remaining -= len(block)
            need(digest.hexdigest() == expected_sha,
                 "Wheel byte count or SHA256 mismatch")
            after = os.fstat(src.fileno())
            need((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) ==
                 (prior.st_dev, prior.st_ino, prior.st_size, prior.st_mtime_ns),
                 "Wheel changed during verification")
            src.seek(0)
            try:
                with zipfile.ZipFile(src, "r") as archive:
                    members = archive.infolist()
                    need(members and len(members) <= 40000,
                         "Unexpected ZIP membership count")
                    uncompressed = 0
                    seen_names = set()
                    for member in members:
                        name = member.filename
                        need(name and not name.startswith(("/", "\\")) and
                             "\\" not in name and "\x00" not in name and
                             all(part not in ("", ".", "..")
                                 for part in name.rstrip("/").split("/")),
                             "Untrusted wheel ZIP member")
                        need(name not in seen_names, "Duplicate ZIP member")
                        seen_names.add(name)
                        # A hash-approved archive can still contain a Unix
                        # symbolic link or a device entry. Do not let an
                        # offline package installer follow such members
                        # outside the dedicated CAPE virtual environment.
                        type_bits = (member.external_attr >> 16) & 0o170000
                        need(type_bits in (0, stat.S_IFREG, stat.S_IFDIR) and
                             not (member.flag_bits & 0x0001),
                             "Unsupported ZIP member type or encryption")
                        if type_bits == stat.S_IFDIR:
                            need(member.is_dir(),
                                 "ZIP declares file path as directory")
                        if type_bits == stat.S_IFREG:
                            need(not member.is_dir(),
                                 "ZIP declares directory as regular file")
                        uncompressed += member.file_size
                        need(uncompressed <= MAX_WHEEL_SIZE * 4,
                             "Oversized wheel expanded data")
            except (zipfile.BadZipFile, ValueError) as exc:
                raise AdmissionBlocked("Damaged or unsafe wheel ZIP") from exc
    except Exception:
        # os.fdopen takes ownership of fd once entered. Never retry or
        # continue installation after a failed hash/ZIP identity check.
        raise
    return expected_sha

def plan(manifest_path, lock_path, wheel_dir, externally_approved_hash,
         min_count=160):
    need(type(externally_approved_hash) is str and
         SHA256.fullmatch(externally_approved_hash),
         "Exact separately approved manifest hash required")
    payload, checksum = read_regular(manifest_path, MAX_MANIFEST)
    need(checksum == externally_approved_hash,
         "Manifest SHA256 not externally approved")
    try:
        metadata = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AdmissionBlocked("Malformed manifest") from exc
    need(type(metadata) is dict and
         metadata.get("source_commit") and
         SHA40.fullmatch(metadata["source_commit"]) and
         metadata.get("platform") == "ubuntu-26.04-amd64" and
         metadata.get("python_version") == "3.12.12" and
         metadata.get("uv_build_version") == "0.9.15" and
         metadata.get("not_an_approved_host_installer") is True,
         "Unexpected runtime provenance/platform profile")
    count = metadata.get("wheel_count")
    rows = metadata.get("wheels")
    need(type(count) is int and min_count <= count <= MAX_WHEELS and
         type(rows) is dict and len(rows) == count,
         "Wrong package count")
    lock_bytes, lock_digest = read_regular(lock_path, MAX_LOCK)
    need(lock_digest == metadata.get("lock_sha256"),
         "Dependency hash lock mismatch")
    home = Path(wheel_dir)
    need(home.is_absolute() and home.is_dir() and
         not any(x.is_symlink() for x in (home, *home.parents)),
         "Wheelhouse directory is not trusted")
    listing = list(home.iterdir())
    need(len(listing) == count, "Unexpected files in wheelhouse")
    actual = {p.name: p for p in listing}
    need(len(actual) == count, "Duplicated wheelhouse names")
    expected_lines = []
    total = 0
    expected_names = set()
    for name, entry in sorted(rows.items()):
        need(type(name) is str and NAME.fullmatch(name) and
             type(entry) is dict and
             type(entry.get("version")) is str and
             VERSION.fullmatch(entry["version"]) and
             type(entry.get("wheel")) is str and
             WHEEL.fullmatch(entry["wheel"]) and
             type(entry.get("size")) is int and
             type(entry.get("sha256")) is str,
             "Malformed wheel identity/version")
        filename = entry["wheel"]
        need(filename not in expected_names and filename in actual,
             "Missing or duplicated referenced wheel")
        expected_names.add(filename)
        safe_wheel(actual[filename], entry["size"], entry["sha256"])
        total += entry["size"]
        need(total <= MAX_TOTAL, "Excess wheelhouse storage")
        expected_lines.append(
            name + "==" + entry["version"] +
            " --hash=sha256:" + entry["sha256"] + "\n")
    need(total == metadata.get("total_wheel_bytes"),
         "Wheelhouse byte total mismatch")
    need(lock_bytes == "".join(expected_lines).encode("utf-8"),
         "Requirements lock does not match manifest")
    return {
        "result": "CAPE_PINNED_PY312_OFFLINE_WHEELHOUSE_VERIFIED",
        "source_sha": metadata["source_commit"],
        "python_version": "3.12.12",
        "target_release": "Ubuntu 26.04 amd64",
        "packages_verified": count,
        "wheel_bytes_verified": total,
        "approved_manifest_sha256": checksum,
        "lock_sha256": lock_digest,
        "host_modified": False,
        "production_installation_executed": False,
        "windows_TPM_snapshot_revert_tested": False,
        "full_three_command_release_approved": False
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest",type=Path,required=True)
    p.add_argument("--lock",type=Path,required=True)
    p.add_argument("--wheelhouse",type=Path,required=True)
    p.add_argument("--approved-manifest-sha256",required=True)
    args = p.parse_args()
    try:
        print(json.dumps(
            plan(args.manifest,args.lock,args.wheelhouse,
                 args.approved_manifest_sha256),
            sort_keys=True,indent=2))
        return 0
    except (AdmissionBlocked, OSError, ValueError, TypeError) as exc:
        print(json.dumps({
            "result":"CAPE_OFFLINE_WHEELHOUSE_ADMISSION_BLOCKED",
            "error_type":type(exc).__name__,
            "host_modified":False
        }),file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
