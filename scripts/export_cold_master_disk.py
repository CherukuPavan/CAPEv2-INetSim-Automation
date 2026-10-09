#!/usr/bin/env python3
"""Read-only preflight or explicitly authorized COLD QCOW2 export.

Creates only an independent, flattened QCOW2 disk; not a ready Windows clone.
Never changes source disks, snapshots, domain XML, networks, or CAPE settings.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

import guard_vm_backing_access as guard

RESERVE = 30 * 1024**3
LOCK_PATH = Path("/run/lock/cape-cold-export.lock")


class ExportError(RuntimeError):
    pass


def cmd(*args: str, timeout: int = 60) -> str:
    try:
        p = subprocess.run(args, capture_output=True, check=True,
                           text=True, timeout=timeout)
        return p.stdout.strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        msg = exc.stderr[:1500] if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
        raise ExportError(f"{args[0]} failed: {msg}") from exc


def virsh(*args: str) -> str:
    return cmd("virsh", "-c", "qemu:///system", *args)


def source_state(vm: str, snapshot: str) -> tuple[str, list[str], int]:
    if not guard.SAFE_VM.fullmatch(vm) or not guard.SAFE_VM.fullmatch(snapshot):
        raise ExportError("VM and snapshot must have safe literal names")
    if virsh("domstate", vm) != "shut off":
        raise ExportError("Master must be shut off before and throughout export")
    if virsh("snapshot-current", vm, "--name") != snapshot:
        raise ExportError("Specified snapshot is not current: do not revert automatically")
    try:
        root = ET.fromstring(virsh("dumpxml", "--inactive", vm))
        snap = ET.fromstring(virsh("snapshot-dumpxml", vm, snapshot))
    except ET.ParseError as exc:
        raise ExportError("Malformed domain/snapshot XML") from exc
    if snap.findtext("./state", "").replace(" ", "").lower() != "shutoff":
        raise ExportError("Selected snapshot is not a shut-off state")
    mem = snap.find("./memory")
    if mem is None or mem.get("snapshot") not in ("no", "none"):
        raise ExportError("Selected snapshot has unknown or saved RAM state")
    disks = root.findall("./devices/disk[@device='disk']")
    if len(disks) != 1 or disks[0].get("type") != "file":
        raise ExportError("Exactly one file-backed QCOW2 disk required")
    src = disks[0].find("source")
    driver = disks[0].find("driver")
    target = disks[0].find("target")
    if (src is None or driver is None or target is None or
            driver.get("type") != "qcow2" or not src.get("file")):
        raise ExportError("Unsupported source disk definition")
    active = src.get("file")
    if not Path(active).is_absolute():
        raise ExportError("Source disk path must be absolute")
    snapshot_disks = snap.findall("./disks/disk")
    expected = [d.find("source") for d in snapshot_disks if
                d.get("name") == target.get("dev") and d.get("snapshot") == "external"]
    if len(expected) != 1 or expected[0] is None or expected[0].get("file") != active:
        raise ExportError("Cold-snapshot disk path differs from persistent VM XML")
    try:
        raw = json.loads(cmd("qemu-img", "info", "--output=json",
                             "--backing-chain", active))
        names = guard.validate_chain(active, raw)
        for name in names:
            guard.check_path(name)
        virtual_size = raw[0].get("virtual-size")
        if not isinstance(virtual_size, int) or virtual_size <= 0:
            raise ExportError("Virtual size unavailable")
        return active, names, virtual_size
    except (guard.GuardError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ExportError(f"Snapshot image validation failed: {exc}") from exc


def fingerprint(paths: list[str]) -> list[tuple[int, int, int, int, int]]:
    result = []
    for name in paths:
        s = os.stat(name)
        if not stat.S_ISREG(s.st_mode):
            raise ExportError("Backing image is not a regular file")
        result.append((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns))
    return result


def check_destination(output: Path, chain: list[str], size: int) -> dict:
    if not output.is_absolute() or ".." in output.parts or not output.name.endswith(".qcow2"):
        raise ExportError("Destination must be an absolute .qcow2 path without '..'")
    if output.exists() or output.is_symlink():
        raise ExportError("Destination already exists; refusing overwrite")
    if str(output) in chain:
        raise ExportError("Destination overlaps with master snapshot chain")
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ExportError("Destination parent directory missing or symlinked")
    for ancestor in (parent, *parent.parents):
        if ancestor.is_symlink():
            raise ExportError("Destination directory tree contains a symlink")
    st = parent.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise ExportError("Destination directory must be root-owned, non-group/world writable")
    available = shutil.disk_usage(parent).free
    required = size + RESERVE
    if available < required:
        raise ExportError(f"Insufficient conservative free space: {available} < {required} bytes")
    return {"available_bytes": available, "conservative_required_bytes": required}


def export(vm: str, snapshot: str, output: Path, dry_run: bool = True) -> dict:
    if os.geteuid() != 0:
        raise ExportError("Run with sudo for read-only source access and secure output")
    if dry_run:
        # Truly observational mode: no runtime lock file, temporary image,
        # or directory creation. The export mode re-checks all invariants.
        top, chain, size = source_state(vm, snapshot)
        meta = check_destination(output, chain, size)
        return {
            "vm": vm, "snapshot": snapshot,
            "top_image": top, "backing_layer_count": len(chain),
            "output": str(output), "virtual_size_bytes": size,
            "destination": meta, "executed": False,
            "warning": "Plan only; Windows identity and static IP are not modified.",
        }
    # Operator supplies a dedicated existing, root-owned directory.
    if LOCK_PATH.is_symlink():
        raise ExportError("Unsafe lock path")
    fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    temp: str | None = None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        top, chain, size = source_state(vm, snapshot)
        meta = check_destination(output, chain, size)
        before = fingerprint(chain)
        info = {
            "vm": vm, "snapshot": snapshot,
            "top_image": top, "backing_layer_count": len(chain),
            "output": str(output), "virtual_size_bytes": size,
            "destination": meta, "executed": False,
            "warning": "Export is an unconfigured disk image: guest identity and static IPv4 are still duplicated.",
        }
        if dry_run:
            return info
        # Never bypass concurrent-QEMU image locks (-U unsafe sharing is banned).
        tmpfd, temp = tempfile.mkstemp(prefix=".cape-export-", suffix=".qcow2",
                                       dir=str(output.parent))
        os.close(tmpfd)
        os.unlink(temp)
        cmd("qemu-img", "convert", "-p", "-f", "qcow2", "-O", "qcow2",
            "-o", "compat=1.1", top, temp, timeout=7200)
        os.chmod(temp, 0o600)
        cmd("qemu-img", "check", "-q", "-f", "qcow2", temp, timeout=3600)
        raw_new = json.loads(cmd("qemu-img", "info", "--output=json", temp))
        if raw_new.get("backing-filename") or raw_new.get("full-backing-filename"):
            raise ExportError("Flattened image unexpectedly retains backing file")
        if raw_new.get("format") != "qcow2" or raw_new.get("virtual-size") != size:
            raise ExportError("Output image format or virtual size mismatch")
        if virsh("domstate", vm) != "shut off" or virsh("snapshot-current", vm, "--name") != snapshot:
            raise ExportError("Master state changed while exporting; output discarded")
        if fingerprint(chain) != before:
            raise ExportError("Source backing chain changed during export; output discarded")
        check_destination(output, chain, size)
        # Hard link is atomic and fails if destination exists; never overwrite.
        os.link(temp, output)
        os.unlink(temp)
        temp = None
        info["executed"] = True
        info["message"] = "New independent cold QCOW2 exported; NOT a defined/bootable analysis clone"
        return info
    finally:
        if temp is not None:
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", default="win11")
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("plan", "export"), default="plan")
    args = parser.parse_args(argv)
    try:
        result = export(args.vm, args.snapshot, args.output, args.mode == "plan")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ExportError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
