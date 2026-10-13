#!/usr/bin/env python3
"""SSL-55 protected storage pressure audit: READ ONLY; NEVER removes files.

Purpose: determine whether ~45.59 GiB can be reclaimed for the existing
64-GiB Windows golden-master export (current exporter requires virtual
disk size + 30 GiB reserve). Other volumes may need separate storage.

Only preselected aggregate directory labels and capacity/VM metadata
are reported; never enumerate home filenames or output guest/TPM bytes.
Do not suggest deleting libvirt overlays, source images, OVMF, swtpm,
snapshots, CAPE analyses, Postgres/Mongo, private backups or Drive keys.
Potential OS/user caches are *candidates for human review only*.

No chmod, sudo, unlink, rm, apt clean, journalctl vacuum, package changes,
service restarts, guest operations, Google Drive or network access.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

GIB = 1024**3
RESERVE = 30 * GIB
MAX_COMMAND_STDOUT = 128 * 1024

SCOPES = {
    "root_var": "/var",
    "root_home": "/home",
    "root_opt": "/opt",
    "root_usr": "/usr",
    "root_tmp": "/tmp",
    "root_var_tmp": "/var/tmp",
    "libvirt_vm_storage_PROTECTED": "/var/lib/libvirt/images",
    "libvirt_VM_metadata_PROTECTED": "/var/lib/libvirt",
    "CAPE_data_and_code_PROTECTED": "/opt/CAPEv2",
    "database_POSTGRES_PROTECTED": "/var/lib/postgresql",
    "database_MONGO_PROTECTED": "/var/lib/mongodb",
    "system_backup_PROTECTED": "/var/backups",
    "apt_package_cache_REVIEW_ONLY": "/var/cache/apt/archives",
    "journald_logs_REVIEW_ONLY": "/var/log/journal",
    "var_log_REVIEW_ONLY": "/var/log",
    "crash_reports_REVIEW_ONLY": "/var/crash",
    "snap_packages_REVIEW_ONLY": "/var/lib/snapd",
    "docker_data_REVIEW_ONLY": "/var/lib/docker",
    "podman_data_REVIEW_ONLY": "/var/lib/containers",
}
HOME_NAMES = {
    "user_pip_cache_REVIEW_ONLY": ".cache/pip",
    "user_poetry_cache_REVIEW_ONLY": ".cache/pypoetry",
    "user_system_cache_REVIEW_ONLY": ".cache",
    "user_thumbnails_REVIEW_ONLY": ".cache/thumbnails",
    "user_trash_REVIEW_ONLY": ".local/share/Trash",
    "user_downloads_REVIEW_ONLY": "Downloads",
}

class StorageAuditBlocked(RuntimeError):
    pass

def require(condition, message):
    if not condition:
        raise StorageAuditBlocked(message)

def process(args, timeout=90):
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, check=False,
            timeout=timeout,
        )
        return (p.stdout.strip() if p.returncode == 0
                and len(p.stdout) < MAX_COMMAND_STDOUT else None)
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None

def metadata_size(path):
    """GNU du metadata accounting; never follow symlinks or delete anything."""
    p = Path(path)
    if not p.is_dir() or p.is_symlink():
        return {"exists_real_directory": False, "allocated_gib": None}
    raw = process(["du", "-s", "-x", "-B1", "--", str(p)], timeout=100)
    if raw is None:
        return {"exists_real_directory": True, "allocated_gib": None,
                "note": "Metadata size unavailable or timed out"}
    # GNU du emits bytes<TAB>path. Do not output paths or filenames.
    first = raw.split("\t", 1)[0]
    if not re.fullmatch(r"\d{1,18}", first):
        return {"exists_real_directory": True, "allocated_gib": None}
    return {"exists_real_directory": True,
            "allocated_gib": round(int(first)/GIB, 2)}

def mounted_space(path):
    p = Path(path)
    if not p.exists() or p.is_symlink():
        return {"existing_path": False}
    try:
        disk = shutil.disk_usage(p)
        info = os.stat(p, follow_symlinks=False)
        return {"existing_path": True,
                "capacity_gib": round(disk.total/GIB, 2),
                "used_gib": round(disk.used/GIB, 2),
                "free_gib": round(disk.free/GIB, 2),
                "device_id": info.st_dev}
    except OSError:
        return {"existing_path": True, "capacity_unavailable": True}

def correct_user_home():
    user = os.environ.get("SUDO_USER")
    if not user or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        return None
    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        return None
    p = Path(entry.pw_dir)
    if not p.is_absolute() or not p.is_dir() or p.is_symlink():
        return None
    return p

def master_disk():
    """Actual libvirt/QCOW2 metadata only; no guest data/TPM read."""
    info = {"domain": "win11", "master_disk_metadata_available": False}
    state = process(["virsh", "-c", "qemu:///system",
                     "domstate", "win11"], timeout=15)
    info["observed_state"] = (state.strip().lower() if state and
                              len(state)<40 else "unavailable")
    if info["observed_state"] != "shut off":
        return info
    xml = process(["virsh", "-c", "qemu:///system",
                   "dumpxml", "--inactive", "win11"], timeout=20)
    if not xml:
        return info
    try:
        root = ET.fromstring(xml)
        src = root.find("./devices/disk[@device='disk']/source")
        require(root.findtext("name") == "win11" and src is not None,
                "Unexpected source master libvirt XML")
        disk = src.get("file")
        require(bool(disk) and Path(disk).is_absolute(),
                "Missing absolute master image source")
        raw = process(["qemu-img", "info", "--backing-chain",
                       "--output=json", disk], timeout=45)
        if raw is None:
            return info
        parsed = json.loads(raw)
        require(isinstance(parsed, list) and 1 <= len(parsed) <= 16,
                "Unexpected QCOW2 backing chain")
        size = parsed[0].get("virtual-size")
        require(type(size) is int and 8*GIB <= size <= 512*GIB,
                "Unexpected source Windows virtual capacity")
        info.update({
            "master_disk_metadata_available": True,
            "virtual_size_gib": round(size/GIB, 2),
            "backing_chain_layers": len(parsed),
            "existing_exporter_needed_free_gib": round(
                (size + RESERVE)/GIB, 2),
            "original_disk_snapshots_TPM_unmodified": True,
        })
    except (ET.ParseError, json.JSONDecodeError, StorageAuditBlocked,
            ValueError, OSError, TypeError):
        return info
    return info

def directory_scopes(home, size_func=metadata_size):
    result = {}
    for label, path in SCOPES.items():
        result[label] = size_func(path)
    if home is not None:
        for label, subpath in HOME_NAMES.items():
            result[label] = size_func(home/subpath)
    else:
        for label in HOME_NAMES:
            result[label] = {"exists_real_directory": None,
                             "allocated_gib": None,
                             "note": "SUDO_USER home unavailable"}
    return result

def report(*, mount="/var/backups", home=None, scan=True):
    require(os.geteuid() == 0, "Run read-only inventory with sudo")
    require(socket.gethostname().split(".",1)[0].lower() ==
            "cse-ssl-55", "Only intended for the protected SSL-55")
    target = Path(mount)
    require(target.is_absolute() and target.is_dir() and
            not target.is_symlink(), "Expected existing real target filesystem")
    locations = {name: mounted_space(path) for name, path in {
        "export_parent_var_backups": mount,
        "libvirt_windows_storage": "/var/lib/libvirt/images",
        "home_storage": str(home) if home is not None else "/home",
        "temporary_storage": "/tmp",
        "mounted_external_storage_root": "/mnt",
    }.items()}
    windows = master_disk()
    free = locations["export_parent_var_backups"].get("free_gib")
    needed = windows.get("existing_exporter_needed_free_gib")
    gap = (round(max(0,needed-free),2)
           if type(free) in (int,float) and
           type(needed) in (int,float) else None)
    sizes = directory_scopes(home) if scan else {}
    return {
        "result": "SSL55_READONLY_DISK_SPACE_AUDIT_NO_DELETIONS",
        "hostname": "CSE-SSL-55",
        "mounts": locations,
        "source_exact_master": windows,
        "missing_free_space_gib": gap,
        "folder_allocated_sizes": sizes,
        "candidate_data_not_yet_authorized_for_deletion": [
            "apt_package_cache_REVIEW_ONLY",
            "journald_logs_REVIEW_ONLY",
            "user_pip_cache_REVIEW_ONLY",
            "user_poetry_cache_REVIEW_ONLY",
            "user_system_cache_REVIEW_ONLY",
            "user_trash_REVIEW_ONLY",
        ],
        "PROTECTED_DO_NOT_DELETE": [
            "all libvirt VM disks/overlays/backing images and snapshots",
            "Windows original master plus trial and clone disks",
            "OVMF NVRAM and swtpm private state",
            "CAPE analysis reports and configured application",
            "CAPE systemd services and databases",
            "source backups, private crypt rclone credentials",
            "unknown user files including Downloads without inspection",
        ],
        "candidate_cleanup_approved": False,
        "files_deleted": 0, "bytes_deleted": 0,
        "service_or_vm_modified": False,
        "requires_human_review_before_any_cleanup": True,
    }

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--storage-dir", type=Path,
                    default=Path("/var/backups"))
    ap.add_argument("--skip-directory-sizes", action="store_true")
    args = ap.parse_args()
    try:
        output=report(mount=str(args.storage_dir),
                      home=correct_user_home(),
                      scan=not args.skip_directory_sizes)
        print(json.dumps(output, sort_keys=True, indent=2), flush=True)
        return 0
    except Exception as exc:
        print(json.dumps({"result": "DISK_INVENTORY_BLOCKED",
                          "error_type": type(exc).__name__,
                          "files_deleted": 0, "host_modified": False},
                         sort_keys=True), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
