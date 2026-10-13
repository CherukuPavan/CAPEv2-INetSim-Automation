#!/usr/bin/env python3
"""Command 1/3 host component: prepare a PERSISTENT CAPE tmpfs mount.

On the observed SSL-55 reference the user manually created a 15995-MiB
tmpfs with UID=995,GID=1009 and CAPE became active. These identity and size
values MUST be derived on every new host, not copied from SSL-55.

PLAN: strictly read-only preflight (no paths are created).
APPLY: root + approval + DIFFERENT approved hostname, ONLY on a host with
no existing mounted/fstab/systemd tmpfs definition and stopped CAPE.
Install one systemd mnt-tmpfs.mount unit and a cape.service mount-dependency
drop-in. Mount via systemd; verify mount owner and free-space with the
existing Command 3 tmpfs preflight. No CAPE service starts/restarts, no VMs,
network, samples or snapshots. No automatic destructive cleanup on errors:
partial installation is reported for operator review.

NOTE: reboot-persistence config can be verified offline; an actual reboot
and stable CAPE startup remain separate physical acceptance requirements.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys

import command3_cape_tmpfs as tmpfs
import command3_cape_api_ratelimit as guard

FSTAB = Path("/etc/fstab")
MOUNT_UNIT = Path("/etc/systemd/system/mnt-tmpfs.mount")
SERVICE_DROPIN = Path("/etc/systemd/system/cape.service.d/90-require-tmpfs.conf")
MOUNT_POINT = Path("/mnt/tmpfs")
APPROVAL = "INSTALL-CAPE-PERSISTENT-TMPFS-OTHER-HOST"
MAX_FSTAB = 2 * 1024 * 1024

class ProvisionBlocked(tmpfs.TmpfsBlocked):
    pass

def need(ok, reason):
    if not ok:
        raise ProvisionBlocked(reason)

def approved_host(actual, requested):
    actual = actual.split(".", 1)[0].lower()
    requested = requested.split(".", 1)[0].lower()
    need(actual not in ("ssl-55", "cse-ssl-55") and
         requested == actual and len(actual) > 1,
         "Protected SSL-55 or other/unapproved host")
    return actual

def secure_existing_file(path, max_size):
    path = Path(path)
    need(path.is_absolute(), "Expected absolute host configuration path")
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), "Symlinked host configuration path")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
             and 0 <= st.st_size <= max_size,
             "Unexpected host file type or size")
        data = os.read(fd, max_size + 1)
        need(len(data) == st.st_size, "Host configuration changed during read")
        return data, st
    finally:
        os.close(fd)

def no_mount_definition(fstab):
    try:
        text = fstab.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProvisionBlocked("Invalid UTF8 fstab") from exc
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        need(len(fields) >= 4,
             "Malformed active fstab entry: manual review")
        need(fields[1] != "/mnt/tmpfs",
             "Existing /mnt/tmpfs fstab entry: never duplicate")
    return True

def available_mib():
    """Use kernel-provided host memory data, not VM memory predictions."""
    result = {}
    with open("/proc/meminfo", encoding="ascii") as f:
        for line in f:
            k, _, value = line.partition(":")
            if k in ("MemTotal", "MemAvailable"):
                fields = value.split()
                need(len(fields) == 2 and fields[1] == "kB",
                     "Unrecognized memory info format")
                result[k] = int(fields[0]) // 1024
    need(set(result) == {"MemTotal", "MemAvailable"},
         "Missing actual host RAM evidence")
    return result["MemTotal"], result["MemAvailable"]

def choose_size(total_mib, available, free_threshold):
    need(all(type(x) is int and x > 0
             for x in (total_mib, available, free_threshold)),
         "Invalid host RAM or CAPE tmpfs free-space requirement")
    need(free_threshold >= 1024 and free_threshold <= 16384,
         "Configured CAPE free-space threshold needs custom mount sizing")
    # This is maximum tmpfs logical capacity (not eager allocation).
    # Provide extra room for dumps, with at most 1/4 installed RAM.
    size = min(16384, total_mib // 4)
    need(size >= free_threshold + 1024 and
         available >= free_threshold + 1024 and
         total_mib >= 4 * (free_threshold + 1024),
         "Host RAM not sufficient for reviewed CAPE tmpfs profile")
    return size

def unit_content(uid, gid, size):
    need(all(type(x) is int and x >= 0 for x in (uid, gid, size))
         and 1024 <= size <= 16384,
         "Invalid tmpfs identity or allocated size")
    return (
        "[Unit]\n"
        "Description=CAPE analysis tmpfs mount\n"
        "Before=cape.service\n\n"
        "[Mount]\n"
        "What=tmpfs\n"
        "Where=/mnt/tmpfs\n"
        "Type=tmpfs\n"
        "Options=rw,nodev,nosuid,noexec,mode=0750,"
        "uid=" + str(uid) + ",gid=" + str(gid) +
        ",size=" + str(size) + "M\n\n"
        "[Install]\n"
        "WantedBy=local-fs.target\n"
    ).encode()

def dropin_content():
    return b"[Unit]\nRequiresMountsFor=/mnt/tmpfs\n"

def ensure_install_paths_available():
    need(MOUNT_POINT == tmpfs.EXPECTED,
         "Inconsistent CAPE tmpfs mount path")
    for location in (MOUNT_POINT, *MOUNT_POINT.parents,
                     MOUNT_UNIT, *MOUNT_UNIT.parents,
                     SERVICE_DROPIN, *SERVICE_DROPIN.parents):
        need(not location.is_symlink(),
             "Symlinked mount or systemd unit path is refused")
    need(MOUNT_POINT.parent.is_dir(),
         "Required /mnt mount parent absent")
    need(not MOUNT_UNIT.exists() and not SERVICE_DROPIN.exists(),
         "Pre-existing CAPE tmpfs systemd mount/drop-in; manual review")
    for foreign in (Path("/usr/lib/systemd/system/mnt-tmpfs.mount"),
                    Path("/lib/systemd/system/mnt-tmpfs.mount"),
                    Path("/run/systemd/system/mnt-tmpfs.mount")):
        need(not foreign.exists() and not foreign.is_symlink(),
             "Another systemd mount unit already defines /mnt/tmpfs")
    if MOUNT_POINT.exists():
        need(MOUNT_POINT.is_dir(), "Existing /mnt/tmpfs is not a directory")
        need(not any(MOUNT_POINT.iterdir()),
             "Existing /mnt/tmpfs contains files; do not hide it with a mount")
    need(tmpfs.mount_fstype(MOUNT_POINT) is None,
         "Existing filesystem mounted at /mnt/tmpfs; no replacement")
    need(SERVICE_DROPIN.parent.is_dir() or
         not SERVICE_DROPIN.parent.exists(),
         "Existing CAPE service drop-in folder is not a directory")

def plan(conf, host):
    machine = approved_host(socket.gethostname(), host)
    settings, config_sha = tmpfs.config(conf)
    need(settings["enabled"], "CAPE [tmpfs] is disabled")
    need(settings["path"] == "/mnt/tmpfs",
         "Unsupported CAPE tmpfs path")
    # Verify user/group are independently provisioned on this host.
    uid, gid = tmpfs.cape_ids()
    fstab, fstab_meta = secure_existing_file(FSTAB, MAX_FSTAB)
    no_mount_definition(fstab)
    ensure_install_paths_available()
    total, available = available_mib()
    size = choose_size(total, available, settings["minimum_free_mib"])
    return {
        "result": "CAPE_PERSISTENT_TMPFS_INSTALL_PLAN_ONLY",
        "approved_host": machine,
        "mountpoint": "/mnt/tmpfs", "filesystem": "tmpfs",
        "systemd_mount_unit": str(MOUNT_UNIT),
        "cape_service_mount_dependency": str(SERVICE_DROPIN),
        "total_ram_mib": total, "available_ram_mib": available,
        "configured_free_mib": settings["minimum_free_mib"],
        "chosen_mount_size_mib": size,
        "cape_uid": uid, "cape_gid": gid,
        "expected_unit_sha256": guard.sha(unit_content(uid, gid, size)),
        "expected_dependency_sha256": guard.sha(dropin_content()),
        "cuckoo_conf_sha256": config_sha,
        "fstab_sha256": guard.sha(fstab),
        "fstab_metadata": (fstab_meta.st_dev, fstab_meta.st_ino,
                           fstab_meta.st_size),
        "host_modified": False,
        "cape_service_restarted": False,
        "reboot_persistence_verified": False,
        "requires_reboot_acceptance": True,
    }

def write_new(path, body, mode=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as out:
        out.write(body)
        out.flush()
        os.fsync(out.fileno())

def systemctl(*args):
    need(args in (("daemon-reload",),
                  ("enable", "--now", "mnt-tmpfs.mount")),
         "Unsupported systemctl mount operation")
    subprocess.run(["systemctl", *args], timeout=60, check=True,
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)

def apply(conf, host):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Interactive root operator required")
    first = plan(conf, host)
    print(json.dumps(first, sort_keys=True, indent=2), flush=True)
    need(input("Type " + APPROVAL + " to provision persistent CAPE tmpfs: ")
         == APPROVAL, "Operator refused persistent CAPE tmpfs installation")
    need(plan(conf, host) == first,
         "Host identity, RAM, source or fstab changed before installation")
    # No service can be running; mounting over its analysis path would be
    # a potentially destructive change.
    state = subprocess.run(["systemctl", "is-active", "cape.service"],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL,
                           timeout=8, text=True, check=False)
    need(state.stdout.strip() in ("inactive", "failed", "unknown"),
         "CAPE main service must be stopped before creating its mount")
    uid, gid = first["cape_uid"], first["cape_gid"]
    # We intentionally leave files for operator inspection on any partial
    # failure instead of attempting an unsafe unmount/recursive rollback.
    try:
        MOUNT_POINT.mkdir(mode=0o750, exist_ok=False)
        dropin_dir = SERVICE_DROPIN.parent
        dropin_dir.mkdir(mode=0o755, exist_ok=True)
        need(not dropin_dir.is_symlink(), "Unexpected symlinked drop-in folder")
        write_new(MOUNT_UNIT, unit_content(uid, gid,
                  first["chosen_mount_size_mib"]))
        write_new(SERVICE_DROPIN, dropin_content())
        systemctl("daemon-reload")
        systemctl("enable", "--now", "mnt-tmpfs.mount")
        last = tmpfs.assess(conf)
        need(last.get("cape_tmpfs_prerequisite_ready") is True
             and last.get("filesystem") == "tmpfs",
             "Mounted filesystem failed CAPE ownership/capacity acceptance")
        return {
            "result": "CAPE_PERSISTENT_TMPFS_MOUNT_CONFIGURED_NO_RESTART",
            "configured": True, "mounted": True,
            "owner_verified": True, "available_free_mib": last["free_mib"],
            "fstab_unchanged": True, "cape_service_restarted": False,
            "reboot_persistence_verified": False,
        }
    except (OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, tmpfs.TmpfsBlocked) as exc:
        raise ProvisionBlocked(
            "PARTIAL_OR_UNKNOWN: inspect new mount unit, CAPE drop-in and "
            "mount state; do not blindly retry: " +
            type(exc).__name__) from exc

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--approved-host", required=True)
    parser.add_argument("--cuckoo-conf", type=Path, default=tmpfs.CONF)
    a = parser.parse_args()
    try:
        result = (plan(a.cuckoo_conf, a.approved_host)
                  if a.mode == "plan" else
                  apply(a.cuckoo_conf, a.approved_host))
        print(json.dumps(result, sort_keys=True, indent=2), flush=True)
        return 0
    except (ProvisionBlocked, tmpfs.TmpfsBlocked,
            guard.Command3Blocked, OSError, ValueError) as exc:
        print(json.dumps({
            "result": "CAPE_PERSISTENT_TMPFS_PROVISIONING_BLOCKED",
            "reason": str(exc), "no_cape_service_restart": True,
        }, sort_keys=True), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
