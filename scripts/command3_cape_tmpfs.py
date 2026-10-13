#!/usr/bin/env python3
"""CAPE tmpfs startup prerequisite: bounded read-only preflight + owner repair.

CAPE's [tmpfs] enabled=on requires an actual tmpfs mounted at the exact
configured /mnt/tmpfs path. The CAPE service account must OWN that mounted
root directory and have write/execute permission. A plain chmod/chown of a
non-mounted /mnt/tmpfs would mask an invalid configuration and may write
large memory dumps onto the system disk.

PLAN: read config, check root-directory mount, permissions and free MiB.
REPAIR-OWNER: OTHER HOST ONLY, root interactive typed approval; verify a
live tmpfs mount, fchown ONLY its root directory inode to cape:cape, no
recursion, chmod, mount, fstab or systemd action. Cannot fix missing mounts.
This helper does not persist mount ownership across reboot: that needs
installer-managed tmpfs uid/gid mount options or a mount-aware startup unit.
"""
from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys

import command3_cape_api_ratelimit as guard

CONF = Path("/opt/CAPEv2/conf/cuckoo.conf")
EXPECTED = Path("/mnt/tmpfs")
APPROVAL = "REPAIR-ONLY-MOUNTED-CAPE-TMPFS-OWNERSHIP-NO-RESTART"
KEY = re.compile(r"^[ \t]*([a-z][a-z_0-9]*)[ \t]*=", re.IGNORECASE)

class TmpfsBlocked(guard.Command3Blocked):
    pass

def need(ok, why):
    if not ok:
        raise TmpfsBlocked(why)

def config(path):
    path = Path(path)
    need(path.is_absolute() and path.name == "cuckoo.conf" and
         path.parent.name == "conf",
         "Expected absolute CAPE conf/cuckoo.conf path")
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), "Symlinked cuckoo.conf blocked")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
             and 0 < st.st_size <= guard.MAX_BYTES
             and not (stat.S_IMODE(st.st_mode) & 0o022),
             "Unsafe cuckoo.conf metadata")
        raw = os.read(fd, guard.MAX_BYTES + 1)
        need(len(raw) == st.st_size, "cuckoo.conf changed during read")
    finally:
        os.close(fd)
    return parse_config(raw), guard.sha(raw)

def parse_config(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TmpfsBlocked("Non-UTF8 cuckoo.conf") from exc
    section = None
    seen = set()
    found = {}
    for line in text.splitlines(keepends=True):
        match = guard.API_SECTION.fullmatch(line.rstrip("\r\n"))
        if match:
            section = match.group(1).strip().lower()
            if section == "tmpfs":
                need("tmpfs" not in seen, "Duplicate [tmpfs] section")
                seen.add("tmpfs")
            continue
        if section != "tmpfs" or line.lstrip().startswith(("#", ";")):
            continue
        match = KEY.match(line)
        if match and match.group(1).lower() in ("enabled", "path", "freespace"):
            k = match.group(1).lower()
            need(k not in found, "Duplicate [tmpfs] " + k)
            # Read a strict single option rather than use ConfigParser
            # interpolation or echo unrelated source/secret values.
            m = re.fullmatch(
                r"^[ \t]*[a-z][a-z_0-9]*[ \t]*=[ \t]*"
                r"([^#;\r\n]*?)[ \t]*(?:[#;][^\r\n]*)?(\r?\n|)$",
                line, re.IGNORECASE)
            need(m is not None, "Malformed [tmpfs] " + k)
            found[k] = m.group(1).strip()
    need("tmpfs" in seen and set(found) == {"enabled", "path", "freespace"},
         "Expected one [tmpfs] and its enabled/path/freespace options")
    enabled = found["enabled"].lower()
    need(enabled in ("on", "off"), "Unrecognized tmpfs enabled value")
    configured = found["path"]
    # Fail closed on unexpected storage paths, not overwrite arbitrary dirs.
    need(configured in ("/mnt/tmpfs", "/mnt/tmpfs/"),
         "Unsupported CAPE tmpfs path; manual mount planning required")
    size = found["freespace"]
    need(size.isascii() and size.isdecimal() and len(size) <= 8,
         "Malformed CAPE tmpfs free-space threshold")
    return {"enabled": enabled == "on",
            "path": str(EXPECTED),
            "minimum_free_mib": int(size)}

def mount_fstype(path):
    try:
        result = subprocess.check_output(
            ["findmnt", "--mountpoint", str(path), "-n", "-o", "FSTYPE"],
            stderr=subprocess.DEVNULL, text=True, timeout=8).strip()
    except subprocess.CalledProcessError:
        return None
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise TmpfsBlocked("Unable to check exact tmpfs mountpoint: " +
                           type(exc).__name__) from exc
    need(result in ("tmpfs", ""),
         "Expected tmpfs at configured path; observed " + result)
    return result if result else None

def cape_ids():
    try:
        return pwd.getpwnam("cape").pw_uid, grp.getgrnam("cape").gr_gid
    except KeyError as exc:
        raise TmpfsBlocked("Missing cape system account/group") from exc

def assess(conf=CONF):
    parsed, digest = config(conf)
    response = {
        "result": "CAPE_TMPFS_STARTUP_PREFLIGHT_ONLY",
        "cuckoo_conf_sha256": digest,
        "configured_tmpfs": parsed,
        "host_modified": False,
        "service_restarted": False,
        "ownership_repair_applied": False,
        "mount_persistence_proved": False,
    }
    if not parsed["enabled"]:
        return {**response, "status": "DISABLED_NO_TMPFS_REQUIRED",
                "cape_tmpfs_prerequisite_ready": True, "blocking_issues": []}
    blockers = []
    if EXPECTED.is_symlink() or any(p.is_symlink() for p in EXPECTED.parents):
        raise TmpfsBlocked("Symlinked tmpfs mount path")
    mounted = mount_fstype(EXPECTED)
    if mounted != "tmpfs":
        blockers.append("CAPE tmpfs enabled but /mnt/tmpfs is not a mounted tmpfs; do not chown an unmounted directory")
        return {**response, "status": "BLOCKED_UNMOUNTED",
                "filesystem": mounted,
                "cape_tmpfs_prerequisite_ready": False,
                "blocking_issues": blockers}
    st = os.stat(EXPECTED, follow_symlinks=False)
    need(stat.S_ISDIR(st.st_mode) and st.st_nlink >= 1,
         "Unexpected tmpfs mount-root metadata")
    uid, gid = cape_ids()
    owner = (st.st_uid == uid and st.st_gid == gid)
    writable = bool(stat.S_IMODE(st.st_mode) & 0o300 == 0o300)
    vfs = os.statvfs(EXPECTED)
    free_mib = (vfs.f_bavail * vfs.f_frsize) // (1024 * 1024)
    if not owner:
        blockers.append("Mounted tmpfs root not owned by cape:cape")
    if not writable:
        blockers.append("Mounted tmpfs root not owner writable/traversable")
    if free_mib < parsed["minimum_free_mib"]:
        blockers.append("Mounted tmpfs available space below cuckoo.conf [tmpfs] freespace threshold")
    return {
        **response,
        "status": "READY" if not blockers else "BLOCKED_MOUNT_ACCESS_OR_CAPACITY",
        "filesystem": "tmpfs",
        "owner_is_cape": owner,
        "owner_write_and_execute": writable,
        "free_mib": free_mib,
        "required_free_mib": parsed["minimum_free_mib"],
        "cape_tmpfs_prerequisite_ready": not blockers,
        "blocking_issues": blockers,
    }

def repair_owner(conf=CONF):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Root interactive operator required for tmpfs ownership repair")
    need(socket.gethostname().split(".", 1)[0].lower() not in
         ("ssl-55", "cse-ssl-55"),
         "Reference SSL-55 repairs are operator-manual, not scripted deployments")
    first = assess(conf)
    need(first["configured_tmpfs"]["enabled"] and
         first.get("filesystem") == "tmpfs",
         "Cannot repair missing/disabled/unmounted CAPE tmpfs")
    if first["cape_tmpfs_prerequisite_ready"]:
        return {**first, "result": "CAPE_TMPFS_ALREADY_READY",
                "applied": False}
    need(first.get("owner_is_cape") is False,
         "Not an ownership-only problem; no permissions/capacity repair")
    need(first.get("owner_write_and_execute") is True and
         first.get("free_mib", 0) >= first.get("required_free_mib", 0),
         "Must fix separate mount permissions/capacity before ownership repair")
    print(json.dumps(first, sort_keys=True, indent=2), flush=True)
    need(input("Type " + APPROVAL + " to change ONLY tmpfs mount-root ownership: ")
         == APPROVAL, "Operator denied tmpfs owner repair")
    need(assess(conf) == first,
         "tmpfs mount/cuckoo.conf state changed during operator approval")
    fd = os.open(EXPECTED, os.O_RDONLY | os.O_DIRECTORY |
                 os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        now = os.stat(EXPECTED, follow_symlinks=False)
        need(st.st_dev == now.st_dev and st.st_ino == now.st_ino and
             mount_fstype(EXPECTED) == "tmpfs",
             "tmpfs was swapped/unmounted during repair")
        uid, gid = cape_ids()
        # A mounted directory FD ensures we only affect that inode, not
        # anything underneath or a race-swapped pathname.
        os.fchown(fd, uid, gid)
        after = os.fstat(fd)
        need(after.st_uid == uid and after.st_gid == gid,
             "tmpfs inode ownership verification failed")
    finally:
        os.close(fd)
    verified = assess(conf)
    need(verified["cape_tmpfs_prerequisite_ready"],
         "Mount now owned by cape, but preflight still fails")
    return {**verified, "result": "CAPE_TMPFS_MOUNT_ROOT_OWNER_REPAIRED",
            "applied": True, "host_modified": True,
            "service_restarted": False,
            "mount_persistence_proved": False}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("plan", "repair-owner"), default="plan")
    p.add_argument("--cuckoo-conf", type=Path, default=CONF)
    a = p.parse_args()
    try:
        result = (assess(a.cuckoo_conf) if a.mode == "plan" else
                  repair_owner(a.cuckoo_conf))
        print(json.dumps(result, indent=2, sort_keys=True), flush=True)
        return 0 if result.get("cape_tmpfs_prerequisite_ready") else 2
    except (TmpfsBlocked, guard.Command3Blocked, OSError, ValueError) as exc:
        print(json.dumps({"result": "CAPE_TMPFS_PREFLIGHT_BLOCKED",
                          "reason": str(exc),
                          "no_mount_change": True,
                          "no_service_restart": True},
                         sort_keys=True), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
