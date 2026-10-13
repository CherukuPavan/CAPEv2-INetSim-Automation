#!/usr/bin/env python3
"""Command 3: guarded, narrow CAPE api.conf ratelimit step (development).

Only the operator-confirmed first Step 13.2.1 is implemented. PLAN reads
one named configuration and reports metadata, never content/secrets. APPLY
requires root, interactive approval and a private backup, atomically changes
only [api] ratelimit = yes -> no, and never restarts a service.

IMPORTANT: Disabling API rate limiting should be considered only for a
trusted access-controlled lab, not an Internet-exposed CAPE API. No machine
or network safety is inferred from this configuration step.
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
import tempfile
import uuid

DEFAULT_CONF = Path("/opt/CAPEv2/conf/api.conf")
DEFAULT_BACKUPS = Path("/var/backups/cape-command3")
API_SECTION = re.compile(r"^[ \t]*\[\s*([^\]\r\n]+?)\s*\][ \t]*(?:[;#].*)?$")
RATE_KEY = re.compile(r"^[ \t]*ratelimit[ \t]*=", re.IGNORECASE)
RATE_LINE = re.compile(
    r"^([ \t]*ratelimit[ \t]*=[ \t]*)(yes|no)([ \t]*(?:[;#][^\r\n]*)?)(\r?\n|)$",
    re.IGNORECASE,
)
MAX_BYTES = 1024 * 1024
APPROVAL = "APPLY-CAPE-API-RATELIMIT-NO-TRUSTED-LAB-ONLY"


class Command3Blocked(RuntimeError):
    pass


def need(value, message):
    if not value:
        raise Command3Blocked(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_config(path):
    path = Path(path)
    need(path.is_absolute() and path.name == "api.conf" and
         path.parent.name == "conf",
         "Expected absolute CAPE conf/api.conf file")
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), "Symlinked configuration path blocked")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             0 < st.st_size <= MAX_BYTES and
             not stat.S_IMODE(st.st_mode) & 0o022,
             "Expected bounded non-writable-by-others CAPE configuration")
        data = os.read(fd, MAX_BYTES + 1)
        need(len(data) == st.st_size, "CAPE configuration changed during read")
        return data, st
    finally:
        os.close(fd)


def change(data):
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Command3Blocked("Non-UTF8 CAPE configuration blocked") from exc
    lines = value.splitlines(keepends=True)
    need(lines, "Empty CAPE api.conf")
    in_api = False
    section_count = 0
    indexes = []
    original = None
    for i, line in enumerate(lines):
        section = API_SECTION.fullmatch(line.rstrip("\r\n"))
        if section:
            in_api = section.group(1).strip().lower() == "api"
            section_count += int(in_api)
            continue
        if in_api and RATE_KEY.match(line):
            indexes.append(i)
            matched = RATE_LINE.fullmatch(line)
            need(matched is not None,
                 "Unrecognized [api] ratelimit expression; manual review")
            original = matched.group(2).lower()
    need(section_count == 1 and len(indexes) == 1,
         "Expected exactly one [api] section and one live ratelimit option")
    if original == "no":
        return data, "NO_CHANGE_ALREADY_CONFIGURED"
    need(original == "yes", "Unexpected API rate limit setting")
    index = indexes[0]
    matched = RATE_LINE.fullmatch(lines[index])
    lines[index] = (matched.group(1) + "no" + matched.group(3) +
                    matched.group(4))
    result = "".join(lines).encode("utf-8")
    need(result != data, "Expected exactly one rate-limit change")
    return result, "ONE_SETTING_PENDING"


def plan(path):
    original, st = safe_config(path)
    proposed, status = change(original)
    return {
        "result": "COMMAND3_API_RATELIMIT_PLAN_ONLY",
        "path": str(path),
        "setting": "[api] ratelimit",
        "target": "no",
        "status": status,
        "before_sha256": sha(original),
        "after_sha256": sha(proposed),
        "source_size": st.st_size,
        "backup_required_if_changed": status != "NO_CHANGE_ALREADY_CONFIGURED",
        "requires_private_trusted_api_access": True,
        "unsafe_if_api_exposed_publicly": True,
        "service_restarted": False,
        "host_modified": False,
    }


def safe_backup_dir(path):
    path = Path(path)
    need(path.is_absolute(), "Backup directory must be absolute")
    for part in (path, *path.parents):
        need(not part.is_symlink(), "Symlinked backup directory blocked")
    if not path.exists():
        # Parent must exist; do not recursively create arbitrary hierarchy.
        need(path.parent.is_dir() and not path.parent.is_symlink(),
             "Backup parent directory missing")
        path.mkdir(mode=0o700)
    st = path.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
         stat.S_IMODE(st.st_mode) == 0o700,
         "Backup folder must be root-owned mode 0700")
    return path


def write_exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def apply(conf, backup_dir):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Root interactive terminal required to change CAPE configuration")
    before = plan(conf)
    if before["status"] == "NO_CHANGE_ALREADY_CONFIGURED":
        return {**before, "result": "COMMAND3_API_RATELIMIT_ALREADY_NO",
                "applied": False, "backup_created": False}
    print(json.dumps(before, sort_keys=True, indent=2), flush=True)
    need(input("Type " + APPROVAL + " to modify api.conf: ") == APPROVAL,
         "Operator did not approve disabling API rate limiting")
    original, st = safe_config(conf)
    proposed, status = change(original)
    need(status == "ONE_SETTING_PENDING" and
         sha(original) == before["before_sha256"] and
         sha(proposed) == before["after_sha256"] and
         st.st_size == before["source_size"],
         "Config changed after approval; no update performed")
    backups = safe_backup_dir(backup_dir)
    backup = backups / ("api.conf.before-command3." + uuid.uuid4().hex + ".bak")
    write_exclusive(backup, original)
    dirfd = os.open(backups, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)
    tmp_path = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=".command3-api-", dir=str(conf.parent))
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as target:
            target.write(proposed)
            target.flush()
            os.fchmod(target.fileno(), stat.S_IMODE(st.st_mode))
            os.fchown(target.fileno(), st.st_uid, st.st_gid)
            os.fsync(target.fileno())
        now, latest = safe_config(conf)
        need((latest.st_dev, latest.st_ino, latest.st_mode, latest.st_uid,
              latest.st_gid, latest.st_size) ==
             (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid,
              st.st_size) and sha(now) == sha(original),
             "Source changed since backed-up config; preserve backup, STOP")
        os.replace(tmp_path, conf)
        tmp_path = None
        dirfd = os.open(conf.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        actual, _ = safe_config(conf)
        need(actual == proposed, "Readback mismatch after API rate-limit edit")
        return {
            "result": "COMMAND3_API_RATELIMIT_NO_APPLIED_NOT_RESTARTED",
            "applied": True, "backup_created": True, "backup_path": str(backup),
            "after_sha256": sha(proposed), "service_restarted": False,
            "requires_private_trusted_api_access": True,
        }
    finally:
        if tmp_path is not None and tmp_path.exists():
            # Only remove our same-directory not-yet-published temp file.
            tmp_path.unlink()


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--mode", choices=("plan", "apply"), default="plan")
    cli.add_argument("--conf", type=Path, default=DEFAULT_CONF)
    cli.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUPS)
    args = cli.parse_args()
    try:
        result = (plan(args.conf) if args.mode == "plan" else
                  apply(args.conf, args.backup_dir))
        print(json.dumps(result, sort_keys=True, indent=2), flush=True)
        return 0
    except (Command3Blocked, OSError, ValueError) as exc:
        print(json.dumps({
            "result": "COMMAND3_API_CONFIG_BLOCKED",
            "reason": str(exc), "no_service_restart": True,
            "no_automatic_retry_if_backup_created": True,
        }, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
