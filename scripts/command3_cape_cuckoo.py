#!/usr/bin/env python3
"""Command 3 Step 3: exact operator-confirmed cuckoo.conf changes.

Crucial deviations from the PDF:
* [resultserver] ip = 0.0.0.0 (operator explicitly rejects 192.168.122.1).
* [cleaner] keys are binaries, tmp, analysis (not *_days).

No database credential is embedded or logged. An already-configured, valid
PostgreSQL URL is retained, or a NEW URL is read from an existing root-private
0600 file (--db-dsn-file). No guest/service/network actions occur here.

Plan is read-only. Apply requires typed authorization, SHA256 recheck,
root-private pre-change backup, same-dir atomic replacement and readback.
Does not certify a safe public interface, free disk, DB availability, actual
CAPE semantics or any service readiness.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib.parse import urlsplit
import uuid

import command3_cape_api_ratelimit as guard

CONF = Path("/opt/CAPEv2/conf/cuckoo.conf")
BACKUPS = guard.DEFAULT_BACKUPS
APPROVAL = "APPLY-CAPE-CUCKOO-22-TARGETS-WILDCARD-RESULTSERVER-ACK"
MAX_DSN_BYTES = 2048

# The user confirmed every AFTER value EXCEPT the image's resultserver IP,
# the three misnamed PDF cleaner fields, and actual database credentials.
# No key is silently created: those three cleaner spellings must already
# exist in the target deployment or the script refuses to guess.
TARGET = {
    "cuckoo": {
        "machinery_screenshots": "on",
        "memory_dump": "on",
        "reschedule": "on",
        "freespace": "0",
        "freespace_processing": "0",
    },
    "resultserver": {
        "ip": "0.0.0.0",
        "store_csvs": "on",
        "upload_max_size": "1000000000",
    },
    "processing": {
        "analysis_size_limit": "1000000000",
    },
    "database": {
        "timeout": "150",
    },
    "timeouts": {
        "default": "300",
        "critical": "300",
        "vm_state": "150",
    },
    "tmpfs": {
        "enabled": "on",
        "freespace": "4096",
    },
    "cleaner": {
        "enabled": "yes",
        "binaries": "0",
        "tmp": "0",
        "analysis": "0",
        "mongo": "yes",
        "unused_files_in_mongodb": "yes",
    },
}
SECTION_RE = guard.API_SECTION
KEY_RE = re.compile(r"^[ \t]*([A-Za-z][A-Za-z_0-9]*)[ \t]*=")
OPTION_RE = re.compile(
    r"^([ \t]*[A-Za-z][A-Za-z_0-9]*[ \t]*=[ \t]*)"
    r"([^#;\r\n]*?)"
    r"([ \t]*(?:[#;][^\r\n]*)?)"
    r"(\r?\n|)$"
)
EXPECTED_COUNT = sum(len(p) for p in TARGET.values()) + 1  # database.connection

class CuckooBlocked(guard.Command3Blocked):
    pass

def need(ok, why):
    if not ok:
        raise CuckooBlocked(why)

def safe_config(path):
    path = Path(path)
    need(path.is_absolute() and path.name == "cuckoo.conf"
         and path.parent.name == "conf",
         "Expected absolute CAPE conf/cuckoo.conf")
    for part in (path, *path.parents):
        need(not part.is_symlink(), "Symlinked CAPE config path blocked")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             0 < st.st_size <= guard.MAX_BYTES and
             not (stat.S_IMODE(st.st_mode) & 0o022),
             "Untrusted cuckoo.conf file or permissions")
        data = os.read(fd, guard.MAX_BYTES + 1)
        need(len(data) == st.st_size, "Configuration changed during read")
        return data, st
    finally:
        os.close(fd)

def safe_dsn(dsn):
    """Accept only the expected local CAPE PostgreSQL endpoint, never log it."""
    try:
        need(type(dsn) is str and len(dsn) < MAX_DSN_BYTES and
             "\n" not in dsn and "\r" not in dsn,
             "Database connection is missing or too long")
        parsed = urlsplit(dsn)
        need(parsed.scheme == "postgresql" and parsed.username == "cape" and
             parsed.password is not None and bool(parsed.password) and
             parsed.hostname == "localhost" and parsed.port == 5432 and
             parsed.path == "/cape" and not parsed.query and
             not parsed.fragment and not any(c.isspace() for c in dsn) and
             "<" not in dsn and ">" not in dsn,
             "Expected configured local PostgreSQL cape DSN, not a placeholder")
    except ValueError as exc:
        raise CuckooBlocked("Invalid local PostgreSQL cape DSN") from exc
    return dsn

def private_dsn_file(path):
    path = Path(path)
    need(path.is_absolute(), "Database secret file path must be absolute")
    for part in (path, *path.parents):
        need(not part.is_symlink(), "Symlinked secret file path blocked")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
             stat.S_IMODE(st.st_mode) == 0o600 and
             st.st_nlink == 1 and 0 < st.st_size <= MAX_DSN_BYTES,
             "Database DSN secret must be a root-owned 0600 regular file")
        data = os.read(fd, MAX_DSN_BYTES + 1)
        need(len(data) == st.st_size, "Database DSN secret changed while reading")
        try:
            decoded = data.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as exc:
            raise CuckooBlocked("Database secret file must be UTF8") from exc
        return safe_dsn(decoded)
    finally:
        os.close(fd)

def transform(data, dsn=None):
    """Conservatively edit only 22 operator-reviewed existing keys."""
    try:
        raw = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CuckooBlocked("Expected UTF8 cuckoo.conf") from exc
    lines = raw.splitlines(keepends=True)
    need(bool(lines), "Empty cuckoo.conf")
    section = None
    occurrences = {name: 0 for name in TARGET}
    found = {}
    for index, line in enumerate(lines):
        heading = SECTION_RE.fullmatch(line.rstrip("\r\n"))
        if heading:
            section = heading.group(1).lower().strip()
            if section in occurrences:
                occurrences[section] += 1
            continue
        if section not in TARGET or line.lstrip().startswith(("#", ";")):
            continue
        possible = KEY_RE.match(line)
        if not possible:
            continue
        key = possible.group(1).lower()
        if section == "cleaner" and key in (
                "binaries_days", "tmp_days", "analysis_days"):
            raise CuckooBlocked(
                "Found PDF-style cleaner *_days option; expected actual "
                "SSL-55 keys binaries, tmp and analysis; STOP for review")
        if key not in TARGET[section] and (section, key) != ("database", "connection"):
            continue
        pair = (section, key)
        need(pair not in found, "Duplicate configured key: [" + section + "] " + key)
        parsed = OPTION_RE.fullmatch(line)
        need(parsed is not None, "Malformed configured option: [" + section + "] " + key)
        found[pair] = (index, parsed, parsed.group(2).strip())
    need(all(x == 1 for x in occurrences.values()),
         "Every target CAPE section must appear exactly once")
    expected = {(section, key) for section, fields in TARGET.items()
                for key in fields} | {("database", "connection")}
    absent = expected - found.keys()
    need(not absent, "Missing reviewed CAPE option(s): " +
         ", ".join("[" + s + "] " + k for s, k in sorted(absent)))
    current_database = found[("database", "connection")][2]
    selected = safe_dsn(dsn) if dsn is not None else safe_dsn(current_database)
    changes = []
    for (section, key), (index, match, actual) in found.items():
        desired = (selected if (section, key) == ("database", "connection")
                   else TARGET[section][key])
        if actual != desired:
            lines[index] = (match.group(1) + desired + match.group(3) + match.group(4))
            changes.append({"section": section, "key": key,
                            "action": "set", "target":
                                "<private-local-postgresql-dsn>" if
                                (section, key) == ("database", "connection")
                                else desired})
    return "".join(lines).encode("utf-8"), sorted(
        changes, key=lambda x: (x["section"], x["key"]))

def plan(path, db_dsn_file=None):
    current, info = safe_config(path)
    dsn = private_dsn_file(db_dsn_file) if db_dsn_file is not None else None
    proposed, changes = transform(current, dsn)
    # Never expose content from database.connection, old or new, in JSON.
    return {
        "result": "COMMAND3_CUCKOO_STEP3_PLAN_ONLY",
        "file": str(path),
        "targets": EXPECTED_COUNT,
        "status": "READY_TO_APPLY" if changes else "ALREADY_CONFIGURED",
        "changes": changes,
        "before_sha256": guard.sha(current),
        "after_sha256": guard.sha(proposed),
        "source_size": info.st_size,
        "database_dsn_from": ("root_private_file" if db_dsn_file else
                              "existing_config_if_valid"),
        "database_password_disclosed": False,
        "resultserver_binds_all_ipv4": True,
        "requires_trusted_firewall_before_service_restart": True,
        "disables_free_space_thresholds": True,
        "enabled_memory_dumps_need_sizing": True,
        "cleaner_zero_retention_must_be_validated": True,
        "tmpfs_existing_mount_and_capacity_must_be_validated": True,
        "service_restarted": False,
        "host_modified": False,
    }

def apply(path, backup_dir, db_dsn_file=None):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Root and direct interactive operator approval required")
    before = plan(path, db_dsn_file)
    if before["status"] == "ALREADY_CONFIGURED":
        return {**before, "result": "COMMAND3_CUCKOO_STEP3_ALREADY_CONFIGURED",
                "applied": False, "backup_created": False}
    print(json.dumps(before, indent=2, sort_keys=True), flush=True)
    need(input("Type " + APPROVAL + " to change cuckoo.conf: ") == APPROVAL,
         "Operator declined guarded cuckoo.conf modifications")
    current, stat_before = safe_config(path)
    dsn = private_dsn_file(db_dsn_file) if db_dsn_file is not None else None
    proposed, changes = transform(current, dsn)
    need(changes and guard.sha(current) == before["before_sha256"]
         and guard.sha(proposed) == before["after_sha256"]
         and stat_before.st_size == before["source_size"],
         "CAPE configuration or database credential changed after approval")
    backups = guard.safe_backup_dir(backup_dir)
    backup = backups / ("cuckoo.conf.before-command3." + uuid.uuid4().hex + ".bak")
    guard.write_exclusive(backup, current)
    dirfd = os.open(backups, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)
    tmp_path = None
    try:
        fd, name = tempfile.mkstemp(prefix=".command3-cuckoo-", dir=str(Path(path).parent))
        tmp_path = Path(name)
        with os.fdopen(fd, "wb") as f:
            f.write(proposed)
            f.flush()
            os.fchmod(f.fileno(), stat.S_IMODE(stat_before.st_mode))
            os.fchown(f.fileno(), stat_before.st_uid, stat_before.st_gid)
            os.fsync(f.fileno())
        reread, now = safe_config(path)
        need((now.st_dev, now.st_ino, now.st_mode, now.st_uid,
              now.st_gid, now.st_size) ==
             (stat_before.st_dev, stat_before.st_ino, stat_before.st_mode,
              stat_before.st_uid, stat_before.st_gid, stat_before.st_size)
             and guard.sha(reread) == guard.sha(current),
             "Concurrent config change detected; preserve backup and STOP")
        os.replace(tmp_path, path)
        tmp_path = None
        dirfd = os.open(Path(path).parent,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        after, _ = safe_config(path)
        need(after == proposed, "Cuckoo config readback mismatch; STOP")
        need(transform(after)[1] == [], "Cuckoo configuration not idempotent")
        return {
            "result": "COMMAND3_CUCKOO_STEP3_APPLIED_NOT_RESTARTED",
            "applied": True, "backup_created": True,
            "backup_path": str(backup), "after_sha256": guard.sha(proposed),
            "changed_keys": [{"section": x["section"], "key": x["key"]}
                             for x in changes],
            "service_restarted": False,
            "postgresql_connection_or_network_runtime_verified": False,
        }
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=("plan", "apply"), default="plan")
    ap.add_argument("--conf", type=Path, default=CONF)
    ap.add_argument("--backup-dir", type=Path, default=BACKUPS)
    ap.add_argument("--db-dsn-file", type=Path,
                    help="Existing root-owned 0600 file containing exact local CAPE PostgreSQL DSN")
    args = ap.parse_args()
    try:
        out = (plan(args.conf, args.db_dsn_file) if args.mode == "plan"
               else apply(args.conf, args.backup_dir, args.db_dsn_file))
        print(json.dumps(out, indent=2, sort_keys=True), flush=True)
        return 0
    except (CuckooBlocked, guard.Command3Blocked, ValueError, OSError) as exc:
        print(json.dumps({
            "result": "COMMAND3_CUCKOO_STEP3_BLOCKED", "reason": str(exc),
            "never_show_or_commit_db_password": True,
            "no_service_restart": True,
        }, sort_keys=True), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
