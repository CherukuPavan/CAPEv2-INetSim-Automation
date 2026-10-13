#!/usr/bin/env python3
"""Command 3 Step 2: fail-closed CAPE auxiliary.conf operator profile.

The operator's SSL-55 [auxiliary_modules] section DOES NOT contain an amsi
line. Insert amsi = yes if absent; update 14 specifically reviewed existing
boolean options, leaving every other section, option and comment unchanged.
No CAPE service restart, guest installation or VM mutation.

Plan is read-only. Apply requires root, a TTY, typed approval, SHA-recheck,
durable root-private backup and atomic same-directory replacement.
This is a development component, not whole Command 3 completion.
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
import uuid

import command3_cape_api_ratelimit as guard

CONF = Path("/opt/CAPEv2/conf/auxiliary.conf")
BACKUPS = guard.DEFAULT_BACKUPS
APPROVAL = "APPLY-CAPE-AUXILIARY-15-SETTINGS-NO-SERVICE-RESTART"
SECTION = "auxiliary_modules"

# Exact operator-supplied 13.2.2 AFTER values. "amsi" is special: absent on
# actual reference machine, so it is ADDED rather than assumed preexisting.
TARGET = {
    "amsi": "yes",
    "curtain": "yes",
    "evtx": "yes",
    "human_linux": "yes",
    "procmon": "yes",
    "recentfiles": "yes",
    "screenshots_windows": "no",
    "screenshots_linux": "no",
    "sysmon_windows": "yes",
    "usage": "yes",
    "file_pickup": "yes",
    "permissions": "yes",
    "pre_script": "yes",
    "during_script": "yes",
    "browsermonitor": "yes",
}
ALLOWED_ADDITION = "amsi"
SECTION_RE = guard.API_SECTION
OPTION_RE = re.compile(
    r"^([ \t]*)([a-zA-Z][a-zA-Z0-9_]*)([ \t]*=[ \t]*)(yes|no)"
    r"([ \t]*(?:[;#][^\r\n]*)?)(\r?\n|)$",
    re.IGNORECASE,
)
POSSIBLE_OPTION_RE = re.compile(
    r"^[ \t]*([a-zA-Z][a-zA-Z0-9_]*)[ \t]*=", re.IGNORECASE,
)

class AuxiliaryBlocked(guard.Command3Blocked):
    pass

def need(test, message):
    if not test:
        raise AuxiliaryBlocked(message)

def safe_config(path):
    path = Path(path)
    need(path.is_absolute() and path.name == "auxiliary.conf"
         and path.parent.name == "conf",
         "Require absolute CAPE conf/auxiliary.conf path")
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), "Symlinked CAPE auxiliary path blocked")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
             and 0 < st.st_size <= guard.MAX_BYTES
             and not (stat.S_IMODE(st.st_mode) & 0o022),
             "Untrusted CAPE auxiliary.conf mode/size/type")
        data = os.read(fd, guard.MAX_BYTES + 1)
        need(len(data) == st.st_size, "Configuration changed while reading")
        return data, st
    finally:
        os.close(fd)

def transform(data):
    """Return changed bytes and only intended modifications."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AuxiliaryBlocked("Non-UTF8 auxiliary.conf blocked") from exc
    lines = text.splitlines(keepends=True)
    need(bool(lines), "Empty auxiliary.conf")
    in_section = False
    section_count = 0
    section_index = None
    found = {}
    changes = []
    for index, line in enumerate(lines):
        heading = SECTION_RE.fullmatch(line.rstrip("\r\n"))
        if heading:
            in_section = heading.group(1).strip().lower() == SECTION
            if in_section:
                section_count += 1
                section_index = index
            continue
        if not in_section or line.lstrip().startswith(("#", ";")):
            continue
        candidate = POSSIBLE_OPTION_RE.match(line)
        if candidate is None:
            continue
        key = candidate.group(1).lower()
        if key not in TARGET:
            continue
        need(key not in found, "Duplicate [auxiliary_modules] key: " + key)
        match = OPTION_RE.fullmatch(line)
        need(match is not None and match.group(2).lower() == key,
             "Unexpected expression for reviewed option: " + key)
        found[key] = (index, match.group(4).lower(), match)
    need(section_count == 1 and section_index is not None,
         "Expected precisely one [auxiliary_modules] section")
    missing = set(TARGET) - set(found)
    need(missing <= {ALLOWED_ADDITION},
         "Missing mandatory auxiliary options: " + ",".join(sorted(missing)))
    for key, (index, old, match) in found.items():
        target = TARGET[key]
        if old != target:
            lines[index] = (
                match.group(1) + match.group(2) + match.group(3) +
                target + match.group(5) + match.group(6))
            changes.append({"key": key, "action": "set", "target": target})
    if ALLOWED_ADDITION not in found:
        # Insert immediately under the unique section header; preserve EOL.
        newline = "\r\n" if "\r\n" in text else "\n"
        if not lines[section_index].endswith(("\n", "\r")):
            lines[section_index] += newline
        lines.insert(section_index + 1, "amsi = yes" + newline)
        changes.append({"key": "amsi", "action": "insert", "target": "yes"})
    return "".join(lines).encode("utf-8"), sorted(
        changes, key=lambda item: item["key"])

def plan(path):
    data, st = safe_config(path)
    proposed, changes = transform(data)
    return {
        "result": "COMMAND3_AUXILIARY_PLAN_ONLY",
        "file": str(path),
        "section": "[" + SECTION + "]",
        "target_count": len(TARGET),
        "target_values": dict(sorted(TARGET.items())),
        "changes": changes,
        "status": "READY_TO_APPLY" if changes else "ALREADY_CONFIGURED",
        "before_sha256": guard.sha(data),
        "after_sha256": guard.sha(proposed),
        "source_size": st.st_size,
        "backup_required": bool(changes),
        "requires_browser_extension_for_browsermonitor": True,
        "requires_guest_module_prerequisite_validation": True,
        "no_service_restart": True,
        "host_modified": False,
    }

def apply(conf, backup_dir):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Root interactive operator required for auxiliary.conf changes")
    before = plan(conf)
    if before["status"] == "ALREADY_CONFIGURED":
        return {**before, "result": "COMMAND3_AUXILIARY_ALREADY_CONFIGURED",
                "applied": False, "backup_created": False}
    print(json.dumps(before, indent=2, sort_keys=True), flush=True)
    need(input("Type " + APPROVAL + " to update auxiliary.conf: ") == APPROVAL,
         "Operator declined Command3 auxiliary profile changes")
    original, st = safe_config(conf)
    proposed, changes = transform(original)
    need(bool(changes) and guard.sha(original) == before["before_sha256"]
         and guard.sha(proposed) == before["after_sha256"]
         and st.st_size == before["source_size"],
         "Configuration changed after operator approval; no write")
    backups = guard.safe_backup_dir(backup_dir)
    backup = backups / ("auxiliary.conf.before-command3." + uuid.uuid4().hex + ".bak")
    guard.write_exclusive(backup, original)
    dirfd = os.open(backups, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)
    tmp_path = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".command3-aux-", dir=str(Path(conf).parent))
        tmp_path = Path(tmp)
        with os.fdopen(fd, "wb") as target:
            target.write(proposed)
            target.flush()
            os.fchmod(target.fileno(), stat.S_IMODE(st.st_mode))
            os.fchown(target.fileno(), st.st_uid, st.st_gid)
            os.fsync(target.fileno())
        actual, current = safe_config(conf)
        need(guard.sha(actual) == guard.sha(original) and
             (current.st_dev, current.st_ino, current.st_mode,
              current.st_uid, current.st_gid, current.st_size) ==
             (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size),
             "CAPE auxiliary.conf changed after backup; preserve evidence, STOP")
        os.replace(tmp_path, conf)
        tmp_path = None
        fd = os.open(Path(conf).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        observed, _ = safe_config(conf)
        need(observed == proposed, "Auxiliary configuration readback mismatch")
        need(transform(observed)[1] == [], "Auxiliary profile not idempotent")
        return {
            "result": "COMMAND3_AUXILIARY_15_TARGETS_APPLIED_NOT_RESTARTED",
            "applied": True, "backup_created": True,
            "backup_path": str(backup),
            "after_sha256": guard.sha(proposed),
            "changed_keys": [item["key"] for item in changes],
            "service_restarted": False,
            "guest_module_prerequisites_verified": False,
        }
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--conf", type=Path, default=CONF)
    parser.add_argument("--backup-dir", type=Path, default=BACKUPS)
    args = parser.parse_args()
    try:
        result = (plan(args.conf) if args.mode == "plan" else
                  apply(args.conf, args.backup_dir))
        print(json.dumps(result, sort_keys=True, indent=2), flush=True)
        return 0
    except (AuxiliaryBlocked, guard.Command3Blocked, ValueError, OSError) as exc:
        print(json.dumps({
            "result": "COMMAND3_AUXILIARY_BLOCKED", "reason": str(exc),
            "no_service_restart": True,
            "no_auto_retry_after_backup_creation": True,
        }, sort_keys=True), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
