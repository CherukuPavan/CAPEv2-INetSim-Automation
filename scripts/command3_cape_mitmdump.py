#!/usr/bin/env python3
"""Command 3 Step 5: exactly one host entry in CAPE mitmdump.conf.

SSL-55 operator target: host = 192.168.122.1. On other approved hosts,
derive the correct IPv4 from the live AND persistent default/virbr0 libvirt
NAT configuration instead of hardcoding SSL-55's gateway.

Read-only plan and root/TTY/typed-approved apply. Fail on absent, duplicate,
malformed or symlinked input. Protect every other setting/comment, make a
root-private backup and atomic change; never start/stop services or VMs.
No evidence of INetSim containment or MITM service reachability is implied.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

import command3_cape_api_ratelimit as guard

CONF = Path("/opt/CAPEv2/conf/mitmdump.conf")
BACKUPS = guard.DEFAULT_BACKUPS
APPROVAL = "APPLY-CAPE-MITMDUMP-HOST-VERIFIED-NAT-NO-RESTART"
KEY = re.compile(r"^[ \t]*host[ \t]*=", re.IGNORECASE)
LINE = re.compile(
    r"^([ \t]*host[ \t]*=[ \t]*)([^#;\r\n]*?)"
    r"([ \t]*(?:[#;][^\r\n]*)?)(\r?\n|)$", re.IGNORECASE,
)
SECTION = guard.API_SECTION


class MitmdumpBlocked(guard.Command3Blocked):
    pass


def need(cond, reason):
    if not cond:
        raise MitmdumpBlocked(reason)


def private_ipv4(value):
    try:
        need(type(value) is str, "Expected verified gateway IPv4")
        ip = ipaddress.IPv4Address(value)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise MitmdumpBlocked("Invalid NAT gateway IPv4") from exc
    private_networks = tuple(ipaddress.IPv4Network(r) for r in
                             ("10.0.0.0/8", "172.16.0.0/12",
                              "192.168.0.0/16"))
    need(any(ip in net for net in private_networks) and
         not ip.is_unspecified and not ip.is_multicast and
         str(ip) == value,
         "NAT gateway must be canonical RFC1918 private unicast IPv4")
    return value


def verified_gateway():
    """Check actual host NAT; do NOT use the pre-snapshot guest attach gate."""
    import command2_portable_master_nat_attach as nat
    live, views = nat.check_network_references()
    need(live.get("nat_network") == "default" and
         live.get("bridge") == "virbr0" and len(views) == 2,
         "Expected approved live and persistent default/virbr0 NAT")
    persistent = nat.profile.ref.nat_details(
        ET.tostring(views[1], encoding="unicode"))
    live_ip = live["ipv4"]
    need(persistent["ipv4"] == live_ip and
         persistent["dynamic_dhcp_ranges"] ==
         live["dynamic_dhcp_ranges"],
         "Host NAT live and persistent networks differ")
    gw = private_ipv4(live_ip["gateway"])
    net = ipaddress.IPv4Network(live_ip["subnet"], strict=True)
    need(net.prefixlen == 24 and
         ipaddress.IPv4Address(gw) in net and
         int(ipaddress.IPv4Address(gw)) == int(net.network_address) + 1,
         "Unexpected default NAT /24 gateway or subnet")
    return gw


def safe_config(path):
    path = Path(path)
    need(path.is_absolute() and path.name == "mitmdump.conf"
         and path.parent.name == "conf",
         "Require absolute CAPE conf/mitmdump.conf")
    for part in (path, *path.parents):
        need(not part.is_symlink(), "Symlinked CAPE path blocked")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and
             0 < meta.st_size <= guard.MAX_BYTES and
             not (stat.S_IMODE(meta.st_mode) & 0o022),
             "CAPE mitmdump.conf must be regular, bounded and not writable by others")
        data = os.read(fd, guard.MAX_BYTES + 1)
        need(len(data) == meta.st_size, "mitmdump.conf changed during read")
        return data, meta
    finally:
        os.close(fd)


def transform(source, gateway):
    gateway = private_ipv4(gateway)
    try:
        data = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MitmdumpBlocked("Non-UTF8 mitmdump.conf blocked") from exc
    need(data and "\0" not in data and "\r" not in data.replace("\r\n", ""),
         "Invalid mitmdump.conf text encoding/line endings")
    lines = data.splitlines(keepends=True)
    positions = []
    for i, line in enumerate(lines):
        if line.lstrip().startswith(("#", ";")):
            continue
        if KEY.match(line):
            m = LINE.fullmatch(line)
            need(m is not None, "Malformed active mitmdump host option")
            value = m.group(2).strip()
            need(value and "\x00" not in value and
                 (value.lower() == "localhost" or
                  len(value) <= 255 and re.fullmatch(
                      r"[A-Za-z0-9_.:-]+", value) is not None),
                 "Unexpected existing mitmdump host value: manual review required")
            positions.append((i, m, value))
    need(len(positions) == 1,
         "Expected exactly one active host = entry in mitmdump.conf")
    i, m, old = positions[0]
    if old == gateway:
        return source, []
    lines[i] = m.group(1) + gateway + m.group(3) + m.group(4)
    return "".join(lines).encode("utf-8"), [{"key": "host", "target": gateway}]


def plan(path, gateway=None):
    current, meta = safe_config(path)
    actual = verified_gateway()
    if gateway is not None:
        need(private_ipv4(gateway) == actual,
             "Requested mitmdump host does not match verified NAT gateway")
    proposed, changes = transform(current, actual)
    return {
        "result": "COMMAND3_MITMDUMP_STEP5_PLAN_ONLY",
        "config": str(path), "setting": "host",
        "target": actual,
        "status": "READY_TO_APPLY" if changes else "ALREADY_CONFIGURED",
        "changes": changes,
        "before_sha256": guard.sha(current),
        "after_sha256": guard.sha(proposed),
        "source_size": meta.st_size,
        "other_config_entries_preserved": True,
        "host_nat_verified_readonly": True,
        "service_restarted": False,
        "network_isolation_verified": False,
        "host_modified": False,
    }


def apply(path, backup_dir, gateway=None):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Direct root operator TTY required")
    import socket
    need(socket.gethostname().split(".", 1)[0].lower() not in
         ("ssl-55", "cse-ssl-55"),
         "Protected SSL-55 must not receive an automated re-apply")
    first = plan(path, gateway)
    if first["status"] == "ALREADY_CONFIGURED":
        return {**first, "result": "COMMAND3_MITMDUMP_ALREADY_CONFIGURED",
                "applied": False, "backup_created": False}
    print(json.dumps(first, indent=2, sort_keys=True), flush=True)
    need(input("Type " + APPROVAL + " to update mitmdump.conf: ") ==
         APPROVAL, "Operator declined mitmdump host configuration")
    # Prevent no-op plan from being used as change authority after NAT drift.
    need(plan(path, gateway) == first,
         "mitmdump or gateway changed since approval; no file write")
    before, meta = safe_config(path)
    after, changes = transform(before, first["target"])
    need(bool(changes) and
         guard.sha(before) == first["before_sha256"] and
         guard.sha(after) == first["after_sha256"] and
         meta.st_size == first["source_size"],
         "Configuration changed after approval; STOP")
    backup_path = guard.safe_backup_dir(backup_dir)
    backup = backup_path / ("mitmdump.conf.before-command3." +
                            uuid.uuid4().hex + ".bak")
    guard.write_exclusive(backup, before)
    dirfd = os.open(backup_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)
    pending = None
    try:
        fd, new_path = tempfile.mkstemp(prefix=".command3-mitmdump-",
                                         dir=str(Path(path).parent))
        pending = Path(new_path)
        with os.fdopen(fd, "wb") as out:
            out.write(after)
            out.flush()
            os.fchmod(out.fileno(), stat.S_IMODE(meta.st_mode))
            os.fchown(out.fileno(), meta.st_uid, meta.st_gid)
            os.fsync(out.fileno())
        current, new_meta = safe_config(path)
        need((new_meta.st_dev, new_meta.st_ino, new_meta.st_mode,
              new_meta.st_uid, new_meta.st_gid, new_meta.st_size) ==
             (meta.st_dev, meta.st_ino, meta.st_mode,
              meta.st_uid, meta.st_gid, meta.st_size) and
             guard.sha(current) == guard.sha(before) and
             verified_gateway() == first["target"],
             "Concurrent file or NAT change detected; preserve backup, STOP")
        os.replace(pending, path)
        pending = None
        dirfd = os.open(Path(path).parent,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        persisted, _ = safe_config(path)
        need(persisted == after and transform(persisted, first["target"])[1] == [],
             "mitmdump.conf readback or idempotence mismatch")
        return {**first, "result": "COMMAND3_MITMDUMP_STEP5_APPLIED_NO_RESTART",
                "applied": True, "backup_created": True,
                "backup_path": str(backup), "service_restarted": False,
                "host_modified": True}
    finally:
        if pending is not None and pending.exists():
            pending.unlink()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("plan", "apply"), default="plan")
    p.add_argument("--conf", type=Path, default=CONF)
    p.add_argument("--backup-dir", type=Path, default=BACKUPS)
    p.add_argument("--gateway", help="Optional exact NAT IPv4 assertion; cannot override discovered gateway")
    args = p.parse_args()
    try:
        value = (plan(args.conf, args.gateway) if args.mode == "plan" else
                 apply(args.conf, args.backup_dir, args.gateway))
        print(json.dumps(value, sort_keys=True, indent=2), flush=True)
        return 0
    except (MitmdumpBlocked, guard.Command3Blocked, ValueError, OSError,
            KeyError, ET.ParseError) as exc:
        print(json.dumps({"result": "COMMAND3_MITMDUMP_BLOCKED",
                          "reason": str(exc),
                          "no_auto_service_restart": True,
                          "no_guest_mutation": True}, sort_keys=True),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
