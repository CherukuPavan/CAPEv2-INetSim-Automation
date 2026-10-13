#!/usr/bin/env python3
"""Command3 Step4: dynamic CAPE KVM machine registration (NO CAPE restart).

Reference master requested by operator: win11 / 192.168.122.125 /
Afterfull / win11 tag. Extra win11_1..win11_N are discovered from the
ACTUAL Command2 root-private identity journal, saved NAT DHCP reservations
and existing named RUNNING-state snapshots, never PDF's win10/snapshot1
or obsolete speculative cape_ready_win11_N snapshots.

A snapshot existing in libvirt is NOT proof of swtpm2-consistent rollback;
this is config-only staging, not authority to analyze malware. The
default NAT remains Internet-forwarding without independent containment.

PLAN is read-only; APPLY is OTHER-HOST-ONLY, requires typed approval,
root-private backup and atomic configuration update. Never executes
systemctl, starts a VM, changes libvirt/network/TPM or CAPE analysis.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

import command3_cape_api_ratelimit as backup_guard

CONF = Path("/opt/CAPEv2/conf/kvm.conf")
BACKUPS = backup_guard.DEFAULT_BACKUPS
APPROVAL = "APPLY-CAPE-KVM-EXACT-VERIFIED-NAMES-NO-RESTART"
SECT = re.compile(r"^[ \t]*\[([A-Za-z][A-Za-z0-9_.-]{0,90})\][ \t]*(?:[#;][^\r\n]*)?$")
OPTION = re.compile(r"^([ \t]*)([A-Za-z][A-Za-z0-9_]*)([ \t]*=[ \t]*)([^#;\r\n]*?)([ \t]*(?:[#;][^\r\n]*)?)(\r?\n|)$")
VM = re.compile(r"win11_([1-9]|1[0-6])\Z")
VALID_SNAPSHOT = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,90}\Z")
RFC1918 = tuple(ipaddress.IPv4Network(x) for x in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))

class KvmBlocked(RuntimeError):
    pass

def need(ok, text):
    if not ok:
        raise KvmBlocked(text)

def safe_conf(path):
    path = Path(path)
    need(path.is_absolute() and path.name == "kvm.conf" and
         path.parent.name == "conf", "Require exact absolute CAPE conf/kvm.conf")
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), "Symlinked CAPE configuration path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             0 < st.st_size <= backup_guard.MAX_BYTES and
             not (stat.S_IMODE(st.st_mode) & 0o022),
             "Unsafe CAPE kvm.conf file size, type or permissions")
        data = os.read(fd, backup_guard.MAX_BYTES + 1)
        need(len(data) == st.st_size, "CAPE kvm.conf changed during read")
        return data, st
    finally:
        os.close(fd)

def ipaddr(value):
    try:
        need(type(value) is str, "IPv4 address must be a string")
        address = ipaddress.IPv4Address(value)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise KvmBlocked("Invalid machine IPv4 address") from exc
    need(any(address in x for x in RFC1918) and
         address not in (ipaddress.IPv4Address("0.0.0.0"),
                         ipaddress.IPv4Address("255.255.255.255")),
         "Machines and resultserver must use a reviewed private IPv4 address")
    return str(address)

def strict_specs(master_ip, master_snapshot, guests, gateway, tag):
    """Construct exact current machine rows; never guess guest IP/snapshot."""
    need(tag in ("win11", "22H2"), "Choose exactly one tag: win11 or 22H2")
    need(type(guests) is list and len(guests) <= 16,
         "0..16 additional clones supported")
    gateway = ipaddr(gateway)
    master_ip = ipaddr(master_ip)
    need(VALID_SNAPSHOT.fullmatch(master_snapshot or "") is not None,
         "Master snapshot name must be an exact libvirt name")
    need(gateway != master_ip, "Master IP must not equal host gateway")
    all_names = ["win11"]
    all_ips = [master_ip]
    result = [dict(name="win11", ip=master_ip, snapshot=master_snapshot)]
    for i, record in enumerate(guests, 1):
        need(type(record) is dict, "Invalid observed clone record")
        name = "win11_" + str(i)
        snap = "cape_one_nat_" + name
        need(record.get("name") == name and
             record.get("snapshot") == snap,
             "Clone name or snapshot differs from CURRENT Command2 snapshot")
        address = ipaddr(record.get("ip"))
        need(address not in all_ips and address != gateway,
             "Cloned Windows IPv4 conflicts with master/gateway/another VM")
        all_names.append(name)
        all_ips.append(address)
        result.append(dict(name=name, ip=address, snapshot=snap))
    return result, gateway, tag

def section_tree(source):
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KvmBlocked("Non-UTF8 CAPE KVM configuration") from exc
    need(text and "\0" not in text and "\r" not in text.replace("\r\n", ""),
         "Invalid CAPE KVM configuration text")
    segments = [{"name": None, "header": "", "body": []}]
    names = set()
    for line in text.splitlines(keepends=True):
        m = SECT.fullmatch(line.rstrip("\r\n"))
        if m:
            name = m.group(1)
            need(name not in names, "Duplicate existing CAPE section " + name)
            names.add(name)
            segments.append({"name": name, "header": line, "body": []})
        else:
            segments[-1]["body"].append(line)
    need("kvm" in names, "Expected existing [kvm] section")
    eol = "\r\n" if "\r\n" in text else "\n"
    return segments, eol

def existing_option(block, key):
    selected = []
    for index, line in enumerate(block["body"]):
        if line.lstrip().startswith(("#", ";")):
            continue
        if not re.match(r"^[ \t]*" + re.escape(key) + r"[ \t]*=", line,
                        flags=re.IGNORECASE):
            continue
        match = OPTION.fullmatch(line)
        need(match is not None, "Malformed CAPE KVM option " + key)
        selected.append((index, match))
    need(len(selected) <= 1, "Duplicate CAPE KVM option " + key)
    return selected[0] if selected else None

def set_opt(block, key, value, eol):
    match = existing_option(block, key)
    if match is None:
        if block["body"] and not block["body"][-1].endswith(("\n", "\r")):
            block["body"][-1] += eol
        block["body"].append(key + " = " + value + eol)
    else:
        i, parts = match
        current = parts.group(4).strip()
        if current != value:
            block["body"][i] = (parts.group(1) + parts.group(2) +
                                parts.group(3) + value +
                                parts.group(5) + parts.group(6))

def render(existing, master_ip, master_snapshot, guests, gateway, tag="win11"):
    """Pure renderer: one master and N real clones in exactly one machines CSV."""
    desired, gateway, tag = strict_specs(
        master_ip, master_snapshot, guests, gateway, tag)
    pieces, eol = section_tree(existing)
    sections = {x["name"]: x for x in pieces if x["name"] is not None}
    kvm = sections["kvm"]
    m = existing_option(kvm, "machines")
    need(m is not None, "Existing [kvm] machines option missing")
    old_csv = [x.strip() for x in m[1].group(4).strip().split(",")]
    need(old_csv and all(old_csv) and
         len(old_csv) == len(set(old_csv)),
         "Invalid original CAPE machines list")
    need(old_csv == ["cuckoo1"] or
         old_csv == [row["name"] for row in desired[:len(old_csv)]],
         "Unreviewed machine entries; never silently drop existing CAPE VMs")
    if old_csv == ["cuckoo1"]:
        need("cuckoo1" in sections and "win11" not in sections,
             "Legacy placeholder cannot be safely replaced")
        old = sections["cuckoo1"]
        # Only remove the exact inactive legacy sample: the user explicitly
        # requested replacing [cuckoo1] with their actual [win11] master.
        need(any("label = cuckoo1" in x for x in old["body"]),
             "Unrecognized active cuckoo1 definition, manual review")
        pieces.remove(old)
        del sections["cuckoo1"]
    # Pre-existing matching named sections may contain custom attributes;
    # preserve unrelated values, update only operator-reviewed fields.
    wanted = {r["name"] for r in desired}
    need(not any(VM.fullmatch(n or "") and n not in wanted
                 for n in sections),
         "Unexpected extra win11_N CAPE section outside requested VM count")
    set_opt(kvm, "machines", ",".join(r["name"] for r in desired), eol)
    set_opt(kvm, "interface", "virbr0", eol)
    set_opt(kvm, "dsn", "qemu:///system", eol)
    for row in desired:
        name = row["name"]
        if name not in sections:
            section = {"name": name, "header": eol + "[" + name + "]" + eol,
                       "body": []}
            sections[name] = section
            pieces.append(section)
        else:
            section = sections[name]
        attrs = {
            "label": name, "platform": "windows", "ip": row["ip"],
            "tags": tag, "snapshot": row["snapshot"],
            "interface": "virbr0", "resultserver_ip": gateway,
            "arch": "x64", "reserved": "no",
        }
        for key, value in attrs.items():
            set_opt(section, key, value, eol)
    built = "".join(s["header"] + "".join(s["body"]) for s in pieces).encode("utf-8")
    need(built and len(built) <= backup_guard.MAX_BYTES,
         "Generated CAPE KVM configuration too large")
    # Ensure the entire generated document parses with no duplicate
    # managed sections and is already stable on a second application.
    return built, [dict(row, tags=tag, resultserver_ip=gateway) for row in desired]

def find_master_snapshot(master_snapshot):
    # Read-only libvirt evidence. Do not assume operator's name is portable.
    import command2_portable_master_nat_attach as nat
    need(nat.virsh("domstate", "win11").strip().lower() == "shut off",
         "Golden master must be SHUT OFF before CAPE KVM handoff")
    snaps = [x.strip() for x in nat.virsh("snapshot-list", "win11", "--name")
             .splitlines() if x.strip()]
    need(master_snapshot in snaps, "Master snapshot is NOT present in libvirt")
    xml = ET.fromstring(nat.virsh("snapshot-dumpxml", "win11", master_snapshot))
    snap_disks = xml.findall("./disks/disk")
    embedded_domain = xml.find("domain")
    need(xml.tag == "domainsnapshot" and
         xml.findtext("name") == master_snapshot and
         xml.findtext("state") == "running" and
         xml.find("memory") is not None and
         xml.find("memory").get("snapshot") in ("internal", "external") and
         embedded_domain is not None and
         embedded_domain.findtext("name") == "win11" and
         any(d.get("snapshot") in ("internal", "external")
             for d in snap_disks),
         "Golden-master snapshot must contain named win11 RUNNING RAM "
         "and at least one snapshotted Windows disk; STOP otherwise")
    # Metadata only: cannot prove corresponding swtpm state or restore.
    return True

def discover(host, journal, master_snapshot):
    """Read actual host, root-only reservation and libvirt NAT snapshots."""
    import command2_portable_master_nat_attach as nat
    import command2_portable_master_nat_running_snapshots as snapshots
    nat.workflow.canonical_host(host)
    need(os.geteuid() == 0, "Root needed to read private Command2 VM journal")
    journal = Path(journal)
    rows = nat.journal_rows(host, journal)
    report = nat.build(host, journal, True)  # all N off; active+saved NAT reservations
    need(report["count"] == len(rows) and
         report.get("guest_saved_nics_attached") is True and
         report.get("host_nat_dhcp_config_applied") is True,
         "Persistently reserved NAT identities are not verified")
    find_master_snapshot(master_snapshot)
    hosts = report["dhcp_hosts"]
    need(len(hosts) == len(rows), "NAT reservation count differs from guest count")
    clients = []
    for n, (row, item) in enumerate(zip(rows, hosts), 1):
        vm = "win11_" + str(n)
        need(row["libvirt_name"] == vm and
             item["name"] == "WIN11-" + str(n) and
             item["mac"].lower() == row["mac_candidate"].lower(),
             "NAT DHCP guest identity is inconsistent with private journal")
        snapshots.libvirt_snapshot(vm, True)
        snapshots.images(row, True)
        clients.append({"name": vm, "ip": item["ip"],
                        "snapshot": "cape_one_nat_" + vm})
    gateway = nat.profile.check_active_nat()["ipv4"]["gateway"]
    need(report["network"] == "default" and report["bridge"] == "virbr0",
         "CAPE guest NICs must use the verified default / virbr0 NAT")
    need(isinstance(gateway, str) and bool(gateway),
         "Unable to identify verified libvirt NAT gateway")
    return clients, gateway

def plan(conf, host, journal, master_ip, master_snapshot, tag):
    import command2_portable_master_nat_attach as nat
    nat.workflow.canonical_host(host)
    # Plan may run on SSL-55 read-only, never change SSL-55, master or clones.
    original, info = safe_conf(conf)
    guests, gateway = discover(host, journal, master_snapshot)
    proposed, resolved = render(
        original, master_ip, master_snapshot, guests, gateway, tag)
    second, _ = render(proposed, master_ip, master_snapshot, guests, gateway, tag)
    need(second == proposed, "Generated CAPE KVM config is not idempotent")
    network = ipaddress.IPv4Network(gateway + "/24", strict=False)
    need(all(ipaddress.IPv4Address(v["ip"]) in network for v in resolved),
         "A VM IP is outside the verified default NAT gateway subnet")
    return {
        "result": "COMMAND3_KVM_ALL_N_PLAN_ONLY",
        "config": str(conf), "source_sha256": backup_guard.sha(original),
        "target_sha256": backup_guard.sha(proposed),
        "source_size": info.st_size,
        "count": len(resolved), "machines": resolved,
        "master": resolved[0]["name"],
        "clone_count": len(guests),
        "legacy_cuckoo1_replaced": b"[cuckoo1]" in original and
                                   b"[cuckoo1]" not in proposed,
        "existing_sections_other_than_managed_preserved": True,
        "actual_libvirt_running_snapshot_metadata_checked": True,
        "master_guest_ipv4_reverified_inside_windows": False,
        "snapshot_revert_with_swtpm_proven": False,
        "safe_malware_isolation_proven": False,
        "cape_service_restarted": False,
        "host_modified": False,
        "CAPE_READY": False,
    }

def apply(conf, host, journal, master_ip, master_snapshot, tag, backups):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Root and direct operator TTY required for CAPE kvm.conf apply")
    need(socket.gethostname().split(".")[0].lower() != "cse-ssl-55",
         "Protected reference SSL-55 is never an automatic KVM apply target")
    before = plan(conf, host, journal, master_ip, master_snapshot, tag)
    if before["source_sha256"] == before["target_sha256"]:
        return {**before, "result": "COMMAND3_KVM_ALREADY_CONFIGURED",
                "applied": False}
    print(json.dumps(before, indent=2, sort_keys=True), flush=True)
    need(input("Type " + APPROVAL + " for config-only KVM update: ") == APPROVAL,
         "Operator did not authorize CAPE KVM configuration changes")
    latest = plan(conf, host, journal, master_ip, master_snapshot, tag)
    need(latest == before, "VM/snapshot/host configuration changed after approval")
    original, metadata = safe_conf(conf)
    guests, gateway = discover(host, journal, master_snapshot)
    new, _ = render(original, master_ip, master_snapshot, guests, gateway, tag)
    need(backup_guard.sha(original) == before["source_sha256"] and
         backup_guard.sha(new) == before["target_sha256"],
         "KVM configuration or journal changed after approval")
    backups = backup_guard.safe_backup_dir(backups)
    backup = backups / ("kvm.conf.before-command3." + uuid.uuid4().hex + ".bak")
    backup_guard.write_exclusive(backup, original)
    d = os.open(backups, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(d)
    finally: os.close(d)
    temporary = None
    try:
        fd, name = tempfile.mkstemp(prefix=".command3-kvm-", dir=str(Path(conf).parent))
        temporary = Path(name)
        with os.fdopen(fd, "wb") as out:
            out.write(new)
            out.flush()
            os.fchmod(out.fileno(), stat.S_IMODE(metadata.st_mode))
            os.fchown(out.fileno(), metadata.st_uid, metadata.st_gid)
            os.fsync(out.fileno())
        observed, now = safe_conf(conf)
        need(backup_guard.sha(observed) == before["source_sha256"] and
             (now.st_dev, now.st_ino, now.st_uid, now.st_gid,
              now.st_mode, now.st_size) ==
             (metadata.st_dev, metadata.st_ino, metadata.st_uid,
              metadata.st_gid, metadata.st_mode, metadata.st_size),
             "Unexpected concurrent KVM file edit, preserve backup and STOP")
        os.replace(temporary, conf)
        temporary = None
        d = os.open(Path(conf).parent,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(d)
        finally: os.close(d)
        persisted, _ = safe_conf(conf)
        need(persisted == new and
             render(persisted, master_ip, master_snapshot, guests,
                    gateway, tag)[0] == persisted,
             "KVM file readback or idempotence mismatch")
        return {**before,
                "result": "COMMAND3_KVM_ALL_N_CONFIG_ONLY_APPLIED_NOT_STARTED",
                "applied": True, "backup_path": str(backup)}
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--approved-host", required=True)
    parser.add_argument("--journal", required=True, type=Path)
    parser.add_argument("--master-ip", required=True,
                        help="Actual verified master Windows IP; 192.168.122.125 was SSL55")
    parser.add_argument("--master-snapshot", required=True,
                        help="Existing RUNNING-state master snapshot; Afterfull was SSL55")
    parser.add_argument("--tag", choices=("win11", "22H2"), default="win11")
    parser.add_argument("--conf", type=Path, default=CONF)
    parser.add_argument("--backup-dir", type=Path, default=BACKUPS)
    args = parser.parse_args()
    try:
        report = (plan(args.conf, args.approved_host, args.journal,
                       args.master_ip, args.master_snapshot, args.tag)
                  if args.mode == "plan" else
                  apply(args.conf, args.approved_host, args.journal,
                        args.master_ip, args.master_snapshot, args.tag,
                        args.backup_dir))
        print(json.dumps(report, sort_keys=True, indent=2), flush=True)
        return 0
    except (KvmBlocked, ValueError, OSError, TypeError, KeyError,
            ET.ParseError) as exc:
        print(json.dumps({
            "result": "COMMAND3_KVM_REGISTRATION_BLOCKED",
            "reason": str(exc), "CAPE_READY": False,
            "no_service_restart": True,
            "no_guest_or_snapshot_mutation": True}, sort_keys=True),
            file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
