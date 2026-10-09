#!/usr/bin/env python3
"""Offline, non-mutating proposed clone plan from an audited Windows master.

This is NOT a clone executor. It never boots a VM, edits libvirt, writes images,
or changes a Windows guest, CAPE, or networks. Outputs an immutable proposal.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import uuid

VM_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,70}\Z")
GUEST_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,100}\Z")
MAX_CLONES = 32
RESERVE_BYTES = 30 * 1024**3


class InvalidInventory(ValueError):
    pass


def _raise(reason: str) -> None:
    raise InvalidInventory(reason)


def read_inventory(filename: Path) -> dict:
    with filename.open(encoding="utf-8") as fp:
        report = json.load(fp)
    if not isinstance(report, dict) or report.get("schema") not in (
        "cape-master-offline-inventory-v1", "cape-master-vm-inventory-v1"
    ):
        _raise("Unrecognized master inventory schema")
    return report


def inventory_snapshots(inventory: dict) -> list[dict]:
    field = inventory.get("snapshots")
    if not isinstance(field, dict):
        _raise("Missing snapshots")
    snapshots = field.get("items")
    if not isinstance(snapshots, list):
        _raise("Snapshot items unavailable")
    return snapshots


def select_source(inventory: dict, snapshot: str) -> tuple[dict | None, list[str]]:
    issues: list[str] = []
    snapshots = inventory_snapshots(inventory)
    matching = [s for s in snapshots if isinstance(s, dict) and s.get("name") == snapshot]
    if len(matching) != 1:
        issues.append("Requested clone-source snapshot is not uniquely present")
        return None, issues
    snap = matching[0]
    state = str(snap.get("state", "")).lower()
    memory = snap.get("memory")
    if state not in ("shutoff", "shut off"):
        issues.append("Clone source snapshot is not marked as shut off")
    if isinstance(memory, dict):
        mem = memory.get("mode", memory.get("snapshot"))
        if mem not in ("no", "none", None):
            issues.append("Clone source snapshot depends on external/active memory")
    else:
        issues.append("Cannot establish snapshot memory handling")
    if inventory.get("vm", {}).get("state", "").lower() not in ("shut off", "shutoff"):
        issues.append("Master VM was not shut down during inventory")
    if inventory.get("snapshots", {}).get("current") != snapshot:
        issues.append("Selected cold snapshot was not current during inventory")
    disks = snap.get("disks")
    if not isinstance(disks, list) or not any(
        d.get("snapshot") == "external" for d in disks if isinstance(d, dict)
    ):
        issues.append("Cold snapshot does not document an external disk layer")
    return snap, issues


def image_details(inventory: dict, snapshot: dict | None) -> tuple[dict | None, list[str]]:
    issues: list[str] = []
    storage = inventory.get("storage")
    if isinstance(storage, dict):  # newer repo inventory
        entries = list(storage.values())
    elif isinstance(storage, list):  # offline user report
        entries = storage
    else:
        entries = []
    disks = inventory.get("vm", {}).get("disks", [])
    active = [d.get("file") or d.get("source_file")
              for d in disks if isinstance(d, dict) and d.get("device") == "disk"]
    if len(active) != 1 or not active[0]:
        return None, ["Exactly one active QCOW2 disk is required"]
    top = active[0]
    topinfo = [e for e in entries if isinstance(e, dict) and
               (e.get("path") == top or e.get("filename") == top)]
    if len(topinfo) != 1:
        return None, ["No unique inspected backing chain for active disk"]
    layer = topinfo[0]
    chain = layer.get("backing_chain")
    if not isinstance(chain, list) or len(chain) < 2 or len(chain) > 16:
        return None, ["Full QCOW2 backing chain was not recorded"]
    seen: set[str] = set()
    for i, piece in enumerate(chain):
        if not isinstance(piece, dict) or piece.get("format") != "qcow2":
            issues.append("Backing chain has a non-QCOW2 or malformed layer")
            break
        name = piece.get("filename")
        if not isinstance(name, str) or not name.startswith("/") or name in seen:
            issues.append("Backing chain has an invalid, relative, or duplicate image path")
            break
        seen.add(name)
        back = piece.get("backing_filename") or piece.get("full-backing-filename")
        if i < len(chain) - 1 and back != chain[i + 1].get("filename"):
            issues.append("Backing chain link does not match next layer")
        if i == len(chain) - 1 and back:
            issues.append("Backing chain has a missing base image")
    if chain[0].get("filename") != top:
        issues.append("Active disk differs from top backing chain image")
    snapshot_disks = (snapshot or {}).get("disks") or []
    snap_paths = [d.get("source") for d in snapshot_disks
                  if isinstance(d, dict) and d.get("snapshot") == "external"]
    if snap_paths and top not in snap_paths:
        issues.append("Cold snapshot disk path differs from active disk")
    if not snap_paths:
        issues.append("No cold-snapshot disk source could be matched")
    virtual_size = chain[0].get("virtual_size") or chain[0].get("virtual-size")
    if not isinstance(virtual_size, int) or virtual_size <= 0:
        issues.append("Image virtual size is unknown")
    return {"top": top, "layer_count": len(chain),
            "virtual_size_bytes": virtual_size,
            "filesystem_available_bytes": layer.get("filesystem_available_bytes")}, issues


def machine_mapping(inventory: dict) -> dict:
    cape = inventory.get("cape", {})
    entries = cape.get("allowlisted_machine_fields")
    if isinstance(entries, dict):
        return entries
    allowlisted = cape.get("allowlisted_mapping", {})
    return allowlisted.get("sections", {}) if isinstance(allowlisted, dict) else {}


def make_candidates(master: dict, count: int, prefix: str,
                    subnet: str | None, first_ip: str | None,
                    master_ip: str | None, reserved: list[str]) -> tuple[list[dict], list[str]]:
    if count < 1 or count > MAX_CLONES:
        _raise(f"Count must be from 1 to {MAX_CLONES}")
    if not VM_PREFIX.fullmatch(prefix):
        _raise("Invalid prefix: use letters/digits/dot/underscore/hyphen")
    identity = master.get("uuid")
    try:
        namespace = uuid.UUID(identity)
    except (ValueError, TypeError, AttributeError):
        _raise("Missing or malformed master libvirt UUID")
    if subnet is None and first_ip is not None:
        _raise("--first-ip requires --subnet")
    if subnet is not None and first_ip is None:
        _raise("--subnet requires --first-ip")
    network = None
    start = None
    used = set()
    if subnet:
        try:
            network = ipaddress.ip_network(subnet, strict=True)
            start = ipaddress.ip_address(first_ip)
            used = {ipaddress.ip_address(x) for x in reserved}
            if master_ip:
                used.add(ipaddress.ip_address(master_ip))
        except ValueError as exc:
            _raise(f"Invalid IPv4 allocation input: {exc}")
        if network.version != 4 or not isinstance(start, ipaddress.IPv4Address):
            _raise("Only explicit IPv4 allocation is supported")
        if start not in network or start in (network.network_address, network.broadcast_address):
            _raise("First IP is outside usable network addresses")
        if any(addr.version != 4 for addr in used):
            _raise("Reserved addresses must be IPv4")
    candidates: list[dict] = []
    for i in range(1, count + 1):
        name = f"{prefix}{i}"
        if not GUEST_NAME.fullmatch(name):
            _raise(f"Generated guest name invalid: {name}")
        new_uuid = uuid.uuid5(namespace, f"cape-isolated-clone-v1:{name}")
        # Locally-administered unicast MAC, stable within this master namespace.
        mac_bytes = hashlib.sha256(f"{namespace}:{name}".encode()).digest()[:5]
        mac = "02:" + ":".join(f"{b:02x}" for b in mac_bytes)
        item = {
            "name": name, "uuid_proposed": str(new_uuid),
            "mac_proposed": mac, "guest_ipv4_proposed": None,
            "state": "NOT_CREATED", "boot_allowed": False,
            "windows_hostname_customized": False,
            "windows_static_ipv4_customized": False,
            "cape_registered": False,
            "isolated_network_verified": False,
        }
        if network is not None and start is not None:
            current = start + (i - 1)
            if current not in network or current in (network.network_address, network.broadcast_address):
                _raise("Requested addresses exceed usable subnet range")
            if current in used:
                _raise(f"Proposed address collides with reserved/master/CAPE IP: {current}")
            used.add(current)
            item["guest_ipv4_proposed"] = str(current)
        candidates.append(item)
    return candidates, ([] if network is not None else
                        ["Guest IPv4 range is not supplied; no addresses were assigned"])


def generate_plan(inv: dict, count: int, prefix: str = "win11_",
                  network_name: str | None = None, subnet: str | None = None,
                  first_ip: str | None = None, master_ip: str | None = None,
                  reserved: list[str] | None = None,
                  source_snapshot: str = "finalshutoffversion") -> dict:
    blockers: list[str] = []
    warnings: list[str] = []
    vm = inv.get("vm") or {}
    master_name = vm.get("name")
    if master_name is None:
        _raise("Master name missing")
    snap, reasons = select_source(inv, source_snapshot)
    blockers.extend(reasons)
    image, reasons = image_details(inv, snap)
    blockers.extend(reasons)
    cape = machine_mapping(inv)
    cape_reserved: list[str] = []
    for value in cape.values():
        if isinstance(value, dict) and isinstance(value.get("ip"), str):
            cape_reserved.append(value["ip"])
    all_reserved = (reserved or []) + cape_reserved
    candidates, reasons = make_candidates(vm, count, prefix, subnet, first_ip,
                                          master_ip, all_reserved)
    blockers.extend(reasons)
    names = [x["name"] for x in candidates]
    if master_name in names:
        blockers.append("Proposed clone name overlaps with the master VM")
    if any(n in cape for n in names):
        blockers.append("A proposed guest name is already present in CAPE registration")
    if network_name is None:
        blockers.append("No explicit isolated analysis-network name selected")
        network_summary = None
    else:
        matches = [x for x in inv.get("networks", []) if x.get("name") == network_name]
        if len(matches) != 1:
            blockers.append("Target network was not audited on this host")
            network_summary = None
        else:
            network_summary = matches[0]
            if network_summary.get("forward_mode") is not None:
                blockers.append("Selected libvirt network is forwarding/NAT; unsafe for analysis")
            # Static XML/network inspection alone cannot certify isolation.
            blockers.append("Independent guest-origin IPv4/IPv6 egress-isolation tests not evidenced")
    if not cape or master_name not in cape:
        blockers.append("CAPE master registration missing or unreconciled")
    if not vm.get("qemu_guest_agent_channel", vm.get("qemu_guest_agent_channel_configured", False)):
        warnings.append("No QEMU guest agent channel; guest static-IP customization mechanism unverified")
    blockers.append("Windows guest IP and hostname change/verification not yet implemented")
    blockers.append("Source snapshot consistency, TPM/NVRAM cloning and CAPE rollback not independently tested")
    top_disk = image or {}
    free = top_disk.get("filesystem_available_bytes")
    size = top_disk.get("virtual_size_bytes")
    if isinstance(free, int) and isinstance(size, int):
        pessimistic = count * size + RESERVE_BYTES
        if free < pessimistic:
            blockers.append("Insufficient free space under conservative full-virtual-size per-clone estimate")
            warnings.append("Sparse QCOW2 clones may occupy less, but this planner requires a safe bound")
    else:
        blockers.append("Destination filesystem capacity could not be assessed")
    memory = vm.get("memory_kib")
    avail = inv.get("host", {}).get("MemAvailable")
    if not isinstance(memory, int) or not isinstance(avail, int):
        blockers.append("Host memory budget is incomplete")
    else:
        if count * memory > avail * 0.75:
            blockers.append("Planned guest RAM exceeds 75% of currently available host memory")
    if not subnet:
        warnings.append("No network was configured or changed")
    return {
        "schema": "cape-clone-plan-v1",
        "master": master_name,
        "source_snapshot": source_snapshot,
        "source_disk": top_disk.get("top"),
        "source_chain_layers": top_disk.get("layer_count"),
        "count": count,
        "network_selected": network_name,
        "network_inventory": network_summary,
        "ipv4_subnet_proposed": subnet,
        "clone_candidates": candidates,
        "status": "BLOCKED_NOT_DEPLOYABLE" if blockers else "PLANNED_NOT_DEPLOYABLE",
        "blockers": sorted(set(blockers)),
        "warnings": sorted(set(warnings)),
        "operations_performed": "NONE; OFFLINE PLAN ONLY",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prefix", default="win11_")
    parser.add_argument("--network", dest="network_name")
    parser.add_argument("--subnet")
    parser.add_argument("--first-ip")
    parser.add_argument("--master-ip")
    parser.add_argument("--reserved-ip", action="append", default=[])
    parser.add_argument("--source-snapshot", default="finalshutoffversion")
    args = parser.parse_args(argv)
    try:
        report = read_inventory(args.inventory)
        plan = generate_plan(report, args.count, args.prefix,
                             args.network_name, args.subnet,
                             args.first_ip, args.master_ip,
                             args.reserved_ip, args.source_snapshot)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(plan, fp, indent=2, sort_keys=True)
            fp.write("\n")
        print(f"PLAN REPORT: {args.output}")
        print(f"Proposed: {', '.join(vm['name'] for vm in plan['clone_candidates'])}")
        print(f"Deployment status: {plan['status']}; {len(plan['blockers'])} blockers")
        print("No VM created or started; no snapshot/network/host configuration changed.")
        return 0
    except (InvalidInventory, ValueError, TypeError, OSError, json.JSONDecodeError) as exc:
        print(f"PLAN ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
