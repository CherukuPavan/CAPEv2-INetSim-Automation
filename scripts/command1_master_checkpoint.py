#!/usr/bin/env python3
"""Read-only Command 1 final Windows-master checkpoint.

This is not the missing automated Windows installer. It validates that a
host's already-provisioned master can safely be considered as a cold clone
source, and emits a private, portable four-command handoff report.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import sys
import uuid

import audit_clone_master
import plan_vm_clones


def validate_master(inventory: dict) -> dict:
    blockers: list[str] = []
    pending: list[str] = []
    vm = inventory.get("vm", {}) if isinstance(inventory, dict) else {}
    snapinfo = inventory.get("snapshots", {}) if isinstance(inventory, dict) else {}
    current = (snapinfo.get("current") if isinstance(snapinfo, dict) else None) or vm.get("current_snapshot")
    name = vm.get("name")
    master_uuid = vm.get("uuid")
    try:
        uuid.UUID(str(master_uuid))
    except (ValueError, AttributeError):
        blockers.append("Master libvirt UUID is unavailable or invalid")
    if not name or not isinstance(name, str):
        blockers.append("Master VM name is missing")
    if vm.get("state", "").lower() not in ("shut off", "shutoff"):
        blockers.append("Master VM is not shut off")
    selected: dict | None = None
    disk_info: dict | None = None
    if current:
        try:
            selected, reasons = plan_vm_clones.select_source(inventory, current)
            blockers.extend(reasons)
            disk_info, reasons = plan_vm_clones.image_details(inventory, selected)
            blockers.extend(reasons)
        except (plan_vm_clones.InvalidInventory, ValueError, TypeError) as exc:
            blockers.append("Cannot validate snapshot inventory: " + str(exc)[:180])
    else:
        blockers.append("No current named shut-off libvirt snapshot was recorded")
    if isinstance(disk_info, dict):
        if disk_info.get("layer_count", 0) < 2:
            blockers.append("Expected an external snapshot chain with at least 2 layers")
        if not disk_info.get("top"):
            blockers.append("Active source disk path is unknown")
    networks = inventory.get("networks", [])
    if not isinstance(networks, list):
        networks = []
    if not networks:
        pending.append("No libvirt network details in master inventory")
    for net in networks:
        if isinstance(net, dict) and net.get("forward_mode"):
            pending.append(
                "Master network " + str(net.get("name")) +
                " is forwarding; Command 2 needs a distinct verified isolated network"
            )
    pending.extend([
        "CAPE agent GET / and ping passed per operator, not independently attested by this report",
        "Windows guest applications, static IPv4 and required tools cannot be certified by libvirt disk metadata",
        "CAPE machine configuration/restarts/UI belong to Command 3",
        "Actual snapshot rollback and clean Windows clone boot require separate acceptance tests",
        "Source images and swtpm/UEFI state are not cryptographically certified by this report",
    ])
    return {
        "schema": "cape-command1-master-checkpoint-v1",
        "time_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": inventory.get("host", {}).get("hostname"),
        "master": {
            "name": name,
            "uuid": master_uuid,
            "libvirt_state": vm.get("state"),
            "cold_snapshot": current,
            "cold_source_image": disk_info.get("top") if isinstance(disk_info, dict) else None,
            "layer_count": disk_info.get("layer_count") if isinstance(disk_info, dict) else None,
            "guest_ram_kib": vm.get("memory_kib"),
            "vcpus": vm.get("vcpus"),
            "qemu_guest_agent_channel": vm.get("qemu_guest_agent_channel_configured"),
        },
        "stage1_snapshot_structure": "PASS" if not blockers else "BLOCKED",
        "next_command": "2 - guarded, count-driven cloned analysis VMs",
        "blockers": sorted(set(blockers)),
        "pending_acceptance": pending,
        "changes": "NONE; read-only checkpoint",
        "release_status": "DEV_EVIDENCE_ONLY_NOT_COMPLETE_COMMAND1_AUTOMATION",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", default="win11", help="Actual master domain name")
    parser.add_argument("--inventory", type=Path, help="Use a previous audit file offline (may be stale)")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.inventory is not None:
            with args.inventory.open(encoding="utf-8") as f:
                inventory = json.load(f)
        else:
            inventory = audit_clone_master.collect(args.vm)
        if not isinstance(inventory, dict) or inventory.get("schema") not in (
            "cape-master-vm-inventory-v1", "cape-master-offline-inventory-v1"
        ):
            raise ValueError("Unrecognized master audit format")
        if inventory.get("vm", {}).get("name") != args.vm:
            raise ValueError("Master audit name does not match --vm")
        report = validate_master(inventory)
        if args.inventory:
            report["pending_acceptance"].append(
                "Inventory was loaded from file; host state must be rechecked before modifying any VM")
        args.report.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.report, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
        print("Checkpoint report:", args.report)
        print("Structural clone-source check:", report["stage1_snapshot_structure"])
        print("Master and snapshots untouched.")
        return 0 if not report["blockers"] else 2
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print("BLOCKED:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
