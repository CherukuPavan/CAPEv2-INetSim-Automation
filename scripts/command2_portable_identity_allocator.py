#!/usr/bin/env python3
"""Pure Command 2 identity allocation for a new, approved deployment host.

NO host access, libvirt calls, disk writes, VM definitions, networking,
Windows changes or malware. Outputs an ephemeral candidate manifest.
Actual production allocator MUST persist its manifest atomically with an
exclusive lock and revalidate an authoritative host inventory before staging.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import secrets
import sys
import uuid

import command2_portable_fresh_count_plan as count_plan

MAX_ATTEMPTS = 128

class IdentityBlocked(ValueError):
    pass


def require(condition, why):
    if not condition:
        raise IdentityBlocked(why)


def mac_ok(value):
    if not isinstance(value, str):
        return False
    return bool(re.fullmatch(r"52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}", value))


def fresh_mac(existing, random_bytes=None):
    """Locally administered unicast 52:54:00 QEMU MAC; fail on exhaustion."""
    draw = random_bytes or secrets.token_bytes
    for _ in range(MAX_ATTEMPTS):
        raw = draw(3)
        require(isinstance(raw, bytes) and len(raw) == 3,
                "Invalid MAC generator output")
        mac = "52:54:00:" + ":".join(f"{b:02x}" for b in raw)
        if mac not in existing:
            existing.add(mac)
            return mac
    raise IdentityBlocked("MAC uniqueness cannot be established")


def fresh_uuid(existing, generator=None):
    """Secure UUIDv4 candidate, unique in this manifest and known inventory."""
    draw = generator or uuid.uuid4
    for _ in range(MAX_ATTEMPTS):
        value = draw()
        require(isinstance(value, uuid.UUID) and value.version == 4 and
                value.variant == uuid.RFC_4122,
                "Identity generator returned an invalid non-v4 UUID")
        lowered = str(value)
        if lowered not in existing:
            existing.add(lowered)
            return lowered
    raise IdentityBlocked("UUID uniqueness cannot be established")


def allocate(plan, *, existing_uuids=(), existing_macs=(),
             uuid_generator=None, mac_random=None):
    """Convert a *fresh-host* NO-WRITE count plan into per-VM candidate IDs.

    The existing UUID/MAC sets MUST eventually come from complete real host
    and network inventories. The current function never treats a plan as
    authorization for a VM definition or network attachment.
    """
    require(isinstance(plan, dict) and
            plan.get("result") == "PORTABLE_COMMAND2_FRESH_MACHINE_PLAN_ONLY",
            "Untrusted or non-fresh-machine plan")
    require(plan.get("no_vm_created") is True and
            plan.get("deployment_authorized") is False,
            "Planner authorization flags must be non-deploying")
    rows = plan.get("planned_vms")
    total = plan.get("target_vm_total")
    require(type(total) is int and 1 <= total <= count_plan.MAX_COUNT and
            isinstance(rows, list) and len(rows) == total,
            "Invalid VM count/row inventory")
    require(plan.get("capacity_estimate_pass") is True,
            "Conservative storage check failed")
    reserved_uuids = set()
    for value in existing_uuids:
        try:
            normalized = str(uuid.UUID(str(value)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise IdentityBlocked("Invalid existing host UUID inventory") from exc
        require(normalized not in reserved_uuids,
                "Duplicate UUID in existing host inventory")
        reserved_uuids.add(normalized)
    reserved_macs = set()
    for value in existing_macs:
        require(mac_ok(value), "Existing MAC inventory is not normalized")
        require(value not in reserved_macs, "Duplicate MAC in existing host inventory")
        reserved_macs.add(value)
    try:
        subnet = ipaddress.IPv4Network(plan["subnet"], strict=True)
    except (KeyError, ValueError, TypeError) as exc:
        raise IdentityBlocked("Invalid planned network") from exc
    allocations = []
    seen_paths = set()
    seen_ips = set()
    for index, row in enumerate(rows, 1):
        require(isinstance(row, dict), "Malformed VM plan row")
        expected_name = f"win11_{index}"
        expected_hostname = f"WIN11-{index}"
        expected_ip = str(ipaddress.IPv4Address(int(subnet.network_address) + index + 100))
        require(row.get("libvirt_name") == expected_name and
                row.get("hostname") == expected_hostname and
                row.get("planned_ipv4") == expected_ip,
                "Unexpected VM name, hostname or planned IP order")
        require(row.get("new_uuid_required") is True and
                row.get("new_tpm_state_required") is True and
                row.get("new_mac_required") is True and
                row.get("guest_ip_not_yet_assigned") is True,
                "Candidate plan claims an identity or guest IP is already provisioned")
        disk = row.get("disk")
        nvram = row.get("nvram")
        require(isinstance(disk, str) and isinstance(nvram, str) and
                disk.endswith("/" + expected_name + ".command2.qcow2") and
                nvram.endswith("/" + expected_name + ".command2_VARS.fd") and
                disk not in seen_paths and nvram not in seen_paths and disk != nvram,
                "Unexpected/duplicate VM artifact destination")
        seen_paths.update((disk, nvram))
        ip = ipaddress.IPv4Address(expected_ip)
        require(ip in subnet and ip != subnet.broadcast_address and
                expected_ip not in seen_ips,
                "VM IP outside subnet or duplicated")
        seen_ips.add(expected_ip)
        vm_id = fresh_uuid(reserved_uuids, uuid_generator)
        generation_id = fresh_uuid(reserved_uuids, uuid_generator)
        allocations.append({
            "libvirt_name": expected_name,
            "windows_hostname_to_apply": expected_hostname,
            "static_ipv4_to_apply": expected_ip,
            "libvirt_uuid_candidate": vm_id,
            "windows_generation_uuid_candidate": generation_id,
            "mac_candidate": fresh_mac(reserved_macs, mac_random),
            "disk_destination": disk,
            "nvram_destination": nvram,
            "tpm_directory_name_should_match_libvirt_uuid": vm_id,
            "independent_tpm_not_created": True,
            "independent_uefi_vars_not_created": True,
            "windows_ip_not_applied": True,
            "windows_hostname_not_applied": True,
            "nic_attached": False,
            "guest_booted": False,
        })
    return {
        "result": "PORTABLE_COMMAND2_CANDIDATE_IDENTITIES_ONLY",
        "count": total,
        "subnet": str(subnet),
        "allocations": allocations,
        "allocations_persisted": False,
        "host_uuid_mac_inventory_verified": False,
        "guest_changes_performed": False,
        "vm_definitions_written": False,
        "network_connected": False,
        "deployment_authorized": False,
        "restore_verified": False,
        "warning": "Ephemeral candidate preview, not a durable staging manifest",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--free-gib", type=float, required=True)
    parser.add_argument("--disk-dir", required=True)
    parser.add_argument("--nvram-dir", required=True)
    parser.add_argument("--subnet", default="192.168.240.0/24")
    args = parser.parse_args()
    try:
        plan = count_plan.plan_fresh(
            args.count, disk_dir=args.disk_dir, nvram_dir=args.nvram_dir,
            analysis_subnet=args.subnet, free_gib=args.free_gib)
        out = allocate(plan)
        print(json.dumps(out, sort_keys=True, indent=2))
        return 0
    except (IdentityBlocked, count_plan.PortablePlanBlocked) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
