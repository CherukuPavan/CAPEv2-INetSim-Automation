#!/usr/bin/env python3
"""Portable Command 2 candidate guest identity blueprint (NO HOST WRITES).

Uses an already checked, read-only target-host preflight result to propose
fresh UUID/MAC/genid values. Candidate values are NOT persistent reservations.
Before *any* VM definition, future deployment must re-enumerate inventory,
lock, reserve identities durably, and revalidate network isolation. No CLI
apply/stage mode is provided here.
"""
from __future__ import annotations

import ipaddress
import re
import secrets
import uuid

class BlueprintBlocked(ValueError):
    """Fail-closed planning error."""

MAX_ATTEMPTS = 32
NAME = re.compile(r"^win11_([1-9][0-9]*)$")
HOST = re.compile(r"^WIN11-([1-9][0-9]*)$")
MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


def need(condition, reason):
    if not condition:
        raise BlueprintBlocked(reason)


def normalized_uuid(value):
    try:
        value = str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise BlueprintBlocked("Malformed libvirt UUID inventory entry") from exc
    return value


def normalized_mac(value):
    need(isinstance(value, str) and bool(MAC.fullmatch(value.lower())),
         "Malformed MAC inventory entry")
    return value.lower()


def allocate_unique_uuid(taken, factory):
    for _ in range(MAX_ATTEMPTS):
        new = normalized_uuid(factory())
        if new not in taken:
            taken.add(new)
            return new
    raise BlueprintBlocked("UUID candidate generation exhausted")


def allocate_unique_mac(taken, entropy):
    for _ in range(MAX_ATTEMPTS):
        raw = entropy(5)
        need(isinstance(raw, bytes) and len(raw) == 5,
             "MAC entropy provider returned malformed bytes")
        # 02 = locally administered, unicast. No real OUI is claimed.
        mac = "02:" + ":".join(f"{x:02x}" for x in raw)
        if mac not in taken:
            taken.add(mac)
            return mac
    raise BlueprintBlocked("MAC candidate generation exhausted")


def blueprint(preflight, *, existing_uuids=(), existing_macs=(),
              uuid_factory=None, entropy=None):
    """Pure candidate planner; does not create/configure any VM or NIC."""
    need(type(preflight) is dict and
         preflight.get("result") == "COMMAND2_READ_ONLY_TARGET_HOST_PREFLIGHT",
         "Required target-host preflight result missing")
    need(preflight.get("preflight_pass") is True,
         "Host discovery blockers must be resolved first")
    need(preflight.get("ssl55_new_vm_prohibited") is False,
         "SSL-55 is a protected reference machine")
    need(preflight.get("host_modified") is False and
         preflight.get("deploy_authorized") is False,
         "Unexpected deploy/write authorization in planning record")
    records = preflight.get("planned_vms")
    count = preflight.get("requested_vm_count")
    try:
        subnet = ipaddress.IPv4Network(preflight.get("analysis_subnet"), strict=True)
    except (ValueError, TypeError, AttributeError) as exc:
        raise BlueprintBlocked("Preflight analysis subnet missing or malformed") from exc
    need(subnet.is_private and subnet.num_addresses >= count + 102,
         "Preflight subnet is inappropriate for guest identity planning")
    need(type(count) is int and 1 <= count <= 16 and
         isinstance(records, list) and len(records) == count,
         "Expected precisely the requested bounded count")
    need(isinstance(existing_uuids, (tuple, list, set)) and
         isinstance(existing_macs, (tuple, list, set)),
         "Complete host UUID/MAC inventory must be supplied")
    taken_uuids = {normalized_uuid(x) for x in existing_uuids}
    taken_macs = {normalized_mac(x) for x in existing_macs}
    gen_uuid = uuid_factory if uuid_factory is not None else uuid.uuid4
    gen_random = entropy if entropy is not None else secrets.token_bytes
    need(callable(gen_uuid) and callable(gen_random),
         "Identity generation providers must be callable")

    names = set()
    paths = set()
    ips = set()
    prepared = []
    for index, item in enumerate(records, start=1):
        need(isinstance(item, dict), "Malformed target VM record")
        name = item.get("libvirt_name")
        hostname = item.get("hostname")
        ip = item.get("planned_ipv4")
        need(name == f"win11_{index}" and hostname == f"WIN11-{index}" and
             isinstance(ip, str) and
             item.get("new_uuid_required") is True and
             item.get("new_mac_required") is True and
             item.get("new_tpm_state_required") is True and
             item.get("guest_ip_not_yet_assigned") is True,
             "VM naming or provenance is not as expected")
        disk, nvram = item.get("disk"), item.get("nvram")
        need(isinstance(disk, str) and isinstance(nvram, str) and
             disk.startswith("/") and nvram.startswith("/") and disk != nvram,
             "Invalid clone disk or UEFI path")
        expected_ip = str(ipaddress.IPv4Address(int(subnet.network_address) + 100 + index))
        need(ip == expected_ip and ipaddress.IPv4Address(ip) in subnet and
             ipaddress.IPv4Address(ip) != subnet.broadcast_address,
             "Unexpected guest IP or wrong analysis subnet")
        need(name not in names and disk not in paths and nvram not in paths
             and ip not in ips, "Duplicated guest name/path/IP")
        names.add(name)
        paths.update((disk, nvram))
        ips.add(ip)
        prepared.append((name, hostname, ip, disk, nvram))
    output = []
    for name, hostname, ip, disk, nvram in prepared:
        output.append({
            "libvirt_name": name,
            "libvirt_uuid_candidate": allocate_unique_uuid(taken_uuids, gen_uuid),
            "smbios_generation_id_candidate": allocate_unique_uuid(taken_uuids, gen_uuid),
            "mac_candidate": allocate_unique_mac(taken_macs, gen_random),
            "windows_hostname_target": hostname,
            "guest_static_ipv4_target": ip,
            "disk_target": disk,
            "uefi_nvram_target": nvram,
            "per_vm_tpm_state_must_be_fresh": True,
            "windows_identity_change_applied": False,
            "static_ipv4_applied": False,
            "nic_attached": False,
            "state_cold_restore_verified": False,
        })
    return {
        "result": "COMMAND2_CANDIDATE_IDENTITIES_ONLY",
        "requested_total": count,
        "candidates": output,
        "identities_reserved": False,
        "guest_personalization_performed": False,
        "network_isolation_verified": False,
        "deploy_authorized": False,
        "created_any_vm": False,
        "next_required": "Revalidate inventory and safely reserve only on another approved target; no SSL-55 staging",
    }
