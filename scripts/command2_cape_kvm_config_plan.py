#!/usr/bin/env python3
"""PURE CAPE KVM machinery configuration for N isolated Windows 11 VMs.

No CAPE file edits, systemctl, network, libvirt, snapshots or VM actions.
The snapshot field is a CANDIDATE, not proof snapshot exists/works.
CLI accepts an existing private candidate reservation JSON, not host
provisioning authority; do not point CAPE at these guests before acceptance.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
import uuid

RFC1918 = [ipaddress.IPv4Network(x) for x in
           ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")]
MAX = 16


class CapeConfigBlocked(ValueError):
    pass


def require(test, msg):
    if not test:
        raise CapeConfigBlocked(msg)


def create_cape_kvm_conf(reservation, subnet="192.168.240.0/24"):
    """Generate standalone kvm.conf proposal without modifying CAPE."""
    require(type(reservation) is dict and
            reservation.get("format") == "CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION" and
            reservation.get("state") == "CANDIDATES_RECORDED_NOT_APPLIED" and
            reservation.get("provisioning_started") is False and
            reservation.get("libvirt_domains_created") is False and
            reservation.get("host_network_modified") is False,
            "Unapproved/modified identity reservation")
    rows = reservation.get("entries")
    require(type(rows) is list and type(reservation.get("guest_count")) is int and
            len(rows) == reservation["guest_count"] and 1 <= len(rows) <= MAX,
            "Reservation count must be 1..16")
    try:
        block = ipaddress.IPv4Network(subnet, strict=True)
    except (TypeError, ValueError) as exc:
        raise CapeConfigBlocked("Invalid reserved private /24") from exc
    require(block.prefixlen == 24 and
            any(block.subnet_of(x) for x in RFC1918) and
            str(block) != "192.168.122.0/24",
            "Unreviewed non-RFC1918/non-/24 or default-NAT subnet")
    names = []
    ip_set, mac_set, uuid_set = set(), set(), set()
    sections = []
    for number, item in enumerate(rows, 1):
        require(type(item) is dict, "Malformed candidate entry")
        name = f"win11_{number}"
        host = f"WIN11-{number}"
        ip = str(ipaddress.IPv4Address(int(block.network_address)+100+number))
        require(item.get("libvirt_name") == name and
                item.get("windows_hostname_target") == host and
                item.get("guest_static_ipv4_target") == ip,
                "CAPE guest names/hostnames/IPs differ from reserved order")
        mac = item.get("mac_candidate")
        ident = item.get("libvirt_uuid_candidate")
        require(type(mac) is str and re.fullmatch(
            r"02:(?:[0-9a-f]{2}:){4}[0-9a-f]{2}",mac) is not None and
            mac not in mac_set and ip not in ip_set,
            "Invalid/duplicate MAC or IP")
        try:
            canonical = str(uuid.UUID(ident))
        except (TypeError, ValueError, AttributeError) as exc:
            raise CapeConfigBlocked("Malformed libvirt UUID") from exc
        require(canonical == ident and canonical not in uuid_set,
                "Duplicate/noncanonical VM UUID")
        mac_set.add(mac); ip_set.add(ip); uuid_set.add(canonical)
        names.append(name)
        sections.append(
            f"[{name}]\n"
            f"label = {name}\n"
            "platform = windows\n"
            f"ip = {ip}\n"
            "arch = x64\n"
            "tags = win11\n"
            f"snapshot = cape_ready_{name}\n"
            "interface = cape-lab0\n"
        )
    conf = (
        "# COMMAND2 PROPOSAL ONLY - NEVER INSTALL WITHOUT ACCEPTANCE\n"
        "# Snapshot names are future targets, not yet verified snapshots.\n"
        "[kvm]\n"
        f"machines = {','.join(names)}\n"
        "interface = cape-lab0\n"
        "dsn = qemu:///system\n\n"
        + "\n".join(sections)
    )
    return {
        "result": "COMMAND2_CAPE_KVM_CONFIG_PLAN_ONLY",
        "guest_count": len(names),
        "machine_names": names,
        "snapshot_names": ["cape_ready_"+n for n in names],
        "guest_ipv4": [str(ipaddress.IPv4Address(
            int(block.network_address)+100+i)) for i in range(1,len(names)+1)],
        "conf_text": conf,
        "guest_boots_verified": False,
        "live_snapshots_exist_verified": False,
        "snapshot_reverts_verified": False,
        "cape_agent_ports_verified": False,
        "inet_sim_verified": False,
        "external_egress_blocked_verified": False,
        "file_written": False,
        "cape_service_restarted": False,
        "deploy_authorized": False,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reservation-json", type=Path, required=True)
    ap.add_argument("--subnet", default="192.168.240.0/24")
    args = ap.parse_args()
    try:
        path = args.reservation_json
        require(path.is_file() and not path.is_symlink(),
                "Expected a regular reservation JSON file")
        result = create_cape_kvm_conf(
            json.loads(path.read_text(encoding="utf-8")),args.subnet)
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except (CapeConfigBlocked, OSError, ValueError, TypeError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
