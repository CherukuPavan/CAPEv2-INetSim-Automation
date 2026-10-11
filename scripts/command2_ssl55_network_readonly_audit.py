#!/usr/bin/env python3
"""Read-only SSL-55 libvirt network inventory; NEVER attach or alter a NIC.

Exact protected VM identity and live/inactive views; report does NOT
claim CAPE IPv4/IPv6 containment or authorize network modification.
No sudo, files, guest boots, snapshots, or host firewall changes.
"""
from __future__ import annotations
import argparse
import json
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

VM_IDS = {
    "win11": "289d89be-68ec-4c62-90e1-ea930849266f",
    "win11_trial_1": "e75f6fef-347d-462f-9738-4de3df6bfa74",
    "win11_1": "732b2256-ee99-41fa-881d-fbf5c476d960",
}
LAB_NETWORK = "cape-analysis-isolated"


class AuditBlocked(RuntimeError):
    pass


def cmd(*args):
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as err:
        raise AuditBlocked("Read-only host command unavailable: " + args[0]) from err
    if p.returncode:
        raise AuditBlocked("Read-only command failed: " + " ".join(args[:3]))
    return p.stdout.strip()


def virsh(*args):
    return cmd("virsh", "-c", "qemu:///system", *args)


def network_interfaces(xml_text, expected_name, expected_uuid):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as err:
        raise AuditBlocked("Invalid libvirt XML") from err
    if root.tag != "domain" or root.findtext("name") != expected_name or \
       root.findtext("uuid") != expected_uuid:
        raise AuditBlocked("Protected VM identity differs from verified baseline")
    interfaces = []
    for node in root.findall("./devices/interface"):
        src = node.find("source")
        model = node.find("model")
        mac = node.find("mac")
        interfaces.append({
            "type": node.get("type"),
            "source_network": src.get("network") if src is not None else None,
            "source_bridge": src.get("bridge") if src is not None else None,
            "model": model.get("type") if model is not None else None,
            "mac_present": mac is not None and bool(mac.get("address")),
        })
    return interfaces


def inventory():
    seen = socket.gethostname().split(".", 1)[0].lower()
    if seen not in ("ssl-55", "cse-ssl-55"):
        raise AuditBlocked("This reference-host audit is for SSL-55 only")
    results = {}
    for vm, expected in VM_IDS.items():
        actual = virsh("domuuid", vm).lower()
        if actual != expected:
            raise AuditBlocked("VM UUID mismatch: " + vm)
        state = virsh("domstate", vm).lower()
        if state not in ("running", "shut off", "paused"):
            raise AuditBlocked("Unexpected libvirt VM state: " + vm)
        views = {
            "inactive": network_interfaces(
                virsh("dumpxml", "--inactive", vm), vm, expected
            )
        }
        if state in ("running", "paused"):
            views["live"] = network_interfaces(virsh("dumpxml", vm), vm, expected)
        results[vm] = {
            "state": state, "uuid": actual, "interface_views": views,
            "interface_counts": {view: len(items) for view, items in views.items()},
        }
    info = virsh("net-info", LAB_NETWORK)
    status = {}
    for key in ("Active", "Autostart", "Bridge"):
        match = re.search(r"^" + re.escape(key) + r":\s*(.*?)\s*$",
                          info, re.M | re.I)
        if match is None:
            raise AuditBlocked("Missing network status: " + key)
        status[key.lower()] = match.group(1).lower()
    lab_safe_to_connect = False  # explicit: inventory is NOT containment proof
    return {
        "result": "SSL55_NETWORK_INVENTORY_READ_ONLY",
        "protected_domains": results, "analysis_network": status,
        "analysis_network_known_off": status["active"] == "no" and
                                      status["autostart"] == "no",
        "win11_master_nic_repair_authorized": False,
        "win11_1_nic_attach_authorized": lab_safe_to_connect,
        "network_ipv4_ipv6_containment_proven": False,
        "firewall_reboot_persistence_proven": False,
        "host_changed": False,
        "next": "Review master NIC XML and independent network isolation evidence before any repair",
    }


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        print(json.dumps(inventory(), indent=2, sort_keys=True))
        return 0
    except AuditBlocked as err:
        print("BLOCKED: " + str(err), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
