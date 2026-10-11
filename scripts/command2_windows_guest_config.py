#!/usr/bin/env python3
"""Pure, no-write Windows 11 Command 2 per-guest personalization configuration.

Input: individually reserved Windows clone identity and approved CIDR.
Output: JSON-ready data for a Windows-side agent already installed by
Command 1. Does NOT boot, connect, rename or change any VM.
"""
from __future__ import annotations
import ipaddress
import re
import uuid


class GuestConfigBlocked(ValueError):
    pass


def need(ok, msg):
    if not ok:
        raise GuestConfigBlocked(msg)


def make_guest_config(entry, subnet):
    need(type(entry) is dict, "Identity reservation row required")
    name = entry.get("libvirt_name")
    match = re.fullmatch(r"win11_([1-9][0-9]{0,2})", name) if type(name) is str else None
    need(match is not None, "Invalid reserved libvirt guest name")
    number = int(match.group(1))
    need(entry.get("windows_hostname_target") == f"WIN11-{number}",
         "Guest Windows name not consistent with reservation")
    try:
        network = ipaddress.IPv4Network(subnet, strict=True)
        wanted = ipaddress.IPv4Address(entry.get("guest_static_ipv4_target"))
        machine_uuid = str(uuid.UUID(entry.get("libvirt_uuid_candidate")))
    except (ValueError, TypeError, AttributeError) as exc:
        raise GuestConfigBlocked("Invalid reserved guest address or UUID") from exc
    need(network.is_private and network.num_addresses >= number+102,
         "Unapproved address range")
    need(str(wanted) == str(ipaddress.IPv4Address(
         int(network.network_address)+100+number)) and
         wanted in network and wanted != network.broadcast_address,
         "Guest IP does not match requested subnet index")
    need(machine_uuid == entry["libvirt_uuid_candidate"],
         "Noncanonical libvirt UUID")
    mac=entry.get("mac_candidate")
    need(type(mac) is str and bool(re.fullmatch(
        r"02:(?:[0-9a-f]{2}:){4}[0-9a-f]{2}",mac)),
        "Unapproved expected guest NIC MAC")
    need(entry.get("disk_target","").endswith(
         "/"+name+".command2.qcow2") and
         entry.get("uefi_nvram_target","").endswith(
         "/"+name+".command2_VARS.fd"),
         "Not a canonical reserved independent clone")
    return {"format":"COMMAND2_GUEST_PERSONALIZATION_V1",
            "guest_name":name,
            "expected_machine_uuid":machine_uuid,
            "hostname":f"WIN11-{number}",
            "ipv4":str(wanted),
            "prefix_length":network.prefixlen,
            "subnet":str(network),
            "nic_mac":mac,
            "default_gateway":None,
            "auto_apply_network":False,
            "host_isolation_must_be_independently_verified":True,
            "configured_in_windows":False,
            "guest_network_interface_attached":False,
            "do_not_enable_default_gateway":True}
