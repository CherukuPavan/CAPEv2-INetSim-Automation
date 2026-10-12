#!/usr/bin/env python3
"""Pure per-VM Windows BENIGN default NAT profile; no host/guest writes.

Uses ONLY a previously validated Command2 all-N master_nat_attach
SAVED STATE report (after actual libvirt one-NIC and DHCP config writes).
This is a different opt-in format from COMMAND2_GUEST_PERSONALIZATION_V1,
which intentionally forbids default gateways. NEVER change that old
isolated guest security contract to accept arbitrary Internet egress.
Configuration JSON is host-generated and SHA pinned by the media builder,
and will require independent host+guest and network identity verification
before final snapshots and CAPE registration.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import re

class NatGuestBlocked(ValueError): pass
def need(ok,reason):
    if not ok:raise NatGuestBlocked(reason)

def make(report):
    need(type(report) is dict and
         report.get("result") in (
           "COMMAND2_MASTER_NAT_ALL_N_SAVED_STATE_VERIFIED",
           "COMMAND2_ALL_N_MASTER_NAT_NICS_AND_DHCP_APPLIED_VERIFIED") and
         report.get("network")=="default" and
         report.get("bridge")=="virbr0" and
         report.get("guest_saved_nics_attached") is True and
         report.get("host_nat_dhcp_config_applied") is True and
         report.get("CAPE_READY") is False and
         report.get("guest_booted_or_configured") is False,
         "Exact host-verified permanent NAT all-N report required")
    entries=report.get("guest_reservations")
    hosts=report.get("dhcp_hosts")
    need(type(entries) is list and 1<=len(entries)<=16 and
         type(hosts) is list and len(entries)==len(hosts)==report["count"],
         "Missing exact 1..16 NAT clones and DHCP host reservations")
    output=[]
    used=set()
    for idx,(entry,host) in enumerate(zip(entries,hosts),1):
        name=f"win11_{idx}"
        nickname=f"WIN11-{idx}"
        mac=entry.get("reserved_mac")
        ip=entry.get("ip")
        uid=entry.get("uuid")
        need(entry.get("vm")==name and
             entry.get("saved_nic_state")=="SINGLE_MASTER_EQUIVALENT_NAT" and
             entry.get("guest_not_started") is True and
             type(mac) is str and
             re.fullmatch(r"02:(?:[0-9a-f]{2}:){4}[0-9a-f]{2}",mac) and
             host=={"mac":mac,"ip":ip,"name":nickname} and
             type(uid) is str and
             re.fullmatch(r"(?i)[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",uid),
             "Per-VM identity/MAC/IP/reservation differs from host proof")
        address=ipaddress.IPv4Address(ip)
        need(address.is_private and
             address not in (ipaddress.IPv4Address("192.168.122.1"),),
             "Nonprivate or unsafe target guest NAT IP")
        # The standard default NAT uses subnet-base+1 for gateway. The
        # actual source NAT may use another RFC1918 /24 on another host.
        subnet=ipaddress.IPv4Network(str(address)+"/24",strict=False)
        gateway=str(ipaddress.IPv4Address(int(subnet.network_address)+1))
        need(address!=subnet.broadcast_address and
             address!=subnet.network_address and
             int(address)-int(subnet.network_address)>=2 and
             str(ip) not in used and mac not in used and uid not in used,
             "NAT guest IP/MAC/UUID collision in verified host report")
        used.update((str(ip),mac,uid))
        output.append({"format":"COMMAND2_MASTER_NAT_WINDOWS_V1",
          "guest_name":name,
          "expected_machine_uuid":uid,
          "hostname":nickname,
          "nic_mac":mac,
          "ipv4":str(address),
          "subnet":str(subnet),
          "prefix_length":24,
          "default_gateway":gateway,
          "dns_ipv4":gateway,
          "nic_network":"default",
          "bridge":"virbr0",
          "addressing":"libvirt_dhcp_reservation",
          "expected_nic_count":1,
          "benign_https_proof_needed":True,
          "network_isolation_proved_by_this_profile":False,
          "malware_public_internet_authorized":False})
    return output

def render_one(obj):
    need(type(obj) is dict and obj.get("format")==
         "COMMAND2_MASTER_NAT_WINDOWS_V1",
         "Invalid guest NAT manifest schema")
    data=(json.dumps(obj,sort_keys=True,separators=(",",":"))+"\n").encode()
    need(len(data)<4096,"NAT Windows manifest unexpectedly large")
    return {"json_bytes":data,
            "sha256":hashlib.sha256(data).hexdigest()}
