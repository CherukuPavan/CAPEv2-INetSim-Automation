#!/usr/bin/env python3
"""Count-driven master-matched NAT plan, exact stable guest identities.

PURE planning: output expected one persistent NIC per clone on same
default/virbr0 NAT used by the protected source 'win11'. Assign each
win11_N a collision-checked candidate IP and DHCP host reservation
corresponding to its already-approved unique MAC. IPs are stable after
libvirt reservation and guest IP settings have actually been installed,
which this tool NEVER claims to have done.

A DHCP lease inventory is not proof that manually assigned static IPs
are free. Apply MUST obtain extra host/guest collision evidence and use
checked libvirt net-update/add plus Windows reconfiguration. NEVER simply
switch the current running win11_1 interface while its guest IP still
belongs to 192.168.240.0/24.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
MAX=16
MAC_RE=re.compile(r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
class NatPlanBlocked(ValueError):pass
def need(ok,why):
    if not ok:raise NatPlanBlocked(why)
def allocate(audit,rows,*,start_offset=201):
    need(type(audit) is dict and
         audit.get("result")=="COMMAND2_MASTER_EQUIVALENT_PERSISTENT_NAT_AUDIT_ONLY" and
         audit.get("target_permanent_libvirt_network")=="default" and
         audit.get("target_permanent_bridge")=="virbr0" and
         audit.get("source_vm_remains_off") is True and
         audit.get("trial_remains_off") is True and
         audit.get("libvirt_network_or_guest_modified") is False,
         "Require exact read-only NAT master-reference audit")
    need(type(rows) is list and 1<=len(rows)<=MAX,
         "1..16 approved guest reservations required")
    planned=audit.get("target_clone_names")
    need(type(planned) is list and planned==[
         "win11_"+str(i) for i in range(1,len(rows)+1)],
         "Count mismatch: reference NAT audit must match all N guests")
    net=audit.get("network_info")
    need(type(net) is dict and net.get("nat_network")=="default" and
         net.get("bridge")=="virbr0" and
         net.get("guest_network_has_unrestricted_egress_by_default") is True,
         "Reference NAT network details changed")
    cfg=net.get("ipv4")
    need(type(cfg) is dict,"Original NAT gateway/subnet missing")
    try:
        subnet=ipaddress.IPv4Network(cfg["subnet"],strict=True)
        gateway=ipaddress.IPv4Address(cfg["gateway"])
    except (KeyError,TypeError,ValueError) as exc:
        raise NatPlanBlocked("Invalid master NAT subnet/gateway") from exc
    need(subnet.prefixlen==24 and subnet.is_private and gateway in subnet and
         gateway==ipaddress.IPv4Address(int(subnet.network_address)+1),
         "Source-master NAT requires private /24 with gateway offset 1")
    need(type(start_offset) is int and 2<=start_offset<=
         254-len(rows)+1,
         "Proposed offset not inside usable /24")
    ranges=net.get("dynamic_dhcp_ranges")
    need(type(ranges) is list and 1<=len(ranges)<=8,
         "Authoritative libvirt DHCP pool missing")
    occupied_ip={gateway}
    occupied_mac=set()
    for lease in audit.get("lease_inventory",{}).get("live_dhcp_leases",[]):
        need(type(lease) is dict and type(lease.get("mac")) is str,
             "Malformed existing DHCP lease")
        occupied_ip.add(ipaddress.IPv4Address(lease["ipv4"]))
    for reservation in net.get("existing_dhcp_host_reservations",[]):
        need(type(reservation) is dict,"Malformed existing DHCP reservation")
        if reservation.get("ipv4"):
            occupied_ip.add(ipaddress.IPv4Address(reservation["ipv4"]))
        if reservation.get("mac"):
            occupied_mac.add(reservation["mac"].lower())
    prior_ip=audit.get("historical_master_windows_ip_reference")
    if prior_ip:
        occupied_ip.add(ipaddress.IPv4Address(prior_ip))
    def in_pool(ip):
        for r in ranges:
            low=ipaddress.IPv4Address(r["first"])
            high=ipaddress.IPv4Address(r["last"])
            if low<=ip<=high:return True
        return False
    output=[]
    used_mac=set()
    for idx,row in enumerate(rows,1):
        need(type(row) is dict and row.get("libvirt_name")=="win11_"+str(idx),
             "Clone identity rows must be exact ordered win11_N")
        mac=row.get("mac_candidate")
        need(type(mac) is str and MAC_RE.fullmatch(mac) is not None and
             int(mac.split(":")[0],16)&1==0 and
             mac.lower() not in used_mac and
             mac.lower() not in occupied_mac,
             "Duplicate/invalid clone MAC in master NAT")
        used_mac.add(mac.lower())
        ip=ipaddress.IPv4Address(int(subnet.network_address)+start_offset+idx-1)
        need(ip in subnet and ip!=subnet.broadcast_address and in_pool(ip),
             "Planned NAT IP outside DHCP-authorized range")
        need(ip not in occupied_ip,
             "NAT requested clone static IPv4 collides with observed "+
             "lease/reservation/master: "+str(ip))
        # Future apply: use same source MAC for reservation and Windows
        # network config; guest must have exact permanent default NIC.
        host=f"WIN11-{idx}"
        hostxml=f"<host mac='{mac.lower()}' name='{host}' ip='{ip}'/>"
        ET.fromstring(hostxml)
        output.append({
            "libvirt_name":row["libvirt_name"],
            "host_network":"default",
            "bridge":"virbr0",
            "required_nic_model":"e1000e",
            "nic_mac":mac.lower(),
            "desired_static_ipv4":str(ip),
            "prefix_length":24,
            "gateway_ipv4":str(gateway),
            "dns_ipv4":str(gateway),
            "dhcp_reservation_xml_preview":hostxml,
            "host_libvirt_reservation_applied":False,
            "windows_guest_static_ipv4_applied":False,
            "cape_guest_machine_ip_registered":False,
            "live_guest_https_tested":False,
            "guest_nic_port_isolated":True,
            "malware_public_internet_allowed":False,
        })
        occupied_ip.add(ip)
    return {
        "result":"COMMAND2_MASTER_MATCHED_PERSISTENT_NAT_COUNT_PLAN_ONLY",
        "master_template":"win11","clones":output,"count":len(output),
        "network":"default","host_bridge":"virbr0",
        "guest_assigned_ip_policy":"static_windows_and_libvirt_reserved",
        "additional_unknown_static_ip_collision_test_required":True,
        "existing_lease_inventory_not_complete_collision_proof":True,
        "temporary_setup_nic_must_be_cleaned_up_first":True,
        "analysis_isolation_nft_policy_must_be_redesigned_before_releasing_samples":True,
        "existing_win11_1_snapshot_must_not_be_reverted":True,
        "live_guest_ip_agent_cape_registration_changes_required":True,
        "any_network_or_vm_changes_performed":False,
        "safe_for_cape_malware":False,
        "auto_apply_authorized":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--audit-json",required=True)
    p.add_argument("--rows-json",required=True)
    p.add_argument("--start-offset",type=int,default=201)
    a=p.parse_args()
    try:
        with open(a.audit_json,encoding="utf-8") as f: audit=json.load(f)
        with open(a.rows_json,encoding="utf-8") as f: rows=json.load(f)
        print(json.dumps(allocate(audit,rows,start_offset=a.start_offset),
                         indent=2,sort_keys=True))
        return 0
    except (NatPlanBlocked,ValueError,TypeError,KeyError,OSError) as exc:
        print(json.dumps({"result":"COMMAND2_MASTER_NAT_ALLOCATION_BLOCKED",
           "reason":str(exc),"libvirt_guest_or_network_changed":False},
           sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
