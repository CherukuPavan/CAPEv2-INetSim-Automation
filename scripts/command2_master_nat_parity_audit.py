#!/usr/bin/env python3
"""Read-only CAPE Command2 MASTER-EQUIVALENT persistent NAT plan on SSL55.

The user's master win11 uses default/virbr0 NAT; future clones must be
persistent and match that *network mode*, not a time-limited second adapter.

This strictly scoped audit never changes libvirt network, DHCP, any guest
NIC, Windows route, nft rules, snapshots, or master/trial state. It
exposes existing DHCP pools/host reservations/leases and conflict risks:
no arbitrary static IP is considered safe merely because a ping fails.

Master XML cannot reveal Windows static TCP/IP configuration; report that
missing guest-side proof explicitly. Protected win11_1 currently has an
isolated NIC and running candidate snapshot; this is diagnostic, NOT a
migration executor. No sample execution authorization is implied.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

HOST="cse-ssl-55"
MASTER="win11"
MASTER_UUID="289d89be-68ec-4c62-90e1-ea930849266f"
TRIAL="win11_trial_1"
TRIAL_UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"
CLONE="win11_1"
CLONE_UUID="732b2256-ee99-41fa-881d-fbf5c476d960"
CANDIDATE="cape_candidate_win11_1"
NAT="default"
BRIDGE="virbr0"
ANALYSIS="cape-analysis-isolated"
MAC_RE=re.compile(r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
class NatParityBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise NatParityBlocked(why)

def virsh(*args):
    try:
        p=subprocess.run(["virsh","-c","qemu:///system",*args],
                         capture_output=True,text=True,check=False,timeout=30)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise NatParityBlocked("Read-only libvirt call failed: "+args[0]) from exc
    need(p.returncode==0 and len(p.stdout)<1_000_000,
         "Libvirt rejected read-only query: "+args[0])
    return p.stdout.strip()

def guest_view(xml,who,expected_uuid):
    root=ET.fromstring(xml)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==who and
         root.findtext("uuid")==expected_uuid,
         "Protected VM identity no longer matches: "+who)
    interfaces=[]
    for nic in root.findall("./devices/interface"):
        source=nic.find("source")
        mac=nic.find("mac")
        model=nic.find("model")
        need(nic.get("type")=="network" and
             source is not None and mac is not None and model is not None and
             MAC_RE.fullmatch(mac.get("address") or ""),
             "Unreviewed network interface on "+who)
        interfaces.append({
            "network":source.get("network"),
            "mac":mac.get("address").lower(),
            "model":model.get("type"),
            "libvirt_port_isolated":(
                nic.find("port") is not None and
                nic.find("port").get("isolated")=="yes")
        })
    need(len(interfaces)<=2,
         "Guest has unexpected NIC count: "+who)
    return interfaces

def nat_details(xml):
    root=ET.fromstring(xml)
    forward=root.find("forward")
    bridge=root.find("bridge")
    need(root.tag=="network" and root.findtext("name")==NAT and
         forward is not None and forward.get("mode","nat")=="nat" and
         bridge is not None and bridge.get("name")==BRIDGE,
         "Master NAT is not the expected default/virbr0")
    ipnodes=root.findall("ip")
    ipv4=[]
    reserved=[]
    pools=[]
    for node in ipnodes:
        address=node.get("address")
        if not address or ":" in address:
            continue
        prefix=node.get("prefix")
        mask=node.get("netmask")
        need(bool(prefix) != bool(mask),
             "Expected exact single netmask or prefix in NAT XML")
        subnet=ipaddress.IPv4Network(
            address+"/"+(prefix or mask), strict=False)
        ipv4.append({"gateway":address,"subnet":str(subnet)})
        for item in node.findall("./dhcp/range"):
            start=ipaddress.IPv4Address(item.get("start"))
            end=ipaddress.IPv4Address(item.get("end"))
            need(start<=end and start in subnet and end in subnet,
                 "DHCP range invalid/outside NAT")
            pools.append({"first":str(start),"last":str(end)})
        for item in node.findall("./dhcp/host"):
            ip=item.get("ip")
            if ip:
                need(ipaddress.IPv4Address(ip) in subnet,
                     "Existing static DHCP reservation outside subnet")
                reserved.append({"mac":item.get("mac"),
                                 "name":item.get("name"),
                                 "ipv4":ip})
    need(len(ipv4)==1 and bool(pools),
         "Expected one active IPv4 NAT subnet with DHCP")
    return {"nat_network":NAT,"bridge":BRIDGE,
            "guest_network_has_unrestricted_egress_by_default":True,
            "ipv4":ipv4[0],
            "dynamic_dhcp_ranges":pools,
            "existing_dhcp_host_reservations":reserved,
            "automatic_safe_clone_static_ip_assigned":False}

def lease_inventory(text):
    # Leases are observations, NOT a complete proof of unused IPs.
    lines=[x.strip() for x in text.splitlines() if x.strip()]
    if len(lines)>1000:raise NatParityBlocked("Unexpected many NAT leases")
    occupied=[]
    for line in lines:
        # mac and IPv4 CIDR are stable format fields across standard virsh
        # net-dhcp-leases output; failures are left as raw lease row counts.
        match=re.search(r"\b((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\b",line,re.I)
        ipv4=re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})\b",line)
        if match and ipv4:
            try: ip=ipaddress.IPv4Address(ipv4.group(1))
            except ipaddress.AddressValueError:continue
            occupied.append({"mac":match.group(1).lower(),"ipv4":str(ip)})
    return {"live_dhcp_leases":occupied,
            "raw_nonempty_line_count":len(lines),
            "lease_table_not_exhaustive_proof_of_static_ip_availability":True}

def assess(count):
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()==HOST,
         "Only protected SSL55 root admission")
    need(type(count) is int and 1<=count<=16,
         "Requested clone count must be 1..16")
    for name,uuid in ((MASTER,MASTER_UUID),(TRIAL,TRIAL_UUID),
                      (CLONE,CLONE_UUID)):
        need(virsh("domuuid",name).lower()==uuid,
             "Protected VM UUID changed: "+name)
    need(virsh("domstate",MASTER).lower()=="shut off" and
         virsh("domstate",TRIAL).lower()=="shut off" and
         virsh("domstate",CLONE).lower()=="running",
         "Expected master/trial OFF, current candidate clone RUNNING")
    names=[x.strip() for x in virsh("snapshot-list",CLONE,"--name").splitlines()
           if x.strip()]
    need(names==[CANDIDATE],"Existing running clone snapshot modified")
    master=guest_view(virsh("dumpxml","--inactive",MASTER),
                      MASTER,MASTER_UUID)
    need(len(master)==1 and
         master[0]["network"]==NAT and
         master[0]["model"]=="e1000e",
         "MASTER is not the expected one e1000e NIC on default NAT")
    existing_saved=guest_view(virsh("dumpxml","--inactive",CLONE),
                              CLONE,CLONE_UUID)
    existing_live=guest_view(virsh("dumpxml",CLONE),
                             CLONE,CLONE_UUID)
    need(len(existing_saved)==1 and
         existing_saved[0]["network"]==ANALYSIS,
         "Current clone persistent interface already changed")
    need(any(i["network"]==ANALYSIS for i in existing_live),
         "Current clone no longer connected to original CAPE network")
    details=nat_details(virsh("net-dumpxml",NAT))
    meta={}
    for line in virsh("net-info",NAT).splitlines():
        key,sep,value=line.partition(":")
        if sep:meta[key.strip().lower()]=value.strip().lower()
    need(meta.get("active")=="yes" and meta.get("bridge")==BRIDGE,
         "Master's libvirt default NAT not active on virbr0")
    lease=lease_inventory(virsh("net-dhcp-leases",NAT))
    wanted=[f"win11_{i}" for i in range(1,count+1)]
    # Require a FULL snapshot+guest identity and DHCP/network occupancy
    # audit before calculating specific fixed lease or Windows static IP.
    return {
        "result":"COMMAND2_MASTER_EQUIVALENT_PERSISTENT_NAT_AUDIT_ONLY",
        "verified_reference_master":MASTER,
        "master_uuid":MASTER_UUID,
        "master_saved_interface":master[0],
        "source_vm_remains_off":True,"trial_remains_off":True,
        "live_clone":CLONE,"live_clone_nics":existing_live,
        "clone_saved_nics":existing_saved,
        "existing_running_snapshot":CANDIDATE,
        "target_permanent_libvirt_network":NAT,
        "target_permanent_bridge":BRIDGE,
        "target_clone_names":wanted,
        "target_each_clone_unique_mac_and_reserved_ip":True,
        "network_info":details,"lease_inventory":lease,
        "historical_master_windows_ip_reference":"192.168.122.125",
        "master_windows_ip_gateway_dns_not_verified_by_saved_xml":True,
        "existing_clone_current_guest_ip":"192.168.240.101",
        "moving_clone_requires_approved_guest_ip_cape_config_updates":True,
        "future_snapshot_must_be_recaptured_after_ip_network_change":True,
        "unrestricted_malware_sample_egress_approved":False,
        "libvirt_network_or_guest_modified":False,
        "running_candidate_snapshot_not_reverted_or_deleted":True
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("audit",),default="audit")
    p.add_argument("--count",type=int,default=1)
    a=p.parse_args()
    try:
        print(json.dumps(assess(a.count),indent=2,sort_keys=True))
        return 0
    except (NatParityBlocked,ET.ParseError,OSError,ValueError,TypeError) as exc:
        print(json.dumps({
            "result":"COMMAND2_MASTER_NAT_PARITY_AUDIT_BLOCKED",
            "reason":str(exc),
            "master_clone_network_or_snapshots_modified":False,
            "no_fixed_ip_assigned_without_collision_checks":True
        },sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
