#!/usr/bin/env python3
"""Separate-host ONLY: one QUARANTINED NIC for BENIGN egress qualification.

Breaks prior impossible dependency: guest IPv4/IPv6 negative-egress tests
cannot be performed while the guest has zero NICs. A checked host guard,
dedicated non-NAT network, collision-free identity, and approved host-only
preflight precede *config-only* e1000e NIC attachment to a shut-off guest.
The guest is STILL NOT APPROVED for malware/CAPE analysis. Runtime guest
negative egress, host agent path, reboot persistence and benign restore
acceptance must FOLLOW. Never run on SSL-55; no network/VM boot here.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import xml.etree.ElementTree as ET

import command2_guarded_isolated_nic as nic

LOCK=Path("/run/lock/cape-command2-benign-nic-once.lock")
REQUIRED_HOST_PRECHECK=(
    "dedicated_lab_no_nat_dhcp",
    "host_bridge_route_collision_absent",
    "host_guard_nft_live_readback",
    "host_guard_boot_fail_closed",
    "host_firewall_unrelated_chains_unchanged",
    "benign_testing_only",
)


class BenignNicBlocked(RuntimeError):
    pass


def require(check,why):
    if not check:
        raise BenignNicBlocked(why)


def approval(path,vm,host,uuid,mac,guest_ip,subnet):
    """Record accepted host-only evidence, not a self-proving signature."""
    p=Path(path)
    require(p.is_absolute() and p.is_file() and not p.is_symlink(),
            "Host-only approval receipt not found")
    st=p.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
            stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and
            st.st_size<65536,"Untrusted host-only approval receipt permissions")
    data=json.loads(p.read_text(encoding="utf-8"))
    require(type(data) is dict and
            data.get("kind")=="COMMAND2_BENIGN_ONLY_HOST_PRECHECK_V1" and
            data.get("approved_host")==host and
            data.get("vm")==vm and data.get("uuid")==uuid and
            data.get("mac")==mac and data.get("guest_ip")==guest_ip and
            data.get("subnet")==subnet and
            type(data.get("operator")) is str and
            len(data["operator"])>=3 and
            all(data.get(k) is True for k in REQUIRED_HOST_PRECHECK),
            "Host-only benign approval invalid/incomplete")
    return True


def collision_check(vm,mac,subnet):
    """Fail closed on libvirt/host MAC collisions and nonbridge IP overlap."""
    names=[name for name in nic.virsh("list","--all","--name").splitlines()
           if name.strip()]
    require(vm in names and len(names)==len(set(names)),
            "Incomplete/duplicate libvirt inventory")
    occupied=set()
    for domain in names:
        xmls=[nic.virsh("dumpxml","--inactive",domain)]
        if nic.virsh("domstate",domain).strip() in ("running","paused"):
            xmls.append(nic.virsh("dumpxml",domain))
        for raw in xmls:
            root=ET.fromstring(raw)
            require(root.findtext("name")==domain,"Unknown libvirt domain MAC owner")
            for item in root.findall("./devices/interface/mac"):
                address=item.get("address")
                if address:occupied.add(address.lower())
    try:
        links=json.loads(nic.cmd("ip","-j","link","show"))
        routes=json.loads(nic.cmd("ip","-j","-4","route","show","table","all"))
    except (TypeError,ValueError) as exc:
        raise BenignNicBlocked("Unverifiable host link/route inventory") from exc
    require(type(links) is list and type(routes) is list and
            len(links)<=8192 and len(routes)<=8192,
            "Host link/route inventory malformed")
    for link in links:
        require(type(link) is dict,"Malformed host link")
        if type(link.get("address")) is str:
            occupied.add(link["address"].lower())
    require(mac not in occupied,"Reserved MAC already used elsewhere")
    import ipaddress
    expected=ipaddress.IPv4Network(subnet,strict=True)
    for route in routes:
        require(type(route) is dict,"Malformed host route")
        dst=route.get("dst","default")
        if dst in ("default",None):continue
        try:other=ipaddress.IPv4Network(dst,strict=False)
        except (TypeError,ValueError):continue
        if other.overlaps(expected):
            require(route.get("dev") == nic.BRIDGE,
                    "Candidate CAPE subnet overlaps another host route")
    return True


def plan(vm,host,uuid,mac,subnet,receipt=None):
    nic.guard_host(host)
    ip,bridge_ip=nic.vm_identity(vm,uuid,mac,subnet)
    before=nic.verify_clone_no_nic(vm,uuid)
    nic.verify_network_live(subnet,bridge_ip)
    collision_check(vm,mac,subnet)
    accepted=(approval(receipt,vm,host,uuid,mac,ip,subnet)
              if receipt is not None else False)
    return {
        "result":"COMMAND2_QUARANTINED_BENIGN_NIC_PLAN_ONLY",
        "vm":vm,"host":host,"uuid":uuid,"mac":mac,
        "reserved_guest_ipv4":ip,"subnet":subnet,
        "approved_host_only_receipt":accepted,
        "saved_domain_xml":before,
        "no_network_or_vm_changes":True,
        "guest_ipv4_negative_test_complete":False,
        "guest_ipv6_negative_test_complete":False,
        "cape_analysis_authorized":False,
        "running_snapshot_authorized":False,
    }


def attach_for_benign_test(vm,host,uuid,mac,subnet,receipt):
    nic.guard_host(host)
    require(os.geteuid()==0,"Only root may attach a benign test NIC")
    require(sys.stdin.isatty(),"Direct interactive approval required")
    before=plan(vm,host,uuid,mac,subnet,receipt)
    require(before["approved_host_only_receipt"],
            "Host-only preconditions are required before connection")
    phrase="ATTACH-QUARANTINED-BENIGN-"+vm.upper()
    require(input("Type "+phrase+" for ONE shut-off guest NIC: ")==phrase,
            "Operator did not approve benign test NIC")
    require(not LOCK.is_symlink(),"NIC lock is symlink")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        meta=os.fstat(fd)
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and
                stat.S_IMODE(meta.st_mode)==0o600 and meta.st_nlink==1,
                "Unsafe benign NIC lock metadata")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        after=plan(vm,host,uuid,mac,subnet,receipt)
        require(after==before,"Host/VM state changed while waiting for lock")
        nic.virsh("attach-interface","--domain",vm,"--type","network",
                  "--source",nic.NETWORK,"--model","e1000e","--mac",mac,
                  "--config")
        root=ET.fromstring(nic.virsh("dumpxml","--inactive",vm))
        nics=root.findall("./devices/interface")
        require(len(nics)==1 and nics[0].get("type")=="network" and
                nics[0].find("source") is not None and
                nics[0].find("source").get("network")==nic.NETWORK and
                nics[0].find("mac") is not None and
                nics[0].find("mac").get("address","").lower()==mac and
                nic.virsh("domstate",vm).strip()=="shut off",
                "Quarantined NIC postcondition failed; do not retry")
        return {
            "result":"COMMAND2_QUARANTINED_NIC_ATTACHED_SHUTOFF_BENIGN_ONLY",
            "vm":vm,"network":nic.NETWORK,"reserved_mac":mac,
            "guest_still_shutoff":True,
            "guest_negative_ipv4_proved":False,"guest_negative_ipv6_proved":False,
            "guest_l2_proved":False,"cape_analysis_authorized":False,
            "snapshot_authorized":False,"production_ready":False,
        }
    finally:
        os.close(fd)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode",choices=("plan","attach-benign"),default="plan")
    ap.add_argument("--vm",required=True)
    ap.add_argument("--approved-host",required=True)
    ap.add_argument("--uuid",required=True)
    ap.add_argument("--mac",required=True)
    ap.add_argument("--subnet",default="192.168.240.0/24")
    ap.add_argument("--host-only-receipt",type=Path)
    a=ap.parse_args()
    try:
        if a.mode=="plan":
            result=plan(a.vm,a.approved_host,a.uuid,a.mac,a.subnet,a.host_only_receipt)
        else:
            require(a.host_only_receipt is not None,
                    "Preapproved host-only receipt required")
            result=attach_for_benign_test(
                a.vm,a.approved_host,a.uuid,a.mac,a.subnet,a.host_only_receipt)
        # Never print domain XML to operator logs.
        result.pop("saved_domain_xml",None)
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (BenignNicBlocked,nic.NicBlocked,OSError,ValueError,
            TypeError,ET.ParseError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
