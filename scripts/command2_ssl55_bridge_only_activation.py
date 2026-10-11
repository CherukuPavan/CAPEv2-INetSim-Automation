#!/usr/bin/env python3
"""SSL55 single existing CAPE bridge start; NO guest/NIC/snapshot actions.

PLAN is read-only. ACTIVATE is interactive and guarded, for the already
defined isolated cape-analysis-isolated network only. Not a security proof.
An activation that changes other host firewall tables or breaks a check
returns BLOCKED; the bridge may remain active with ZERO connected guest
NICs for explicit human review. No automatic rollback of host firewall.
"""
from __future__ import annotations
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0,"/usr/local/libexec/cape-command2")
import command2_ssl55_existing_guard_readonly as guard
import command2_ssl55_boot_persistence_readonly as boot

LOCK=Path("/run/lock/cape-command2-ssl55-bridge-only.lock")
NET="cape-analysis-isolated"
BRIDGE="cape-lab0"
SUBNET=ipaddress.IPv4Network("192.168.240.0/24")
BRIDGE_IP="192.168.240.1"
UNIT="cape-analysis-guard.service"
EXACT_VMS={"win11":guard.MASTER_UUID,
           "win11_1":guard.CLONE_UUID,
           "win11_trial_1":guard.TRIAL_UUID}

class BridgeBlocked(RuntimeError):pass

def need(ok,msg):
    if not ok:raise BridgeBlocked(msg)

def read(*argv):
    try:
        p=subprocess.run(argv,text=True,capture_output=True,
                         timeout=40,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise BridgeBlocked("Cannot read host state: "+argv[0]) from exc
    need(p.returncode==0,"Host check failed: "+argv[0])
    return p.stdout.strip()

def virsh(*argv):
    return read("virsh","-c","qemu:///system",*argv)

def service():
    raw=read("systemctl","show","--no-pager",
             "--property=LoadState,UnitFileState,ActiveState,Result,ExecMainStatus,ConditionResult",UNIT)
    d=dict(line.split("=",1) for line in raw.splitlines() if "=" in line)
    need(d.get("LoadState")=="loaded" and
         d.get("UnitFileState")=="enabled" and
         d.get("ActiveState")=="active" and
         d.get("Result")=="success" and
         d.get("ExecMainStatus")=="0" and
         d.get("ConditionResult")=="yes",
         "Dedicated CAPE guard did not successfully run after boot")
    base=boot.parse_show(boot.read("systemctl","show","--no-pager",
                        "--property=LoadState,UnitFileState,ActiveState",
                        "nftables.service"),"nftables.service")
    need(base.get("load_state")=="loaded" and
         base.get("unit_file_state")=="disabled" and
         base.get("active_state")=="inactive",
         "Original nftables.service unexpectedly active/enabled")
    return {"cape_guard_unit_loaded_active_success":True,
            "general_nftables_stays_disabled_inactive":True}

def get_json(*args):
    try:out=json.loads(read(*args))
    except (TypeError,ValueError) as exc:
        raise BridgeBlocked("Malformed host JSON inventory: "+args[0]) from exc
    need(type(out) is list,"Expected host inventory list")
    return out

def network():
    info=virsh("net-info",NET)
    props={}
    for line in info.splitlines():
        k,sep,v=line.partition(":")
        if sep:props[k.strip().lower()]=v.strip().lower()
    need(props.get("active")=="no" and
         props.get("autostart")=="no" and
         props.get("persistent")=="yes" and
         props.get("bridge")==BRIDGE,
         "Lab network is not existing inactive manual-start CAPE bridge")
    root=ET.fromstring(virsh("net-dumpxml",NET))
    ipnodes=root.findall("./ip")
    port=root.find("./port")
    bridge=root.find("./bridge")
    dns=root.find("./dns")
    need(root.tag=="network" and root.findtext("name")==NET and
         root.find("./forward") is None and
         not root.findall(".//dhcp") and
         not root.findall(".//route") and
         bridge is not None and bridge.get("name")==BRIDGE and
         port is not None and port.get("isolated")=="yes" and
         dns is not None and dns.get("enable")=="no" and
         len(ipnodes)==1 and ipnodes[0].get("address")==BRIDGE_IP and
         ipnodes[0].get("netmask")=="255.255.255.0" and
         ipnodes[0].get("family") in (None,"ipv4"),
         "Unexpected libvirt lab definition (including L2 port isolation)")
    need(not root.findall("./ip[@family='ipv6']") and
         root.find("./forward") is None, "IPv6/forwarding in lab definition")
    return True

def host_collision():
    links=get_json("ip","-j","link","show")
    ipv4routes=get_json("ip","-j","-4","route","show","table","all")
    ipv4addr=get_json("ip","-j","-4","addr","show")
    need(all(type(x) is dict for x in links+ipv4routes+ipv4addr),
         "Host inventory contains untrusted item")
    need(not any(x.get("ifname")==BRIDGE for x in links),
         "Analysis bridge already exists unexpectedly")
    for route in ipv4routes:
        dest=route.get("dst","default")
        if dest in ("default",None):continue
        try:network=ipaddress.IPv4Network(dest,strict=False)
        except (TypeError,ValueError):continue
        need(not network.overlaps(SUBNET),
             "CAPE guest subnet collides with an existing host route")
    for link in ipv4addr:
        for row in link.get("addr_info",()):
            if type(row) is not dict or row.get("family")!="inet":continue
            try:network=ipaddress.IPv4Network(
                f'{row["local"]}/{row["prefixlen"]}',strict=False)
            except (TypeError,ValueError,KeyError) as exc:
                raise BridgeBlocked("Cannot parse host IPv4 address") from exc
            need(not network.overlaps(SUBNET),
                 "CAPE guest subnet overlaps existing host interface")

def nft_table_inventory():
    d=json.loads(read("nft","-j","list","ruleset"))
    rows=d.get("nftables") if type(d) is dict else None
    need(type(rows) is list,"Unexpected nft ruleset JSON")
    return sorted((n["table"].get("family"),n["table"].get("name"))
                  for n in rows if type(n) is dict and
                  type(n.get("table")) is dict)

def protected():
    report=guard.audit()
    need(report.get("no_vm_or_network_changes") is True and
         report["existing_lab_firewall"].get("expected_guard_shape") is True and
         report["analysis_network"].get("active")=="no",
         "Current CAPE nft guard/network state unacceptable")
    for vm,uid in EXACT_VMS.items():
        v=report.get("protected_domains",{}).get(vm,{})
        need(v.get("uuid_verified") is True and
             v.get("power_state")=="shut off" and
             v.get("nic_counts",{}).get("inactive")==(
                 1 if vm=="win11" else 0) and
             boot.domain_autostart(vm) is False,
             "Protected master/trial/clone no longer safely shut off")
    active=virsh("list","--name")
    need(not active.strip(),"Another libvirt guest is currently active")
    return True

def plan():
    need(os.geteuid()==0,"Root required for protected shared host audit")
    actual=socket.gethostname().split(".",1)[0].lower()
    need(actual in ("cse-ssl-55","ssl-55") and
         guard.SENTINEL.is_dir() and not guard.SENTINEL.is_symlink(),
         "Wrong/unprotected shared machine")
    service()
    protected()
    network()
    host_collision()
    nft_tables=nft_table_inventory()
    need(("inet",guard.TABLE) in nft_tables,
         "Existing verified CAPE nft guard table missing")
    return {"result":"SSL55_EXISTING_BRIDGE_ACTIVATION_PLAN_ONLY",
            "host":actual,"network":NET,"bridge":BRIDGE,
            "bridge_ipv4":BRIDGE_IP,"isolated_port_required":True,
            "iptables_or_nft_changes_authorized":False,
            "original_host_nft_tables":nft_tables,
            "all_guests_shutoff":True,"clone_saved_nics":0,
            "network_started":False,"nic_attached":False,
            "host_changed":False,"ipv4_egress_proved":False,
            "ipv6_egress_proved":False,
            "guest_l2_isolation_proved":False,
            "cape_analysis_authorized":False}

def activate():
    need(os.geteuid()==0,"Root required for bridge activation")
    need(sys.stdin.isatty(),"Direct operator terminal required")
    before=plan()
    phrase="START-ISOLATED-BRIDGE-ONLY-SSL55"
    need(input("Type "+phrase+" to activate the existing isolated bridge ONLY: ")==phrase,
         "No operator approval; host unchanged")
    need(not LOCK.is_symlink(),"Unsafe bridge activation lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    started=False
    try:
        m=os.fstat(fd)
        need(stat.S_ISREG(m.st_mode) and m.st_uid==0 and
             stat.S_IMODE(m.st_mode)==0o600 and m.st_nlink==1,
             "Unsafe privileged lock metadata")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(plan()==before,"Host changed while awaiting activation")
        virsh("net-start",NET)
        started=True
        # No guest attaches are permitted by this stage, even after
        # a successful start. Verify the isolated bridge and guard.
        info=virsh("net-info",NET)
        need(re.search(r"(?im)^Active:\s+yes\s*$",info) is not None and
             re.search(r"(?im)^Autostart:\s+no\s*$",info) is not None,
             "Bridge start did not yield manual-only active network")
        links=get_json("ip","-j","link","show")
        need(sum(1 for x in links if x.get("ifname")==BRIDGE)==1,
             "Expected exactly one CAPE bridge after start")
        addrs=get_json("ip","-j","-4","addr","show")
        cap=[x for x in addrs if x.get("ifname")==BRIDGE]
        need(len(cap)==1 and
             any(x.get("family")=="inet" and
                 x.get("local")==BRIDGE_IP and
                 x.get("prefixlen")==24
                 for x in cap[0].get("addr_info",())),
             "CAPE bridge IPv4 not as approved")
        v6=get_json("ip","-j","-6","addr","show","dev",BRIDGE)
        need(not any(x.get("scope") in ("global","site")
                 for row in v6 for x in row.get("addr_info",())),
             "Unexpected globally reachable IPv6 bridge address")
        # Structural CAPE guard verification independent of lab state.
        json_table=read("nft","-j","list","table","inet",guard.TABLE)
        text_table=read("nft","list","table","inet",guard.TABLE)
        guard.guard_policy_structure(json_table,text_table)
        tables_after=nft_table_inventory()
        need(tables_after==before["original_host_nft_tables"],
             "Host nft table inventory changed after bridge start; STOP")
        need(not virsh("list","--name").strip(),
             "VM running unexpectedly after bridge start")
        for vm in ("win11_1","win11_trial_1"):
            root=ET.fromstring(virsh("dumpxml","--inactive",vm))
            need(not root.findall("./devices/interface"),
                 "Unexpected guest NIC after bridge start")
        return {"result":"SSL55_ISOLATED_BRIDGE_ONLY_ACTIVE_WITH_NO_GUEST_NICS",
                "network":NET,"bridge":BRIDGE,
                "bridge_ipv4":BRIDGE_IP,"bridge_started":True,
                "protected_guests_still_shutoff":True,
                "protected_clones_still_zero_nic":True,
                "cape_nft_guard_still_present":True,
                "host_nft_table_inventory_unchanged":True,
                "guest_ipv4_negative_egress_verified":False,
                "guest_ipv6_negative_egress_verified":False,
                "cape_analysis_authorized":False,
                "snapshot_capture_authorized":False}
    except Exception as exc:
        # No blind net-destroy: the bridge may be active in an unknown
        # condition, but zero-NIC guard was enforced before start.
        raise BridgeBlocked(
            ("PARTIAL: bridge may now be ACTIVE; DO NOT attach a NIC. "
             if started else "BLOCKED without starting bridge: ")+str(exc)) from exc
    finally:
        os.close(fd)

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument("--mode",choices=("plan","activate"),default="plan")
    args=a.parse_args()
    try:
        res=plan() if args.mode=="plan" else activate()
        print(json.dumps(res,indent=2,sort_keys=True))
        return 0
    except (BridgeBlocked,guard.AuditBlocked,boot.BootBlocked,
            OSError,ValueError,TypeError,ET.ParseError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
