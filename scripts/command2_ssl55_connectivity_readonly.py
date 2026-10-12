#!/usr/bin/env python3
"""Strict READ-ONLY diagnosis of SSL55 win11_1 missing public Internet.

The current Windows clone sits on CAPE's isolated single-NIC network.
This utility proves WHY that network cannot provide WAN access, without
altering guests, CAPE agent, libvirt networks, host nft, snapshots, routes
or DNS. Host WAN reachability does NOT imply guest WAN connectivity.
"""
from __future__ import annotations
import argparse
import json
import os
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

VM="win11_1"
UUID="732b2256-ee99-41fa-881d-fbf5c476d960"
SNAP="cape_candidate_win11_1"
MASTER=("win11","289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL=("win11_trial_1","e75f6fef-347d-462f-9738-4de3df6bfa74")
MAC="02:0a:30:6a:3f:50"
NET="cape-analysis-isolated"
BRIDGE="cape-lab0"
class ConnectivityAuditBlocked(RuntimeError):pass
def need(ok,msg):
    if not ok:raise ConnectivityAuditBlocked(msg)
def cmd(*args,timeout=20):
    try:
        p=subprocess.run(args,check=False,text=True,capture_output=True,
                         timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise ConnectivityAuditBlocked("Read-only host command unavailable: "+args[0]) from e
    need(p.returncode==0 and len(p.stdout)<500_000,
         "Read-only host command failed: "+args[0])
    return p.stdout.strip()
def virsh(*args):
    return cmd("virsh","-c","qemu:///system",*args)
def view_domain(raw):
    root=ET.fromstring(raw)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==VM and root.findtext("uuid")==UUID,
         "Exact running guest identity changed")
    nics=root.findall("./devices/interface")
    need(len(nics)==1 and nics[0].get("type")=="network" and
         nics[0].find("source") is not None and
         nics[0].find("source").get("network")==NET and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address","").lower()==MAC,
         "Guest no longer has the expected isolated single NIC")
    return {"one_isolated_nic_only":True,"nic_mac":MAC,"network":NET,
            "no_temporary_public_internet_nic":True}
def inspect_network(raw):
    root=ET.fromstring(raw)
    forward=root.find("forward")
    dns=root.find("dns")
    port=root.find("port")
    ips=root.findall("ip")
    bridge=root.find("bridge")
    need(root.tag=="network" and root.findtext("name")==NET and
         bridge is not None and bridge.get("name")==BRIDGE and
         port is not None and port.get("isolated")=="yes" and
         forward is None and dns is not None and
         dns.get("enable")=="no" and
         len(ips)==1 and ips[0].get("address")=="192.168.240.1" and
         not root.findall(".//dhcp") and
         not root.findall(".//route"),
         "Unexpected libvirt CAPE bridge definition; STOP without changing it")
    return {"bridge":BRIDGE,
            "libvirt_forwarding_enabled":False,
            "libvirt_nat_enabled":False,
            "libvirt_dns_enabled":False,
            "libvirt_dhcp_enabled":False,
            "inter_guest_l2_ports_isolated":True,
            "guest_real_public_internet_available_via_this_bridge":False}
def infer_firewall(nft_dump):
    # Do not attempt to interpret foreign chain ordering as permission.
    # Presence of an installed guard + isolated libvirt network is enough
    # to explain the missing Internet; proving isolation needs packet tests.
    root=json.loads(nft_dump)
    rows=root.get("nftables") if type(root) is dict else None
    need(type(rows) is list and len(rows)<2000,
         "Invalid dedicated firewall table JSON")
    rulecount=sum(1 for r in rows if type(r) is dict and
                  type(r.get("rule")) is dict)
    chains=[r["chain"].get("name") for r in rows if type(r) is dict and
            type(r.get("chain")) is dict]
    need(rulecount>=3 and
         {"cape_forward","cape_input","cape_output"}.issubset(chains),
         "CAPE independent firewall guard not visible")
    return {"dedicated_guard_table":"cape_analysis_guard",
            "guard_chain_names_present":True,
            "rule_count_at_least_three":True,
            "packet_path_negative_tested_here":False}
def assess():
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Only canonical protected SSL55 root approved")
    need(virsh("domuuid",VM).lower()==UUID and
         virsh("domstate",VM).lower()=="running",
         "Expected running clone changed")
    for name,uid in (MASTER,TRIAL):
        need(virsh("domuuid",name).lower()==uid and
             virsh("domstate",name).lower()=="shut off",
             "Protected master or trial differs")
    need(virsh("list","--name").splitlines()==[VM],
         "An additional VM is running; stop for review")
    names=[x.strip() for x in virsh("snapshot-list",VM,"--name").splitlines()
           if x.strip()]
    need(names==[SNAP],"Existing experimental snapshot not preserved")
    saved=view_domain(virsh("dumpxml","--inactive",VM))
    live=view_domain(virsh("dumpxml",VM))
    bridge=inspect_network(virsh("net-dumpxml",NET))
    guard=infer_firewall(cmd("nft","-j","list","table","inet",
                             "cape_analysis_guard"))
    host_route=cmd("ip","-4","route","get","1.1.1.1")
    need(" dev " in " "+host_route,
         "Host route query failed")
    flags=cmd("sysctl","-n","net.ipv4.ip_forward")
    need(flags in ("0","1"),"Unexpected host sysctl forwarding state")
    return {"result":"SSL55_WIN11_1_PUBLIC_INTERNET_ABSENCE_EXPLAINED_READONLY",
        "vm":VM,"vm_running":True,"snapshot":SNAP,
        "protected_master_and_trial_off":True,
        "saved_domain":saved,"live_domain":live,
        "analysis_network":bridge,"guard":guard,
        "host_has_ipv4_default_route_candidate":True,
        "host_ipv4_forwarding_sysctl_on":flags=="1",
        "host_route_does_not_prove_guest_internet":True,
        "guest_windows_dns_gateway_and_browser_directly_tested":False,
        "reason_no_guest_public_internet":
          "EXPLICIT_ONE_NIC_NO_FORWARD_LIBVIRT_PLUS_CAPE_EGRESS_GUARD",
        "fix_requires_separate_approved_benign_provisioning_profile":True,
        "final_snapshot_must_return_to_offline_inetsim_profile":True,
        "current_snapshot_created_again":False,
        "network_or_firewall_modified":False,
        "guest_or_snapshot_modified":False,
        "CAPE_READY":False}
def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument("--mode",choices=("audit",),default="audit")
    a.parse_args()
    try:
        print(json.dumps(assess(),indent=2,sort_keys=True))
        return 0
    except (ConnectivityAuditBlocked,ET.ParseError,json.JSONDecodeError,
            OSError,ValueError,TypeError) as e:
        print(json.dumps({"result":"SSL55_GUEST_CONNECTIVITY_AUDIT_BLOCKED",
           "reason":str(e),"guest_or_network_modified":False,
           "no_snapshot_or_revert_performed":True},
           sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
