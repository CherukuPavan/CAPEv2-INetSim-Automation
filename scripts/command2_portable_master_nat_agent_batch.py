#!/usr/bin/env python3
"""OTHER-host all-N running master-NAT CAPE Agent acceptance (READ ONLY).

Call AFTER the guarded all-N DHCP/NIC attach, guest Windows hostname/DHCP
configuration and approved benign boot. Requires every win11_1..N
RUNNING, one exact saved+live e1000e default/virbr0 NIC with host-pinned
unique MAC, exact active+inactive DHCP host reservation, active lease,
host route source virbr0 gateway, and CAPE Agent HTTP GET admin identity.
No VM boot/stop, snapshot creation/revert, service/network mutation.
This is NOT proof of guest Windows HTTPS, swtpm safe restore, NAT egress
containment, INetSim sample traffic or CAPE production readiness.
"""
from __future__ import annotations
import argparse
import http.client
import ipaddress
import json
from pathlib import Path
import os
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

import command2_portable_master_nat_attach as attach

class BatchAgentBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise BatchAgentBlocked(why)

def route(ip):
    try:
        p=subprocess.run(["ip","-j","-4","route","get",ip],
                        capture_output=True,text=True,timeout=15,
                        check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise BatchAgentBlocked("Host route query missing or timed out") from exc
    need(p.returncode==0 and len(p.stdout)<65536,
         "Host cannot inspect route to selected guest NAT IP")
    result=json.loads(p.stdout)
    need(type(result) is list and len(result)==1,
         "Ambiguous route to Windows NAT guest IP")
    return result[0]

def agent(ip,gateway):
    conn=None
    try:
        conn=http.client.HTTPConnection(ip,8000,timeout=6,
                                      source_address=(gateway,0))
        conn.request("GET","/",headers={"Accept":"application/json"})
        answer=conn.getresponse()
        body=answer.read(8193)
        if answer.status!=200 or len(body)>8192:
            return {"valid":False,"reason":"bad_agent_http_status"}
        result=json.loads(body.decode("utf-8"))
        if type(result) is not dict or result.get("message")!="CAPE Agent!" or \
           type(result.get("version")) is not str or \
           result.get("is_user_admin") is not True:
            return {"valid":False,"reason":"wrong_agent_http_identity"}
        return {"valid":True,"agent_version":result["version"],
                "admin_context_verified":True}
    except (OSError,TimeoutError,ValueError,UnicodeError,
            http.client.HTTPException) as exc:
        return {"valid":False,"reason":"unreachable_or_invalid",
                "exception_kind":type(exc).__name__}
    finally:
        if conn:conn.close()

def nic_xml(raw,row):
    root=ET.fromstring(raw)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==row["libvirt_name"] and
         root.findtext("uuid")==row["libvirt_uuid_candidate"],
         "Guest UUID/domain identity changed")
    nics=root.findall("./devices/interface")
    need(len(nics)==1,"Expected one guest NIC only")
    nic=nics[0]
    src=nic.find("source");model=nic.find("model");mac=nic.find("mac")
    need(nic.get("type")=="network" and
         src is not None and src.get("network")=="default" and
         model is not None and model.get("type")=="e1000e" and
         mac is not None and
         (mac.get("address") or "").lower()==row["mac_candidate"].lower(),
         "Guest NIC/MAC/model not the reserved source-master default NAT")
    return True

def read_lease(text):
    # 'virsh net-dhcp-leases default' format is bounded human-readable
    # columns. Only MAC and IPv4/CIDR are required; hostname may be
    # unknown before Windows bootstrap completes.
    import re
    seen=[]
    for line in text.splitlines():
        mac=re.search(r"\b((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\b",line,re.I)
        ipv4=re.search(r"\b((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})\b",line)
        if not mac or not ipv4:continue
        ip=str(ipaddress.IPv4Address(ipv4.group(1)))
        seen.append((mac.group(1).lower(),ip))
    need(len(seen)<1024 and len(seen)==len(set(seen)),
         "Unexpected duplicate/mass DHCP lease inventory")
    return seen

def check(host,journal):
    rows=attach.journal_rows(host,journal)
    net,views=attach.check_network_references()
    network=ipaddress.IPv4Network(net["ipv4"]["subnet"])
    need(network.prefixlen==24 and network.is_private,
         "Expected source master default private /24")
    gateway=net["ipv4"]["gateway"]
    need(gateway==str(ipaddress.IPv4Address(
         int(network.network_address)+1)),
         "Master NAT gateway different from expected +1")
    expected={r["libvirt_name"] for r in rows}
    active=[n.strip() for n in attach.virsh("list","--name").splitlines()
            if n.strip()]
    need(len(active)==len(rows) and set(active)==expected,
         "Only the complete approved N clone batch may be running")
    for name in ("win11","win11_trial_1"):
        if name=="win11_trial_1":
            allnames=attach.virsh("list","--all","--name").splitlines()
            if name not in allnames:continue
        need(attach.virsh("domstate",name).lower()=="shut off",
             "Protected master or trial changed from shut off")
    leases=read_lease(attach.virsh("net-dhcp-leases","default"))
    verified=[]
    for i,row in enumerate(rows,1):
        ip=str(ipaddress.IPv4Address(
              int(network.network_address)+200+i))
        mac=row["mac_candidate"].lower()
        vm=row["libvirt_name"]
        need(attach.virsh("domuuid",vm).lower()==
             row["libvirt_uuid_candidate"] and
             attach.virsh("domstate",vm).lower()=="running",
             "Running guest identity/power differs: "+vm)
        need(nic_xml(attach.virsh("dumpxml","--inactive",vm),row) and
             nic_xml(attach.virsh("dumpxml",vm),row),
             "Saved/live NIC mismatch: "+vm)
        res=(mac,ip,"WIN11-"+str(i))
        need(all(attach.reservations(root).count(res)==1 for root in views),
             "Exact active/persistent DHCP host reservation missing: "+vm)
        need(leases.count((mac,ip))==1 and
             not any(otherip==ip and othermac!=mac
                 for othermac,otherip in leases),
             "Expected live NAT DHCP address not assigned uniquely: "+vm)
        path=route(ip)
        need(path.get("dev")=="virbr0" and
             path.get("prefsrc",path.get("src"))==gateway and
             not path.get("gateway"),
             "Wrong host route/interface to guest NAT Agent: "+vm)
        remote=agent(ip,gateway)
        need(remote.get("valid") is True,
             "CAPE Agent admin HTTP unavailable on reserved NAT: "+vm)
        verified.append({"vm":vm,"mac":mac,"ipv4":ip,
             "reserved_unique_mac_ip_live_and_persistent":True,
             "saved_live_one_master_nat_nic":True,
             "host_gateway_route_verified":True,
             "cape_agent":remote,
             "windows_actual_hostname_proven":False,
             "windows_real_https_proven_by_host_http_test":False,
             "VM_snapshot_created":False,
             "swtpm_consistent_revert_proven":False,
             "malware_public_internet_authorized":False})
    return {"result":"COMMAND2_ALL_N_MASTER_NAT_AGENTS_RUNNING_VERIFIED_READONLY",
       "host":host,"count":len(rows),"guests":verified,
       "all_nat_guest_mac_ip_agent_host_routes_verified":True,
       "snapshots_created_by_this_check":False,
       "windows_guest_https_witness_required":True,
       "host_ipv6_and_l2_sample_containment_proven":False,
       "CAPE_READY":False,"swtpm_reversion_proven":False,
       "physical_two_simultaneous_benign_cape_analyses_passed":False,
       "host_guest_services_networks_modified":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    a=p.parse_args()
    try:
        print(json.dumps(check(a.approved_host,a.journal),
                         indent=2,sort_keys=True))
        return 0
    except (BatchAgentBlocked,attach.NatAttachBlocked,
            attach.profile.PortableNatBlocked,
            attach.workflow.WorkflowBlocked,
            attach.workflow.snapshotgate.GateBlocked,
            OSError,ValueError,TypeError,KeyError,ET.ParseError) as exc:
        print(json.dumps({"result":"COMMAND2_MASTER_NAT_AGENT_BATCH_BLOCKED",
                          "reason":str(exc),
                          "CAPE_READY":False,
                          "no_guest_or_host_network_changes":True},
                         sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
