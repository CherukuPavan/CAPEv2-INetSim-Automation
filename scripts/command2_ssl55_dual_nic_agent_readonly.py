#!/usr/bin/env python3
"""SSL55 exact clone dual-network CAPE Agent transition gate (read-only).

Requires physical operator-attached persistent default/virbr0 e1000e
MAC 02:ca:55:11:01:02 and preserved original isolated NIC. Windows
proof from operator dated 2026-10-12 shows NAT DHCP 192.168.122.131,
gateway/DNS 192.168.122.1, external TCP/443 and HTTPS success.

This module validates EXACT host/guest identities, private snapshot, both
saved/live NICs, host route, optional DHCP lease occupancy and probes
the CAPE agent via BOTH host bridges using harmless HTTP GET /. It never
changes libvirt, Windows, CAPE config, nft, INetSim, snapshot or TPM.
It cannot prove post-reboot DHCP permanence, TPM state restoration, or
safe malware egress and NEVER authorizes dropping the old adapter.
"""
from __future__ import annotations
import argparse
import http.client
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

VM="win11_1"
UID="732b2256-ee99-41fa-881d-fbf5c476d960"
MASTER=("win11","289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL=("win11_trial_1","e75f6fef-347d-462f-9738-4de3df6bfa74")
SNAP="cape_candidate_win11_1"
POSTNAT="cape_postnat_win11_1"
POSTNAT_IMAGES=(
    "/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2",
    "/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd.qcow2",
)
AGENT_PORT=8000
PATHS={
    "original_isolated":("192.168.240.101","192.168.240.1",
                         "cape-analysis-isolated","02:0a:30:6a:3f:50","cape-lab0"),
    "permanent_nat":("192.168.122.131","192.168.122.1",
                     "default","02:ca:55:11:01:02","virbr0"),
}
class ReaddressBlocked(RuntimeError):pass
def need(ok,msg):
    if not ok:raise ReaddressBlocked(msg)

def cmd(*args,timeout=25):
    try:
        proc=subprocess.run(args,capture_output=True,text=True,
                            check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ReaddressBlocked("Read-only host query failed/timed out: "+args[0]) from exc
    need(proc.returncode==0 and len(proc.stdout)<=500000,
         "Read-only host query rejected: "+args[0])
    return proc.stdout.strip()
def virsh(*args):
    return cmd("virsh","-c","qemu:///system",*args)

def interfaces(xml):
    root=ET.fromstring(xml)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==VM and root.findtext("uuid")==UID,
         "Exact clone UUID/name mismatch")
    out=[]
    for d in root.findall("./devices/interface"):
        mac=d.find("mac");src=d.find("source");model=d.find("model")
        need(d.get("type")=="network" and
             mac is not None and src is not None and model is not None,
             "Unexpected live/persistent passthrough NIC")
        out.append((src.get("network"),(mac.get("address") or "").lower(),
                    model.get("type")))
    expected=[(q[2],q[3],"e1000e") for q in PATHS.values()]
    need(sorted(out)==sorted(expected) and len(out)==2,
         "Require both expected permanent NAT and original isolated NICs")
    return {"persistent_and_live_two_expected_nics":True,
            "offline_isolated_mac":PATHS["original_isolated"][3],
            "permanent_nat_mac":PATHS["permanent_nat"][3]}

def libvirt_networks():
    for label,(ip,source,net,mac,bridge) in PATHS.items():
        x=ET.fromstring(virsh("net-dumpxml",net))
        br=x.find("bridge")
        forward=x.find("forward")
        need(x.tag=="network" and x.findtext("name")==net and
             br is not None and br.get("name")==bridge,
             "Network bridge changed for "+label)
        if label=="original_isolated":
            port=x.find("port")
            need(forward is None and port is not None and
                 port.get("isolated")=="yes" and
                 not x.findall(".//dhcp"),
                 "Original CAPE isolated network changed")
        else:
            need(forward is not None and
                 forward.get("mode","nat")=="nat" and
                 len(x.findall(".//dhcp/range"))>=1,
                 "Original master's default NAT/DHCP changed")
        route=json.loads(cmd("ip","-j","-4","route","get",ip))
        need(type(route) is list and len(route)==1 and
             route[0].get("dev")==bridge and
             route[0].get("prefsrc",route[0].get("src"))==source and
             not route[0].get("gateway"),
             "Host route to "+label+" guest is NOT local "+bridge)
    return {"host_ipv4_routes_match_both_guest_subnets":True,
            "isolated_bridge_retained":True,
            "default_nat_dhcp_retained":True}

def inventory_lease():
    raw=virsh("net-dhcp-leases","default")
    hits=[]
    for line in raw.splitlines():
        if "02:ca:55:11:01:02" in line.lower():
            ip_re=re.search(r"\b192\.168\.122\.\d{1,3}/\d{1,2}\b",line)
            if ip_re:
                hits.append(ip_re.group(0).split("/")[0])
    return {"observed_nat_mac_lease_count":len(hits),
            "observed_nat_ips_for_mac":hits,
            "lease_table_is_not_proof_of_current_or_future_ip":True,
            "guest_windows_ipv4_from_20261012_screenshot":"192.168.122.131",
            "stable_dhcp_reservation_exists_verified":False}

def probe(ip,source):
    conn=None
    try:
        conn=http.client.HTTPConnection(ip,AGENT_PORT,timeout=5,
                                        source_address=(source,0))
        conn.request("GET","/",headers={"Accept":"application/json"})
        resp=conn.getresponse()
        data=resp.read(8193)
        if resp.status!=200 or len(data)>8192:
            return {"reachable_and_identified":False,
                    "outcome":"http_non_200_or_oversized"}
        body=json.loads(data.decode("utf-8"))
        ready=(type(body) is dict and
               body.get("message")=="CAPE Agent!" and
               type(body.get("version")) is str and
               body.get("is_user_admin") is True)
        return {"reachable_and_identified":ready,
                "outcome":"cape_agent_verified" if ready else "unexpected_agent_identity",
                "agent_version":body.get("version") if ready else None}
    except (OSError,TimeoutError,http.client.HTTPException,
            json.JSONDecodeError,ValueError,UnicodeError) as exc:
        return {"reachable_and_identified":False,
                "outcome":"connection_or_json_failed",
                "failure_kind":type(exc).__name__}
    finally:
        if conn:conn.close()

def assess():
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Exact protected SSL55 root only")
    need(virsh("domuuid",VM).lower()==UID and
         virsh("domstate",VM).lower()=="running",
         "Clone not in expected running state")
    for name,uuid in (MASTER,TRIAL):
        need(virsh("domuuid",name).lower()==uuid and
             virsh("domstate",name).lower()=="shut off",
             "Protected master/trial changed")
    need(virsh("list","--name").splitlines()==[VM],
         "Unknown other guest running")
    snapshots=[x.strip() for x in
             virsh("snapshot-list",VM,"--name").splitlines() if x.strip()]
    second=sorted(snapshots)==sorted([SNAP,POSTNAT])
    need(snapshots==[SNAP] or second,
         "Unexpected candidate/post-NAT snapshot inventory")
    for snap in ([SNAP,POSTNAT] if second else [SNAP]):
        snaproot=ET.fromstring(virsh("snapshot-dumpxml",VM,snap))
        mem=snaproot.find("memory")
        domain=snaproot.find("domain")
        disks=snaproot.findall("./disks/disk")
        need(snaproot.tag=="domainsnapshot" and
             snaproot.findtext("name")==snap and
             snaproot.findtext("state")=="running" and
             domain is not None and
             domain.findtext("uuid")==UID and domain.findtext("name")==VM and
             mem is not None and mem.get("snapshot")=="internal" and
             sum(x.get("name")=="sda" and x.get("snapshot")=="internal"
                 for x in disks)==1 and
             len({d.get("name") for d in disks})==len(disks),
             "Saved running memory+OS disk snapshot missing for "+snap)
    # A second candidate must be real on BOTH exact, independent QCOW2
    # files—not just a libvirt metadata node created after NAT changed.
    if second:
        from pathlib import Path
        for raw in POSTNAT_IMAGES:
            path=Path(raw)
            need(path.is_file() and not path.is_symlink(),
                 "Post-NAT image missing or linked")
            info=json.loads(cmd("qemu-img","info","-U","--output=json",
                                str(path),timeout=90))
            need(type(info) is dict and info.get("format")=="qcow2" and
                 not info.get("backing-filename"),
                 "Post-NAT image not standalone QCOW2")
            entries=info.get("snapshots",[])
            need(type(entries) is list and all(type(x) is dict and
                 type(x.get("name")) is str for x in entries),
                 "Post-NAT image checkpoint list malformed")
            names=[x["name"] for x in entries]
            need(names.count(SNAP)==1 and names.count(POSTNAT)==1 and
                 len(names)==2,
                 "Post-NAT OS/UEFI actual QCOW2 checkpoints do not match")
    saved=interfaces(virsh("dumpxml","--inactive",VM))
    live=interfaces(virsh("dumpxml",VM))
    networks=libvirt_networks()
    leases=inventory_lease()
    checks={}
    for key,details in PATHS.items():
        checks[key]=probe(details[0],details[1])
    return {
        "result":"SSL55_DUAL_PERMANENT_NAT_CAPE_AGENT_AUDIT_READONLY",
        "vm":VM,"snapshot":SNAP,"state":"running",
        "postnat_running_snapshot_verified":second,
        "expected_running_snapshot_names":([SNAP,POSTNAT] if second else [SNAP]),
        "TPM_safe_revert_proven":False,
        "interfaces_saved":saved,"interfaces_live":live,
        "routes_networks":networks,
        "nat_lease_observation":leases,
        "agent_checks":checks,
        "original_agent_still_reachable":checks["original_isolated"]["reachable_and_identified"],
        "nat_agent_reachable":checks["permanent_nat"]["reachable_and_identified"],
        "next_safe_step_requires_guest_ip_cape_config_plan":True,
        "permanent_nat_dhcp_reservation_committed":False,
        "cape_ip_registration_changed":False,
        "inetsim_traffic_flow_tested":False,
        "old_adapter_detached":False,
        "final_running_snapshot_taken":False,
        "swtpm_revert_proven":False,
        "malware_analysis_allowed":False,
        "host_or_guest_modified":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("audit",),default="audit")
    p.parse_args()
    try:
        info=assess()
        print(json.dumps(info,sort_keys=True,indent=2))
        # A failed NAT agent check is useful physical feedback, NOT a
        # license to change Windows firewall or remove old interface.
        return 0 if info["original_agent_still_reachable"] and info["nat_agent_reachable"] else 3
    except (ReaddressBlocked,OSError,ValueError,TypeError,KeyError,ET.ParseError) as exc:
        print(json.dumps({"result":"SSL55_NAT_CAPE_AGENT_AUDIT_BLOCKED",
            "reason":str(exc),"guest_network_or_snapshot_modified":False,
            "original_interface_should_be_preserved":True},
             sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
