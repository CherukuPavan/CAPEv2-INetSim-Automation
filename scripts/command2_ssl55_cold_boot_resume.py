#!/usr/bin/env python3
"""SSL55 only: guarded isolated-net activation and existing clone cold boot.

No VM creation, snapshots, restart/revert, firewall modifications, NAT
activation, autostart changes, sample execution or backup modification.
Operator must explicitly approve network activation and clone startup.
"""
from __future__ import annotations
import argparse
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

VM="win11_1"
UID="732b2256-ee99-41fa-881d-fbf5c476d960"
MASTER=("win11","289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL=("win11_trial_1","e75f6fef-347d-462f-9738-4de3df6bfa74")
NET="cape-analysis-isolated"
BRIDGE="cape-lab0"
HOST_IP="192.168.240.1"
GUEST_IP="192.168.240.101"
SUBNET=ipaddress.ip_network("192.168.240.0/24")
DISK="/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2"
VARS="/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd"
BACKUP=Path("/var/lib/libvirt/images/cape-clones-staging/cape-win11_1-cold-recovery/cold-b8c6f2d3b4ba4e948dc476b2a1b35c2d")

class Blocked(Exception):pass
def need(condition,msg):
    if not condition:raise Blocked(msg)

def run(*args,timeout=45):
    try:
        p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise Blocked("Host query unavailable: "+args[0]) from exc
    need(p.returncode==0,"Host utility returned error: "+args[0]+" exit="+str(p.returncode))
    need(len(p.stdout)<2_000_000,"Oversized status")
    return p.stdout.strip()
def virsh(*args):return run("virsh","-c","qemu:///system",*args)

def prop(raw):
    d={}
    for line in raw.splitlines():
        key,sep,val=line.partition(":")
        if sep:d[key.strip().lower()]=val.strip().lower()
    return d

def check_xml(raw):
    root=ET.fromstring(raw)
    need(root.tag=="domain" and root.findtext("name")==VM and
         root.findtext("uuid")==UID,"Clone identity differs")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1,"Expected one primary clone disk")
    d=disks[0]
    src=d.find("source");driver=d.find("driver")
    target=d.find("target")
    need(src is not None and src.get("file")==DISK and
         driver is not None and driver.get("type")=="qcow2" and
         target is not None and target.get("dev")=="sda",
         "Clone disk differs")
    backing=d.find("backingStore")
    need(backing is None or (backing.find("source") is None and
         backing.find("backingStore") is None),
         "Clone master backing dependency reappeared")
    need(root.findtext("./os/nvram")==VARS,"Unexpected UEFI variables path")
    tpm=root.findall("./devices/tpm/backend")
    need(len(tpm)==1 and tpm[0].get("type")=="emulator" and
         tpm[0].get("version")=="2.0","Unexpected swtpm2")
    nics=root.findall("./devices/interface")
    need(len(nics)==1 and nics[0].get("type")=="network" and
         nics[0].find("source") is not None and
         nics[0].find("source").get("network")==NET and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address","").lower()=="02:0a:30:6a:3f:50",
         "NIC differs from isolated analysis NIC")
    need(not root.findall("./devices/hostdev") and
         not root.findall("./devices/filesystem") and
         not root.findall("./devices/redirdev"),
         "Unexpected host-access device")
    return True

def check_bundle():
    need(BACKUP.is_dir() and not BACKUP.is_symlink(),"Saved cold bundle missing")
    st=BACKUP.stat()
    need(st.st_uid==0 and stat.S_IMODE(st.st_mode)&0o077==0,
         "Cold bundle directory is not private")
    mf=BACKUP/"manifest.json"
    need(mf.is_file() and not mf.is_symlink() and mf.stat().st_size<200000,
         "Invalid cold manifest")
    m=json.loads(mf.read_text())
    need(m.get("format")=="cape-ssl55-cold-v1" and
         m.get("vm")==VM and m.get("uuid")==UID and
         m.get("restore_tested") is False,"Unexpected cold manifest identity")
    records=m.get("files")
    need(type(records) is list and
         {x.get("name") for x in records if type(x) is dict}==
         {"disk.qcow2","uefi-vars.fd","tpm-tpm2-00.permall"} and
         len(records)==3,"Cold bundle inventory differs")
    for row in records:
        p=BACKUP/row["name"]
        need(p.is_file() and not p.is_symlink() and p.stat().st_nlink==1 and
             p.stat().st_uid==0 and
             stat.S_IMODE(p.stat().st_mode)&0o077==0 and
             p.stat().st_size==row["size"],"Cold backup artifact metadata differs")
    check_xml((BACKUP/"domain.xml").read_text())
    return {"cold_bundle_metadata_valid":True,
            "files_hashed_at_original_capture":3,
            "hashes_recalculated_here":False,
            "restore_proven":False}

def exact_network():
    n=ET.fromstring(virsh("net-dumpxml",NET))
    b=n.find("bridge");port=n.find("port");dns=n.find("dns")
    ips=n.findall("ip")
    need(n.tag=="network" and n.findtext("name")==NET and
         n.find("forward") is None and not n.findall(".//dhcp") and
         not n.findall(".//route") and
         b is not None and b.get("name")==BRIDGE and
         port is not None and port.get("isolated")=="yes" and
         dns is not None and dns.get("enable")=="no" and
         len(ips)==1 and ips[0].get("address")==HOST_IP and
         ips[0].get("netmask")=="255.255.255.0" and
         ips[0].get("family") in (None,"ipv4"),
         "CAPE network is not the agreed no-forward, port-isolated /24")
    p=prop(virsh("net-info",NET))
    need(p.get("persistent")=="yes" and p.get("autostart")=="no" and
         p.get("bridge")==BRIDGE and p.get("active") in ("yes","no"),
         "Unexpected network activation/autostart state")
    return p["active"]

def guard_firewall():
    need(run("systemctl","is-active","cape-analysis-guard.service")=="active",
         "Dedicated CAPE guard service inactive")
    raw=run("nft","-j","list","table","inet","cape_analysis_guard")
    text=run("nft","list","table","inet","cape_analysis_guard")
    # Use existing in-repo structural firewall inspector, installed on SSL55.
    sys.path.insert(0,"/usr/local/libexec/cape-command2")
    try:
        import command2_ssl55_existing_guard_readonly as guard
        guard.guard_policy_structure(raw,text)
    except (ImportError,AttributeError) as exc:
        raise Blocked("Verified CAPE firewall inspector unavailable") from exc
    return True

def network_collision():
    # Only applicable while the isolated bridge is inactive.
    obj=json.loads(run("ip","-j","-4","route","show","table","all"))
    addrs=json.loads(run("ip","-j","-4","addr","show"))
    links=json.loads(run("ip","-j","link","show"))
    need(all(type(x) is dict for x in obj+addrs+links),"Unexpected IP inventory shape")
    need(not any(x.get("ifname")==BRIDGE for x in links),
         "Bridge already exists despite inactive network")
    for r in obj:
        dest=r.get("dst")
        if dest in (None,"default"):continue
        try: candidate=ipaddress.ip_network(dest,strict=False)
        except (ValueError,TypeError) as exc:
            raise Blocked("Malformed IPv4 host route inventory") from exc
        need(not SUBNET.overlaps(candidate),
             "CAPE subnet collides with host route: do not activate")
    for item in addrs:
        for addr in item.get("addr_info",[]):
            if addr.get("family")!="inet":continue
            try: candidate=ipaddress.ip_network(
                str(addr["local"])+"/"+str(addr["prefixlen"]),strict=False)
            except (KeyError,ValueError,TypeError) as exc:
                raise Blocked("Malformed host IPv4 address") from exc
            need(not SUBNET.overlaps(candidate),
                 "CAPE subnet collides with existing interface: do not activate")

def exact_guests():
    need(virsh("domuuid",VM).lower()==UID,"Pilot UUID differs")
    for name,uid in (MASTER,TRIAL):
        need(virsh("domuuid",name).lower()==uid and
             virsh("domstate",name).lower()=="shut off",
             "Protected original VM UUID or shutdown state changed: "+name)
    need(not virsh("snapshot-list",VM,"--name").strip(),
         "Unexpected guest snapshot exists")
    need(virsh("domstate",VM).lower()=="shut off",
         "Pilot must be off before cold start")
    need(not virsh("list","--name").strip(),
         "Another libvirt guest is running")
    check_xml(virsh("dumpxml","--inactive",VM))

def plan():
    need(os.geteuid()==0,"Run with sudo")
    need(socket.gethostname().split(".")[0].lower()=="cse-ssl-55",
         "SSL55-only pilot; no portable-host mutation allowed")
    exact_guests()
    bundle=check_bundle()
    network_state=exact_network()
    guard_firewall()
    if network_state=="no":network_collision()
    return {"result":"COLD_BOOT_RESUME_PLAN_PASS_NO_WRITES",
            "vm":VM,"vm_state":"shut off",
            "network":NET,"network_active":network_state,
            "requires_net_start":network_state=="no",
            "protected_originals_shutoff":True,
            "existing_clone_only":True,
            "cold_bundle":bundle,
            "guest_egress_negative_proven":False,
            "host_modified":False}

def bridge_active():
    need(exact_network()=="yes","Network not active")
    links=json.loads(run("ip","-j","link","show","dev",BRIDGE))
    addresses=json.loads(run("ip","-j","-4","addr","show","dev",BRIDGE))
    need(len(links)==1 and links[0].get("ifname")==BRIDGE,
         "Expected isolated bridge missing")
    need(len(addresses)==1 and
         any(z.get("local")==HOST_IP and z.get("prefixlen")==24
             for z in addresses[0].get("addr_info",[])),
         "Bridge address differs")
    v6=json.loads(run("ip","-j","-6","addr","show","dev",BRIDGE))
    need(all(z.get("scope") not in ("global","site")
             for item in v6 for z in item.get("addr_info",[])),
         "Unexpected IPv6 routable address")
    guard_firewall()
    exact_guests()

def agent():
    c=http.client.HTTPConnection(GUEST_IP,8000,timeout=4,
                                 source_address=(HOST_IP,0))
    try:
        c.request("GET","/",headers={"Accept":"application/json"})
        r=c.getresponse();payload=r.read(8193)
        if r.status!=200 or len(payload)>8192:return False
        obj=json.loads(payload.decode("utf8"))
        return (type(obj) is dict and obj.get("message")=="CAPE Agent!" and
                obj.get("is_user_admin") is True and
                isinstance(obj.get("version"),str))
    except (OSError,ValueError,UnicodeError,http.client.HTTPException):
        return False
    finally:c.close()

def resume():
    need(sys.stdin.isatty(),"Use controlling terminal for approval")
    first=plan()
    print(json.dumps(first,indent=2,sort_keys=True),flush=True)
    if first["requires_net_start"]:
        phrase="START-ISOLATED-NETWORK-SSL55"
        need(input("Type "+phrase+" to activate ONLY existing CAPE isolated network: ")==
             phrase,"Network activation not approved")
        second=plan()
        need(first==second,"Host preflight changed before network activation")
        virsh("net-start",NET)
        print("ISOLATED_NETWORK_START_REQUESTED",flush=True)
    bridge_active()
    phrase="START-WIN11_1-AFTER-COLD-BACKUP"
    need(input("Type "+phrase+" to start ONLY existing win11_1: ")==
         phrase,"VM start not approved")
    bridge_active()
    virsh("start",VM)
    print("CLONE_START_REQUESTED",flush=True)
    for index in range(60):
        if virsh("domstate",VM).lower()!="running":
            raise Blocked("VM left running state while awaiting CAPE Agent")
        if agent():
            return {"result":"COLD_BOOT_AGENT_VERIFIED",
                    "clone_running":True,"agent_via_isolated_bridge":True,
                    "cold_backup_preserved":True,
                    "original_master_or_trial_modified":False,
                    "memory_snapshot_revert_proven":False,
                    "cold_restore_proven":False,
                    "negative_ipv4_ipv6_l2_proven":False}
        time.sleep(5)
    raise Blocked("VM started but CAPE Agent did not respond in time. "
                  "Preserve state and inspect; no automatic VM reset")

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode",choices=("plan","resume"),default="plan")
    a=ap.parse_args()
    try:
        result=plan() if a.mode=="plan" else resume()
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (Blocked,OSError,subprocess.TimeoutExpired,ValueError,TypeError,
            ET.ParseError) as exc:
        print(json.dumps({"result":"STOP_FOR_OPERATOR_REVIEW",
                          "reason":str(exc),
                          "no_automatic_vm_or_network_rollback":True},
                         indent=2),file=sys.stderr)
        return 2
if __name__=="__main__":sys.exit(main())
