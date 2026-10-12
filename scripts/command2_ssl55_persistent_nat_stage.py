#!/usr/bin/env python3
"""SSL55 migration STEP 1: persistent master-style NAT NIC staging.

PLAN is strictly read-only. APPLY with typed consent attaches exactly ONE
independent e1000e NIC to win11_1 on the same existing default/virbr0 NAT as
its protected shut-off master. Uses BOTH --live and --config so NIC persists.
Critically leaves old cape-analysis-isolated NIC and its 192.168.240.101
reachable while Windows is checked for DHCP/HTTPS. Snapshot is untouched.
This is NOT an internet proof, not a final single-NIC migration and NEVER
authorizes malware analysis while unrestricted default NAT is connected.
If partial attach occurs, no auto-retry or arbitrary device removal.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

HOST="cse-ssl-55"
VM="win11_1"
UID="732b2256-ee99-41fa-881d-fbf5c476d960"
MASTER=("win11","289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL=("win11_trial_1","e75f6fef-347d-462f-9738-4de3df6bfa74")
SNAP="cape_candidate_win11_1"
ISOLATED="cape-analysis-isolated"
ANALYSIS_MAC="02:0a:30:6a:3f:50"
ONLINE_MAC="02:ca:55:11:01:02"
DEFAULT="default"
LOCK=Path("/run/lock/cape-ssl55-permanent-nat-stage-win11-1.lock")
class StagingBlocked(RuntimeError):pass
def need(x,msg):
    if not x:raise StagingBlocked(msg)
def command(*args,timeout=65):
    try:
        p=subprocess.run(args,capture_output=True,text=True,
                         check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise StagingBlocked("Command missing/timeout: "+args[0]) from exc
    need(p.returncode==0 and len(p.stdout)<600_000,
         "Host libvirt command refused: "+args[0])
    return p.stdout.strip()
def virsh(*args,timeout=65):
    return command("virsh","-c","qemu:///system",*args,timeout=timeout)

def domain(raw,name,uid):
    root=ET.fromstring(raw)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==name and root.findtext("uuid")==uid,
         "Unexpected VM identity: "+name)
    devices=root.findall("./devices/interface")
    need(len(devices)<=2,"Unexpected NIC count in "+name)
    nics=[]
    for device in devices:
        mac=device.find("mac")
        model=device.find("model")
        src=device.find("source")
        need(device.get("type")=="network" and mac is not None and
             model is not None and src is not None,
             "Unreviewed VM NIC device")
        nics.append({"mac":(mac.get("address") or "").lower(),
                     "model":model.get("type"),
                     "network":src.get("network")})
    return nics

def check_online():
    root=ET.fromstring(virsh("net-dumpxml",DEFAULT))
    f=root.find("forward")
    bridge=root.find("bridge")
    ips=root.findall("ip")
    need(root.tag=="network" and root.findtext("name")==DEFAULT and
         f is not None and f.get("mode","nat")=="nat" and
         bridge is not None and bridge.get("name")=="virbr0" and
         len(ips)==1 and ips[0].get("address")=="192.168.122.1" and
         len(root.findall(".//dhcp/range"))>=1,
         "Master default NAT no longer on expected DHCP virbr0")
    info=virsh("net-info",DEFAULT)
    # virsh aligns net-info values with variable whitespace:
    # "Active:          yes" is normal, not evidence of an inactive NAT.
    # Split once on the colon and trim both sides, as other working
    # SSL55 audits do. Never infer "active" from the network definition.
    fields={}
    for line in info.splitlines():
        key,sep,value=line.partition(":")
        if sep:
            key=key.strip().lower()
            need(key not in fields,"Duplicate net-info field: "+key)
            fields[key]=value.strip().lower()
    need(fields.get("name")==DEFAULT and
         fields.get("active")=="yes" and
         fields.get("bridge")=="virbr0",
         "Existing default NAT must be ACTIVE on bridge virbr0")
    return {"network":DEFAULT,"bridge":"virbr0",
            "ipv4_gateway":"192.168.122.1",
            "dhcp_network_present":True,
            "actual_guest_internet_verified":False}

def check_snapshot():
    names=[x.strip() for x in virsh("snapshot-list",VM,"--name").splitlines()
           if x.strip()]
    need(names==[SNAP],"Original captured candidate snapshot was changed")
    x=ET.fromstring(virsh("snapshot-dumpxml",VM,SNAP))
    mem=x.find("memory")
    need(x.tag=="domainsnapshot" and x.findtext("name")==SNAP and
         x.findtext("state")=="running" and mem is not None and
         mem.get("snapshot")=="internal" and
         sum(d.get("name")=="sda" and d.get("snapshot")=="internal"
             for d in x.findall("./disks/disk"))==1,
         "Expected pre-existing captured RAM+Windows disk missing")

def inspect(online=False):
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()==HOST,
         "Exact protected SSL55 root only")
    need(virsh("domuuid",VM).lower()==UID and
         virsh("domstate",VM).lower()=="running",
         "Clone UUID or running state changed")
    for name,uid in (MASTER,TRIAL):
        need(virsh("domuuid",name).lower()==uid and
             virsh("domstate",name).lower()=="shut off",
             "Protected source or trial changed")
    need(virsh("list","--name").splitlines()==[VM],
         "Unknown guest running")
    check_snapshot()
    source=domain(virsh("dumpxml","--inactive",MASTER[0]),*MASTER)
    need(len(source)==1 and source[0]["network"]==DEFAULT and
         source[0]["model"]=="e1000e",
         "Protected master network no longer same NAT/e1000e")
    expected=[{"mac":ANALYSIS_MAC,"model":"e1000e",
               "network":ISOLATED}]
    new={"mac":ONLINE_MAC,"model":"e1000e","network":DEFAULT}
    if online:expected.append(new)
    saved=domain(virsh("dumpxml","--inactive",VM),VM,UID)
    live=domain(virsh("dumpxml",VM),VM,UID)
    for actual,label in ((saved,"saved"),(live,"live")):
        need(len(actual)==len(expected) and
             sorted(actual,key=lambda n:n["mac"])==
             sorted(expected,key=lambda n:n["mac"]),
             "Unexpected "+label+" win11_1 NICs; do NOT auto-mutate")
    nat=check_online()
    # Dedicated offline bridge must remain entirely isolated; only
    # separate default NAT is used for trusted provisioning.
    xml=ET.fromstring(virsh("net-dumpxml",ISOLATED))
    br=xml.find("bridge")
    port=xml.find("port")
    need(xml.find("forward") is None and
         br is not None and br.get("name")=="cape-lab0" and
         port is not None and port.get("isolated")=="yes" and
         not xml.findall(".//dhcp") and
         not xml.findall(".//route"),
         "Original CAPE analysis bridge isolation changed")
    other=[n.strip() for n in virsh("list","--all","--name").splitlines()
           if n.strip() and n.strip()!=VM]
    for name in other:
        if virsh("domstate",name).lower()=="running":
            raise StagingBlocked("Another guest unexpectedly running: "+name)
        for nic in domain(virsh("dumpxml","--inactive",name),name,
                          virsh("domuuid",name).lower()):
            need(nic["mac"]!=ONLINE_MAC,
                 "Permanent NAT MAC would collide with an existing VM")
    return {"result":("SSL55_PERMANENT_MASTER_NAT_NIC_STAGED_VERIFIED"
                      if online else "SSL55_PERMANENT_MASTER_NAT_STAGE_PLAN_ONLY"),
            "vm":VM,"master_nat":nat,
            "planned_persistent_nat_mac":ONLINE_MAC,
            "saved_and_live_nics":saved,
            "master_trial_shut_off":True,
            "original_isolated_nic_preserved":True,
            "snapshot_preserved":SNAP,
            "persistent_nat_adapter_now_attached":online,
            "windows_static_192_168_240_101_still_needs_migration":True,
            "windows_dhcp_https_tested":False,
            "cape_new_ip_registered":False,
            "final_single_nic_reached":False,
            "final_running_snapshot_created":False,
            "swtpm_safe_restore_proven":False,
            "malware_analysis_allowed":False}

def stage():
    need(sys.stdin.isatty(),"Direct operator TTY required for permanent NIC")
    initial=inspect(False)
    print(json.dumps(initial,sort_keys=True,indent=2),flush=True)
    authorization="STAGE-PERSISTENT-NAT-WIN11_1-TRUSTED-SETUP-ONLY"
    need(input("Type "+authorization+" to stage new NAT NIC: ")==authorization,
         "Explicit benign-only staging approval missing")
    need(not LOCK.is_symlink(),"Unsafe staging lock")
    fd=os.open(LOCK,os.O_NOFOLLOW|os.O_CREAT|os.O_RDWR,0o600)
    attempted=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Untrusted staging lock metadata")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise StagingBlocked("Other persistent NAT operation active") from e
        need(inspect(False)==initial,
             "Host network/guest/snapshot changed after approval")
        attempted=True
        virsh("attach-interface",VM,"network",DEFAULT,
              "--mac",ONLINE_MAC,"--model","e1000e",
              "--live","--config",timeout=180)
        return inspect(True)
    except Exception as exc:
        if attempted:
            raise StagingBlocked(
                "PERSISTENT_NIC_ATTACH_ATTEMPTED_REVIEW_LIVE_AND_SAVED_XML: "
                "do not retry, reboot, or run malware; "+str(exc)) from exc
        raise
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","stage","verify"),default="plan")
    a=p.parse_args()
    try:
        report=(inspect(False) if a.mode=="plan" else
                inspect(True) if a.mode=="verify" else stage())
        print(json.dumps(report,sort_keys=True,indent=2),flush=True)
        return 0
    except (StagingBlocked,OSError,ValueError,TypeError,ET.ParseError,
            json.JSONDecodeError) as e:
        print(json.dumps({"result":"SSL55_PERSISTENT_MASTER_NAT_STAGE_BLOCKED",
              "reason":str(e),"snapshot_revert_attempted":False,
              "no_automatic_vm_restart_or_detach":True},
              sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
