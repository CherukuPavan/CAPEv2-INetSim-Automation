#!/usr/bin/env python3
"""SSL55: guarded BENIGN ONLY boot of existing win11_1.

Plan only inspects. boot-benign can ONLY call virsh start win11_1
after exact isolated NIC, guard, three protected VMs, active CAPE
bridge and operator approval. No other VM, snapshot, network, firewall,
Windows static IP or malware action is permitted.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0,"/usr/local/libexec/cape-command2")
import command2_ssl55_existing_guard_readonly as guard
import command2_ssl55_boot_persistence_readonly as boot

VM="win11_1"
UUID=guard.CLONE_UUID
MAC="02:0a:30:6a:3f:50"
NETWORK="cape-analysis-isolated"
BRIDGE="cape-lab0"
BRIDGE_IP="192.168.240.1"
IP="192.168.240.101"
DISK="/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2"
NVRAM="/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd"
LOCK=Path("/run/lock/cape-ssl55-win11-1-benign-boot.lock")
CONFIRM="BOOT-ISOLATED-WIN11_1-BENIGN-ONLY"


class BootBlocked(RuntimeError):
    pass


def require(ok, why):
    if not ok:raise BootBlocked(why)


def cmd(*args):
    try:
        p=subprocess.run(args,text=True,capture_output=True,
                         timeout=35,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise BootBlocked("Unable to query host: "+args[0]) from exc
    require(p.returncode==0,"Host command failed: "+args[0])
    return p.stdout.strip()


def virsh(*args):
    return cmd("virsh","-c","qemu:///system",*args)


def guest_xml(xml):
    try:root=ET.fromstring(xml)
    except ET.ParseError as exc:raise BootBlocked("VM XML malformed") from exc
    require(root.tag=="domain" and root.get("type")=="kvm" and
            root.findtext("name")==VM and root.findtext("uuid")==UUID,
            "Unexpected win11_1 identity")
    interfaces=root.findall("./devices/interface")
    require(len(interfaces)==1,"win11_1 must have exactly one NIC")
    i=interfaces[0]
    mac=i.find("mac"); src=i.find("source"); model=i.find("model")
    require(i.get("type")=="network" and
            src is not None and src.get("network")==NETWORK and
            mac is not None and mac.get("address","").lower()==MAC and
            model is not None and model.get("type")=="e1000e",
            "Wrong guest NIC model/MAC/network")
    disks=root.findall("./devices/disk[@device='disk']")
    require(len(disks)==1 and disks[0].get("type")=="file" and
            disks[0].find("source") is not None and
            disks[0].find("source").get("file")==DISK and
            disks[0].find("driver") is not None and
            disks[0].find("driver").get("type")=="qcow2" and
            root.findtext("./os/nvram")==NVRAM,
            "Clone disk or NVRAM changed unexpectedly")
    tpm=root.find("./devices/tpm/backend")
    require(tpm is not None and tpm.get("type")=="emulator" and
            tpm.get("version")=="2.0","Existing TPM2 missing/changed")
    return hashlib.sha256(xml.encode()).hexdigest()


def network_live():
    fields={}
    for line in virsh("net-info",NETWORK).splitlines():
        key,sep,val=line.partition(":")
        if sep: fields[key.strip().lower()]=val.strip().lower()
    require(fields.get("active")=="yes" and
            fields.get("autostart")=="no" and
            fields.get("persistent")=="yes" and
            fields.get("bridge")==BRIDGE,
            "CAPE isolated bridge is not active/manual")
    net=ET.fromstring(virsh("net-dumpxml",NETWORK))
    b=net.find("bridge"); port=net.find("port"); dns=net.find("dns")
    ips=net.findall("ip")
    require(net.tag=="network" and net.findtext("name")==NETWORK and
            b is not None and b.get("name")==BRIDGE and
            port is not None and port.get("isolated")=="yes" and
            dns is not None and dns.get("enable")=="no" and
            net.find("forward") is None and
            not net.findall(".//dhcp") and not net.findall(".//route") and
            len(ips)==1 and ips[0].get("address")==BRIDGE_IP and
            ips[0].get("netmask")=="255.255.255.0" and
            ips[0].get("family") in (None,"ipv4"),
            "CAPE bridge XML unexpectedly permits NAT/DHCP/DNS/IPv6/L2")
    try:
        a=json.loads(cmd("ip","-j","-4","addr","show","dev",BRIDGE))
        v6=json.loads(cmd("ip","-j","-6","addr","show","dev",BRIDGE))
    except (TypeError,ValueError) as exc:
        raise BootBlocked("Unreadable bridge IP address state") from exc
    require(type(a) is list and len(a)==1 and
            any(x.get("family")=="inet" and x.get("local")==BRIDGE_IP and
                x.get("prefixlen")==24 for x in a[0].get("addr_info",())),
            "CAPE bridge IPv4 address changed")
    require(type(v6) is list and not any(
            x.get("scope") in ("global","site")
            for link in v6 for x in link.get("addr_info",())),
            "CAPE bridge has global IPv6")


def verify_guard():
    host=socket.gethostname().split(".",1)[0].lower()
    require(host in ("ssl-55","cse-ssl-55") and
            guard.SENTINEL.is_dir() and not guard.SENTINEL.is_symlink(),
            "Protected SSL55 host marker/hostname differs")
    require(os.geteuid()==0,"Root required")
    unit=boot.parse_show(boot.read(
        "systemctl","show","--no-pager",
        "--property=LoadState,UnitFileState,ActiveState",
        "cape-analysis-guard.service"),"cape-analysis-guard.service")
    require(unit.get("load_state")=="loaded" and
            unit.get("unit_file_state")=="enabled" and
            unit.get("active_state")=="active","Guard unit not active")
    outcome=cmd("systemctl","show","--no-pager",
                "-p","Result","-p","ExecMainStatus","-p","ConditionResult",
                "cape-analysis-guard.service")
    require("Result=success" in outcome and
            "ExecMainStatus=0" in outcome and
            "ConditionResult=yes" in outcome,
            "Dedicated guard service not successful in current boot")
    default=boot.parse_show(boot.read(
        "systemctl","show","--no-pager",
        "--property=LoadState,UnitFileState,ActiveState",
        "nftables.service"),"nftables.service")
    require(default.get("unit_file_state")=="disabled" and
            default.get("active_state")=="inactive",
            "General nftables.service changed")
    guard.guard_policy_structure(
        cmd("nft","-j","list","table","inet",guard.TABLE),
        cmd("nft","list","table","inet",guard.TABLE))


def preflight():
    verify_guard()
    network_live()
    require(virsh("domuuid",VM).lower()==UUID and
            virsh("domstate",VM).strip()=="shut off",
            "Existing win11_1 is not the approved shut-off clone")
    fingerprint=guest_xml(virsh("dumpxml","--inactive",VM))
    for name,uid,nics in (
        ("win11",guard.MASTER_UUID,1),
        ("win11_trial_1",guard.TRIAL_UUID,0)):
        require(virsh("domuuid",name).lower()==uid and
                virsh("domstate",name).strip()=="shut off" and
                boot.domain_autostart(name) is False,
                "Protected master/trial identity/state/autostart changed")
        xml=ET.fromstring(virsh("dumpxml","--inactive",name))
        require(xml.findtext("name")==name and xml.findtext("uuid")==uid
                and len(xml.findall("./devices/interface"))==nics,
                "Protected master/trial saved NIC configuration changed")
    require(boot.domain_autostart(VM) is False,
            "win11_1 autostart unexpectedly enabled")
    require(not virsh("list","--name").strip(),
            "Another libvirt guest is running")
    require(not virsh("snapshot-list",VM,"--name").strip(),
            "Unexpected snapshot exists on win11_1")
    return {"result":"SSL55_WIN11_1_BENIGN_BOOT_PLAN_ONLY",
            "guest":VM,"uuid":UUID,"mac":MAC,"bridge":BRIDGE,
            "vm_saved_xml_sha256":fingerprint,
            "guest_ipv4_target":IP,"vm_shutoff":True,
            "guest_booted":False,
            "guest_windows_static_ipv4_verified":False,
            "guest_external_ipv4_egress_tested":False,
            "guest_external_ipv6_egress_tested":False,
            "cape_agent_verified":False,
            "running_snapshot_created":False,
            "malware_analysis_authorized":False,
            "host_changes":False}


def boot_benign():
    require(os.geteuid()==0 and sys.stdin.isatty(),
            "Root interactive shell required")
    before=preflight()
    require(input("Type "+CONFIRM+" to boot win11_1 for benign checks: ")==CONFIRM,
            "Operator declined benign-only boot")
    require(not LOCK.is_symlink(),"Unsafe root boot lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    started=False
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
                stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,
                "Unsafe root lock metadata")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(preflight()==before,
                "Guest/network/guard changed while waiting")
        virsh("start",VM)
        started=True
        require(virsh("domstate",VM).strip()=="running",
                "win11_1 failed to enter running state")
        guest_xml(virsh("dumpxml",VM))
        require(virsh("domuuid",VM).lower()==UUID and
                boot.domain_autostart(VM) is False,
                "Live guest UUID/autostart changed")
        for name in ("win11","win11_trial_1"):
            require(virsh("domstate",name).strip()=="shut off",
                    "Protected master/trial unexpectedly started")
        network_live()
        require(virsh("list","--name").splitlines()==[VM],
                "Unexpected other VM active after guest boot")
        return {"result":"SSL55_WIN11_1_RUNNING_BENIGN_ONLY_NO_ANALYSIS",
                "guest":VM,"uuid":UUID,"network":NETWORK,
                "mac":MAC,"guest_ipv4_target":IP,
                "power_state":"running","master_trial_still_shutoff":True,
                "windows_static_ip_verified":False,
                "ipv4_ipv6_external_egress_tested":False,
                "cape_agent_checked":False,
                "running_snapshot_captured":False,
                "malware_execution_authorized":False,
                "next":"Use Windows console for trusted offline configuration and benign IPv4/IPv6 checks."}
    except Exception as exc:
        raise BootBlocked(
            ("PARTIAL: guest may be RUNNING. DO NOT repeat or restart. "
             if started else "BLOCKED before boot: ")+str(exc)) from exc
    finally:os.close(fd)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode",choices=("plan","boot-benign"),default="plan")
    a=ap.parse_args()
    try:
        result=preflight() if a.mode=="plan" else boot_benign()
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except (BootBlocked,guard.AuditBlocked,boot.BootBlocked,
            ET.ParseError,OSError,ValueError,TypeError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
