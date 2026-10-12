#!/usr/bin/env python3
"""SSL55 exact post-OVMF-transition benign Windows boot: guarded and paused.

Only win11_1; requires protected source/trial OFF, verified saved QCOW2
firmware and original XML, already-installed persistent isolated network
guard. Boot --paused, inspect LIVE isolated devices, resume if safe, then
attempt only read-only CAPE Agent HTTP. No snapshot, force stop or malware.
An agent timeout leaves the VM running for review; NEVER blindly retry.
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
import time
import xml.etree.ElementTree as ET

import command2_ssl55_activate_qcow2_ovmf as activation
import command2_ssl55_win11_1_benign_boot as oldboot
import command2_cape_agent_probe as agent

VM=activation.VM
UID=activation.UID
LOCK=Path("/run/lock/cape-ssl55-win11-1-qcow2-benign-boot.lock")
IP="192.168.240.101"

class BootBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise BootBlocked(why)

def virsh(*args,timeout=120):
    try:
        result=subprocess.run(["virsh","-c","qemu:///system",*args],
                              capture_output=True,text=True,check=False,
                              timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise BootBlocked("libvirt command missing or timed out: "+args[0]) from exc
    need(result.returncode==0,"libvirt refused: "+args[0])
    return result.stdout.strip()

def read_xml(raw,*,expected_state):
    root=ET.fromstring(raw)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==VM and root.findtext("uuid")==UID,
         "Unexpected running/saved guest identity")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].find("source") is not None and
         disks[0].find("source").get("file")==str(activation.ref.DISK) and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2",
         "Unexpected Windows disk")
    chain=disks[0].find("backingStore")
    need(chain is None or (chain.find("source") is None and
                          chain.find("backingStore") is None),
         "Unexpected master backing chain in guest XML")
    nv=root.find("./os/nvram")
    need(nv is not None and nv.text==str(activation.SIDE) and
         nv.get("format")=="qcow2",
         "Unexpected EFI variables in guest XML")
    tpm=root.find("./devices/tpm/backend")
    need(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0","Expected independent TPM2 absent")
    net=root.findall("./devices/interface")
    need(len(net)==1 and net[0].get("type")=="network" and
         net[0].find("source") is not None and
         net[0].find("source").get("network")=="cape-analysis-isolated" and
         net[0].find("mac") is not None and
         net[0].find("mac").get("address","").lower()=="02:0a:30:6a:3f:50",
         "Unexpected analysis VM NIC")
    for tag in ("hostdev","filesystem","redirdev","channel","shmem","vsock"):
        need(not root.findall("./devices/"+tag),
             "Unapproved host-connected VM device: "+tag)
    return {"vm":VM,"uuid":UID,
            "disk":str(activation.ref.DISK),
            "nvram":str(activation.SIDE),
            "nic_mac":"02:0a:30:6a:3f:50",
            "readback_state":expected_state}

def preflight(backup_dir):
    need(socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55" and
         os.geteuid()==0,"Only protected SSL55 root execution is permitted")
    verified=activation.plan(backup_dir,mode="verify")
    # Existing on-host policy checker also validates nft, dedicated
    # guard unit, libvirt network, non-forwarding/DHCP and persistence.
    oldboot.verify_guard()
    oldboot.network_live()
    need(not virsh("list","--name").strip(),
         "Another libvirt guest already running; refuse concurrent first boot")
    need(virsh("domstate",VM).lower()=="shut off",
         "Only already SHUT OFF win11_1 can be booted")
    saved=virsh("dumpxml","--inactive",VM)
    read_xml(saved,expected_state="shut off")
    need(not virsh("snapshot-list",VM,"--name").strip(),
         "Existing snapshot already present; do not boot for first snapshot")
    need(oldboot.boot.domain_autostart(VM) is False,
         "Clone autostart unexpectedly enabled")
    for name,uid in (activation.ref.MASTER,activation.ref.TRIAL):
        need(virsh("domstate",name).lower()=="shut off" and
             virsh("domuuid",name).lower()==uid,
             "Protected original/trial unexpectedly changed")
    return {"result":"SSL55_WIN11_1_QCOW2_FIRST_BENIGN_BOOT_PLAN_ONLY",
            "vm":VM,"uuid":UID,"firmware_verified":True,
            "original_xml_backup_sha256":
                verified["backup_original_xml_sha256"],
            "saved_domain_xml_sha256":hashlib.sha256(saved.encode()).hexdigest(),
            "isolated_network_and_guard_readback":True,
            "all_three_guests_off":True,
            "snapshot_created":False,"guest_booted":False,
            "swtpm_revert_proven":False,"malware_authorized":False}

def first_boot(backup_dir):
    need(sys.stdin.isatty(),"Interactive terminal required for clone-only boot")
    original=preflight(backup_dir)
    print(json.dumps(original,sort_keys=True,indent=2),flush=True)
    phrase="BOOT-SSL55-WIN11_1-QCOW2-BENIGN"
    need(input("Type "+phrase+" to boot ONLY this Windows clone: ")==phrase,
         "Boot authorization not given")
    need(not LOCK.is_symlink(),"Untrusted guest boot lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    started=False
    resumed=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1
             and stat.S_IMODE(st.st_mode)==0o600,
             "Unsafe global boot lock metadata")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BootBlocked("Another boot already running") from exc
        need(preflight(backup_dir)==original,
             "Firmware/VM/network changed since boot authorization")
        virsh("start",VM,"--paused",timeout=180)
        started=True
        current=virsh("domstate",VM).lower()
        need(current.startswith("paused"),
             "VM started but not paused; inspect, do not destroy/reset")
        read_xml(virsh("dumpxml",VM),expected_state="paused")
        oldboot.verify_guard()
        oldboot.network_live()
        for name,_ in (activation.ref.MASTER,activation.ref.TRIAL):
            need(virsh("domstate",name).lower()=="shut off",
                 "Protected master/trial started unexpectedly")
        virsh("resume",VM,timeout=60)
        resumed=True
        need(virsh("domstate",VM).lower()=="running",
             "VM did not enter RUNNING state after approved resume")
        read_xml(virsh("dumpxml",VM),expected_state="running")
    except Exception as exc:
        state="unknown"
        try:state=virsh("domstate",VM)
        except Exception:pass
        raise BootBlocked("PARTIAL_VM_STATE_REVIEW_REQUIRED: "+
                          f"state={state}, paused_start={started}, "
                          f"resumed={resumed}. No force shutdown or retry. "
                          +str(exc)) from exc
    finally:
        os.close(fd)
    # Agent is strictly read-only and failure never triggers VM restart.
    detail=None
    last=None
    for _ in range(24):
        try:
            detail=agent.probe_agent(IP)
            break
        except (agent.AgentBlocked,OSError,ValueError) as exc:
            last=str(exc)
        time.sleep(5)
    return {"result":("SSL55_WIN11_1_QCOW2_BOOT_AND_CAPE_AGENT_OK" if detail
                      else "SSL55_WIN11_1_QCOW2_BOOT_AGENT_NOT_YET_READY"),
            "vm":VM,"vm_running_after_boot":virsh("domstate",VM).lower()=="running",
            "original_master_and_trial_off":
                all(virsh("domstate",v).lower()=="shut off"
                    for v,_ in (activation.ref.MASTER,activation.ref.TRIAL)),
            "agent_probe":detail,"agent_probe_last_failure":last if not detail else None,
            "snapshot_created":False,"TPM_rollback_proven":False,
            "no_automatic_vm_shutdown_or_retry":True,
            "malware_analysis_approved":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","boot-benign"),default="plan")
    p.add_argument("--xml-backup-dir",required=True,type=Path)
    a=p.parse_args()
    try:
        report=(preflight(a.xml_backup_dir) if a.mode=="plan" else
                first_boot(a.xml_backup_dir))
        print(json.dumps(report,sort_keys=True,indent=2),flush=True)
        return 0 if report.get("agent_probe_last_failure") is None else 2
    except (BootBlocked,activation.TransitionBlocked,
            activation.prep.SSL55PrepareBlocked,
            oldboot.BootBlocked,oldboot.guard.AuditBlocked,
            oldboot.boot.BootBlocked,agent.AgentBlocked,
            OSError,ValueError,TypeError,ET.ParseError) as exc:
        print(json.dumps({"result":"SSL55_QCOW2_BENIGN_BOOT_BLOCKED",
            "reason":str(exc),
            "never_auto_reset_or_retry":True},sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
