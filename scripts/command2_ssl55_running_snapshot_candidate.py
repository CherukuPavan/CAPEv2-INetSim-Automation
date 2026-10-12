#!/usr/bin/env python3
"""Guarded SSL55 win11_1 RUNNING snapshot candidate (NOT CAPE-approved).

The live guest has previously booted from its QCOW2 OVMF sidecar. Use only
a separate 'cape_candidate_win11_1' NAME until TPM-safe revert is proven.
The experiment can change the running clone's QCOW2 snapshot state; unlike
the read-only plan it needs per-run typed authorization. No snapshot revert,
forced shutdown, CAPE registration or malware execution is included.

CAPE needs memory+disk state, but libvirt does not independently snapshot
swtpm persistent state. This tool NEVER declares a capture CAPE-ready.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

import command2_ssl55_activate_qcow2_ovmf as transition
import command2_ssl55_scoped_nvram_sidecar as prep
import command2_ssl55_win11_1_benign_boot as hostguard
import command2_cape_agent_probe as agent
import command2_native_snapshot_stack_guard as native

VM="win11_1"
UID="732b2256-ee99-41fa-881d-fbf5c476d960"
SNAP="cape_candidate_win11_1"
SAVE_SHA="791b263b34a45b9212561228c4c771652f32cac458f88bf29e5d42b9758d48e6"
ROOT_BACKUP=Path("/var/lib/libvirt/qemu/nvram/cape_win11_1_xml_backup_nRWa8wUO")
LOCK=Path("/run/lock/cape-ssl55-win11-1-snapshot-candidate.lock")
MIN_RESERVE=40*1024**3
EXPECTED_IP="192.168.240.101"
class SnapshotCandidateBlocked(RuntimeError):pass
def need(ok,message):
    if not ok:raise SnapshotCandidateBlocked(message)

def cmd(*args,timeout=60):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,
                         check=False)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise SnapshotCandidateBlocked("Host command missing/timeout: "+args[0]) from e
    need(p.returncode==0,"Host command returned failure: "+args[0])
    need(len(p.stdout)<2_000_000,"Host command returned excessive output")
    return p.stdout.strip()

def virsh(*args,timeout=60):
    return cmd("virsh","-c","qemu:///system",*args,timeout=timeout)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def check_critical_live(saved,live):
    a=ET.fromstring(saved);b=ET.fromstring(live)
    for root in (a,b):
        need(root.tag=="domain" and root.get("type")=="kvm" and
             root.findtext("name")==VM and root.findtext("uuid")==UID,
             "Domain does not match protected clone")
        nv=root.find("./os/nvram")
        need(nv is not None and nv.get("format")=="qcow2" and
             nv.text==str(transition.SIDE),
             "QCOW2 UEFI sidecar no longer active")
        loader=root.find("./os/loader")
        need(loader is not None and loader.get("type")=="pflash",
             "UEFI loader not reviewed")
        disk=root.findall("./devices/disk[@device='disk']")
        need(len(disk)==1 and disk[0].find("driver") is not None and
             disk[0].find("driver").get("type")=="qcow2" and
             disk[0].find("source") is not None and
             disk[0].find("source").get("file")==str(transition.ref.DISK),
             "OS disk is not independent expected QCOW2")
        backing=disk[0].find("backingStore")
        need(backing is None or (backing.find("source") is None and
              backing.find("backingStore") is None),
             "Unexpected libvirt disk backing image")
        tpm=root.find("./devices/tpm/backend")
        need(tpm is not None and tpm.get("type")=="emulator" and
             tpm.get("version")=="2.0","Exact emulated TPM2 not found")
        nets=root.findall("./devices/interface")
        need(len(nets)==1 and nets[0].get("type")=="network" and
             nets[0].find("source") is not None and
             nets[0].find("source").get("network")=="cape-analysis-isolated" and
             nets[0].find("mac") is not None and
             nets[0].find("mac").get("address","").lower()=="02:0a:30:6a:3f:50",
             "Unexpected guest NIC")
        for tag in ("hostdev","filesystem","redirdev","channel","shmem","vsock"):
            need(not root.findall("./devices/"+tag),
                 "Host-connected unsafe VM device present")
    # libvirt changes certain READ-ONLY device attributes at VM startup:
    # disk source gains block graph index, and a network interface source
    # may gain bridge / portid metadata. Whitelist ONLY these known runtime
    # fields. Never skip validation of the exact storage, OVMF, TPM,
    # isolated network, NIC MAC, or UEFI loader in either view.
    volatile=[]
    for xpath in ("./devices/disk[@device='disk']/source",
                  "./os/nvram","./devices/interface/mac",
                  "./devices/interface/source",
                  "./devices/tpm/backend","./os/loader"):
        va=a.find(xpath);vb=b.find(xpath)
        need(va is not None and vb is not None,
             "Missing expected device in live/saved VM: "+xpath)
        left=dict(va.attrib);right=dict(vb.attrib)
        need((va.text or "").strip()==(vb.text or "").strip(),
             "Critical device TEXT/path differs in live/saved VM: "+xpath)
        if xpath=="./devices/disk[@device='disk']/source":
            need(set(left)=={"file"} and
                 set(right).issubset({"file","index"}) and
                 left["file"]==right["file"]==str(transition.ref.DISK),
                 "Unexpected live/saved disk source attributes or path")
            if "index" in right:
                need(right["index"].isdigit() and
                     0<=int(right["index"])<=256,
                     "Invalid live QEMU block graph disk index")
                volatile.append("running.disk_source.index")
        elif xpath=="./devices/interface/source":
            need(left=={"network":"cape-analysis-isolated"} and
                 right.get("network")=="cape-analysis-isolated" and
                 set(right).issubset({"network","bridge","portid"}),
                 "Unreviewed isolated NIC source/portgroup attributes")
            if "bridge" in right:
                need(right["bridge"]=="cape-lab0",
                     "Live NIC bridge is NOT exact isolated cape-lab0")
                volatile.append("running.nic_source.bridge")
            if "portid" in right:
                try:
                    port_uuid=uuid.UUID(right["portid"])
                except (ValueError,TypeError,AttributeError) as exc:
                    raise SnapshotCandidateBlocked(
                        "Live network port identifier invalid") from exc
                need(str(port_uuid)==right["portid"].lower(),
                     "Noncanonical network port UUID")
                volatile.append("running.nic_source.portid")
        elif xpath=="./devices/interface/mac":
            need(left==right=={"address":"02:0a:30:6a:3f:50"},
                 "Critical guest NIC MAC attributes changed")
        else:
            need(left==right,
                 "Critical device attributes differ in live/saved VM: "+xpath)
    return {"critical_devices_match":True,
            "only_documented_runtime_xml_metadata":sorted(volatile),
            "disk_file_nvram_file_nic_network_mac_tpm_loader_bound":True}

def inspect():
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Snapshot experiment allowed only for exact protected SSL55 root")
    need(virsh("domuuid",VM).lower()==UID and
         virsh("domstate",VM).lower()=="running",
         "Exact clone must already be RUNNING")
    for vm,uid in (transition.ref.MASTER,transition.ref.TRIAL):
        need(virsh("domuuid",vm).lower()==uid and
             virsh("domstate",vm).lower()=="shut off",
             "Protected source master/trial power or identity changed")
    names=virsh("snapshot-list",VM,"--name").splitlines()
    need(not [x for x in names if x.strip()],
         "Snapshot metadata already exists; no duplicate capture/retry")
    need(virsh("list","--name").splitlines()==[VM],
         "An unexpected other guest is running")
    saved=virsh("dumpxml","--inactive",VM)
    need(sha(saved.encode())==SAVE_SHA,
         "Exact previously activated saved XML changed")
    live=virsh("dumpxml",VM)
    xml_compat=check_critical_live(saved,live)
    # The prior original RAW NVRAM is not writable by this tool and must
    # remain unchanged after the isolated QCOW2-sidecar Windows boot.
    need(prep.sha256(transition.RAW)==transition.RAW_SHA,
         "Previously preserved RAW OVMF contents changed")
    backup=ROOT_BACKUP/transition.BACKUP_FILE
    need(backup.is_file() and not backup.is_symlink() and
         backup.stat().st_uid==0 and
         stat.S_IMODE(backup.stat().st_mode)==0o600 and
         backup.stat().st_nlink==1 and
         sha(backup.read_bytes())==transition.XML_SHA,
         "Original stopped libvirt XML recovery copy missing or altered")
    # Must not call transition.plan: it compares the now LIVE-mutated
    # QCOW2 UEFI sidecar to an old RAW copy and will falsely reject.
    cold=prep.verify_existing_bundle()
    need(cold["manifest_sha256"]==transition.MANIFEST_SHA and
         cold["byte_verified_member_count"]==3,
         "Existing stopped full disk+OVMF+swtpm recovery bytes changed")
    ver=native.parse_versions(virsh("version","--daemon"))
    meta=json.loads(cmd("qemu-img","info","-U","--output=json",
                        str(transition.SIDE)))
    need(meta.get("format")=="qcow2" and
         not meta.get("backing-filename"),
         "Live NVRAM sidecar not standalone QCOW2")
    diskmeta=json.loads(cmd("qemu-img","info","-U","--output=json",
                            str(transition.ref.DISK)))
    need(diskmeta.get("format")=="qcow2" and
         not diskmeta.get("backing-filename"),
         "Live guest OS image not standalone QCOW2")
    tpm_path=transition.ref.TPM
    need(tpm_path.is_dir() and not tpm_path.is_symlink() and
         any(f.is_file() and not f.is_symlink() and f.name.endswith(".permall")
             for f in tpm_path.iterdir()),
         "Emulated TPM state missing")
    hostguard.verify_guard()
    hostguard.network_live()
    memory=ET.fromstring(saved).find("memory")
    need(memory is not None and memory.get("unit") in ("KiB","MiB","GiB")
         and memory.text and memory.text.isdecimal(),
         "VM memory unit or size unexpected")
    mem=int(memory.text)*{"KiB":1024,"MiB":1024**2,"GiB":1024**3}[memory.get("unit")]
    need(2*1024**3<=mem<=32*1024**3,
         "Unexpected guest memory: conservative capture limit")
    f=os.statvfs(transition.ref.DISK.parent)
    free=f.f_bavail*f.f_frsize
    need(free>MIN_RESERVE+2*mem+2*1024**3,
         "Insufficient storage headroom for memory snapshot and host reserve")
    # CAPE Agent from the host, read-only, no test samples.
    agent_info=agent.probe_agent(EXPECTED_IP)
    need(agent_info["result"]=="COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
         "Windows CAPE agent not ready")
    # --print-xml is explicitly a *preview*, NOT a snapshot or proof
    # that libvirt/QEMU will accept the requested live capture.
    preview=virsh("snapshot-create-as","--domain",VM,"--name",SNAP,
                  "--print-xml")
    snapshot_preview=ET.fromstring(preview)
    need(snapshot_preview.tag=="domainsnapshot" and
         snapshot_preview.findtext("name")==SNAP,
         "Snapshot preview failed or differs from requested candidate")
    return {"result":"SSL55_RUNNING_SNAPSHOT_CANDIDATE_PLAN_ONLY",
            "vm":VM,"vm_state":"running","candidate_name":SNAP,
            "protected_master_trial_shut_off":True,
            "verified_cold_recovery_member_count":3,
            "saved_xml_sha256":SAVE_SHA,
            "snapshot_preview_sha256":sha(preview.encode()),
            "free_gib":round(free/1024**3,2),
            "guest_memory_gib":round(mem/1024**3,2),
            "agent_version":agent_info["version"],
            "host_policy_readback_passed":True,
            **xml_compat,
            **ver,
            "snapshot_created":False,
            "swtpm_consistent_restore_proven":False,
            "safe_for_Cape_samples":False,
            "actual_live_snapshot_support_unproven":True,
            "host_or_guest_modified":False}

def capture_candidate():
    need(sys.stdin.isatty(),"Direct TTY required for physical candidate snapshot")
    first=inspect()
    print(json.dumps(first,indent=2,sort_keys=True),flush=True)
    phrase="CAPTURE-SSL55-BENIGN-TPM-UNPROVEN-CANDIDATE"
    need(input("Type "+phrase+" ONLY to attempt running candidate snapshot: ")==
         phrase,"No explicit snapshot experiment approval")
    need(not LOCK.is_symlink(),"Unsafe snapshot global lock path")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    attempted=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Untrusted snapshot lock permissions")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SnapshotCandidateBlocked("Snapshot experiment already running") from exc
        rechecked=inspect()
        # Snapshot XML preview can contain a NEW creation timestamp and
        # filesystem free-space naturally fluctuates. Both independent
        # inspections already apply the strict safety gates; compare only
        # stable identity/version data rather than volatile report fields.
        stable=("vm","candidate_name","saved_xml_sha256",
                "protected_master_trial_shut_off",
                "verified_cold_recovery_member_count",
                "libvirt_daemon_version","qemu_hypervisor_version",
                "host_policy_readback_passed")
        need(all(rechecked[key]==first[key] for key in stable),
             "Guest identity, software stack or recovery proof changed")
        attempted=True
        virsh("snapshot-create-as","--domain",VM,"--name",SNAP,
              "--atomic",timeout=1800)
        meta=virsh("snapshot-dumpxml",VM,SNAP)
        root=ET.fromstring(meta)
        mem=root.find("memory")
        disks=root.findall("./disks/disk")
        need(root.tag=="domainsnapshot" and
             root.findtext("name")==SNAP and
             root.findtext("state")=="running" and
             mem is not None and mem.get("snapshot")=="internal" and
             len(disks)>=1 and
             any(d.get("snapshot")=="internal" for d in disks),
             "Snapshot present but no verified running INTERNAL memory/disk; "
             "do not delete or retry")
        need(virsh("domstate",VM).lower()=="running",
             "Guest unexpectedly not running after snapshot")
        again=agent.probe_agent(EXPECTED_IP)
        need(again["result"]=="COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
             "Agent failed after capture; candidate may exist, no retry")
        return {"result":"SSL55_RUNNING_SNAPSHOT_CANDIDATE_CAPTURED_ONLY",
                "snapshot":SNAP,"guest_state":"running",
                "memory_internal":True,"disk_internal":True,
                "agent_admin_http_after_capture":True,
                "TPM_consistent_restore_verified":False,
                "CAPE_READY":False,"malware_analysis_authorized":False,
                "snapshot_revert_attempted":False,
                "requires_separate_recovery_proof":True}
    except Exception as exc:
        if attempted:
            raise SnapshotCandidateBlocked(
                "CAPTURE_ATTEMPTED_VM_STATE_MUST_BE_REVIEWED. No auto-retry, "
                "rollback, snapshot-delete or poweroff. "+str(exc)) from exc
        raise
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","capture-candidate"),default="plan")
    args=p.parse_args()
    try:
        result=inspect() if args.mode=="plan" else capture_candidate()
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except (SnapshotCandidateBlocked,
            transition.TransitionBlocked,prep.SSL55PrepareBlocked,
            hostguard.BootBlocked,hostguard.guard.AuditBlocked,
            hostguard.boot.BootBlocked,agent.AgentBlocked,
            native.NativeBlocked,ValueError,TypeError,ET.ParseError,
            OSError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({"result":"SSL55_SNAPSHOT_CANDIDATE_BLOCKED",
            "reason":str(exc),"do_not_run_revert_or_malware":True,
            "no_automatic_vm_recovery":True},sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
