#!/usr/bin/env python3
"""Read-only SSL55 postcapture audit for the REAL win11_1 running snapshot.

Existing snapshot cape_candidate_win11_1 was created 2026-10-12. This tool
does NOT capture, revert, rename, delete, pause, stop, start, clone, register
CAPE, modify swtpm/NVRAM or run any guest command. Proves disk+RAM snapshot
metadata and records whether QEMU exposes independent NVRAM snapshot IDs.
TPM state is NOT included in libvirt memory/disk snapshots. Any report
that treats a running snapshot as 'CAPE_READY' without real TPM-consistent
recovery is unsafe.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

import command2_ssl55_running_snapshot_candidate as candidate
import command2_ssl55_activate_qcow2_ovmf as transition
import command2_ssl55_scoped_nvram_sidecar as prep
import command2_ssl55_win11_1_benign_boot as hostguard
import command2_cape_agent_probe as agent

VM=candidate.VM
UUID=candidate.UID
SNAP=candidate.SNAP
SIDE=transition.SIDE
RAW=transition.RAW
DISK=transition.ref.DISK
TPM=transition.ref.TPM
BACKUP=candidate.ROOT_BACKUP/transition.BACKUP_FILE
MIN_RESERVE=40*1024**3
class PostcaptureBlocked(RuntimeError):pass
def need(ok,reason):
    if not ok:raise PostcaptureBlocked(reason)

def command(*args,timeout=30):
    try:
        p=subprocess.run(args,capture_output=True,text=True,check=False,
                         timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise PostcaptureBlocked("Host read-only command unavailable: "+args[0]) from e
    need(p.returncode==0 and len(p.stdout)<2_000_000,
         "Read-only command failed or oversized: "+args[0])
    return p.stdout.strip()

def virsh(*args):
    return command("virsh","-c","qemu:///system",*args)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def safe_snapshot_metadata(raw):
    root=ET.fromstring(raw)
    need(root.tag=="domainsnapshot" and
         root.findtext("name")==SNAP and root.findtext("state")=="running",
         "Candidate was not captured as a RUNNING snapshot")
    memory=root.find("memory")
    need(memory is not None and memory.get("snapshot")=="internal",
         "Memory is not an internal RUNNING snapshot")
    disks=root.findall("./disks/disk")
    need(len(disks)>=1,"Snapshot has no explicit disk metadata")
    internal=[d for d in disks if d.get("snapshot")=="internal"]
    need(len(internal)>=1,"No internal disk snapshot")
    # This exact SSL55 clone exposes its Windows system disk as sda.
    # An internal snapshot on a different device (such as NVRAM alone)
    # must NEVER be mistaken for a verified Windows OS-disk checkpoint.
    need(sum(d.get("name")=="sda" and d.get("snapshot")=="internal"
             for d in disks)==1,
         "Exact Windows OS disk sda not present as one INTERNAL snapshot")
    need(len({d.get("name") for d in disks})==len(disks),
         "Duplicate snapshot disk entries: manual review")
    # Never infer that NVRAM or swtpm state was snapshotted just because
    # the guest OS disk was captured with internal memory.
    dom=root.find("domain")
    need(dom is not None and dom.findtext("uuid")==UUID and
         dom.findtext("name")==VM,
         "Snapshot metadata lacks exact saved domain/VM identity")
    return {"snapshot_name":SNAP,
            "snapshot_state_at_creation":"running",
            "memory_snapshot":"internal",
            "disk_entries":len(disks),
            "internal_disk_entries":len(internal),
            "snapshot_disk_names":[d.get("name") for d in disks],
            "snapshot_domain_uuid":UUID,
            "snapshot_metadata_sha256":digest(raw.encode()),
            "metadata_proves_tpm_state_restoration":False}

def qcow_info(path):
    p=Path(path)
    need(p.is_file() and not p.is_symlink(),
         "Approved QCOW2 guest storage source not present")
    data=json.loads(command("qemu-img","info","-U","--output=json",str(p),
                            timeout=90))
    need(type(data) is dict and data.get("format")=="qcow2" and
         not data.get("backing-filename"),
         "On-disk guest storage has unapproved backing or wrong format")
    snaplist=data.get("snapshots",[])
    need(type(snaplist) is list and len(snaplist)<=128,
         "Unexpected QEMU internal snapshot enumeration")
    names=[]
    for snap in snaplist:
        need(type(snap) is dict and
             type(snap.get("name")) is str and
             len(snap["name"])<128,
             "Malformed QEMU snapshot inventory")
        names.append(snap["name"])
    return {"format":"qcow2","standalone":True,
            "virtual_size_bytes":data.get("virtual-size"),
            "internal_snapshot_names":names,
            "candidate_snapshot_present_in_image":SNAP in names}

def tpm_structure():
    need(TPM.is_dir() and not TPM.is_symlink(),
         "Expected independent TPM state directory missing")
    members=[]
    for p in sorted(TPM.iterdir()):
        need(p.is_file() and not p.is_symlink() and
             re.fullmatch(r"[A-Za-z0-9_.-]{1,128}",p.name) is not None,
             "Unexpected independent swtpm directory entry")
        st=p.stat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,
             "Unsafe swtpm state file metadata")
        members.append({"name":p.name,"size_bytes":st.st_size})
    need(any(x["name"].endswith(".permall") for x in members),
         "Expected swtpm permanent state missing")
    return {"path":str(TPM),
            "files_metadata_only":members,
            "file_content_copied_or_hashed_while_running":False,
            "swtpm_persistent_state_in_libvirt_snapshot":False,
            "rollback_compatible_swtpm_checkpoint_found":False}

def assess():
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "READ-ONLY SSL55 audit restricted to exact protected host/root")
    need(virsh("domuuid",VM).lower()==UUID and
         virsh("domstate",VM).lower()=="running",
         "Expected exact clone to remain running after capture")
    for name,uid in (transition.ref.MASTER,transition.ref.TRIAL):
        need(virsh("domuuid",name).lower()==uid and
             virsh("domstate",name).lower()=="shut off",
             "Protected master/trial state or UUID differs")
    need(virsh("list","--name").splitlines()==[VM],
         "Unexpected other VM active")
    listed=[n.strip() for n in virsh("snapshot-list",VM,"--name").splitlines()
            if n.strip()]
    need(listed==[SNAP],
         "Expected exactly one unmodified candidate snapshot; STOP")
    snapshot=safe_snapshot_metadata(virsh("snapshot-dumpxml",VM,SNAP))
    saved=virsh("dumpxml","--inactive",VM)
    live=virsh("dumpxml",VM)
    need(digest(saved.encode())==candidate.SAVE_SHA,
         "Saved VM XML changed since approved post-OVMF boot")
    graph=candidate.check_critical_live(saved,live)
    need(graph["critical_devices_match"] is True,
         "Critical saved/live disk/TPM/UEFI/NIC identity changed")
    need(BACKUP.is_file() and not BACKUP.is_symlink() and
         BACKUP.stat().st_uid==0 and
         stat.S_IMODE(BACKUP.stat().st_mode)==0o600 and
         BACKUP.stat().st_nlink==1 and
         digest(BACKUP.read_bytes())==transition.XML_SHA,
         "Approved original libvirt XML recovery differs")
    need(prep.sha256(RAW)==transition.RAW_SHA,
         "Protected original RAW OVMF unexpectedly changed")
    prior=prep.verify_existing_bundle()
    need(prior["manifest_sha256"]==transition.MANIFEST_SHA and
         prior["byte_verified_member_count"]==3,
         "Independent cold disk/OVMF/swtpm backup changed")
    hostguard.verify_guard()
    hostguard.network_live()
    diskinfo=qcow_info(DISK)
    fwinfo=qcow_info(SIDE)
    tpm=tpm_structure()
    free=os.statvfs(DISK.parent)
    available=free.f_bavail*free.f_frsize
    need(available>=MIN_RESERVE,
         "Protected 40GiB host free-space reserve not met")
    cap=agent.probe_agent(candidate.EXPECTED_IP)
    need(cap.get("result")=="COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
         "CAPE Agent no longer reports admin HTTP readiness")
    candidate_in_os=diskinfo["candidate_snapshot_present_in_image"]
    return {"result":"SSL55_SNAPSHOT_POSTCAPTURE_READONLY_COMPLETE",
            "vm":VM,"uuid":UUID,"state":"running",
            "snapshot":snapshot,"snapshot_in_os_disk_image":candidate_in_os,
            "snapshot_in_uefi_image":
               fwinfo["candidate_snapshot_present_in_image"],
            "guest_os_disk_qcow2":diskinfo,
            "uefi_qcow2":fwinfo,
            "swtpm":tpm,"critical_domain":graph,
            "cold_bundle_members_rehashed":3,
            "host_guard_and_isolated_network_present":True,
            "admin_agent_after_capture":True,
            "cape_agent_version":cap["version"],
            "master_trial_shut_off":True,
            "free_storage_gib":round(available/1024**3,2),
            "snapshot_experimental_capture_metadata_ok":True,
            "snapshot_os_disk_label_present":candidate_in_os,
            "tpm_uefi_full_state_restore_physically_tested":False,
            "running_snapshot_revert_physically_tested":False,
            "snapshot_can_be_reverted_consistently":False,
            "release_for_cape_analysis":False,
            "needs_disposable_benign_restore_validation":True,
            "host_or_guest_changed":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("audit",),default="audit")
    p.parse_args()
    try:
        print(json.dumps(assess(),sort_keys=True,indent=2))
        return 0
    except (PostcaptureBlocked,candidate.SnapshotCandidateBlocked,
            transition.TransitionBlocked,prep.SSL55PrepareBlocked,
            hostguard.BootBlocked,hostguard.guard.AuditBlocked,
            hostguard.boot.BootBlocked,agent.AgentBlocked,
            OSError,ValueError,TypeError,KeyError,json.JSONDecodeError,
            ET.ParseError) as e:
        print(json.dumps({"result":"SSL55_POSTCAPTURE_AUDIT_BLOCKED",
            "reason":str(e),"snapshot_capture_attempted":False,
            "snapshot_reverted":False,"host_or_guest_modified":False},
            sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
