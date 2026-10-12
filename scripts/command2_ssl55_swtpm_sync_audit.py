#!/usr/bin/env python3
"""SSL55 win11_1 TPM snapshot synchronization feasibility, READ-ONLY.

Does not contact swtpm control sockets; does not read active TPM contents,
QMP command/TPM state, invoke save/load, or alter guest/snapshot. Examines
the already captured exact snapshot, both QCOW2 image snapshot inventories,
swtpm state-file metadata and exact live process association. A process,
a file, an image snapshot, and QEMU's migration support are NOT evidence
that libvirt checkpointed persistent swtpm state at the same instant.

This is a hold gate only; it cannot authorize CAPE sample analysis/revert.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

HOST="cse-ssl-55"
VM="win11_1"
UUID="732b2256-ee99-41fa-881d-fbf5c476d960"
SNAP="cape_candidate_win11_1"
DISK=Path("/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2")
OVMF=Path("/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd.qcow2")
TPM=Path("/var/lib/libvirt/swtpm")/UUID/"tpm2"
MASTER=("win11","289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL=("win11_trial_1","e75f6fef-347d-462f-9738-4de3df6bfa74")
MAX_PROC_CMDLINE=65536
class AuditBlocked(RuntimeError): pass
def require(test, why):
    if not test: raise AuditBlocked(why)

def cmd(*argv, timeout=60):
    try:
        p=subprocess.run(argv,check=False,capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise AuditBlocked("Read-only host query unavailable: "+argv[0]) from exc
    require(p.returncode==0 and len(p.stdout)<=2_000_000,
            "Host inspection command did not complete: "+argv[0])
    return p.stdout.strip()
def virsh(*args):
    return cmd("virsh","-c","qemu:///system",*args)
def xml_domain(raw):
    root=ET.fromstring(raw)
    require(root.tag=="domain" and root.get("type")=="kvm" and
            root.findtext("name")==VM and root.findtext("uuid")==UUID,
            "Guest libvirt identity changed")
    disks=root.findall("./devices/disk[@device='disk']")
    require(len(disks)==1 and disks[0].find("source") is not None and
            disks[0].find("source").get("file")==str(DISK) and
            disks[0].find("driver") is not None and
            disks[0].find("driver").get("type")=="qcow2",
            "Expected independent guest disk changed")
    nv=root.find("./os/nvram")
    require(nv is not None and nv.get("format")=="qcow2" and
            nv.text==str(OVMF), "Expected own QCOW2 OVMF changed")
    tpm=root.find("./devices/tpm/backend")
    require(tpm is not None and tpm.get("type")=="emulator" and
            tpm.get("version")=="2.0",
            "Expected swtpm emulated TPM 2.0 changed")
    nics=root.findall("./devices/interface")
    require(len(nics)==1 and nics[0].get("type")=="network" and
            nics[0].find("source") is not None and
            nics[0].find("source").get("network")=="cape-analysis-isolated" and
            nics[0].find("mac") is not None and
            nics[0].find("mac").get("address","").lower()=="02:0a:30:6a:3f:50",
            "Unexpected guest NIC/network")
    require(not any(root.findall("./devices/"+t) for t in
            ("hostdev","filesystem","redirdev","channel","shmem","vsock")),
            "Guest has unreviewed host-connected device")
    return {"identity_storage_uefi_tpm_network_match":True}

def snapshot_metadata(raw):
    root=ET.fromstring(raw)
    require(root.tag=="domainsnapshot" and
            root.findtext("name")==SNAP and root.findtext("state")=="running",
            "Exact captured snapshot must have running state")
    embedded=root.find("domain")
    require(embedded is not None and
            embedded.findtext("name")==VM and embedded.findtext("uuid")==UUID,
            "Snapshot embedded domain identity differs")
    mem=root.find("memory")
    disks=root.findall("./disks/disk")
    require(mem is not None and mem.get("snapshot")=="internal" and
            sum(d.get("name")=="sda" and d.get("snapshot")=="internal"
                for d in disks)==1 and
            len({d.get("name") for d in disks})==len(disks),
            "Expected internal Windows OS disk sda plus RAM snapshot missing")
    raw_epoch=root.findtext("creationTime")
    # libvirt includes a creationTime in snapshot metadata; an omitted
    # field is a BLOCKER, never invent an arbitrary capture timestamp.
    require(raw_epoch is not None and raw_epoch.isdigit(),
            "Snapshot capture timestamp missing")
    when=int(raw_epoch)
    require(0<when<=int(time.time())+300,"Snapshot capture timestamp invalid")
    return {"snapshot_epoch_unix_seconds":when,
            "running_ram_and_exact_sda_internal_metadata":True,
            "other_disk_entries":len(disks)-1}

def qcow_names(path):
    path=Path(path)
    require(path.is_file() and not path.is_symlink(),
            "Expected approved QCOW2 image missing")
    x=json.loads(cmd("qemu-img","info","-U","--output=json",str(path),timeout=90))
    require(type(x) is dict and x.get("format")=="qcow2" and
            not x.get("backing-filename"),"QCOW2 image format/backing invalid")
    snaps=x.get("snapshots",[])
    require(type(snaps) is list and len(snaps)<=128,
            "Unapproved image snapshot inventory")
    names=[item.get("name") for item in snaps if type(item) is dict]
    require(len(names)==len(snaps) and
            all(type(name) is str and len(name)<128 for name in names),
            "Malformed image snapshot entries")
    require(names.count(SNAP)==1,
            "Expected exact candidate snapshot inside "+path.name)
    return {"qcow2":True,"candidate_name_present_once":True,
            "snapshot_names":names}

def find_swtpm_process(proc=Path("/proc")):
    """Select by matching exact TPM state path, never by loose VM name.

    Reads only /proc/<pid>/cmdline, not process memory, sockets or disk.
    Process arguments may contain sensitive paths: report only booleans
    and a count, never copy raw command line to a report.
    """
    matching=[]
    for entry in proc.iterdir():
        if not entry.name.isdecimal() or not entry.is_dir():
            continue
        try:
            raw=(entry/"cmdline").read_bytes()
        except (FileNotFoundError,PermissionError,ProcessLookupError,OSError):
            continue
        if not raw or len(raw)>MAX_PROC_CMDLINE:
            continue
        args=[x.decode("utf-8","replace") for x in raw.split(b"\0") if x]
        if not args or Path(args[0]).name!="swtpm":
            continue
        stateopts=[args[i+1] for i,a in enumerate(args[:-1])
                   if a=="--tpmstate"]
        if any(v.split(",",1)[0]=="dir="+str(TPM) for v in stateopts):
            matching.append(entry.name)
    require(len(matching)==1,
            "Expected one independently bound live swtpm instance for this clone")
    return {"unique_swtpm_process_bound_to_clone":True,
            "matched_swtpm_process_count":len(matching),
            "live_swtpm_state_blob_export_performed":False,
            "live_swtpm_control_socket_queried":False}

def tpm_files(capture_epoch):
    require(TPM.is_dir() and not TPM.is_symlink(),
            "Dedicated swtpm state directory missing")
    entries=[]
    for f in sorted(TPM.iterdir()):
        require(f.is_file() and not f.is_symlink(),
                "Unexpected swtpm path type")
        st=f.stat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink==1,
                "Unexpected swtpm state hardlink or non-regular file")
        entries.append({"name":f.name,"size_bytes":st.st_size,
            "modified_after_snapshot":st.st_mtime>capture_epoch})
    require(any(x["name"]=="tpm2-00.permall" and x["size_bytes"]>0
                for x in entries),"TPM permanent state file missing")
    return {"independent_tpm_state_dir":str(TPM),
            "files_metadata_only":entries,
            "files_hashed_or_copied_while_running":False,
            "tpm_persistent_state_at_capture_time_verified":False}

def assess():
    require(os.geteuid()==0 and
            socket.gethostname().split(".",1)[0].lower()==HOST,
            "Exact reference SSL55 root only")
    require(virsh("domuuid",VM).lower()==UUID and
            virsh("domstate",VM).lower()=="running",
            "Exact snapshot guest must remain running")
    for name,uid in (MASTER,TRIAL):
        require(virsh("domuuid",name).lower()==uid and
                virsh("domstate",name).lower()=="shut off",
                "Original master/trial identity or state differs")
    require(virsh("list","--name").splitlines()==[VM],
            "Unexpected running VM; no interference permitted")
    require([x.strip() for x in virsh("snapshot-list",VM,"--name").splitlines()
             if x.strip()]==[SNAP],
            "Exact existing libvirt snapshot not alone")
    saved=xml_domain(virsh("dumpxml","--inactive",VM))
    live=xml_domain(virsh("dumpxml",VM))
    snapshot=snapshot_metadata(virsh("snapshot-dumpxml",VM,SNAP))
    disk=qcow_names(DISK)
    nvram=qcow_names(OVMF)
    tpm=tpm_files(snapshot["snapshot_epoch_unix_seconds"])
    process=find_swtpm_process()
    return {
        "result":"COMMAND2_SSL55_TPM_SNAPSHOT_SYNC_INVENTORY_READONLY",
        "host":HOST,"vm":VM,"uuid":UUID,"snapshot":SNAP,
        "guest_running_now":True,
        "master_trial_shut_off":True,
        "snapshot_metadata":snapshot,
        "saved_domain":saved,"live_domain":live,
        "os_disk_snapshot":disk,"uefi_snapshot":nvram,
        "swtpm_live_process":process,"swtpm":tpm,
        "swtpm_ioctl_installed":shutil.which("swtpm_ioctl") is not None,
        "swtpm_blob_export_import_feature_supported_by_upstream":True,
        "libvirt_snapshotted_swtpm_checkpoint_proven":False,
        "matching_snapshot_epoch_tpm_state_artifact_provided":False,
        "two_benign_reverts_verified":False,
        "cancellation_or_unsafe_retry_performed":False,
        "malware_execution_authorized":False,
        "CAPE_READY":False,
        "snapshot_revert_authorized":False,
        "tpm_safe_recovery_path_not_yet_proven":True,
        "host_or_guest_state_modified":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("audit",),default="audit")
    p.parse_args()
    try:
        print(json.dumps(assess(),indent=2,sort_keys=True))
        return 0
    except (AuditBlocked,OSError,ValueError,TypeError,KeyError,
            json.JSONDecodeError,ET.ParseError) as exc:
        print(json.dumps({"result":"COMMAND2_SSL55_TPM_SYNC_AUDIT_BLOCKED",
            "reason":str(exc),"guest_or_snapshot_modified":False,
            "do_not_revert_or_capture_again":True},
            sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__": raise SystemExit(main())
