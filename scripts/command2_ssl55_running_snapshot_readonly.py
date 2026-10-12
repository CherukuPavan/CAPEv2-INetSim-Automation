#!/usr/bin/env python3
"""Canonical SSL55 win11_1 CAPE *running* snapshot decision: READ-ONLY.

Does not snapshot, pause, power off, change NVRAM format, change TPM,
restore the cold backup or touch source master/trial. Captures the exact
blockers for a full Windows memory+disk+OVMF+TPM CAPE reset strategy.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

VM="win11_1"
UID="732b2256-ee99-41fa-881d-fbf5c476d960"
MASTER=("win11","289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL=("win11_trial_1","e75f6fef-347d-462f-9738-4de3df6bfa74")
DISK=Path("/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2")
VARS=Path("/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd")
TPM=Path("/var/lib/libvirt/swtpm")/UID/"tpm2"
COLD=Path("/var/lib/libvirt/images/cape-clones-staging/cape-win11_1-cold-recovery/cold-b8c6f2d3b4ba4e948dc476b2a1b35c2d")
GIB=1024**3
class AuditBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise AuditBlocked(why)
def cmd(*args,timeout=60):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise AuditBlocked("Read-only host utility unavailable: "+args[0]) from exc
    need(p.returncode==0,"Read-only host utility returned failure: "+args[0])
    need(len(p.stdout)<2_000_000,"Unexpected oversized host response")
    return p.stdout.strip()
def virsh(*args):return cmd("virsh","-c","qemu:///system",*args)

def checkdomain(raw):
    r=ET.fromstring(raw)
    need(r.tag=="domain" and r.findtext("name")==VM and
         r.findtext("uuid")==UID,"Unexpected clone XML identity")
    disks=r.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].find("source") is not None and
         disks[0].find("source").get("file")==str(DISK) and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2",
         "Unexpected clone system QCOW2")
    chain=disks[0].find("backingStore")
    need(chain is None or (chain.find("source") is None and
         chain.find("backingStore") is None),
         "Clone has an unexpected master backing dependency")
    loader=r.find("./os/loader")
    nv=r.find("./os/nvram")
    need(nv is not None and nv.text==str(VARS),
         "Unexpected UEFI variable store path")
    t=r.find("./devices/tpm/backend")
    need(t is not None and t.get("type")=="emulator" and
         t.get("version")=="2.0",
         "Unexpected TPM emulator model")
    nics=r.findall("./devices/interface")
    need(len(nics)==1 and
         nics[0].find("source") is not None and
         nics[0].find("source").get("network")=="cape-analysis-isolated" and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address","").lower()=="02:0a:30:6a:3f:50",
         "Unexpected isolated NIC")
    return {"loader_type":loader.get("type","unspecified") if loader is not None else "missing",
            "xml_nvram_format":nv.get("format","raw"),
            "vm_name":VM,"vm_uuid":UID,
            "swtpm_emulator_2":True,"disk_backing_empty":True}

def fileinfo(p):
    need(p.is_file() and not p.is_symlink(),"VM state path missing/symlinked: "+p.name)
    s=p.stat()
    need(stat.S_ISREG(s.st_mode),"Unexpected VM state file type")
    return {"size_bytes":s.st_size,"allocated_bytes":s.st_blocks*512}

def perform():
    need(os.geteuid()==0,"sudo required for snapshot read-only inventory")
    need(socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Expected canonical SSL55 only")
    need(virsh("domuuid",VM).lower()==UID,"Unexpected clone UUID")
    need(virsh("domstate",VM).lower()=="running",
         "Snapshot feasibility requires the already-running clone")
    for name,uuid in (MASTER,TRIAL):
        need(virsh("domuuid",name).lower()==uuid and
             virsh("domstate",name).lower()=="shut off",
             "Protected original VM identity/state differs: "+name)
    live=checkdomain(virsh("dumpxml",VM))
    inactive=checkdomain(virsh("dumpxml","--inactive",VM))
    need(live==inactive,"Guest firmware/device state differs live vs saved")
    qcow=json.loads(cmd("qemu-img","info","-U","--output=json",str(DISK)))
    need(qcow.get("format")=="qcow2" and not qcow.get("backing-filename"),
         "Guest disk does not have standalone QCOW2 metadata")
    varfile=json.loads(cmd("qemu-img","info","-U","--output=json",str(VARS)))
    need(varfile.get("format") in ("raw","qcow2"),
         "Unexpected UEFI VARS backing format")
    need(TPM.is_dir() and not TPM.is_symlink(),
         "Exact clone swtpm2 state folder missing")
    tpm_state=[]
    for p in sorted(TPM.iterdir()):
        need(p.is_file() and not p.is_symlink(),"Unexpected swtpm entry")
        v=fileinfo(p);v["filename"]=p.name;tpm_state.append(v)
    need(any(p["filename"].endswith(".permall") for p in tpm_state),
         "TPM permanent state missing")
    snapshot_list=[x.strip() for x in virsh("snapshot-list",VM,"--name").splitlines()
                   if x.strip()]
    cold_exists=(COLD/"manifest.json").is_file()
    free=os.statvfs(DISK.parent)
    avail=free.f_frsize*free.f_bavail
    raw=(varfile["format"]=="raw" or live["xml_nvram_format"]=="raw")
    tpm_present=True
    return {
      "result":"SSL55_CAPE_RUNNING_SNAPSHOT_COMPATIBILITY_READONLY",
      "vm":VM,
      "vm_state":"running",
      "master_trial_shut_off":True,
      "disk_standalone_qcow2":True,
      "disk_virtual_size_bytes":qcow.get("virtual-size"),
      "nvram_format_on_disk":varfile["format"],
      "nvram_format_in_libvirt_xml":live["xml_nvram_format"],
      "nvram_file_metadata":fileinfo(VARS),
      "swtpm_state_files_metadata_only":tpm_state,
      "snapshot_names":snapshot_list,
      "canonical_cold_backup_manifest_present":cold_exists,
      "available_storage_gib":round(avail/GIB,2),
      "protected_reserve_gib":40,
      "native_internal_running_snapshot_with_raw_pflash_allowed":False if raw else None,
      "libvirt_swtpm_state_atomic_snapshot_proven":False,
      "snapshot_capture_attempted":False,
      "snapshot_revert_tested":False,
      "running_snapshot_ready_for_cape":False,
      "native_snapshot_blockers":[
          *([] if not raw else ["RAW_PFLASH_VARIABLE_STORE"]),
          "SWTMP2_ATOMIC_CAPTURE_AND_REVERT_UNPROVEN",
          "NO_VERIFIED_RUNNING_REVERT_CYCLE",
      ],
      "next_safe_step":"Prototype full-state recovery and running snapshot "
          "on approved disposable SECOND host; do not convert this "
          "running SSL55 variable store or run generic snapshot-create",
      "host_guest_modified":False,
    }

if __name__=="__main__":
    try: print(json.dumps(perform(),indent=2,sort_keys=True))
    except (AuditBlocked,OSError,ValueError,TypeError,ET.ParseError) as exc:
        print(json.dumps({"result":"SSL55_SNAPSHOT_READONLY_BLOCKED",
                          "reason":str(exc),"host_guest_modified":False},
                         indent=2),file=sys.stderr)
        sys.exit(2)
