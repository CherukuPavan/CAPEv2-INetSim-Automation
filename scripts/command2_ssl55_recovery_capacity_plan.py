#!/usr/bin/env python3
"""Read-only recovery capacity/identity preflight for existing SSL55 clone.

Does not shut down, create files, read TPM secrets or create any snapshots.
The separate cold-checkpoint design is NOT authorized by this report.
"""
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

NAME="win11_1"
UUID="732b2256-ee99-41fa-881d-fbf5c476d960"
DISK=Path("/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2")
NVRAM=Path("/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd")
TPM=Path("/var/lib/libvirt/swtpm")/UUID/"tpm2"
GIB=1024**3

class Blocked(RuntimeError):pass
def need(ok,msg):
    if not ok:raise Blocked(msg)
def read(*args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=40)
    need(p.returncode==0,"Read-only command failed: "+args[0])
    return p.stdout.strip()
def virsh(*args):
    return read("virsh","-c","qemu:///system",*args)

def xml_check(raw):
    root=ET.fromstring(raw)
    need(root.findtext("name")==NAME and root.findtext("uuid")==UUID,
         "Exact clone identity differs")
    disk=root.find("./devices/disk[@device='disk']")
    need(disk is not None and disk.find("source") is not None and
         disk.find("source").get("file")==str(DISK),"Clone disk changed")
    backing=disk.find("backingStore")
    need(backing is None or (backing.find("source") is None and
         backing.find("backingStore") is None),"Clone still backed by master")
    need(root.findtext("./os/nvram")==str(NVRAM),"NVRAM path changed")
    backend=root.find("./devices/tpm/backend")
    need(backend is not None and backend.get("type")=="emulator" and
         backend.get("version")=="2.0","Expected swtpm2 missing")
    nic=root.findall("./devices/interface")
    need(len(nic)==1 and nic[0].find("source") is not None and
         nic[0].find("source").get("network")=="cape-analysis-isolated",
         "Unexpected guest network")

def metadata(path):
    need(path.is_file() and not path.is_symlink(),"Missing or linked artifact")
    s=path.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,
         "Hardlinked or unexpected artifact")
    return {"size":s.st_size,"allocated":s.st_blocks*512}

def perform():
    need(os.geteuid()==0,"Root needed for private file metadata")
    need(socket.gethostname().split(".")[0].lower()=="cse-ssl-55",
         "Unexpected host")
    need(virsh("domuuid",NAME).lower()==UUID and
         virsh("domstate",NAME).lower()=="running",
         "Expected running clone unchanged")
    for name,uuid in (
        ("win11","289d89be-68ec-4c62-90e1-ea930849266f"),
        ("win11_trial_1","e75f6fef-347d-462f-9738-4de3df6bfa74")):
        need(virsh("domuuid",name).lower()==uuid and
             virsh("domstate",name).lower()=="shut off",
             "Protected domain identity/state changed")
    need(not virsh("snapshot-list",NAME,"--name").strip(),
         "Unexpected clone snapshot exists")
    xml_check(virsh("dumpxml",NAME))
    xml_check(virsh("dumpxml","--inactive",NAME))
    net=virsh("net-info","cape-analysis-isolated")
    need(bool(re.search(r"^Active:\s+yes\s*$",net,re.M|re.I)),
         "Isolated network inactive")
    disk=metadata(DISK)
    nvram=metadata(NVRAM)
    need(TPM.is_dir() and not TPM.is_symlink(),"Missing TPM state directory")
    states=[]
    for f in sorted(TPM.iterdir()):
        need(f.is_file() and not f.is_symlink(),"Unexpected TPM state object")
        if f.name==".lock":continue
        m=metadata(f)
        states.append({"name":f.name,"bytes":m["size"]})
    need(any(x["name"].endswith(".permall") for x in states),
         "TPM persistent state unavailable")
    v=os.statvfs(str(DISK.parent))
    free=v.f_bavail*v.f_frsize
    bound=disk["size"]+45*GIB
    return {
        "result":"COMMAND2_COLD_RECOVERY_CAPACITY_READONLY",
        "clone_disk_apparent_gib":round(disk["size"]/GIB,2),
        "clone_disk_allocated_gib":round(disk["allocated"]/GIB,2),
        "available_gib":round(free/GIB,2),
        "worst_case_full_file_copy_plus_reserve_gib":round(bound/GIB,2),
        "capacity_pass_at_this_instant":free>=bound,
        "reserve_gib":40,"overhead_gib":5,
        "uefi_vars_bytes":nvram["size"],
        "tpm_files_metadata_only":states,
        "no_guest_shutdown":True,"no_new_files":True,
        "checkpoint_captured":False,"cold_restore_verified":False,
        "snapshot_revert_verified":False
    }
if __name__=="__main__":
    try:print(json.dumps(perform(),indent=2,sort_keys=True))
    except (Blocked,OSError,ET.ParseError,ValueError) as e:
        print("BLOCKED: "+str(e),file=sys.stderr)
        sys.exit(2)
