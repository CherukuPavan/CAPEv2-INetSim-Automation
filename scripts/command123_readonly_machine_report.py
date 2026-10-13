#!/usr/bin/env python3
"""Day-of-test READ-ONLY source/new-host report for exact CAPE 3-command work.

No root privileges needed for normal system inventory; read-only libvirt
queries may require local permissions or sudo. No Drive tokens, crypt keys,
TPM contents, raw Windows disk, or full configs are collected.
No package install, VM action, mount, firewall change, snapshot or restart.

Use --role source on SSL-55 and --role target on the new machine.
Use --storage-dir EXISTING_PATH for planned local master-export storage
(source) or Windows disk/clone storage (target). Output stdout JSON
without writing any file; redirect to a user-owned chmod0600 report.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

GIB=1024**3
ALLOWED=("virsh","qemu-img","rclone","python3","git","findmnt")
MAX_OUT=256*1024

def call(*args,timeout=14):
    try:
        p=subprocess.run(list(args),capture_output=True,text=True,
                         timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        return {"ok":False,"error":type(exc).__name__}
    if len(p.stdout)>MAX_OUT:
        return {"ok":False,"error":"Oversized reply"}
    # Avoid raw stderr: it could contain environment or sensitive details.
    return {"ok":p.returncode==0,"stdout":p.stdout if p.returncode==0 else "",
            "exit_status":p.returncode}

def pkg_binary_status():
    return {x:shutil.which(x) is not None for x in ALLOWED}

def os_release():
    data={}
    p=Path("/etc/os-release")
    if p.is_file():
        for line in p.read_text(encoding="utf-8").splitlines():
            if "=" not in line:continue
            k,v=line.split("=",1)
            if k in ("ID","VERSION_ID","PRETTY_NAME"):
                data[k]=v.strip().strip('"')
    return data

def mem():
    facts={}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            for key in ("MemTotal","MemAvailable"):
                if line.startswith(key+":"):
                    facts[key+"_gib"]=round(int(line.split()[1])/1024**2,2)
    except (OSError,ValueError,IndexError):
        pass
    return facts

def capacity(path):
    p=Path(path)
    if not p.is_absolute() or not p.is_dir() or p.is_symlink():
        return {"ok":False,"reason":"Storage path must already be an absolute real directory"}
    try:
        st=os.statvfs(p)
        return {"ok":True,"storage_dir":str(p),
                "free_gib":round(st.f_bavail*st.f_frsize/GIB,1),
                "total_gib":round(st.f_blocks*st.f_frsize/GIB,1)}
    except OSError as exc:
        return {"ok":False,"reason":type(exc).__name__}

def source_master():
    from pathlib import Path
    result={"master":"win11","source_vm_modified":False,
            "exact_cold_bundle_not_exported_by_this_tool":True}
    state=call("virsh","-c","qemu:///system","domstate","win11")
    if not state["ok"]:
        result["libvirt_master_query"]="BLOCKED_OR_MISSING"
        return result
    result["power_state"]=state["stdout"].strip()
    result["safe_for_cold_export"]=result["power_state"]=="shut off"
    snap=call("virsh","-c","qemu:///system",
              "snapshot-list","win11","--name")
    result["snapshot_names"]=(snap["stdout"].splitlines()
                              if snap["ok"] else [])
    info=call("virsh","-c","qemu:///system","dumpxml","--inactive","win11")
    if info["ok"]:
        try:
            root=ET.fromstring(info["stdout"])
            disk=root.find("./devices/disk[@device='disk']/source")
            nv=root.find("./os/nvram")
            result["disk_source_path"]=(disk.get("file") if disk is not None
                                        else None)
            result["UEFI_vars_path"]=(nv.text if nv is not None else None)
            result["TPM_emulator_present"]=(root.find(
                "./devices/tpm/backend[@type='emulator']") is not None)
            disk_path=result.get("disk_source_path")
            if disk_path and shutil.which("qemu-img"):
                # Metadata only. Never read/print Windows disk data.
                meta=call("qemu-img","info","--output=json",disk_path)
                if meta["ok"]:
                    data=json.loads(meta["stdout"])
                    result["virtual_disk_gib"]=round(
                        data.get("virtual-size",0)/GIB,2)
                    result["disk_format"]=data.get("format")
                    result["backing_image_present"]=bool(data.get(
                        "backing-filename"))
                    result["conservative_free_space_needed_gib"]=round(
                        data.get("virtual-size",0)/GIB+30,1)
        except (ValueError,ET.ParseError,TypeError,IndexError):
            result["disk_xml_metadata"]="unavailable"
    return result

def target():
    result={"VMs_started_or_installed":False}
    if shutil.which("virsh"):
        domains=call("virsh","-c","qemu:///system","list","--all","--name")
        result["existing_domain_names"]=(domains["stdout"].splitlines()
                                          if domains["ok"] else
                                          ["LIBVIRT_UNAVAILABLE"])
        net=call("virsh","-c","qemu:///system","net-list","--all","--name")
        result["libvirt_network_names"]=(net["stdout"].splitlines()
                                         if net["ok"] else
                                         ["LIBVIRT_UNAVAILABLE"])
    try:
        result["dev_kvm_present"]=Path("/dev/kvm").exists()
    except OSError:result["dev_kvm_present"]=False
    return result

def run(role, storage):
    installed=pkg_binary_status()
    report={
        "role":role,"purpose":"read_only_day_of_test_cape_planning",
        "OS":os_release(),
        "arch":platform.machine(),
        "CPU_count":os.cpu_count(),
        "memory":mem(),
        "binaries_installed":installed,
        "storage":capacity(storage),
        "run_as_uid":os.geteuid(),
        "secrets_included":False,"host_modified":False,
        "Windows_VMs_started_or_reverted":False,
    }
    if role=="source":report["exact_master"]=source_master()
    else:report["target_machine"]=target()
    storage_entry=report["storage"]
    if role=="source" and storage_entry.get("ok"):
        need=report["exact_master"].get("conservative_free_space_needed_gib")
        report["conservative_export_space_check"]=(
            "UNKNOWN_IMAGE_SIZE" if need is None
            else "SUFFICIENT_CONSERVATIVE_HEADROOM" if
            storage_entry["free_gib"]>need else
            "INSUFFICIENT_LOCAL_EXPORT_SPACE_USE_APPROVED_EXTERNAL_DRIVE")
    report["ready_to_run_fresh_host_install"]=False
    report["physical_integration_accepted"]=False
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--role",required=True,choices=("source","target"))
    p.add_argument("--storage-dir",required=True,type=Path)
    args=p.parse_args()
    try:
        print(json.dumps(run(args.role,args.storage_dir),
                         sort_keys=True,indent=2))
        return 0
    except (OSError,ValueError,TypeError) as exc:
        print(json.dumps({"result":"SOURCE_OR_TARGET_DIAGNOSTIC_BLOCKED",
                          "error_type":type(exc).__name__,
                          "host_modified":False}),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
