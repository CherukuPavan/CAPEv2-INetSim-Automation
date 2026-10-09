#!/usr/bin/env python3
"""READ-ONLY master preservation feasibility audit for BitLocker-template recovery.

Does not modify images, libvirt definitions, snapshots, TPM state, NVRAM,
network configuration or guests. Prints no TPM/BitLocker material.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

MASTER="win11"
SNAPSHOT="finalshutoffversion"

class AuditFailure(RuntimeError):
    pass

def require(value: bool, message: str) -> None:
    if not value:
        raise AuditFailure(message)

def invoke(*args: str, timeout: int = 60) -> str:
    try:
        p=subprocess.run(args,check=True,capture_output=True,text=True,
                         timeout=timeout)
        return p.stdout.strip()
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError) as exc:
        raise AuditFailure(f"{args[0]} failed during read-only audit") from exc

def virsh(*args: str) -> str:
    return invoke("virsh","-c","qemu:///system",*args)

def xml_summary(domain_text: str, snap_text: str) -> dict:
    try:
        root=ET.fromstring(domain_text)
        snap=ET.fromstring(snap_text)
        require(root.findtext("name")==MASTER,"Unexpected VM name")
        require(snap.findtext("name")==SNAPSHOT,"Unexpected snapshot")
        require(snap.findtext("state","").replace(" ","").lower()=="shutoff",
                "Snapshot is not a shut-off checkpoint")
        mem=snap.find("memory")
        require(mem is not None and mem.get("snapshot")=="no",
                "Cold snapshot has memory state")
        disks=root.findall("./devices/disk[@device='disk']")
        require(len(disks)==1,"Expected exactly one Windows disk")
        disk=disks[0]
        src=disk.find("source")
        driver=disk.find("driver")
        target=disk.find("target")
        require(disk.get("type")=="file" and src is not None and driver is not None
                and target is not None and driver.get("type")=="qcow2",
                "Unrecognized Windows master disk")
        file=src.get("file")
        dev=target.get("dev")
        require(file is not None and Path(file).is_absolute() and dev is not None,
                "Invalid master QCOW2 path/target")
        snaps=[e for e in snap.findall("./disks/disk")
               if e.get("name")==dev and e.get("snapshot")=="external"]
        require(len(snaps)==1,"Expected one external cold snapshot disk")
        source=snaps[0].find("source")
        require(source is not None and source.get("file")==file,
                "Master current disk differs from cold snapshot record")
        nvram=root.find("./os/nvram")
        require(nvram is not None and bool(nvram.text),
                "Missing original UEFI NVRAM file path")
        nvr=Path(nvram.text.strip())
        require(nvr.is_absolute(),"NVRAM file path is not absolute")
        tpm=root.findall("./devices/tpm")
        require(len(tpm)==1,"Expected one virtual TPM device")
        back=tpm[0].find("backend")
        require(back is not None and back.get("type")=="emulator",
                "Original TPM is not libvirt-managed emulator backend")
        # A vTPM may hold the only available BitLocker-unlock protector.
        # Never read, copy, export or print its state contents here.
        interfaces=root.findall("./devices/interface")
        require(len(interfaces)==1,
                "Expected exactly one original Windows NIC")
        nic=interfaces[0]
        source=nic.find("source")
        require(source is not None,"Cannot identify original NIC source")
        return {
            "qcow2":file,
            "target":dev,
            "nvram":str(nvr),
            "tpm_backend":"emulator",
            "tpm_version":back.get("version","unknown"),
            "nic_type":nic.get("type","unknown"),
            "nic_source_network":source.get("network"),
            "nic_source_bridge":source.get("bridge"),
            "existing_nic_link_state":(
                nic.find("link").get("state")
                if nic.find("link") is not None else "default-up"
            )
        }
    except ET.ParseError as exc:
        raise AuditFailure("Invalid domain/snapshot XML") from exc

def audit() -> dict:
    require(os.geteuid()==0,"Read-only audit requires sudo for libvirt state")
    require(virsh("domstate",MASTER)=="shut off",
            "Master must remain shut off")
    require(virsh("snapshot-current",MASTER,"--name")==SNAPSHOT,
            "Master current snapshot changed")
    domain=virsh("dumpxml","--inactive",MASTER)
    snap=virsh("snapshot-dumpxml",MASTER,SNAPSHOT)
    data=xml_summary(domain,snap)
    disk=Path(data["qcow2"])
    nvr=Path(data["nvram"])
    for title,path in (("master_disk",disk),("master_nvram",nvr)):
        require(not any(part.is_symlink() for part in (path,*path.parents)),
                f"Symlink in {title} path")
        require(path.is_file(),f"{title} missing")
        require(stat.S_ISREG(path.stat().st_mode),f"{title} is not regular")
        data[title+"_bytes"]=path.stat().st_size
    require(nvr.stat().st_size>0,"NVRAM store is empty")
    chain=json.loads(invoke("qemu-img","info","--output=json",
                            "--backing-chain",str(disk),timeout=120))
    require(isinstance(chain,list) and 2<=len(chain)<=16,
            "Unexpected master backing chain")
    require(chain[0].get("filename")==str(disk),
            "Backing chain does not start with master disk")
    layer_names=[]
    for part in chain:
        name=part.get("filename")
        require(part.get("format")=="qcow2" and isinstance(name,str),
                "Non-QCOW2 master backing layer")
        p=Path(name)
        require(p.is_absolute() and p.is_file() and not p.is_symlink(),
                "Invalid master backing image")
        require(name not in layer_names,"Repeated backing image layer")
        layer_names.append(name)
    for i,part in enumerate(chain):
        back=part.get("full-backing-filename") or part.get("backing-filename")
        if i==len(chain)-1:
            require(not back,"Base image unexpectedly has backing")
        else:
            require(bool(back) and os.path.normpath(
                back if os.path.isabs(back) else
                str(Path(layer_names[i]).parent/back)
            )==layer_names[i+1],"Broken QCOW2 backing chain")
    data["master_layers"]=layer_names
    data["disk_virtual_size_bytes"]=chain[0].get("virtual-size")
    require(data["disk_virtual_size_bytes"]==64*1024**3,
            "Unexpected master disk virtual size")
    staged=Path("/var/lib/libvirt/images/cape-clones-staging/win11_1.qcow2")
    data["existing_detached_export"]=staged.is_file() and not staged.is_symlink()
    data["remaining_free_gib"]=round(shutil.disk_usage(disk.parent).free/1024**3,2)
    # Report existence and permissions of TPM state roots, not secret filenames.
    tpm_root=Path("/var/lib/libvirt/swtpm")
    data["libvirt_swtpm_root_exists"]=tpm_root.is_dir() and not tpm_root.is_symlink()
    expected=tpm_root/virsh("domuuid",MASTER)
    data["uuid_scoped_swtpm_state_dir_exists"]=expected.is_dir() and not expected.is_symlink()
    data["swtpm_state_location_verified"]=False
    # Libvirt and swtpm state placement can be customized; do not infer a
    # restoration plan from directory existence alone.
    data["overall"]="READ_ONLY_PRESERVATION_REVIEW_REQUIRED"
    data["apply_operations_authorized_by_this_audit"]=False
    data["note"]="No files, domains, secrets, snapshots, services, networks or TPM state changed"
    return data

if __name__=="__main__":
    try:
        print(json.dumps(audit(),indent=2,sort_keys=True))
    except (AuditFailure,ValueError,OSError,KeyError,TypeError) as exc:
        print("BLOCKED:",str(exc),file=sys.stderr)
        sys.exit(2)
