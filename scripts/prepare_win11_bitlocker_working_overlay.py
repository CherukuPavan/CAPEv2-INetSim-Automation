#!/usr/bin/env python3
"""Prepare a standalone writable *working overlay*, never boot or modify master.

MODE defaults to plan. --create creates one QCOW2 overlay referencing the
verified cold win11 top image. It does not change libvirt XML, snapshot
metadata, VM state, NVRAM, TPM, network, Windows or BitLocker.
Creating this overlay is NOT approval to boot, decrypt or detach the source.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

VM="win11"
SNAP="finalshutoffversion"
TOP=Path("/var/lib/libvirt/images/win11.finalshutoffversion")
DEST=Path("/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2")
BACKUP_BASE=Path("/var/backups/cape-win11-preservation")
LOCK=Path("/run/lock/cape-cold-export.lock")
RESERVE=30*1024**3

class Block(RuntimeError):
    pass

def require(test: bool, message: str) -> None:
    if not test:
        raise Block(message)

def cmd(*args: str, timeout: int=120) -> str:
    try:
        return subprocess.run(args, check=True, text=True,
                              capture_output=True, timeout=timeout).stdout.strip()
    except (OSError,subprocess.TimeoutExpired,subprocess.CalledProcessError) as exc:
        raise Block(f"Command {args[0]} failed; do not retry blindly") from exc

def virsh(*args: str) -> str:
    return cmd("virsh","-c","qemu:///system",*args)

def safe_regular(path: Path) -> os.stat_result:
    require(path.is_absolute() and ".." not in path.parts,
            "Unsafe source path")
    for p in (path,*path.parents):
        require(not p.is_symlink(),"Source path contains symlink")
    st=path.stat()
    require(stat.S_ISREG(st.st_mode),"Expected regular source image")
    return st

def backup_readiness() -> bool:
    require(BACKUP_BASE.is_dir() and not BACKUP_BASE.is_symlink(),
            "Protected backup parent unavailable")
    root=BACKUP_BASE.stat()
    require(root.st_uid==0 and stat.S_IMODE(root.st_mode)==0o700,
            "Protected backup parent must be root-private")
    candidates=sorted(BACKUP_BASE.glob("win11-state-*"))
    safe=[]
    for folder in candidates:
        if folder.is_symlink() or not folder.is_dir():
            continue
        st=folder.stat()
        if st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o700:
            continue
        keys=[
            folder/"metadata"/"domain.xml",
            folder/"metadata"/"snapshot-names.txt",
            folder/"metadata"/"snapshot-"+SNAP+".xml",
            folder/"private"/"original_VARS.fd",
        ]
        if all(not p.is_symlink() and p.is_file() for p in keys) and (
            folder/"private"/"swtpm").is_dir():
            safe.append(folder)
    require(bool(safe),"No complete local protected-state backup layout found")
    # Layout-only inspection; no confidential file bytes are opened.
    return True

def snapshot_fingerprint() -> tuple:
    require(virsh("domstate",VM)=="shut off","Original Windows VM is not shut off")
    require(virsh("snapshot-current",VM,"--name")==SNAP,
            "Original cold snapshot pointer changed")
    dom=ET.fromstring(virsh("dumpxml","--inactive",VM))
    snap=ET.fromstring(virsh("snapshot-dumpxml",VM,SNAP))
    disk=dom.findall("./devices/disk[@device='disk']")
    require(len(disk)==1,"Expected exactly one original Windows disk")
    src=disk[0].find("source")
    target=disk[0].find("target")
    require(src is not None and src.get("file")==str(TOP)
            and target is not None and target.get("dev"),"Original disk has changed")
    matches=[d for d in snap.findall("./disks/disk") if
             d.get("name")==target.get("dev") and d.get("snapshot")=="external"]
    require(len(matches)==1,"Original cold snapshot disk mapping changed")
    source=matches[0].find("source")
    require(source is not None and source.get("file")==str(TOP),
            "Cold snapshot no longer points to original image")
    require(snap.findtext("state","").replace(" ","")=="shutoff",
            "Original snapshot was not cold")
    mem=snap.find("memory")
    require(mem is not None and mem.get("snapshot")=="no",
            "Original snapshot contains saved RAM")
    rows=json.loads(cmd("qemu-img","info","--output=json",
                        "--backing-chain",str(TOP)))
    require(isinstance(rows,list) and len(rows)==4,"Master QCOW2 chain changed")
    require(rows[0].get("virtual-size")==64*1024**3,"Original disk virtual size changed")
    seen=[]
    result=[]
    for index,row in enumerate(rows):
        name=row.get("filename")
        require(row.get("format")=="qcow2" and isinstance(name,str),
                "Invalid original source image format")
        entry=Path(name)
        st=safe_regular(entry)
        require(str(entry) not in seen,"Repeated original image path")
        seen.append(str(entry))
        result.append((str(entry),st.st_dev,st.st_ino,st.st_size,
                       st.st_mtime_ns,st.st_ctime_ns))
        back=row.get("full-backing-filename") or row.get("backing-filename")
        if index==len(rows)-1:
            require(not back,"Oldest image unexpectedly has a backing file")
        else:
            require(bool(back),"Broken source backing chain")
            actual=os.path.normpath(
                back if os.path.isabs(back) else str(entry.parent/back))
            require(actual==rows[index+1].get("filename"),
                    "Backing chain paths are inconsistent")
    require(seen[0]==str(TOP) and Path(seen[-1]).name=="win11.qcow2",
            "Original master top/base chain differs from accepted baseline")
    return tuple(result)

def preflight() -> tuple:
    require(os.geteuid()==0,"Run through sudo")
    baseline=snapshot_fingerprint()
    backup_readiness()
    require(not DEST.exists() and not DEST.is_symlink(),
            "Working overlay path already exists: never overwrite")
    parent=DEST.parent
    require(not any(p.is_symlink() for p in (parent,*parent.parents)),
            "Unsafe overlay directory ancestry")
    st=parent.stat()
    require(parent.is_dir() and st.st_uid==0 and not st.st_mode & 0o022,
            "Overlay parent directory is not root-controlled")
    free=shutil.disk_usage(parent).free
    require(free>=64*1024**3+RESERVE,"Insufficient space for full overlay growth and reserve")
    return baseline,round(free/1024**3,2)

def perform(mode: str) -> dict:
    require(mode in ("plan","create"),"Unknown mode")
    if mode=="plan":
        _,free=preflight()
        return {
            "status":"PLAN_ONLY_NO_CHANGES",
            "master":VM,"snapshot":SNAP,
            "overlay_destination":str(DEST),
            "overlay_backing_file":str(TOP),
            "free_gib":free,
            "local_protected_backup_layout_present":True,
            "backup_restoration_tested":False,
            "vm_definition_changed":False,
            "vm_started":False,
            "bitlocker_changed":False,
            "next_gate":"Independent review of offline XML/NIC changes and restoration before any boot"
        }
    require(not LOCK.is_symlink(),"Untrusted export lock symlink")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    tmp=None
    try:
        require(os.fstat(fd).st_uid==0 and not os.fstat(fd).st_mode & 0o077,
                "Untrusted export lock mode")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        before,free=preflight()
        # Build a *new* overlay, never modify any original QCOW2 image.
        temp_fd,tmp=tempfile.mkstemp(prefix=".cape-working-",
                                     suffix=".qcow2",dir=DEST.parent)
        os.close(temp_fd)
        os.unlink(tmp)
        cmd("qemu-img","create","-f","qcow2","-F","qcow2",
            "-b",str(TOP),tmp,timeout=120)
        os.chmod(tmp,0o600)
        info=json.loads(cmd("qemu-img","info","--output=json",tmp))
        require(info.get("format")=="qcow2" and
                info.get("virtual-size")==64*1024**3 and
                info.get("full-backing-filename")==str(TOP) and
                info.get("backing-filename")==str(TOP),
                "New overlay did not have exactly the expected backing image")
        require(snapshot_fingerprint()==before,
                "Original image or libvirt snapshot changed during overlay preparation")
        require(shutil.disk_usage(DEST.parent).free>=RESERVE,
                "Host filesystem reserve exhausted")
        require(not DEST.exists() and not DEST.is_symlink(),
                "Overlay destination unexpectedly appeared")
        # Atomic hardlink to avoid ever replacing an existing destination.
        os.link(tmp,DEST)
        os.unlink(tmp)
        tmp=None
        return {
            "status":"WORKING_OVERLAY_CREATED_NOT_ATTACHED",
            "path":str(DEST),
            "backing_image":str(TOP),
            "original_master_state":"shut off",
            "original_snapshot":SNAP,
            "protected_backup_layout_verified":True,
            "source_metadata_unchanged":True,
            "guest_started":False,
            "master_definition_modified":False,
            "tpm_modified":False,
            "nvram_modified":False,
            "bitlocker_modified":False,
            "warning":"Do not boot: working overlay is still encrypted and not connected to VM"
        }
    finally:
        if tmp is not None:
            try:os.unlink(tmp)
            except FileNotFoundError:pass
        os.close(fd)

def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("plan","create"),default="plan")
    args=parser.parse_args(argv)
    try:
        print(json.dumps(perform(args.mode),indent=2,sort_keys=True))
        return 0
    except (Block,OSError,ValueError,ET.ParseError,json.JSONDecodeError) as exc:
        print(f"BLOCKED: {exc}",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
