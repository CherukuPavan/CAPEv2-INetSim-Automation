#!/usr/bin/env python3
"""Cold, independent export of the decrypted Windows 11 maintenance overlay.

Requires manual Windows guest shutdown after BitLocker status reports Fully
Decrypted, 0.0%. Plan is read-only. Export creates ONE new root-private
flattened QCOW2 template, never mutates original master/maintenance layers,
libvirt XML, original TPM/NVRAM, snapshots or network.

The template is not a configured analysis VM or evidence of safe egress.
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

import probe_cold_windows_volume_crypto as cryptoprobe

MASTER="win11"
SNAP="finalshutoffversion"
ORIGINAL="/var/lib/libvirt/images/win11.finalshutoffversion"
SOURCE="/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2"
OUTPUT=Path("/var/lib/libvirt/images/cape-clones-staging/win11_decrypted_template.qcow2")
BACKUP=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
LOCK=Path("/run/lock/cape-cold-export.lock")
RESERVE=30*1024**3
SIZE=64*1024**3

class TemplateExportError(RuntimeError):
    pass

def ensure(test:bool, reason:str)->None:
    if not test:
        raise TemplateExportError(reason)

def shell(*args:str,timeout:int=90)->str:
    try:
        return subprocess.run(args,text=True,capture_output=True,check=True,
                              timeout=timeout).stdout.strip()
    except (OSError,subprocess.TimeoutExpired,subprocess.CalledProcessError) as exc:
        # Do not print untrusted guest or saved configuration content.
        raise TemplateExportError(f"{args[0]} failed during template export") from exc

def virsh(*args:str)->str:
    return shell("virsh","-c","qemu:///system",*args)

def secure_regular(path:Path):
    ensure(path.is_absolute() and ".." not in path.parts,
           "Unexpected relative or parent-traversing source")
    for anc in (path,*path.parents):
        ensure(not anc.is_symlink(),"Source path contains symlink")
    st=path.stat()
    ensure(stat.S_ISREG(st.st_mode),"Missing regular image file")
    return st

def fingerprint(names:list[str])->list[tuple]:
    return [
        (str(p),s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        for p in map(Path,names) for s in (secure_regular(p),)
    ]

def read_preflight()->tuple[list[str],dict]:
    ensure(os.geteuid()==0,"Requires sudo on SSL-55")
    ensure(virsh("domstate",MASTER)=="shut off",
           "Windows is still running: shut down Windows normally first")
    ensure(virsh("snapshot-current",MASTER,"--name")==SNAP,
           "Original cold snapshot pointer changed")
    ensure(BACKUP.is_dir() and not BACKUP.is_symlink()
           and BACKUP.stat().st_uid==0
           and (BACKUP.stat().st_mode & 0o077)==0,
           "Protected original state backup unavailable")
    dom_backup=BACKUP/"metadata"/"domain.xml"
    snap_backup=BACKUP/"metadata"/("snapshot-"+SNAP+".xml")
    ensure(dom_backup.is_file() and snap_backup.is_file(),
           "Original backup XML files missing")
    dom=ET.fromstring(virsh("dumpxml","--inactive",MASTER))
    prior=ET.fromstring(dom_backup.read_text())
    ensure(dom.findtext("./uuid")==prior.findtext("./uuid"),
           "Guest identity differs from protected original")
    ensure(dom.find("./os/nvram") is not None and
           prior.find("./os/nvram") is not None and
           (dom.find("./os/nvram").text or "").strip()==
           (prior.find("./os/nvram").text or "").strip(),
           "Guest UEFI NVRAM pairing changed")
    tpm=dom.find("./devices/tpm/backend")
    prev_tpm=prior.find("./devices/tpm/backend")
    ensure(tpm is not None and prev_tpm is not None and
           tpm.get("type")==prev_tpm.get("type")=="emulator" and
           tpm.get("version")==prev_tpm.get("version"),
           "Original TPM backend differs from preserved definition")
    disks=dom.findall("./devices/disk[@device='disk']")
    ensure(len(disks)==1 and disks[0].find("source") is not None and
           disks[0].find("source").get("file")==SOURCE,
           "win11 not using the expected maintenance overlay")
    for tag in ("interface","redirdev","channel","hostdev","filesystem"):
        ensure(not dom.findall("./devices/"+tag),
               "Maintenance guest definition unexpectedly has "+tag)
    ensure(virsh("snapshot-dumpxml",MASTER,SNAP).strip() ==
           snap_backup.read_text().strip(),
           "Original cold snapshot metadata has changed")
    raw=json.loads(shell("qemu-img","info","--output=json",
                         "--backing-chain",SOURCE,timeout=120))
    ensure(isinstance(raw,list) and len(raw)==5 and
           all(item.get("format")=="qcow2" for item in raw) and
           raw[0].get("filename")==SOURCE and
           raw[0].get("virtual-size")==SIZE and
           raw[0].get("full-backing-filename")==ORIGINAL and
           raw[1].get("filename")==ORIGINAL,
           "Unexpected maintenance backing chain")
    names=[x.get("filename") for x in raw]
    ensure(all(isinstance(n,str) for n in names),
           "Malformed backing layer")
    fingerprint(names)
    try:
        crypto=cryptoprobe.require_cleartext_candidate(Path(SOURCE))
    except cryptoprobe.VolumeProbeError as exc:
        raise TemplateExportError(
            "Maintenance disk did not verify as clear NTFS; no export permitted"
        ) from exc
    ensure(OUTPUT.is_absolute() and
           not OUTPUT.exists() and not OUTPUT.is_symlink(),
           "Independent plaintext template destination already exists")
    folder=OUTPUT.parent
    ensure(folder.is_dir() and not folder.is_symlink(),
           "Root-only output folder missing")
    folder_stat=folder.stat()
    ensure(folder_stat.st_uid==0 and not folder_stat.st_mode & 0o022,
           "Output folder must not be writable by untrusted users")
    free=shutil.disk_usage(folder).free
    ensure(free>=SIZE+RESERVE,
           "Insufficient disk space for 64 GiB copy plus 30 GiB reserve")
    return names,{
        "source":SOURCE,
        "destination":str(OUTPUT),
        "virtual_size_gib":64,
        "free_space_gib":round(free/1024**3,2),
        "source_partitions":crypto["partitions"],
        "source_clear_ntfs_candidate":True,
        "master_shut_off":True,
        "original_snapshot_unchanged":True,
        "original_tpm_and_nvram_read_or_copied":False,
    }

def perform(mode:str)->dict:
    ensure(mode in ("plan","export"),"Unknown template export mode")
    if mode=="plan":
        _,summary=read_preflight()
        return dict(summary,mode="PLAN_READ_ONLY",
                    copy_created=False,master_modified=False)
    ensure(not LOCK.is_symlink(),"Unsafe maintenance/export lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    temp=None
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        initial,summary=read_preflight()
        before=fingerprint(initial)
        fd_tmp,temp=tempfile.mkstemp(prefix=".cape-decrypted-template-",
                                    suffix=".qcow2",dir=OUTPUT.parent)
        os.close(fd_tmp)
        os.unlink(temp)
        print("Converting cold decrypted overlay to a standalone QCOW2 template...",
              flush=True)
        shell("qemu-img","convert","-f","qcow2","-O","qcow2",
              "-o","compat=1.1",SOURCE,temp,timeout=7200)
        os.chmod(temp,0o600)
        shell("qemu-img","check","-q","-f","qcow2",temp,timeout=3600)
        out=json.loads(shell("qemu-img","info","--output=json",temp))
        ensure(out.get("format")=="qcow2" and
               out.get("virtual-size")==SIZE and
               not out.get("backing-filename") and
               not out.get("full-backing-filename"),
               "Output retained backing dependency or invalid format")
        try:
            cryptoprobe.require_cleartext_candidate(Path(temp))
        except cryptoprobe.VolumeProbeError as exc:
            raise TemplateExportError(
                "Output QCOW2 plaintext verification failed"
            ) from exc
        subsequent,_=read_preflight()
        ensure(subsequent==initial and fingerprint(initial)==before,
               "Maintenance source changed during template export")
        ensure(shutil.disk_usage(OUTPUT.parent).free>=RESERVE,
               "Insufficient post-export disk reserve")
        ensure(not OUTPUT.exists() and not OUTPUT.is_symlink(),
               "Destination appeared during conversion")
        os.link(temp,OUTPUT)
        os.unlink(temp)
        temp=None
        return dict(summary,
                    mode="EXPORTED_STANDALONE_PLAINTEXT_QCOW2",
                    output_has_backing_file=False,
                    output_clear_ntfs_candidate=True,
                    copy_created=True,master_modified=False,
                    vm_registered=False,guest_boot_verified=False,
                    isolated_network_verified=False,
                    warning="Template contains accessible Windows data; keep root-private")
    finally:
        if temp is not None:
            try:os.unlink(temp)
            except FileNotFoundError:pass
        os.close(fd)

def main(argv=None)->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("plan","export"),default="plan")
    args=parser.parse_args(argv)
    try:
        print(json.dumps(perform(args.mode),indent=2,sort_keys=True))
        return 0
    except (OSError,ValueError,ET.ParseError,TemplateExportError) as exc:
        print("BLOCKED:",str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
