#!/usr/bin/env python3
"""OTHER-HOST all-N offline RAW OVMF -> QCOW2 conversion for exact NAT clones.

Only after the independent exact golden-master Windows QCOW2 clone disks
and persistent default/virbr0 NAT NICs exist; BEFORE any new clone boots.
Requires all N clones and master SHUT OFF, zero existing snapshots, exact
root-private evidence dir, explicit N-level operator approval. Preserve
original RAW UEFI VARS and original inactive VM XML for every clone,
prepare standalone same-byte QCOW2 firmware copy, then change ONLY the
saved <os><nvram> reference/format. No source win11 mutation or guest
start/restart, no TPM blob copy/edit, no auto rollback/retry after a
partial step. This makes native RAM+OS+UEFI capture technically possible;
TPM rollback still NOT validated nor approved.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

import command2_portable_master_nat_attach as attach

MAX_RAW=16*1024*1024
LOCK=Path("/run/lock/cape-command2-master-nat-ovmf-convert.lock")
class NatFirmwareBlocked(RuntimeError):pass
def need(x,msg):
    if not x:raise NatFirmwareBlocked(msg)

def qemu(*args,timeout=180):
    try:
        p=subprocess.run(["qemu-img",*args],capture_output=True,text=True,
                         check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise NatFirmwareBlocked("qemu-img absent or timed out") from exc
    need(p.returncode==0 and len(p.stdout)<=16384,
         "qemu-img inspected/converted image returned nonzero")
    return p.stdout.strip()

def sha(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for data in iter(lambda:f.read(1024*1024),b""):
            h.update(data)
    return h.hexdigest()

def private_folder(path):
    p=Path(path)
    need(p.is_absolute() and p.is_dir() and not p.is_symlink() and
         p.stat().st_uid==0 and stat.S_IMODE(p.stat().st_mode)==0o700,
         "Evidence must be an existing root-only 0700 folder")
    return p

def inspect_one(row,folder,active):
    vm=row["libvirt_name"]
    need(attach.virsh("domstate",vm).lower()=="shut off" and
         not attach.virsh("snapshot-list",vm,"--name").strip(),
         "Cloned VM must be stopped and snapshot-free before firmware change")
    actual=attach.virsh("dumpxml","--inactive",vm)
    root=ET.fromstring(actual)
    nv=root.find("./os/nvram")
    loader=root.find("./os/loader")
    tpm=root.find("./devices/tpm/backend")
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==vm and
         root.findtext("uuid")==row["libvirt_uuid_candidate"] and
         loader is not None and loader.get("type")=="pflash" and
         nv is not None and
         tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0",
         "Master clone identity/UEFI pflash/swtpm device changed")
    disk=root.findall("./devices/disk[@device='disk']")
    nics=root.findall("./devices/interface")
    need(len(disk)==1 and disk[0].find("source") is not None and
         disk[0].find("source").get("file")==row["disk_target"] and
         len(nics)==1 and nics[0].find("source") is not None and
         nics[0].find("source").get("network")=="default" and
         nics[0].find("model") is not None and
         nics[0].find("model").get("type")=="e1000e" and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address","").lower()==row["mac_candidate"].lower(),
         "Wrong Windows OS image or NAT interface")
    raw=Path(row["uefi_nvram_target"])
    sidecar=Path(str(raw)+".qcow2")
    backup=folder/(vm+".ovmf-before-qcow2.xml")
    need(raw.is_absolute() and raw.is_file() and not raw.is_symlink() and
         raw.stat().st_nlink==1 and 0<raw.stat().st_size<=MAX_RAW,
         "Original UEFI RAW vars absent/linked/oversized")
    original=json.loads(qemu("info","--output=json",str(raw)))
    need(original.get("format")=="raw" and
         original.get("virtual-size")==raw.stat().st_size,
         "Original UEFI source no longer RAW")
    if not active:
        need(nv.get("format","raw")=="raw" and
             (nv.text or "")==str(raw) and
             not sidecar.exists() and not sidecar.is_symlink() and
             not backup.exists() and not backup.is_symlink(),
             "Only never-converted exact RAW VM is eligible for new conversion")
        outcome="RAW_NVRAM_NOT_CONVERTED"
    else:
        need(nv.get("format")=="qcow2" and (nv.text or "")==str(sidecar) and
             sidecar.is_file() and not sidecar.is_symlink() and
             sidecar.stat().st_nlink==1 and
             (sidecar.stat().st_uid,sidecar.stat().st_gid)==
             (raw.stat().st_uid,raw.stat().st_gid) and
             backup.is_file() and not backup.is_symlink() and
             backup.stat().st_uid==0 and
             stat.S_IMODE(backup.stat().st_mode)==0o600,
             "Expected saved QCOW2 vars and prior XML backup missing")
        metadata=json.loads(qemu("info","--output=json",str(sidecar)))
        need(metadata.get("format")=="qcow2" and
             metadata.get("virtual-size")==raw.stat().st_size and
             not metadata.get("backing-filename"),
             "UEFI QCOW2 variables have backing/format mismatch")
        qemu("compare","-f","raw","-F","qcow2",str(raw),str(sidecar))
        prior=ET.fromstring(backup.read_text(encoding="utf-8"))
        priornv=prior.find("./os/nvram")
        need(prior.findtext("name")==vm and
             prior.findtext("uuid")==row["libvirt_uuid_candidate"] and
             priornv is not None and
             priornv.get("format","raw")=="raw" and
             (priornv.text or "")==str(raw),
             "Prior preserved RAW OVMF domain XML identity mismatch")
        outcome="QCOW2_NVRAM_ACTIVE_IN_SAVED_XML"
    return {"vm":vm,"uuid":row["libvirt_uuid_candidate"],
            "mac":row["mac_candidate"].lower(),
            "original_raw_path":str(raw),"sidecar":str(sidecar),
            "source_nvram_sha256":sha(raw),
            "source_nvram_size":raw.stat().st_size,
            "inactive_xml_sha256":hashlib.sha256(actual.encode()).hexdigest(),
            "original_xml_backup":str(backup),"state":outcome,
            "clone_shut_off":True,
            "protected_source_master_not_modified":True}

def check(host,journal,evidence,active):
    attach.workflow.canonical_host(host)
    need(os.geteuid()==0,"Root required for exact golden-master firmware")
    folder=private_folder(evidence)
    rows=attach.journal_rows(host,journal)
    need(1<=len(rows)<=16,"Exact count-driven clone journal required")
    need(not attach.virsh("list","--name").strip(),
         "All VMs, including master, must be off during firmware conversion")
    source=attach.profile.check_master()
    need(source["master_left_shut_off"] is True,
         "Protected win11 master changed")
    actual=[inspect_one(row,folder,active) for row in rows]
    return {"result":("COMMAND2_ALL_N_QCOW2_OVMF_SAVED_VERIFIED"
                      if active else "COMMAND2_ALL_N_QCOW2_OVMF_CONVERSION_PLAN"),
        "host":host,"count":len(actual),"guests":actual,
        "master_shut_off_and_unmodified":True,
        "original_raw_and_xml_preserved":True,
        "Windows_OS_disk_or_TPM_state_changed":False,
        "any_guest_started_or_snapshot_created":False,
        "UEFI_snapshot_compatible_format_planned":True,
        "TPM_safe_snapshot_restoration_proven":False,
        "CAPE_READY":False}

def copy_and_define(row,folder):
    before=inspect_one(row,folder,False)
    raw=Path(before["original_raw_path"])
    dst=Path(before["sidecar"])
    backup=Path(before["original_xml_backup"])
    current=attach.virsh("dumpxml","--inactive",row["libvirt_name"])
    need(hashlib.sha256(current.encode()).hexdigest()==before["inactive_xml_sha256"],
         "Clone domain changed since firmware preflight")
    # Save original XML DURABLY before any changed libvirt definition.
    fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        f.write(current);f.flush();os.fsync(f.fileno())
    dirfd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(dirfd)
    finally:os.close(dirfd)
    # qemu-img refuses an existing destination; no overwrite. Preserve
    # raw unchanged; verify exact byte equivalence before activating.
    qemu("convert","-f","raw","-O","qcow2",str(raw),str(dst),timeout=180)
    os.chown(dst,raw.stat().st_uid,raw.stat().st_gid)
    os.chmod(dst,0o600)
    qemu("check","-f","qcow2",str(dst))
    qemu("compare","-f","raw","-F","qcow2",str(raw),str(dst))
    need(sha(raw)==before["source_nvram_sha256"],
         "Source RAW firmware mutated while copying")
    root=ET.fromstring(current)
    nv=root.find("./os/nvram")
    need(nv is not None and nv.get("format","raw")=="raw" and
         (nv.text or "")==str(raw),"Stopped VM firmware changed")
    nv.set("format","qcow2");nv.text=str(dst)
    with tempfile.NamedTemporaryFile(mode="wb",dir=str(folder),
        prefix=".command2-nat-ovmf-",suffix=".xml",delete=False) as out:
        tmp=Path(out.name)
        os.fchmod(out.fileno(),0o600)
        out.write(ET.tostring(root,encoding="utf-8"))
        out.flush();os.fsync(out.fileno())
    try:
        attach.virsh("define",str(tmp),"--validate",timeout=90)
    finally:
        tmp.unlink(missing_ok=True)
    return inspect_one(row,folder,True)

def apply(host,journal,evidence):
    need(sys.stdin.isatty(),"Direct operator approval for N guest UEFI conversion")
    old=check(host,journal,evidence,False)
    print(json.dumps(old,indent=2,sort_keys=True),flush=True)
    phrase="CONVERT-"+str(old["count"])+"-MASTER-NAT-UEFI-QCOW2-ONLY"
    need(input("Type "+phrase+" to preserve RAW and switch saved clone XML: ")==phrase,
         "Operator denied protected clone-only UEFI switch")
    need(not LOCK.is_symlink(),"Unsafe firmware conversion lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    attempted=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Firmware conversion lock metadata unsafe")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise NatFirmwareBlocked("Concurrent firmware stage already active") from e
        need(check(host,journal,evidence,False)==old,
             "Guest/source firmware changed after operator consent")
        rows=attach.journal_rows(host,journal)
        done=[]
        for row in rows:
            attempted=True
            done.append(copy_and_define(row,private_folder(evidence)))
        full=check(host,journal,evidence,True)
        return {**full,"result":"COMMAND2_ALL_N_MASTER_NAT_OVMF_QCOW2_APPLIED_VERIFIED",
                "actual_guest_boot_or_TPM_revert_verified":False}
    except Exception as e:
        if attempted:
            raise NatFirmwareBlocked(
                "OVMF_QCOW2_TRANSITION_MAY_BE_PARTIAL: stop; do NOT "
                "retry, delete originals, reboot guests or revert. "+str(e)) from e
        raise
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","apply","verify"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--evidence-dir",type=Path,required=True)
    a=p.parse_args()
    try:
        result=(apply(a.approved_host,a.journal,a.evidence_dir)
                if a.mode=="apply" else check(
                     a.approved_host,a.journal,a.evidence_dir,
                     a.mode=="verify"))
        print(json.dumps(result,indent=2,sort_keys=True),flush=True)
        return 0
    except (NatFirmwareBlocked,attach.NatAttachBlocked,
            attach.profile.PortableNatBlocked,
            attach.workflow.WorkflowBlocked,
            OSError,ValueError,KeyError,TypeError,ET.ParseError,
            json.JSONDecodeError) as e:
        print(json.dumps({"result":"COMMAND2_MASTER_NAT_OVMF_CONVERSION_BLOCKED",
            "reason":str(e),"do_not_autoretry_on_partial":True,
            "master_or_guest_TPM_mutated":False},
            sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__": raise SystemExit(main())
