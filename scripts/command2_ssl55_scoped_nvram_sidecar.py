#!/usr/bin/env python3
"""Scoped SSL-55 win11_1 RAW OVMF -> separate QCOW2 preparation (NOT activation).

Read-only plan is permitted with the existing guest RUNNING; it reports
the explicit stop-before-prepare requirement. Prepare only works when the
exact clone is already SHUT OFF, its master/trial untouched, its stopped
cold disk+OVMF+swtpm bundle has been byte reverified and a human has
approved. PREPARE changes NO VM definition, Windows disk, running memory,
TPM, original RAW OVMF or snapshot state. One new QCOW2 file only.

This is a necessary *preparation* for native UEFI running snapshots, not
a snapshot creation or proof that swtpm supports coordinated rollback.
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
import xml.etree.ElementTree as ET

import command2_ssl55_running_snapshot_readonly as reference

VM=reference.VM
UID=reference.UID
DISK=reference.DISK
VARS=reference.VARS
COLD=reference.COLD
SIDE=Path(str(VARS)+".qcow2")
GIB=1024**3
MIN_RESERVE=40*GIB
LOCK=Path("/run/lock/cape-command2-ssl55-win11-1-nvram-prepare.lock")

class SSL55PrepareBlocked(RuntimeError):pass
def need(ok,reason):
    if not ok:raise SSL55PrepareBlocked(reason)

def run(*args,timeout=120):
    try:
        p=subprocess.run(args,capture_output=True,text=True,check=False,
                         timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise SSL55PrepareBlocked("Host utility unavailable or timed out") from exc
    need(p.returncode==0,"Host utility nonzero result: "+args[0])
    return p.stdout.strip()

def virsh(*args):
    return run("virsh","-c","qemu:///system",*args)

def sha256(file):
    h=hashlib.sha256()
    with Path(file).open("rb") as fd:
        for chunk in iter(lambda:fd.read(4*1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def regular(file,*,root=False):
    p=Path(file)
    need(p.is_absolute() and not p.is_symlink() and p.is_file(),
         "Snapshot recovery source missing/symlinked: "+p.name)
    st=p.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,
         "Snapshot recovery artifact has unexpected hardlinks")
    if root:
        need(st.st_uid==0 and not st.st_mode&0o022,
             "Recovery source must be root controlled")
    return st

def verify_existing_bundle():
    need(COLD.is_absolute() and COLD.is_dir() and not COLD.is_symlink(),
         "Canonical existing clone-only cold recovery folder missing")
    directory=COLD.stat()
    need(directory.st_uid==0 and
         stat.S_IMODE(directory.st_mode)&0o077==0,
         "Cold recovery folder must be root-private")
    manifest=COLD/"manifest.json"
    mstat=regular(manifest,root=True)
    need(0<mstat.st_size<128*1024,"Recovery manifest unexpectedly sized")
    raw=manifest.read_bytes()
    data=json.loads(raw)
    need(type(data) is dict and
         data.get("format")=="cape-ssl55-cold-v1" and
         data.get("vm")==VM and data.get("uuid")==UID and
         data.get("restore_tested") is False and
         type(data.get("files")) is list,
         "Unexpected existing cold recovery manifest")
    members=data["files"]
    need(len(members)>=3 and len(members)<=12,
         "Cold recovery file set incomplete/unbounded")
    names=[r.get("name") for r in members if type(r) is dict]
    need(len(names)==len(members) and len(set(names))==len(names) and
         {"disk.qcow2","uefi-vars.fd"}.issubset(names) and
         any(n.startswith("tpm-") and n.endswith(".permall") for n in names),
         "Recovery must contain disk, RAW OVMF and swtpm persistent state")
    checked=[]
    for item in members:
        name=item["name"]
        need(type(name) is str and
             re.fullmatch(r"(?:disk\.qcow2|uefi-vars\.fd|tpm-[A-Za-z0-9_.-]+)",name)
             and name not in ("tpm-.","tpm-..") and
             type(item.get("size")) is int and item["size"]>0 and
             type(item.get("sha256")) is str and
             re.fullmatch(r"[0-9a-f]{64}",item["sha256"]),
             "Unexpected cold recovery member")
        path=COLD/name
        st=regular(path,root=True)
        need(st.st_size==item["size"] and sha256(path)==item["sha256"],
             "Saved cold recovery hash/length changed: "+name)
        checked.append(name)
    # The previous cold backup is preserved, not silently rewritten.
    return {"manifest_sha256":hashlib.sha256(raw).hexdigest(),
            "byte_verified_member_count":len(checked),
            "full_cold_restore_actually_tested":False}

def inspect():
    need(os.geteuid()==0,"Root needed to read private host/swtpm state")
    need(socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Only canonical protected SSL-55 scoped win11_1 supported")
    need(virsh("domuuid",VM).lower()==UID,"Actual clone UUID differs")
    state=virsh("domstate",VM).lower()
    need(state in ("running","shut off"),
         "Refuse paused, saved, migrated or otherwise unexpected clone state")
    for vm,uid in (reference.MASTER,reference.TRIAL):
        need(virsh("domuuid",vm).lower()==uid and
             virsh("domstate",vm).lower()=="shut off",
             "Protected master or trial changed from preserved state: "+vm)
    need(not virsh("snapshot-list",VM,"--name").strip(),
         "Unexpected preexisting clone snapshots; stop and inspect")
    saved=virsh("dumpxml","--inactive",VM)
    xml=reference.checkdomain(saved)
    if state=="running":
        need(reference.checkdomain(virsh("dumpxml",VM))==xml,
             "Saved and RUNNING guest identity/firmware/NIC differ")
    need(xml["xml_nvram_format"]=="raw",
         "Original RAW firmware not in expected format")
    disk=regular(DISK)
    nvram=regular(VARS)
    need(0<nvram.st_size<16*1024*1024,
         "Unexpected raw OVMF variable store size")
    qdisk=json.loads(run("qemu-img","info","-U","--output=json",str(DISK)))
    qvars=json.loads(run("qemu-img","info","-U","--output=json",str(VARS)))
    need(qdisk.get("format")=="qcow2" and
         not qdisk.get("backing-filename") and
         qvars.get("format")=="raw",
         "Clone disk or RAW firmware has unexpected real format")
    need(not SIDE.exists() and not SIDE.is_symlink(),
         "Firmware QCOW2 sidecar already exists; stop for inspection")
    backup=verify_existing_bundle()
    free=os.statvfs(VARS.parent)
    headroom=free.f_bavail*free.f_frsize
    need(headroom>MIN_RESERVE+2*GIB,
         "Insufficient free disk for firmware preparation + shared-host reserve")
    return {"result":"SSL55_WIN11_1_QCOW2_OVMF_SIDECAR_PLAN_ONLY",
            "vm":VM,"uuid":UID,"vm_state":state,
            "requires_clean_shutdown_before_prepare":state!="shut off",
            "protected_master_and_trial_shut_off":True,
            "raw_original":str(VARS),"raw_sha256":sha256(VARS),
            "proposed_distinct_sidecar":str(SIDE),
            "saved_vm_xml_sha256":hashlib.sha256(saved.encode()).hexdigest(),
            "cold_recovery_manifest_sha256":backup["manifest_sha256"],
            "existing_cold_recovery_files_rehashed":backup["byte_verified_member_count"],
            "cold_backup_real_restore_tested":False,
            "swtpm_atomic_snapshot_restore_verified":False,
            "source_master_files_touched":False,
            "running_snapshot_created":False,"host_or_guest_changed":False}

def prepare():
    need(sys.stdin.isatty(),"Direct local terminal required for firmware preparation")
    first=inspect()
    need(first["vm_state"]=="shut off",
         "NO LIVE CONVERSION: cleanly shut down ONLY win11_1 and re-run")
    print(json.dumps(first,indent=2,sort_keys=True),flush=True)
    phrase="PREPARE-SSL55-CLONE-NVRAM-QCOW2"
    need(input("Type "+phrase+" to create a NEW separate firmware sidecar ONLY: ")==
         phrase,"Preparation approval not given")
    need(not LOCK.is_symlink(),"Untrusted firmware preparation lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Unsafe lock file metadata")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SSL55PrepareBlocked("Concurrent NVRAM preparation") from exc
        need(inspect()==first,"VM/cold recovery/source changed since operator approval")
        saved_xml_before=virsh("dumpxml","--inactive",VM)
        # A stopped VM's QEMU/swtpm processes must have exited before even
        # reading its state for an operation that might later be activated.
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():continue
            try:
                cmd=(entry/"cmdline").read_bytes().decode("utf-8","replace").lower()
            except (OSError,UnicodeError):
                continue
            if UID in cmd and any(k in cmd for k in ("qemu-system","swtpm")):
                raise SSL55PrepareBlocked("QEMU/swtpm clone process unexpectedly active")
        temp=Path(str(SIDE)+".pending")
        need(not temp.exists() and not temp.is_symlink(),
             "Incomplete existing firmware conversion candidate; refuse retry")
        try:
            run("qemu-img","convert","-f","raw","-O","qcow2",
                str(VARS),str(temp),timeout=180)
            need(temp.is_file() and not temp.is_symlink(),
                 "Converted candidate missing")
            st=VARS.stat()
            os.chown(temp,st.st_uid,st.st_gid)
            os.chmod(temp,0o600)
            run("qemu-img","check","-f","qcow2",str(temp))
            run("qemu-img","compare","-f","raw","-F","qcow2",
                str(VARS),str(temp),timeout=180)
            meta=json.loads(run("qemu-img","info","--output=json",str(temp)))
            need(meta.get("format")=="qcow2" and
                 meta.get("virtual-size")==st.st_size and
                 not meta.get("backing-filename") and
                 sha256(VARS)==first["raw_sha256"],
                 "QCOW2 conversion not an exact standalone RAW equivalent")
            os.link(temp,SIDE,follow_symlinks=False)
            temp.unlink()
            dfd=os.open(VARS.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(dfd)
            finally:os.close(dfd)
        except (OSError,SSL55PrepareBlocked,ValueError,TypeError) as exc:
            raise SSL55PrepareBlocked("Incomplete sidecar retained for inspection; "
                     "no retry, original RAW and VM XML unchanged: "+str(exc)) from exc
        need(virsh("domstate",VM).lower()=="shut off" and
             virsh("dumpxml","--inactive",VM)==saved_xml_before,
             "VM state/XML changed unexpectedly after preparation")
        return {"result":"SSL55_CLONE_OVMF_SIDECAR_CREATED_INACTIVE",
                "vm":VM,"sidecar":str(SIDE),"sidecar_sha256":sha256(SIDE),
                "original_raw_kept":True,"guest_vm_xml_changed":False,
                "guest_booted":False,"running_snapshot_created":False,
                "tpm_rollback_proven":False,
                "requires_separately_approved_qcow2_xml_transition":True}
    finally:os.close(fd)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=("plan","prepare"),default="plan")
    args=parser.parse_args()
    try:
        result=inspect() if args.mode=="plan" else prepare()
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (SSL55PrepareBlocked,reference.AuditBlocked,OSError,
            ValueError,TypeError,KeyError,ET.ParseError,
            subprocess.TimeoutExpired) as exc:
        print(json.dumps({"result":"SSL55_CLONE_NVRAM_PREPARATION_BLOCKED",
            "reason":str(exc),"no_automatic_vm_or_tpm_changes":True},
            sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
