#!/usr/bin/env python3
"""Undo ONLY an untouched, shut-off, zero-NIC Command2 staged clone.

Read original root-private reservation and per-VM BEFORE and COMPLETE
receipts. Refuse guest ever booted, network attached, snapshots, TPM state,
saved state, source drift, foreign disk/firmware refs, or UUID mismatch.
Never delete disk/UEFI bytes: after an explicitly consented libvirt undefine
with --keep-nvram, quarantine exact independent OS/NVRAM files by same-FS
atomic renames. Every step is durably journaled; partial changes STOP and
must be reconciled manually. No guest or unrelated host resources touched.

Not a universal rollback: once Windows guest first-boots, changes its TPM,
or acquires any NIC/snapshot, this route correctly REFUSES operation.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import xml.etree.ElementTree as ET

import command2_portable_zero_nic_stager as stager

VM = re.compile(r"win11_([1-9]|1[0-6])\Z")
RECORD_PREFIX = "command2-zero-nic-rollback-"
STATES = ("prepared", "domain_undefined", "disk_quarantined",
          "nvram_quarantined", "verified")


class CloneRollbackBlocked(RuntimeError):
    pass


def need(ok, why):
    if not ok:
        raise CloneRollbackBlocked(why)


def private_json(path, max_bytes=65536):
    stager.exact_file(path, max_bytes=max_bytes)
    obj=json.loads(Path(path).read_bytes())
    need(type(obj) is dict, "Untrusted clone journal record")
    return obj


def expected(host, folder, vm):
    need(type(vm) is str and VM.fullmatch(vm), "Invalid owned clone name")
    stager.host_guard(host, for_stage=True)
    root=stager.exact_dir(folder, mode=0o700)
    rows=stager.reservation_entries(root,host)
    found=[r for r in rows if r["libvirt_name"]==vm]
    need(len(found)==1,"Unowned clone missing from original reservation")
    row=found[0]
    intent=private_json(root/(stager.INTENT_PREFIX+vm+".json"))
    complete=private_json(root/(stager.COMPLETE_PREFIX+vm+".json"))
    need(intent=={
        "name":vm,"stage":"BEFORE_ANY_CLONE_FILES",
        "disk":row["disk_target"],"nvram":row["uefi_nvram_target"],
        "uuid":row["libvirt_uuid_candidate"],"zero_nics":True
    },"Staging intent does not prove exact original absence")
    need(complete=={
        "name":vm,"status":"SHUT_OFF_ZERO_NICS_STAGED",
        "uuid":row["libvirt_uuid_candidate"],
        "tpm_persistent_state_created":False,
        "guest_personalized":False,"network_attached":False,
        "clean_restore_verified":False
    },"Staging completion record not exact")
    return row


def sha256_file(path):
    h=hashlib.sha256()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        while True:
            b=os.read(fd,1024*1024)
            if not b: break
            h.update(b)
    finally:
        os.close(fd)
    return h.hexdigest()


def no_foreign_domain_uses_images(vm,disk,nvram):
    """A user's other guest must never lose shared Windows storage."""
    names=[x.strip() for x in
           stager.virsh("list","--all","--name").splitlines() if x.strip()]
    need(len(names)<=128 and len(names)==len(set(names)),
         "Cannot trust libvirt domain inventory")
    need(vm in names, "Target clone not present in complete VM inventory")
    for other in names:
        if other==vm:
            continue
        need(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", other) is not None,
             "Foreign libvirt name invalid; stop cleanup")
        root=ET.fromstring(stager.virsh("dumpxml","--inactive",other))
        need(root.tag=="domain" and root.findtext("name")==other,
             "Cannot review other domain storage")
        disks={elem.get("file") for elem in
               root.findall("./devices/disk/source") if elem.get("file")}
        fw=root.findtext("./os/nvram")
        need(disk not in disks and nvram not in disks and
             fw not in (disk,nvram),
             "Another defined VM references this clone's OS/UEFI storage")


def live_admission(row):
    vm=row["libvirt_name"]
    uid=row["libvirt_uuid_candidate"]
    need(stager.virsh("domuuid",vm).lower()==uid and
         stager.virsh("domstate",vm).lower()=="shut off",
         "Clone UUID changed or guest not completely shut off")
    need(not stager.virsh("list","--name").strip(),
         "Cannot modify clone while ANY libvirt guest runs")
    need(not stager.virsh("snapshot-list",vm,"--name").strip(),
         "Snapshot metadata exists: zero-NIC staged-only recovery forbidden")
    need(re.search(r"(?mi)^Managed save:\s*no\s*$",
                   stager.virsh("dominfo",vm)) is not None,
         "Cannot prove absence of guest managed RAM save")
    raw=stager.virsh("dumpxml","--inactive",vm)
    root=ET.fromstring(raw)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==vm and root.findtext("uuid")==uid and
         root.findtext("genid")==row["smbios_generation_id_candidate"] and
         not root.findall("./devices/interface") and
         not root.findall("./devices/hostdev") and
         not root.findall("./devices/filesystem"),
         "Guest XML no longer matches exact shutoff zero-NIC clone")
    disks=root.findall("./devices/disk[@device='disk']/source")
    need(len(disks)==1 and disks[0].get("file")==row["disk_target"] and
         root.findtext("./os/nvram")==row["uefi_nvram_target"],
         "Guest no longer references the owned standalone images")
    tpm=root.find("./devices/tpm/backend")
    need(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0",
         "Unknown guest TPM backend")
    # NEVER remove a TPM that Windows might have touched.
    tpm_dir=Path("/var/lib/libvirt/swtpm")/uid
    need(not tpm_dir.exists() and not tpm_dir.is_symlink(),
         "Persistent/volatile swtpm state exists: require different coherent recovery")
    no_foreign_domain_uses_images(vm,row["disk_target"],
                                  row["uefi_nvram_target"])
    return raw


def standalone_paths(row):
    disk=Path(row["disk_target"])
    nvram=Path(row["uefi_nvram_target"])
    need(disk.is_absolute() and nvram.is_absolute() and
         disk!=nvram and
         disk.name==row["libvirt_name"]+".command2.qcow2" and
         nvram.name==row["libvirt_name"]+".command2_VARS.fd",
         "Unowned or unexpectedly named VM images")
    stager.exact_dir(disk.parent)
    stager.exact_dir(nvram.parent)
    stager.exact_file(disk,root=False)
    stager.exact_file(nvram,root=False)
    need(disk.stat().st_nlink==1 and nvram.stat().st_nlink==1,
         "Shared disk or firmware hardlink")
    return disk,nvram


def plan(host,folder,vm):
    row=expected(host,folder,vm)
    target=Path(folder)/(RECORD_PREFIX+vm+".json")
    need(not target.exists() and not target.is_symlink(),
         "Clone undo already attempted; no blind replay")
    xml=live_admission(row)
    disk,nvram=standalone_paths(row)
    uid=row["libvirt_uuid_candidate"]
    # The original guest must be present and shut off. No imported master
    # or foreign guest is ever targeted for undefinition by this route.
    need(stager.virsh("domstate","win11").lower()=="shut off",
         "Protected exact Windows master not shut off")
    quarantine_disk=disk.parent/("."+disk.name+".quarantine-"+uid)
    quarantine_nvram=nvram.parent/("."+nvram.name+".quarantine-"+uid)
    need(not any(p.exists() or p.is_symlink() for p in
                 (quarantine_disk,quarantine_nvram)),
         "Quarantine conflict blocks reverse staging")
    return {
        "result":"COMMAND2_ZERO_NIC_UNTOUCHED_CLONE_UNDO_PLAN_ONLY",
        "vm":vm,"uuid":uid,"host":host,
        "disk":str(disk),"nvram":str(nvram),
        "disk_quarantine":str(quarantine_disk),
        "nvram_quarantine":str(quarantine_nvram),
        "inactive_domain_xml_sha256":hashlib.sha256(xml.encode()).hexdigest(),
        "disk_sha256":sha256_file(disk),
        "nvram_sha256":sha256_file(nvram),
        "clone_was_absent_before_staging":True,
        "clone_zero_nics":True,
        "TPM_state_absent":True,
        "snapshots_absent":True,
        "vm_running":False,
        "host_modified":False,
        "complete_deployment_rollback":False,
    }


def record(path,payload,first=False):
    need(type(payload) is dict and payload.get("schema") == 1 and
         payload.get("status") in STATES and
         type(payload.get("vm")) is str and
         VM.fullmatch(payload["vm"]) is not None,
         "Malformed zero-NIC recovery receipt")
    raw=(json.dumps(payload,sort_keys=True,separators=(",",":"))+"\n").encode()
    need(len(raw)<=16384,"Oversized VM undo receipt")
    if first:
        stager.atomic_note(path.parent,path.name,payload)
        return
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
             0<st.st_size<=16384,"Untrusted previous VM undo receipt")
        before=os.read(fd,16385)
        need(len(before)==st.st_size,"VM undo record changed during read")
    finally:
        os.close(fd)
    previous=json.loads(before)
    need(previous.get("schema")==1 and
         previous.get("vm")==payload["vm"] and
         previous.get("uuid")==payload["uuid"] and
         previous.get("before")==payload["before"] and
         previous.get("status") in STATES and
         STATES.index(payload["status"]) ==
         STATES.index(previous["status"])+1,
         "VM rollback receipt state changed or skipped")
    fd,tmp=tempfile.mkstemp(dir=path.parent,prefix=".vm-undo-")
    try:
        with os.fdopen(fd,"wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(),0o600)
            os.fsync(stream.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.lexists(tmp):os.unlink(tmp)
    _fsync(path.parent)


def quarantine_noreplace(source,target,expected_sha):
    """Same-dir, no-overwrite owned clone preservation.

    Hardlink the exact stopped guest image into its unique quarantine name
    using link(O_EXCL) semantics, then unlink the original name. A crash
    may leave TWO names pointing to the same inode; never auto-retry.
    """
    source=Path(source)
    target=Path(target)
    need(source.parent==target.parent and
         not source.is_symlink() and source.is_file() and
         not target.exists() and not target.is_symlink(),
         "Untrusted or colliding guest quarantine destination")
    need(source.stat().st_nlink==1 and
         sha256_file(source)==expected_sha,
         "Original guest image differs from approved source")
    os.link(source,target,follow_symlinks=False)
    _fsync(source.parent)
    need(source.stat().st_ino==target.stat().st_ino and
         sha256_file(target)==expected_sha,
         "Quarantine hardlink contents mismatch")
    os.unlink(source)
    _fsync(source.parent)
    need(not source.exists() and not source.is_symlink() and
         target.stat().st_nlink==1,
         "Original guest image remains linked after quarantine")
    return True


def revert(host,folder,vm):
    need(os.geteuid()==0 and sys.stdin.isatty(),
         "Root interactive approval required")
    initial=plan(host,folder,vm)
    print(json.dumps(initial,sort_keys=True,indent=2),flush=True)
    phrase="QUARANTINE-ONLY-UNTOUCHED-"+vm.upper()
    need(input("Type "+phrase+": ").strip()==phrase,
         "Zero-NIC staged clone undo declined")
    need(plan(host,folder,vm)==initial,
         "Clone changed after approval; preserve it")
    row=expected(host,folder,vm)
    root=stager.exact_dir(folder,mode=0o700)
    lock=root/".command2-zero-nic-rollback.lock"
    fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Untrusted staged-clone rollback lock")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise CloneRollbackBlocked("Another clone undo in progress") from e
        need(plan(host,folder,vm)==initial,
             "Snapshot, master, VM or file identity changed under lock")
        record_path=root/(RECORD_PREFIX+vm+".json")
        data={
            "schema":1,"vm":vm,"uuid":row["libvirt_uuid_candidate"],
            "status":"prepared","before":initial,
            "never_delete_any_VM_storage":True,
            "other_VM_resources_untouched":True,
            "complete_deployment_rollback":False,
        }
        record(record_path,data,True)
        try:
            stager.virsh("undefine",vm,"--keep-nvram")
            need(vm not in stager.virsh("list","--all","--name").splitlines(),
                 "Clone domain still defined; keep VM storage")
            data["status"]="domain_undefined"
            record(record_path,data)
            disk,nvram=standalone_paths(row)
            need(sha256_file(disk)==initial["disk_sha256"],
                 "Disk changed during VM undefinition")
            quarantine_noreplace(disk,initial["disk_quarantine"],
                                 initial["disk_sha256"])
            data["status"]="disk_quarantined"
            record(record_path,data)
            need(sha256_file(nvram)==initial["nvram_sha256"],
                 "UEFI changed during VM undefinition")
            quarantine_noreplace(nvram,initial["nvram_quarantine"],
                                 initial["nvram_sha256"])
            data["status"]="nvram_quarantined"
            record(record_path,data)
            need(not disk.exists() and not nvram.exists() and
                 sha256_file(initial["disk_quarantine"])==initial["disk_sha256"] and
                 sha256_file(initial["nvram_quarantine"])==initial["nvram_sha256"],
                 "Quarantined clone artifacts no longer match originals")
            data["status"]="verified"
            record(record_path,data)
            return {
                "result":"COMMAND2_UNTOUCHED_ZERO_NIC_CLONE_QUARANTINED",
                "vm":vm,"root_private_receipt":str(record_path),
                "disk_and_uefi_bytes_preserved":True,
                "master_vm_unchanged":True,
                "tpm_state_was_absent":True,
                "complete_deployment_rollback":False,
            }
        except Exception as exc:
            # Intent is durable and the operation is deliberately NOT
            # idempotent; never retry after any uncertain libvirt action.
            raise CloneRollbackBlocked(
                "Clone undo partial/unknown; preserve exact VM/artifacts/ledger"
            ) from exc
    finally:
        os.close(fd)


def _fsync(folder):
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--mode",choices=("plan","revert"),default="plan")
    cli.add_argument("--approved-host",required=True)
    cli.add_argument("--journal-dir",type=Path,required=True)
    cli.add_argument("--vm",required=True)
    args=cli.parse_args()
    try:
        value=plan(args.approved_host,args.journal_dir,args.vm) if args.mode=="plan" else revert(
            args.approved_host,args.journal_dir,args.vm)
        print(json.dumps(value,indent=2,sort_keys=True),flush=True)
        return 0
    except (CloneRollbackBlocked,stager.StageBlocked,
            OSError,ValueError,TypeError,ET.ParseError,json.JSONDecodeError) as exc:
        print(json.dumps({"result":"COMMAND2_ZERO_NIC_ROLLBACK_BLOCKED_OR_PARTIAL",
                          "error_type":type(exc).__name__,
                          "no_untracked_guest_or_disk_removed":True,
                          "retries_unauthorized":True}),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
