#!/usr/bin/env python3
"""Read-only full-state cold recovery bundle admission for running snapshots.

Unlike command2_portable_cold_bundle.verify_bundle, this accepts a RUNNING
guest because it hashes the already captured, separately stored artifacts
without accessing or attempting to copy the live VM disk/swtpm files.

Acceptance here proves byte integrity of a prior cold bundle, NOT that its
disk + OVMF + swtpm state has ever been successfully restored/booted.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import stat

MAX_MANIFEST=256*1024
EXPECTED_MANIFEST="command2-cold-bundle.json"
NAME=re.compile(r"win11_([1-9]|1[0-6])\Z")
UUID=re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
TPM_NAME=re.compile(r"[a-zA-Z0-9_.-]{1,128}\Z")
RESERVE_GIB=40

class RecoveryBlocked(RuntimeError):
    pass

def need(ok,why):
    if not ok: raise RecoveryBlocked(why)

def stat_private_file(file,size_limit=None):
    file=Path(file)
    need(file.is_file() and not file.is_symlink(),
         "Expected non-symlinked recovery file missing")
    st=file.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
         st.st_uid==0 and stat.S_IMODE(st.st_mode)&0o077==0,
         "Recovery file not root-owned/private single-link")
    if size_limit is not None:
        need(st.st_size<=size_limit,"Oversized recovery metadata")
    return st

def sha256_file(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda:stream.read(4*1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def inspect(vm,uuid,folder):
    """Verify offline artifact integrity; no guest state changes or external calls."""
    need(type(vm) is str and NAME.fullmatch(vm) is not None and
         type(uuid) is str and UUID.fullmatch(uuid) is not None,
         "Invalid guest identity for full recovery verification")
    p=Path(folder)
    need(p.is_absolute() and p.is_dir() and not p.is_symlink(),
         "Expected absolute private recovery folder missing")
    st=p.stat()
    need(st.st_uid==0 and stat.S_IMODE(st.st_mode)&0o077==0,
         "Recovery folder must be root owned and private")
    manifestpath=p/EXPECTED_MANIFEST
    stat_private_file(manifestpath,MAX_MANIFEST)
    raw=manifestpath.read_bytes()
    data=json.loads(raw)
    need(type(data) is dict and
         data.get("kind")=="COMMAND2_FULL_COLD_BUNDLE_V1" and
         data.get("capture_complete") is True and
         data.get("source_vm_shutoff") is True and
         data.get("vm")==vm and data.get("uuid")==uuid,
         "Recovery bundle identity or complete stopped-capture proof invalid")
    records=data.get("entries")
    need(type(records) is dict and
         "disk.qcow2" in records and "UEFI_VARS.fd" in records and
         any(k.startswith("swtpm/") and k.endswith(".permall")
             for k in records),
         "Recovery bundle missing disk/OVMF/swtpm permanent state")
    results={}
    for rel,expected in sorted(records.items()):
        allowed=(rel in ("disk.qcow2","UEFI_VARS.fd") or
                 (rel.startswith("swtpm/") and rel.count("/")==1 and
                  TPM_NAME.fullmatch(rel.split("/",1)[1]) is not None))
        need(allowed and type(expected) is dict,
             "Unexpected recovery bundle member or metadata")
        f=p/rel
        state=stat_private_file(f)
        need(state.st_size==expected.get("bytes") and
             sha256_file(f)==expected.get("sha256"),
             "Recovery artifact hash/length differs: "+rel)
        results[rel]={"bytes":state.st_size,"sha256":expected["sha256"]}
    need(data.get("disk","").endswith("/"+vm+".command2.qcow2") and
         data.get("nvram","").endswith("/"+vm+".command2_VARS.fd") and
         data.get("swtpm_dir","").endswith("/"+uuid+"/tpm2"),
         "Recovery manifest does not bind exact independent guest paths")
    return {"result":"COMMAND2_FULL_COLD_RECOVERY_BYTES_VERIFIED",
            "vm":vm,"uuid":uuid,
            "bundle":str(p),
            "manifest_sha256":hashlib.sha256(raw).hexdigest(),
            "members":results,
            "all_member_hashes_recomputed":True,
            "original_master_unmodified_by_check":True,
            "current_guest_state_changed":False,
            "cold_restore_physically_proven_by_this_check":False,
            "running_memory_snapshot_created_by_this_check":False}
