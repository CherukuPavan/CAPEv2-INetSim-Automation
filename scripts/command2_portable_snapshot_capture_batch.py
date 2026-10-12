#!/usr/bin/env python3
"""Strict all-N running CAPE snapshot admission/capture on approved OTHER host.

Read-only `plan` checks ALL separately prepared guests before ANY capture.
`capture` is sequential, keeps exact per-VM typed operator approvals and
delegates to the guarded single-VM running memory+disk snapshot helper.
No auto-revert, guest reboot, swtpm extraction, TPM acceptance fabrication
or unsafe fallback. NOT eligible on SSL-55's current RAW-pflash guest.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import ipaddress

import command2_portable_workflow as workflow
import command2_running_snapshot_batch_gate as batch
import command2_running_cape_snapshot_gate as snapshot
import command2_snapshot_recovery_preflight as recovery
import command2_native_snapshot_stack_guard as native

GIB=1024**3
MIN_FREE=40*GIB
MAX_MANIFEST_INDEX=128*1024
FORMAT="COMMAND2_RUNNING_SNAPSHOT_BUNDLE_INDEX_V1"
VM_RE=re.compile(r"win11_([1-9]|1[0-6])\Z")
HASH_RE=re.compile(r"[0-9a-f]{64}\Z")

class CaptureBatchBlocked(RuntimeError):pass
def need(test,reason):
    if not test:raise CaptureBatchBlocked(reason)

def private_index(folder):
    batch.private_evidence_folder(folder)
    filename=Path(folder)/"snapshot-recovery-index.json"
    need(filename.is_file() and not filename.is_symlink(),
         "Snapshot recovery index missing")
    st=filename.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
         st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
         0<st.st_size<=MAX_MANIFEST_INDEX,
         "Snapshot recovery index must be root/private regular 0600")
    return json.loads(filename.read_text(encoding="utf-8"))

def checked_inputs(host,journal,evidence_dir):
    workflow.canonical_host(host)
    need(os.geteuid()==0,"Root required for canonical snapshot evidence")
    need(isinstance(journal,Path) and journal.is_absolute() and
         journal.name=="command2-identity-reservation.json",
         "Expected exact private Command2 reservation journal")
    need(isinstance(evidence_dir,Path) and evidence_dir.is_absolute(),
         "Absolute private snapshot evidence directory required")
    batch.private_evidence_folder(journal.parent)
    rows=batch.reservation_rows(journal,host)
    need(bool(rows),"Empty Command2 snapshot guest count")
    index=private_index(evidence_dir)
    need(type(index) is dict and index.get("format")==FORMAT and
         index.get("host")==host and
         index.get("guest_count")==len(rows) and
         type(index.get("entries")) is dict and
         set(index["entries"])=={r["libvirt_name"] for r in rows},
         "Exact all-N recovery index missing or guest set differs")
    journal_hash=hashlib.sha256(journal.read_bytes()).hexdigest()
    index_hash=hashlib.sha256(
        (evidence_dir/"snapshot-recovery-index.json").read_bytes()).hexdigest()
    # All VMs must have independently backed recovery bundles and no snapshot
    # yet. A checksum-valid cold backup is NOT evidence of a tested restore.
    reviewed=[]
    total_ram=0
    file_systems={}
    for row in rows:
        vm=row["libvirt_name"]
        record=index["entries"][vm]
        need(type(record) is dict and set(record)=={"manifest_sha256"},
             "Per-guest recovery index must not contain unreviewed flags")
        digest=record["manifest_sha256"]
        need(type(digest) is str and HASH_RE.fullmatch(digest),
             "Missing canonical reviewed per-VM cold recovery SHA256")
        item=evidence_dir/vm
        batch.private_evidence_folder(item)
        bundle=item/"cold"
        receipt=item/"snapshot-acceptance.json"
        uid=row["libvirt_uuid_candidate"]
        one,subnet,_=workflow.load_guest(journal,host,vm)
        need(one==row,"Guest entry changed during snapshot admission")
        plan=snapshot.plan(vm,host,uid,row["mac_candidate"],
                           row["guest_static_ipv4_target"],receipt,subnet)
        need(plan.get("required_acceptance_receipt_provided") is True,
             "Exact host/Windows snapshot acceptance receipt missing")
        checked=recovery.inspect(vm,uid,bundle,digest)
        stack=native.inspect(vm)
        need(checked["manifest_sha256"]==digest and
             stack["uefi_variable_store_real_format"]=="qcow2" and
             stack["swtpm2_present"] is True,
             "Full recovery/UEFI/QEMU snapshot admission failed")
        ram=stack["guest_ram_bytes"]
        total_ram+=ram
        diskpath=Path(row["disk_target"])
        fs=os.stat(diskpath.parent).st_dev
        file_systems.setdefault(fs,[]).append(str(diskpath.parent))
        reviewed.append({"vm":vm,"uuid":uid,
               "guest_ip":row["guest_static_ipv4_target"],
               "receipt_sha256":plan["receipt_sha256"],
               "manifest_sha256":digest,"ram_bytes":ram,
               "bundle":str(bundle),"receipt":str(receipt),
               "expected_snapshot":"cape_ready_"+vm,
               "captured":False,"revert_tested":False})
    # Native inspect has per-guest headroom; reserve additionally for the
    # entire requested batch, not just one RAM capture at a time.
    for paths in file_systems.values():
        f=os.statvfs(paths[0])
        free=f.f_frsize*f.f_bavail
        need(free>MIN_FREE+2*total_ram+4*GIB,
             "Insufficient shared filesystem reserve for ALL guest RAM snapshots")
    return {"result":"COMMAND2_RUNNING_SNAPSHOT_BATCH_ALL_N_PREFLIGHT",
        "host":host,"guest_count":len(rows),
        "journal_sha256":journal_hash,"evidence_index_sha256":index_hash,
        "total_snapshot_guest_ram_bytes":total_ram,
        "guests":reviewed,
        "all_guest_recovery_bundle_bytes_verified":True,
        "actual_tpm_state_rollback_verified":False,
        "running_snapshots_created":False,"production_ready":False}

def run(host,journal,evidence_dir,mode):
    need(mode in ("plan","capture"),"Unrecognized running snapshot batch mode")
    if mode=="capture":
        need(sys.stdin.isatty(),
             "Exact interactive approval required for each VM capture")
    initial=checked_inputs(host,journal,evidence_dir)
    print(json.dumps(initial,sort_keys=True,indent=2),flush=True)
    if mode=="plan":
        return 0
    for record in initial["guests"]:
        need(hashlib.sha256(journal.read_bytes()).hexdigest()==
             initial["journal_sha256"] and
             hashlib.sha256((evidence_dir/"snapshot-recovery-index.json")
                            .read_bytes()).hexdigest()==
             initial["evidence_index_sha256"],
             "Canonical guest journal/backup index changed mid-batch; STOP")
        vm=record["vm"]
        row,subnet,_=workflow.load_guest(journal,host,vm)
        argv=[
            sys.executable,"-B",str(Path(snapshot.__file__).resolve()),
            "--mode","capture","--vm",vm,"--approved-host",host,
            "--expected-uuid",row["libvirt_uuid_candidate"],
            "--expected-mac",row["mac_candidate"],
            "--guest-ip",row["guest_static_ipv4_target"],"--subnet",subnet,
            "--receipt",record["receipt"],
            "--recovery-bundle",record["bundle"],
            "--reviewed-manifest-sha",record["manifest_sha256"],
        ]
        print(json.dumps({"result":"COMMAND2_CAPTURE_CHILD_PENDING",
              "vm":vm,"separate_typed_approval_required":True,
              "no_auto_restore_or_cleanup":True},sort_keys=True),flush=True)
        done=subprocess.run(argv,check=False)
        if done.returncode!=0:
            print(json.dumps({"result":"COMMAND2_CAPTURE_BATCH_STOPPED",
                  "vm":vm,"child_returncode":done.returncode,
                  "prior_snapshots_preserved":True,
                  "snapshot_may_be_partially_created":True,
                  "do_not_retry_without_actual_libvirt_review":True},
                  sort_keys=True),file=sys.stderr,flush=True)
            return 2
    print(json.dumps({"result":"COMMAND2_RUNNING_BATCH_CAPTURE_ATTEMPTED",
        "count":initial["guest_count"],
        "all_snapshot_metadata_needs_independent_readback":True,
        "real_tpm_uefi_benign_reverts_pending":True,
        "cape_analysis_released":False,
        "production_ready":False},sort_keys=True),flush=True)
    return 0

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","capture"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--snapshot-evidence-dir",type=Path,required=True)
    args=p.parse_args()
    try:
        return run(args.approved_host,args.journal,args.snapshot_evidence_dir,
                   args.mode)
    except (CaptureBatchBlocked,workflow.WorkflowBlocked,batch.GateBlocked,
            snapshot.SnapshotBlocked,recovery.RecoveryBlocked,
            native.NativeBlocked,OSError,ValueError,TypeError,KeyError,
            json.JSONDecodeError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({"result":"COMMAND2_RUNNING_SNAPSHOT_BATCH_BLOCKED",
                "reason":str(exc),"any_host_or_guest_changes_this_step":False},
                sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
