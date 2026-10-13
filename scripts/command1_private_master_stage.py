#!/usr/bin/env python3
"""Joined Command1 target-host private Drive -> EXACT master import handoff.

PLAN: remote size/crypt config + empty private destination/storage and
      APPROVED OTHER-HOST target Windows disk/UEFI paths. No VM operations.
STAGE: root direct terminal, overall typed consent, root-private durable
       witness; use separately approved encrypted rclone crypt download with
       exact manifest SHA256 validation, then existing guarded cold MASTER
       importer. Never boot Windows, create snapshots, reuse its TPM for
       clones, or install host software.
VERIFY: byte-check private golden bundle plus read-only *staged* import
        inspection. No Windows boot or CAPE snapshot acceptance inferred.

Actual full Command1 still also requires fresh host packages/CAPEv2/INetSim,
firmware, verified Windows boot and final TPM-consistent running snapshot.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import stat
import sys
import uuid

import command1_private_drive_bundle as drive
import command1_import_existing_master as imported
import command1_export_existing_master as golden

DEFAULT_WITNESSES = Path("/var/lib/cape-command1-receipts")
APPROVAL = "STAGE-EXACT-WIN11-MASTER-PRIVATE-GDRIVE-OTHER-HOST"

class ExactMasterBlocked(RuntimeError):
    pass

def need(ok, text):
    if not ok: raise ExactMasterBlocked(text)

def root_host(host):
    need(os.geteuid()==0,
         "Root required for sensitive Windows golden-master import")
    return imported.require_host(host)

def path_plan(args):
    root_host(args.approved_host)
    need(args.tpm_user and args.tpm_user.strip() == args.tpm_user,
         "Explicit swtpm service owner required")
    need(args.os_disk.is_absolute() and args.os_disk.suffix==".qcow2" and
         args.uefi_vars.is_absolute() and
         args.uefi_vars.suffix in (".fd",".qcow2"),
         "OS target must be new QCOW2 and UEFI target must be new VARS")
    need(args.os_disk != args.uefi_vars,
         "Windows OS and UEFI files must have separate paths")
    imported.approved_target(args.os_disk)
    imported.approved_target(args.uefi_vars)
    transfer=drive.plan_download(
        args.approved_host,args.bundle_dir,args.crypt_remote,
        args.bundle_id,args.rclone_config)
    return {
        "result":"COMMAND1_EXACT_DRIVE_IMPORT_STAGE_PLAN_ONLY",
        "transfer":transfer,
        "master":"win11","master_os_target":str(args.os_disk),
        "master_uefi_target":str(args.uefi_vars),
        "target_tpm_service_user":args.tpm_user,
        "master_shut_off_on_import":True,
        "VM_imported":False,
        "VM_booted":False,
        "final_running_snapshot_created":False,
        "host_modified":False,
    }

def secure_witness_folder(path):
    path=Path(path)
    need(path.is_absolute() and path.parent.is_dir() and
         not any(p.is_symlink() for p in (path,*path.parents)),
         "Root-private witness parent missing or symlinked")
    if not path.exists():
        path.mkdir(mode=0o700)
    st=path.stat()
    need(st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700 and
         stat.S_ISDIR(st.st_mode),
         "Witness dir must be owned by root and mode 0700")
    return path

def save_witness(file,data,*,initial=False):
    raw=(json.dumps(data,sort_keys=True,indent=2)+"\n").encode()
    need(len(raw) < 262144,"Witness unexpectedly large")
    if initial:
        fd=os.open(file,os.O_CREAT|os.O_EXCL|os.O_WRONLY|
                   os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(fd,"wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
    else:
        need(not file.is_symlink() and file.is_file() and
             file.stat().st_uid==0 and
             stat.S_IMODE(file.stat().st_mode)==0o600,
             "Existing witness must be root-private")
        from tempfile import mkstemp
        fd,tmp=mkstemp(prefix=".cape-command1-witness-",dir=str(file.parent))
        try:
            with os.fdopen(fd,"wb") as f:
                f.write(raw)
                f.flush()
                os.fchmod(f.fileno(),0o600)
                os.fsync(f.fileno())
            os.replace(tmp,file)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    directory=os.open(file.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)

def stage(args):
    need(os.geteuid()==0 and sys.stdin.isatty(),
         "Approved new-host stage requires interactive root operator")
    before=path_plan(args)
    print(json.dumps(before,sort_keys=True,indent=2),flush=True)
    need(input("Type "+APPROVAL+" to stage the exact PRIVATE master: ")
         ==APPROVAL,"Operator declined exact master download/import")
    need(path_plan(args)==before,"Target/source changed after approval")
    folder=secure_witness_folder(args.witness_dir)
    target=folder/("command1-drive-import."+uuid.uuid4().hex+".json")
    journal={
        "result":"COMMAND1_PRIVATE_MASTER_STAGE_STARTED",
        "approved_host":root_host(args.approved_host),
        "destination":str(args.bundle_dir),
        "OS_disk_target":str(args.os_disk),
        "uefi_target":str(args.uefi_vars),
        "completed":[],
        "master_running_snapshot_created":False,
        "VM_booted":False,
    }
    save_witness(target,journal,initial=True)
    try:
        journal["current"]="private_google_drive_download"
        save_witness(target,journal)
        copied=drive.apply_download(
            args.approved_host,args.bundle_dir,args.crypt_remote,
            args.bundle_id,args.rclone_config)
        need(copied.get("result")==
             "COMMAND1_PRIVATE_MASTER_DOWNLOADED_SHA256_VERIFIED",
             "Exact master Drive download not byte verified")
        journal["completed"].append(
            {"step":"private_google_drive_download",
             "manifest_sha256":copied["bundle_manifest_sha256"]})
        journal["current"]="stopped_master_import"
        save_witness(target,journal)
        # Do NOT call importer.apply blindly after a copy.
        # It has its own approval, storage/TPM owner/UEFI constraints and
        # complete SHA/VM uniqueness checks.
        import_plan=imported.check(
            args.approved_host,args.bundle_dir,args.os_disk,
            args.uefi_vars,args.tpm_user)
        need(import_plan.get("from_verified_actual_master_bundle") is True,
             "Downloaded bytes did not pass master import preflight")
        staged=imported.apply(
            args.approved_host,args.bundle_dir,args.os_disk,
            args.uefi_vars,args.tpm_user)
        need(staged.get("from_verified_actual_master_bundle") is True,
             "Actual golden master import did not pass byte verification")
        journal["completed"].append({
            "step":"stopped_master_import",
            "master_uuid":staged.get("master_uuid")})
        journal["current"]=None
        journal["result"]="COMMAND1_PRIVATE_DRIVE_MASTER_IMPORTED_SHUT_OFF"
        save_witness(target,journal)
        return {
            "result":journal["result"],"witness":str(target),
            "exact_master_imported":True,
            "master_VM_running_snapshot_created":False,
            "fresh_host_CAPE_install_complete":False,
            "service_restarted":False,
            "clone_TMPS_reused":False,
        }
    except Exception as exc:
        journal["result"]="COMMAND1_PRIVATE_MASTER_STAGE_PARTIAL_OR_UNKNOWN"
        journal["error_type"]=type(exc).__name__
        # No exception string: may contain guest disk paths/credentials.
        save_witness(target,journal)
        raise ExactMasterBlocked(
            "PARTIAL_OR_UNKNOWN: private bundle/VM staging incomplete; "
            "do not blindly re-run, delete files or revert snapshots") from None

def verify(args):
    root_host(args.approved_host)
    proof=golden.manifest_check(args.bundle_dir)
    observed=imported.check(args.approved_host,args.bundle_dir,
                            args.os_disk,args.uefi_vars,args.tpm_user,
                            staged=True)
    need(observed.get("from_verified_actual_master_bundle") is True,
         "Actual imported master failed read-only verification")
    return {"result":"COMMAND1_PRIVATE_EXACT_MASTER_STAGED_VERIFIED_ONLY",
            "bundle_manifest_sha256":proof["manifest_sha256"],
            "target_master_details":observed,
            "VM_booted_or_reverted":False,
            "CAPE_final_running_snapshot_proven":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","stage","verify"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--crypt-remote",required=True)
    p.add_argument("--bundle-id",required=True)
    p.add_argument("--bundle-dir",type=Path,required=True)
    p.add_argument("--os-disk",type=Path,required=True)
    p.add_argument("--uefi-vars",type=Path,required=True)
    p.add_argument("--tpm-user",required=True)
    p.add_argument("--rclone-config",type=Path,default=drive.DEFAULT_RCLONE_CONFIG)
    p.add_argument("--witness-dir",type=Path,default=DEFAULT_WITNESSES)
    args=p.parse_args()
    try:
        report=(path_plan(args) if args.mode=="plan" else
                stage(args) if args.mode=="stage" else verify(args))
        print(json.dumps(report,sort_keys=True,indent=2),flush=True)
        return 0
    except Exception as exc:
        print(json.dumps({
            "result":"COMMAND1_EXACT_DRIVE_IMPORT_BLOCKED",
            "error_type":type(exc).__name__,
            "no_VM_boot_or_snapshot_revert":True,
            "review_private_witness_after_partial":True,
        },sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
