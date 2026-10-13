#!/usr/bin/env python3
"""SSL55 -> SSL46 encrypted LAN storage staging for exact Windows golden master.

Does NOT delete anything. Requires a separately operator-created,
authenticated SSHFS mount of a PRIVATE folder on SSL46, with sshfs
"idmap=user" mapping the SSL46 dedicated user to root locally and no
"allow_other". The remote SSH hostname/key and identity must be verified
by the operator before mounting: no password/token or root SSH automation.

PLAN: check actual FUSE SSHFS mount source, root-only directory identity,
      available remote space and actual SHUT-OFF source win11+QCOW2 chain.
EXPORT: typed approval, recheck source, invoke original reviewed
        cold/flattened disk+XML+OVMF+swtpm exporter DIRECTLY to SSHFS.
VERIFY: rehash EVERY remote member and retain approved SSHFS identity.
UPLOAD: via SAME SSHFS mounted folder, use local ROOT rclone CRYPT
        config and its existing immutable upload + remote byte comparison.

Original SSL55 master, snapshots and chain never modified. No SSL46
cleanup is performed; no incomplete bundle is automatically retried.
This is engineering-stage and requires physical SSHFS/QEMU tests before
being called a full golden-master transfer success.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

import command1_export_existing_master as golden
import command1_private_drive_bundle as drive

MOUNT_DEFAULT=Path("/mnt/cape-ssl46-export")
BUNDLE_RE=re.compile(r"cape-master-[A-Za-z0-9_-]{4,72}\Z")
SOURCE_RE=re.compile(
    r"[A-Za-z_][A-Za-z0-9_.-]{0,31}@[A-Za-z0-9_.-]{2,253}:"
    r"/[A-Za-z0-9_./-]{3,220}\Z")
APPROVAL="EXPORT-EXACT-WIN11-MASTER-TO-AUTHENTICATED-SSL46-SSHFS"

class LanStageBlocked(RuntimeError):
    pass

def need(ok,reason):
    if not ok:raise LanStageBlocked(reason)

def protected_source():
    need(os.geteuid()==0 and sys.stdin.isatty(),
         "SSL55 LAN export requires direct ROOT terminal")
    need(socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Refuse export from any system other than CSE-SSL-55")

def path_and_mount(path,expected_source):
    path=Path(path)
    need(path.is_absolute() and path.name=="cape-ssl46-export" and
         path.is_dir() and not path.is_symlink() and
         not any(p.is_symlink() for p in path.parents),
         "Expected existing root-owned /mnt/cape-ssl46-export directory")
    need(type(expected_source) is str and
         SOURCE_RE.fullmatch(expected_source) is not None and
         ".." not in Path(expected_source.split(":",1)[1]).parts,
         "Expected source must be user@SSL46:/private/absolute/path")
    server=expected_source.split("@",1)[1].split(":",1)[0].lower()
    need(server not in ("localhost","127.0.0.1","cse-ssl-55","ssl-55"),
         "SSHFS peer cannot be SSL55")
    try:
        proc=subprocess.run(["findmnt","--mountpoint",str(path),
            "--json","--output","TARGET,SOURCE,FSTYPE,OPTIONS"],
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            text=True,timeout=15,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise LanStageBlocked("Cannot inspect exact mounted SSHFS") from exc
    need(proc.returncode==0 and len(proc.stdout)<64*1024,
         "SSHFS not currently mounted on the exact dedicated path")
    try:
        data=json.loads(proc.stdout)
        mounts=data["filesystems"]
        need(type(mounts) is list and len(mounts)==1,
             "Expected exactly one mounted SSHFS filesystem")
        row=mounts[0]
        need(type(row) is dict and row.get("target")==str(path) and
             row.get("source")==expected_source and
             row.get("fstype") in ("fuse.sshfs","sshfs"),
             "Mounted FUSE peer/path differs from approved SSL46 share")
    except (ValueError,TypeError,KeyError,IndexError) as exc:
        raise LanStageBlocked("Unrecognized mounted SSHFS identity") from exc
    # sshfs userspace idmap=user is not always listed in kernel mount
    # options. Enforce the EFFECTIVE local owner/permission outcome.
    st=path.stat()
    need(st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,
         "SSHFS must expose the private SSL46 directory as root 0700")
    available=os.statvfs(path)
    free=available.f_bavail*available.f_frsize
    need(free>0,"Cannot confirm remote free space")
    return {"mount":str(path),"source":expected_source,
            "peer":server,"fs_type":row["fstype"],
            "root_private_0700":True,"free_bytes":free}

def protected_paths(mount,bundle):
    root=Path(mount)
    folder=Path(bundle)
    need(folder.is_absolute() and folder.parent==root and
         BUNDLE_RE.fullmatch(folder.name) is not None and
         not folder.is_symlink(),
         "Golden export must stay directly below the approved SSL46 mount")
    return folder

def plan(mount,source,bundle,require_new):
    protected_source()
    fs=path_and_mount(mount,source)
    target=protected_paths(mount,bundle)
    if require_new:
        need(not target.exists() and not target.is_symlink(),
             "Expected NEW cape-master bundle, never overwrite or auto-retry")
    else:
        need(target.is_dir() and not target.is_symlink(),
             "Missing previously exported golden bundle")
    if require_new:
        existing=golden.plan(target)
        need(existing.get("result")=="COMMAND1_ACTUAL_MASTER_EXPORT_PLAN_ONLY",
             "Actual golden source/exporter plan not admitted")
        virtual=existing["master_source_disk_virtual_bytes"]
        need(fs["free_bytes"]>=virtual+golden.MIN_AVAILABLE,
             "Insufficient actual SSL46 remote space for flattened copy")
        return {
            "result":"SSL55_TO_SSL46_REMOTE_GOLDEN_EXPORT_PLAN_ONLY",
            "master":"win11","master_shut_off":True,
            "source_virtual_gib":round(virtual/1024**3,2),
            "remote_free_gib":round(fs["free_bytes"]/1024**3,2),
            "min_required_free_gib":round(
                (virtual+golden.MIN_AVAILABLE)/1024**3,2),
            "bundle_destination":str(target),
            "mount_identity":fs["source"],
            "will_modify_original_win11":False,
            "will_delete_SSL46_files":False,
            "remote_private_files_unencrypted_at_rest_until_cleanup":True,
            "encrypted_LAN_transport_requires_SSHFS":True,
            "no_Google_Drive_upload_yet":True,
        }
    proof=golden.manifest_check(target)
    need(proof.get("all_member_files_sha256_verified") is True,
         "Remote golden bundle lacks all-member SHA256 verification")
    return {
        "result":"SSL46_GOLDEN_BUNDLE_SHA256_VERIFIED_OVER_SSHFS",
        "mount_identity":fs["source"],
        "bundle":str(target),
        "master_proof":proof,
        "source_master_modified":False,
        "SSL46_files_deleted":False,
    }

def export(mount,source,bundle):
    first=plan(mount,source,bundle,True)
    print(json.dumps(first,sort_keys=True,indent=2),flush=True)
    need(input("Type "+APPROVAL+" to export to SSL46: ")==APPROVAL,
         "Operator declined private SSL46 network export")
    second=plan(mount,source,bundle,True)
    need(second["mount_identity"]==first["mount_identity"] and
         second["bundle_destination"]==first["bundle_destination"] and
         second["source_virtual_gib"]==first["source_virtual_gib"],
         "Remote mount, intended target or source changed after approval")
    # Existing importer separately demands typed consent for its exact
    # frozen Windows+QCOW2+UEFI+swtpm copying operation. It also obtains
    # an exclusive host lock and revalidates the original VM/chain.
    saved=golden.capture(Path(bundle))
    need(saved.get("all_member_files_sha256_verified") is True,
         "Existing exact source exporter did not verify all bundle bytes")
    final=plan(mount,source,bundle,False)
    return {"result":"SSL55_TO_SSL46_MASTER_EXPORT_SHA256_VERIFIED",
            "destination":str(bundle),
            "mount_identity":final["mount_identity"],
            "bundle_sha256":final["master_proof"]["manifest_sha256"],
            "source_master_or_snapshots_modified":False,
            "SSL46_automatic_deletion":False,
            "Google_Drive_uploaded":False,
            "actual_running_snapshot_metadata_transferred":False}

def upload(mount,source,bundle,crypt,config):
    # Upload THROUGH the SSL55 SSHFS client. Thus SSL46 needs only
    # SSH private storage; it does NOT need Google OAuth/rclone access.
    state=plan(mount,source,bundle,False)
    need(crypt=="cape_crypt",
         "Only the verified private cape_crypt remote is supported")
    result=drive.apply_upload("CSE-SSL-55",Path(bundle),crypt,Path(config))
    need(result.get("result")==
         "COMMAND1_PRIVATE_CRYPT_GDRIVE_UPLOAD_CHECKED" and
         result.get("download_compare_performed") is True,
         "rclone immutable crypt upload and full remote comparison not proven")
    after=plan(mount,source,bundle,False)
    need(after["master_proof"]["manifest_sha256"]==
         state["master_proof"]["manifest_sha256"],
         "Golden source bundle changed during Drive transfer")
    return {"result":"SSL46_STAGED_MASTER_PRIVATE_DRIVE_VERIFIED",
            "cloud_crypt_remote":"cape_crypt",
            "remote_bytes_compared":True,
            "local_bundle_hash_unchanged":True,
            "no_SSL46_files_deleted":True,
            "manual_cleanup_only_after_independent_cloud_retrieval":True,
            "original_SSL55_master_or_snapshots_modified":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","export","verify","upload"),
                   default="plan")
    p.add_argument("--mountpoint",type=Path,default=MOUNT_DEFAULT)
    p.add_argument("--sshfs-source",required=True)
    p.add_argument("--bundle",required=True,type=Path)
    p.add_argument("--crypt-remote",default="cape_crypt")
    p.add_argument("--rclone-config",type=Path,
                   default=drive.DEFAULT_RCLONE_CONFIG)
    args=p.parse_args()
    try:
        result=(plan(args.mountpoint,args.sshfs_source,args.bundle,True)
                if args.mode=="plan" else
                export(args.mountpoint,args.sshfs_source,args.bundle)
                if args.mode=="export" else
                plan(args.mountpoint,args.sshfs_source,args.bundle,False)
                if args.mode=="verify" else
                upload(args.mountpoint,args.sshfs_source,args.bundle,
                       args.crypt_remote,args.rclone_config))
        print(json.dumps(result,sort_keys=True,indent=2),flush=True)
        return 0
    except Exception as exc:
        print(json.dumps({
            "result":"SSL55_SSL46_GOLDEN_STAGING_BLOCKED_OR_PARTIAL",
            "error_type":type(exc).__name__,
            "never_auto_delete_partial_remote_export":True,
            "source_master_and_snapshots_must_remain_unchanged":True,
            "review_remote_storage_before_retry":True,
        },sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
