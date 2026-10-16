#!/usr/bin/env python3
"""Single guarded Command1 SUBSTAGE: tracked host APT/source + exact cold master.

Internal engineering sequence, NOT final three-command CAPEv2 release.
The real sequence calls the existing source/host transaction then the
restricted Drive reader -> hash-verified exact master -> shutoff VM import.
It does not start a VM, capture RAM, or prove swtpm-consistent restore.

Prerequisites that must already exist: a root:0600 service account key
authorized as a Drive Viewer, root-private staging parents, and an exact
reviewed upstream CAPEv2 commit. The installer cannot invent cloud access.
The first phase records a separate transaction before APT; this controller
writes its own root-private crash receipt before either phase begins.
No retries or cleanup of uncertain state are attempted.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import uuid

import command1_tracked_prerequisite_stage as base
import command1_private_master_handoff_sequence as master
import command1_worldwide_drive_reader as reader
import command123_deployment_transaction as tx
import command1_cape_runtime_rootless_stage as runtime

RECEIPTS = Path("/var/lib/cape-command1-integrated-cold")
APPROVAL = "INTEGRATE-CAPE-SOURCE-AND-PRIVATE-COLD-MASTER"
PHASES = ("tracked_host_and_cape_source", "private_exact_master_import")
RUNTIME_PHASE = "rootless_cape_python_runtime"
RUNTIME_FIELDS = (
    "runtime_manifest", "runtime_lock", "runtime_wheelhouse",
    "runtime_approved_manifest_sha256", "runtime_uv",
    "runtime_approved_uv_sha256", "runtime_python",
    "runtime_approved_python_sha256",
)


def runtime_arguments(args):
    """Optional CAPE runtime requires the complete eight-field profile."""
    values = [getattr(args, key, None) for key in RUNTIME_FIELDS]
    if not any(item is not None for item in values):
        return None
    need(all(value is not None and bool(str(value)) for value in values),
         "Partial CAPE runtime input profile refused")
    return dict(zip(RUNTIME_FIELDS, values))


def phases_for(args):
    return (PHASES[0], RUNTIME_PHASE, PHASES[1]) if (
        runtime_arguments(args) is not None) else PHASES


def runtime_preflight(args):
    """Admit reviewed wheel bytes/uv/Python before any APT changes."""
    fields = runtime_arguments(args)
    if fields is None:
        return {"requested": False, "runtime_stage_performed": False}
    admission = runtime.wheels.plan(
        fields["runtime_manifest"], fields["runtime_lock"],
        fields["runtime_wheelhouse"],
        fields["runtime_approved_manifest_sha256"])
    need(admission["source_sha"] == args.cape_revision,
         "Offline runtime source differs from pinned CAPE commit")
    need(runtime.sha_file(fields["runtime_uv"]) ==
         fields["runtime_approved_uv_sha256"],
         "Unapproved uv binary")
    need(runtime.sha_file(fields["runtime_python"]) ==
         fields["runtime_approved_python_sha256"],
         "Unapproved isolated Python binary")
    account = runtime.user_account(getattr(args, "runtime_user", "cape"))
    return {
        "requested": True,
        "packages_verified": admission["packages_verified"],
        "approved_manifest_sha256":
            fields["runtime_approved_manifest_sha256"],
        "runtime_uid": account.pw_uid,
        "runtime_user": account.pw_name,
        "offline_only": True,
        "source_matches_exact_revision": True,
        "runtime_stage_performed": False,
    }

class IntegratedBlocked(RuntimeError):
    pass

def need(ok,reason):
    if not ok:
        raise IntegratedBlocked(reason)

def admitted(args):
    need(os.geteuid() == 0, "Root required for private master")
    tx.host_guard(args.approved_host)
    master.admitted_host(args.approved_host)
    need(type(args.cape_revision) is str and
         re.fullmatch(r"[0-9a-f]{40}", args.cape_revision),
         "Exactly reviewed upstream CAPEv2 commit SHA40 required")
    need(type(args.bundle_id) is str and
         re.fullmatch(r"cape-master-[A-Za-z0-9_-]{4,72}", args.bundle_id),
         "Exact source master bundle ID required")
    need(args.bundle_destination.name == args.bundle_id,
         "Private master folder must match remote bundle ID")
    # All security-sensitive paths and key format must pass the private
    # reader check BEFORE allocating a transaction or installing packages.
    identity = reader.verify_inputs(args)
    items = ("service_account_file", "config", "bundle_destination",
             "os_disk", "uefi_vars", "receipt_dir", "handoff_receipt_dir")
    paths = [master.trusted_path(getattr(args,label), label)
             for label in items]
    need(len(set(paths)) == len(paths), "Staging paths overlap")
    for label in ("bundle_destination", "os_disk", "uefi_vars"):
        p = getattr(args,label)
        master.trusted_path(p,label,may_not_exist=True)
    need(args.bundle_destination.parent != args.os_disk.parent and
         args.bundle_destination.parent != args.uefi_vars.parent,
         "Remote master source overlaps target image directories")
    need(args.receipt_dir != args.handoff_receipt_dir,
         "Both private receipt directories must be distinct")
    need(not args.receipt_dir.exists() and
         not args.handoff_receipt_dir.exists(),
         "Unresolved prior integration journals; do not retry")
    for label in ("receipt_dir", "handoff_receipt_dir"):
        p = getattr(args,label)
        need(p.parent.is_dir() and p.parent.stat().st_uid == 0 and
             not p.parent.stat().st_mode & 0o022,
             "Private journal parent must exist and be root-owned")
    need(args.swtpm_user and re.fullmatch(
         r"[a-z_][a-z0-9_-]{0,31}",args.swtpm_user) is not None,
         "Explicit swtpm account required")
    return identity

def preflight(args):
    identity=admitted(args)
    current=base.preflight(args.approved_host,args.cape_revision)
    python_profile=runtime_preflight(args)
    return {
        "result":"COMMAND1_INTEGRATED_COLD_SEQUENCE_PLAN_ONLY",
        "host":args.approved_host,
        "pinned_upstream_source_commit":args.cape_revision,
        "master_bundle_id":args.bundle_id,
        "private_service_account_identity":
            identity["service_account_email_to_share_with_as_viewer"],
        "base_apt_and_pinned_cape_source":current,
        "ordered_phases":list(phases_for(args)),
        "offline_python_runtime_profile":python_profile,
        "authorized_private_master_key_already_provisioned":True,
        "cold_master_staged":False,
        "guest_booted":False,
        "CAPE_ready":False,
        "TPM_running_checkpoint_tested":False,
        "host_modified":False,
    }

def execute(args):
    need(runtime_arguments(args) is None,
         "Optional offline runtime phase is not wired into the executor; "
         "refusing a partial integrated deployment")
    need(sys.stdin.isatty(),"Use interactive root terminal")
    initial=preflight(args)
    print(json.dumps(initial,indent=2,sort_keys=True),flush=True)
    need(input("Type "+APPROVAL+": ").strip()==APPROVAL,
         "Operator declined integrated cold stage")
    need(preflight(args)==initial,
         "Source, credentials or host prereqs changed after approval")
    folder=master.private_receipt_dir(args.receipt_dir)
    receipt=folder/("command1-integrated-"+uuid.uuid4().hex+".json")
    doc={
        "schema":1,"host":args.approved_host,
        "master_bundle_id":args.bundle_id,
        "upstream_source_sha":args.cape_revision,
        "phases":list(phases_for(args)),
        "finished":[],"current":None,"phase":"started",
        "host_vm_started":False,
        "complete_command1":False,
        "guest_tpm_revert_tested":False,
    }
    master.durable_receipt(receipt,doc,first=True)
    for phase in phases_for(args):
        doc["current"]=phase
        master.durable_receipt(receipt,doc)
        try:
            if phase=="tracked_host_and_cape_source":
                result=base.apply(args.approved_host,args.cape_revision)
                need(result.get("exact_public_source_staged") is True,
                     "Pinned CAPE source was not staged")
                doc["transaction_id"]=result["transaction_id"]
            else:
                # Now QEMU/libvirt/rclone should be installed; the child
                # performs its own full root/VM/TPM admission.
                need(master.inputs(args)["host_modified"] is False,
                     "Private cold handoff preflight rejected")
                child_args=argparse.Namespace(**vars(args))
                child_args.receipt_dir=args.handoff_receipt_dir
                result=master.execute(child_args)
                need(result.get("master_imported_shut_off") is True and
                     result.get("guest_started") is False,
                     "Exact master was not imported shut off")
        except Exception as error:
            doc["phase"]="PARTIAL_OR_UNKNOWN_STOP"
            doc["failure_type"]=type(error).__name__
            master.durable_receipt(receipt,doc)
            raise IntegratedBlocked(
                "One or more Command1 stages may be partial; preserve both "
                "root-private receipts and manually review BEFORE retry") from error
        doc["finished"].append(phase)
        doc["current"]=None
        master.durable_receipt(receipt,doc)
    doc["phase"]="exact_cold_master_staged_only"
    master.durable_receipt(receipt,doc)
    return {
        "result":"COMMAND1_TRACKED_HOST_SOURCE_AND_EXACT_COLD_MASTER_ONLY",
        "receipt":str(receipt),
        "tracked_transaction":doc["transaction_id"],
        "all_phases_completed":list(phases_for(args)),
        "rootless_cape_python_runtime_installed": (
            RUNTIME_PHASE in phases_for(args)),
        "rootless_python_packages_installed":
            doc.get("rootless_python_runtime_packages",0),
        "master_vm_state":"shut off",
        "full_cape_installed":False,
        "TPM_coherent_running_snapshot_proven":False,
        "complete_command1":False,
        "no_guest_booted":True,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","run"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--cape-revision",required=True)
    p.add_argument("--service-account-file",type=Path,required=True)
    p.add_argument("--shared-parent-folder-id",required=True)
    p.add_argument("--crypt-subfolder",default="master-backups")
    p.add_argument("--config",type=Path,
                   default=Path("/root/cape-command1-crypt-reader.conf"))
    p.add_argument("--bundle-id",required=True)
    p.add_argument("--bundle-destination",type=Path,required=True)
    p.add_argument("--os-disk",type=Path,required=True)
    p.add_argument("--uefi-vars",type=Path,required=True)
    p.add_argument("--swtpm-user",required=True)
    p.add_argument("--receipt-dir",type=Path,default=RECEIPTS)
    p.add_argument("--handoff-receipt-dir",type=Path,
                   default=master.RECEIPTS)
    args=p.parse_args()
    try:
        response=preflight(args) if args.mode=="plan" else execute(args)
        print(json.dumps(response,indent=2,sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({
            "result":"COMMAND1_INTEGRATED_COLD_BLOCKED_OR_PARTIAL",
            "error_type":type(error).__name__,
            "no_automatic_retry_cleanup_or_guest_boot":True,
            "CAPE_three_commands_complete":False,
        },sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
