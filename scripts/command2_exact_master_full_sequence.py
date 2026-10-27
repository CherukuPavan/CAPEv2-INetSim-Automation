#!/usr/bin/env python3
"""Command2 ONE INVOCATION guarded N-clone sequencer for OTHER hosts.

Cold exact-master staging -> independent clone UEFI QCOW2 preparation ->
per-VM firstboot -> trusted CAPE Agent Windows NAT script transport/request ->
independent Windows/NAT/DNS/real HTTPS verification -> all-N Agent health ->
native running RAM/OS/UEFI snapshot candidates -> final graceful shutdown.

This controller does not bypass child typed approvals, infer acceptance
from a successful HTTP request, boot the master, copy master TPM state to
clones, authorize malware analysis, or restore an unsafe running snapshot.
Each component validates identity/resources and protects partial writes.
Any failed child => durable PARTIAL_OR_UNKNOWN and STOP. Never auto-retry.
The final snapshots remain TPM-UNVERIFIED until other-host benign restore.

Mode plan: call only exact-master cold-stage plan; no host changes.
Mode run: demand one overall root/TTY approval, then invoke all pinned
existing guarded phase helpers, retaining their own typed approvals.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import uuid

import command2_portable_workflow as workflow

DEFAULT_WITNESSES = Path("/var/lib/cape-command2-sequence-receipts")
APPROVAL = "RUN-EXACT-MASTER-N-CLONES-WITH-INDIVIDUAL-APPROVALS"
MAX_COUNT = 16

class SequenceBlocked(RuntimeError):
    pass

def need(ok, why):
    if not ok:
        raise SequenceBlocked(why)

def vm_names(count):
    need(type(count) is int and 1 <= count <= MAX_COUNT,
         "Expected 1..16 additional Windows VM count")
    return ["win11_" + str(i) for i in range(1, count + 1)]

def resolve_count(count):
    if count is not None:
        return len(vm_names(count))
    need(sys.stdin.isatty(), "Direct terminal required to answer additional VM count")
    value = input("How many ADDITIONAL Windows VMs? (1-16): ").strip()
    need(re.fullmatch(r"(?:[1-9]|1[0-6])", value) is not None,
         "Count must be an integer from 1 to 16")
    return int(value)

def absolute(path, label):
    p = Path(path)
    need(p.is_absolute() and not p.is_symlink(),
         "Require exact absolute non-symlink " + label)
    return p

def admitted_dirs(args):
    """Refuse ancestor aliases: cold master/VM storage must never overlap."""
    fields = ("bundle", "disk_dir", "nvram_dir", "journal_dir",
              "iso_dir", "evidence_dir", "receipt_dir")
    paths = [absolute(getattr(args, field), field) for field in fields]
    for p in paths:
        need(".." not in p.parts, "Parent traversal in stage path")
        for ancestor in (p, *p.parents):
            need(not ancestor.is_symlink(),
                 "Symlinked master, VM, or receipt path refused")
    for i, parent in enumerate(paths):
        for child in paths[i + 1:]:
            need(parent != child and parent not in child.parents and
                 child not in parent.parents,
                 "Master, OS, firmware, journal, ISO, evidence and receipt "
                 "paths must be independent, never nested")
    return paths

def pending_journal(args):
    # Exact journal is written by existing count-driven clone stage.
    return args.journal_dir / "command2-identity-reservation.json"

def child_args(args, count, script, step, vm=None):
    h = args.approved_host
    journal = str(pending_journal(args))
    evidence = str(args.evidence_dir)
    vmarg = ["--vm", vm] if vm else []
    if step == "cold_count_stage":
        return [script, "--mode", "stage", "--approved-host", h,
                "--bundle", str(args.bundle),
                "--disk-dir", str(args.disk_dir),
                "--nvram-dir", str(args.nvram_dir),
                "--journal-dir", str(args.journal_dir),
                "--iso-dir", str(args.iso_dir),
                "--count", str(count)]
    if step in ("all_clone_uefi_qcow2", "verify_all_clone_uefi_qcow2"):
        return [script, "--mode", ("apply" if step == "all_clone_uefi_qcow2"
                                   else "verify"), "--approved-host", h,
                "--journal", journal, "--evidence-dir", evidence]
    if step == "boot_exact_windows":
        return [script, "--mode", "boot", "--approved-host", h,
                "--journal", journal, "--vm", vm, "--evidence-dir", evidence]
    if step in ("upload_trusted_windows_setup",
                "request_benign_windows_identity",
                "independently_verify_windows"):
        iso = str(args.iso_dir / (vm + ".master-nat.iso"))
        which = {
            "upload_trusted_windows_setup": "stage",
            "request_benign_windows_identity": "execute",
            "independently_verify_windows": "verify",
        }[step]
        return [script, "--mode", which, "--approved-host", h,
                "--journal", journal, "--vm", vm,
                "--nat-iso", iso, "--evidence-dir", evidence]
    if step == "all_clones_agent_health":
        return [script, "--approved-host", h, "--journal", journal]
    if step in ("capture_all_running_candidates", "verify_all_running_candidates"):
        return [script, "--mode", ("capture" if step == "capture_all_running_candidates"
                                   else "verify"), "--approved-host", h,
                "--journal", journal, "--evidence-dir", evidence]
    if step == "all_graceful_shutdown":
        return [script, "--mode", "shutdown", "--approved-host", h,
                "--journal", journal, "--evidence-dir", evidence,
                "--timeout-seconds", str(args.shutdown_timeout)]
    raise SequenceBlocked("Unapproved Command2 phase: " + step)

STEPS = {
    "cold_count_stage": "command2_from_exact_master_bundle.py",
    "all_clone_uefi_qcow2": "command2_portable_master_nat_ovmf_qcow2.py",
    "verify_all_clone_uefi_qcow2": "command2_portable_master_nat_ovmf_qcow2.py",
    "boot_exact_windows": "command2_portable_master_nat_firstboot.py",
    "upload_trusted_windows_setup": "command2_portable_nat_agent_setup_transport.py",
    "request_benign_windows_identity": "command2_portable_nat_agent_execute.py",
    "independently_verify_windows": "command2_portable_nat_agent_verify.py",
    "all_clones_agent_health": "command2_portable_master_nat_agent_batch.py",
    "capture_all_running_candidates":
        "command2_portable_master_nat_running_snapshots.py",
    "verify_all_running_candidates":
        "command2_portable_master_nat_running_snapshots.py",
    "all_graceful_shutdown": "command2_portable_master_nat_final_shutdown.py",
}

def phases(count):
    vm_names(count)
    s = [("cold_count_stage", None),
         ("all_clone_uefi_qcow2", None),
         ("verify_all_clone_uefi_qcow2", None)]
    for vm in vm_names(count):
        s += [(name, vm) for name in (
            "boot_exact_windows",
            "upload_trusted_windows_setup",
            "request_benign_windows_identity",
            "independently_verify_windows")]
    s += [("all_clones_agent_health", None),
          ("capture_all_running_candidates", None),
          ("verify_all_running_candidates", None),
          ("all_graceful_shutdown", None)]
    return s

def script_for(step):
    need(step in STEPS, "Unreviewed Command2 step")
    src = Path(__file__).resolve().with_name(STEPS[step])
    need(src.is_file() and not src.is_symlink(),
         "Missing pinned Command2 program: " + STEPS[step])
    return str(src)

def run_child(argv):
    """Allow only pinned sibling helpers; basenames alone are not trusted."""
    need(type(argv) is list and len(argv) >= 2 and
         type(argv[0]) is str, "Invalid helper invocation")
    helper = Path(argv[0])
    need(helper.is_absolute() and not helper.is_symlink() and
         helper.is_file() and helper.parent ==
         Path(__file__).resolve().parent and
         helper.name in STEPS.values(),
         "Unreviewed executable or helper path")
    try:
        return subprocess.run([sys.executable, "-B", *argv],
                              check=False).returncode
    except OSError as exc:
        raise SequenceBlocked("Pinned helper unavailable: " +
                              type(exc).__name__) from exc

def witness_folder(folder):
    path = absolute(folder, "witness-dir")
    for p in (path, *path.parents):
        need(not p.is_symlink(), "Symlinked receipt directory blocked")
    need(path.parent.is_dir() and path.parent.stat().st_uid == 0 and
         not path.parent.stat().st_mode & 0o022,
         "Private receipt parent must be root owned not writable by others")
    if not path.exists():
        path.mkdir(mode=0o700)
    st=path.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
         stat.S_IMODE(st.st_mode) == 0o700,
         "Receipt directory must be root-owned mode 0700")
    return path

def save_witness(path, data, *, first=False):
    raw = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()
    need(len(raw) < 512*1024, "Receipt too large")
    if first:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
    else:
        need(not path.is_symlink(), "Untrusted witness path")
        s=path.stat()
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and
             stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1,
             "Untrusted existing witness file")
        from tempfile import mkstemp
        fd, tmp = mkstemp(prefix=".command2-sequence-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw); f.flush()
                os.fchmod(f.fileno(), 0o600)
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
    d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(d)
    finally: os.close(d)

def plan(args):
    host = workflow.canonical_host(args.approved_host)
    need(os.geteuid() == 0, "Root required to read the exact master bundle")
    admitted_dirs(args)
    count = resolve_count(args.count)
    # Existing cold wizard performs the real golden-master source, disk,
    # libvirt, DHCP, identity and storage checks. Never bypass it.
    wizard = script_for("cold_count_stage")
    argv = [wizard, "--mode", "plan", "--approved-host", host,
            "--bundle", str(args.bundle),
            "--disk-dir", str(args.disk_dir),
            "--nvram-dir", str(args.nvram_dir),
            "--journal-dir", str(args.journal_dir),
            "--iso-dir", str(args.iso_dir), "--count", str(count)]
    need(run_child(argv) == 0,
         "Exact golden-master cold clone plan failed; no stage will run")
    return {
        "result": "COMMAND2_EXACT_MASTER_FULL_SEQUENCE_PLAN_ONLY",
        "additional_vm_count": count,
        "master_win11_untouched": True,
        "vm_names": vm_names(count),
        "step_count": len(phases(count)),
        "post_clone_phases": [STEPS[x] for x in STEPS],
        "existing_verified_journal_required_after_cold_stage": True,
        "operator_approvals_per_mutating_phase": True,
        "every_Windows_VM_windows_configured_verified": False,
        "TPM_safe_snapshot_restore_proven": False,
        "no_sample_analysis_or_service_restart": True,
        "host_modified": False,
    }

def execute(args):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Root interactive operator required for N-VM sequence")
    approved = workflow.canonical_host(args.approved_host)
    count=resolve_count(args.count)
    # Count is already resolved. Same value used in live cold-stage preflight.
    first_args=argparse.Namespace(**vars(args))
    first_args.count=count
    summary=plan(first_args)
    print(json.dumps(summary, sort_keys=True, indent=2), flush=True)
    need(input("Type " + APPROVAL + " for the full guarded clone sequence: ")
         == APPROVAL, "Operator declined Command2 all-N sequence")
    need(plan(first_args)==summary,
         "Golden source/host/current cold-stage plan changed after approval")
    folder=witness_folder(args.receipt_dir)
    target=folder/("command2-full-sequence."+uuid.uuid4().hex+".json")
    receipt={
        "result":"COMMAND2_EXACT_MASTER_SEQUENCE_STARTED",
        "approved_host":approved,
        "count":count,
        "names":vm_names(count),
        "completed":[],
        "current":None,
        "original_master_mutated":False,
        "snapshot_revert_attempted":False,
        "swtpm_restore_verified":False,
    }
    save_witness(target, receipt, first=True)
    for step, vm in phases(count):
        receipt["current"]={"step":step,"vm":vm}
        save_witness(target, receipt)
        name=script_for(step)
        argv=child_args(args,count,name,step,vm)
        try:
            code=run_child(argv)
        except Exception as exc:
            code=-1
        if code != 0:
            receipt["result"]="COMMAND2_SEQUENCE_PARTIAL_OR_UNKNOWN"
            receipt["failed_step"]={"step":step,"vm":vm,"exit_code":code}
            # No automatic retry, reset, force-stop, revert or cleanup.
            save_witness(target, receipt)
            raise SequenceBlocked(
                "PARTIAL_OR_UNKNOWN: halted after failed " + step +
                ((" for " + vm) if vm else "") +
                "; preserve all guests and review root-private receipt")
        receipt["completed"].append({"step":step,"vm":vm})
        receipt["current"]=None
        save_witness(target,receipt)
    receipt["result"]="COMMAND2_ALL_N_CANDIDATE_SNAPSHOTS_SHUT_OFF_TPM_UNVERIFIED"
    save_witness(target,receipt)
    return {
        "result":receipt["result"],
        "witness":str(target),
        "count":count,
        "master":"win11",
        "names":vm_names(count),
        "running_ram_disk_uefi_snapshot_candidates_stored":True,
        "clones_final_state":"shut off",
        "swtpm2_snapshots_revert_proven":False,
        "CAPE_SAFE_TO_RUN_SAMPLES":False,
        "all_VM_steps_invoked":True,
    }

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("plan","run"),default="plan")
    parser.add_argument("--approved-host",required=True)
    parser.add_argument("--bundle",type=Path,required=True)
    parser.add_argument("--disk-dir",type=Path,required=True)
    parser.add_argument("--nvram-dir",type=Path,required=True)
    parser.add_argument("--journal-dir",type=Path,required=True)
    parser.add_argument("--iso-dir",type=Path,required=True)
    parser.add_argument("--evidence-dir",type=Path,required=True)
    parser.add_argument("--count",type=int)
    parser.add_argument("--receipt-dir",type=Path,default=DEFAULT_WITNESSES)
    parser.add_argument("--shutdown-timeout",type=int,default=360)
    args=parser.parse_args()
    try:
        need(90<=args.shutdown_timeout<=900,
             "Windows graceful timeout must be 90..900 seconds")
        result=plan(args) if args.mode=="plan" else execute(args)
        print(json.dumps(result, indent=2, sort_keys=True), flush=True)
        return 0
    except Exception as exc:
        print(json.dumps({
            "result":"COMMAND2_EXACT_MASTER_SEQUENCE_BLOCKED_OR_PARTIAL",
            "error_type":type(exc).__name__,
            "no_automatic_retry_or_cleanup":True,
            "no_original_master_revert":True,
            "no_TPM_consistent_restore_claim":True,
        },sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
