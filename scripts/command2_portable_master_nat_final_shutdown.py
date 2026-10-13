#!/usr/bin/env python3
"""Guarded final SHUT OFF handoff after all-N golden NAT running snapshots.

OTHER HOST ONLY. Requires ALL count-driven, independently configured Windows
guests to be running with matching RAM+Windows QCOW2+UEFI QCOW2 snapshots,
verified guest HTTPS/DHCP/Agent receipts, and native-stack checks BEFORE
requesting any shutdown. Gracefully shuts down each exact clone, never forces
power off. Preserves every running-state checkpoint, its disk and UEFI state.
The snapshot is still TPM-UNVERIFIED and NOT CAPE/malware ready.

Plan is read-only. Apply requires one N-batch approval plus each existing
guest shutdown helper's own typed consent. Stop after any partial failure.
No retry, boot, reset, libvirt revert, swtpm edit or CAPE registration.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import command2_portable_master_nat_running_snapshots as snapshots
import command2_graceful_shutdown as shutdown

LOCK=Path("/run/lock/cape-command2-master-nat-final-shutdown.lock")

class FinalShutdownBlocked(RuntimeError):
    pass

def need(ok,why):
    if not ok:
        raise FinalShutdownBlocked(why)

def preflight(host,journal,evidence_dir):
    # The underlying all-N gate checks exact private journal, independent
    # Windows acceptance receipts, live MAC/IP/Agent, QCOW2 UEFI and RAM
    # memory/disk snapshot inventories without changing any guest.
    whole=snapshots.assess(host,journal,evidence_dir,True)
    need(whole.get("result")==
         "COMMAND2_MASTER_NAT_ALL_N_RUNNING_CANDIDATES_VERIFIED" and
         whole.get("all_running_native_snapshots_created") is True and
         whole.get("CAPE_READY") is False and
         whole.get("swtpm_epoch_matched_backup_and_twice_benign_revert_proven")
             is False,
         "Only experimental N running snapshots, never a TPM-ready CAPE state")
    count=whole["count"]
    guests=whole["guest_snapshots"]
    need(type(count) is int and 1<=count<=16 and
         type(guests) is list and len(guests)==count,
         "All-N running snapshot admission has inconsistent VM count")
    rows=snapshots.attach.journal_rows(host,journal)
    need(len(rows)==count and [r["libvirt_name"] for r in rows]==
         ["win11_"+str(i) for i in range(1,count+1)],
         "Exact ordered count-driven VM reservation changed")
    ordered=[]
    for row,guest in zip(rows,guests):
        vm=row["libvirt_name"]
        need(guest["vm"]==vm and
             guest["uuid"]==row["libvirt_uuid_candidate"] and
             guest["expected_name"]=="cape_one_nat_"+vm and
             guest["snapshot_captured"] is True and
             guest["swtpm_state_consistency_at_checkpoint_proved"] is False,
             "Unmatched RAM/UEFI/TPM warning in per-VM snapshot receipt")
        # Check that the general shutdown engine also sees the exact
        # persistent one-interface NAT profile, UUID and shutdown method.
        report=shutdown.inspect(host,"portable-master-nat",vm,journal)
        need(report["state"]=="running" and
             report["uuid"]==row["libvirt_uuid_candidate"] and
             report["capabilities"]["acpi"] or False,
             "NAT Windows guest not running with supported ACPI shutdown")
        ordered.append({"vm":vm,"uuid":row["libvirt_uuid_candidate"],
            "running_snapshot":guest["expected_name"],
            "shutdown_mode":"graceful_ACPI_or_QGA_only"})
    return {"result":"COMMAND2_MASTER_NAT_FINAL_SHUTDOWN_PLAN_ONLY",
        "host":host,"count":count,"guests":ordered,
        "journal_sha256":hashlib.sha256(Path(journal).read_bytes()).hexdigest(),
        "snapshot_metadata_verified_before_shutdown":True,
        "all_windows_receipts_and_live_agent_verified_before_shutdown":True,
        "all_clones_currently_running":True,
        "snapshot_revert_tpm_state_proven":False,
        "malware_or_cape_ready":False,
        "no_vm_mutation_in_plan":True}

def finish_check(host,journal,records,done):
    # This intentionally does NOT call all-N live Agent verification:
    # already-stopped guests cannot respond to CAPE Agent HTTP.
    rows=snapshots.attach.journal_rows(host,journal)
    need(len(rows)==len(records),"Clone journal count changed during handoff")
    for row,entry in zip(rows,records):
        vm=row["libvirt_name"]
        need(vm==entry["vm"] and
             row["libvirt_uuid_candidate"]==entry["uuid"],
             "Final VM identity changed during shutdown")
        snapshots.libvirt_snapshot(vm,True)
        snapshots.images(row,True)
        info=shutdown.inspect(host,"portable-master-nat",vm,journal)
        need(info["state"]==("shut off" if vm in done else "running"),
             "Unexplained guest power state in final snapshot readback")

def execute(host,journal,evidence_dir,timeout_seconds=360):
    need(os.geteuid()==0 and sys.stdin.isatty(),
         "Root and direct operator terminal required for final all-N handoff")
    need(type(timeout_seconds) is int and 90<=timeout_seconds<=900,
         "Graceful shutdown timeout must be 90..900 seconds")
    initial=preflight(host,journal,evidence_dir)
    print(json.dumps(initial,sort_keys=True,indent=2),flush=True)
    phrase="FINAL-SHUTDOWN-"+str(initial["count"])+"-NAT-TPM-UNVERIFIED"
    need(input("Type "+phrase+" for guarded sequential SHUT OFF: ")==phrase,
         "Operator did not approve graceful final N shutdown")
    need(not LOCK.is_symlink(),"Untrusted final NAT shutdown lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Root-private final NAT shutdown lock required")
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise FinalShutdownBlocked("Another final NAT shutdown active") from exc
        need(preflight(host,journal,evidence_dir)==initial,
             "Windows/snapshot/full-N state changed after initial approval")
        done=[]
        attempted=False
        try:
            for entry in initial["guests"]:
                need(hashlib.sha256(Path(journal).read_bytes()).hexdigest()==
                     initial["journal_sha256"],
                     "Guest journal changed during final NAT shutdown")
                vm=entry["vm"]
                row=next(r for r in snapshots.attach.journal_rows(host,journal)
                         if r["libvirt_name"]==vm)
                snapshots.libvirt_snapshot(vm,True)
                snapshots.images(row,True)
                info=shutdown.inspect(host,"portable-master-nat",vm,journal)
                need(info["state"]=="running" and
                     info["uuid"]==entry["uuid"],
                     "Guest changed before exact graceful shutdown")
                # A shutdown request can be accepted yet Windows can remain
                # running. Mark attempt before calling the child.
                attempted=True
                result=shutdown.request_shutdown(host,"portable-master-nat",
                        vm,journal,timeout_seconds)
                need(result["result"]==
                     "COMMAND2_GRACEFUL_SHUTDOWN_SHUT_OFF_CONFIRMED",
                     "Windows did not reach verified shut off state")
                done.append(vm)
                snapshots.libvirt_snapshot(vm,True)
                snapshots.images(row,True)
                need(shutdown.inspect(host,"portable-master-nat",vm,journal)
                     ["state"]=="shut off",
                     "VM not shut off despite graceful confirmation")
            finish_check(host,journal,initial["guests"],set(done))
        except Exception as exc:
            if attempted:
                raise FinalShutdownBlocked(
                    "FINAL_NAT_SHUTDOWN_PARTIAL_OR_UNKNOWN: do not retry, "
                    "force-off, boot, revert or delete snapshots. "
                    "Inspect exact VM power/TPM state manually: "+
                    str(exc)) from exc
            raise
        return {**initial,
            "result":"COMMAND2_MASTER_NAT_ALL_N_SHUT_OFF_SNAPSHOTS_PRESERVED",
            "guest_states":"shut off","snapshot_metadata_preserved":True,
            "all_guest_windows_shutdown_gracefully":True,
            "swtpm_safe_full_snapshot_revert_proven":False,
            "CAPE_READY":False,"malware_execution_authorized":False}
    finally:
        os.close(fd)
        LOCK.unlink(missing_ok=True)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","shutdown"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--evidence-dir",type=Path,required=True)
    p.add_argument("--timeout-seconds",type=int,default=360)
    a=p.parse_args()
    try:
        result=execute(a.approved_host,a.journal,a.evidence_dir,
             a.timeout_seconds) if a.mode=="shutdown" else preflight(
             a.approved_host,a.journal,a.evidence_dir)
        print(json.dumps(result,sort_keys=True,indent=2),flush=True)
        return 0
    except (FinalShutdownBlocked,shutdown.ShutdownBlocked,
            snapshots.NATSnapshotBlocked,
            snapshots.agents.BatchAgentBlocked,
            snapshots.native.NativeBlocked,
            snapshots.attach.NatAttachBlocked,
            snapshots.attach.profile.PortableNatBlocked,
            snapshots.attach.workflow.WorkflowBlocked,
            ValueError,TypeError,KeyError,OSError,
            json.JSONDecodeError) as exc:
        print(json.dumps({"result":"COMMAND2_MASTER_NAT_FINAL_SHUTDOWN_BLOCKED",
            "reason":str(exc),"no_automatic_retry_or_hard_stop":True,
            "snapshot_swtpm_safe_revert_not_established":True},
            sort_keys=True),file=sys.stderr,flush=True)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
