#!/usr/bin/env python3
"""Quarantine ONLY a deployment-owned CAPE Python venv, never delete it.

The runtime was absent before the deployment. Once all CAPE services and
VMs are stopped, an exact root-private deployment receipt authorizes
renaming only that owned runtime into an untraversable quarantine directory.
Foreign data inside are preserved; no host Python, APT package or other
user's virtualenv is removed. Requires its own explicit typed approval.
A crash after prepared undo refuses unattended retry/reconciliation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys

import command123_deployment_transaction as tx
import command1_cape_runtime_rootless_stage as runtime

class RuntimeUndoBlocked(RuntimeError):
    pass


def need(ok, why):
    if not ok:
        raise RuntimeUndoBlocked(why)


def owned_entry(doc):
    rows = [x for x in doc["entries"]
            if x.get("kind") == runtime.RUNTIME_KIND]
    need(len(rows) == 1, "One sealed owned runtime receipt required")
    row = rows[0]
    need(row.get("status") in ("sealed","rollback_verified") and
         row.get("stage") == "command1" and
         type(row.get("id")) is str and
         re.fullmatch(r"[0-9a-f]{32}",row["id"]) and
         type(row.get("runtime_owner")) is str and
         runtime.USERNAME.fullmatch(row["runtime_owner"]),
         "Runtime ownership is incomplete or uncertain")
    return row


def quarantine_parent(*, create=False):
    home=runtime.stage_parent(create=False)
    location=home/".quarantine"
    need(not location.is_symlink(),"Symlinked quarantine parent")
    if not location.exists() and create:
        location.mkdir(mode=0o700)
        tx.fsync_dir(home)
    if location.exists():
        st=location.stat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
             stat.S_IMODE(st.st_mode) == 0o700,
             "Quarantine must be root-owned and inaccessible to CAPE user")
    return location


def inspect(host, transaction):
    receipt,doc=tx.load(transaction,host)
    need(doc["phase"] == "active",
         "Only still-active deployment can release its owned runtime")
    row=owned_entry(doc)
    active=runtime.ROOT/transaction
    quarantine=quarantine_parent()/("owned-"+row["id"])
    need(row.get("target") == str(active) and
         row.get("before_present") is False,
         "Runtime target was not originally absent")
    if row["status"] == "rollback_verified":
        need(row.get("quarantine") == str(quarantine) and
             not active.exists() and not active.is_symlink() and
             quarantine.is_dir() and not quarantine.is_symlink(),
             "Owned runtime quarantine cannot be reverified")
        status="already_quarantined"
    else:
        need(active.is_dir() and not active.is_symlink() and
             not quarantine.exists() and not quarantine.is_symlink(),
             "Owned runtime directory no longer matches receipt")
        expected_uid=pwd.getpwnam(row["runtime_owner"]).pw_uid
        st=active.stat()
        need(st.st_uid==expected_uid and
             stat.S_IMODE(st.st_mode)==0o700,
             "Runtime owner/permissions changed")
        status="quarantine_owned_runtime"
    return {
        "result":"COMMAND1_OWNED_RUNTIME_ROLLBACK_PLAN",
        "transaction":transaction,
        "step_id":row["id"],
        "action":status,
        "runtime_path":str(active),
        "quarantine_path":str(quarantine),
        "prior_runtime_did_not_exist":True,
        "no_delete_operation":True,
        "host_modified":False,
        "full_three_command_rollback_proven":False,
    }


def undo(host,transaction):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Root interactive consent required for runtime quarantine")
    with tx.exclusive_transaction_lock(transaction):
        plan=inspect(host,transaction)
        need(plan["action"] == "quarantine_owned_runtime",
             "Already reversed or runtime state unverified")
        tx.no_live_work()
        print(json.dumps(plan,indent=2,sort_keys=True),flush=True)
        phrase="QUARANTINE-ONLY-OWNED-CAPE-PYTHON-"+transaction
        need(input("Type "+phrase+": ").strip()==phrase,
             "Operator did not approve runtime removal")
        need(inspect(host,transaction) == plan,
             "Runtime changed after approval")
        tx.no_live_work()
        receipt,doc=tx.load(transaction,host)
        row=owned_entry(doc)
        need(row["id"]==plan["step_id"],"Runtime receipt drifted")
        folder=quarantine_parent(create=True)
        src=Path(plan["runtime_path"])
        dst=Path(plan["quarantine_path"])
        need(dst.parent==folder and not dst.exists() and
             not dst.is_symlink(),
             "Unknown destination collision")
        row["status"]="rollback_prepared"
        row["quarantine"]=str(dst)
        tx.atomic_receipt(receipt,doc)
        # This rename is the sole undo mutation; preserve all staged files
        # in a root-only container rather than recursively deleting.
        os.rename(src,dst)
        tx.fsync_dir(folder)
        tx.fsync_dir(runtime.ROOT)
        row["status"]="rollback_verified"
        tx.atomic_receipt(receipt,doc)
        return {
            "result":"COMMAND1_OWNED_PYTHON_RUNTIME_UNDEPLOYED_QUARANTINED",
            "transaction":transaction,
            "owned_runtime_active_path_absent":True,
            "original_packages_and_system_python_untouched":True,
            "retained_quarantine_for_manual_disposal":str(dst),
            "full_three_command_rollback_proven":False,
        }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","undo"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--transaction",required=True)
    args=p.parse_args()
    try:
        result=(inspect(args.approved_host,args.transaction)
                if args.mode=="plan" else
                undo(args.approved_host,args.transaction))
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (RuntimeUndoBlocked,RuntimeError,OSError,ValueError,
            TypeError,KeyError) as error:
        print(json.dumps({
            "result":"COMMAND1_OWNED_RUNTIME_REVERSE_BLOCKED_OR_PARTIAL",
            "error_type":type(error).__name__,
            "no_foreign_runtime_deletion":True
        }),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
