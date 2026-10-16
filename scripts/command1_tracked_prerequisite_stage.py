#!/usr/bin/env python3
"""Command1 internal base-only stage with automatic pre-mutation transaction.

A future one-command installer can invoke this module internally. It plans
reviewed seven Ubuntu base packages, creates the sole root-private deployment
baseline BEFORE APT and delegates to complete dpkg provenance. Failure leaves
the active transaction for diagnosis rather than blindly deleting resources.

NOT a full fresh-host CAPEv2 installer or a final operator command.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import command123_deployment_transaction as tx
import command123_tracked_prereqs as packages


def need(ok, reason):
    tx.need(ok, reason)


def preflight(host):
    tx.host_guard(host)
    proposed = packages.plan()
    return {"result": "COMMAND1_BASE_TRANSACTION_PREFLIGHT",
            "host": host, "apt": proposed,
            "new_transaction_created": False,
            "full_CAPEv2_installed": False,
            "exact_Windows_master_imported": False,
            "running_snapshot_restore_proven": False,
            "host_modified": False}


def apply(host):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Command1 base transaction needs interactive root")
    initial = preflight(host)
    print(json.dumps(initial, indent=2, sort_keys=True), flush=True)
    approval = "BEGIN-CAPE-DEPLOYMENT-ON-" + host.upper()
    need(input("Type " + approval + ": ").strip() == approval,
         "Deployment transaction declined")
    need(preflight(host) == initial,
         "Host prerequisites changed before first transaction")
    new = tx.begin(host)
    transaction = new["transaction_id"]
    try:
        installed = packages.apply(transaction, host)
    except Exception as error:
        # The durable active marker remains, and prepared APT receipts
        # block accidental reuse. Do NOT reinitialize a new transaction.
        raise tx.TransactionBlocked(
            "Partial or unknown base-prerequisite state; "
            "root-private transaction preserved: " + transaction
        ) from error
    return {"result": "COMMAND1_TRACKED_BASE_PREREQUISITES_ONLY",
            "transaction_id": transaction,
            "automatic_transaction_pointer_created": True,
            "package_stage": installed["result"],
            "full_CAPEv2_installed": False,
            "VM_snapshots_ready": False,
            "safe_to_submit_samples": False,
            "full_deployment_rollback_ready": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("plan", "apply"), default="plan")
    p.add_argument("--approved-host", required=True)
    a = p.parse_args()
    try:
        result = preflight(a.approved_host) if a.mode == "plan" else apply(
            a.approved_host)
        print(json.dumps(result, indent=2, sort_keys=True), flush=True)
        return 0
    except (tx.TransactionBlocked, OSError, ValueError,
            TypeError) as error:
        print(json.dumps({
            "result": "COMMAND1_TRACKED_BASE_STAGE_BLOCKED_OR_PARTIAL",
            "error_type": type(error).__name__,
            "never_reset_unresolved_transaction": True,
            "three_command_deployment_complete": False,
        }, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
