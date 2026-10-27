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
import command1_tracked_cape_source as source


def need(ok, reason):
    tx.need(ok, reason)


def preflight(host, cape_revision=None):
    tx.host_guard(host)
    proposed = packages.plan()
    if cape_revision is not None:
        need(type(cape_revision) is str and
             source.SHA40.fullmatch(cape_revision),
             "Exact CAPE source revision required for combined bootstrap")
        source.safe_root(create=False)
    return {"result": "COMMAND1_BASE_TRANSACTION_PREFLIGHT",
            "host": host, "apt": proposed,
            "pinned_cape_source_commit": cape_revision,
            "public_cape_source_import_planned": cape_revision is not None,
            "new_transaction_created": False,
            "full_CAPEv2_installed": False,
            "exact_Windows_master_imported": False,
            "running_snapshot_restore_proven": False,
            "host_modified": False}


def apply(host, cape_revision=None):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Command1 base transaction needs interactive root")
    initial = preflight(host, cape_revision)
    print(json.dumps(initial, indent=2, sort_keys=True), flush=True)
    approval = "BEGIN-CAPE-DEPLOYMENT-ON-" + host.upper()
    need(input("Type " + approval + ": ").strip() == approval,
         "Deployment transaction declined")
    need(preflight(host, cape_revision) == initial,
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
    pinned_source = None
    if cape_revision is not None:
        try:
            pinned_source = source.install(host, transaction, cape_revision)
            need(pinned_source.get("result") ==
                 "COMMAND1_CAPE_PINNED_SOURCE_STAGED_ONLY",
                 "Pinned CAPE checkout was not sealed")
        except Exception as error:
            # APT is already tracked; a source checkout may be partial.
            # Do not destroy it, retry fetch or start the next command.
            raise tx.TransactionBlocked(
                "CAPE source stage partial or uncertain; "
                "root-private transaction retained: " + transaction
            ) from error
    return {"result": ("COMMAND1_TRACKED_BASE_AND_PINNED_CAPE_SOURCE_ONLY"
                       if pinned_source else
                       "COMMAND1_TRACKED_BASE_PREREQUISITES_ONLY"),
            "transaction_id": transaction,
            "pinned_upstream_source_commit": cape_revision,
            "exact_public_source_staged": pinned_source is not None,
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
    p.add_argument("--cape-revision",
                   help="Optional exact upstream CAPEv2 SHA40; staged after base APT under same transaction")
    a = p.parse_args()
    try:
        result = (preflight(a.approved_host, a.cape_revision)
                  if a.mode == "plan" else
                  apply(a.approved_host, a.cape_revision))
        print(json.dumps(result, indent=2, sort_keys=True), flush=True)
        return 0
    except (tx.TransactionBlocked, OSError, ValueError,
            TypeError) as error:
        print(json.dumps({
            "result": "COMMAND1_TRACKED_BASE_STAGE_BLOCKED_OR_PARTIAL",
            "error_type": type(error).__name__,
            # Preflight failures should not force blind retry cycles.
            # Reasons are our own bounded safety diagnostics, not tokens.
            "block_reason": (str(error)[:300]
                             if isinstance(error, tx.TransactionBlocked)
                             else "OS/parse error (see protected host logs)"),
            "never_reset_unresolved_transaction": True,
            "three_command_deployment_complete": False,
        }, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
