#!/usr/bin/env python3
"""Transaction-scoped partial CAPE recovery orchestrator.

A single operator invocation for tracked CAPE files, one source checkout
and seven base-prerequisite packages. Dependency order: STOPPED services
and guests -> restore file originals -> quarantine owned pristine CAPE source
-> remove only proven new APT additions
-> finalize owned subset. Individual steps retain their own direct typed
consent and durable receipts. Never removes VM/TPM/network/firewall or
unproven resources. NOT a full three-command deployment rollback.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import command123_deployment_transaction as transaction
import command123_tracked_apt_rollback as packages
import command1_tracked_cape_source as cape_source


class ScopedRecoveryBlocked(RuntimeError):
    pass


def need(ok, message):
    if not ok:
        raise ScopedRecoveryBlocked(message)


def owned_stage_plan(host, txid):
    source, doc = transaction.load(txid, host)
    need(doc["phase"] == "active",
         "Transaction must be in active state (not partial or completed)")
    need(bool(doc["entries"]), "Transaction has no attested resources to reverse")
    names = [item.get("kind") for item in doc["entries"]]
    # Reject unknown/unfinished assets even if the helper subcommands
    # might independently permit a subset. No blind cleanup of VMs/etc.
    need(set(names) <= {"file", "package", "cape_source"},
         "Deployment includes unsupported VM/network/account/resource steps")
    prepared_files = [
        entry for entry in doc["entries"]
        if entry.get("kind") == "file" and entry.get("status") == "sealed"
    ]
    already_reversed = [
        entry for entry in doc["entries"]
        if entry.get("kind") == "file" and
        entry.get("status") == "rollback_verified"
    ]
    other_files = [
        entry for entry in doc["entries"]
        if entry.get("kind") == "file" and
        entry.get("status") not in ("sealed", "rollback_verified")
    ]
    need(not other_files, "Unsealed or partially restored file blocks recovery")
    package_rows = [entry for entry in doc["entries"]
                    if entry.get("kind") == "package"]
    need(len(package_rows) <= 1, "Cannot attribute multiple APT transactions")
    if package_rows:
        need(package_rows[0].get("status") in ("sealed", "rollback_verified"),
             "Unverified or partial package installation/undo")
    source_rows = [entry for entry in doc["entries"]
                   if entry.get("kind") == "cape_source"]
    need(len(source_rows) <= 1, "Cannot attribute repeated upstream CAPE checkout")
    if source_rows:
        need(source_rows[0].get("status") in ("sealed", "rollback_verified"),
             "Unverified or partially reverted source")
        source_inspection = cape_source.undo_plan(host, txid)
        need(source_inspection["action"] ==
             ("quarantine_owned_checkout" if
              source_rows[0]["status"] == "sealed" else "already_quarantined"),
             "CAPE source provenance and quarantine disagree")
    else:
        source_inspection = None
    first = transaction.rollback_plan(txid, host, files_only=True)
    need(first["can_rollback"],
         "File originals are missing or changed; recovery refused")
    # Package verification uses exact dpkg bytes AND no foreign additions.
    apt_inspection = (packages.inspect(txid, host)
                      if package_rows and
                         package_rows[0]["status"] == "sealed"
                      else None)
    if package_rows and package_rows[0]["status"] == "rollback_verified":
        packages.verify_reversed(txid, host)
    need(apt_inspection is None or
         apt_inspection["exact_dpkg_after_state_matches"],
         "Cannot safely remove package additions")
    return {
        "result": "CAPE_RECORDED_FILE_AND_BASE_APT_ROLLBACK_PLAN",
        "transaction": txid,
        "file_rollback_steps_needed": len(prepared_files),
        "file_rollback_steps_already_proven": len(already_reversed),
        "apt_new_packages_to_remove": (
            apt_inspection["packages_to_remove"] if apt_inspection else []),
        "apt_rollback_needed": apt_inspection is not None,
        "source_rollback_needed": source_inspection is not None and
                                  source_inspection["action"] ==
                                  "quarantine_owned_checkout",
        "source_rollback_action": (source_inspection["action"]
                                   if source_inspection else None),
        "file_actions": first["actions"],
        "all_non_file_non_apt_resource_types_supported": False,
        "no_host_changes": True,
        "full_three_command_rollback_verified": False,
    }


def run(host, txid):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Direct root operator approval required")
    transaction.host_guard(host)
    initial = owned_stage_plan(host, txid)
    print(json.dumps(initial, sort_keys=True, indent=2), flush=True)
    phrase = "ROLLBACK-TRACKED-CAPE-FILES-AND-BASE-APT-" + txid
    need(input("Type " + phrase + ": ").strip() == phrase,
         "Overall subset rollback declined")
    need(owned_stage_plan(host, txid) == initial,
         "Selected resources drifted after approval")
    # Guards are checked again under each stage's own transaction lock.
    # A partial stage prevents the next stage from running.
    if initial["file_rollback_steps_needed"]:
        result = transaction.rollback_files_first(txid, host, True)
        need(result["transaction_still_active"] is True,
             "File rollback not verified")
    if initial.get("source_rollback_needed", False):
        result = cape_source.undo(host, txid)
        need(result["result"] == "COMMAND1_OWNED_SOURCE_UNDEPLOYED_QUARANTINED",
             "Owned CAPE source checkout was not quarantined")
    if initial["apt_rollback_needed"]:
        result = packages.rollback(txid, host)
        need(result["preexisting_package_inventory_restored"] is True,
             "Package rollback not verified")
    final = transaction.rollback_plan(txid, host)
    need(final["can_rollback"] and all(
        action["action"] == "keep" for action in final["actions"]),
        "Remaining rollback steps not attested as reversed")
    finished = transaction.rollback(txid, host, True)
    need(finished["result"] == "CAPE_TRACKED_FILE_CHANGES_ROLLED_BACK",
         "Final transaction phase has not been sealed")
    return {
        "result": "CAPE_ATTESTED_FILE_AND_BASE_APT_SUBSET_REVERSED",
        "transaction": txid,
        "resource_types_reversed": [
            "reviewed_CAPE_files", "pinned_owned_CAPEv2_source_quarantined",
            "base_apt_additions"],
        "other_resource_rollback_not_included": True,
        "full_three_command_rollback_verified": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("plan", "rollback"), default="plan")
    p.add_argument("--approved-host", required=True)
    ids = p.add_mutually_exclusive_group(required=True)
    ids.add_argument("--transaction")
    ids.add_argument("--use-active-transaction", action="store_true")
    args = p.parse_args()
    try:
        txid = (transaction.active_transaction(args.approved_host)
                if args.use_active_transaction else args.transaction)
        result = (owned_stage_plan(args.approved_host, txid)
                  if args.mode == "plan" else run(args.approved_host, txid))
        print(json.dumps(result, sort_keys=True, indent=2), flush=True)
        return 0
    except (ScopedRecoveryBlocked, transaction.TransactionBlocked,
            OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({
            "result": "CAPE_SCOPED_RECOVERY_BLOCKED_OR_PARTIAL",
            "error_type": type(error).__name__,
            "no_unproven_VM_or_network_deletion": True,
            "no_whole_deployment_rollback_claimed": True,
        }), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
