#!/usr/bin/env python3
"""Strict rollback of tracked Command1 base APT additions (Ubuntu 24.04).

Undo ONLY newly installed, transaction-attributed packages. Never purge,
autoremove, upgrade, or touch preexisting packages. Refuse when the installed
package inventory differs from the exact sealed post-install snapshot, APT
would remove anything outside the attested set, or VMs/services are active.
All changes require explicit root operator approval and durable receipts.

This is intentionally NOT a universal CAPE package or VM rollback.
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

import command123_deployment_transaction as ledger
import command123_tracked_prereqs as apt

REMOVAL = re.compile(r"^Remv ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?) (?:\[|$)")
MAX = apt.MAX


def need(ok, reason):
    ledger.need(ok, reason)


def trusted_inventory_file(folder, filename, sha):
    need(type(filename) is str and
         re.fullmatch(r"apt-(?:before|after|rollback)-[a-f0-9]{32}", filename) and
         isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha),
         "Untrusted package inventory receipt")
    ledger.owner_dir(folder)
    file = folder / filename
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600 and
             0 < st.st_size <= MAX, "Untrusted package inventory file")
        raw = os.read(fd, MAX + 1)
        need(len(raw) == st.st_size and
             hashlib.sha256(raw).hexdigest() == sha,
             "Package inventory receipt is damaged")
    finally:
        os.close(fd)
    data = json.loads(raw)
    need(type(data) is dict and "dpkg" in data and
         all(type(k) is str and apt.PACKAGE.fullmatch(k) and
             type(v) is str and bool(v) for k, v in data.items()),
         "Invalid package inventory schema")
    need(apt.snap_bytes(data) == raw,
         "Inventory receipt is not byte-identical to sealed JSON")
    return data


def eligible_entry(doc):
    records = [r for r in doc["entries"] if r.get("kind") == "package"]
    need(len(records) == 1 and
         records[0].get("stage") == "command1" and
         records[0].get("status") == "sealed",
         "Exactly one sealed Command1 APT addition is required")
    rec = records[0]
    need(type(rec.get("id")) is str and
         re.fullmatch(r"[0-9a-f]{32}", rec["id"]),
         "Invalid package receipt ID")
    for field in ("before_sha256", "after_sha256"):
        need(type(rec.get(field)) is str and
             re.fullmatch(r"[0-9a-f]{64}", rec[field]),
             "Missing original/installed package inventory proof")
    return rec


def verify_reversed(transaction, host):
    """Check an earlier base-APT rollback still matches original dpkg state.

    No mutation, no permission to delete; a stale 'rollback_verified' flag
    alone never proves that later third-party software has not appeared.
    """
    apt.verify_host()
    receipt, doc = ledger.load(transaction, host)
    need(doc["phase"] == "active",
         "Package baseline verification requires active transaction")
    records = [row for row in doc["entries"] if row.get("kind") == "package"]
    need(len(records) == 1 and
         records[0].get("status") == "rollback_verified",
         "No independently completed package rollback")
    row = records[0]
    step = row["id"]
    need(type(step) is str and re.fullmatch(r"[0-9a-f]{32}", step),
         "Invalid APT rollback receipt identifier")
    baseline = trusted_inventory_file(
        receipt.parent, "apt-before-" + step, row["before_sha256"])
    reverted_sha = row.get("rollback_after_sha256")
    observed = trusted_inventory_file(
        receipt.parent, "apt-rollback-" + step, reverted_sha)
    need(observed == baseline and apt.installed() == baseline,
         "Post-rollback package inventory no longer equals baseline")
    return {"result": "CAPE_BASE_APT_REVERSE_STATE_REVERIFIED",
            "transaction": transaction,
            "before_package_count": len(baseline),
            "preexisting_package_inventory_matches": True,
            "mutated": False}


def simulated_remove(names):
    need(type(names) is list and names == sorted(set(names)) and
         all(apt.PACKAGE.fullmatch(n) for n in names),
         "Invalid package removal set")
    if not names:
        return []
    raw = apt.read_command([
        "apt-get", "-s", "-o", "Debug::NoLocking=true",
        "remove", "--no-auto-remove", "--", *names])
    removals = []
    for line in raw.splitlines():
        if line.startswith(("Inst ", "Purg ", "Conf ", "Hold ")):
            raise ledger.TransactionBlocked(
                "APT removal would upgrade/install/purge or alter other packages")
        if line.startswith("Remv "):
            match = REMOVAL.match(line)
            need(match is not None, "Unrecognized APT removal record")
            removals.append(match.group(1))
    need(sorted(removals) == names,
         "APT would remove additional packages or leave intended packages")
    return removals


def inspect(transaction, host):
    apt.verify_host()
    receipt, doc = ledger.load(transaction, host)
    need(doc["phase"] == "active", "Deployment already rolling back")
    entry = eligible_entry(doc)
    step = entry["id"]
    before = trusted_inventory_file(
        receipt.parent, "apt-before-" + step, entry["before_sha256"])
    after = trusted_inventory_file(
        receipt.parent, "apt-after-" + step, entry["after_sha256"])
    changes = apt.delta(before, after, entry.get("simulated", []))
    need(changes == entry.get("observed_change") and
         not changes["preexisting_changed"] and
         not changes["preexisting_removed"] and
         not changes["unplanned_additions"],
         "APT original creation evidence is incomplete or unexpected")
    # A user installed any new package (or upgraded even one) after our
    # transaction? Preserve all packages. Never infer they are ours.
    current = apt.installed()
    need(current == after,
         "Installed package inventory drifted since deployment")
    added = sorted(changes["new_packages"])
    simulated_remove(added)
    return {"result": "CAPE_ATTESTED_BASE_APT_ROLLBACK_PLAN",
            "transaction": transaction,
            "step": step,
            "packages_to_remove": added,
            "preexisting_package_count": len(before),
            "exact_dpkg_after_state_matches": True,
            "apt_simulation_only_removes_tracked_additions": True,
            "existing_package_changes_proposed": False,
            "other_resource_rollback_not_included": True,
            "no_host_changes": True}


def rollback(transaction, host):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Interactive root required for package rollback")
    ledger.host_guard(host)
    with ledger.exclusive_transaction_lock(transaction):
        prior = inspect(transaction, host)
        ledger.no_live_work()
        print(json.dumps(prior, sort_keys=True, indent=2), flush=True)
        phrase = "REMOVE-ONLY-TRACKED-CAPE-BASE-APT-" + transaction
        need(input("Type " + phrase + ": ") == phrase,
             "Operator did not approve package removal")
        need(inspect(transaction, host) == prior,
             "APT rollback candidate drifted before approval")
        receipt, doc = ledger.load(transaction, host)
        entry = eligible_entry(doc)
        step = entry["id"]
        before = trusted_inventory_file(
            receipt.parent, "apt-before-" + step, entry["before_sha256"])
        # Journal 'in-flight' before launching ANY apt command.
        entry["status"] = "rollback_partial"
        entry["rollback_current"] = "APT_REMOVE"
        ledger.atomic_receipt(receipt, doc)
        names = prior["packages_to_remove"]
        try:
            if names:
                proc = subprocess.run(
                    ["apt-get", "remove", "-y", "--no-auto-remove",
                     "--", *names],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, env=apt.ENV,
                    timeout=1200, check=False)
                code = proc.returncode
            else:
                code = 0
            current = apt.installed()
            evidence = apt.snap_bytes(current)
            ledger.private_copy(
                receipt.parent, "apt-rollback-" + step, evidence)
            entry["rollback_exit_code"] = code
            entry["rollback_after_sha256"] = (
                hashlib.sha256(evidence).hexdigest())
            verified = code == 0 and current == before
            entry["status"] = ("rollback_verified" if verified
                               else "rollback_partial")
            entry["rollback_current"] = None if verified else "REVIEW_REQUIRED"
            ledger.atomic_receipt(receipt, doc)
            need(verified, "APT undo did not restore exact baseline inventory")
            return {"result": "CAPE_BASE_APT_ADDITIONS_REVERTED_VERIFIED",
                    "transaction": transaction,
                    "count_removed": len(names),
                    "preexisting_package_inventory_restored": True,
                    "full_deployment_rollback_completed": False}
        except Exception as error:
            # Keep partial status and do not retry or auto-clean a disputed
            # apt transaction.
            raise ledger.TransactionBlocked(
                "APT rollback is partial or unknown; examine private receipt"
            ) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan-rollback", "rollback"),
                        default="plan-rollback")
    parser.add_argument("--approved-host", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--transaction")
    source.add_argument("--use-active-transaction", action="store_true")
    args = parser.parse_args()
    try:
        txid = (ledger.active_transaction(args.approved_host)
                if args.use_active_transaction else args.transaction)
        report = (inspect(txid, args.approved_host)
                  if args.mode == "plan-rollback" else
                  rollback(txid, args.approved_host))
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (ledger.TransactionBlocked, OSError, ValueError,
            TypeError, json.JSONDecodeError) as error:
        print(json.dumps({
            "result": "CAPE_PACKAGE_ROLLBACK_BLOCKED_OR_PARTIAL",
            "error_type": type(error).__name__,
            "no_unproven_package_removal": True,
            "whole_deployment_rollback_not_claimed": True,
        }), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
