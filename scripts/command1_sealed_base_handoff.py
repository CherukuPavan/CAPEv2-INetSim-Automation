#!/usr/bin/env python3
"""Read-only attestation of an already SEALED Command 1 APT baseline.

Use after an interrupted fresh-host Command 1: do not start a second
transaction, delete earlier package receipts, or infer package ownership.
The current complete dpkg inventory must exactly equal the sealed after
snapshot. Python upgrades are separately admitted only for Jammy's
reviewed narrow allowlist. Does not install CAPE, QEMU or any VM.
"""
from __future__ import annotations

import hashlib
import json
import sys

import command123_deployment_transaction as tx
import command123_tracked_prereqs as apt
from command123_tracked_apt_rollback import trusted_inventory_file


def attest(host):
    apt.verify_host()
    ident = tx.active_transaction(host)
    receipt, doc = tx.load(ident, host)
    tx.need(doc["phase"] == "active", "Unusable existing transaction")
    items = [row for row in doc["entries"] if row.get("kind") == "package"]
    tx.need(len(items) == 1, "Expected exactly one existing base APT stage")
    row = items[0]
    tx.need(row.get("stage") == "command1" and row.get("status") == "sealed",
            "Prior base installation is not sealed")
    step = row["id"]
    before = trusted_inventory_file(receipt.parent, "apt-before-" + step,
                                    row["before_sha256"])
    after = trusted_inventory_file(receipt.parent, "apt-after-" + step,
                                   row["after_sha256"])
    changes = apt.delta(before, after, row.get("simulated", []))
    tx.need(changes == row.get("observed_change"),
            "Package modifications differ from original sealed receipt")
    tx.need(not changes["preexisting_removed"] and
            not changes["unplanned_additions"],
            "Original APT transaction contains unreviewed package changes")
    altered = set(changes["preexisting_changed"])
    approved = set(row.get("preexisting_python_upgrade_versions_before", {}))
    tx.need(altered == approved and
            (not altered or (
                apt.verify_host() == "22.04" and
                altered <= apt.JAMMY_PYTHON_UPGRADE_ALLOWLIST)),
            "Unrecognized preexisting package upgrades in sealed transaction")
    tx.need(all(
        row["preexisting_python_upgrade_versions_before"][name]
        == before[name] for name in approved),
        "Python upgrade original versions do not match sealed baseline")
    present = apt.installed()
    tx.need(present == after,
            "Host package inventory changed since sealed base stage")
    tx.need(not any(
        item.get("kind") == "cape_source" and
        item.get("status") not in ("rollback_verified",)
        for item in doc["entries"]),
        "Upstream CAPE source already attempted; inspect its journal")
    return {
        "result": "COMMAND1_EXISTING_BASE_TRANSACTION_ATTESTED",
        "transaction_id": ident,
        "approved_host": host,
        "after_inventory_sha256": hashlib.sha256(apt.snap_bytes(after)).hexdigest(),
        "base_package_additions": len(changes["new_packages"]),
        "existing_python_upgrades": sorted(altered),
        "may_stage_pinned_cape_source_under_same_transaction": True,
        "apt_reinstall_required": False,
        "full_package_rollback_supported": False,
        "full_CAPEv2_installed": False,
        "safe_to_submit_malware": False,
        "host_modified": False
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approved-host", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(attest(args.approved_host), indent=2, sort_keys=True))
        return 0
    except (tx.TransactionBlocked, OSError, ValueError, TypeError, KeyError,
            json.JSONDecodeError) as error:
        print(json.dumps({
            "result": "COMMAND1_EXISTING_BASE_NOT_ATTESTED",
            "error_type": type(error).__name__,
            "block_reason": str(error)[:250] if isinstance(
                error, tx.TransactionBlocked) else "Invalid receipt or host state",
            "never_create_second_transaction": True,
        }, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
