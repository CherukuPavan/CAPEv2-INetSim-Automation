#!/usr/bin/env python3
"""Guarded next step on an EXISTING host with sealed Command1 base APT.

Attest the existing root-private dpkg transaction against the live host,
then stage an exact pinned public upstream CAPEv2 source commit under the
SAME transaction. Does not install CAPE services, VMs, hypervisors, or
private golden media; does not create another package baseline.

This is NOT the final Command1 production release.
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys
from pathlib import Path

import command1_sealed_base_handoff as sealed
import command1_tracked_cape_source as source
import command123_deployment_transaction as tx

SHA40 = re.compile(r"[0-9a-f]{40}\Z")


def resume(host: str, cape_revision: str, *, apply: bool):
    tx.need(isinstance(cape_revision, str) and
            SHA40.fullmatch(cape_revision) is not None,
            "Pin a 40-hex upstream CAPEv2 commit")
    proof = sealed.attest(host)
    transaction = proof["transaction_id"]
    plan = source.plan(host, transaction, cape_revision)
    result = {
        "result": "COMMAND1_EXISTING_BASE_READY_FOR_CAPE_SOURCE",
        "base": proof, "cape_source": plan,
        "existing_apt_transaction_reused": True,
        "new_package_transaction_created": False,
        "source_installed": False,
        "full_cape_installed": False,
        "TPM_snapshots_proven": False,
    }
    if not apply:
        return result
    tx.need(os.geteuid() == 0 and sys.stdin.isatty(),
            "Interactive root terminal required")
    # The inner source installer has exact plan-revalidation and an explicit
    # operator approval BEFORE journaling or performing Git/network changes.
    stage = source.install(host, transaction, cape_revision)
    tx.need(stage.get("result") ==
            "COMMAND1_CAPE_PINNED_SOURCE_STAGED_ONLY" and
            stage.get("transaction") == transaction,
            "CAPEv2 source was not sealed under existing transaction")
    result.update({
        "result": "COMMAND1_BASE_AND_UPSTREAM_SOURCE_STAGED",
        "source_installed": True,
        "source": stage,
    })
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("plan", "apply"), default="plan")
    p.add_argument("--approved-host", required=True)
    p.add_argument("--cape-revision", required=True)
    args=p.parse_args()
    try:
        out=resume(args.approved_host,args.cape_revision,
                   apply=args.mode == "apply")
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0
    except (tx.TransactionBlocked, source.SourceBlocked, OSError, ValueError,
            TypeError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "result": "COMMAND1_SEALED_BASE_SOURCE_STAGE_BLOCKED_OR_PARTIAL",
            "reason": str(exc)[:250],
            "never_erase_or_repeat_uncertain_transaction": True,
            "full_cape_ready": False,
        },sort_keys=True),file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
