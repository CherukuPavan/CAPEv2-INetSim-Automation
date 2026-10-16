#!/usr/bin/env python3
"""Guarded TWO benign running-snapshot revert cycles on a disposable other host.

Calls the existing fully checked one-cycle revert TWICE; between cycles,
gracefully shuts down Windows without force or reset. Root-private durable
receipt prevents accidental silent continuation after any partial operation.
CAPE Agent response is tested by the existing revert probe on both cycles.
This does NOT prove TPM NV-state/OVMF atomic rollback or network egress.
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
import tempfile
import time
import uuid

import command2_disposable_snapshot_revert_probe as once

LOCK = Path("/run/lock/cape-command2-two-cycle-revert.lock")
DEFAULT_RECEIPTS = Path("/var/lib/cape-command2-two-cycle-receipts")


class TwoCycleBlocked(RuntimeError):
    pass


def need(condition, reason):
    if not condition:
        raise TwoCycleBlocked(reason)


def witness_dir(folder):
    folder = Path(folder)
    need(folder.is_absolute() and not folder.is_symlink() and
         folder.parent.is_dir() and folder.parent.stat().st_uid == 0 and
         not folder.parent.stat().st_mode & 0o022,
         "Untrusted receipt directory parent")
    for part in folder.parents:
        need(not part.is_symlink(), "Symlinked receipt path")
    if not folder.exists():
        folder.mkdir(mode=0o700)
    st = folder.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
         stat.S_IMODE(st.st_mode) == 0o700,
         "Receipt must reside under root:0700 directory")
    return folder


def write_receipt(target, data, initial=False):
    raw = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()
    need(len(raw) < 65536, "Oversized restore receipt")
    if initial:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                 st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600,
                 "Untrusted existing restore receipt")
        finally:
            os.close(fd)
        fd, temporary = tempfile.mkstemp(prefix=".cycle-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fchmod(stream.fileno(), 0o600)
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)
    dirfd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def shut_down_without_force(vm, timeout=600):
    need(60 <= timeout <= 600, "Invalid graceful shutdown bound")
    need(once.virsh("domstate", vm).lower() == "running",
         "Expected running guest after snapshot revert")
    once.virsh("shutdown", vm)
    deadline = time.monotonic() + timeout
    while True:
        state = once.virsh("domstate", vm).lower()
        if state == "shut off":
            return True
        need(state in ("running", "in shutdown"),
             "Unexpected libvirt guest state during shutdown")
        need(time.monotonic() < deadline,
             "Guest did not shut down gracefully; no forced poweroff")
        time.sleep(3)


def plan(host, journal, vm, bundle, sha):
    checked = once.plan(host, journal, vm, bundle, sha)
    need(checked.get("one_disposable_guest_shut_off") is True and
         checked.get("host_nft_libvirt_isolation_structure_verified") is True,
         "No isolated and stopped disposable guest")
    fields = ("host", "vm", "uuid", "guest_ip", "subnet", "snapshot",
              "reviewed_full_cold_recovery_manifest_sha256")
    identity = {name: checked[name] for name in fields}
    digest = hashlib.sha256(json.dumps(
        identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"result": "COMMAND2_TWO_BENIGN_REVERT_PLAN_ONLY",
            "host": host, "vm": vm, "snapshot": checked["snapshot"],
            "identity_sha256": digest, "cold_manifest_sha256": sha,
            "cycles_planned": 2, "host_modified": False,
            "running_snapshot_revert_tested": False,
            "TPM_UEFI_full_state_revert_proven": False,
            "safe_for_malware": False}


def lock():
    need(not LOCK.is_symlink(), "Unsafe symlinked two-cycle lock")
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
             stat.S_IMODE(st.st_mode) == 0o600, "Unsafe two-cycle lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise TwoCycleBlocked("Another two-cycle revert is running") from error
        return fd
    except Exception:
        os.close(fd)
        raise


def run(host, journal, vm, bundle, sha, receipts):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Interactive approved other-host root operator required")
    initial = plan(host, journal, vm, bundle, sha)
    print(json.dumps(initial, indent=2, sort_keys=True), flush=True)
    phrase = "TWO-BENIGN-RESTORES-" + vm.upper()
    need(input("Type " + phrase + ": ").strip() == phrase,
         "Two-cycle revert was not approved")
    need(plan(host, journal, vm, bundle, sha) == initial,
         "Disposable guest changed before approval")
    folder = witness_dir(receipts)
    target = folder / ("two-reverts." + vm + "." + uuid.uuid4().hex + ".json")
    receipt = {
        "result": "TWO_CYCLE_BENIGN_STARTED", "host": host, "vm": vm,
        "snapshot": initial["snapshot"], "identity_sha256": initial["identity_sha256"],
        "cycles": [], "in_progress": None,
        "TPM_UEFI_full_state_revert_proven": False, "safe_for_malware": False,
        "production_ready": False,
    }
    write_receipt(target, receipt, initial=True)
    fd = lock()
    try:
        for cycle in (1, 2):
            fresh = plan(host, journal, vm, bundle, sha)
            need(fresh["identity_sha256"] == initial["identity_sha256"],
                 "Windows guest or full cold recovery changed between cycles")
            receipt["in_progress"] = "revert_" + str(cycle)
            write_receipt(target, receipt)
            # The child performs a separate typed-approval and verifies
            # network isolation and Agent health after actual virsh revert.
            result = once.revert_once(host, journal, vm, bundle, sha)
            need(result.get("result") ==
                 "COMMAND2_ONE_BENIGN_RUNNING_SNAPSHOT_REVERT_AGENT_REACHABLE" and
                 result.get("guest_running_after_revert") is True and
                 result.get("post_revert_agent_http_verified") is True,
                 "One revert failed to restore Windows Agent in running VM")
            receipt["in_progress"] = "graceful_shutdown_" + str(cycle)
            write_receipt(target, receipt)
            need(shut_down_without_force(vm),
                 "Windows graceful stop not verified")
            after = plan(host, journal, vm, bundle, sha)
            need(after["identity_sha256"] == initial["identity_sha256"],
                 "VM identity/isolation changed after shutdown")
            receipt["cycles"].append({
                "cycle": cycle, "revert_verified_running": True,
                "Agent_http_verified": True, "clean_shutdown_verified": True,
            })
            receipt["in_progress"] = None
            write_receipt(target, receipt)
        receipt["result"] = "TWO_BENIGN_REVERT_CYCLES_AGENT_ONLY_VERIFIED"
        write_receipt(target, receipt)
        return {"result": receipt["result"], "guest": vm,
                "private_witness": str(target),
                "real_benign_running_revert_cycles_verified": 2,
                "Windows_agent_worked_both_times": True,
                "guest_off_final": True,
                "TPM_UEFI_full_state_revert_proven": False,
                "disk_mutation_rollback_proven": False,
                "physical_egress_containment_proven": False,
                "production_ready": False}
    except Exception as error:
        receipt["result"] = "TWO_CYCLE_PARTIAL_OR_UNKNOWN"
        receipt["error_type"] = type(error).__name__
        receipt["no_auto_retry_or_guest_cleanup"] = True
        write_receipt(target, receipt)
        raise TwoCycleBlocked("Incomplete cycle, preserve VM and private receipt") from None
    finally:
        os.close(fd)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("plan", "run"), default="plan")
    p.add_argument("--approved-host", required=True)
    p.add_argument("--journal", required=True, type=Path)
    p.add_argument("--vm", required=True)
    p.add_argument("--recovery-bundle", required=True, type=Path)
    p.add_argument("--manifest-sha256", required=True)
    p.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPTS)
    args = p.parse_args()
    try:
        report = (plan(args.approved_host, args.journal, args.vm,
                       args.recovery_bundle, args.manifest_sha256)
                  if args.mode == "plan" else
                  run(args.approved_host, args.journal, args.vm,
                      args.recovery_bundle, args.manifest_sha256,
                      args.receipt_dir))
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (TwoCycleBlocked, once.RevertBlocked, OSError, ValueError,
            TypeError) as error:
        print(json.dumps({"result": "TWO_CYCLE_BLOCKED_OR_PARTIAL",
                          "exception_type": type(error).__name__,
                          "no_automatic_retry": True,
                          "TPM_UEFI_proven": False}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
