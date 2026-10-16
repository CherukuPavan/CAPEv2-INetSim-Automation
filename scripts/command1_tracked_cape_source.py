#!/usr/bin/env python3
"""Guarded pinned CAPEv2 upstream source stage under root-private deployment.

This stages a PUBLIC upstream CAPEv2 source checkout by exact Git commit
into a new, deployment-unique root-owned directory. Source code only:
NO upstream install scripts are invoked, no OS packages, VMs, networks,
accounts or service state are touched. The full CAPE install is unbuilt.

The transaction is journaled as PREPARED before creating any target paths.
The final checkout is SHA/tree verified, structurally checked, atomic
renamed and SEALED; errors preserve PREPARED records and staging data.
A separate guarded undo quarantines the exact pristine owned checkout
only after services and VMs are known stopped. Never deletes originals.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

import command123_deployment_transaction as tx

SOURCE = "https://github.com/kevoreilly/CAPEv2.git"
DEST_ROOT = Path("/opt/cape-deployments")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
NO_GIT = frozenset((".git",))
MAX_TRACKED = 18000
MAX_BYTES = 2 * 1024 * 1024 * 1024
GIT_ENV = {
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "HOME": "/",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GCM_INTERACTIVE": "Never",
}


class SourceBlocked(RuntimeError):
    pass


def need(ok, why):
    if not ok:
        raise SourceBlocked(why)


def safe_root(*, create=False):
    need(DEST_ROOT.is_absolute() and not DEST_ROOT.is_symlink() and
         DEST_ROOT.parent == Path("/opt") and
         DEST_ROOT.parent.is_dir() and
         DEST_ROOT.parent.stat().st_uid == 0 and
         not DEST_ROOT.parent.stat().st_mode & 0o022,
         "Invalid protected /opt source parent")
    if not DEST_ROOT.exists():
        if not create:
            return DEST_ROOT
        DEST_ROOT.mkdir(mode=0o755)
        tx.fsync_dir(DEST_ROOT.parent)
    st = DEST_ROOT.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
         not st.st_mode & 0o022, "Untrusted CAPE installation parent")
    return DEST_ROOT


def execute_git(path, *args, timeout=120):
    need(path.is_absolute() and path.is_dir() and not path.is_symlink(),
         "Untrusted Git execution directory")
    result = subprocess.run(
        ["git", "-C", str(path), "-c", "core.hooksPath=/dev/null",
         "-c", "core.fsmonitor=false",
         "-c", "core.externalDiff=false", *args],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=GIT_ENV, timeout=timeout, check=False)
    need(result.returncode == 0 and len(result.stdout) <= MAX_BYTES,
         "Pinned CAPE Git command failed or oversized")
    return result.stdout


def tracked_hash(directory):
    """Compute SHA256 tree from Git's tracked regular files, no links/devices."""
    need(directory.is_absolute() and not directory.is_symlink(),
         "Source path invalid")
    raw = execute_git(directory, "ls-files", "--stage", "-z")
    rows = raw.split(b"\0")
    need(rows[-1] == b"" and 0 < len(rows) - 1 <= MAX_TRACKED,
         "Git checkout tracked-file inventory invalid")
    summary = hashlib.sha256()
    total = 0
    seen = set()
    for row in rows[:-1]:
        need(b"\t" in row, "Malformed Git tracked-file record")
        header, encoded_path = row.split(b"\t", 1)
        fields = header.split()
        need(len(fields) == 3 and fields[0] in (b"100644", b"100755") and
             fields[2] == b"0", "Link, submodule or unresolved index refused")
        try:
            filename = encoded_path.decode("utf-8")
        except UnicodeError as err:
            raise SourceBlocked("Invalid UTF-8 checkout filename") from err
        relative = Path(filename)
        need(not relative.is_absolute() and filename == str(relative) and
             filename not in seen and len(filename) < 1024 and
             all(x not in (".", "..", "") for x in relative.parts) and
             not any(part.is_symlink()
                     for part in (directory / relative, *(directory / relative).parents)
                     if part != directory.parent),
             "Unsafe or repeated source path")
        seen.add(filename)
        file = directory / relative
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                 (stat.S_IMODE(st.st_mode) & 0o111 != 0) ==
                 (fields[0] == b"100755") and st.st_size <= 100 * 1024 * 1024,
                 "Unexpected source object type, executable mode or size")
            current = hashlib.sha256()
            remaining = st.st_size
            while remaining > 0:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                need(bool(chunk), "Source file changed during inspection")
                current.update(chunk)
                remaining -= len(chunk)
            total += st.st_size
            need(total <= MAX_BYTES, "Source checkout unexpectedly large")
        finally:
            os.close(fd)
        summary.update(encoded_path + b"\0" + fields[0] + b"\0")
        summary.update(current.digest())
    return {"file_count": len(seen), "total_bytes": total,
            "content_sha256": summary.hexdigest()}


def pristine(directory, pinned):
    need(type(pinned) is str and SHA40.fullmatch(pinned),
         "Explicit pinned public CAPE commit required")
    commit = execute_git(directory, "rev-parse", "--verify", "HEAD").strip()
    need(commit.decode("ascii") == pinned, "Source commit mismatch")
    tree = execute_git(directory, "rev-parse",
                       "--verify", "HEAD^{tree}").strip().decode("ascii")
    need(SHA40.fullmatch(tree), "Unverifiable CAPE Git tree")
    need(execute_git(directory, "status", "--porcelain=v1",
                     "--untracked-files=all") == b"",
         "Unexpected source changes, untracked additions or index drift")
    result = tracked_hash(directory)
    result.update({"revision": pinned, "tree": tree})
    return result


def plan(host, transaction, revision):
    need(SHA40.fullmatch(revision or "") is not None,
         "Exact 40-hex upstream source SHA is mandatory")
    receipt, record = tx.load(transaction, host)
    need(record["phase"] == "active" and
         not any(row.get("kind") == "cape_source" for row in record["entries"]),
         "Source has already been attempted in this transaction")
    root = safe_root(create=False)
    dest = root / transaction
    staging = root / (".cape-stage-" + transaction)
    need(not dest.exists() and not dest.is_symlink() and
         not staging.exists() and not staging.is_symlink(),
         "Source checkout destination or abandoned staging area exists")
    return {"result": "COMMAND1_PINNED_CAPE_SOURCE_PLAN_ONLY",
            "source": SOURCE, "revision": revision,
            "target": str(dest / "CAPEv2"),
            "host_mutated": False, "upstream_install_script_executed": False,
            "CAPE_services_ready": False,
            "complete_three_command_install": False}


def install(host, transaction, revision):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Source stage requires direct interactive root approval")
    with tx.exclusive_transaction_lock(transaction):
        preview = plan(host, transaction, revision)
        print(json.dumps(preview, indent=2, sort_keys=True), flush=True)
        approval = "STAGE-PINNED-CAPE-SOURCE-" + transaction
        need(input("Type " + approval + ": ").strip() == approval,
             "Pinned CAPE source import declined")
        need(plan(host, transaction, revision) == preview,
             "Source destination changed before approval")
        receipt, ledger = tx.load(transaction, host)
        step = uuid.uuid4().hex
        dest = DEST_ROOT / transaction
        entry = {"id": step, "kind": "cape_source", "stage": "command1",
                 "status": "prepared", "git_source": SOURCE,
                 "revision": revision, "target": str(dest / "CAPEv2"),
                 "staging": str(DEST_ROOT / (".cape-stage-" + transaction)),
                 "before_present": False, "after": None}
        ledger["entries"].append(entry)
        tx.atomic_receipt(receipt, ledger)
        # All source writes happen strictly after durable prepare receipt.
        safe_root(create=True)
        stage = DEST_ROOT / (".cape-stage-" + transaction)
        need(not stage.exists() and not stage.is_symlink(),
             "Transaction already has an abandoned staged checkout")
        stage.mkdir(mode=0o700)
        tx.fsync_dir(DEST_ROOT)
        try:
            execute_git(stage, "init", "-q")
            execute_git(stage, "remote", "add", "origin", SOURCE)
            execute_git(stage, "fetch", "--no-tags", "--depth=1",
                        "origin", revision, timeout=1200)
            execute_git(stage, "checkout", "-q", "--detach", "FETCH_HEAD")
            identity = pristine(stage, revision)
            # Stage becomes CAPEv2 only in its own isolated transaction root.
            dest.mkdir(mode=0o755)
            dest.chmod(0o755)
            tx.fsync_dir(DEST_ROOT)
            final = dest / "CAPEv2"
            need(not final.exists(), "Source checkout target collision")
            os.rename(stage, final)
            final.chmod(0o755)  # Public upstream code; readable by CAPE service.
            tx.fsync_dir(dest)
            need(pristine(final, revision) == identity,
                 "Post-placement Git checkout verification failed")
            entry["after"] = identity
            entry["status"] = "sealed"
            tx.atomic_receipt(receipt, ledger)
            return {"result": "COMMAND1_CAPE_PINNED_SOURCE_STAGED_ONLY",
                    "transaction": transaction, "source_tree": identity,
                    "source_target": str(final),
                    "services_configured": False,
                    "production_ready": False}
        except Exception as err:
            # This stage is never blindly retried: leave exact durable
            # prepared receipt and any partial source tree for investigation.
            raise SourceBlocked(
                "CAPEv2 source import partial or unverified; retain transaction"
            ) from err


def source_entry(doc):
    matching = [row for row in doc["entries"]
                if row.get("kind") == "cape_source"]
    need(len(matching) == 1 and
         matching[0].get("stage") == "command1" and
         matching[0].get("git_source") == SOURCE,
         "Exactly one owned CAPE source record required")
    entry = matching[0]
    need(type(entry.get("id")) is str and
         re.fullmatch(r"[0-9a-f]{32}", entry["id"]),
         "Untrusted source receipt ID")
    need(SHA40.fullmatch(entry.get("revision", "")),
         "Source revision not pinned")
    return entry


def undo_plan(host, transaction):
    receipt, doc = tx.load(transaction, host)
    need(doc["phase"] == "active", "Source recovery needs active transaction")
    entry = source_entry(doc)
    expected = DEST_ROOT / transaction / "CAPEv2"
    quarantine = DEST_ROOT / transaction / (".quarantine-" + entry["id"])
    need(entry["target"] == str(expected),
         "Recorded source differs from owned transaction path")
    if entry["status"] == "rollback_verified":
        need(not expected.exists() and not expected.is_symlink() and
             entry.get("quarantine") == str(quarantine) and
             quarantine.is_dir() and not quarantine.is_symlink() and
             pristine(quarantine, entry["revision"]) == entry["after"],
             "Completed source undo quarantine no longer verified")
        action = "already_quarantined"
    else:
        need(entry["status"] == "sealed" and type(entry.get("after")) is dict,
             "Source step was not successfully sealed")
        need(expected.is_dir() and not expected.is_symlink() and
             not quarantine.exists() and not quarantine.is_symlink(),
             "Source path was modified or quarantine already exists")
        need(pristine(expected, entry["revision"]) == entry["after"],
             "Deployment source has foreign modifications; preserve it")
        action = "quarantine_owned_checkout"
    return {
        "result": "COMMAND1_OWNED_CAPE_SOURCE_UNDO_PLAN",
        "transaction": transaction, "step_id": entry["id"],
        "action": action, "source_path": str(expected),
        "quarantine_path": str(quarantine),
        "target_was_absent_before_deployment": True,
        "no_host_changes": True,
        "manual_disposal_of_quarantined_source_needed": True,
        "whole_deployment_rollback_complete": False,
    }


def undo(host, transaction):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Only direct root operator can undo owned source")
    with tx.exclusive_transaction_lock(transaction):
        before = undo_plan(host, transaction)
        need(before["action"] == "quarantine_owned_checkout",
             "Source is already reversed or uncertain")
        tx.no_live_work()
        print(json.dumps(before, indent=2, sort_keys=True), flush=True)
        phrase = "QUARANTINE-OWNED-CAPE-SOURCE-" + transaction
        need(input("Type " + phrase + ": ").strip() == phrase,
             "Owned CAPE source quarantine declined")
        need(undo_plan(host, transaction) == before,
             "Source changed after operator approval")
        receipt, doc = tx.load(transaction, host)
        entry = source_entry(doc)
        target = Path(before["source_path"])
        quarantine = Path(before["quarantine_path"])
        entry["status"] = "source_rollback_partial"
        tx.atomic_receipt(receipt, doc)
        try:
            os.rename(target, quarantine)
            tx.fsync_dir(target.parent)
            need(pristine(quarantine, entry["revision"]) == entry["after"] and
                 not target.exists() and not target.is_symlink(),
                 "Relocated source did not verify")
            entry["status"] = "rollback_verified"
            entry["quarantine"] = str(quarantine)
            tx.atomic_receipt(receipt, doc)
        except Exception as error:
            raise SourceBlocked(
                "Source undo interrupted; do not retry without reconciliation"
            ) from error
        return {"result": "COMMAND1_OWNED_SOURCE_UNDEPLOYED_QUARANTINED",
                "transaction": transaction,
                "source_was_active": False,
                "quarantined_source_preserved": str(quarantine),
                "whole_deployment_rollback_complete": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",
                   choices=("plan", "install", "plan-undo", "undo"),
                   default="plan")
    p.add_argument("--approved-host", required=True)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--transaction")
    group.add_argument("--use-active-transaction", action="store_true")
    p.add_argument("--revision", required=True)
    args = p.parse_args()
    try:
        target = (tx.active_transaction(args.approved_host)
                  if args.use_active_transaction else args.transaction)
        if args.mode == "plan":
            out = plan(args.approved_host, target, args.revision)
        elif args.mode == "install":
            out = install(args.approved_host, target, args.revision)
        elif args.mode == "plan-undo":
            out = undo_plan(args.approved_host, target)
        else:
            out = undo(args.approved_host, target)
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0
    except (tx.TransactionBlocked, SourceBlocked, OSError, ValueError,
            subprocess.TimeoutExpired, UnicodeError) as err:
        print(json.dumps({"result": "COMMAND1_CAPE_SOURCE_BLOCKED_OR_PARTIAL",
                          "error_type": type(err).__name__,
                          "no_automatic_retries_or_deletion": True,
                          "full_Cape_install_complete": False}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
