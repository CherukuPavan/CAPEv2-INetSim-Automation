#!/usr/bin/env python3
"""Root-private deployment-scoped transaction records for tracked CAPE files.

Never infers ownership from names or pre/post machine inventory. An operator
must begin one transaction before Command 1, prepare each file *before*
mutation and seal its exact post-state. Unknown stages and unsupported
package/VM/TPM/network changes are NEVER automatically rolled back.

This is an incremental, fail-closed foundation, NOT universal deployment undo.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import uuid

ROOT = Path("/var/lib/cape-deployment-transactions")
CONFIG_FILES = frozenset(("api.conf", "auxiliary.conf", "cuckoo.conf",
                          "kvm.conf", "mitmdump.conf", "routing.conf"))
UNIT_FILES = frozenset(("cape.service", "cape-processor.service",
                        "cape-rooter.service", "cape-web.service",
                        "suricata.service"))
SERVICE_STOPS = tuple(sorted(UNIT_FILES))
BLOCKED_HOSTS = frozenset(("ssl-55", "cse-ssl-55", "ssl-46", "cse-ssl-46"))
MAX_FILE = 2 * 1024 * 1024
MAX_RECEIPT = 1024 * 1024
KINDS = frozenset(("file", "package", "cape_runtime",
                   "libvirt_domain", "libvirt_network",
                   "nft_table", "service_state", "account"))
STAGES = frozenset(("command1", "command2", "command3"))


class TransactionBlocked(RuntimeError):
    pass


def need(condition, reason):
    if not condition:
        raise TransactionBlocked(reason)


def host_guard(approved):
    real = socket.gethostname().split(".", 1)[0].lower()
    need(real not in BLOCKED_HOSTS and
         isinstance(approved, str) and
         real == approved.lower() and
         re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", real),
         "Protected or unapproved host")
    return real


def owner_dir(path):
    need(not path.is_symlink() and path.is_dir(),
         "Expected a real private directory")
    st = path.stat()
    need(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o700,
         "Transaction directories must be root:root mode 0700")


def setup_root():
    need(os.geteuid() == 0, "Root is required for transaction creation")
    need(ROOT.is_absolute() and not ROOT.is_symlink() and
         ROOT.parent.is_dir() and ROOT.parent.stat().st_uid == 0 and
         not ROOT.parent.stat().st_mode & 0o022,
         "Unsafe transaction root parent")
    ROOT.mkdir(mode=0o700, exist_ok=True)
    owner_dir(ROOT)


def receipt_path(transaction):
    need(isinstance(transaction, str) and
         re.fullmatch(r"[0-9a-f]{32}", transaction),
         "Expected exact transaction ID")
    setup_root()
    folder = ROOT / transaction
    owner_dir(folder)
    return folder / "ledger.json"


def fsync_dir(folder):
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def global_begin_lock():
    """Serialize first-command transaction allocation on a new host."""
    setup_root()
    path = ROOT / ".active.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
             st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600,
             "Untrusted active deployment lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise TransactionBlocked("Another deployment is starting") from error
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def active_transaction(host):
    """Root-only authenticated current deployment ID; no guessed baseline."""
    host = host_guard(host)
    setup_root()
    marker = ROOT / "active.json"
    need(not marker.is_symlink(), "Active transaction pointer is a symlink")
    fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
             stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and
             0 < st.st_size < 4096, "Untrusted active transaction pointer")
        raw = os.read(fd, 4096)
        need(len(raw) == st.st_size, "Active pointer changed while reading")
    finally:
        os.close(fd)
    data = json.loads(raw)
    need(type(data) is dict and data.get("schema") == 1 and
         data.get("host") == host and
         re.fullmatch(r"[0-9a-f]{32}", data.get("transaction_id", "")),
         "Untrusted active transaction mapping")
    transaction = data["transaction_id"]
    receipt, doc = load(transaction, host)
    need(doc["phase"] == "active", "Active deployment record not usable")
    return transaction


@contextmanager
def exclusive_transaction_lock(transaction):
    """Prevent overlapping root-owned writers from racing on one ledger."""
    path = receipt_path(transaction)
    lock = path.parent / ".transaction.lock"
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
             st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600,
             "Untrusted transaction lock file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise TransactionBlocked("Transaction already has a live writer") from error
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def serialized_transaction(func):
    @wraps(func)
    def locked(transaction, *args, **kwargs):
        with exclusive_transaction_lock(transaction):
            return func(transaction, *args, **kwargs)
    return locked


def atomic_receipt(path, value, new=False):
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    need(len(data) < MAX_RECEIPT, "Oversized ledger")
    if new:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        verified_receipt(path)
        fd, tmp = tempfile.mkstemp(prefix=".ledger-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(), 0o600)
                os.fsync(stream.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.lexists(tmp):
                os.unlink(tmp)
    fsync_dir(path.parent)


def verified_receipt(path):
    need(not path.is_symlink(), "Symlinked ledger")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600 and
             st.st_size < MAX_RECEIPT,
             "Untrusted ledger metadata")
        raw = os.read(fd, MAX_RECEIPT)
        need(len(raw) == st.st_size, "Ledger changed during inspection")
    finally:
        os.close(fd)
    obj = json.loads(raw)
    need(type(obj) is dict and obj.get("schema") == 1 and
         type(obj.get("entries")) is list and
         obj.get("phase") in ("active", "repair_partial",
                               "file_rollback_partial",
                               "rollback_partial", "rolled_back"),
         "Invalid ledger schema")
    return obj


def load(transaction, host):
    actual = host_guard(host)
    path = receipt_path(transaction)
    manifest = verified_receipt(path)
    need(manifest.get("host") == actual and
         manifest.get("transaction_id") == transaction,
         "Ledger bound to different host or transaction")
    return path, manifest


def begin(host):
    host = host_guard(host)
    with global_begin_lock():
        marker = ROOT / "active.json"
        need(not marker.exists() and not marker.is_symlink(),
             "An active or unresolved deployment already exists; no new baseline")
        uid = uuid.uuid4().hex
        folder = ROOT / uid
        folder.mkdir(mode=0o700)
        fsync_dir(ROOT)
        data = {"schema": 1, "transaction_id": uid, "host": host,
                "phase": "active", "entries": [],
                "unsupported_resource_rollback": ["package", "libvirt_domain",
                    "libvirt_network", "nft_table", "service_state", "account"],
                "whole_deployment_rollback_ready": False}
        atomic_receipt(folder / "ledger.json", data, new=True)
        pointer = {"schema": 1, "host": host, "transaction_id": uid}
        # The active pointer is created only after the durable ledger.
        # If interrupted before this write, only an empty orphaned private
        # ledger remains; no host resources have been changed by begin().
        atomic_receipt(marker, pointer, new=True)
    return {"result": "CAPE_TRANSACTION_STARTED",
            "transaction_id": uid, "root_private": True,
            "automatic_cross_command_discovery": True,
            "host_mutations": False}


def allowed_file(path):
    p = Path(path)
    need(p.is_absolute(), "File must be absolute")
    ok = (p.parent == Path("/opt/CAPEv2/conf") and
          p.name in CONFIG_FILES) or (
          p.parent == Path("/etc/systemd/system") and
          p.name in UNIT_FILES)
    need(ok, "File is outside reviewed CAPE configuration/systemd paths")
    for part in (p, *p.parents):
        need(not part.is_symlink(), "Symlinked path or parent")
    need(p.parent.exists() and p.parent.is_dir(),
         "File parent must already exist; no implicit mkdir")
    need(p.parent.stat().st_uid == 0 and
         not p.parent.stat().st_mode & 0o022,
         "File parent must be root-owned and non-writable to nonroot users")
    return p


def observed_file(path):
    p = allowed_file(path)
    if not p.exists():
        return None, None
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             0 <= st.st_size <= MAX_FILE,
             "Untrusted target file")
        raw = os.read(fd, MAX_FILE + 1)
        need(len(raw) == st.st_size, "File changed while hashing")
        state = {"sha256": hashlib.sha256(raw).hexdigest(),
                 "length": len(raw), "mode": stat.S_IMODE(st.st_mode),
                 "uid": st.st_uid, "gid": st.st_gid}
        return raw, state
    finally:
        os.close(fd)


def private_copy(folder, filename, raw):
    owner_dir(folder)
    target = folder / filename
    need(not target.exists() and not target.is_symlink(),
         "Recovery copy already exists")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    fsync_dir(folder)


@serialized_transaction
def prepare_file(transaction, host, stage, path):
    need(stage in STAGES, "Unknown deployment stage")
    file_path = allowed_file(path)
    file_receipt, doc = load(transaction, host)
    need(doc["phase"] == "active", "Cannot add changes to rollback phase")
    need(not any(item["path"] == str(file_path) for item in doc["entries"]
                 if item["kind"] == "file"),
         "File is already recorded; no ambiguous repeated modifications")
    before, before_state = observed_file(file_path)
    uid = uuid.uuid4().hex
    folder = file_receipt.parent
    if before is not None:
        private_copy(folder, "before-" + uid, before)
    entry = {"id": uid, "stage": stage, "kind": "file",
             "path": str(file_path), "status": "prepared",
             "before": before_state, "after": None}
    # Durable record BEFORE a writer is permitted to modify the file.
    doc["entries"].append(entry)
    atomic_receipt(file_receipt, doc)
    return {"result": "CAPE_FILE_BEFORE_STATE_RECORDED", "step_id": uid,
            "before_existed": before is not None, "writer_authorized": True}


@serialized_transaction
def seal_file(transaction, host, step_id):
    need(isinstance(step_id, str) and re.fullmatch(r"[0-9a-f]{32}", step_id),
         "Invalid step ID")
    receipt, doc = load(transaction, host)
    need(doc["phase"] == "active", "Ledger not active")
    matches = [x for x in doc["entries"] if x["id"] == step_id]
    need(len(matches) == 1 and matches[0]["status"] == "prepared",
         "Seal only one prepared step")
    entry = matches[0]
    after, state = observed_file(entry["path"])
    if after is not None:
        private_copy(receipt.parent, "after-" + step_id, after)
    entry["after"] = state
    entry["status"] = "sealed"
    atomic_receipt(receipt, doc)
    return {"result": "CAPE_FILE_POST_STATE_SEALED",
            "step_id": step_id, "after_existed": after is not None}


@serialized_transaction
def record_unsupported(transaction, host, stage, kind, identity):
    """Durably refuse unimplemented mutating resource changes.

    Call BEFORE any package/VM/network/account mutation. This creates a
    blocker that cannot later be disguised as an owned, reversible resource.
    """
    need(stage in STAGES and kind in KINDS - {"file"},
         "Unknown resource stage or kind")
    need(isinstance(identity, str) and
         re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,256}", identity),
         "Untrusted resource identity")
    receipt, doc = load(transaction, host)
    need(doc["phase"] == "active", "Transaction no longer active")
    step = {"id": uuid.uuid4().hex, "kind": kind, "stage": stage,
            "identity": identity, "status": "UNSUPPORTED_NO_MUTATION"}
    doc["entries"].append(step)
    atomic_receipt(receipt, doc)
    return {"result": "CAPE_RESOURCE_UNSUPPORTED_FAIL_CLOSED",
            "kind": kind, "mutation_authorized": False}


def read_backup(folder, item, state):
    need(state is not None, "Missing expected state")
    owner_dir(folder)
    p = folder / item
    need(not p.is_symlink(), "Symlinked private recovery copy")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600 and
             st.st_size == state["length"], "Invalid recovery copy")
        raw = os.read(fd, MAX_FILE + 1)
    finally:
        os.close(fd)
    need(len(raw) == state["length"] and
         hashlib.sha256(raw).hexdigest() == state["sha256"],
         "Recovery copy hash mismatch")
    return raw


def rollback_plan(transaction, host, *, files_only=False):
    receipt, doc = load(transaction, host)
    need(doc["phase"] == "active",
         "Rollback planning refuses partial or completed transactions")
    actions, blocked = [], []
    for entry in reversed(doc["entries"]):
        kind, step_id = entry["kind"], entry["id"]
        if kind == "package" and entry["status"] == "rollback_verified":
            actions.append({"id": step_id, "action": "keep",
                            "already_reversed_by": "tracked_apt_rollback"})
            continue
        if kind == "cape_runtime" and entry["status"] == "rollback_verified":
            # Verify preserved runtime quarantine with its independent
            # receipt before sealing the enclosing deployment as reversed.
            try:
                from command1_cape_runtime_rootless_rollback import inspect as runtime_undo_plan
                witness = runtime_undo_plan(host, transaction)
                need(witness["action"] == "already_quarantined" and
                     witness["step_id"] == step_id,
                     "Owned CAPE Python runtime undo not independently verified")
            except (OSError, ValueError, RuntimeError) as error:
                raise TransactionBlocked("Runtime undo unverifiable") from error
            actions.append({"id":step_id,"action":"keep",
                            "already_reversed_by":"runtime_quarantine"})
            continue
        if kind == "cape_source" and entry["status"] == "rollback_verified":
            # Recheck actual pristine quarantine, not just journal status.
            try:
                from command1_tracked_cape_source import undo_plan as source_undo_plan
                witness = source_undo_plan(host, transaction)
                need(witness["action"] == "already_quarantined" and
                     witness["step_id"] == step_id,
                     "Owned CAPE checkout undo not independently verified")
            except (OSError, ValueError, RuntimeError) as error:
                raise TransactionBlocked("Owned CAPE source undo unverifiable") from error
            actions.append({"id": step_id, "action": "keep",
                            "already_reversed_by": "tracked_cape_source"})
            continue
        if kind == "cape_runtime" and entry["status"] == "sealed" and files_only:
            # File restoration must happen before owned runtime quarantine,
            # and both must finish before source/package rollback.
            actions.append({"id":step_id,"action":"defer_runtime"})
            continue
        if kind == "cape_source" and entry["status"] == "sealed" and files_only:
            actions.append({"id": step_id, "action": "defer_source"})
            continue
        if kind == "package" and entry["status"] == "sealed" and files_only:
            # Release files in reverse deployment order before uninstalling
            # packages. Keep package receipt active for later exact APT undo.
            actions.append({"id": step_id, "action": "defer_package"})
            continue
        if kind == "file" and entry["status"] == "rollback_verified":
            _, current = observed_file(entry["path"])
            action = "keep" if current == entry["before"] else "BLOCKED_DRIFT"
            if action != "keep":
                blocked.append(step_id)
            actions.append({"id": step_id, "path": entry["path"],
                            "action": action})
            continue
        if kind != "file" or entry["status"] != "sealed":
            blocked.append(step_id)
            actions.append({"id": step_id,
                            "action": "BLOCKED_UNOWNED_OR_INCOMPLETE"})
            continue
        before, after = entry["before"], entry["after"]
        _, current = observed_file(entry["path"])
        if current == before:
            action = "keep"
        elif current == after:
            action = "restore_before" if before is not None else "quarantine_created"
        else:
            action = "BLOCKED_DRIFT"
            blocked.append(step_id)
        if action == "restore_before":
            read_backup(receipt.parent, "before-" + step_id, before)
        actions.append({"id": step_id, "path": entry["path"], "action": action})
    return {"result": ("CAPE_DEPLOYMENT_FILE_FIRST_ROLLBACK_PLAN"
                       if files_only else
                       "CAPE_DEPLOYMENT_TRANSACTION_ROLLBACK_PLAN"),
            "transaction_id": transaction, "can_rollback": not blocked,
            "blocked_ids": blocked, "actions": actions,
            "package_rollback_deferred": files_only,
            "all_deployment_resource_types_supported": False,
            "no_changes_performed": True}


@serialized_transaction
def rollback_files_first(transaction, host, approved=False):
    """Reverse tracked files, leaving separately tracked APT in place.

    The transaction remains ACTIVE after successful file restoration.
    Only then may the exact separately guarded APT rollback run.
    """
    need(approved is True and sys.stdin.isatty() and os.geteuid() == 0,
         "File-first rollback requires interactive root")
    receipt, doc = load(transaction, host)
    need(doc["phase"] == "active", "Cannot replay interrupted file undo")
    preview = rollback_plan(transaction, host, files_only=True)
    need(preview["can_rollback"] and
         any(x["kind"] == "file" and x["status"] == "sealed"
             for x in doc["entries"]),
         "Unowned changes or no pending tracked files")
    no_live_work()
    phrase = "ROLLBACK-CAPE-FILES-BEFORE-APT-" + transaction
    need(input("Type " + phrase + ": ").strip() == phrase,
         "File rollback not approved")
    need(rollback_plan(transaction, host, files_only=True) == preview,
         "File rollback targets drifted before consent")
    doc["phase"] = "file_rollback_partial"
    doc["current_step"] = None
    atomic_receipt(receipt, doc)
    completed = []
    try:
        for action in preview["actions"]:
            step = action["id"]
            entry = next(item for item in doc["entries"] if item["id"] == step)
            if entry["kind"] == "package":
                need(action["action"] in ("defer_package", "keep"),
                     "Package state changed during file undo")
                continue
            if entry["kind"] == "cape_source":
                need(action["action"] in ("defer_source", "keep"),
                     "Source state changed during file undo")
                continue
            doc["current_step"] = step
            atomic_receipt(receipt, doc)
            if entry["status"] == "rollback_verified":
                need(action["action"] == "keep", "Tracked file drift")
            elif action["action"] == "keep":
                _, current = observed_file(entry["path"])
                need(current == entry["before"], "File drift on rollback")
            else:
                _, current = observed_file(entry["path"])
                need(current == entry["after"], "File drift on rollback")
                if action["action"] == "restore_before":
                    data = read_backup(receipt.parent, "before-" + step,
                                       entry["before"])
                    restore_original(entry["path"], data, entry["before"])
                elif action["action"] == "quarantine_created":
                    quarantine = receipt.parent / "quarantine"
                    quarantine.mkdir(mode=0o700, exist_ok=True)
                    owner_dir(quarantine)
                    target = quarantine / step
                    need(not target.exists() and not target.is_symlink(),
                         "Quarantine file conflict")
                    os.rename(entry["path"], target)
                    fsync_dir(quarantine)
                    fsync_dir(Path(entry["path"]).parent)
                else:
                    need(False, "Unexpected file rollback action")
            _, verified = observed_file(entry["path"])
            need(verified == entry["before"],
                 "Original file did not return to baseline")
            entry["status"] = "rollback_verified"
            entry["file_rollback_action"] = action["action"]
            completed.append(step)
            doc["completed_steps"] = completed
            doc["current_step"] = None
            atomic_receipt(receipt, doc)
        doc["phase"] = "active"
        doc.pop("completed_steps", None)
        doc.pop("current_step", None)
        atomic_receipt(receipt, doc)
        return {"result": "CAPE_RECORDED_FILES_REVERSED_APT_STILL_PENDING",
                "file_steps": completed,
                "transaction_still_active": True,
                "full_deployment_rollback_ready": False}
    except Exception as error:
        raise TransactionBlocked(
            "Partial file undo retained for manual recovery; no blind retry"
        ) from error


def repair_plan(transaction, host):
    receipt, doc = load(transaction, host)
    need(doc["phase"] == "active",
         "Repair planning refuses partial or rolled back transactions")
    actions, blocked = [], []
    for entry in doc["entries"]:
        step = entry["id"]
        if entry["kind"] != "file" or entry["status"] != "sealed":
            blocked.append(step)
            actions.append({"id": step,
                            "action": "BLOCKED_UNOWNED_OR_INCOMPLETE"})
            continue
        after = entry["after"]
        _, observed = observed_file(entry["path"])
        if observed == after:
            action = "keep"
        elif observed is None and after is not None:
            action = "recreate_from_sealed"
            read_backup(receipt.parent, "after-" + step, after)
        else:
            action = "BLOCKED_DRIFT"
            blocked.append(step)
        actions.append({"id": step, "path": entry["path"], "action": action})
    return {"result": "CAPE_DEPLOYMENT_TRANSACTION_REPAIR_PLAN",
            "transaction_id": transaction, "can_repair": not blocked,
            "blocked_ids": blocked, "actions": actions,
            "all_deployment_resource_types_supported": False,
            "no_changes_performed": True}


@serialized_transaction
def repair(transaction, host, approved=False):
    need(approved is True and sys.stdin.isatty() and os.geteuid() == 0,
         "Repair requires interactive root approval")
    receipt, doc = load(transaction, host)
    need(doc["phase"] == "active", "Unsafe to replay partial repair")
    preview = repair_plan(transaction, host)
    need(preview["can_repair"] and doc["entries"],
         "Unsealed or unsupported resource prevents repair")
    no_live_work()
    phrase = "REPAIR-CAPE-TRANSACTION-" + transaction
    need(input("Type " + phrase + ": ").strip() == phrase,
         "Explicit repair approval declined")
    need(repair_plan(transaction, host) == preview,
         "Repair targets changed after approval")
    doc["phase"] = "repair_partial"
    doc["current_step"] = None
    atomic_receipt(receipt, doc)
    completed = []
    try:
        for action in preview["actions"]:
            step = action["id"]
            entry = next(x for x in doc["entries"] if x["id"] == step)
            doc["current_step"] = step
            atomic_receipt(receipt, doc)
            if entry["kind"] == "package":
                need(action["action"] == "keep" and
                     entry["status"] == "rollback_verified",
                     "Cannot reapply package rollback from file recovery")
            elif action["action"] == "keep":
                pass
            elif action["action"] == "recreate_from_sealed":
                _, observed = observed_file(entry["path"])
                need(observed is None, "File unexpectedly reappeared")
                raw = read_backup(receipt.parent, "after-" + step,
                                  entry["after"])
                restore_original(entry["path"], raw, entry["after"])
                _, restored = observed_file(entry["path"])
                need(restored == entry["after"],
                     "Repair readback mismatch")
            else:
                need(False, "Unexpected repair action")
            completed.append(step)
            doc["completed_steps"] = completed
            doc["current_step"] = None
            atomic_receipt(receipt, doc)
        doc["phase"] = "active"
        doc.pop("completed_steps", None)
        doc.pop("current_step", None)
        atomic_receipt(receipt, doc)
        return {"result": "CAPE_TRACKED_MISSING_FILES_REPAIRED",
                "steps": completed, "whole_deployment_repair_ready": False}
    except Exception as error:
        raise TransactionBlocked("Partial repair retained for manual recovery") from error


def service_inactive_from_systemd(raw):
    """Only exact inactive stopped/missing units admit recovery.

    'systemctl is-active' uses different nonzero codes for inactive versus
    missing. A freshly interrupted installation may legitimately have never
    created a CAPE unit, so read both explicit systemd properties.
    """
    need(type(raw) is str and len(raw) < 1024, "Untrusted systemd response")
    pairs = {}
    for line in raw.strip().splitlines():
        require_pair = line.split("=", 1)
        need(len(require_pair) == 2 and
             require_pair[0] in ("LoadState", "ActiveState") and
             require_pair[0] not in pairs,
             "Unexpected systemd unit state")
        pairs[require_pair[0]] = require_pair[1]
    need(set(pairs) == {"LoadState", "ActiveState"},
         "Incomplete systemd unit state")
    return (pairs["ActiveState"] == "inactive" and
            pairs["LoadState"] in ("loaded", "not-found"))


def no_live_work():
    for unit in SERVICE_STOPS:
        try:
            p = subprocess.run(
                ["systemctl", "show", "--no-pager", "-p", "LoadState",
                 "-p", "ActiveState", unit],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, timeout=8, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise TransactionBlocked("Cannot safely verify CAPE service state") from error
        need(p.returncode == 0 and
             service_inactive_from_systemd(p.stdout),
             "CAPE service is active, failed, masked or state is unknown")
    try:
        p = subprocess.run(["virsh", "-c", "qemu:///system", "list",
                            "--state-running", "--name"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=12)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TransactionBlocked("Cannot inspect running libvirt VMs") from error
    need(p.returncode == 0 and not p.stdout.strip(),
         "Rollback requires no running libvirt domain")


def restore_original(path, raw, state):
    file_path = allowed_file(path)
    fd, name = tempfile.mkstemp(prefix=".cape-rollback-", dir=file_path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), state["mode"])
            os.fchown(stream.fileno(), state["uid"], state["gid"])
            os.fsync(stream.fileno())
        os.replace(name, file_path)
        fsync_dir(file_path.parent)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


@serialized_transaction
def rollback(transaction, host, approved=False):
    need(approved is True and sys.stdin.isatty() and os.geteuid() == 0,
         "Rollback requires interactive root approval")
    receipt, doc = load(transaction, host)
    need(doc["phase"] == "active", "Unsafe to replay partial rollback")
    preview = rollback_plan(transaction, host)
    need(preview["can_rollback"] and doc["entries"],
         "Unsealed, modified or unsupported resource prevents rollback")
    no_live_work()
    expected_phrase = "ROLLBACK-CAPE-TRANSACTION-" + transaction
    need(input("Type " + expected_phrase + ": ").strip() == expected_phrase,
         "Explicit transaction approval declined")
    need(rollback_plan(transaction, host) == preview,
         "Rollback targets changed after approval")
    doc["phase"] = "rollback_partial"
    doc["current_step"] = None
    atomic_receipt(receipt, doc)
    completed = []
    try:
        for action in preview["actions"]:
            step = action["id"]
            entry = next(x for x in doc["entries"] if x["id"] == step)
            doc["current_step"] = step
            atomic_receipt(receipt, doc)
            if action["action"] == "keep":
                pass
            else:
                _, observed = observed_file(entry["path"])
                need(observed == entry["after"], "File drift before rollback")
                if action["action"] == "restore_before":
                    raw = read_backup(receipt.parent, "before-" + step,
                                      entry["before"])
                    restore_original(entry["path"], raw, entry["before"])
                elif action["action"] == "quarantine_created":
                    quarantine = receipt.parent / "quarantine"
                    quarantine.mkdir(mode=0o700, exist_ok=True)
                    owner_dir(quarantine)
                    target = quarantine / step
                    need(not target.exists(), "Quarantine conflict")
                    os.rename(entry["path"], target)
                    fsync_dir(quarantine)
                    fsync_dir(Path(entry["path"]).parent)
                else:
                    need(False, "Unexpected rollback action")
                _, restored = observed_file(entry["path"])
                need(restored == entry["before"], "Rollback readback mismatch")
            completed.append(step)
            doc["completed_steps"] = completed
            doc["current_step"] = None
            atomic_receipt(receipt, doc)
        doc["phase"] = "rolled_back"
        atomic_receipt(receipt, doc)
        return {"result": "CAPE_TRACKED_FILE_CHANGES_ROLLED_BACK",
                "steps": completed, "whole_deployment_rollback_ready": False}
    except Exception as error:
        raise TransactionBlocked("Partial rollback retained for manual recovery") from error


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", required=True,
                   choices=("begin", "current", "prepare-file", "seal-file",
                            "record-unsupported", "plan-repair", "repair",
                            "plan-files-first", "rollback-files-first",
                            "plan-rollback", "rollback"))
    p.add_argument("--approved-host", required=True)
    p.add_argument("--transaction")
    p.add_argument("--stage", choices=sorted(STAGES))
    p.add_argument("--path")
    p.add_argument("--step")
    p.add_argument("--kind", choices=sorted(KINDS - {"file"}))
    p.add_argument("--identity")
    args = p.parse_args()
    try:
        if args.mode == "begin":
            need(args.transaction is None, "Begin must create its own ID")
            output = begin(args.approved_host)
        elif args.mode == "current":
            ident = active_transaction(args.approved_host)
            output = {"result": "CAPE_CURRENT_TRANSACTION_VERIFIED",
                      "transaction_id": ident, "host": args.approved_host}
        else:
            need(args.transaction, "Explicit transaction ID required")
            if args.mode == "prepare-file":
                output = prepare_file(args.transaction, args.approved_host,
                                      args.stage, args.path)
            elif args.mode == "seal-file":
                output = seal_file(args.transaction, args.approved_host, args.step)
            elif args.mode == "record-unsupported":
                output = record_unsupported(args.transaction, args.approved_host,
                                            args.stage, args.kind, args.identity)
            elif args.mode == "plan-repair":
                output = repair_plan(args.transaction, args.approved_host)
            elif args.mode == "repair":
                output = repair(args.transaction, args.approved_host, True)
            elif args.mode == "plan-files-first":
                output = rollback_plan(args.transaction, args.approved_host,
                                       files_only=True)
            elif args.mode == "rollback-files-first":
                output = rollback_files_first(args.transaction, args.approved_host,
                                              True)
            elif args.mode == "plan-rollback":
                output = rollback_plan(args.transaction, args.approved_host)
            else:
                output = rollback(args.transaction, args.approved_host, True)
        print(json.dumps(output, sort_keys=True, indent=2))
        return 0
    except (TransactionBlocked, OSError, KeyError, TypeError, ValueError,
            json.JSONDecodeError) as error:
        print(json.dumps({"result": "CAPE_TRANSACTION_BLOCKED_OR_PARTIAL",
                          "error_type": type(error).__name__,
                          "never_assume_full_rollback": True}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
