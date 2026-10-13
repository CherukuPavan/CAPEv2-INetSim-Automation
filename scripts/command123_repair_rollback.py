#!/usr/bin/env python3
"""Guarded NEW-HOST configuration recovery. NO VM, package or network removal.

baseline : BEFORE deployment, record exact original CAPE config file bytes.
seal     : AFTER controlled deployment, record the desired CAPE config bytes.
plan     : check drift, missing files, immutable SHA proofs, and blockers.
repair   : create ONLY missing sealed config files, never overwrite edits.
rollback : restore original tracked config files if unchanged since sealing;
           move newly created files into a root-only quarantine, not delete.

This is NOT a whole-host rollback or full CAPE self-healer. It refuses live
guests and active CAPE units before changing files. A clean VM-host filesystem
snapshot (before installation) or host reimage is required for a genuine
whole-system rollback. Never run on protected CSE-SSL-55/46.
"""
from __future__ import annotations

import argparse
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

ROOT = Path("/var/lib/cape-deployment-recovery")
CONF = Path("/opt/CAPEv2/conf")
NAMES = ("api.conf", "auxiliary.conf", "cuckoo.conf", "kvm.conf",
         "mitmdump.conf", "routing.conf")
MAX_CONF = 2 * 1024 * 1024
APPROVALS = {
    "baseline": "CAPTURE-NEW-HOST-PREDEPLOYMENT-BASELINE",
    "seal": "SEAL-DEPLOYED-CAPE-CONFIG-REFERENCE",
    "repair": "REPAIR-ONLY-MISSING-SEALED-CAPE-CONFIGS",
    "rollback": "ROLLBACK-ONLY-ATTESTED-CAPE-CONFIGS",
}
PROTECTED = frozenset(("ssl-55", "cse-ssl-55", "ssl-46", "cse-ssl-46"))
UNIT_NAMES = ("cape.service", "cape-processor.service", "cape-rooter.service",
              "cape-web.service", "suricata.service")
MANIFEST = "manifest.json"


class RecoveryBlocked(RuntimeError):
    pass


def require(test, reason):
    if not test:
        raise RecoveryBlocked(reason)


def current_host(approved):
    real = socket.gethostname().split(".", 1)[0].lower()
    require(real not in PROTECTED and real == approved.lower().split(".", 1)[0]
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", real) is not None,
            "Protected or incorrectly approved host")
    return real


def guard_file_path(path):
    path = Path(path)
    require(path in tuple(CONF / name for name in NAMES),
            "Only six exact CAPE configuration paths are authorized")
    require(not any(part.is_symlink() for part in (path, *path.parents)),
            "Symlinked path or parent blocked")
    require(CONF.is_dir() and not CONF.is_symlink(),
            "Expected existing CAPE conf directory")
    st = CONF.stat()
    require(stat.S_ISDIR(st.st_mode) and not st.st_mode & 0o022,
            "CAPE conf parent is group/world writable")
    return path


def snapshot_file(path):
    path = guard_file_path(path)
    if not path.exists():
        return None, None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                0 <= st.st_size <= MAX_CONF,
                "Unrecognized CAPE conf file type, links or size")
        data = os.read(fd, MAX_CONF + 1)
        require(len(data) == st.st_size, "CAPE conf changed during inspection")
        meta = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data), "uid": st.st_uid, "gid": st.st_gid,
            "mode": stat.S_IMODE(st.st_mode),
        }
        return data, meta
    finally:
        os.close(fd)


def private_folder(path):
    require(path.is_absolute() and not any(
        p.is_symlink() for p in (path, *path.parents)),
        "Private recovery folder cannot be symlinked")
    s = path.stat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and
            stat.S_IMODE(s.st_mode) == 0o700,
            "Recovery folder must be owned root and mode 0700")
    return path


def ensure_root():
    require(os.geteuid() == 0, "Recovery snapshots require root")
    require(ROOT.parent.is_dir() and ROOT.parent.stat().st_uid == 0
            and not ROOT.parent.stat().st_mode & 0o022,
            "Recovery parent must be root-owned and not writable by users")
    require(not ROOT.is_symlink(), "Recovery root symlink denied")
    ROOT.mkdir(mode=0o700, exist_ok=True)
    private_folder(ROOT)


def write_once(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def replace_manifest(path, data):
    encoded = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()
    require(len(encoded) < 65536, "Recovery manifest unexpectedly large")
    fd, tmp = tempfile.mkstemp(prefix=".cape-recovery-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(encoded)
            f.flush()
            os.fchmod(f.fileno(), 0o600)
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_manifest(receipt, approved):
    require(receipt is not None and receipt.name == MANIFEST and
            receipt.parent.parent == ROOT and
            re.fullmatch(r"[0-9a-f]{32}", receipt.parent.name) is not None,
            "Expected exact /var/lib/cape-deployment-recovery/UUID/manifest.json")
    private_folder(ROOT)
    private_folder(receipt.parent)
    require(not receipt.is_symlink() and receipt.is_file(),
            "Missing or symlinked recovery manifest")
    st = receipt.stat()
    require(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600 and
            st.st_nlink == 1 and st.st_size < 65536,
            "Recovery manifest must be root-only, singly linked")
    data = json.loads(receipt.read_text())
    require(type(data) is dict and data.get("schema") == 1 and
            data.get("host") == current_host(approved) and
            data.get("files") is not None and
            set(data["files"]) == set(NAMES),
            "Recovery record does not match exact host/config schema")
    require(data.get("phase") in ("baseline", "sealed", "partial"),
            "Recovery phase invalid")
    return data


def copy_to_store(folder, name, state, blob):
    if blob is None:
        return
    private_folder(folder)
    write_once(folder / name, blob)
    check = (folder / name).read_bytes()
    require(hashlib.sha256(check).hexdigest() == state["sha256"],
            "Written private recovery copy failed SHA check")


def checked_blob(folder, name, expected):
    require(expected is not None, "No expected snapshot for this file")
    private_folder(folder)
    candidate = folder / name
    require(not candidate.is_symlink(), "Symlinked recovery blob denied")
    st = candidate.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
            stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1,
            "Recovery blob not root-private")
    content = candidate.read_bytes()
    require(len(content) == expected["size"] and
            hashlib.sha256(content).hexdigest() == expected["sha256"],
            "Recovery snapshot hash mismatch")
    return content


def phase_snapshot(directory, phase):
    private_folder(directory)
    dest = directory / phase
    dest.mkdir(mode=0o700)
    private_folder(dest)
    result = {}
    for name in NAMES:
        blob, state = snapshot_file(CONF / name)
        result[name] = state
        copy_to_store(dest, name, state, blob)
    return result


def approve(mode):
    require(sys.stdin.isatty(), "Interactive terminal approval required")
    phrase = APPROVALS[mode]
    require(input("Type " + phrase + " to proceed: ").strip() == phrase,
            "Recovery change declined")


def baseline(approved):
    current_host(approved)
    require(CONF.is_dir(), "Create CAPE conf folder through approved installer first")
    ensure_root()
    print(json.dumps({"mode": "baseline",
                      "captures_root_private_config_copies": list(NAMES),
                      "VM_package_network_changes": False}, indent=2))
    approve("baseline")
    directory = ROOT / uuid.uuid4().hex
    directory.mkdir(mode=0o700)
    try:
        initial = phase_snapshot(directory, "before")
        doc = {"schema": 1, "host": current_host(approved),
               "phase": "baseline",
               "files": {name: {"before": initial[name], "after": None}
                         for name in NAMES},
               "VM_package_network_rollback_supported": False}
        write_once(directory / MANIFEST,
                   (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode())
        return {"result": "CAPE_BASELINE_CAPTURED",
                "receipt": str(directory / MANIFEST),
                "files_tracked": len(NAMES), "no_host_configs_modified": True}
    except Exception:
        # Preserve any partial private copies for operator examination.
        raise RecoveryBlocked("Partial private baseline retained; do not reuse it") from None


def seal(receipt, approved):
    doc = read_manifest(receipt, approved)
    require(doc["phase"] == "baseline",
            "Sealing requires exact, previously unsealed baseline")
    approve("seal")
    after = phase_snapshot(receipt.parent, "after")
    for name in NAMES:
        doc["files"][name]["after"] = after[name]
    doc["phase"] = "sealed"
    replace_manifest(receipt, doc)
    return {"result": "CAPE_POSTDEPLOY_CONFIG_SEALED",
            "receipt": str(receipt), "changes_recorded": True,
            "not_a_VMs_or_packages_ownership_proof": True}


def state_plan(receipt, approved, mode):
    doc = read_manifest(receipt, approved)
    require(doc["phase"] in ("sealed", "partial"),
            "Baseline must be SEALED before repair/rollback inspection")
    actions = []
    blocked = []
    for name in NAMES:
        _, now = snapshot_file(CONF / name)
        origin = doc["files"][name]["before"]
        sealed = doc["files"][name]["after"]
        if mode == "repair":
            if now == sealed:
                change = "keep"
            elif now is None and sealed is not None:
                change = "recreate_from_sealed"
            else:
                change = "BLOCKED_UNRECOGNIZED_DRIFT"
        else:
            if now == origin:
                change = "keep"
            elif now == sealed:
                if origin is None and sealed is not None:
                    change = "quarantine_new_config"
                elif origin is not None:
                    change = "restore_before"
                else:
                    change = "keep"
            elif now is None and sealed is None and origin is not None:
                change = "restore_before"
            else:
                change = "BLOCKED_UNRECOGNIZED_DRIFT"
        if change.startswith("BLOCKED"):
            blocked.append(name)
        actions.append({"config": name, "action": change})
    return {"result": "CAPE_" + mode.upper() + "_READ_ONLY_PLAN",
            "receipt": str(receipt), "actions": actions,
            "blocked": blocked, "can_apply": not blocked,
            "whole_host_recovery_supported": False,
            "no_VM_package_network_or_TPM_changes": True}


def no_live_workloads():
    """Never mutate CAPE settings while analysis services/VMs are running."""
    for unit in UNIT_NAMES:
        try:
            p = subprocess.run(["systemctl", "is-active", "--quiet", unit],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise RecoveryBlocked("Cannot confirm services are stopped") from e
        require(p.returncode in (3, 4), "CAPE/Suricata service active or unknown: " + unit)
    try:
        p = subprocess.run(["virsh", "-c", "qemu:///system",
                            "list", "--state-running", "--uuid"],
                           capture_output=True, text=True, timeout=12)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RecoveryBlocked("Cannot confirm libvirt guests are stopped") from e
    require(p.returncode == 0 and not p.stdout.strip(),
            "Running libvirt guests or libvirt status unavailable")


def atomically_restore(target, blob, meta, *, missing_only):
    target = guard_file_path(target)
    if missing_only:
        require(not target.exists(), "Refuse to overwrite an existing config")
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(blob)
            out.flush()
            os.fchown(out.fileno(), meta["uid"], meta["gid"])
            os.fchmod(out.fileno(), meta["mode"])
            os.fsync(out.fileno())
        return
    fd, tmp = tempfile.mkstemp(prefix=".cape-restore-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(blob)
            out.flush()
            os.fchown(out.fileno(), meta["uid"], meta["gid"])
            os.fchmod(out.fileno(), meta["mode"])
            os.fsync(out.fileno())
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def apply(receipt, approved, mode):
    require(mode in ("repair", "rollback"), "Unsupported recovery mode")
    doc = read_manifest(receipt, approved)
    require(doc["phase"] == "sealed", "Partial recovery requires manual review")
    first = state_plan(receipt, approved, mode)
    require(first["can_apply"], "Configuration drift not owned by sealed deployment")
    no_live_workloads()
    print(json.dumps(first, sort_keys=True, indent=2), flush=True)
    approve(mode)
    require(state_plan(receipt, approved, mode) == first,
            "Config state drifted after approval")
    no_live_workloads()
    # Durable fail-closed witness: no blind retry even after first mutation.
    doc["phase"] = "partial"
    doc["current_recovery"] = mode
    doc["completed_recovery_steps"] = []
    replace_manifest(receipt, doc)
    try:
        quarantine = receipt.parent / "quarantine"
        steps = []
        for action in first["actions"]:
            name, choice = action["config"], action["action"]
            if choice == "keep":
                continue
            now, observed = snapshot_file(CONF / name)
            wanted = doc["files"][name]["after"]
            require(observed == wanted or
                    (observed is None and choice in
                     ("recreate_from_sealed", "restore_before")),
                    "Config changed after preflight; stop")
            if choice == "recreate_from_sealed":
                blob = checked_blob(receipt.parent / "after", name, wanted)
                atomically_restore(CONF / name, blob, wanted, missing_only=True)
            elif choice == "restore_before":
                original = doc["files"][name]["before"]
                blob = checked_blob(receipt.parent / "before", name, original)
                atomically_restore(CONF / name, blob, original,
                                   missing_only=observed is None)
            elif choice == "quarantine_new_config":
                if not quarantine.exists():
                    quarantine.mkdir(mode=0o700)
                private_folder(quarantine)
                require(not (quarantine / name).exists(),
                        "Quarantine file already exists")
                os.rename(CONF / name, quarantine / name)
            else:
                require(False, "Unexpected action")
            steps.append(name)
            doc["completed_recovery_steps"] = steps
            replace_manifest(receipt, doc)
        doc["phase"] = "sealed"
        doc.pop("current_recovery", None)
        doc.pop("completed_recovery_steps", None)
        replace_manifest(receipt, doc)
        return {"result": "CAPE_" + mode.upper() + "_TRACKED_CONFIGS_DONE",
                "changed_configs": steps,
                "VM_package_network_TPM_rollback_not_performed": True,
                "restart_or_reload_not_performed": True}
    except Exception:
        raise RecoveryBlocked(
            "PARTIAL recovery: preserved receipt and copies; "
            "STOP, manually inspect before any retry") from None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", required=True,
                   choices=("baseline", "seal", "plan-repair",
                            "plan-rollback", "repair", "rollback"))
    p.add_argument("--approved-host", required=True)
    p.add_argument("--receipt", type=Path)
    a = p.parse_args()
    try:
        require(os.geteuid() == 0,
                "Run as root; original configs may contain database secrets")
        current_host(a.approved_host)
        if a.mode == "baseline":
            require(a.receipt is None, "Baseline creates its OWN new receipt")
            result = baseline(a.approved_host)
        else:
            require(a.receipt is not None, "Explicit baseline receipt required")
            ensure_root()
            if a.mode == "seal":
                result = seal(a.receipt, a.approved_host)
            elif a.mode.startswith("plan-"):
                result = state_plan(a.receipt, a.approved_host,
                                    a.mode.removeprefix("plan-"))
            else:
                result = apply(a.receipt, a.approved_host, a.mode)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except Exception as e:
        print(json.dumps({"result": "CAPE_CONFIG_RECOVERY_BLOCKED_OR_PARTIAL",
                          "error_type": type(e).__name__,
                          "no_automatic_retry_or_deletion": True,
                          "full_host_rollback_not_claimed": True}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
