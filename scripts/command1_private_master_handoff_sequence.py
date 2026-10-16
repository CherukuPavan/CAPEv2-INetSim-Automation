#!/usr/bin/env python3
"""One guarded invocation for authorized PRIVATE golden-master cold handoff.

This is a Command1 SUBSTAGE, not the complete fresh-host installer.
On a separately approved target with prerequisites already installed:
  (1) configure a restricted service-account rclone crypt reader,
  (2) download + SHA-verify the privately encrypted exact cold master,
  (3) stage the byte-verified master QCOW2/OVMF/swtpm into libvirt SHUT OFF.

Every child retains its own root interactive typed consent and performs its
own target checks. A private journal persists BEFORE a child is invoked.
If a child fails, the journal keeps the partial/unknown stage: NEVER retry
blindly, erase key material, change cloud permissions, or revert TPM state.
No VM boot, service restart, untrusted sample or malware network is allowed.
The service-account JSON must already have been securely provisioned; there
is no way to derive it from the public GitHub repository.
"""
from __future__ import annotations

import argparse
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

import command1_worldwide_drive_reader as reader

RECEIPTS = Path("/var/lib/cape-command1-master-handoff")
STAGES = ("restricted_reader", "encrypted_master_download", "cold_master_import")
CHILD = {
    "restricted_reader": "command1_worldwide_drive_reader.py",
    "encrypted_master_download": "command1_private_drive_bundle.py",
    "cold_master_import": "command1_import_existing_master.py",
}
APPROVAL = "RUN-PRIVATE-MASTER-COLD-HANDOFF-NEW-HOST"
# Original SSL46 export and remote-byte-compared crypt upload logs 2026-10-13.
# A SHA256 digest is source provenance, NOT a cloud authentication secret.
REFERENCE_BUNDLE_ID = "cape-master-SSL55-20261013-lan01"
REFERENCE_MANIFEST_SHA256 = (
    "709b67bd2ddbe85ffc957ab34bb97f5c4bc49f7b32b7eff2d08de4588a860d2a"
)


class HandoffBlocked(RuntimeError):
    pass


def need(ok, why):
    if not ok:
        raise HandoffBlocked(why)


def trusted_path(value, label, *, may_not_exist=False):
    p = Path(value)
    need(p.is_absolute() and ".." not in p.parts and
         not any(q.is_symlink() for q in (p, *p.parents)),
         "Untrusted path or symlink: " + label)
    if may_not_exist:
        need(not p.exists(), "Destination already exists: " + label)
        need(p.parent.is_dir() and p.parent.stat().st_uid == 0 and
             not p.parent.stat().st_mode & 0o022,
             "New file parent not protected: " + label)
    return p


def admitted_host(host):
    actual = socket.gethostname().split(".", 1)[0].lower()
    need(type(host) is str and
         re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", host) is not None and
         actual == host and
         actual not in ("cse-ssl-55", "ssl-55", "cse-ssl-46", "ssl-46"),
         "Only an explicitly approved OTHER host")
    return actual


def inputs(args):
    need(os.geteuid() == 0, "Root required for protected golden material")
    admitted_host(args.approved_host)
    credential = reader.verify_inputs(args)
    for tool in ("rclone", "qemu-img", "virsh"):
        import shutil
        need(shutil.which(tool) is not None,
             "Required host tool missing: " + tool)
    for label in ("bundle_destination", "os_disk", "uefi_vars"):
        trusted_path(getattr(args, label), label, may_not_exist=True)
    trusted_path(args.service_account_file, "service_account_file")
    trusted_path(args.config, "restricted_rclone_config",
                 may_not_exist=True)
    trusted_path(args.receipt_dir, "root_private_receipt_dir",
                 may_not_exist=not args.receipt_dir.exists())
    need(len({str(args.service_account_file), str(args.config),
              str(args.bundle_destination), str(args.os_disk),
              str(args.uefi_vars), str(args.receipt_dir)}) == 6,
         "Golden source, private reader, master images and receipts collide")
    need(args.bundle_destination.parent != args.os_disk.parent and
         args.bundle_destination.parent != args.uefi_vars.parent,
         "Master destination must not share artifact source directory")
    need(type(args.swtpm_user) is str and
         re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", args.swtpm_user) is not None,
         "Explicit local swtpm service account required")
    need(type(args.bundle_id) is str and
         re.fullmatch(r"cape-master-[A-Za-z0-9_-]{4,72}", args.bundle_id)
         is not None,
         "Exact approved master bundle ID required")
    need(args.bundle_destination.name == args.bundle_id,
         "Local golden bundle directory must match exact encrypted remote bundle ID")
    return {
        "result": "COMMAND1_PRIVATE_MASTER_HANDOFF_PREFLIGHT",
        "approved_host": args.approved_host,
        "service_account_scope_planned": "restricted_read_only",
        "service_account_identity": credential[
            "service_account_email_to_share_with_as_viewer"],
        "bundle_id": args.bundle_id,
        "stages": list(STAGES),
        "source_repo_is_not_master_image": True,
        "running_snapshot_not_created": True,
        "swtpm_running_revert_not_proven": True,
        "CAPE_ready": False,
        "host_modified": False,
    }


def child_argv(args, stage):
    need(stage in STAGES, "Unreviewed master handoff stage")
    program = Path(__file__).resolve().with_name(CHILD[stage])
    need(program.is_file() and not program.is_symlink(),
         "Pinned handoff helper missing")
    common = ["--approved-host", args.approved_host]
    if stage == "restricted_reader":
        extra = ["--mode", "setup",
                 "--service-account-file", str(args.service_account_file),
                 "--shared-parent-folder-id", args.shared_parent_folder_id,
                 "--crypt-subfolder", args.crypt_subfolder,
                 "--config", str(args.config)]
    elif stage == "encrypted_master_download":
        extra = ["--mode", "download",
                 "--destination", str(args.bundle_destination),
                 "--crypt-remote", "cape_crypt",
                 "--bundle-id", args.bundle_id,
                 "--rclone-config", str(args.config)]
        if args.bundle_id == REFERENCE_BUNDLE_ID:
            # Refuse a byte-consistent but substituted master source.
            extra.extend(["--expected-manifest-sha256",
                          REFERENCE_MANIFEST_SHA256])
    else:
        extra = ["--mode", "stage",
                 "--bundle", str(args.bundle_destination),
                 "--os-disk", str(args.os_disk),
                 "--uefi-vars", str(args.uefi_vars),
                 "--swtpm-user", args.swtpm_user]
    return [sys.executable, "-B", str(program), *common, *extra]


def private_receipt_dir(path):
    p = trusted_path(path, "receipt_dir")
    need(p.parent.is_dir() and p.parent.stat().st_uid == 0 and
         not p.parent.stat().st_mode & 0o022,
         "Root-only receipt parent required")
    if not p.exists():
        p.mkdir(mode=0o700)
    st = p.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
         stat.S_IMODE(st.st_mode) == 0o700,
         "Root-owned 0700 handoff receipt directory required")
    return p


def durable_receipt(target, doc, *, first=False):
    raw = (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode()
    need(len(raw) <= 32768, "Oversized handoff record")
    if first:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            raise
    else:
        old = target.lstat()
        need(stat.S_ISREG(old.st_mode) and old.st_uid == 0 and
             old.st_nlink == 1 and stat.S_IMODE(old.st_mode) == 0o600,
             "Unknown or replaced handoff receipt")
        fd, name = tempfile.mkstemp(prefix=".master-handoff-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fchmod(stream.fileno(), 0o600)
                os.fsync(stream.fileno())
            os.replace(name, target)
        finally:
            if os.path.lexists(name):
                os.unlink(name)
    d = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(d)
    finally:
        os.close(d)


def invoke(argv):
    need(Path(argv[2]).name in set(CHILD.values()),
         "Unexpected subprocess target")
    try:
        return subprocess.run(argv, check=False, timeout=24 * 3600).returncode
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HandoffBlocked(
            "Child exited uncertainly; review journal and host state") from error


def execute(args):
    need(sys.stdin.isatty(), "Interactive root TTY required")
    before = inputs(args)
    print(json.dumps(before, sort_keys=True, indent=2), flush=True)
    need(input("Type " + APPROVAL + ": ").strip() == APPROVAL,
         "Operator declined private golden handoff")
    need(inputs(args) == before,
         "Golden handoff preconditions changed after approval")
    root = private_receipt_dir(args.receipt_dir)
    target = root / ("master-handoff-" + uuid.uuid4().hex + ".json")
    doc = {
        "schema": 1, "host": args.approved_host,
        "phase": "started", "current_stage": None,
        "finished": [], "bundle_id": args.bundle_id,
        "private_reader_config": str(args.config),
        "source_bundle_destination": str(args.bundle_destination),
        "master_disk": str(args.os_disk),
        "master_uefi": str(args.uefi_vars),
        "no_windows_guest_booted": True,
        "no_swtpm_checkpoint_consistency_claim": True,
        "not_a_complete_command1": True,
    }
    durable_receipt(target, doc, first=True)
    for stage in STAGES:
        doc["current_stage"] = stage
        durable_receipt(target, doc)
        try:
            code = invoke(child_argv(args, stage))
        except Exception:
            code = -1
        if code != 0:
            doc["phase"] = "partial_or_unknown"
            doc["last_exit_code"] = code
            durable_receipt(target, doc)
            raise HandoffBlocked(
                "Partial private handoff. Preserve receipt, master storage, "
                "swtpm and credential files; DO NOT blindly retry")
        doc["finished"].append(stage)
        doc["current_stage"] = None
        durable_receipt(target, doc)
    doc["phase"] = "cold_master_staged_not_booted"
    durable_receipt(target, doc)
    return {
        "result": "COMMAND1_VERIFIED_PRIVATE_COLD_MASTER_STAGED_ONLY",
        "receipt": str(target),
        "completed_stages": list(STAGES),
        "master_imported_shut_off": True,
        "guest_started": False,
        "TPM_coherent_running_snapshot_verified": False,
        "CAPE_ready": False,
        "complete_command1": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("plan", "run"), default="plan")
    p.add_argument("--approved-host", required=True)
    p.add_argument("--service-account-file", type=Path, required=True)
    p.add_argument("--shared-parent-folder-id", required=True)
    p.add_argument("--crypt-subfolder", default="master-backups")
    p.add_argument("--config", type=Path, default=reader.DEFAULT_CONFIG)
    p.add_argument("--bundle-id", required=True)
    p.add_argument("--bundle-destination", type=Path, required=True)
    p.add_argument("--os-disk", type=Path, required=True)
    p.add_argument("--uefi-vars", type=Path, required=True)
    p.add_argument("--swtpm-user", required=True)
    p.add_argument("--receipt-dir", type=Path, default=RECEIPTS)
    args = p.parse_args()
    try:
        response = inputs(args) if args.mode == "plan" else execute(args)
        print(json.dumps(response, sort_keys=True, indent=2))
        return 0
    except (HandoffBlocked, reader.ReaderBlocked, OSError,
            ValueError, TypeError) as error:
        print(json.dumps({
            "result": "COMMAND1_PRIVATE_HANDOFF_BLOCKED_OR_PARTIAL",
            "error_type": type(error).__name__,
            "never_auto_delete_secrets_or_master_bytes": True,
            "complete_command1": False,
        }), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
