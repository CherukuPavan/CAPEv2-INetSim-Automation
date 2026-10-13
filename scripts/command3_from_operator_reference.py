#!/usr/bin/env python3
"""Command 3 combined CAPE operator-reference workflow (development).

ONE entrypoint for the five supported config edits + strict read-only checks
for routing, tmpfs mount and installed services.

PLAN    : checks all five edit plans, routing review and tmpfs admission
          without modifying any host state (except normal file reads).
CONFIGURE: approved OTHER host, root + direct TTY, all five plans must pass
          before writes, root-private durable per-step witness, then invoke
          each existing guarded apply in operator order. Each helper still
          asks its own exact typed approval and makes its own atomic backup.
          Does not silently alter router/firewall, restart services or VMs.
VERIFY  : reads same config plans, routing/tmpfs admission and the exact five
          systemd units; never claims ready while routing/TPM gates remain.

The user manually finished the seven reference steps on SSL-55; no automated
re-application is permitted there. This is a joined config workflow, NOT a
completed fresh-host Command1, Command2 or malware-ready 3-command release.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import stat
import sys
import uuid

import command3_cape_api_ratelimit as api
import command3_cape_auxiliary as aux
import command3_cape_cuckoo as cuckoo
import command3_cape_kvm as kvm
import command3_cape_mitmdump as mitm
import command3_cape_routing as route
import command3_cape_tmpfs as tmpfs
import command3_cape_services as services

DEFAULT_CONF_DIR = Path("/opt/CAPEv2/conf")
DEFAULT_WITNESSES = Path("/var/lib/cape-command3-receipts")
APPROVAL = "CONFIGURE-CAPE-STEP1-THROUGH-STEP5-NO-RESTART"

class Command3PipelineBlocked(RuntimeError):
    pass

def need(ok, why):
    if not ok:
        raise Command3PipelineBlocked(why)

def approved_host(host):
    actual = socket.gethostname().split(".", 1)[0].lower()
    requested = host.split(".", 1)[0].lower()
    need(actual not in ("ssl-55", "cse-ssl-55") and
         actual == requested and len(actual) >= 2,
         "No automatic Command3 changes on SSL-55 or a different host")
    return actual

def safe_directories(config_dir):
    path = Path(config_dir)
    need(path.is_absolute() and path.name == "conf",
         "Expected absolute CAPE conf directory")
    for segment in (path, *path.parents):
        need(not segment.is_symlink(), "Symlinked CAPE config folder blocked")
    need(path.is_dir(), "Missing CAPE configuration directory")
    return path

def named_configs(directory):
    root = safe_directories(directory)
    return {
        "api": root / "api.conf",
        "auxiliary": root / "auxiliary.conf",
        "cuckoo": root / "cuckoo.conf",
        "kvm": root / "kvm.conf",
        "mitmdump": root / "mitmdump.conf",
        "routing": root / "routing.conf",
    }

def five_plans(args):
    paths = named_configs(args.conf_dir)
    # Every plan must be independently admissible BEFORE first config write;
    # this prevents a five-step partial deployment for known bad inputs.
    results = [
        ("api", api.plan(paths["api"])),
        ("auxiliary", aux.plan(paths["auxiliary"])),
        ("cuckoo", cuckoo.plan(paths["cuckoo"], args.db_dsn_file)),
        ("kvm", kvm.plan(paths["kvm"], args.approved_host, args.journal,
                         args.master_ip, args.master_snapshot, args.tag)),
        ("mitmdump", mitm.plan(paths["mitmdump"])),
    ]
    need([x[0] for x in results] ==
         ["api", "auxiliary", "cuckoo", "kvm", "mitmdump"],
         "Unexpected CAPE configuration stage order")
    return paths, results

def target_tmpfs_ready():
    """Pre-admit the ON-state tmpfs required by Step3, even if now OFF.

    Reading cuckoo.conf [tmpfs] when currently OFF would incorrectly
    skip mount checks. The proposed Step3 target explicitly turns it ON.
    This must be checked before any combined config changes.
    """
    mount = tmpfs.EXPECTED
    need(not mount.is_symlink() and
         not any(p.is_symlink() for p in mount.parents),
         "Target CAPE tmpfs path contains a symlink")
    need(tmpfs.mount_fstype(mount) == "tmpfs",
         "Step3 would enable tmpfs, but /mnt/tmpfs is not actually mounted")
    st = os.stat(mount, follow_symlinks=False)
    uid, gid = tmpfs.cape_ids()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == uid and st.st_gid == gid
         and stat.S_IMODE(st.st_mode) & 0o300 == 0o300,
         "Step3 requires cape-owned writable/traversable tmpfs mount root")
    vfs = os.statvfs(mount)
    free = (vfs.f_bavail * vfs.f_frsize) // (1024 * 1024)
    limit = int(cuckoo.TARGET["tmpfs"]["freespace"])
    need(free >= limit,
         "Step3 requires enough available tmpfs free MiB before file edits")
    return {"status":"TARGET_ON_MOUNT_READY", "mounted_tmpfs":True,
            "cape_ownership":True, "owner_writable":True,
            "free_mib":free,"required_free_mib":limit,
            "host_modified":False}


def review(args, verify=False):
    paths, stages = five_plans(args)
    # Retain the complete user-provided routing target as a traceable
    # PLAN-only report. It is not an authorization to create network egress.
    routing = route.plan(paths["routing"])
    mount = tmpfs.assess(paths["cuckoo"])
    try:
        target_mount = target_tmpfs_ready()
    except (Command3PipelineBlocked, OSError, tmpfs.TmpfsBlocked) as exc:
        target_mount = {
            "status":"TARGET_ON_MOUNT_NOT_READY",
            "error_type":type(exc).__name__, "host_modified":False}
    service = (services.report(paths["routing"], "verify", paths["cuckoo"])
               if verify else None)
    return {
        "result": ("COMMAND3_JOINED_VERIFY_READ_ONLY" if verify
                   else "COMMAND3_JOINED_PLAN_ONLY"),
        "config_stages": [{"name": name, "plan": data}
                          for name, data in stages],
        "pending_changes": [
            name for name, data in stages
            if data.get("status") in ("READY_TO_APPLY",) or
            (name == "api" and data.get("status") == "ONE_SETTING_PENDING") or
            (name == "kvm" and
             data.get("source_sha256") != data.get("target_sha256"))],
        "routing_review": routing,
        "tmpfs_preflight": mount,
        "target_enabled_tmpfs_preflight": target_mount,
        "service_readiness": service,
        "configuration_only_apply_supported": True,
        "routing_auto_apply_supported": False,
        "service_auto_restart_supported": False,
        "host_modified": False,
        "VMs_modified": False,
        "CAPE_READY": False,
    }

def private_witness_dir(directory):
    path = Path(directory)
    need(path.is_absolute(), "Witness directory must be absolute")
    for item in (path, *path.parents):
        need(not item.is_symlink(), "Symlinked witness path not allowed")
    if not path.exists():
        need(path.parent.is_dir() and not path.parent.is_symlink(),
             "Create root-private witness parent separately before use")
        path.mkdir(mode=0o700)
    st = path.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
         stat.S_IMODE(st.st_mode) == 0o700,
         "Witness directory must be root owned, mode 0700")
    return path

def write_witness(path, value, *, first=False):
    """Durable sanitized milestone: atomic replace, 0600, same directory."""
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    need(len(raw) < 512 * 1024, "Refusing oversized witness receipt")
    if first:
        fd = os.open(path, os.O_CREAT | os.O_EXCL |
                     os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
    else:
        prior = path.stat()
        need(stat.S_ISREG(prior.st_mode) and prior.st_uid == 0 and
             stat.S_IMODE(prior.st_mode) == 0o600 and
             prior.st_nlink == 1 and not path.is_symlink(),
             "Untrusted existing witness receipt")
        from tempfile import mkstemp
        fd, tmp = mkstemp(prefix=".command3-witness-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(raw)
                out.flush()
                os.fchmod(out.fileno(), 0o600)
                os.fsync(out.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(d)
    finally:
        os.close(d)

def configure(args):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Configuration batch needs a root interactive terminal")
    approved_host(args.approved_host)
    paths, staged = five_plans(args)
    initial = [(name, dict(plan)) for name, plan in staged]
    # Crucial ordering: Step3 sets [tmpfs] enabled=on. Even if its prior
    # value is OFF, the target mount MUST exist and meet access/capacity
    # requirements before writing any configuration file.
    initial_mount = target_tmpfs_ready()
    # Confirm that we never silently add a routing apply: this script calls
    # only five reviewed config helpers. It can leave routing unchanged.
    other = route.plan(paths["routing"])
    need(other["unsupported_automatic_apply"] is True,
         "Unexpected automatic routing writer: fail closed")
    print(json.dumps({
        "result": "COMMAND3_CONFIG_ONLY_BATCH_APPROVAL",
        "order": [name for name, _ in staged],
        "planned": [{"name": name,
                     "changed": (result.get("source_sha256") !=
                                 result.get("target_sha256")
                                 if name == "kvm" else
                                 result.get("status") not in
                                 ("ALREADY_CONFIGURED",
                                  "NO_CHANGE_ALREADY_CONFIGURED"))}
                    for name, result in staged],
        "routing_will_not_be_modified": True,
        "services_will_not_be_restarted": True,
        "source_sha256s": {name: result.get("source_sha256",
                             result.get("before_sha256"))
                          for name, result in staged},
    }, indent=2, sort_keys=True), flush=True)
    need(input("Type " + APPROVAL + " for guarded five-config batch: ")
         == APPROVAL, "Batch was not approved")
    # Existing independently revalidated plan APIs detect journal/snapshot,
    # guest identity, IP and secret drift before any mutation.
    paths_again, staged_again = five_plans(args)
    need(paths_again == paths and staged_again == initial and
         target_tmpfs_ready() == initial_mount,
         "CAPE plans, VM identities or tmpfs changed before batch approval")
    directory = private_witness_dir(args.witness_dir)
    target = directory / ("command3-config." + uuid.uuid4().hex + ".json")
    witness = {
        "result": "COMMAND3_CONFIG_BATCH_STARTED",
        "host": approved_host(args.approved_host),
        "source_checksums": {name: result.get("source_sha256",
                                 result.get("before_sha256"))
                             for name, result in staged},
        "step_order": [name for name, _ in staged],
        "completed": [],
        "no_service_restart": True,
        "routing_unchanged": True,
        "VMs_unchanged": True,
        "full_command3_complete": False,
    }
    write_witness(target, witness, first=True)
    actions = [
        ("api", lambda: api.apply(paths["api"], args.backup_dir)),
        ("auxiliary", lambda: aux.apply(paths["auxiliary"],
                                       args.backup_dir)),
        ("cuckoo", lambda: cuckoo.apply(paths["cuckoo"],
                                       args.backup_dir, args.db_dsn_file)),
        ("kvm", lambda: kvm.apply(paths["kvm"], args.approved_host,
                                 args.journal, args.master_ip,
                                 args.master_snapshot, args.tag,
                                 args.backup_dir)),
        ("mitmdump", lambda: mitm.apply(paths["mitmdump"],
                                       args.backup_dir)),
    ]
    for name, action in actions:
        witness["current_step"] = name
        write_witness(target, witness)
        try:
            outcome = action()
            need(outcome.get("result") is not None and
                 (outcome.get("applied") is True or
                  outcome.get("applied") is False),
                 "Malformed config helper response at " + name)
            witness["completed"].append({
                "name": name, "result": outcome["result"],
                "applied": outcome["applied"],
                "backup_exists": bool(outcome.get("backup_path")
                                      or outcome.get("backup_created"))})
            witness.pop("current_step", None)
            write_witness(target, witness)
        except Exception as exc:
            witness["result"] = "COMMAND3_CONFIG_BATCH_PARTIAL_OR_UNKNOWN"
            witness["failed_step"] = name
            witness["error_type"] = type(exc).__name__
            # Never persist str(exc) here: exceptions may contain private
            # database strings, filenames or partial connection settings.
            write_witness(target, witness)
            raise Command3PipelineBlocked(
                "PARTIAL_OR_UNKNOWN: failed at " + name +
                "; review root-private witness and helper backup receipts. "
                "No automatic retry or cleanup") from None
    witness["result"] = "COMMAND3_FIVE_CONFIG_FILES_APPLIED_NO_RESTART"
    witness.pop("current_step", None)
    write_witness(target, witness)
    return {
        "result": witness["result"], "witness": str(target),
        "steps": witness["completed"],
        "routing_auto_apply": False, "services_restarted": False,
        "VMs_modified": False,
        "Command3_final_release_complete": False,
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("plan", "configure", "verify"),
                   default="plan")
    p.add_argument("--approved-host", required=True)
    p.add_argument("--journal", required=True, type=Path)
    p.add_argument("--master-ip", required=True)
    p.add_argument("--master-snapshot", required=True)
    p.add_argument("--tag", choices=("win11", "22H2"), default="win11")
    p.add_argument("--conf-dir", type=Path, default=DEFAULT_CONF_DIR)
    p.add_argument("--backup-dir", type=Path, default=api.DEFAULT_BACKUPS)
    p.add_argument("--db-dsn-file", type=Path)
    p.add_argument("--witness-dir", type=Path, default=DEFAULT_WITNESSES)
    args = p.parse_args()
    try:
        result = (review(args) if args.mode == "plan" else
                  review(args, True) if args.mode == "verify" else
                  configure(args))
        print(json.dumps(result, indent=2, sort_keys=True), flush=True)
        return 0
    except Exception as exc:
        # Avoid writing secret-bearing arbitrary exception strings from
        # dependency helpers into public/terminal report.
        print(json.dumps({
            "result": "COMMAND3_BATCH_BLOCKED_OR_PARTIAL",
            "error_type": type(exc).__name__,
            "no_services_restarted": True,
            "no_routing_or_VM_modification": True,
            "review_private_witness_if_configure": True,
        }, sort_keys=True), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
