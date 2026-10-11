#!/usr/bin/env python3
"""Guarded SSL-55 clone-only cold checkpoint: plan, capture, verify.

DEFAULT PLAN does not write, start/stop VMs, or read a running disk.
CAPTURE requires a fully SHUT OFF exact clone and explicit terminal approval.
It preserves separate QCOW2, UEFI NVRAM and per-clone swtpm state files.
No restore, libvirt snapshot, network mutation, or master changes exist here.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
import uuid
import xml.etree.ElementTree as ET

VM = "win11_1"
UUID = "732b2256-ee99-41fa-881d-fbf5c476d960"
MASTER = ("win11", "289d89be-68ec-4c62-90e1-ea930849266f", "shut off")
TRIAL = ("win11_trial_1", "e75f6fef-347d-462f-9738-4de3df6bfa74", "running")
NETWORK = "cape-analysis-isolated"
DISK = Path("/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2")
NVRAM = Path("/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd")
TPM_DIR = Path("/var/lib/libvirt/swtpm") / UUID / "tpm2"
CHECKPOINTS = Path("/var/lib/libvirt/images/cape-clones-staging/cape-cold-checkpoints")
LOCK = Path("/run/lock/cape-command2-cold-checkpoint.lock")
GIB = 1024 ** 3
RESERVE_GIB = 30
VIRTUAL_GIB = 64
CHUNK = 4 * 1024 * 1024

class Blocked(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Blocked(message)


def cmd(*argv, timeout=120):
    try:
        run = subprocess.run(argv, text=True, capture_output=True,
                             timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked("Host utility not available: " + argv[0]) from exc
    require(run.returncode == 0, "Host utility failed: " + argv[0] +
            " (exit=" + str(run.returncode) + ")")
    return run.stdout.strip()


def virsh(*argv):
    return cmd("virsh", "-c", "qemu:///system", *argv)


def secure_dir(path, root=True):
    require(path.is_dir() and not path.is_symlink(), "Missing/linked directory " + str(path))
    s = path.stat()
    require(not (s.st_mode & 0o022) and (not root or s.st_uid == 0),
            "Unsafe directory permissions: " + str(path))


def file_meta(path, root_owner=False):
    require(path.is_file() and not path.is_symlink(), "Missing/linked file: " + str(path))
    s = path.stat()
    require(stat.S_ISREG(s.st_mode) and not (s.st_mode & 0o022),
            "Unexpected file or writable to other users: " + path.name)
    if root_owner:
        require(s.st_uid == 0 and s.st_mode & 0o077 == 0,
                "Clone artifact is not root/private: " + path.name)
    require(s.st_nlink == 1, "Hardlinked artifact cannot be safely checkpointed: " + path.name)
    return {"size": s.st_size, "mode": stat.S_IMODE(s.st_mode),
            "uid": s.st_uid, "gid": s.st_gid,
            "identity": (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)}


def inspect_domain(name, expected_uuid, state):
    require(virsh("domuuid", name).lower() == expected_uuid,
            "Unexpected libvirt UUID: " + name)
    require(virsh("domstate", name).lower() == state,
            "Unexpected libvirt state: " + name)


def parse_clone_xml(raw):
    root = ET.fromstring(raw)
    require(root.tag == "domain" and root.findtext("name") == VM and
            root.findtext("uuid") == UUID, "Unexpected clone identity")
    disks = root.findall("./devices/disk[@device='disk']")
    require(len(disks) == 1 and disks[0].find("source") is not None and
            disks[0].find("source").get("file") == str(DISK) and
            disks[0].find("driver") is not None and
            disks[0].find("driver").get("type") == "qcow2", "Unexpected clone disk")
    require(root.findtext("./os/nvram") == str(NVRAM), "Unexpected NVRAM")
    tpm = root.findall("./devices/tpm")
    require(len(tpm) == 1 and tpm[0].find("backend") is not None and
            tpm[0].find("backend").get("type") == "emulator" and
            tpm[0].find("backend").get("version") == "2.0", "Unexpected TPM")
    for tag in ("interface", "hostdev", "filesystem", "redirdev", "redirfilter",
                "channel", "shmem", "vsock", "smartcard", "crypto"):
        require(not root.findall("./devices/" + tag), "Forbidden guest device " + tag)
    require(not any(x.tag.endswith("}commandline") for x in root.iter()),
            "Unexpected qemu commandline")
    return raw


def tpm_inventory():
    secure_dir(TPM_DIR.parent, root=False)
    secure_dir(TPM_DIR, root=False)
    names = []
    for path in sorted(TPM_DIR.iterdir()):
        require(not path.is_symlink(), "Unexpected TPM symlink")
        if path.name == ".lock":
            require(path.is_file(), "TPM lock file unexpectedly not regular")
            continue
        require(re.fullmatch(r"[a-zA-Z0-9_.-]+", path.name), "Invalid TPM filename")
        meta = file_meta(path)
        require(meta["size"] > 0 and meta["size"] < 20 * 1024 * 1024,
                "Unexpected TPM file size")
        require(meta["mode"] & 0o077 == 0, "TPM state not private")
        names.append(path)
    require(any(p.name.endswith(".permall") for p in names),
            "Missing TPM permanent state")
    return names


def free_bytes():
    v = os.statvfs(DISK.parent)
    return v.f_bavail * v.f_frsize


def assert_stopped_processes():
    # A shut-off libvirt domain alone does not prove swtpm has exited.
    # Inspect process names/cmdline without disclosing command content.
    proc = Path("/proc")
    require(proc.is_dir(), "Cannot inspect live process directory")
    for directory in proc.iterdir():
        if not directory.name.isdigit():
            continue
        try:
            program = (directory / "comm").read_text().strip().lower()
            if not ("swtpm" in program or "qemu" in program):
                continue
            raw = (directory / "cmdline").read_bytes()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as exc:
            raise Blocked("Cannot check active emulator/TPM processes") from exc
        argstr = raw.decode("utf-8", errors="replace")
        if UUID in argstr or ("qemu" in program and
                             ("guest=" + VM in argstr or "name=" + VM in argstr)):
            raise Blocked("Clone emulator or swtpm process still active")


def guards(mode):
    require(os.geteuid() == 0, "Host root is required (sudo)")
    for name, identity, state in (MASTER, TRIAL):
        inspect_domain(name, identity, state)
    master_xml = ET.fromstring(virsh("dumpxml", "--inactive", MASTER[0]))
    require(master_xml.findtext("uuid") == MASTER[1], "Master XML identity changed")
    master_disk = master_xml.find("./devices/disk[@device='disk']/source")
    require(master_disk is not None and master_disk.get("file") ==
            "/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2",
            "Protected original master disk path changed")
    require(virsh("snapshot-current", MASTER[0], "--name") == "finalshutoffversion",
            "Original master current snapshot changed")
    state = virsh("domstate", VM).lower()
    require(state in (("running", "shut off") if mode == "plan" else ("shut off",)),
            "Exact clone must be shut off for capture (never auto-shutdown)")
    inspect_domain(VM, UUID, state)
    domain = parse_clone_xml(virsh("dumpxml", "--inactive", VM))
    if state == "running":
        parse_clone_xml(virsh("dumpxml", VM))
    trial_xml = ET.fromstring(virsh("dumpxml", TRIAL[0]))
    require(not trial_xml.findall("./devices/interface"), "Trial unexpectedly has NICs")
    info = virsh("net-info", NETWORK)
    require(re.search(r"^Active:\s+no\s*$", info, re.M | re.I) and
            re.search(r"^Autostart:\s+no\s*$", info, re.M | re.I),
            "Analysis network activated or autostarted")
    require(not virsh("snapshot-list", VM, "--name").strip(),
            "Existing clone snapshot: preserve/inspect before checkpoint")
    secure_dir(DISK.parent)
    secure_dir(NVRAM.parent)
    disk = file_meta(DISK, root_owner=True)
    nvram = file_meta(NVRAM, root_owner=True)
    tpm = tpm_inventory()
    need = (VIRTUAL_GIB + RESERVE_GIB) * GIB
    remaining = free_bytes()
    # Metadata-only plan for running disk. The image can change during boot.
    if mode == "capture":
        require(remaining >= need, "Insufficient conservative cold checkpoint space")
        data = json.loads(cmd("qemu-img", "info", "--output=json", str(DISK)))
        require(data.get("format") == "qcow2" and
                data.get("virtual-size") == VIRTUAL_GIB * GIB and
                not data.get("backing-filename") and not data.get("full-backing-filename"),
                "Source is not an independent 64 GiB qcow2")
        cmd("qemu-img", "check", "-q", "-f", "qcow2", str(DISK), timeout=3600)
        assert_stopped_processes()
    return {"status": state, "domain_xml": domain, "disk": disk,
            "nvram": nvram, "tpm": tpm, "free": remaining,
            "conservative_required": need}


def stamp(path):
    return file_meta(path)["identity"]


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as reader:
        while True:
            part = reader.read(CHUNK)
            if not part:
                return digest.hexdigest()
            digest.update(part)


def copy_file(source, dest, *, mode, owner, expected_identity):
    require(not dest.exists() and not dest.is_symlink(), "Destination exists")
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    outfd = None
    try:
        start = os.fstat(source_fd)
        require(stat.S_ISREG(start.st_mode) and
                (start.st_dev, start.st_ino, start.st_size, start.st_mtime_ns,
                 start.st_ctime_ns) == expected_identity,
                "Source changed before copy: " + source.name)
        outfd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                        os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        h = hashlib.sha256()
        with os.fdopen(outfd, "wb", closefd=True) as out, os.fdopen(source_fd, "rb", closefd=False) as src:
            outfd = None
            processed = 0
            while True:
                block = src.read(CHUNK)
                if not block:
                    break
                require(free_bytes() >= RESERVE_GIB * GIB + len(block),
                        "Storage floor reached; preserve incomplete capture")
                out.write(block)
                h.update(block)
                processed += len(block)
                if processed % (256 * 1024 * 1024) < CHUNK:
                    print("COPY_PROGRESS_GIB: " + str(round(processed / GIB, 2)), flush=True)
                    assert_stopped_processes()
                    require(virsh("domstate", VM).lower() == "shut off",
                            "Clone started during checkpoint")
            out.flush()
            os.fsync(out.fileno())
            os.fchmod(out.fileno(), 0o600)
        end = os.fstat(source_fd)
        require((end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns)
                == expected_identity, "Source changed during copy")
        require(processed == start.st_size and sha(dest) == h.hexdigest(),
                "Checkpoint copy integrity mismatch")
        return {"name": dest.name, "size": processed,
                "sha256": h.hexdigest(), "source_uid": owner[0],
                "source_gid": owner[1], "source_mode": format(mode, "04o")}
    finally:
        if outfd is not None:
            os.close(outfd)
        os.close(source_fd)


def plan():
    facts = guards("plan")
    return {"result": "COLD_CHECKPOINT_PLAN_ONLY", "vm": VM,
            "vm_state": facts["status"], "vm_uuid": UUID,
            "nic_count": 0, "master_unchanged_identity_state": True,
            "swtpm_files": [p.name for p in facts["tpm"]],
            "free_gib": round(facts["free"] / GIB, 2),
            "required_conservative_gib": VIRTUAL_GIB + RESERVE_GIB,
            "capacity_estimate_pass": facts["free"] >= facts["conservative_required"],
            "capture_requires_guest_shutdown": True,
            "read_live_qcow2": False,
            "snapshot_or_restore_created": False,
            "no_host_changes": True,
            "next": "Operator full Windows shutdown then separately authorize CAPTURE only"}


def capture():
    # Called only after interactive confirmation; no automatic VM shutdown.
    facts = guards("capture")
    # Single operator lock; no removal of pre-existing unknown lock files.
    require(not LOCK.is_symlink(), "Unsafe checkpoint lock path")
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        facts = guards("capture")
        if CHECKPOINTS.exists() or CHECKPOINTS.is_symlink():
            secure_dir(CHECKPOINTS)
        else:
            # Create ONLY a private directory underneath the clone-owned staging dir.
            CHECKPOINTS.mkdir(mode=0o700)
        ident = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
        partial = CHECKPOINTS / (".incomplete-" + ident)
        final = CHECKPOINTS / ("cold-" + ident)
        partial.mkdir(mode=0o700)
        try:
            files = []
            items = [(DISK, "disk.qcow2", facts["disk"]),
                     (NVRAM, "uefi_VARS.fd", facts["nvram"])]
            for path in facts["tpm"]:
                items.append((path, "swtpm/" + path.name, file_meta(path)))
            (partial / "swtpm").mkdir(mode=0o700)
            for source, name, metadata in items:
                print("CAPTURE_COPY_BEGIN: " + name, flush=True)
                record = copy_file(source, partial / name, mode=metadata["mode"],
                                   owner=(metadata["uid"], metadata["gid"]),
                                   expected_identity=metadata["identity"])
                record["name"] = name  # retain relative swtpm/ path in manifest
                files.append(record)
                print("CAPTURE_COPY_VERIFIED: " + name, flush=True)
            # Final guest state and source metadata gate after slow disk copy.
            require(virsh("domstate", VM).lower() == "shut off", "Clone started during copy")
            assert_stopped_processes()
            for source, _, metadata in items:
                require(stamp(source) == metadata["identity"], "Source mutated during checkpoint")
            require(virsh("dumpxml", "--inactive", VM) == facts["domain_xml"],
                    "Clone XML changed during copy")
            xml_file = partial / "domain.xml"
            xml_file.write_text(facts["domain_xml"], encoding="utf-8")
            xml_file.chmod(0o600)
            files.append({"name": "domain.xml", "size": xml_file.stat().st_size,
                          "sha256": sha(xml_file), "source_uid": 0,
                          "source_gid": 0, "source_mode": "0600"})
            manifest = {"version": 1, "kind": "command2-cold-clone-checkpoint",
                        "vm": VM, "uuid": UUID,
                        "created_utc": datetime.now(timezone.utc).isoformat(),
                        "artifacts": files,
                        "source_clone_shutdown_during_capture": True,
                        "original_master_content_hashes_verified": False,
                        "restore_tested": False, "network_attached": False,
                        "checkpoint_complete_not_restore_certificate": True}
            mf = partial / "manifest.json"
            mf.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            mf.chmod(0o600)
            # Flush directory contents before publishing a checkpoint.
            for directory in (partial / "swtpm", partial):
                dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            require(virsh("domstate", VM).lower() == "shut off", "Clone became active before publish")
            assert_stopped_processes()
            require(not final.exists() and not final.is_symlink(), "Checkpoint name collision")
            partial.rename(final)
            dfd = os.open(CHECKPOINTS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            return {"result": "CLONE_COLD_CHECKPOINT_CAPTURED_UNRESTORED",
                    "checkpoint": str(final), "vm": VM, "uuid": UUID,
                    "artifact_count": len(files),
                    "source_shutdown": True, "restore_tested": False,
                    "analysis_network_changed": False,
                    "original_master_modified": False}
        except Exception:
            # No automatic destructive rollback. Incomplete checkpoint stays private.
            print("INCOMPLETE_CHECKPOINT_RETAINED: " + str(partial), file=sys.stderr)
            raise
    finally:
        os.close(fd)


def verify(backup):
    require(os.geteuid() == 0, "Run with sudo/root")
    require(backup.is_absolute() and backup.parent == CHECKPOINTS and
            re.fullmatch(r"cold-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}", backup.name) and
            backup.is_dir() and not backup.is_symlink(), "Unexpected checkpoint directory")
    secure_dir(backup)
    secure_dir(backup / "swtpm")
    manifest = backup / "manifest.json"
    require(file_meta(manifest, root_owner=True)["size"] < 256 * 1024,
            "Unsafe manifest")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    require(data.get("version") == 1 and data.get("vm") == VM and
            data.get("uuid") == UUID and
            data.get("kind") == "command2-cold-clone-checkpoint",
            "Checkpoint identity mismatch")
    files = data.get("artifacts")
    require(isinstance(files, list) and len(files) >= 4 and len(files) <= 20,
            "Checkpoint file inventory unexpected")
    names = [v.get("name") for v in files if isinstance(v, dict)]
    require(len(names) == len(files) and len(set(names)) == len(names),
            "Duplicate or malformed checkpoint artifact")
    require(all(isinstance(name, str) and (
        name in ("disk.qcow2", "uefi_VARS.fd", "domain.xml") or
        re.fullmatch(r"swtpm/[A-Za-z0-9_.-]+", name)) for name in names),
        "Path traversal in manifest")
    require(set(("disk.qcow2", "uefi_VARS.fd", "domain.xml")) <= set(names) and
            any(name.startswith("swtpm/") and name.endswith(".permall") for name in names),
            "Missing mandatory state in checkpoint")
    results = []
    for record in files:
        loc = backup / record["name"]
        st = file_meta(loc, root_owner=True)
        require(st["size"] == record.get("size") and sha(loc) == record.get("sha256"),
                "Checkpoint artifact checksum mismatch: " + record["name"])
        results.append(record["name"])
    xml = (backup / "domain.xml").read_text(encoding="utf-8")
    parse_clone_xml(xml)
    meta = json.loads(cmd("qemu-img", "info", "--output=json", str(backup / "disk.qcow2")))
    require(meta.get("format") == "qcow2" and
            meta.get("virtual-size") == VIRTUAL_GIB * GIB and
            not meta.get("backing-filename") and not meta.get("full-backing-filename"),
            "Checkpoint qcow2 format/independence mismatch")
    cmd("qemu-img", "check", "-q", "-f", "qcow2", str(backup / "disk.qcow2"), timeout=3600)
    return {"result": "COLD_CHECKPOINT_FILE_INTEGRITY_VERIFIED",
            "vm": VM, "uuid": UUID, "checkpoint": str(backup),
            "verified_files": results, "restore_tested": False,
            "boot_tested_from_checkpoint": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "capture", "verify"), default="plan")
    parser.add_argument("--checkpoint", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.mode == "capture":
            require(sys.stdin.isatty(), "Interactive terminal needed for capture")
            phrase = "CAPTURE-COLD-WIN11-1"
            ack = input("Type " + phrase + " to authorize shutoff clone checkpoint: ")
            require(ack == phrase, "Operator did not authorize checkpoint")
            result = capture()
        elif args.mode == "verify":
            require(args.checkpoint is not None, "--checkpoint required for verification")
            result = verify(args.checkpoint)
        else:
            require(args.checkpoint is None, "Do not supply checkpoint path in plan")
            result = plan()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, ET.ParseError, json.JSONDecodeError,
            BlockingIOError) as error:
        print("BLOCKED: " + str(error), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
