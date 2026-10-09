#!/usr/bin/env python3
"""Guard external-QCOW2 snapshot access without weakening host-wide AppArmor.

Modes: plan (default, read-only), apply (explicit), verify (read-only).
Does not start guests, alter QCOW2 files or change network policy.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import subprocess
import sys
import uuid as uuidlib
import xml.etree.ElementTree as ET

ABSTRACTION = Path("/etc/apparmor.d/abstractions/libvirt-qemu")
RULEDIR = Path("/etc/apparmor.d/abstractions/libvirt-qemu.d")
PROFILEDIR = Path("/etc/apparmor.d/libvirt")
LOCKFILE = Path("/run/cape-qcow2-apparmor-guard.lock")
INCLUDE = re.compile(r"^\s*(?:#include|include)\s+if\s+exists\s+<abstractions/libvirt-qemu\.d>\s*$", re.M)
SAFE_PATH = re.compile(r"/[A-Za-z0-9_./+@-]{1,4095}\Z")
SAFE_VM = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")


class GuardError(RuntimeError):
    pass


def run(*args: str) -> str:
    try:
        result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=45)
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
        raise GuardError(f"Command {args[0]} failed: {detail}") from exc


def check_path(path: str) -> Path:
    if not SAFE_PATH.fullmatch(path):
        raise GuardError(f"Unsupported image path characters: {path!r}")
    p = Path(path)
    if str(p) != os.path.normpath(path):
        raise GuardError(f"Image path must be normalized: {path}")
    for ancestor in (p, *p.parents):
        if ancestor.is_symlink():
            raise GuardError(f"Refusing symlink in image path: {ancestor}")
    try:
        mode = p.stat().st_mode
    except OSError as exc:
        raise GuardError(f"Cannot stat image: {p}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise GuardError(f"Not a regular disk image: {p}")
    return p


def validate_chain(top: str, records: object) -> list[str]:
    """Validate ordering, safe paths and QCOW2 back-references; return top -> base."""
    if not isinstance(records, list) or not 2 <= len(records) <= 16:
        raise GuardError("Expected an external snapshot chain with 2–16 QCOW2 layers")
    names: list[str] = []
    for record in records:
        if not isinstance(record, dict) or record.get("format") != "qcow2":
            raise GuardError("Non-QCOW2 or malformed backing-chain entry")
        name = record.get("filename")
        if not isinstance(name, str) or not SAFE_PATH.fullmatch(name):
            raise GuardError(f"Unsafe or missing chain filename: {name!r}")
        if name in names:
            raise GuardError("Cyclic or duplicated backing-image path")
        names.append(name)
    if names[0] != top:
        raise GuardError(f"Active disk {top} differs from first image {names[0]}")
    for index, record in enumerate(records):
        back = record.get("full-backing-filename") or record.get("backing-filename")
        if index == len(records) - 1:
            if back:
                raise GuardError("Incomplete chain: oldest image still has a backing file")
            continue
        if not isinstance(back, str):
            raise GuardError("Incomplete chain: missing backing-file reference")
        expected = os.path.normpath(back if back.startswith("/") else os.path.join(os.path.dirname(names[index]), back))
        if expected != names[index + 1]:
            raise GuardError(f"Backing-chain mismatch at {names[index]}")
    return names


def policy_text(backings: list[str]) -> str:
    if not backings:
        raise GuardError("No backing images detected")
    for path in backings:
        if not SAFE_PATH.fullmatch(path):
            raise GuardError(f"Cannot encode unsafe AppArmor path: {path!r}")
    return "# CAPEv2 explicit QCOW2 snapshot backing images; read and lock ONLY.\n" + "".join(
        f'"{path}" rk,\n' for path in backings
    )


def discover(vm: str) -> tuple[str, list[str]]:
    if not SAFE_VM.fullmatch(vm):
        raise GuardError("Invalid libvirt VM name")
    if run("virsh", "-c", "qemu:///system", "domstate", vm).strip() != "shut off":
        raise GuardError(f"VM {vm} must be shut off; no live-disk or active-policy mutations")
    xml = ET.fromstring(run("virsh", "-c", "qemu:///system", "dumpxml", "--inactive", vm))
    disks = xml.findall("./devices/disk[@device='disk']")
    if len(disks) != 1:
        raise GuardError("Expected exactly one disk; multi-disk VMs need separate review")
    disk = disks[0]
    src = disk.find("source")
    driver = disk.find("driver")
    if disk.get("type") != "file" or src is None or not src.get("file"):
        raise GuardError("Only file-backed libvirt disks are supported")
    if driver is None or driver.get("type") != "qcow2":
        raise GuardError("Expected a QCOW2 libvirt disk")
    top = str(check_path(src.get("file")))
    uuid = run("virsh", "-c", "qemu:///system", "domuuid", vm).strip()
    try:
        uuid = str(uuidlib.UUID(uuid))
    except ValueError as exc:
        raise GuardError("Invalid libvirt VM UUID") from exc
    records = json.loads(run("qemu-img", "info", "--output=json", "--backing-chain", top))
    images = validate_chain(top, records)
    for name in images:
        check_path(name)
    return uuid, images


def ensure_supported() -> None:
    try:
        if Path("/sys/module/apparmor/parameters/enabled").read_text().strip() != "Y":
            raise GuardError("AppArmor is not enabled; cannot use this guard")
        if ABSTRACTION.is_symlink() or not ABSTRACTION.is_file():
            raise GuardError("Libvirt QEMU abstraction is missing or symlinked")
        if not INCLUDE.search(ABSTRACTION.read_text()):
            raise GuardError("This host lacks the verified libvirt-qemu.d include")
        if RULEDIR.is_symlink() or (RULEDIR.exists() and not RULEDIR.is_dir()):
            raise GuardError("AppArmor override directory is unsafe")
        if RULEDIR.exists():
            directory_stat = RULEDIR.stat()
            if directory_stat.st_uid != 0 or directory_stat.st_mode & 0o022:
                raise GuardError("AppArmor override directory is not root-controlled")
        if PROFILEDIR.is_symlink() or not PROFILEDIR.is_dir():
            raise GuardError("Missing or unsafe libvirt profile directory")
    except OSError as exc:
        raise GuardError(f"AppArmor environment check failed: {exc}") from exc
    if not Path("/usr/sbin/apparmor_parser").exists():
        raise GuardError("apparmor_parser is not installed")


def policy_path(uuid: str) -> Path:
    return RULEDIR / f"99-cape-qcow2-{uuid}"


def parse_profile(uuid: str) -> None:
    profile = PROFILEDIR / f"libvirt-{uuid}"
    template = PROFILEDIR / "TEMPLATE.qemu"
    use = profile if profile.is_file() and not profile.is_symlink() else template
    if not use.is_file() or use.is_symlink():
        raise GuardError("No safe AppArmor guest profile or template for validation")
    run("apparmor_parser", "-Q", str(use))
    # A shut-off VM can have no generated profile. Libvirt loads the policy on start.
    if use == profile:
        run("apparmor_parser", "-r", str(profile))


def read_existing(path: Path) -> str | None:
    if path.is_symlink():
        raise GuardError(f"Existing override is a symlink: {path}")
    try:
        return path.read_text()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise GuardError(f"Cannot read existing override: {exc}") from exc


def apply(uuid: str, expected: str, vm: str) -> str:
    if os.geteuid() != 0:
        raise GuardError("Apply requires root; run with sudo on an authorized host")
    if LOCKFILE.is_symlink():
        raise GuardError("Refusing symlinked coordination lock")
    fd = os.open(LOCKFILE, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        # Re-run discovery under the lock to detect changed snapshot pointers.
        again_uuid, again_images = discover(vm)
        if again_uuid != uuid or policy_text(again_images[1:]) != expected:
            raise GuardError("VM snapshot chain changed after preflight; no changes applied")
        ensure_supported()
        target = policy_path(uuid)
        existing = read_existing(target)
        if existing is not None:
            if existing != expected:
                raise GuardError("Override exists with different contents; refusing overwrite")
            parse_profile(uuid)
            return "Already configured; validated without overwriting the policy"
        RULEDIR.mkdir(mode=0o755, parents=False, exist_ok=True)
        created = False
        temp_name = None
        try:
            policy_fd, temp_name = tempfile.mkstemp(prefix=".cape-qcow2-", dir=str(RULEDIR))
            os.fchmod(policy_fd, 0o644)
            with os.fdopen(policy_fd, "w") as stream:
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
            # An atomic hard link refuses to replace an unrecognized override.
            os.link(temp_name, target)
            created = True
            os.unlink(temp_name)
            temp_name = None
            parse_profile(uuid)
            return f"Installed and parsed read+lock backing-image rules: {target}"
        except Exception as exc:
            if created and read_existing(target) == expected:
                target.unlink()
                try:
                    parse_profile(uuid)
                except GuardError as reload_exc:
                    raise GuardError(f"Policy reverted; reload also failed: {reload_exc}") from exc
            raise
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except FileNotFoundError:
                    pass
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", required=True, help="Exact libvirt domain name")
    parser.add_argument("--mode", choices=("plan", "apply", "verify"), default="plan")
    args = parser.parse_args(argv)
    try:
        uuid, chain = discover(args.vm)
        ensure_supported()
        expected = policy_text(chain[1:])
        dest = policy_path(uuid)
        existing = read_existing(dest)
        print(f"VM={args.vm} UUID={uuid} mode={args.mode}")
        print(f"Active QCOW2={chain[0]}; backing layer count={len(chain)-1}")
        for image in chain[1:]:
            print(f"Backing permission required: {image} (read + lock, no write)")
        print("NOTE: local libvirt-qemu.d rules are SHARED across QEMU guest profiles.")
        print("NOTE: verifies policy preparation only; does NOT certify DAC, startup, rollback or guest isolation.")
        if args.mode == "plan":
            if existing is not None and existing != expected:
                raise GuardError(f"Conflicting managed override at {dest}")
            print(f"PLAN: {'already present' if existing == expected else 'would create'} {dest}; no changes")
        elif args.mode == "verify":
            if existing != expected:
                raise GuardError("Expected exact read+lock policy is not installed")
            print(f"VERIFIED policy contents: {dest}; VM startup still requires independent checks")
        else:
            print(apply(uuid, expected, args.vm))
        return 0
    except (GuardError, OSError, ValueError, ET.ParseError, json.JSONDecodeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
