#!/usr/bin/env python3
"""Private crash-aware identity reservation journal for a SEPARATE host.

Component API only; NO CLI, VM definition, cloning, NIC action, or guest
writes. This records proposed guest identities, not proof the host inventory
is authoritative. Never call this on reference SSL-55, including from tests.
Tests use mock hostnames and private temporary directories exclusively.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import uuid

class ReservationBlocked(RuntimeError):
    pass

RECORD_NAME = "command2-identity-reservation.json"
LOCK_NAME = ".command2-identity-reservation.lock"
PENDING_PREFIX = ".command2-identity-pending-"
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_GUESTS = 4096
ID_FIELDS = ("libvirt_uuid_candidate", "smbios_generation_id_candidate")
KEYS = ("libvirt_name", "libvirt_uuid_candidate",
        "smbios_generation_id_candidate", "mac_candidate",
        "windows_hostname_target", "guest_static_ipv4_target",
        "disk_target", "uefi_nvram_target")
SUPPORTED = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


def require(test, reason):
    if not test:
        raise ReservationBlocked(reason)


def host_identity():
    """Hostname is a guard, NOT cryptographic machine attestation."""
    name = socket.gethostname().split(".", 1)[0].lower()
    require(name not in ("ssl-55", "cse-ssl-55"),
            "SSL55_REFERENCE_ONLY: identity reservations prohibited")
    require(bool(SUPPORTED.fullmatch(name)), "Unrecognized host name")
    return name


def canonical(blueprint):
    """Strictly validate schema and uniqueness before any disk activity."""
    require(type(blueprint) is dict and
            blueprint.get("result") == "COMMAND2_CANDIDATE_IDENTITIES_ONLY"
            and blueprint.get("identities_reserved") is False
            and blueprint.get("created_any_vm") is False
            and blueprint.get("deploy_authorized") is False
            and blueprint.get("network_isolation_verified") is False,
            "Expected safe, unreserved guest blueprint")
    rows = blueprint.get("candidates")
    n = blueprint.get("requested_total")
    require(type(n) is int and 1 <= n <= MAX_GUESTS and
            type(rows) is list and len(rows) == n,
            "Invalid candidate count or record structure")
    unique_ids, unique_macs, unique_ips, unique_paths = set(), set(), set(), set()
    out = []
    for i, row in enumerate(rows, 1):
        require(type(row) is dict and
                row.get("libvirt_name") == f"win11_{i}" and
                row.get("windows_hostname_target") == f"WIN11-{i}" and
                row.get("nic_attached") is False and
                row.get("static_ipv4_applied") is False and
                row.get("windows_identity_change_applied") is False and
                row.get("per_vm_tpm_state_must_be_fresh") is True,
                "Untrusted candidate identity or already modified guest")
        record = {}
        for key in KEYS:
            require(type(row.get(key)) is str and bool(row[key]),
                    "Missing identity field " + key)
            record[key] = row[key]
        for key in ID_FIELDS:
            try:
                normalized = str(uuid.UUID(record[key]))
            except (ValueError, TypeError) as exc:
                raise ReservationBlocked("Invalid UUID candidate") from exc
            require(normalized == record[key] and normalized not in unique_ids,
                    "Duplicate/noncanonical UUID candidate")
            unique_ids.add(normalized)
        mac = record["mac_candidate"]
        require(bool(re.fullmatch(r"02:(?:[0-9a-f]{2}:){4}[0-9a-f]{2}", mac))
                and mac not in unique_macs, "Invalid or duplicate MAC")
        unique_macs.add(mac)
        ip = record["guest_static_ipv4_target"]
        import ipaddress
        try:
            parsed = str(ipaddress.IPv4Address(ip))
        except ValueError as exc:
            raise ReservationBlocked("Invalid IPv4 candidate") from exc
        require(parsed == ip and ip not in unique_ips,
                "Duplicate/noncanonical IPv4 candidate")
        unique_ips.add(ip)
        for key in ("disk_target", "uefi_nvram_target"):
            val = record[key]
            require(val.startswith("/") and "\x00" not in val and
                    ".." not in Path(val).parts and val not in unique_paths and
                    val != "/", "Unsafe/colliding disk or NVRAM candidate")
            unique_paths.add(val)
        out.append(record)
    return out


def payload(blueprint, machine):
    """Canonical bytes: deterministic digest for safe exact replay."""
    require(type(machine) is str and bool(SUPPORTED.fullmatch(machine)),
            "Explicit verified machine name required")
    items = canonical(blueprint)
    return {"format": "CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
            "version": 1, "host": machine,
            "guest_count": len(items),
            "entries": items,
            "provisioning_started": False, "libvirt_domains_created": False,
            "host_network_modified": False,
            "state": "CANDIDATES_RECORDED_NOT_APPLIED"}


def serialize(data):
    value = (json.dumps(data, sort_keys=True, separators=(",", ":")) +
             "\n").encode("utf-8")
    require(len(value) <= MAX_RECORD_BYTES, "Reservation record too large")
    return value


def read_exact(dirfd, filename):
    fd = os.open(filename, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                 dir_fd=dirfd)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
                stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and
                st.st_size <= MAX_RECORD_BYTES,
                "Reservation file has unsafe metadata")
        with os.fdopen(fd, "rb", closefd=False) as inp:
            content = inp.read(MAX_RECORD_BYTES + 1)
        require(len(content) <= MAX_RECORD_BYTES,
                "Oversized reservation file")
        return content
    finally:
        os.close(fd)


def reserve(blueprint, directory, *, expected_host):
    """Exclusive atomic reservation record, no VM operations.

    Caller must independently attest exact libvirt UUID/MAC inventory and
    approve that this separate host is a safe deployment target. This
    helper only persists a candidate record and cannot perform either.
    A crash before atomic publication leaves a .pending- file and
    **blocks** retry for explicit operator review. No blind cleanup.
    """
    local = host_identity()  # fail before any filesystem mutation on SSL-55
    require(expected_host == local, "Wrong target host; refuse reservation")
    folder = Path(directory)
    require(folder.is_absolute() and folder.name not in ("", ".", "..") and
            not folder.is_symlink() and folder.is_dir(), "Private directory required")
    statdir = folder.stat()
    require(stat.S_IMODE(statdir.st_mode) == 0o700 and
            statdir.st_uid == os.geteuid(),
            "Reservation directory must be owned by user with mode 0700")
    wanted = serialize(payload(blueprint, local))
    dirfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lockfd = None
    try:
        lockfd = os.open(LOCK_NAME, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC |
                         os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
        ls = os.fstat(lockfd)
        require(stat.S_ISREG(ls.st_mode) and ls.st_uid == os.geteuid() and
                stat.S_IMODE(ls.st_mode) == 0o600 and ls.st_nlink == 1,
                "Unsafe reservation lock")
        fcntl.flock(lockfd, fcntl.LOCK_EX)
        # Never auto-delete suspicious/incomplete files.
        require(not any(name.startswith(PENDING_PREFIX) for name in os.listdir(folder)),
                "Incomplete reservation present; manual recovery required")
        try:
            existing = read_exact(dirfd, RECORD_NAME)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            require(existing == wanted,
                    "Reservation conflict: existing manifest differs")
            return {"status": "EXACT_IDEMPOTENT_RESERVATION_RECORD",
                    "reused": True, "host": local,
                    "sha256": hashlib.sha256(wanted).hexdigest(),
                    "guest_count": len(blueprint["candidates"]),
                    "guest_vm_created": False, "network_modified": False}
        tmp = PENDING_PREFIX + uuid.uuid4().hex
        tmpfd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
        try:
            with os.fdopen(tmpfd, "wb", closefd=False) as out:
                out.write(wanted)
                out.flush()
                os.fsync(tmpfd)
            require(read_exact(dirfd, tmp) == wanted,
                    "Reservation staged bytes differ")
            # Exclusive publish: will never replace an existing manifest.
            os.link(tmp, RECORD_NAME, src_dir_fd=dirfd, dst_dir_fd=dirfd,
                    follow_symlinks=False)
            os.fsync(dirfd)
            os.unlink(tmp, dir_fd=dirfd)
            os.fsync(dirfd)
        finally:
            os.close(tmpfd)
        return {"status": "CANDIDATE_RESERVATION_RECORDED_NOT_DEPLOYED",
                "reused": False, "host": local,
                "sha256": hashlib.sha256(wanted).hexdigest(),
                "guest_count": len(blueprint["candidates"]),
                "guest_vm_created": False, "network_modified": False}
    finally:
        if lockfd is not None:
            os.close(lockfd)
        os.close(dirfd)
