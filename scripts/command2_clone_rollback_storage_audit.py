#!/usr/bin/env python3
"""Read-only QCOW2 integrity admission for a separately staged clone.

This does not authorize a snapshot restore, TPM rollback or guest startup.
"""
from __future__ import annotations
import json
from pathlib import Path
import subprocess

VIRTUAL_BYTES = 64 * 1024**3


class DiskAdmissionBlocked(RuntimeError):
    pass


def inspect_qcow2(path, runner=subprocess.run):
    source = Path(path)
    if not source.is_absolute() or source.is_symlink() or not source.is_file():
        raise DiskAdmissionBlocked("Expected existing regular absolute disk")
    try:
        result = runner(
            ["qemu-img", "info", "--output=json", str(source)],
            capture_output=True, text=True, timeout=60, check=False)
        if result.returncode != 0 or len(result.stdout) > 1048576:
            raise DiskAdmissionBlocked("QCOW2 metadata unavailable")
        info = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        raise DiskAdmissionBlocked("Cannot verify disk metadata") from error
    if not isinstance(info, dict) or info.get("format") != "qcow2":
        raise DiskAdmissionBlocked("Disk is not QCOW2")
    if info.get("virtual-size") != VIRTUAL_BYTES:
        raise DiskAdmissionBlocked("Unexpected virtual disk capacity")
    if info.get("backing-filename") or info.get("full-backing-filename"):
        raise DiskAdmissionBlocked("Disk has external backing storage")
    if info.get("snapshots", []) != []:
        raise DiskAdmissionBlocked("Disk has internal snapshots or unknown snapshot metadata")
    if info.get("encrypted"):
        raise DiskAdmissionBlocked("Encrypted or unreviewed QCOW2 metadata")
    specific = info.get("format-specific")
    if specific is not None:
        if not isinstance(specific, dict) or specific.get("type") != "qcow2":
            raise DiskAdmissionBlocked("Unknown QCOW2 format-specific metadata")
        data = specific.get("data")
        if not isinstance(data, dict) or any(data.get(key) for key in (
                "data-file", "has-backing-file", "corrupt")):
            raise DiskAdmissionBlocked("QCOW2 external data, backing or corruption")
    return {"result": "INDEPENDENT_QCOW2_METADATA_ONLY",
            "no_internal_snapshots": True,
            "no_external_backing": True,
            "no_external_data_file": True,
            "no_disk_mutation": True,
            "never_booted_proven": False,
            "tpm_restore_proven": False,
            "deployment_ready": False}
