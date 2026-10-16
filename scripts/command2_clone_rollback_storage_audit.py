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


def require_no_foreign_qcow2_backing_reference(
        foreign_path, protected_paths, runner=subprocess.run):
    """Fail closed if a foreign guest image depends on any owned clone image.

    A guest can reference an owned image indirectly as an N-layer QCOW2
    backing file without mentioning it anywhere in its saved domain XML.
    Never rename that owned image while another domain depends on it.
    """
    source = Path(foreign_path)
    if not source.is_absolute() or not source.exists():
        raise DiskAdmissionBlocked("Foreign VM image not inspectable")
    protected = tuple(Path(x) for x in protected_paths)
    if not protected or any(not x.is_absolute() or not x.exists()
                            for x in protected):
        raise DiskAdmissionBlocked("Protected clone image missing")
    try:
        result = runner(
            ["qemu-img", "info", "-U", "--backing-chain",
             "--output=json", str(source)],
            capture_output=True, text=True, timeout=60, check=False)
        if result.returncode != 0 or len(result.stdout) > 1048576:
            raise DiskAdmissionBlocked("Foreign backing inventory unavailable")
        layers = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        raise DiskAdmissionBlocked("Cannot verify foreign backing inventory") from error
    if not isinstance(layers, list) or not 1 <= len(layers) <= 64:
        raise DiskAdmissionBlocked("Malformed or excessive backing chain")
    try:
        expected_start = source.resolve(strict=True)
        originals = {x.resolve(strict=True) for x in protected}
        examined = []
        for layer in layers:
            if not isinstance(layer, dict):
                raise DiskAdmissionBlocked("Unreviewed backing-chain layer")
            name = layer.get("filename")
            if not isinstance(name, str) or not name or not Path(name).is_absolute():
                raise DiskAdmissionBlocked("Opaque or relative backing-chain path")
            candidate = Path(name).resolve(strict=True)
            if not candidate.is_file():
                raise DiskAdmissionBlocked("Non-file backing-chain layer")
            examined.append(candidate)
            if candidate in originals:
                raise DiskAdmissionBlocked(
                    "Another VM has a direct or indirect reference to clone storage")
        if examined[0] != expected_start or len(set(examined)) != len(examined):
            raise DiskAdmissionBlocked("Inconsistent foreign backing-chain identity")
        if layers[-1].get("backing-filename") or layers[-1].get("full-backing-filename"):
            raise DiskAdmissionBlocked("Foreign backing inventory is incomplete")
    except (OSError, RuntimeError) as error:
        raise DiskAdmissionBlocked("Cannot resolve foreign image dependencies") from error
    return {"foreign_chain_independent_of_owned_clone": True,
            "foreign_chain_layers_verified": len(layers),
            "no_foreign_image_mutation": True}

