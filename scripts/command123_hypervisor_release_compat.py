#!/usr/bin/env python3
"""Read-only release compatibility gate for the REAL CAPE running snapshots.

The existing command2_native_snapshot_stack_guard.py requires QEMU >=9.0
and libvirt >=10.10 for its experimental QCOW2 OVMF native snapshot path.
Ubuntu 24.04 distro APT versions (QEMU 8.2, libvirt 10.0) are too old,
even though those packages can boot ordinary cold KVM guests.

This checks the actual APT candidates BEFORE installing anything. It does
not build/upgrade hypervisors, write APT sources, change users, start
guests, or claim TPM-consistent snapshot restore.
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
import sys

import command2_native_snapshot_stack_guard as snap

PACKAGES = {"qemu-system-x86": ("QEMU", snap.MIN_QEMU),
            "libvirt-daemon-system": ("libvirt", snap.MIN_LIBVIRT)}
MAX_OUTPUT = 65536


class ReleaseBlocked(RuntimeError):
    pass


def parse_deb_version(text):
    """Accept versioned Debian epochs; reject bogus/missing candidates."""
    if not isinstance(text, str):
        raise ReleaseBlocked("APT version was not a string")
    match = re.fullmatch(r"(?:[0-9]{1,5}:)?([0-9]{1,4})\.([0-9]{1,4})"
                         r"(?:\.([0-9]{1,4}))?(?:[+~.\-A-Za-z0-9:]*)?",
                         text.strip())
    if match is None:
        raise ReleaseBlocked("No recognizable APT package version")
    return tuple(int(x or 0) for x in match.groups())


def policy_candidate(body):
    matches = re.findall(r"(?m)^\s*Candidate:\s*(\S+)\s*$", body)
    if len(matches) != 1 or matches[0] == "(none)":
        raise ReleaseBlocked("APT candidate unavailable or ambiguous")
    return matches[0]


def read_policy(package):
    if package not in PACKAGES:
        raise ReleaseBlocked("Unapproved package identifier")
    try:
        p = subprocess.run(["apt-cache", "policy", package],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, check=False, timeout=12)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ReleaseBlocked("Cannot inspect available Ubuntu APT package") from e
    if p.returncode != 0 or len(p.stdout) > MAX_OUTPUT:
        raise ReleaseBlocked("Unexpected APT policy response")
    return policy_candidate(p.stdout)


def candidate_matrix(candidates):
    if set(candidates) != set(PACKAGES):
        raise ReleaseBlocked("Both QEMU and libvirt candidate versions needed")
    rows = {}
    blockers = []
    for package, (label, required) in PACKAGES.items():
        raw = candidates[package]
        try:
            parsed = parse_deb_version(raw)
            usable = parsed >= required
        except ReleaseBlocked:
            parsed = None
            usable = False
        rows[package] = {
            "component": label, "candidate": raw,
            "version": ".".join(map(str, parsed)) if parsed else None,
            "minimum_for_existing_snapshot_gate": ".".join(map(str, required)),
            "satisfies_snapshot_gate": usable,
        }
        if not usable:
            blockers.append(package + ":APT_CANDIDATE_TOO_OLD_OR_UNKNOWN")
    return {
        "result": ("COMMAND123_HYPERVISOR_RELEASE_CANDIDATES_ADMITTED"
                   if not blockers else
                   "COMMAND123_HYPERVISOR_RELEASE_CANDIDATES_BLOCKED"),
        "apt": rows, "blockers": blockers,
        "running_snapshot_stack_versions_admitted": not blockers,
        "cold_windows_boot_proven": False,
        "swtpm_restore_consistency_proven": False,
        "CAPE_three_commands_ready": False,
        "apt_modified": False, "VMs_modified": False,
        "safe_to_autoinstall_for_full_snapshot_contract": not blockers,
    }


def plan():
    if platform.machine() != "x86_64":
        raise ReleaseBlocked("Only approved x86_64 host architecture")
    candidates = {name: read_policy(name) for name in PACKAGES}
    return candidate_matrix(candidates)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", default="plan", choices=("plan",))
    parser.parse_args()
    try:
        report = plan()
        print(json.dumps(report, indent=2, sort_keys=True))
        # Failure must block use as a production full-snapshot installer.
        return 0 if report["running_snapshot_stack_versions_admitted"] else 3
    except (ReleaseBlocked, ValueError, OSError) as e:
        print(json.dumps({
            "result": "COMMAND123_HYPERVISOR_RELEASE_PRECHECK_BLOCKED",
            "error_type": type(e).__name__,
            "no_host_installation_attempted": True,
        }, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
