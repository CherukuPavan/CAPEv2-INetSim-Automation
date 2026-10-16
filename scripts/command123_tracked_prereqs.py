#!/usr/bin/env python3
"""Root-private APT provenance wrapper for ONLY reviewed Ubuntu base prerequisites.

Requires an existing Command 1 transaction. Captures complete dpkg inventory
before and after the subprocess, including transitive packages. Any incomplete
or unexpected transaction remains blocked. No package removal is attempted.
This component does NOT install a CAPE hypervisor or analysis VMs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import uuid

import command123_deployment_transaction as ledger
import command123_hypervisor_release_compat as hypervisor

BASE = ("python3", "python3-venv", "python3-pip", "git", "cpu-checker",
        "msr-tools", "acpica-tools")
# Ubuntu 26.04 official LTS virtualization package set. In Ubuntu 24.04 the
# historical 7-base-package component remains unchanged.
VIRT26 = ("qemu-system-x86", "qemu-utils", "libvirt-clients",
          "libvirt-daemon-system", "libvirt-daemon-config-network",
          "ovmf", "swtpm", "swtpm-tools", "virtinst")
ENV = {"LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive",
       "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?\Z")
INST = re.compile(r"^Inst ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?) (?:\(|\[)")
MAX = 8 * 1024 * 1024


def need(ok, reason):
    ledger.need(ok, reason)


def read_command(argv):
    try:
        result = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=ENV, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as err:
        raise ledger.TransactionBlocked("APT/dpkg inspection unavailable") from err
    need(result.returncode == 0 and len(result.stdout) <= MAX,
         "APT/dpkg inspection failed or oversized")
    return result.stdout.decode("utf-8")


def verify_host():
    need(platform.machine() == "x86_64", "Requires x86_64")
    os_release = Path("/etc/os-release").read_text()
    # Ubuntu os-release has quoted/unquoted key/value declarations.
    values = {}
    for line in os_release.splitlines():
        if "=" in line and not line.startswith("#"):
            key, val = line.split("=", 1)
            values[key] = val.strip('"')
    # Ubuntu 26.04 LTS ships official signed QEMU/libvirt versions meeting
    # the native snapshot VERSION thresholds. This only permits the seven
    # tracked base prerequisites; it is NOT authorization to install the
    # hypervisor, run guests, or assume swtpm snapshot coherence.
    need(values.get("ID") == "ubuntu" and
         values.get("VERSION_ID") in ("24.04", "26.04"),
         "Requires supported Ubuntu 24.04 or 26.04 LTS")
    return values["VERSION_ID"]


def installed():
    result = {}
    raw = read_command(["dpkg-query", "-W",
                        "-f=" + "${Package}\t${Version}\t${Status}\n"])
    for row in raw.splitlines():
        fields = row.split("\t")
        need(len(fields) == 3, "Bad dpkg row format")
        package, version, status = fields
        need(PACKAGE.fullmatch(package) and bool(version),
             "Bad dpkg package name or version")
        if status == "install ok installed":
            need(package not in result, "Duplicate dpkg package")
            result[package] = version
    need("dpkg" in result, "Incomplete installed inventory")
    return result


def simulate(names, *, allow_virt26=False):
    need(type(allow_virt26) is bool and
         set(names) <= (set(BASE) | (set(VIRT26) if allow_virt26 else set())),
         "Unapproved package")
    output = read_command(["apt-get", "-s", "-o", "Debug::NoLocking=true",
                           "install", "--no-install-recommends", *names])
    actions = []
    for line in output.splitlines():
        if line.startswith(("Remv ", "Purg ", "Hold ")):
            raise ledger.TransactionBlocked("APT proposes removals or holds")
        if line.startswith("Inst "):
            match = INST.match(line)
            need(match is not None, "Unknown APT simulated installation")
            actions.append(match.group(1))
    need(len(actions) == len(set(actions)), "Duplicate APT plan entry")
    return actions


def plan():
    release = verify_host()
    # Meeting the package versions does NOT imply TPM-safe snapshot restore.
    compat = None
    allowed = BASE
    if release == "26.04":
        try:
            compat = hypervisor.plan()
        except hypervisor.ReleaseBlocked as error:
            raise ledger.TransactionBlocked(
                "Resolute signed APT candidate inventory unavailable"
            ) from error
        need(compat["running_snapshot_stack_versions_admitted"],
             "Resolute QEMU/libvirt APT candidates below floor")
        allowed += VIRT26
    before = installed()
    missing = sorted(pkg for pkg in allowed if pkg not in before)
    simulated = (
        (simulate(missing, allow_virt26=True) if release == "26.04"
         else simulate(missing))
        if missing else [])
    need(not set(simulated) & set(before),
         "APT would upgrade or reinstall a preexisting package")
    return {"result": "CAPE_BASE_APT_REVIEW_ONLY",
            "requested_missing": missing,
            "simulated_installations": simulated,
            "installed_package_count": len(before),
            "baseline_inventory_sha256": hashlib.sha256(
                snap_bytes(before)).hexdigest(),
            "host_modified": False,
            "target_lts_release": release,
            "resolute_virt26_binaries_in_scope": release == "26.04",
            "qemu_libvirt_candidate_versions_admitted":
                (compat is not None and
                 compat["running_snapshot_stack_versions_admitted"]),
            "snapshot_stack_authorized": False}


def snap_bytes(state):
    data = (json.dumps(state, sort_keys=True,
                       separators=(",", ":")) + "\n").encode()
    need(len(data) <= MAX, "Oversized dpkg snapshot")
    return data


def delta(before, after, planned):
    added = {k: after[k] for k in after if k not in before}
    changed = {k: {"before": before[k], "after": after[k]}
               for k in before if k in after and before[k] != after[k]}
    removed = {k: before[k] for k in before if k not in after}
    return {
        "new_packages": added,
        "preexisting_changed": changed,
        "preexisting_removed": removed,
        "unplanned_additions": sorted(set(added) - set(planned)),
    }


def apply(transaction, host):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Interactive root operator required")
    ledger.host_guard(host)
    with ledger.exclusive_transaction_lock(transaction):
        receipt, doc = ledger.load(transaction, host)
        need(doc["phase"] == "active" and
             not any(x["kind"] == "package" for x in doc["entries"]),
             "Unresolved or repeated APT step")
        proposal = plan()
        if not proposal["requested_missing"]:
            return {"result": "CAPE_BASE_APT_ALREADY_PRESENT",
                    "mutated": False, "transaction": transaction}
        print(json.dumps(proposal, indent=2, sort_keys=True), flush=True)
        phrase = ("INSTALL-TRACKED-CAPE-BASE-AND-VIRT26"
                  if proposal.get("resolute_virt26_binaries_in_scope") else
                  "INSTALL-TRACKED-CAPE-BASE-PREREQUISITES")
        need(input("Type " + phrase + ": ") == phrase,
             "APT package installation declined")
        need(plan() == proposal, "Package plan changed after approval")
        before = installed()
        need(hashlib.sha256(snap_bytes(before)).hexdigest() ==
             proposal["baseline_inventory_sha256"],
             "Installed package versions changed after approval")
        step_id = uuid.uuid4().hex
        folder = receipt.parent
        original = snap_bytes(before)
        ledger.private_copy(folder, "apt-before-" + step_id, original)
        record = {"id": step_id, "kind": "package", "stage": "command1",
                  "status": "prepared", "requested": proposal["requested_missing"],
                  "simulated": proposal["simulated_installations"],
                  "before_sha256": hashlib.sha256(original).hexdigest(),
                  "after_sha256": None,
                  "package_rollback_supported": False}
        doc["entries"].append(record)
        # Durably record intent BEFORE apt can mutate the host.
        ledger.atomic_receipt(receipt, doc)
        command = ["apt-get", "install", "-y", "--no-install-recommends",
                   *proposal["requested_missing"]]
        try:
            proc = subprocess.run(
                command, env=ENV, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=1200, check=False)
            after = installed()
            data = snap_bytes(after)
            ledger.private_copy(folder, "apt-after-" + step_id, data)
            changes = delta(before, after, proposal["simulated_installations"])
            record["after_sha256"] = hashlib.sha256(data).hexdigest()
            record["observed_change"] = changes
            record["apt_exit_code"] = proc.returncode
            approved = (proc.returncode == 0 and
                        all(n in after for n in proposal["requested_missing"]) and
                        not changes["preexisting_changed"] and
                        not changes["preexisting_removed"] and
                        not changes["unplanned_additions"])
            record["status"] = ("sealed" if approved
                                else "PARTIAL_OR_UNEXPECTED_NO_AUTO_RETRY")
            ledger.atomic_receipt(receipt, doc)
            need(approved, "APT partial/unexpected change; stop and inspect")
            return {"result": (
                        "CAPE_BASE_AND_RESOLUTE_VIRT26_BINARIES_INSTALLED"
                        if proposal.get("resolute_virt26_binaries_in_scope")
                        else "CAPE_BASE_APT_INSTALLED_AND_PROVEN"),
                    "transaction": transaction, "step_id": step_id,
                    "new_packages": len(changes["new_packages"]),
                    "no_guest_started_or_snapshot_created": True,
                    "TPM_coherent_restore_proven": False,
                    "package_rollback_supported": False}
        except Exception as err:
            # Even if snapshot or inspection fails, the prepared ledger
            # entry remains and no destructive rollback is authorized.
            raise ledger.TransactionBlocked(
                "APT partially applied or unknown; inspect root-private journal"
            ) from err


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("plan", "apply"), default="plan")
    source = p.add_mutually_exclusive_group()
    source.add_argument("--transaction")
    source.add_argument("--use-active-transaction", action="store_true")
    p.add_argument("--approved-host")
    a = p.parse_args()
    try:
        if a.mode == "plan":
            value = plan()
        else:
            need(a.approved_host and
                 (a.transaction or a.use_active_transaction),
                 "Existing deployment transaction and approved host required")
            ident = (ledger.active_transaction(a.approved_host)
                     if a.use_active_transaction else a.transaction)
            value = apply(ident, a.approved_host)
        print(json.dumps(value, sort_keys=True, indent=2))
        return 0
    except (ledger.TransactionBlocked, OSError, ValueError,
            UnicodeDecodeError) as error:
        print(json.dumps({"result": "CAPE_APT_GUARD_BLOCKED_OR_PARTIAL",
                          "error_type": type(error).__name__,
                          "no_unverified_package_removal": True}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
