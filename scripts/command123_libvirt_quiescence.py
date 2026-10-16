#!/usr/bin/env python3
"""Strict READ-ONLY libvirt quiescence check for deployment recovery.

Checking only virsh --state-running misses paused, pmsuspended and other
non-shutoff guests. To protect third-party VMs, enumerate ALL defined
domains, inspect each state and accept only exact 'shut off'. Fail closed
when a domain disappears or changes during the inventory.

No guest is ever started, destroyed, reverted, undefined or modified.
"""
from __future__ import annotations

import subprocess
import re

MAX_DOMAINS = 256
MAX_OUTPUT = 65536


class QuiescenceBlocked(RuntimeError):
    pass


def need(ok, why):
    if not ok:
        raise QuiescenceBlocked(why)


def read_virsh(*args):
    cmd = ["virsh", "-c", "qemu:///system", *args]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise QuiescenceBlocked("Cannot inspect libvirt domain state") from exc
    need(proc.returncode == 0 and
         isinstance(proc.stdout, str) and
         len(proc.stdout) < MAX_OUTPUT,
         "Cannot trust libvirt domain inventory")
    return proc.stdout


def enumerate_domains():
    raw = read_virsh("list", "--all", "--name")
    rows = [line.strip() for line in raw.splitlines() if line.strip()]
    need(len(rows) <= MAX_DOMAINS and len(set(rows)) == len(rows) and
         all(0 < len(name) <= 256 and
             "\x00" not in name and
             "\r" not in name and "\n" not in name for name in rows),
         "Invalid, duplicate or excessive libvirt guest inventory")
    return tuple(sorted(rows))


def scan_domain_identities(names):
    """Snapshot exact UUIDs and state. Never trust a name alone as identity."""
    identities = {}
    for name in names:
        raw_id = read_virsh("domuuid", name).strip()
        need(re.fullmatch(
            r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}",
            raw_id) is not None,
            "Libvirt domain UUID absent or invalid")
        uuid = raw_id.lower()
        need(uuid not in identities.values(),
             "Two libvirt domains share one UUID")
        state = read_virsh("domstate", name).strip()
        need(state == "shut off",
             "Libvirt domain is live, paused, suspended or state unknown")
        identities[name] = uuid
    return identities


def no_nonshutoff_domains():
    """Fail closed if names, UUIDs, or state drift during two read-only scans."""
    before = enumerate_domains()
    first = scan_domain_identities(before)
    need(enumerate_domains() == before,
         "Libvirt guest inventory drift during quiescence check")
    second = scan_domain_identities(before)
    need(second == first,
         "Libvirt domain identity replaced under an unchanged name")
    # A second state sweep catches stopped->running transitions after the
    # first pass. It does not provide an exclusive libvirt lifecycle lock.
    need(enumerate_domains() == before,
         "Libvirt guest inventory drift during quiescence check")
    return {
        "only_shutoff_domains_observed": True,
        "defined_domain_count": len(before),
        "domain_uuid_verified_twice": True,
        "domain_state_verified_twice": True,
        "no_live_guest_mutation_performed": True,
        "not_an_exclusive_libvirt_lock": True,
    }
