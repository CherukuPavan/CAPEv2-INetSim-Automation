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
    return tuple(rows)


def no_nonshutoff_domains():
    """Return evidence only if all libvirt domains remain strictly shut off."""
    before = enumerate_domains()
    for name in before:
        state = read_virsh("domstate", name).strip()
        need(state == "shut off",
             "Libvirt domain is live, paused, suspended or state unknown")
    # A domain may start or be newly defined while the state scan runs.
    # This double inventory cannot close all races; callers still need
    # exclusive lifecycle ownership for a physical full rollback.
    need(enumerate_domains() == before,
         "Libvirt guest inventory drift during quiescence check")
    return {
        "only_shutoff_domains_observed": True,
        "defined_domain_count": len(before),
        "no_live_guest_mutation_performed": True,
        "not_an_exclusive_libvirt_lock": True,
    }
