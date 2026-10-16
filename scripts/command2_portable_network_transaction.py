#!/usr/bin/env python3
"""Durable create-only receipts for Command2 isolated libvirt/network/nft setup.

This module NEVER calls virsh, nft, changes guest state or deletes anything.
The installer must record exact source digests before first mutation, then
record each progress transition. Partial work is NOT a retry/undo license.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

RECEIPT = "command2-isolated-network-deployment.json"
PHASES = ("prepared", "nft_applied", "network_defined",
          "network_started", "verified")
MAX = 16384


class NetworkTransactionBlocked(RuntimeError):
    pass


def need(ok, msg):
    if not ok:
        raise NetworkTransactionBlocked(msg)


def root_private(stat_result):
    return (stat.S_ISREG(stat_result.st_mode) and
            stat_result.st_uid == 0 and
            stat_result.st_nlink == 1 and
            stat.S_IMODE(stat_result.st_mode) == 0o600 and
            0 < stat_result.st_size <= 1024 * 1024)


def safe_dir(journal):
    journal = Path(journal)
    need(journal.is_absolute() and
         journal.name == "command2-identity-reservation.json" and
         not journal.is_symlink(), "Invalid reservation journal")
    folder = journal.parent
    need(folder.is_dir() and
         not any(p.is_symlink() for p in (folder, *folder.parents)),
         "Untrusted journal folder or symlinked ancestor")
    st = folder.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
         stat.S_IMODE(st.st_mode) == 0o700,
         "Root private 0700 journal folder required")
    return folder


def validate(data):
    need(type(data) is dict and data.get("schema") == 1 and
         data.get("status") in PHASES and
         data.get("network") == "cape-analysis-isolated" and
         data.get("table") == "cape_analysis_cmd2_guard" and
         data.get("bridge") == "cape-lab0" and
         data.get("both_resources_absent_before") is True and
         data.get("guests_stopped_before") is True and
         data.get("retries_authorized") is False,
         "Invalid network ownership receipt")
    need(type(data.get("host")) is str and
         re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}",data["host"]),
         "Untrusted network receipt hostname")
    for field in ("reservation_sha256", "nft_rules_sha256",
                  "network_xml_sha256"):
        need(type(data.get(field)) is str and
             re.fullmatch(r"[0-9a-f]{64}",data[field]),
             "Missing exact network source checksum")
    return data


def write(target, payload, *, first=False):
    data = (json.dumps(validate(payload), sort_keys=True,
                       indent=2) + "\n").encode()
    need(len(data) <= MAX, "Oversized network receipt")
    if first:
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd,"wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        old = read(target)
        need(old["status"] != payload["status"],
             "Cannot replay same journal transition")
        fd,temp = tempfile.mkstemp(dir=target.parent,prefix=".net-step-")
        try:
            with os.fdopen(fd,"wb") as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(),0o600)
                os.fsync(stream.fileno())
            os.replace(temp,target)
        finally:
            if os.path.lexists(temp):
                os.unlink(temp)
    dfd = os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def read(target):
    need(not target.is_symlink(),"Symlinked network receipt")
    fd = os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(root_private(st) and st.st_size <= MAX,
             "Nonprivate or malformed receipt")
        raw = os.read(fd,MAX+1)
        need(len(raw)==st.st_size,"Receipt changed during inspection")
    finally:
        os.close(fd)
    return validate(json.loads(raw))


def record_path(journal):
    return safe_dir(journal) / RECEIPT


def begin(host, journal, plan):
    target = record_path(journal)
    need(not target.exists() and not target.is_symlink(),
         "Prior network install record exists; no blind retry")
    need(type(plan) is dict and
         plan.get("approved_host") == host and
         plan.get("libvirt_network_preexisting") is False and
         plan.get("nft_table_preexisting") is False and
         plan.get("guests_running") is False,
         "Resource absence and stopped guests unproven")
    source = Path(journal)
    fd = os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(root_private(st),"Reservation journal not root-private")
        raw = os.read(fd,st.st_size+1)
        need(len(raw)==st.st_size,"Reservation changed during read")
    finally:
        os.close(fd)
    entry = {
        "schema":1,"status":"prepared","host":host,
        "reservation_sha256":hashlib.sha256(raw).hexdigest(),
        "network":plan["network_name"],"bridge":plan["bridge"],
        "table":plan["nft_table"],
        "network_xml_sha256":plan["network_xml_sha256"],
        "nft_rules_sha256":plan["nft_rules_sha256"],
        "both_resources_absent_before":True,
        "guests_stopped_before":True,
        "retries_authorized":False,
        "whole_deployment_rollback_ready":False,
    }
    write(target,entry,first=True)
    return entry


def advance(journal, prior, successor):
    need(prior in PHASES and successor in PHASES and
         PHASES.index(successor)==PHASES.index(prior)+1,
         "Nonsequential network phase")
    target=record_path(journal)
    data=read(target)
    need(data["status"]==prior,"Network phase drifted or was replayed")
    data["status"]=successor
    write(target,data)
    return data
