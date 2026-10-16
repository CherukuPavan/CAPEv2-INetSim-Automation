#!/usr/bin/env python3
"""Deployment-scoped five-unit systemd START effect reversal.

Only an independently journaled, previously INACTIVE unit may be STOPPED.
If a service was active before the original restart, its old process/memory
cannot be restored: leave it untouched and mark whole-deployment rollback
incomplete. Never disable or enable units; never replace unit files. The
pre/post InvocationID + UnitFileState + FragmentPath form a drift guard.

A missing/partial restart receipt is PLAN-ONLY, not a cleanup license.
Requires no running libvirt domains, root direct TTY and host-matched exact
operator approval. No guest/network/firewall/package actions here.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import uuid

UNITS = (
    "cape.service", "cape-processor.service", "cape-rooter.service",
    "cape-web.service", "suricata.service",
)
PROPS = ("Id", "LoadState", "ActiveState", "UnitFileState",
         "FragmentPath", "InvocationID")
PROTECTED = frozenset(("ssl-55", "cse-ssl-55", "ssl-46", "cse-ssl-46"))
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
SCHEMA = 1


class ServiceOwnershipBlocked(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise ServiceOwnershipBlocked(message)


def host_guard(approved):
    actual = socket.gethostname().split(".", 1)[0].lower()
    need(actual not in PROTECTED and
         type(approved) is str and
         approved.lower().split(".", 1)[0] == actual and
         len(actual) >= 2,
         "Systemd scoped rollback denied on protected or different host")
    return actual


def unit_state(unit):
    need(unit in UNITS, "Unexpected service unit")
    try:
        out = subprocess.run(
            ["systemctl", "show", "--no-pager",
             "--property=" + ",".join(PROPS), unit],
            text=True, capture_output=True, timeout=12, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ServiceOwnershipBlocked("Cannot inspect exact systemd unit") from exc
    need(out.returncode == 0 and len(out.stdout) <= 8192,
         "Systemd state unavailable")
    fields = {}
    for line in out.stdout.splitlines():
        key, sep, val = line.partition("=")
        if key in PROPS and sep:
            need(key not in fields, "Duplicate systemd property")
            fields[key] = val.strip()
    need(set(fields) == set(PROPS) and fields["Id"] == unit and
         fields["LoadState"] == "loaded" and
         fields["ActiveState"] in ("active", "inactive") and
         fields["FragmentPath"].startswith(("/etc/systemd/system/",
                                           "/usr/lib/systemd/system/",
                                           "/lib/systemd/system/")) and
         "\x00" not in fields["FragmentPath"] and
         fields["UnitFileState"] in (
             "enabled","disabled","static","indirect","generated","linked",
             "enabled-runtime","masked-runtime","alias"
         ),
         "Incomplete/unexpected systemd unit state")
    if fields["ActiveState"] == "active":
        need(HEX32.fullmatch(fields["InvocationID"].lower()) is not None,
             "Active unit lacks stable InvocationID")
    return fields


def snapshot():
    return {unit:unit_state(unit) for unit in UNITS}


def validate_state_rows(rows):
    need(type(rows) is dict and set(rows) == set(UNITS),
         "Journal service list differs from reviewed units")
    for unit, row in rows.items():
        need(type(row) is dict and set(row) == set(PROPS) and
             row["Id"] == unit and row["LoadState"] == "loaded" and
             row["ActiveState"] in ("active","inactive") and
             type(row["FragmentPath"]) is str and
             row["FragmentPath"].startswith((
                 "/etc/systemd/system/","/usr/lib/systemd/system/",
                 "/lib/systemd/system/")) and
             type(row["InvocationID"]) is str and
             type(row["UnitFileState"]) is str and
             not any("\x00" in x for x in row.values()),
             "Malformed ownership journal state")
        if row["ActiveState"] == "active":
            need(HEX32.fullmatch(row["InvocationID"].lower()) is not None,
                 "Journal active service lacks InvocationID")


def plan_from_receipt(receipt):
    need(type(receipt) is dict and receipt.get("target_host") and
         receipt.get("approved_units") == list(UNITS),
         "Unrelated Command3 restart witness")
    need(receipt.get("result") ==
         "COMMAND3_FIVE_SERVICE_RESTARTS_ACTIVE_VERIFIED" and
         receipt.get("completed") == list(UNITS) and
         receipt.get("all_five_active_after_restart_verified") is True,
         "Partial or unverified service restart cannot be auto-undone")
    before = receipt.get("service_states_before")
    after = receipt.get("service_states_after")
    validate_state_rows(before)
    validate_state_rows(after)
    now = snapshot()
    actions, blocked, historical = [], [], []
    for unit in UNITS:
        prior, post, current = before[unit], after[unit], now[unit]
        if prior["ActiveState"] == "active":
            historical.append(unit)
            actions.append({"unit":unit, "action":"PRESERVE_PREEXISTING_ACTIVE"})
            continue
        if prior["UnitFileState"] != post["UnitFileState"] or (
                prior["FragmentPath"] != post["FragmentPath"]):
            blocked.append(unit)
            actions.append({"unit":unit,"action":"BLOCKED_UNIT_CHANGED_DURING_RESTART"})
            continue
        if current == post and post["ActiveState"] == "active":
            actions.append({"unit":unit,"action":"STOP_ONLY_DEPLOYMENT_STARTED"})
        elif current["ActiveState"] == "inactive" and (
                current["FragmentPath"] == post["FragmentPath"] and
                current["UnitFileState"] == post["UnitFileState"]):
            actions.append({"unit":unit,"action":"KEEP_ALREADY_INACTIVE"})
        else:
            blocked.append(unit)
            actions.append({"unit":unit,"action":"BLOCKED_POST_RESTART_DRIFT"})
    return {
        "result":"COMMAND3_SCOPED_SERVICE_UNDO_PLAN",
        "actions":actions,
        "blocked_units":blocked,
        "preexisting_active_units_preserved":historical,
        "all_services_can_be_reverted":not historical and not blocked,
        "some_runtime_restarts_irreversible":bool(historical),
        "no_mutations_performed":True,
        "full_host_rollback_complete":False
    }


def trusted_receipt(path):
    p=Path(path)
    need(p.is_absolute() and p.name.startswith("command3-five-units.") and
         p.name.endswith(".json") and
         not any(x.is_symlink() for x in (p,*p.parents)),
         "Wrong restart witness path")
    for parent in (p.parent,p.parent.parent):
        s=parent.stat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and
             not s.st_mode & 0o022,
             "Restart receipt parent directory is not root protected")
    s=p.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and
         s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and
         0 < s.st_size < 131072, "Restart receipt missing or unprotected")
    return json.loads(p.read_text())


def no_live_guest():
    try:
        response = subprocess.run(
            ["virsh","-c","qemu:///system","list","--state-running","--name"],
            capture_output=True,text=True,timeout=20,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ServiceOwnershipBlocked("Cannot prove guest inactivity") from exc
    need(response.returncode == 0 and not response.stdout.strip(),
         "Cannot stop service while libvirt guest running")


def stop_owned(unit):
    need(unit in UNITS,"Unknown service")
    try:
        done=subprocess.run(["systemctl","stop",unit],
            capture_output=True,text=True,timeout=60,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ServiceOwnershipBlocked("Exact systemctl stop uncertain") from exc
    need(done.returncode == 0,
         "Exact systemctl stop failed")


def rollback_plan(path,approved_host):
    host_guard(approved_host)
    receipt=trusted_receipt(path)
    need(receipt["target_host"] == approved_host.lower().split(".",1)[0],
         "Service witness belongs to different host")
    return plan_from_receipt(receipt)


def rollback(path,approved_host):
    need(os.geteuid()==0 and sys.stdin.isatty(),
         "Unit reversal needs root and direct operator TTY")
    witness=trusted_receipt(path)
    host=host_guard(approved_host)
    need(witness.get("target_host")==host,"Different receipt host")
    plan=plan_from_receipt(witness)
    need(not plan["blocked_units"],
         "Unit changed since reviewed restart; no partial automatic rollback")
    no_live_guest()
    print(json.dumps(plan,indent=2,sort_keys=True),flush=True)
    phrase="UNDO-ONLY-DEPLOYMENT-STARTED-CAPE-SERVICES"
    need(input("Type "+phrase+": ").strip()==phrase,
         "Operator declined service state reversal")
    need(rollback_plan(path,approved_host)==plan,
         "Unit state or witness drift after approval")
    no_live_guest()
    # A journal already identifies the exact permitted unit state effects.
    # First write an atomic root-private action witness; do not proceed
    # without crash evidence. Separate file never changes original journal.
    receipt_path=Path(path)
    journal_path=receipt_path.with_name(
        "command3-service-undo."+uuid.uuid4().hex+".json")
    record={"result":"COMMAND3_SCOPED_UNDO_STARTED",
            "source_receipt":receipt_path.name,
            "target_host":host,"completed":[],"pending":None}
    import command3_cape_restart_verified as restart
    restart.record(journal_path,record,initial=True)
    try:
        for action in plan["actions"]:
            if action["action"]!="STOP_ONLY_DEPLOYMENT_STARTED":
                continue
            unit=action["unit"]
            need(plan_from_receipt(trusted_receipt(path)) == plan,
                 "Unit state drift during scoped reversal")
            no_live_guest()
            record["pending"]=unit
            restart.record(journal_path,record)
            stop_owned(unit)
            after=unit_state(unit)
            need(after["ActiveState"]=="inactive",
                 "Unit remained active after scoped stop")
            record["completed"].append(unit)
            record["pending"]=None
            restart.record(journal_path,record)
        record["result"]="COMMAND3_SCOPED_NEWLY_STARTED_SERVICES_STOPPED"
        restart.record(journal_path,record)
        return {"result":record["result"],"receipt":str(journal_path),
                "stopped_units":record["completed"],
                "preexisting_active_services_preserved":
                    plan["preexisting_active_units_preserved"],
                "full_deployment_rollback_complete":False}
    except Exception as exc:
        record["result"]="COMMAND3_SCOPED_UNDO_PARTIAL_OR_UNKNOWN"
        record["error_type"]=type(exc).__name__
        restart.record(journal_path,record)
        raise ServiceOwnershipBlocked(
            "Partial service rollback retained for manual review") from None


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("plan","rollback"),default="plan")
    parser.add_argument("--approved-host",required=True)
    parser.add_argument("--restart-receipt",type=Path,required=True)
    args=parser.parse_args()
    try:
        doc=(rollback_plan(args.restart_receipt,args.approved_host)
             if args.mode=="plan" else
             rollback(args.restart_receipt,args.approved_host))
        print(json.dumps(doc,indent=2,sort_keys=True))
        return 0
    except (ServiceOwnershipBlocked,ValueError,OSError,KeyError) as exc:
        print(json.dumps({
            "result":"COMMAND3_SCOPED_SERVICE_UNDO_BLOCKED",
            "error_type":type(exc).__name__,
            "no_blind_retry_or_other_units_modified":True
        }),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
