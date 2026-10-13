#!/usr/bin/env python3
"""Command3 restart ONLY the five operator-approved CAPE/Suricata units.

New-host-only, root interactive. No firewall, routing, guest, libvirt,
installer, network or TPM mutations. Do not infer sample-analysis safety.

PLAN: read-only exact unit + enabled tmpfs prerequisites; no restart.
RESTART: one explicit overall consent; root-private durable witness;
         recheck approved files/units/mount; restart exact units in the
         operator's actual SSL55 order with bounded timeout and per-step
         receipts, then verify each unit stays ActiveState=active.
VERIFY: read-only current status (not evidence that this tool ran).

A partial/failed restart leaves durable PARTIAL_OR_UNKNOWN and never
automatically retries or rolls back service/config state.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time
import uuid

import command3_cape_services as services
import command3_cape_tmpfs as tmpfs
import command3_cape_routing as routing

UNITS=services.OPERATOR_ORDER
RECEIPTS=Path("/var/lib/cape-command3-restart-receipts")
APPROVAL="RESTART-FIVE-CAPE-SURICATA-UNITS-ON-NEW-HOST"
WAIT_SECONDS=90

class RestartBlocked(RuntimeError):
    pass

def need(value,why):
    if not value:
        raise RestartBlocked(why)

def target_host(requested):
    here=socket.gethostname().split(".",1)[0].lower()
    need(here not in ("cse-ssl-55","ssl-55") and
         type(requested) is str and
         requested.lower().split(".",1)[0]==here,
         "Service restart forbidden on protected SSL-55 or different host")
    return here

def inspect(routing_conf,cuckoo_conf):
    target=Path(routing_conf)
    route_raw,_=routing.read_conf(target)
    # Operator target reference is explicit. Check current file has the
    # expected exact settings, but this isn't proof of network containment.
    proposed,changes=routing.proposed_diff(route_raw)
    config_is_exact=(proposed == route_raw and changes==[])
    t=tmpfs.assess(Path(cuckoo_conf))
    states=[services.systemd_status(unit) for unit in UNITS]
    need(len(states)==len(UNITS) and
         [x["unit"] for x in states]==list(UNITS),
         "Installed systemd service identities differ from operator list")
    return {
        "result":"COMMAND3_RESTART_PREFLIGHT_READ_ONLY",
        "approved_five_units":list(UNITS),
        "current_active_states":[{"unit":x["unit"],
                                   "loaded":x["loaded"],
                                   "active":x["active"],
                                   "state":x["active_state"],
                                   "last_result":x["last_result"]}
                                  for x in states],
        "all_five_units_loaded":all(x["loaded"] and
                                    x["installed_fragment"] for x in states),
        "routing_reference_matches_operator_values":config_is_exact,
        "routing_file_sha256":routing.guard.sha(route_raw),
        "tmpfs_ready":bool(t.get("cape_tmpfs_prerequisite_ready",False)),
        "tmpfs_readiness":t,
        "host_modified":False,
        "no_vm_start_or_snapshot_revert":True,
        "safe_to_analyze_untrusted_samples":False,
        "restart_executed":False,
    }

def admitted_status(report):
    need(report["all_five_units_loaded"],
         "All five exact systemd units must exist before any restart")
    need(report["tmpfs_ready"],
         "CAPE tmpfs mount/owner/free-space preflight failed")
    need(report["routing_reference_matches_operator_values"],
         "CAPE routing config differs from operator target: review before restart")

def witness_dir(path):
    folder=Path(path)
    need(folder.is_absolute() and
         not any(p.is_symlink() for p in (folder,*folder.parents)),
         "Restart receipt location must be absolute non-symlink path")
    need(folder.parent.is_dir() and
         folder.parent.stat().st_uid==0 and
         not folder.parent.stat().st_mode&0o022,
         "Root-private receipt parent required")
    if not folder.exists():
        folder.mkdir(mode=0o700)
    st=folder.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
         stat.S_IMODE(st.st_mode)==0o700 and
         st.st_nlink>=2,
         "Root-private restart receipt folder must be mode 0700")
    return folder

def record(path,document,initial=False):
    raw=(json.dumps(document,sort_keys=True,indent=2)+"\n").encode()
    need(len(raw)<131072,"Oversize service restart witness")
    if initial:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
                   os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(fd,"wb") as output:
            output.write(raw);output.flush();os.fsync(output.fileno())
    else:
        st=path.stat()
        need(not path.is_symlink() and stat.S_ISREG(st.st_mode) and
             st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600 and
             st.st_nlink==1,"Existing restart witness not root-private")
        from tempfile import mkstemp
        fd,tmp=mkstemp(prefix=".command3-restart-",dir=str(path.parent))
        try:
            with os.fdopen(fd,"wb") as output:
                output.write(raw);output.flush()
                os.fchmod(output.fileno(),0o600)
                os.fsync(output.fileno())
            os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def restart_exact(unit):
    need(unit in UNITS,"Non-operator service target refused")
    try:
        p=subprocess.run(["systemctl","restart",unit],
                         check=False,stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,timeout=60)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise RestartBlocked("Systemd restart invocation failed for "+unit+
                             ": "+type(exc).__name__) from exc
    need(p.returncode==0,"systemctl restart returned nonzero for "+unit)

def wait_active(timeout=WAIT_SECONDS):
    deadline=time.monotonic()+timeout
    previous=None
    while True:
        status=[services.systemd_status(unit) for unit in UNITS]
        if all(item["active"] and item["loaded"] and
               item["last_result"] in ("success","") for item in status):
            # A brief confirmation sample catches immediate restart loops.
            time.sleep(1)
            again=[services.systemd_status(unit) for unit in UNITS]
            if all(v["active"] and v["loaded"] and
                   v["last_result"] in ("success","") for v in again):
                return again
        previous=status
        if time.monotonic()>=deadline:
            break
        time.sleep(3)
    need(False,"Five-service verification timed out or auto-restart loop")
    return previous

def apply(host,routing_conf,cuckoo_conf,receipts):
    need(os.geteuid()==0 and sys.stdin.isatty(),
         "Five-service restart requires root interactive operator")
    name=target_host(host)
    first=inspect(routing_conf,cuckoo_conf)
    admitted_status(first)
    print(json.dumps(first,sort_keys=True,indent=2),flush=True)
    need(input("Type "+APPROVAL+" to restart exact services: ")==APPROVAL,
         "Operator declined service restart")
    second=inspect(routing_conf,cuckoo_conf)
    admitted_status(second)
    need(second["routing_file_sha256"]==first["routing_file_sha256"] and
         second["approved_five_units"]==first["approved_five_units"] and
         second["all_five_units_loaded"] and second["tmpfs_ready"],
         "Routing/units/tmpfs changed after approval")
    folder=witness_dir(receipts)
    path=folder/("command3-five-units."+uuid.uuid4().hex+".json")
    document={
        "result":"COMMAND3_FIVE_SERVICE_RESTART_STARTED",
        "target_host":name,"approved_units":list(UNITS),
        "completed":[],"current_step":None,
        "routing_sha256":first["routing_file_sha256"],
        "guest_or_snapshot_modified":False,
        "malware_analysis_authorized":False,
        "all_five_active_after_restart_verified":False,
    }
    record(path,document,initial=True)
    try:
        for unit in UNITS:
            document["current_step"]=unit
            record(path,document)
            # Re-evaluate tmpfs and routing before every service change.
            latest=inspect(routing_conf,cuckoo_conf)
            admitted_status(latest)
            need(latest["routing_file_sha256"]==first["routing_file_sha256"],
                 "Routing config changed while restarting services")
            restart_exact(unit)
            document["completed"].append(unit)
            document["current_step"]=None
            record(path,document)
        final=wait_active()
        need([v["unit"] for v in final]==list(UNITS),
             "Unexpected systemd status listing after restart")
        document["result"]="COMMAND3_FIVE_SERVICE_RESTARTS_ACTIVE_VERIFIED"
        document["all_five_active_after_restart_verified"]=True
        record(path,document)
        return {
            "result":document["result"],
            "witness":str(path),
            "restarted_in_operator_order":list(UNITS),
            "systemd_units_active_at_check":True,
            "guest_or_snapshot_modified":False,
            "network_containment_or_TPM_revert_attested":False,
            "CAPE_READY_FOR_SAMPLE_ANALYSIS":False,
        }
    except Exception as exc:
        document["result"]="COMMAND3_RESTART_PARTIAL_OR_UNKNOWN"
        document["error_type"]=type(exc).__name__
        record(path,document)
        raise RestartBlocked(
            "PARTIAL_OR_UNKNOWN: check root-private restart receipt, "
            "unit journal and tmpfs; never blindly retry") from None

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","restart","verify"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--routing-conf",type=Path,default=routing.CONF)
    p.add_argument("--cuckoo-conf",type=Path,default=tmpfs.CONF)
    p.add_argument("--receipt-dir",type=Path,default=RECEIPTS)
    a=p.parse_args()
    try:
        # A read-only plan is allowed on SSL55 for operator verification.
        if a.mode=="restart":
            result=apply(a.approved_host,a.routing_conf,
                         a.cuckoo_conf,a.receipt_dir)
        else:
            result=inspect(a.routing_conf,a.cuckoo_conf)
            result["result"]=("COMMAND3_FIVE_SERVICE_READONLY_VERIFY" if
                              a.mode=="verify" else
                              "COMMAND3_FIVE_SERVICE_RESTART_PLAN_ONLY")
            result["current_systemd_healthy"] = all(
                u["loaded"] and u["active"] for
                u in result["current_active_states"])
        print(json.dumps(result,indent=2,sort_keys=True),flush=True)
        return 0
    except Exception as exc:
        print(json.dumps({"result":"COMMAND3_FIVE_SERVICE_RESTART_BLOCKED",
                          "error_type":type(exc).__name__,
                          "review_private_receipt_if_restart_invoked":True},
                         sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
