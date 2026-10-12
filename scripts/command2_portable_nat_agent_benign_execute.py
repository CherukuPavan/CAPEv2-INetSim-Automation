#!/usr/bin/env python3
"""OTHER-host, user-approved benign Windows NAT setup via exact CAPE Agent.

For the original user golden-master clones, the existing CAPE Agent can
perform a reviewable hostname/DHCP operation without manually recreating
apps or registry settings. ONLY a previously pinned and uploaded approved
PowerShell file is executed using a hard-coded command shape. Requires
root-private immutable upload witness, exact VM UUID/MAC, strict host
ARP+Agent identity, one guest running, source master shutoff and typed
permission. No arbitrary command string from user or JSON ever reaches
Agent. No malware, reboots, snapshots, TPM ops, firewall/defender changes.

Apply writes a durable one-time intent BEFORE any guest-side execution.
A guest IP transition may end the HTTP session; treat every error after
the intent as POSSIBLY APPLIED, do not auto retry or roll back. External
read-only Windows and host Agent verification must follow. The existing
guest NAT PowerShell refuses unreviewed inherited static IPv4.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import urllib.parse

import command2_portable_nat_agent_setup_transport as transport

class BenignExecuteBlocked(RuntimeError):pass
def need(condition,reason):
    if not condition:raise BenignExecuteBlocked(reason)

def private_receipt(path):
    p=Path(path)
    need(p.is_absolute() and p.is_file() and not p.is_symlink(),
         "Expected existing root-private Windows media upload receipt")
    s=p.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and
         s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and
         0<s.st_size<=128*1024,
         "Windows upload receipt owner/mode/bounds unsafe")
    return json.loads(p.read_text(encoding="utf-8"))

def inspect(host,journal,vm,iso,evidence_dir):
    evidence=transport.verified_evidence_folder(evidence_dir)
    state=transport.inspect(host,journal,vm,iso)
    upload=evidence/(vm+transport.STAGE_SUFFIX)
    stage=private_receipt(upload)
    expected={
        "approved_host":host,"vm":vm,"vm_uuid":state["uuid"],
        "mac":state["mac"],"bootstrap_ip":state["bootstrap_ip"],
        "gateway":state["source_gateway"],
        "target_ip":state["target_nat_ipv4"],
        "json_sha256":state["iso_config_sha256"],
        "script_sha256":state["approved_script_sha256"]}
    need(stage.get("format")=="COMMAND2_TRUSTED_WINDOWS_NAT_UPLOAD_ONLY_V1" and
         all(stage.get(k)==v for k,v in expected.items()) and
         stage.get("only_trusted_setup_files_uploaded") is True and
         stage.get("powershell_executed") is False and
         stage.get("remote_files")==[
           "C:/CAPE_NAT2/nat-config.json",
           "C:/CAPE_NAT2/command2_guest_master_nat.ps1"],
         "Verified immutable exact-VM Windows benign upload witness differs")
    intent=evidence/(vm+transport.INTENT_SUFFIX)
    need(not intent.exists() and not intent.is_symlink(),
         "Prior guest execution intent exists; never rerun blindly")
    return {"result":"COMMAND2_EXACT_WINDOWS_BENIGN_NAT_EXECUTION_PLAN_ONLY",
            "vm":vm,"target_nat_ip":state["target_nat_ipv4"],
            "bootstrap_ip":state["bootstrap_ip"],
            "gateway":state["source_gateway"],
            "upload_receipt_sha256":hashlib.sha256(upload.read_bytes()).hexdigest(),
            "script_sha256":state["approved_script_sha256"],
            "config_sha256":state["iso_config_sha256"],
            "execution_attempted":False,
            "Windows_DHCP_or_hostname_changed":False,
            "Windows_reboot_triggered":False,
            "master_and_other_clones_not_targeted":True,
            "malware_analysis_authorized":False}

def command(data):
    # Reject anything not derived from exact SHA-pinned local transport.
    digest=data["config_sha256"]
    need(re.fullmatch(r"[0-9a-f]{64}",digest) is not None,
         "Untrusted Windows NAT configuration SHA")
    return (
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        "-File C:/CAPE_NAT2/command2_guest_master_nat.ps1 "
        "-ConfigFile C:/CAPE_NAT2/nat-config.json "
        "-ExpectedSha256 "+digest+
        " -Mode Apply -ApproveBenignNat -ApproveRename"
    )

def apply(host,journal,vm,iso,evidence_dir):
    need(sys.stdin.isatty(),"Operator terminal required for Windows change")
    first=inspect(host,journal,vm,iso,evidence_dir)
    print(json.dumps(first,sort_keys=True,indent=2),flush=True)
    approved="EXECUTE-BENIGN-NAT-WINDOWS-SETUP-"+vm.upper()
    need(input("Type "+approved+" to change only that Windows guest: ")==
         approved,"Explicit benign Windows guest configuration denied")
    evidence=transport.verified_evidence_folder(evidence_dir)
    need(inspect(host,journal,vm,iso,evidence_dir)==first,
         "VM Agent/IP/ARP/upload receipt changed after consent")
    intent=evidence/(vm+transport.INTENT_SUFFIX)
    # Persist intent BEFORE remote request. Even lost replies cannot be
    # interpreted as proof that the guest was unchanged.
    obj={"format":"COMMAND2_BENIGN_WINDOWS_NAT_EXECUTION_INTENT_V1",
         "approved_host":host,"vm":vm,"target_nat_ip":first["target_nat_ip"],
         "bootstrap_ip":first["bootstrap_ip"],
         "upload_receipt_sha256":first["upload_receipt_sha256"],
         "command_sha256":hashlib.sha256(command(first).encode()).hexdigest(),
         "operator_consented":True,
         "guest_network_change_may_be_partial":True,
         "do_not_retry_without_manual_reconciliation":True}
    fd=os.open(intent,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        json.dump(obj,f,sort_keys=True,indent=2)
        f.write("\n");f.flush();os.fsync(f.fileno())
    dfd=os.open(evidence,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    body=urllib.parse.urlencode({"command":command(first)}).encode("ascii")
    try:
        response=transport.agent_post(
             first["bootstrap_ip"],first["gateway"],
             "/execute",body,"application/x-www-form-urlencoded")
        need(response.get("message")=="Successfully executed command",
             "CAPE Agent did not confirm selected guest PowerShell command")
        return {"result":"COMMAND2_GUEST_BENIGN_NAT_POWERSHELL_EXECUTION_ATTEMPTED",
                "vm":vm,"intent":str(intent),
                "guest_ipv4_must_be_verified_after_possible_transition":True,
                "hostname_rename_may_require_separate_safe_reboot":True,
                "snapshot_or_tpm_changed":False,
                "CAPE_READY":False,
                "malware_authorized":False}
    except Exception as exc:
        raise BenignExecuteBlocked(
             "GUEST_COMMAND_SENT_OR_MAY_HAVE_RUN_PRESERVE_INTENT: "
             "do NOT repeat. Inspect Windows IP/hostname/Agent/PowerShell "
             "output on this clone before any continuation: "+str(exc)) from exc

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","apply"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--vm",required=True)
    p.add_argument("--nat-iso",type=Path,required=True)
    p.add_argument("--evidence-dir",type=Path,required=True)
    a=p.parse_args()
    try:
        result=apply(a.approved_host,a.journal,a.vm,a.nat_iso,
                     a.evidence_dir) if a.mode=="apply" else inspect(
                     a.approved_host,a.journal,a.vm,a.nat_iso,a.evidence_dir)
        print(json.dumps(result,indent=2,sort_keys=True),flush=True)
        return 0
    except (BenignExecuteBlocked,transport.TransportBlocked,
            transport.attach.NatAttachBlocked,OSError,ValueError,TypeError,
            KeyError,json.JSONDecodeError) as exc:
        print(json.dumps({"result":"COMMAND2_BENIGN_WINDOWS_NAT_EXECUTE_BLOCKED",
              "reason":str(exc),
              "do_not_auto_retry_guest_changes":True,
              "snapshot_and_cape_not_changed":True},sort_keys=True),
              file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
