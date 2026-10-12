#!/usr/bin/env python3
"""OTHER-HOST exact-VM CAPE Agent trusted NAT Windows guest APPLY request.

Uses stage receipt from command2_portable_nat_agent_setup_transport.py.
The configured golden Windows image, NOT reconstructed app settings, is
kept. After verifying source hashes, live guest UUID + MAC-bound Agent,
issue only a fixed PowerShell benign NAT/unique-hostname script command.
The CAPE Agent async execution request is NOT evidence that Windows
finished, rebooted, got a reserved IP or passed HTTPS. Never retry after
any attempt; durable root-private intent is written/fynced BEFORE POST.

No malware, sample execution, arbitrary supplied command, VM restart,
CAPE snapshot/revert, disabled Windows protection or firewall edits.
This helper cannot solve TPM-backed BitLocker compatibility by itself.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlencode

import command2_portable_nat_agent_setup_transport as transport

INTENT_FORMAT="COMMAND2_APPROVED_ONE_WINDOWS_NAT_APPLY_REQUEST_V1"
class GuestExecuteBlocked(RuntimeError):pass
def need(cond,reason):
    if not cond: raise GuestExecuteBlocked(reason)

def script_command(sha):
    need(isinstance(sha,str) and len(sha)==64 and
         all(x in "0123456789abcdef" for x in sha),
         "Exact golden NAT JSON SHA256 required")
    return ("powershell.exe -NoProfile -NonInteractive "
        "-ExecutionPolicy Bypass "
        "-File C:/CAPE_NAT2/command2_guest_master_nat.ps1 "
        "-ConfigFile C:/CAPE_NAT2/nat-config.json "
        "-ExpectedSha256 "+sha+
        " -Mode Apply -ApproveBenignNat -ApproveRename "
        "-ApproveLegacyMasterIpTransition")

def trusted_stage_json(stage):
    """Admit exact private receipt file, including real ownership."""
    need(stage.is_file() and not stage.is_symlink() and
         stage.stat().st_size<32*1024 and
         stage.stat().st_nlink==1 and
         stage.stat().st_uid==0 and stage.stat().st_mode&0o777==0o600,
         "Exact root-private verified per-VM upload receipt missing")
    return json.loads(stage.read_text(encoding="utf-8"))

def authorized_stage(host,journal,vm,nat_iso,evidence_dir):
    folder=transport.verified_evidence_folder(evidence_dir)
    stage=folder/(vm+transport.STAGE_SUFFIX)
    data=trusted_stage_json(stage)
    before=transport.inspect(host,journal,vm,nat_iso)
    need(data.get("format")==
         "COMMAND2_TRUSTED_WINDOWS_NAT_UPLOAD_ONLY_V1" and
         data.get("approved_host")==host and
         data.get("vm")==vm and
         data.get("vm_uuid")==before["uuid"] and
         data.get("mac")==before["mac"] and
         data.get("bootstrap_ip")==before["bootstrap_ip"] and
         data.get("gateway")==before["source_gateway"] and
         data.get("target_ip")==before["target_nat_ipv4"] and
         data.get("json_sha256")==before["iso_config_sha256"] and
         data.get("script_sha256")==before["approved_script_sha256"] and
         data.get("remote_files")==[
           "C:/CAPE_NAT2/nat-config.json",
           "C:/CAPE_NAT2/command2_guest_master_nat.ps1"] and
         data.get("powershell_executed") is False and
         data.get("windows_hostname_ipv4_verified") is False,
         "Stage receipt does not match currently MAC-authenticated exact VM")
    # Configured clones are NOT allowed to change guest identity after
    # capturing a running checkpoint; snapshot later, once fully verified.
    need(not transport.attach.virsh(
         "snapshot-list",vm,"--name").strip(),
         "Clone has existing snapshots: do not change Windows networking")
    target=folder/(vm+transport.INTENT_SUFFIX)
    need(not target.exists() and not target.is_symlink(),
         "Windows setup attempt already journaled. STOP; never re-execute.")
    return {"result":"COMMAND2_GUEST_NAT_APPLY_INTENT_PREFLIGHT_ONLY",
        "vm":vm,"host":host,
        "uuid":before["uuid"],"mac":before["mac"],
        "source_gateway":before["source_gateway"],
        "bootstrap_ip":before["bootstrap_ip"],
        "target_nat_ip":before["target_nat_ipv4"],
        "json_sha256":before["iso_config_sha256"],
        "script_sha256":before["approved_script_sha256"],
        "stage_receipt":str(stage),
        "future_execution_intent":str(target),
        "fixed_command_sha256":hashlib.sha256(
           script_command(before["iso_config_sha256"]).encode()).hexdigest(),
        "guest_powershell_executed":False,
        "guest_hostname_ipv4_https_independently_verified":False,
        "guest_restart_performed":False,
        "safe_for_malware_execution":False}

def request_execute(ip,gateway,json_sha256):
    # The only command is generated HERE from a SHA-pinned known file.
    # No operator-supplied commandline or shell interpolation is accepted.
    command=script_command(json_sha256)
    body=urlencode({"command":command,"async":"1"}).encode("ascii")
    answer=transport.agent_post(ip,gateway,"/execute",body,
                                "application/x-www-form-urlencoded")
    need(answer.get("message")=="Successfully executed command",
         "CAPE Agent did not acknowledge async benign setup request")
    return {"http_accepted_async_powerShell_request":True,
            "powershell_process_exit_status_verified":False,
            "windows_dhcp_ipv4_hostname_https_verified":False}

def apply(host,journal,vm,nat_iso,evidence_dir):
    need(sys.stdin.isatty(),"Direct operator TTY required for Windows network edits")
    before=authorized_stage(host,journal,vm,nat_iso,evidence_dir)
    print(json.dumps(before,sort_keys=True,indent=2),flush=True)
    phrase="EXECUTE-ONLY-TRUSTED-WINDOWS-NAT-SETUP-"+vm.upper()
    need(input("Type "+phrase+" to request approved guest setup: ")==phrase,
         "Operator did not approve exact guest PowerShell execution")
    again=authorized_stage(host,journal,vm,nat_iso,evidence_dir)
    need(again==before,"Guest Agent/DHCP/ISO/receipt changed after approval")
    target=Path(before["future_execution_intent"])
    # Durable conservative intent first: if power/network loss happens
    # before HTTP, operator still must manually review the guest.
    obj={"format":INTENT_FORMAT,
         "vm":vm,"host":host,"uuid":before["uuid"],"mac":before["mac"],
         "bootstrap_ip":before["bootstrap_ip"],
         "target_nat_ip":before["target_nat_ip"],
         "stage_receipt_sha256":hashlib.sha256(
             Path(before["stage_receipt"]).read_bytes()).hexdigest(),
         "fixed_command_sha256":before["fixed_command_sha256"],
         "json_sha256":before["json_sha256"],
         "execution_started_or_unknown":True,
         "windows_guest_change_completed":False,
         "guest_hostname_dhcp_and_https_verified":False,
         "no_retry_even_if_connection_lost":True}
    fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        json.dump(obj,f,sort_keys=True,indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    dirfd=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(dirfd)
    finally: os.close(dirfd)
    try:
        transport_info=request_execute(before["bootstrap_ip"],
                                       before["source_gateway"],
                                       before["json_sha256"])
    except Exception as exc:
        raise GuestExecuteBlocked(
          "EXACT_WINDOWS_SETUP_REQUEST_MAY_HAVE_RUN: durable intent exists; "
          "do not retry, reboot or call sample analysis; "+
          type(exc).__name__) from exc
    return {**before,**transport_info,
        "result":"COMMAND2_EXACT_WINDOWS_NAT_ASYNC_REQUEST_ACKNOWLEDGED",
        "intent_receipt":str(target),
        "real_guest_firstboot_still_requires_independent_acceptance":True}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","execute"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--vm",required=True)
    p.add_argument("--nat-iso",type=Path,required=True)
    p.add_argument("--evidence-dir",type=Path,required=True)
    a=p.parse_args()
    try:
        result=(apply(a.approved_host,a.journal,a.vm,a.nat_iso,a.evidence_dir)
                if a.mode=="execute" else authorized_stage(
                   a.approved_host,a.journal,a.vm,a.nat_iso,a.evidence_dir))
        print(json.dumps(result,sort_keys=True,indent=2),flush=True)
        return 0
    except (GuestExecuteBlocked,transport.TransportBlocked,
            transport.attach.NatAttachBlocked,
            transport.attach.workflow.WorkflowBlocked,
            OSError,ValueError,TypeError,KeyError,json.JSONDecodeError) as exc:
        print(json.dumps({"result":"COMMAND2_WINDOWS_NAT_EXECUTE_BLOCKED",
          "reason":str(exc),"no_automatic_retry":True,
          "no_guest_reboot_or_snapshot_requested":True},
          sort_keys=True),file=sys.stderr,flush=True)
        return 2
if __name__=="__main__": raise SystemExit(main())
