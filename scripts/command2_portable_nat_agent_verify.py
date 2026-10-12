#!/usr/bin/env python3
"""OTHER-HOST independent CAPE Agent Windows master-NAT acceptance verifier.

Requires exactly one running clone, exact saved/live e1000e MAC+UUID,
verified L2 neighbor MAC and elevated CAPE Agent at RESERVED NAT IPv4.
Read-only *guest script* is executed through the reviewed CAPE Agent
/execute API with -Mode Verify -RequireHTTPS, and its bounded JSON result
must report verified hostname, DHCP IP, gateway, DNS and real HTTPS.
It NEVER executes guest setup/renew/rename, invokes snapshot/revert,
reboots, edits host or authorizes unrestricted malware sample internet.
A previous durable Windows apply intent must exist; this is not a retry.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import os
import re
import sys
from urllib.parse import urlencode

import command2_portable_nat_agent_execute as approved
import command2_portable_nat_agent_setup_transport as transport

SUFFIX=".command2-windows-nat-independent-verified.json"
class GuestVerifyBlocked(RuntimeError): pass
def need(ok,why):
    if not ok: raise GuestVerifyBlocked(why)

def validate_intent(before,evidence):
    folder=transport.verified_evidence_folder(evidence)
    vm=before["vm"]
    stage=folder/(vm+transport.STAGE_SUFFIX)
    original=approved.trusted_stage_json(stage)
    needed=folder/(vm+transport.INTENT_SUFFIX)
    intent=approved.trusted_stage_json(needed)
    need(intent.get("format")==approved.INTENT_FORMAT and
         intent.get("vm")==vm and intent.get("host")==before["host"] and
         intent.get("uuid")==before["uuid"] and
         intent.get("mac")==before["mac"] and
         intent.get("target_nat_ip")==before["target_nat_ip"] and
         intent.get("json_sha256")==before["json_sha256"] and
         intent.get("fixed_command_sha256")==
         before["fixed_command_sha256"] and
         intent.get("stage_receipt_sha256")==
         hashlib.sha256(stage.read_bytes()).hexdigest() and
         intent.get("execution_started_or_unknown") is True and
         intent.get("windows_guest_change_completed") is False and
         intent.get("guest_hostname_dhcp_and_https_verified") is False and
         original.get("vm")==vm and
         original.get("json_sha256")==before["json_sha256"] and
         original.get("script_sha256")==before["script_sha256"],
         "The exact approved guest apply intent/stage changed; STOP")
    dst=folder/(vm+SUFFIX)
    need(not dst.exists() and not dst.is_symlink(),
         "Windows NAT verification receipt already exists; avoid overwrites")
    return dst

def ready(host,journal,vm,nat_iso,evidence):
    # Do not call approved.authorized_stage: it MUST refuse a second
    # apply now that the durable execution-intent exists.
    folder=transport.verified_evidence_folder(evidence)
    stage=folder/(vm+transport.STAGE_SUFFIX)
    stored=approved.trusted_stage_json(stage)
    current=transport.inspect(host,journal,vm,nat_iso)
    before={
       "vm":vm,"host":host,"uuid":current["uuid"],"mac":current["mac"],
       "source_gateway":current["source_gateway"],
       "target_nat_ip":current["target_nat_ipv4"],
       "json_sha256":current["iso_config_sha256"],
       "script_sha256":current["approved_script_sha256"],
       "fixed_command_sha256":hashlib.sha256(
          approved.script_command(current["iso_config_sha256"]).encode()).hexdigest()}
    need(current["bootstrap_ip"]==before["target_nat_ip"],
         "Windows CAPE Agent not yet on verified DHCP NAT IP; "
         "do not interpret legacy master bootstrap as successful conversion")
    need(stored.get("approved_host")==host and stored.get("vm")==vm and
         stored.get("vm_uuid")==before["uuid"] and
         stored.get("mac")==before["mac"] and
         stored.get("target_ip")==before["target_nat_ip"] and
         stored.get("json_sha256")==before["json_sha256"],
         "Approved Windows setup upload receipt differs from actual guest")
    dst=validate_intent(before,evidence)
    return before,dst

def verify_command(config_sha):
    need(re.fullmatch(r"[0-9a-f]{64}",config_sha or "") is not None,
         "Cannot verify arbitrary Windows setup configuration")
    return ("powershell.exe -NoProfile -NonInteractive "
       "-ExecutionPolicy Bypass "
       "-File C:/CAPE_NAT2/command2_guest_master_nat.ps1 "
       "-ConfigFile C:/CAPE_NAT2/nat-config.json "
       "-ExpectedSha256 "+config_sha+" -Mode Verify -RequireHTTPS")

def witness(ip,source,sha,vm):
    command=verify_command(sha)
    body=urlencode({"command":command,
                    "encoding":"base64"}).encode("ascii")
    data=transport.agent_post(ip,source,"/execute",body,
                               "application/x-www-form-urlencoded")
    need(data.get("message")=="Successfully executed command" and
         isinstance(data.get("stdout"),str) and
         len(data["stdout"])<65536,
         "Agent failed to return bounded base64 Windows read-only witness")
    try:
        raw=base64.b64decode(data["stdout"],validate=True)
        decoded=raw.decode("utf-8-sig")
        lines=[x.strip() for x in decoded.splitlines() if x.strip()]
        need(len(lines)<80 and len(raw)<32768,"Oversized Windows witness")
        good=[]
        for line in lines:
            if line.startswith("{") and line.endswith("}"):
                obj=json.loads(line)
                if obj.get("result")=="COMMAND2_WINDOWS_MASTER_NAT_READONLY_VERIFIED":
                    good.append(obj)
        need(len(good)==1,"Unique Windows NAT verify result absent")
        result=good[0]
        need(result.get("vm_name")==vm and
             all(result.get(x) is True for x in (
                "hostname_verified","one_nic_mac_verified",
                "dhcp_reserved_ip_observed","gateway_verified",
                "dns_verified","external_https_witnessed")) and
             result.get("sample_execution_authorized") is False and
             result.get("this_command_modified_guest") is False,
             "Windows returned incomplete/unsafe NAT acceptance fields")
    except (ValueError,TypeError,KeyError,UnicodeError,
            json.JSONDecodeError) as exc:
        raise GuestVerifyBlocked("Invalid CAPE Agent Windows read-only witness") from exc
    return {"guest_hostname_effective":True,
            "guest_only_expected_mac":True,
            "guest_dhcp_exact_reserved_ipv4":True,
            "guest_default_nat_gateway_and_dns":True,
            "real_guest_https_from_nat_ipv4":True,
            "guest_script_ran_in_verify_readonly_mode":True}

def collect(host,journal,vm,nat_iso,evidence):
    before,dst=ready(host,journal,vm,nat_iso,evidence)
    observed=witness(before["target_nat_ip"],before["source_gateway"],
                     before["json_sha256"],vm)
    # Independent receiver-side check after the Windows guest's HTTP
    # witness was collected, before accepting the result.
    current,destination=ready(host,journal,vm,nat_iso,evidence)
    need(current==before and dst==destination,
         "VM/Agent/MAC/DHCP changed during Windows verification")
    result={"format":"COMMAND2_WINDOWS_NAT_INDEPENDENT_ACCEPTANCE_V1",
       **before,**observed,
       "CAPE_agent_through_new_nat_and_L2_mac_verified":True,
       "running_memory_disk_uefi_snapshot_captured":False,
       "swtpm_consistent_revert_proven":False,
       "malware_analysis_authorized":False}
    fd=os.open(dst,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        json.dump(result,f,sort_keys=True,indent=2)
        f.write("\n");f.flush();os.fsync(f.fileno())
    dirfd=os.open(dst.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(dirfd)
    finally:os.close(dirfd)
    return {"result":"COMMAND2_GUEST_NAT_WINDOWS_AND_HTTPS_VERIFIED",
        "vm":vm,"target_nat_ip":before["target_nat_ip"],
        "witness_path":str(dst),**observed,
        "snapshot_and_TPM_recovery_unverified":True,
        "safe_to_run_malware":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","verify"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--vm",required=True)
    p.add_argument("--nat-iso",type=Path,required=True)
    p.add_argument("--evidence-dir",type=Path,required=True)
    a=p.parse_args()
    try:
        if a.mode=="plan":
            current,_=ready(a.approved_host,a.journal,a.vm,
                            a.nat_iso,a.evidence_dir)
            result={"result":"COMMAND2_WINDOWS_NAT_VERIFY_PREFLIGHT_ONLY",
                "vm":a.vm,"target_nat_ip":current["target_nat_ip"],
                "guest_verified":False,"no_guest_network_mutations":True}
        else:
            result=collect(a.approved_host,a.journal,a.vm,
                           a.nat_iso,a.evidence_dir)
        print(json.dumps(result,sort_keys=True,indent=2),flush=True)
        return 0
    except (GuestVerifyBlocked,approved.GuestExecuteBlocked,
            transport.TransportBlocked,
            transport.attach.NatAttachBlocked,ValueError,TypeError,
            OSError,KeyError,json.JSONDecodeError) as exc:
        print(json.dumps({"result":"COMMAND2_WINDOWS_NAT_INDEPENDENT_VERIFY_BLOCKED",
             "reason":str(exc),"no_snapshot_or_guest_power_operation":True},
             sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
