#!/usr/bin/env python3
"""OTHER-HOST benign per-VM Windows NAT setup through verified CAPE Agent.

A completed master image already contains the elevated CAPE Agent used by
CAPE Sandbox. This helper may, on an explicitly approved disposable host,
send ONLY the pinned repository's benign NAT Windows script and exact
per-VM ISO JSON over CAPE Agent '/store', then request ONLY a hard-coded
PowerShell command via '/execute'. Uses ONE running cloned guest at a time,
the guest's exact libvirt UUID/MAC, verified host route/ARP MAC and Agent
HTTP/admin/feature identity. Never runs malware/analysis jobs.

PLAN checks host/guest/ISO and endpoint; NO upload/write/guest command.
STAGE requires direct operator approval and uploads only trusted setup
media; never executes it.
EXECUTE requires separate typed approval and previous durable stage
receipt; it can change Windows DHCP/DNS/hostname. No reboot, VM stop,
snapshot, TPM operation, firewall changes or retry on partial network
loss. Host must separately reconnect and verify after guest IPv4 shift.
Transport cannot work unless the golden Windows Agent already starts
elevated and guest NIC is reachable on a safe bootstrap IPv4.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

import command2_portable_master_nat_attach as attach
import command2_portable_master_nat_media as media

SENTINEL=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
LOCK=Path("/run/lock/cape-command2-windows-benign-agent-transport.lock")
STAGE_SUFFIX=".command2-windows-nat-stage.json"
INTENT_SUFFIX=".command2-windows-nat-execute-intent.json"
VM_RE=re.compile(r"win11_([1-9]|1[0-6])\Z")
MAX_PAYLOAD=64*1024
MAX_RESPONSE=128*1024
class TransportBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise TransportBlocked(why)

def q(*args,timeout=25):
    try:
        result=subprocess.run(args,capture_output=True,text=True,
                              check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise TransportBlocked("Required read-only host query failed: "+args[0]) from exc
    need(result.returncode==0 and len(result.stdout)<=MAX_RESPONSE,
         "Read-only host query rejected "+args[0])
    return result.stdout.strip()

def iso_entry(path,leaf):
    need(leaf in ("nat-config.json","nat-config.sha256",
                  "command2_guest_master_nat.ps1"),
         "Unrecognized Windows provisioning ISO entry")
    try:
        p=subprocess.run(["isoinfo","-R","-i",str(path),"-x","/"+leaf],
                         capture_output=True,check=False,timeout=40)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise TransportBlocked("isoinfo/ISO extraction unavailable") from exc
    need(p.returncode==0 and 1<=len(p.stdout)<=MAX_PAYLOAD,
         "Provisioning ISO missing required content: "+leaf)
    return p.stdout

def iso_profile(vm,iso):
    need(iso.is_absolute() and iso.is_file() and not iso.is_symlink(),
         "Expected exact immutable master NAT ISO")
    doc=iso_entry(iso,"nat-config.json")
    digest=iso_entry(iso,"nat-config.sha256").decode("ascii").strip()
    script=iso_entry(iso,"command2_guest_master_nat.ps1")
    need(re.fullmatch(r"[0-9a-f]{64}",digest) and
         hashlib.sha256(doc).hexdigest()==digest,
         "Guest JSON does not match pinned ISO hash")
    local_script=media.script_source()
    need(script==local_script,
         "NAT guest script differs from reviewed repository source")
    cfg=json.loads(doc.decode("utf-8-sig"))
    need(type(cfg) is dict and cfg.get("format")==
         "COMMAND2_MASTER_NAT_WINDOWS_V1" and cfg.get("guest_name")==vm and
         cfg.get("nic_network")=="default" and
         cfg.get("bridge")=="virbr0" and
         cfg.get("malware_public_internet_authorized") is False,
         "ISO does not contain reviewed no-malware master NAT profile")
    return {"config":cfg,"config_bytes":doc,"script_bytes":script,
            "config_sha256":digest,
            "script_sha256":hashlib.sha256(script).hexdigest()}

def agent_get(ip,source):
    conn=None
    try:
        conn=http.client.HTTPConnection(ip,8000,timeout=7,
                                         source_address=(source,0))
        conn.request("GET","/",headers={"Accept":"application/json"})
        answer=conn.getresponse()
        body=answer.read(MAX_RESPONSE+1)
        need(answer.status==200 and len(body)<=MAX_RESPONSE,
             "Windows Agent identity did not return bounded HTTP200")
        parsed=json.loads(body.decode("utf-8"))
        need(type(parsed) is dict and parsed.get("message")=="CAPE Agent!" and
             parsed.get("is_user_admin") is True and
             type(parsed.get("version")) is str and
             type(parsed.get("features")) is list and
             "execute" in parsed["features"],
             "Expected elevated CAPE Agent execute feature missing")
        return {"ip":ip,"source":source,
                "admin_cape_agent_and_execute_feature":True,
                "agent_version":parsed["version"]}
    except (OSError,ValueError,http.client.HTTPException,
            UnicodeError) as exc:
        raise TransportBlocked("CAPE Agent identity/connection rejected") from exc
    finally:
        if conn:conn.close()

def mac_of_neighbor(ip):
    entries=json.loads(q("ip","-j","neigh","show",ip,"dev","virbr0"))
    need(type(entries) is list and len(entries)==1,
         "Expected exactly one host neighbor entry for bootstrap guest")
    value=(entries[0].get("lladdr") or "").lower()
    need(re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}",value),
         "Bootstrap Windows neighbor has no verified Ethernet MAC")
    return value

def inspect(host,journal,vm,iso):
    attach.workflow.canonical_host(host)
    need(os.geteuid()==0,"Root required for exact private golden clone data")
    need(VM_RE.fullmatch(vm) is not None,
         "Only approved win11_N clone name accepted")
    rows=attach.journal_rows(host,journal)
    row=next((x for x in rows if x["libvirt_name"]==vm),None)
    need(row is not None,"Guest missing from approved private identity journal")
    need(attach.virsh("domuuid",vm).lower()==
         row["libvirt_uuid_candidate"] and
         attach.virsh("domstate",vm).lower()=="running" and
         attach.virsh("domstate","win11").lower()=="shut off",
         "Master not off or target cloned VM identity/state differs")
    active=[x.strip() for x in attach.virsh("list","--name").splitlines()
            if x.strip()]
    need(active==[vm],
         "For benign firstboot, ONLY the single selected clone may run")
    # The all-N attachment checker would reject any RUNNING clone; verify
    # only this exact saved+live permanent NIC and active NAT gateway.
    for arguments in (("dumpxml","--inactive",vm),("dumpxml",vm)):
        root=ET.fromstring(attach.virsh(*arguments))
        need(root.findtext("name")==vm and root.findtext("uuid")==
             row["libvirt_uuid_candidate"],
             "Guest live/saved XML changed")
        nics=root.findall("./devices/interface")
        need(len(nics)==1,"Exactly one default NAT interface required")
        a=nics[0]
        need(a.get("type")=="network" and
             a.find("source") is not None and
             a.find("source").get("network")=="default" and
             a.find("mac") is not None and
             a.find("mac").get("address","").lower()==
             row["mac_candidate"].lower() and
             a.find("model") is not None and
             a.find("model").get("type")=="e1000e",
             "Guest NIC differs from approved persistent master NAT")
    meta=iso_profile(vm,iso)
    c=meta["config"]
    need(c["expected_machine_uuid"]==row["libvirt_uuid_candidate"] and
         c["nic_mac"].lower()==row["mac_candidate"].lower(),
         "Windows provisioning ISO UUID/MAC not from identity journal")
    network=attach.profile.check_active_nat()
    subnet=ipaddress.IPv4Network(network["ipv4"]["subnet"])
    wanted=str(ipaddress.IPv4Address(
                   int(subnet.network_address)+200+int(vm.split("_")[1])))
    need(c["ipv4"]==wanted and c["default_gateway"]==
         network["ipv4"]["gateway"],
         "Guest desired NAT IP/gateway differs from reviewed network")
    gateway=network["ipv4"]["gateway"]
    # Host must have L2 proof that our Agent endpoint is THIS clone,
    # not another Windows VM or the shutoff golden master.
    probes=[wanted]
    if str(subnet)=="192.168.122.0/24":
        probes.append("192.168.122.125")
    candidates=[]
    for ip in probes:
        try:
            details=agent_get(ip,gateway)
            if mac_of_neighbor(ip)==row["mac_candidate"].lower():
                candidates.append(details)
        except TransportBlocked:
            pass
    need(len(candidates)==1,
         "No unique elevated CAPE Agent reachable at target or original "
         "template IP with EXACT guest neighbor MAC")
    return {
       "result":"COMMAND2_EXACT_GUEST_BENIGN_AGENT_TRANSPORT_PLAN_ONLY",
       "vm":vm,"uuid":row["libvirt_uuid_candidate"],
       "mac":row["mac_candidate"].lower(),
       "bootstrap_ip":candidates[0]["ip"],
       "agent_version":candidates[0]["agent_version"],
       "target_nat_ipv4":wanted,
       "source_gateway":gateway,
       "iso":str(iso),
       "iso_config_sha256":meta["config_sha256"],
       "approved_script_sha256":meta["script_sha256"],
       "agent_powershell_upload_or_execution_done":False,
       "unique_hostname_windows_verified":False,
       "malware_public_internet_authorized":False,
       "tpm_snapshot_revert_proven":False
    }

def agent_post(ip,source,path,body,content_type):
    need(type(body) is bytes and 0<len(body)<MAX_PAYLOAD,
         "Windows provisioning payload too large/empty")
    conn=None
    try:
        conn=http.client.HTTPConnection(ip,8000,timeout=20,
                                         source_address=(source,0))
        conn.request("POST",path,body=body,headers={
            "Content-Type":content_type,"Content-Length":str(len(body))})
        answer=conn.getresponse()
        raw=answer.read(MAX_RESPONSE+1)
        need(len(raw)<=MAX_RESPONSE,
             "Oversized CAPE Agent response")
        response=json.loads(raw.decode("utf-8"))
        need(answer.status==200 and response.get("status_code")==200 and
             type(response.get("message")) is str,
             "Windows CAPE Agent request failed, do not blindly retry")
        return response
    except (OSError,ValueError,http.client.HTTPException,
            UnicodeError) as exc:
        raise TransportBlocked("CAPE Agent setup POST failed/connection changed") from exc
    finally:
        if conn:conn.close()

def store(ip,source,filename,content):
    need(filename in ("nat-config.json","command2_guest_master_nat.ps1"),
         "Only reviewed benign Windows setup files may be written")
    dest="C:/CAPE_NAT2/"+filename
    boundary="----CAPECommand2TrustedWinSetupOnly"
    header=(f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="filepath"\r\n\r\n'
            f"{dest}\r\n--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="'
            +filename+'"\r\nContent-Type: application/octet-stream\r\n\r\n')
    payload=(header.encode("ascii")+content+b"\r\n"+
             f"--{boundary}--\r\n".encode("ascii"))
    answer=agent_post(ip,source,"/store",payload,
                     "multipart/form-data; boundary="+boundary)
    need(answer["message"]=="Successfully stored file",
         "CAPE Agent /store response not recognized")
    return {"remote_path":dest,"bytes":len(content)}

def stage(host,journal,vm,iso,evidence_dir):
    need(sys.stdin.isatty(),"Direct operator TTY required for guest file writes")
    before=inspect(host,journal,vm,iso)
    phrase="UPLOAD-ONLY-TRUSTED-NAT-WINDOWS-SETUP-"+vm.upper()
    need(input("Type "+phrase+" for only two reviewed guest files: ")==phrase,
         "Operator did not approve Windows NAT setup upload")
    evidence=Path(evidence_dir)
    need(evidence.is_absolute() and evidence.is_dir() and
         not evidence.is_symlink() and
         evidence.stat().st_uid==0 and
         stat.S_IMODE(evidence.stat().st_mode)==0o700,
         "Existing root-only 0700 guest evidence directory required")
    outcome=evidence/(vm+STAGE_SUFFIX)
    need(not outcome.exists() and not outcome.is_symlink(),
         "Guest provisioning already has a stage witness; do not retry")
    checked=inspect(host,journal,vm,iso)
    need(checked==before,"Guest/ARP/Agent changed since upload consent")
    meta=iso_profile(vm,iso)
    started=False
    try:
        started=True
        a=store(before["bootstrap_ip"],before["source_gateway"],
                "nat-config.json",meta["config_bytes"])
        b=store(before["bootstrap_ip"],before["source_gateway"],
                "command2_guest_master_nat.ps1",meta["script_bytes"])
        done={"format":"COMMAND2_TRUSTED_WINDOWS_NAT_UPLOAD_ONLY_V1",
              "approved_host":host,"vm":vm,
              "vm_uuid":before["uuid"],"mac":before["mac"],
              "bootstrap_ip":before["bootstrap_ip"],
              "gateway":before["source_gateway"],
              "target_ip":before["target_nat_ipv4"],
              "json_sha256":before["iso_config_sha256"],
              "script_sha256":before["approved_script_sha256"],
              "remote_files":[a["remote_path"],b["remote_path"]],
              "only_trusted_setup_files_uploaded":True,
              "powershell_executed":False,
              "windows_hostname_ipv4_verified":False}
        fd=os.open(outcome,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"w") as stream:
            json.dump(done,stream,sort_keys=True,indent=2)
            stream.write("\n");stream.flush();os.fsync(stream.fileno())
        return {"result":"COMMAND2_TRUSTED_GUEST_NAT_MEDIA_UPLOADED_NOT_EXECUTED",
                "vm":vm,"target_nat_ip":before["target_nat_ipv4"],
                "stage_receipt":str(outcome),"windows_guest_changed_network":False,
                "reboot_requested":False,"snapshot_created":False}
    except Exception as exc:
        if started:
            raise TransportBlocked(
                "AGENT_UPLOAD_STARTED_MAY_BE_PARTIAL: do not retry, "
                "inspect original VM; "+str(exc)) from exc
        raise

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","stage"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--vm",required=True)
    p.add_argument("--nat-iso",type=Path,required=True)
    p.add_argument("--evidence-dir",type=Path)
    a=p.parse_args()
    try:
        info=(stage(a.approved_host,a.journal,a.vm,a.nat_iso,
                    a.evidence_dir) if a.mode=="stage" else
              inspect(a.approved_host,a.journal,a.vm,a.nat_iso))
        print(json.dumps(info,sort_keys=True,indent=2),flush=True)
        return 0
    except (TransportBlocked,attach.NatAttachBlocked,
            attach.workflow.WorkflowBlocked,media.NatMediaBlocked,
            OSError,ValueError,TypeError,KeyError,ET.ParseError) as exc:
        print(json.dumps({"result":"COMMAND2_TRUSTED_GUEST_AGENT_TRANSPORT_BLOCKED",
           "reason":str(exc),"no_malware_or_snapshot_execution":True,
           "no_guest_restart":True},sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
