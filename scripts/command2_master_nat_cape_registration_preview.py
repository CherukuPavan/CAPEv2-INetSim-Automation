#!/usr/bin/env python3
"""PURE pre-registration of Windows clones on existing CAPE KVM config.

We have verified physical SSL55 /opt/CAPEv2/conf/kvm.conf:
[kvm] machines = cuckoo1, no [win11_1] stanza. Existing CAPE's
generic registration helper silently drops names whose libvirt domains
are not present. NEVER delete 'cuckoo1' implicitly.

This renderer preserves every old section and machine entry byte-for-byte
except one exact [kvm] machines CSV append, adds fresh win11_N stanzas,
and refuses existing sections or unsafe IP names. Snapshot names are
FUTURE TARGETS only, NOT verification that RAM/disk/UEFI/swtpm can be
reverted. NO apply mode, file writes or host side effects.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path

SECTION=re.compile(r"(?m)^[ \t]*\[([A-Za-z0-9_.-]+)\][ \t]*$")
CSV=re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,90}$")
MACHINES=re.compile(r"(?mi)^([ \t]*machines[ \t]*=[ \t]*)([^#;\r\n]*)([^\r\n]*)$")
VM=re.compile(r"win11_([1-9]|1[0-6])\Z")
class CapeNatCandidateBlocked(ValueError):pass
def need(cond,why):
    if not cond:raise CapeNatCandidateBlocked(why)

def render(original,guests):
    need(type(original) is str and len(original)<512*1024 and
         "\0" not in original and "\r" not in original and
         original.endswith("\n"),
         "CAPE configuration must be readable LF-only text")
    matches=list(SECTION.finditer(original))
    named=[m.group(1) for m in matches]
    need(len(named)==len(set(named)) and named.count("kvm")==1,
         "Expected one [kvm] stanza and no duplicated sections")
    ix=named.index("kvm")
    region_start=matches[ix].end()
    region_end=matches[ix+1].start() if ix+1<len(matches) else len(original)
    body=original[region_start:region_end]
    options=list(MACHINES.finditer(body))
    need(len(options)==1,"Expected exactly one [kvm] machines property")
    old=[x.strip() for x in options[0].group(2).split(",") if x.strip()]
    need(len(old)>0 and len(old)==len(set(old)) and
         all(CSV.fullmatch(x) and x in named for x in old),
         "Existing CAPE machines list is invalid or references absent stanzas")
    need(type(guests) is list and 1<=len(guests)<=16,
         "1..16 new clones required")
    names=[]
    addresses=[]
    extra=[]
    for idx,row in enumerate(guests,1):
        need(type(row) is dict,"Invalid candidate row")
        name=row.get("name")
        ip=row.get("ip")
        snap=row.get("snapshot")
        need(type(name) is str and VM.fullmatch(name) and
             name not in named and name not in old and name not in names,
             "New VM name collides with existing CAPE configuration")
        need(type(snap) is str and snap=="cape_ready_"+name,
             "Only prospective per-VM final snapshot name permitted")
        try:
            ip_obj=ipaddress.IPv4Address(ip)
        except (ValueError,TypeError) as err:
            raise CapeNatCandidateBlocked("Invalid guest NAT IP") from err
        need(ip_obj in ipaddress.IPv4Network("192.168.122.0/24") and
             ip_obj not in (ipaddress.IPv4Address("192.168.122.1"),
                            ipaddress.IPv4Address("192.168.122.255")) and
             str(ip_obj) not in addresses,
             "Guest NAT address conflicts or outside reviewed default subnet")
        names.append(name)
        addresses.append(str(ip_obj))
        # libvirt NAT bridge is virbr0, CAPE Agent was physically verified
        # on it, but a final snapshot is not yet captured/revert-proven.
        extra.append(
            f"\n[{name}]\nlabel = {name}\nplatform = windows\n"
            f"ip = {ip_obj}\narch = x64\ntags = win11\n"
            f"snapshot = {snap}\ninterface = virbr0\n")
    # Keep whitespace BEFORE any trailing inline comment; swallowing it
    # breaks some CAPE config comments and violates the preservation gate.
    trailing_ws=options[0].group(2)[len(options[0].group(2).rstrip()):]
    newvalues=",".join(old+names)
    newbody=(body[:options[0].start()]+
             options[0].group(1)+newvalues+trailing_ws+
             options[0].group(3)+body[options[0].end():])
    future=(original[:region_start]+newbody+original[region_end:]+
            "".join(extra))
    need(future.count("[cuckoo1]")==original.count("[cuckoo1]"),
         "Original legacy cuckoo1 stanza must never be removed")
    # Snapshot readiness is ALWAYS external evidence; this is a preview.
    return {"result":"COMMAND2_MASTER_NAT_CAPE_REGISTRATION_PREVIEW_ONLY",
            "existing_machine_names_preserved":old,
            "candidate_new_guest_names":names,
            "candidate_guest_nat_ips":addresses,
            "candidate_final_snapshot_names":["cape_ready_"+n for n in names],
            "cape_machine_list_after_append":old+names,
            "bridge_for_clone_agent":"virbr0",
            "existing_config_sha256":hashlib.sha256(original.encode()).hexdigest(),
            "proposed_config_sha256":hashlib.sha256(future.encode()).hexdigest(),
            "existing_cape_stanzas_modified":False,
            "candidate_snapshot_at_capture_in_current_vm":False,
            "final_running_snapshot_exists_verified":False,
            "tpm_restoration_physically_verified":False,
            "inetsim_routing_verified":False,
            "unrestricted_public_malware_egress_authorized":False,
            "configuration_was_written":False,
            "cape_services_restarted":False,
            "auto_apply_authorized":False},future

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--kvm-conf",type=Path,required=True)
    p.add_argument("--guests-json",type=Path,required=True)
    a=p.parse_args()
    try:
        need(a.kvm_conf.is_absolute() and a.kvm_conf.name=="kvm.conf"
             and a.kvm_conf.is_file() and not a.kvm_conf.is_symlink(),
             "Expected exact existing CAPE kvm.conf")
        need(a.guests_json.is_file() and not a.guests_json.is_symlink(),
             "Expected JSON of candidate new NAT guests")
        result,_=render(a.kvm_conf.read_text(encoding="utf-8"),
                        json.loads(a.guests_json.read_text(encoding="utf-8")))
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except (CapeNatCandidateBlocked,OSError,ValueError,TypeError) as exc:
        print(json.dumps({"result":"COMMAND2_CAPE_NAT_REGISTRATION_PREVIEW_BLOCKED",
              "reason":str(exc),"CAPE_config_modified":False},
              sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
