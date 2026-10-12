#!/usr/bin/env python3
"""SSL55 read-only CAPE KVM registration discovery for master-style NAT clone.

NEVER prints CAPE secrets or copies complete config contents into reports.
Inspects only [kvm] machines and exact [win11_1] stanza's ip/snapshot/
interface/machinery identity; confirms master/trial unchanged, current
running snapshot, both NICs, NAT DHCP host reservation and both CAPE Agent
HTTP GET responses. No VM/network/CAPE/service/TPM/snapshot modification.

If the CAPE conf path is unknown, searches only conventional CAPEv2
locations, without recursive filesystem walks; more than one match blocks
auto-selection. Not evidence that unrestricted NAT is safe for malware.
"""
from __future__ import annotations
import argparse
import configparser
import json
import os
from pathlib import Path
import socket
import stat
import sys
import xml.etree.ElementTree as ET

import command2_ssl55_nat_dhcp_reservation as reserve

class CapeDiscoveryBlocked(RuntimeError): pass
def need(cond,msg):
    if not cond:raise CapeDiscoveryBlocked(msg)

def possible_paths():
    roots=[Path("/opt/CAPEv2"),Path("/opt/cape"),
           Path("/srv/CAPEv2"),Path("/srv/cape")]
    home=Path("/home")
    if home.is_dir() and not home.is_symlink():
        users=[p for p in sorted(home.iterdir()) if p.is_dir()
               and not p.is_symlink()]
        need(len(users)<=50,"Too many home folders for narrow CAPE discovery")
        for p in users:
            roots.extend([p/"CAPEv2",p/"cape",p/"CAPE",p/"capev2"])
    return [r/"conf"/"kvm.conf" for r in roots]

def select_conf(explicit=None):
    candidates=([Path(explicit)] if explicit is not None else possible_paths())
    located=[p for p in candidates if p.is_file() and not p.is_symlink()]
    need(len(located)==1,
         "Expected exactly one existing CAPE conf/kvm.conf; located "+
         str(len(located))+" candidates. Use --kvm-conf with exact path.")
    p=located[0]
    need(p.is_absolute() and p.name=="kvm.conf" and
         p.parent.name=="conf" and not any(x.is_symlink() for x in p.parents),
         "Untrusted or ambiguous CAPE configuration path")
    st=p.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
         st.st_size<=512*1024 and st.st_size>0 and
         not (stat.S_IMODE(st.st_mode)&0o002),
         "CAPE kvm.conf is nonregular, linked, oversized, or world-writable")
    return p

def inspect_kvm(contents):
    cfg=configparser.ConfigParser(interpolation=None,strict=True,
                                   inline_comment_prefixes=("#",";"))
    cfg.optionxform=str.lower
    try:
        cfg.read_string(contents)
    except (configparser.Error,ValueError) as exc:
        raise CapeDiscoveryBlocked("Cannot safely parse CAPE machine config") from exc
    need(cfg.has_section("kvm"),"CAPE [kvm] machine configuration missing")
    machines=cfg.get("kvm","machines",fallback="").split(",")
    names=[name.strip() for name in machines if name.strip()]
    need(len(set(names))==len(names),
         "CAPE KVM machine names list has duplicate entries")
    target="win11_1"
    linked=target in names
    section=cfg.has_section(target)
    need(not linked or section,
         "win11_1 is named in [kvm] machines but its stanza is absent")
    expected={"name":target,"network_nat_ip":"192.168.122.131"}
    if section:
        # Do not report unrelated properties such as passwords, credentials,
        # resultserver commandline or API tokens that might live in the file.
        for field in ("label","ip","snapshot","interface","platform"):
            expected[field]=cfg.get(target,field,fallback=None)
    return {
       "kvm_machine_name_count":len(names),
       "kvm_machine_name_list":names[:64],
       "win11_1_listed_in_kvm_machines":linked,
       "win11_1_section_exists":section,
       "win11_1_targeted_fields_only":expected,
       "win11_1_registration_decision":(
           "UPDATE_EXISTING_STANZA" if linked and section else
           "REPAIR_UNLISTED_STANZA" if section else
           "CREATE_NEW_STANZA"),
       "snapshot_for_final_cape_registration_is_not_yet_ready":True,
       "cape_config_or_services_modified":False,
    }

def inspect(explicit=None):
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Read-only CAPE audit restricted to original protected SSL55 root")
    reservation=reserve.inspect()
    need(reservation["reservation_present_in_live_and_config"] is True,
         "CAPE discovery requires verified NAT MAC/.131 host reservation")
    path=select_conf(explicit)
    observed=inspect_kvm(path.read_text(encoding="utf-8"))
    return {"result":"SSL55_CAPE_REGISTRATION_DISCOVERY_READONLY",
       "path":str(path),
       "nat_dhcp_mac_ip_reservation_live_and_config_verified":True,
       "current_nat_agent_http_positive":True,
       "current_isolated_agent_http_positive":True,
       "candidate_snapshot_preserved":"cape_candidate_win11_1",
       "network_status":"two_persistent_nics_not_final_analysis_network",
       "current_nic_retirement_approved":False,
       "swtpm_restore_proven":False,
       "unrestricted_malware_egress_authorized":False,
       "cape_conf_write_authorized":False,
       "vm_guest_service_or_snapshot_modified":False,
       "registration":observed}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("audit",),default="audit")
    p.add_argument("--kvm-conf",help="Optional exact CAPE conf/kvm.conf")
    args=p.parse_args()
    try:
        result=inspect(args.kvm_conf)
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except (CapeDiscoveryBlocked,reserve.ReservationBlocked,
            reserve.dual.ReaddressBlocked,ValueError,OSError,
            configparser.Error,TypeError,KeyError,UnicodeError) as exc:
        print(json.dumps({"result":"SSL55_CAPE_REGISTRATION_DISCOVERY_BLOCKED",
            "reason":str(exc),"guest_network_or_cape_conf_modified":False},
             sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
