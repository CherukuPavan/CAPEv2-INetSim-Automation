#!/usr/bin/env python3
"""SSL55 read-only CAPE/INetSim network compatibility audit after NAT reserve.

No guest traffic generation, service restart, CAPE config modification,
libvirt changes, TPM/snapshot use or malware. Only prints non-secret
machine and network fields (IPs/bridges/ports, service status). An exposed
TCP listening socket or service status is not proof of INetSim traffic
working. CAPE machine names are preserved.
"""
from __future__ import annotations
import argparse
import configparser
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys

import command2_ssl55_cape_nat_registration_discovery as discovery
import command2_master_nat_cape_registration_preview as preview

KVM=Path("/opt/CAPEv2/conf/kvm.conf")
INET=Path("/etc/inetsim/inetsim.conf")
CLONE_NAME="win11_1"
CLONE_IP="192.168.122.131"
class TopologyBlocked(RuntimeError):pass
def need(cond,msg):
    if not cond:raise TopologyBlocked(msg)

def cmd(*args,timeout=20,allow_unavailable=False):
    try:
        p=subprocess.run(args,capture_output=True,text=True,
                         check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        if allow_unavailable:return None
        raise TopologyBlocked("Read-only host command unavailable: "+args[0]) from exc
    if p.returncode!=0 or len(p.stdout)>400000:
        if allow_unavailable:return None
        raise TopologyBlocked("Read-only host command failed: "+args[0])
    return p.stdout.strip()

def cape_selected_fields(data):
    parser=configparser.ConfigParser(interpolation=None,strict=True,
                                     inline_comment_prefixes=("#",";"))
    parser.read_string(data)
    need(parser.has_section("kvm"),"Expected CAPE [kvm] section")
    wanted={}
    for name in ("kvm","cuckoo1"):
        if parser.has_section(name):
            wanted[name]={}
            for key in ("interface","ip","snapshot","label","platform"):
                x=parser.get(name,key,fallback=None)
                if x is not None:
                    need("\n" not in x and len(x)<128,
                         "CAPE relevant network field unexpectedly long")
                    wanted[name][key]=x
    return wanted

def inetsim_selected_fields(path=INET):
    if not path.is_file() or path.is_symlink():
        return {"config_file_present":False,
                "inetsim_bindings_confirmed":False}
    # Only allowlisted INetSim public network knobs; never report credentials.
    allowed={"service_bind_address","dns_bind_address",
             "dns_default_ip","dns_default_hostname",
             "http_bind_address","https_bind_address"}
    found={}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line=raw.split("#",1)[0].strip()
        if not line:continue
        bits=line.split(None,1)
        if len(bits)<2 or bits[0] not in allowed:continue
        value=bits[1].strip().strip('"').strip("'")
        need(len(value)<256 and "\x00" not in value,
             "Unexpected INetSim config value")
        if bits[0].endswith("_address") or bits[0]=="dns_default_ip":
            try:ipaddress.ip_address(value)
            except ValueError:
                # INetSim often uses variable hostname or '*' binding:
                # an unparseable value must be marked, not treated as proof.
                value="UNREVIEWED_NON_IP_BIND"
        elif not re.fullmatch(r"[a-zA-Z0-9.-]{1,120}",value):
            value="NON_PLAIN_HOSTNAME"
        need(bits[0] not in found,"Duplicate INetSim public binding key")
        found[bits[0]]=value
    return {"config_file_present":True,
            "selected_network_bindings":found,
            "inetsim_bindings_confirmed":False}

def service_state(name):
    raw=cmd("systemctl","show",name,"--no-pager",
            "--property=LoadState,ActiveState,SubState",
            allow_unavailable=True)
    if raw is None:return {"query_available":False}
    fields={}
    for line in raw.splitlines():
        k,sep,v=line.partition("=")
        if sep and k in {"LoadState","ActiveState","SubState"}:
            fields[k]=v.strip()
    return {"query_available":True,**fields}

def listening_ports():
    text=cmd("ss","-H","-ln","-t","-u",allow_unavailable=True)
    if text is None:return {"query_available":False}
    target_ports={53,80,443,2042,8000}
    bindings=[]
    for line in text.splitlines():
        parts=line.split()
        if len(parts)<5:continue
        local=parts[4]
        try:
            port=int(local.rsplit(":",1)[-1])
        except ValueError:continue
        if port not in target_ports:continue
        # Avoid reporting unrelated host process information or access data.
        host=local.rsplit(":",1)[0].strip("[]")
        if host not in ("0.0.0.0","::","*","192.168.122.1",
                        "192.168.240.1","127.0.0.1"):
            host="OTHER_BIND"
        bindings.append({"protocol":parts[0],
                         "host":host,"port":port})
    return {"query_available":True,"selected_listener_inventory":bindings,
            "listeners_alone_do_not_prove_inetsim_routing":True}

def inspect():
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Protected root SSL55 only")
    prior=discovery.inspect(str(KVM))
    need(prior["registration"]["win11_1_registration_decision"]==
         "CREATE_NEW_STANZA" and
         prior["current_nat_agent_http_positive"] is True,
         "Expected CAPE discovery and NAT agent evidence changed")
    data=KVM.read_text(encoding="utf-8")
    proposal,_=preview.render(data,[{"name":CLONE_NAME,"ip":CLONE_IP,
                      "snapshot":"cape_ready_"+CLONE_NAME}])
    return {"result":"SSL55_CAPE_INETSIM_NAT_TOPOLOGY_READONLY",
            "registration_plan":proposal,
            "current_machine_network_fields":cape_selected_fields(data),
            "inetsim":inetsim_selected_fields(),
            "inetsim_service":service_state("inetsim.service"),
            "cape_service":service_state("cape.service"),
            "relevant_listeners":listening_ports(),
            "win11_1_nat_agent_ip":CLONE_IP,
            "existing_cuckoo1_machine_preserved":True,
            "real_running_final_snapshot_exists":False,
            "inet_sim_end_to_end_traffic_witnessed":False,
            "final_cape_registration_permitted":False,
            "swtpm_revert_proven":False,
            "malware_analysis_permitted":False,
            "host_vm_config_or_snapshot_modified":False}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("audit",),default="audit")
    p.parse_args()
    try:
        print(json.dumps(inspect(),sort_keys=True,indent=2))
        return 0
    except (TopologyBlocked,discovery.CapeDiscoveryBlocked,
            preview.CapeNatCandidateBlocked,
            discovery.reserve.ReservationBlocked,
            discovery.reserve.dual.ReaddressBlocked,
            OSError,ValueError,TypeError,KeyError,configparser.Error) as exc:
        print(json.dumps({"result":"SSL55_CAPE_INETSIM_NAT_TOPOLOGY_BLOCKED",
            "reason":str(exc),"host_modified":False},
            sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
