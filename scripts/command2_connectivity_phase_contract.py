#!/usr/bin/env python3
"""Command2 intentional connectivity states; pure, fail-closed contracts.

A CAPE Windows guest can need the PUBLIC Internet for BENIGN Windows setup,
but MUST NOT use public Internet in the malware-analysis snapshot/run state.
At most one clearly marked temporary provisioning NIC may exist in setup.
Never consider the presence of a CAPE Agent or an isolated NIC proof of
Internet availability. No network changes, samples or shell commands here.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET

VM_RE=re.compile(r"win11_([1-9]|1[0-6])\Z")
ISOLATED="cape-analysis-isolated"
PROVISIONING="cape-trusted-provisioning-nat"
class ConnectivityBlocked(ValueError):pass
def need(test,reason):
    if not test:raise ConnectivityBlocked(reason)

def classify_network(raw):
    root=ET.fromstring(raw)
    need(root.tag=="network","Expected libvirt network XML")
    name=root.findtext("name")
    need(type(name) is str and len(name)>0,"Libvirt network must be named")
    forward=root.find("forward")
    dns=root.find("dns")
    dhcp=root.findall(".//dhcp")
    port=root.find("port")
    return {"name":name,
        "forward":None if forward is None else forward.get("mode","nat"),
        "dns_enabled":dns is not None and dns.get("enable")!="no",
        "dhcp_enabled":bool(dhcp),
        "l2_ports_isolated":port is not None and port.get("isolated")=="yes"}

def classify_vm(raw,vm):
    root=ET.fromstring(raw)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==vm and VM_RE.fullmatch(vm) is not None,
         "Must bind exact win11_N KVM guest identity")
    interfaces=root.findall("./devices/interface")
    need(1<=len(interfaces)<=2,"Only 1 isolation + optional 1 provisioning NIC")
    networks=[]
    for nic in interfaces:
        source=nic.find("source")
        mac=nic.find("mac")
        need(nic.get("type")=="network" and
             source is not None and
             type(source.get("network")) is str and
             mac is not None and
             re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}",
                          (mac.get("address") or "").lower()),
             "Guest NIC must have named libvirt network and MAC")
        networks.append(source.get("network"))
    need(len(set(networks))==len(networks),
         "Duplicate or ambiguous guest NIC sources")
    return {"vm":vm,"network_names":networks}

def assess(*,vm,domain_xml,analysis_network_xml,
           phase,approved_benign_setup=False,
           provisioning_network_xml=None,
           no_samples_running=False,
           operator_external_egress_verified=False,
           ipv4_negative_egress_verified=False,
           ipv6_negative_egress_verified=False,
           cape_agent_verified=False,
           inetsim_verified=False):
    """Pure contract. Verified booleans must be backed by real host/guest
    witness in application code; never auto-produce receipts from this.
    """
    need(phase in ("trusted_setup","analysis_isolated","final_snapshot"),
         "Only explicit trusted setup, analysis isolation and final snapshot")
    vmnet=classify_vm(domain_xml,vm)
    net=classify_network(analysis_network_xml)
    need(net["name"]==ISOLATED and net["forward"] is None and
         net["l2_ports_isolated"] and not net["dhcp_enabled"] and
         not net["dns_enabled"],"CAPE malware-analysis bridge changed")
    attached=vmnet["network_names"]
    if phase=="trusted_setup":
        need(approved_benign_setup is True and no_samples_running is True,
             "Internet setup requires explicit BENIGN-only approval and no samples")
        need(provisioning_network_xml is not None,
             "Temporary independent provisioning NAT network must exist")
        provision=classify_network(provisioning_network_xml)
        need(provision["name"]==PROVISIONING and
             provision["forward"]=="nat" and provision["dhcp_enabled"],
             "Unapproved provisioning bridge: require distinct NAT + DHCP")
        need(set(attached)=={ISOLATED,PROVISIONING} and len(attached)==2,
             "Trusted setup needs exact isolated + temporary provisioning NIC")
        return {"result":"COMMAND2_BENIGN_INTERNET_PROVISIONING_PLAN_ONLY",
                "vm":vm,"phase":phase,
                "internet_access_capable_not_proven":True,
                "operator_real_internet_guest_test_verified":
                   operator_external_egress_verified is True,
                "temporary_nat_interface_present":True,
                "guest_ready_for_final_running_snapshot":False,
                "malware_analysis_allowed":False,
                "host_or_guest_modified":False}
    need(attached==[ISOLATED],
         "Temporary provisioning NAT NIC must be REMOVED before final snapshot")
    need(provisioning_network_xml is None,
         "Unnecessary online provisioning network attached to offline gate")
    need(ipv4_negative_egress_verified is True and
         ipv6_negative_egress_verified is True,
         "Independent Windows IPv4 AND IPv6 external egress negative tests required")
    result={"result":"COMMAND2_ANALYSIS_NETWORK_ISOLATION_CONTRACT",
            "vm":vm,"phase":phase,
            "internet_is_intentionally_simulated_or_blocked":True,
            "guest_unrestricted_real_internet_access":False,
            "temporary_nat_interface_present":False,
            "external_ipv4_ipv6_negative_witnesses_present":True,
            "malware_analysis_allowed":False,
            "host_or_guest_modified":False}
    if phase=="final_snapshot":
        need(cape_agent_verified is True and inetsim_verified is True,
             "CAPE Agent AND INetSim verified before FINAL running snapshot")
        result["result"]="COMMAND2_FINAL_RUNNING_SNAPSHOT_NETWORK_CONTRACT_PASSED"
        result["network_only_snapshot_precondition_passed"]=True
        result["tpm_consistent_restore_proven"]=False
        result["final_snapshot_created"]=False
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase",required=True,
      choices=("trusted_setup","analysis_isolated","final_snapshot"))
    p.add_argument("--vm",required=True)
    p.add_argument("--domain-xml",required=True,
                   help="Path to OFFLINE saved XML for pure analysis")
    p.add_argument("--analysis-network-xml",required=True,
                   help="Path to a saved no-forward isolated libvirt network XML")
    p.add_argument("--provisioning-network-xml")
    p.add_argument("--approved-benign-setup",action="store_true")
    p.add_argument("--no-samples-running",action="store_true")
    p.add_argument("--operator-external-egress-verified",action="store_true")
    p.add_argument("--ipv4-negative-egress-verified",action="store_true")
    p.add_argument("--ipv6-negative-egress-verified",action="store_true")
    p.add_argument("--cape-agent-verified",action="store_true")
    p.add_argument("--inetsim-verified",action="store_true")
    args=p.parse_args()
    from pathlib import Path
    try:
        result=assess(vm=args.vm,
         domain_xml=Path(args.domain_xml).read_text(encoding="utf-8"),
         analysis_network_xml=Path(args.analysis_network_xml).read_text(encoding="utf-8"),
         provisioning_network_xml=(Path(args.provisioning_network_xml).
            read_text(encoding="utf-8")
            if args.provisioning_network_xml else None),
         phase=args.phase,
         approved_benign_setup=args.approved_benign_setup,
         no_samples_running=args.no_samples_running,
         operator_external_egress_verified=args.operator_external_egress_verified,
         ipv4_negative_egress_verified=args.ipv4_negative_egress_verified,
         ipv6_negative_egress_verified=args.ipv6_negative_egress_verified,
         cape_agent_verified=args.cape_agent_verified,
         inetsim_verified=args.inetsim_verified)
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (ConnectivityBlocked,OSError,ET.ParseError,ValueError) as exc:
        print(json.dumps({"result":"COMMAND2_NETWORK_PHASE_BLOCKED",
          "reason":str(exc),"host_or_guest_modified":False,
          "no_snapshot_or_network_change_attempted":True},
           sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
