#!/usr/bin/env python3
"""OTHER-host first boot of ONE exact independently staged master-NAT clone.

Only after exact Command2 root-private identity reservation and persistent
default/virbr0 DHCP host entry were provisioned. One clone at a time; master
must remain shut off. Typed operator consent; start PAUSED, verify current
live guest MAC and independent QCOW2/UEFI/TPM identity BEFORE guest CPU can
run, then resume. No guest network/Windows changes, no CAPE sample, no TPM
state restore, no snapshot or automated retries on partial failure.
Guest Windows boot/BitLocker and CAPE Agent identity must be proved later.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as ET

import command2_portable_master_nat_attach as network
import command2_portable_master_nat_agent_batch as agent_batch
import command2_portable_nat_agent_verify as acceptance
import command2_portable_nat_agent_setup_transport as transport

LOCK=Path("/run/lock/cape-command2-master-nat-firstboot.lock")
NAME=re.compile(r"win11_([1-9]|1[0-6])\Z")
class NatBootBlocked(RuntimeError):pass
def need(condition,reason):
    if not condition:raise NatBootBlocked(reason)

def completed_running_clones(host,rows,requested,net,evidence):
    """Admit only EARLIER VMs with a full Windows NAT/HTTPS witness.

    Every running guest must already have left the template 192.168.122.125
    and be verified on its own reserved IP and MAC. The next clone may
    then boot while those approved earlier clones remain running.
    """
    others=[x.strip() for x in network.virsh("list","--name").splitlines()
            if x.strip()]
    need(len(others)==len(set(others)),"Ambiguous live VM domain inventory")
    if not others:return []
    need(evidence is not None,"Completed prior Windows witness folder required")
    folder=transport.verified_evidence_folder(evidence)
    current=int(NAME.fullmatch(requested).group(1))
    subnet=network.ipaddress.IPv4Network(net["ipv4"]["subnet"])
    gateway=net["ipv4"]["gateway"]
    approved=[]
    for vm in others:
        found=NAME.fullmatch(vm)
        need(found is not None and int(found.group(1))<current and
             vm!=requested,
             "Unreviewed or not-yet-personalized VM is running")
        row=next((r for r in rows if r["libvirt_name"]==vm),None)
        need(row is not None and
             network.virsh("domuuid",vm).lower()==
             row["libvirt_uuid_candidate"] and
             network.virsh("domstate",vm).lower()=="running",
             "Earlier running clone does not match exact guest journal")
        ip=str(network.ipaddress.IPv4Address(
           int(subnet.network_address)+200+int(found.group(1))))
        cert=folder/(vm+acceptance.SUFFIX)
        proof=acceptance.approved.trusted_stage_json(cert)
        need(proof.get("format")==
             "COMMAND2_WINDOWS_NAT_INDEPENDENT_ACCEPTANCE_V1" and
             proof.get("host")==host and proof.get("vm")==vm and
             proof.get("uuid")==row["libvirt_uuid_candidate"] and
             proof.get("mac")==row["mac_candidate"].lower() and
             proof.get("target_nat_ip")==ip and
             all(proof.get(k) is True for k in (
                 "guest_hostname_effective","guest_only_expected_mac",
                 "guest_dhcp_exact_reserved_ipv4",
                 "guest_default_nat_gateway_and_dns",
                 "real_guest_https_from_nat_ipv4",
                 "guest_script_ran_in_verify_readonly_mode",
                 "CAPE_agent_through_new_nat_and_L2_mac_verified")) and
             proof.get("malware_analysis_authorized") is False and
             proof.get("swtpm_consistent_revert_proven") is False,
             "Earlier running Windows clone lacks exact verified NAT witness")
        need(agent_batch.nic_xml(
             network.virsh("dumpxml","--inactive",vm),row) and
             agent_batch.nic_xml(network.virsh("dumpxml",vm),row),
             "Previous VM saved/live permanent NAT e1000e MAC changed")
        route=agent_batch.route(ip)
        need(route.get("dev")=="virbr0" and
             route.get("prefsrc",route.get("src"))==gateway and
             not route.get("gateway"),
             "Previous cloned guest route no longer on source-master NAT")
        remote=agent_batch.agent(ip,gateway)
        need(remote.get("valid") is True and
             transport.mac_of_neighbor(ip)==row["mac_candidate"].lower(),
             "Earlier guest no longer has exact NAT Agent/MAC ownership")
        approved.append({"vm":vm,"reserved_ip":ip,
                         "Windows_verified_and_guest_agent_live":True})
    return approved

def checked(host,journal,vm,evidence=None):
    network.workflow.canonical_host(host)
    need(os.geteuid()==0,"Root required for pinned canonical VM firstboot")
    need(NAME.fullmatch(vm) is not None,
         "Expected one count-driven win11_1..16 guest")
    rows=network.journal_rows(host,journal)
    row=next((x for x in rows if x["libvirt_name"]==vm),None)
    need(row is not None,"VM not in authorized count-driven identity journal")
    source=network.profile.check_master()
    n,views=network.check_network_references()
    need(n["nat_network"]=="default" and n["bridge"]=="virbr0",
         "Source-master default NAT not active")
    previously_verified=completed_running_clones(host,rows,vm,n,evidence)
    current=network.virsh("domstate",vm).lower()
    need(current=="shut off","Clone must be shut off for first boot")
    meta=network.check_exact_guest(row,expected_mac=row["mac_candidate"])
    # Old generic all-N check refuses a running clone, so inspect
    # reservations in both network views directly.
    expected=(row["mac_candidate"].lower(),
         str(network.ipaddress.IPv4Address(
             int(network.ipaddress.IPv4Network(n["ipv4"]["subnet"]).network_address)+
             200+int(NAME.fullmatch(vm).group(1)))),
         "WIN11-"+NAME.fullmatch(vm).group(1))
    need(all(network.reservations(root).count(expected)==1 for root in views),
         "Exact guest permanent DHCP reservation absent from active/config")
    raw=network.virsh("dumpxml","--inactive",vm)
    root=ET.fromstring(raw)
    need(root.findtext("name")==vm and
         root.findtext("uuid")==row["libvirt_uuid_candidate"],
         "VM stopped XML identity mismatch")
    disk=root.findall("./devices/disk[@device='disk']")
    nv=root.find("./os/nvram")
    backend=root.find("./devices/tpm/backend")
    need(len(disk)==1 and disk[0].find("source") is not None and
         disk[0].find("source").get("file")==row["disk_target"] and
         nv is not None and (nv.text or "") in (
           row["uefi_nvram_target"],row["uefi_nvram_target"]+".qcow2") and
         backend is not None and backend.get("type")=="emulator" and
         backend.get("version")=="2.0",
         "VM master-image OS disk, OVMF vars or independent TPM differs")
    need(not network.virsh("snapshot-list",vm,"--name").strip(),
         "First boot cannot start VM with unreviewed existing snapshot")
    return {"result":"COMMAND2_MASTER_NAT_CLONE_FIRSTBOOT_PLAN_ONLY",
       "vm":vm,"uuid":row["libvirt_uuid_candidate"],
       "mac":row["mac_candidate"],
       "expected_reserved_ip":expected[1],
       "prior_running_clones_with_independent_NAT_witness":previously_verified,
       "source_master_shut_off":source["master_left_shut_off"],
       "guest_shut_off_and_single_nat_interface":True,
       "exact_guest_DHCP_reservation_both_network_views":True,
       "master_apps_registry_copied_from_disk_not_rebuilt":True,
       "windows_actual_boot_verified":False,
       "bitlocker_tpm_new_identity_boot_verified":False,
       "Windows_hostname_IP_agent_https_verified":False,
       "native_running_snapshot_created":False,
       "malware_analysis_authorized":False}

def live_identity(vm,identity):
    raw=network.virsh("dumpxml",vm)
    root=ET.fromstring(raw)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==vm and root.findtext("uuid")==identity["uuid"],
         "Paused guest lost pinned UUID/name")
    nics=root.findall("./devices/interface")
    need(len(nics)==1 and nics[0].find("source") is not None and
         nics[0].find("source").get("network")=="default" and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address","").lower()==identity["mac"].lower() and
         nics[0].find("model") is not None and
         nics[0].find("model").get("type")=="e1000e",
         "Paused guest NIC unexpectedly changed before CPU resume")
    return True

def boot(host,journal,vm,evidence=None):
    need(sys.stdin.isatty(),"Real direct-operator TTY needed for first boot")
    initial=checked(host,journal,vm,evidence)
    print(json.dumps(initial,sort_keys=True,indent=2),flush=True)
    phrase="BOOT-TRUSTED-MASTER-NAT-CLONE-"+vm.upper()
    need(input("Type "+phrase+" to start ONE fresh clone: ")==phrase,
         "No exact VM first-boot authorization")
    need(not LOCK.is_symlink(),"Unsafe firstboot operation lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    attempted=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1
             and stat.S_IMODE(st.st_mode)==0o600,
             "Firstboot root lock not 0600")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise NatBootBlocked("Another exact firstboot operation active") from exc
        need(checked(host,journal,vm,evidence)==initial,
             "Canonical VM/DHCP/master changed after operator approval")
        attempted=True
        network.virsh("start",vm,"--paused",timeout=180)
        need(network.virsh("domstate",vm).lower()=="paused",
             "Fresh Windows guest must be paused for pre-resume guard")
        live_identity(vm,initial)
        need(network.virsh("domstate","win11").lower()=="shut off",
             "Master source unexpectedly started during clone boot")
        network.virsh("resume",vm,timeout=120)
        need(network.virsh("domstate",vm).lower()=="running",
             "Guest resume not confirmed, do not auto-retry")
        live_identity(vm,initial)
        return {**initial,
            "result":"COMMAND2_MASTER_NAT_CLONE_GUEST_STARTED_ONLY",
            "hypervisor_guest_running":True,
            "windows_actual_boot_verified":False,
            "source_master_unmodified":True,
            "no_guest_setup_or_reboot_or_snapshot_requested":True}
    except Exception as exc:
        if attempted:
            raise NatBootBlocked(
                "FIRSTBOOT_STARTED_MAY_BE_PAUSED_OR_PARTIAL: STOP, "
                "do NOT automatically retry, force shutdown or revert. "+
                str(exc)) from exc
        raise
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","boot"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--vm",required=True)
    p.add_argument("--evidence-dir",type=Path)
    args=p.parse_args()
    try:
        out=boot(args.approved_host,args.journal,args.vm,args.evidence_dir) if args.mode=="boot" \
            else checked(args.approved_host,args.journal,args.vm,args.evidence_dir)
        print(json.dumps(out,sort_keys=True,indent=2),flush=True)
        return 0
    except (NatBootBlocked,network.NatAttachBlocked,
            network.profile.PortableNatBlocked,network.workflow.WorkflowBlocked,
            acceptance.GuestVerifyBlocked,transport.TransportBlocked,
            agent_batch.BatchAgentBlocked,KeyError,ValueError,TypeError,
            OSError,ET.ParseError) as exc:
        print(json.dumps({"result":"COMMAND2_MASTER_NAT_FIRSTBOOT_BLOCKED",
            "reason":str(exc),"no_automatic_guest_restart_or_snapshot":True},
            sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
