#!/usr/bin/env python3
"""Count-driven OTHER-HOST Command 2 golden-master wizard (developer stage).

One invocation asks how many ADDITIONAL VMs (1-16), then coordinates
EXISTING guarded components: read-only resource/cold-image plan, clone
unique OS images and UEFI, define zero-NIC guests, install persistent
default/virbr0 NAT NIC+unique DHCP MAC/IP, prepare per-VM Windows NAT
configuration optical media. It PRESERVES the exact original Windows
apps/settings by cloning the verified private Command1 master bundle.

MODE plan is completely read-only. MODE stage requires interactive,
separately typed authorization from each existing safeguarded component.
It STOPS at Windows first boot: optical images are NOT auto-attached,
Windows guest hostname/DHCP settings are not executed, final live
snapshot + TPM revert are not proven. Reports cannot claim Command2 done.
No CAPE malware traffic on default unrestricted NAT is authorized.
NEVER runs on CSE-SSL-55 protected reference host.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import socket
import stat
import sys
import hashlib
import xml.etree.ElementTree as ET

import command1_export_existing_master as golden
import command2_portable_zero_nic_entrypoint as clones
import command2_portable_master_nat_attach as nat
import command2_portable_master_nat_media as media
import command2_portable_master_nat_profile as nat_plan

class GoldenCommand2Blocked(RuntimeError):pass
def need(ok,msg):
    if not ok:raise GoldenCommand2Blocked(msg)

def count_from_args(count):
    if count is None:
        need(sys.stdin.isatty(),
             "Interactive TTY needed to ask for additional Windows VM count")
        try:
            count=int(input("How many ADDITIONAL Windows VMs? (1-16): ").strip())
        except ValueError as exc:
            raise GoldenCommand2Blocked("Enter an integer 1..16") from exc
    need(type(count) is int and 1<=count<=16,
         "Exactly 1..16 additional Windows VMs are supported")
    return count

def paths(host,bundle,disk_dir,nvram_dir,journal_dir,iso_dir):
    clones.guard_host(host,"plan")
    proof=golden.manifest_check(bundle)
    need(proof.get("result")=="COMMAND1_COLD_MASTER_BUNDLE_BYTE_VERIFIED",
         "Private golden master bundle byte verification failed")
    src=Path(bundle)/golden.FILES["disk"]
    os_disk=Path(disk_dir)
    vars_dir=Path(nvram_dir)
    journal_dir=Path(journal_dir)
    iso_dir=Path(iso_dir)
    for value in (os_disk,vars_dir,journal_dir,iso_dir):
        need(value.is_absolute() and value.is_dir() and not value.is_symlink(),
             "Command2 needs separate existing absolute private destination dirs")
    need(len({str(x) for x in (os_disk,vars_dir,journal_dir,iso_dir)})==4,
         "Do not alias guest storage, firmware, identity, and ISO directories")
    need(stat.S_IMODE(iso_dir.stat().st_mode)==0o700 and
         iso_dir.stat().st_uid==0,
         "NAT Windows ISO directory must be root 0700")
    meta=json.loads((Path(bundle)/golden.MANIFEST).read_text())
    sha=meta["artifacts"]["disk"]["sha256"]
    need(proof["manifest_sha256"]==golden.sha(Path(bundle)/golden.MANIFEST),
         "Manifest changed after golden verification")
    return {"host":host,"bundle":Path(bundle),"template":src,
            "disk_sha":sha,"manifest_sha":proof["manifest_sha256"],
            "disk_dir":os_disk,"nvram_dir":vars_dir,
            "journal_dir":journal_dir,"iso_dir":iso_dir}

def run(mode,host,bundle,disk_dir,nvram_dir,journal_dir,iso_dir,count):
    need(mode in ("plan","stage"),"Unsupported Command2 stage mode")
    count=count_from_args(count)
    config=paths(host,bundle,disk_dir,nvram_dir,journal_dir,iso_dir)
    need(clones.stager.virsh("domstate","win11").lower()=="shut off",
         "Imported actual golden-master VM must remain shut off")
    master_uuid,master_nv=clones.source_profile()
    need(master_uuid==json.loads((config["bundle"]/golden.MANIFEST)
                   .read_text())["master_uuid"],
         "Imported master UUID differs from transferred original golden bundle")
    planned,resources=clones.proposal(
        count=count,approved_host=host,
        disk_dir=config["disk_dir"],nvram_dir=config["nvram_dir"],
        template=config["template"],subnet="auto")
    # The old zero-NIC staging planner still prepares a NONDEPLOYED
    # isolated-IP identity placeholder; the actual deploy network
    # MUST be the master's default NAT handled by nat.attach+media.
    natref=nat_plan.check_active_nat()
    natsubnet=natref["ipv4"]["subnet"]
    need(natref["nat_network"]=="default" and
         natref["bridge"]=="virbr0",
         "Approved master-style NAT reference absent")
    report={
      "result":("COMMAND2_EXACT_MASTER_NAT_WIZARD_PLAN_ONLY"
                if mode=="plan" else "COMMAND2_EXACT_MASTER_NAT_STAGE_PROGRESS"),
      "source":"private_exact_master_windows_disk_bundle",
      "master_identity_from_bundle_verified":True,
      "count_additional_vms":count,
      "names":["win11_"+str(i) for i in range(1,count+1)],
      "source_windows_apps_registry_files_preserved_by_image_clone":True,
      "source_master_stopped":True,
      "actual_nic_profile":"persistent_default_nat_e1000e",
      "actual_nat_subnet":natsubnet,
      "old_isolated_journal_ip_not_for_nic_application":True,
      "legacy_guest_isolated_config_JSON_must_not_be_run":True,
      "running_guest_snapshot_created":False,
      "TPM_revert_twice_accepted":False,
      "malware_execution_authorized":False,
      "all_N_guest_firstboot_automatic":False,
      "Command2_finished":False}
    if mode=="plan":
        report["resources"]=resources
        return report
    need(sys.stdin.isatty(),"Full N-guest stage needs direct operator TTY")
    need(input("Type STAGE-"+str(count)+"-EXACT-MASTER-WINDOWS-CLONES: ")==
         "STAGE-"+str(count)+"-EXACT-MASTER-WINDOWS-CLONES",
         "Operator declined large Windows guest clone/staging changes")
    # This stage uses the existing guarded all-N reservation and image
    # stager. It NEVER applies the legacy isolated network to guests.
    staged=clones.execute(
        count=count,approved_host=host,
        disk_dir=config["disk_dir"],nvram_dir=config["nvram_dir"],
        template=config["template"],template_sha256=config["disk_sha"],
        subnet="auto",journal_dir=config["journal_dir"],mode="stage")
    need(staged["result"]=="COMMAND2_ZERO_NIC_GROUP_STAGE_RETURNED",
         "Zero-NIC clone source-stage incomplete; STOP")
    journal=config["journal_dir"]/"command2-identity-reservation.json"
    # The NAT operations require all N currently shut off / zero NIC.
    attached=nat.apply(host,journal)
    need(attached["result"]==
         "COMMAND2_ALL_N_MASTER_NAT_NICS_AND_DHCP_APPLIED_VERIFIED",
         "One-NAT-per-VM or unique DHCP lease reservation incomplete; STOP")
    made=media.build(host,journal,config["iso_dir"])
    need(made["result"] in (
         "COMMAND2_ALL_N_WINDOWS_NAT_OPTICAL_MEDIA_BUILT",
         "COMMAND2_ALL_N_MASTER_NAT_MEDIA_BUILT"),
         "NAT guest provisioning media incomplete, review status")
    return {**report,
        "result":"COMMAND2_EXACT_MASTER_ALL_N_COLD_STAGE_NAT_MEDIA_READY",
        "zero_nic_stage_receipt":staged["result"],
        "persistent_nat_dhcp_receipt":attached["result"],
        "windows_nat_media_receipt":made["result"],
        "source_master_or_tpm_reused_for_clones":False,
        "windows_guest_boot_and_identity_still_required":True,
        "guest_running_snapshots_and_swtpm_revert_still_required":True,
        "end_to_end_unattended_complete":False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("plan","stage"),default="plan")
    parser.add_argument("--approved-host",required=True)
    parser.add_argument("--bundle",type=Path,required=True)
    parser.add_argument("--disk-dir",type=Path,required=True)
    parser.add_argument("--nvram-dir",type=Path,required=True)
    parser.add_argument("--journal-dir",type=Path,required=True)
    parser.add_argument("--iso-dir",type=Path,required=True)
    parser.add_argument("--count",type=int)
    a=parser.parse_args()
    try:
        print(json.dumps(run(a.mode,a.approved_host,a.bundle,
               a.disk_dir,a.nvram_dir,a.journal_dir,a.iso_dir,a.count),
               sort_keys=True,indent=2),flush=True)
        return 0
    except (GoldenCommand2Blocked,clones.Command2Blocked,
            clones.stager.StageBlocked,clones.reserve.ReservationBlocked,
            nat.NatAttachBlocked,nat.profile.PortableNatBlocked,
            media.NatMediaBlocked,golden.MasterExportBlocked,ValueError,
            TypeError,KeyError,OSError,ET.ParseError) as exc:
        print(json.dumps({"result":"COMMAND2_GOLDEN_MASTER_NAT_WIZARD_BLOCKED",
            "reason":str(exc),"do_not_blind_retry_partial_guest_stage":True},
            sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
