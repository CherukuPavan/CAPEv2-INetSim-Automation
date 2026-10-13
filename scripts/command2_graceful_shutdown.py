#!/usr/bin/env python3
"""Gracefully shut down ONLY a pinned CAPE Windows clone and verify SHUT OFF.

libvirt shutdown returns when a REQUEST was submitted; a subsequent actual
'shut off' state is REQUIRED. Prefer verified live QEMU guest-agent channel,
then one ACPI power button event if the OS does not stop. Never invoke
destroy, reset, managedsave, snapshot, force, or alter libvirt XML/firmware.

SSL55 is restricted to win11_1 and protected master/trial. Portable targets
require a canonical count-driven Command2 private reservation. The separate
portable-master-nat scope accepts only exactly snapshotted golden NAT clones,
with saved+live one-NIC identity checks before a graceful SHUT OFF handoff.
This is NOT proof of swtpm-safe snapshot revert or malware containment.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

VM_RE=re.compile(r"win11_([1-9]|1[0-6])\Z")
LOCK=Path("/run/lock/cape-command2-graceful-shutdown.lock")
SSL55_UUID="732b2256-ee99-41fa-881d-fbf5c476d960"
PROTECTED={"win11":"289d89be-68ec-4c62-90e1-ea930849266f",
           "win11_trial_1":"e75f6fef-347d-462f-9738-4de3df6bfa74"}
class ShutdownBlocked(RuntimeError):pass
def need(ok,msg):
    if not ok:raise ShutdownBlocked(msg)

def virsh(*args,timeout=30):
    try:
        p=subprocess.run(["virsh","-c","qemu:///system",*args],
                         text=True,capture_output=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ShutdownBlocked("libvirt command unavailable or timed out: "+args[0]) from exc
    need(p.returncode==0,"libvirt request rejected: "+args[0])
    return p.stdout.strip()

def state(vm):
    return virsh("domstate",vm).lower()

def guard(host,scope,vm,journal):
    need(os.geteuid()==0,"Root required for exact VM identity admission")
    current=socket.gethostname().split(".",1)[0].lower()
    need(current==host and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}",host or ""),
         "Approved hostname differs")
    if scope=="ssl55-clone":
        need(current=="cse-ssl-55" and vm=="win11_1" and journal is None,
             "Protected SSL55 permits ONLY win11_1, no arbitrary guest")
        for master,uid in PROTECTED.items():
            need(virsh("domuuid",master).lower()==uid and
                 state(master)=="shut off",
                 "Protected master/trial changed identity or state")
        return {"uuid":SSL55_UUID,
                "disk":"/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2",
                "nvram":"/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd",
                "mac":"02:0a:30:6a:3f:50"}
    need(scope in ("portable-other","portable-master-nat") and
         current not in ("ssl-55","cse-ssl-55"),
         "Portable workflow forbidden on protected SSL55")
    import command2_portable_workflow as flow
    flow.canonical_host(host)
    need(type(vm) is str and VM_RE.fullmatch(vm) and
         isinstance(journal,Path) and journal.is_absolute() and
         journal.name=="command2-identity-reservation.json",
         "Exact reserved VM/private journal required")
    if scope=="portable-master-nat":
        # The canonical golden-master NAT profile is deliberately NOT the
        # older isolated network. Require an actual running-state snapshot
        # already captured before using this final CAPE handoff shutdown.
        import ipaddress
        import command2_portable_master_nat_attach as nat
        rows=nat.journal_rows(host,journal)
        row=next((r for r in rows if r["libvirt_name"]==vm),None)
        need(row is not None,"NAT clone absent from canonical count journal")
        need(state("win11")=="shut off","Original master must remain shut off")
        net,views=nat.check_network_references()
        need(net["nat_network"]=="default" and net["bridge"]=="virbr0",
             "Golden master's persistent NAT bridge changed")
        network=ipaddress.IPv4Network(net["ipv4"]["subnet"])
        need(network.prefixlen==24 and network.is_private,
             "Master NAT subnet no longer the reviewed private /24")
        index=int(VM_RE.fullmatch(vm).group(1))
        expected_ip=str(ipaddress.IPv4Address(
            int(network.network_address)+200+index))
        entry=(row["mac_candidate"].lower(),expected_ip,"WIN11-"+str(index))
        need(all(nat.reservations(view).count(entry)==1 for view in views),
             "Final NAT guest DHCP reservation changed")
        snap="cape_one_nat_"+vm
        need(virsh("snapshot-list",vm,"--name").splitlines()==[snap],
             "NAT handoff shutdown needs exactly one existing running snapshot")
        saved=ET.fromstring(virsh("snapshot-dumpxml",vm,snap))
        memory=saved.find("memory")
        need(saved.tag=="domainsnapshot" and
             saved.findtext("name")==snap and
             saved.findtext("state")=="running" and
             memory is not None and memory.get("snapshot")=="internal",
             "NAT final snapshot has no proven RUNNING RAM checkpoint")
        # Direct invocations of this helper must not bypass the final
        # all-N wrapper's full RAM + Windows disk + QCOW2 UEFI admission.
        import command2_portable_master_nat_running_snapshots as verified
        verified.libvirt_snapshot(vm,True)
        verified.images(row,True)
        all_domains=nat.virsh("list","--all","--name").splitlines()
        if "win11_trial_1" in all_domains:
            need(state("win11_trial_1")=="shut off",
                 "Protected Windows trial must remain shut off")
        return {"uuid":row["libvirt_uuid_candidate"],
                "disk":row["disk_target"],
                "nvram":row["uefi_nvram_target"],
                "mac":row["mac_candidate"],"network":"default",
                "nic_model":"e1000e","reserved_nat_ipv4":expected_ip,
                "running_snapshot":snap}
    row,_,_=flow.load_guest(journal,host,vm)
    need(state("win11")=="shut off","Original master must remain shut off")
    return {"uuid":row["libvirt_uuid_candidate"],"disk":row["disk_target"],
            "nvram":row["uefi_nvram_target"],"mac":row["mac_candidate"]}

def capabilities(xml,vm,expected):
    root=ET.fromstring(xml)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==vm and root.findtext("uuid")==expected["uuid"],
         "Domain identity/KVM definition differs")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].find("source") is not None and
         disks[0].find("source").get("file")==expected["disk"] and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2",
         "Guest disk is not expected independent QCOW2")
    nv=root.find("./os/nvram")
    need(nv is not None and nv.text in
         (expected["nvram"],expected["nvram"]+".qcow2") and
         nv.get("format","raw")==
             ("qcow2" if nv.text.endswith(".qcow2") else "raw"),
         "Guest independent OVMF path/format differs")
    nics=root.findall("./devices/interface")
    need(len(nics)==1 and nics[0].get("type")=="network" and
         nics[0].find("source") is not None and
         nics[0].find("source").get("network")==
             expected.get("network","cape-analysis-isolated") and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address","").lower()==expected["mac"] and
         (expected.get("nic_model") is None or (
             nics[0].find("model") is not None and
             nics[0].find("model").get("type")==expected["nic_model"])),
         "Guest has an unexpected analysis NIC/MAC/model")
    tpm=root.find("./devices/tpm/backend")
    need(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0","Independent TPM2 missing")
    for tag in ("hostdev","filesystem","redirdev","shmem","vsock"):
        need(not root.findall("./devices/"+tag),
             "Unapproved host passthrough device: "+tag)
    channels=root.findall("./devices/channel")
    qga=[ch for ch in channels if ch.get("type")=="unix" and
         ch.find("target") is not None and
         ch.find("target").get("type")=="virtio" and
         ch.find("target").get("name")=="org.qemu.guest_agent.0"]
    need(len(qga)==len(channels) and len(qga)<=1,
         "Unapproved/duplicate host-connected guest channel")
    acpi=root.find("./features/acpi") is not None
    need(acpi or bool(qga),
         "Neither ACPI nor verified QGA channel available")
    return {"acpi":acpi,"qga_channel":bool(qga),"disk":expected["disk"],
            "nvram":nv.text,"mac":expected["mac"]}

def inspect(host,scope,vm,journal=None):
    expected=guard(host,scope,vm,journal)
    need(virsh("domuuid",vm).lower()==expected["uuid"],
         "Exact guest libvirt UUID changed")
    status=state(vm)
    need(status in ("running","shut off"),
         "Refuse paused/saved/crashed guest state")
    saved=virsh("dumpxml","--inactive",vm)
    cap=capabilities(saved,vm,expected)
    if status=="running":
        live=virsh("dumpxml",vm)
        need(capabilities(live,vm,expected)==cap,
             "Running and saved guest devices differ")
    return {"result":"COMMAND2_GRACEFUL_SHUTDOWN_PLAN_ONLY","host":host,
            "scope":scope,"vm":vm,"uuid":expected["uuid"],"state":status,
            "already_off":status=="shut off","capabilities":cap,
            "saved_xml_sha256":hashlib.sha256(saved.encode()).hexdigest(),
            "shutdown_completed":status=="shut off",
            "shutdown_requested":False,"forced_poweroff":False,
            "libvirt_or_guest_modified":False}

def await_stop(vm,deadline,clock,sleep):
    while True:
        current=state(vm)
        if current=="shut off":return True
        need(current in ("running","in shutdown"),
             "VM in unexpected state during graceful shutdown: "+current)
        remaining=deadline-clock()
        if remaining<=0:return False
        sleep(min(5,remaining))

def request_shutdown(host,scope,vm,journal=None,timeout_seconds=360,
                     *,clock=time.monotonic,sleep=time.sleep):
    need(type(timeout_seconds) is int and 90<=timeout_seconds<=900,
         "Expected grace period 90..900 seconds")
    baseline=inspect(host,scope,vm,journal)
    if baseline["already_off"]:
        return {**baseline,"result":"COMMAND2_GRACEFUL_SHUTDOWN_ALREADY_OFF",
                "no_shutdown_request_needed":True}
    need(sys.stdin.isatty(),"Direct operator terminal required")
    print(json.dumps(baseline,indent=2,sort_keys=True),flush=True)
    phrase="SHUTDOWN-COMMAND2-"+vm.upper()
    need(input("Type "+phrase+" for automatic graceful shutdown only: ")==phrase,
         "Graceful shutdown not approved")
    need(not LOCK.is_symlink(),"Untrusted shutdown lock path")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Root-only shutdown lock invalid")
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ShutdownBlocked("Another guest shutdown already in progress") from exc
        need(inspect(host,scope,vm,journal)==baseline,
             "Live VM/master/config changed after authorization")
        attempted=[]
        deadline=clock()+timeout_seconds
        if baseline["capabilities"]["qga_channel"]:
            try:
                virsh("shutdown",vm,"--mode","agent")
                attempted.append("agent-request-accepted")
                if await_stop(vm,min(deadline,clock()+35),clock,sleep):
                    return finish(host,scope,vm,journal,attempted)
            except ShutdownBlocked:
                attempted.append("agent-request-rejected")
        if baseline["capabilities"]["acpi"] and state(vm) in ("running","in shutdown"):
            try:
                virsh("shutdown",vm,"--mode","acpi")
                attempted.append("acpi-request-accepted")
            except ShutdownBlocked:
                attempted.append("acpi-request-rejected")
        if await_stop(vm,deadline,clock,sleep):
            return finish(host,scope,vm,journal,attempted)
        raise ShutdownBlocked("Graceful shutdown TIMEOUT: Windows ignored/stalled "
              +",".join(attempted)+"; VM still active; NO force-off/reset used")
    finally:
        os.close(fd)

def finish(host,scope,vm,journal,attempted):
    need(state(vm)=="shut off","Shutdown REQUEST is not completion")
    final=guard(host,scope,vm,journal)
    need(virsh("domuuid",vm).lower()==final["uuid"],
         "Guest identity/master changed after shutdown")
    return {"result":"COMMAND2_GRACEFUL_SHUTDOWN_SHUT_OFF_CONFIRMED",
            "vm":vm,"state":"shut off","request_attempts":attempted,
            "shutdown_state_observed":True,
            "specific_shutoff_cause_independently_proven":False,
            "safe_for_separately_guarded_cold_operation":True,
            "forced_poweroff":False,"disk_tpm_nvram_modified_by_helper":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--scope",choices=("ssl55-clone","portable-other","portable-master-nat"),required=True)
    p.add_argument("--approved-host",required=True)
    p.add_argument("--vm",required=True)
    p.add_argument("--journal",type=Path)
    p.add_argument("--mode",choices=("plan","shutdown"),default="plan")
    p.add_argument("--timeout-seconds",type=int,default=360)
    a=p.parse_args()
    try:
        out=inspect(a.approved_host,a.scope,a.vm,a.journal) if a.mode=="plan" else (
            request_shutdown(a.approved_host,a.scope,a.vm,a.journal,a.timeout_seconds))
        print(json.dumps(out,indent=2,sort_keys=True))
        return 0
    except (ShutdownBlocked,OSError,ValueError,TypeError,ET.ParseError) as err:
        print(json.dumps({"result":"COMMAND2_GRACEFUL_SHUTDOWN_BLOCKED",
              "reason":str(err),"never_force_power_off":True,
              "never_continue_cold_operation_until_shut_off_verified":True},
              sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
