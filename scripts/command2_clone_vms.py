#!/usr/bin/env python3
"""Command 2 (developer-stage): guarded Windows clone provisioning.

Ask VM count if omitted. Requires a reviewed JSON deployment profile and
an existing isolated libvirt network. Apply mode provisions clones from a
verified COLD master snapshot, personalizes offline, starts only benign
validation guests, checks host ping + CAPE agent, creates analysis snapshots,
and updates CAPE machine registration after all guests pass.

NOT a network-isolation certificate or permission to run live malware.
No automatic host/guest security disablement. Never mutates master disks.
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

import clone_domain_xml
import export_cold_master_disk
import personalize_clone_windows
import register_cape_clones
import verify_clone_agent

SCHEMA = "cape-command2-profile-v1"
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,90}\Z")
RESERVE = 30 * 1024 ** 3
MAX_COUNT = 32

class ProvisionError(RuntimeError):
    pass


def cmd(*args: str, timeout: int = 60) -> str:
    try:
        x = subprocess.run(args, check=True, capture_output=True,
                           text=True, timeout=timeout)
        return x.stdout.strip()
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        # Never dump full source XML or private host configuration in failure.
        message = (exc.stderr[:600] if isinstance(exc, subprocess.CalledProcessError)
                   and exc.stderr else str(exc)[:500])
        raise ProvisionError(f"{args[0]} command failed: {message}") from exc


def virsh(*args: str, timeout: int = 60) -> str:
    return cmd("virsh", "-c", "qemu:///system", *args, timeout=timeout)


def load_profile(filename: Path) -> dict:
    if filename.is_symlink() or not filename.is_file():
        raise ProvisionError("Deployment profile missing or symlinked")
    data = json.loads(filename.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ProvisionError("Unsupported deployment profile schema")
    for key in ("master", "snapshot", "network", "disk_dir", "nvram_dir",
                "old_ipv4", "first_ipv4", "mask", "gateway", "dns", "cape_config",
                "snapshot_name"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise ProvisionError(f"Required profile field absent: {key}")
    for key in ("master", "snapshot", "network", "snapshot_name"):
        if not NAME.fullmatch(data[key]):
            raise ProvisionError(f"Invalid deployment profile name: {key}")
    for key in ("disk_dir", "nvram_dir", "cape_config"):
        p = Path(data[key])
        if not p.is_absolute() or ".." in p.parts:
            raise ProvisionError(f"Unsafe profile destination path: {key}")
    for key in ("old_ipv4", "first_ipv4", "gateway", "dns"):
        try:
            ipaddress.IPv4Address(data[key])
        except ValueError as exc:
            raise ProvisionError(f"Invalid profile IPv4 field: {key}") from exc
    # An offline Windows hostname is not the libvirt name: '_' is forbidden.
    return data


def candidates(count: int, profile: dict, existing: set[str]) -> list[dict]:
    if not 1 <= count <= MAX_COUNT:
        raise ProvisionError(f"Clone count must be between 1 and {MAX_COUNT}")
    subnet = ipaddress.IPv4Network("0.0.0.0/" + profile["mask"])
    start = ipaddress.IPv4Address(profile["first_ipv4"])
    net = ipaddress.IPv4Network(f"{start}/{subnet.prefixlen}", strict=False)
    try:
        excluded = {ipaddress.IPv4Address(profile["old_ipv4"]),
                    ipaddress.IPv4Address(profile["gateway"]),
                    ipaddress.IPv4Address(profile["dns"])}
        excluded.update(ipaddress.IPv4Address(x)
                        for x in profile.get("reserved_ipv4", []))
    except ValueError as exc:
        raise ProvisionError("Invalid reserved IPv4 address") from exc
    if profile["master"] in existing:
        existing.discard(profile["master"])
    result = []
    for index in range(1, count + 1):
        name = f"win11_{index}"
        if not NAME.fullmatch(name) or name in existing:
            raise ProvisionError(f"VM already exists or has unsafe name: {name}")
        ip = start + index - 1
        if ip not in net or ip in (net.network_address, net.broadcast_address) or ip in excluded:
            raise ProvisionError(f"Requested IP is unavailable or outside subnet: {ip}")
        excluded.add(ip)
        result.append({"name": name, "ip": str(ip),
                       "windows_hostname": f"WIN11-{index}"})
    return result


def check_network(name: str, desired_ip: str, mask: str) -> str:
    root = ET.fromstring(virsh("net-dumpxml", name))
    clone_domain_xml.validate_no_forward_network(ET.tostring(root, encoding="unicode"))
    if root.findtext("name") != name:
        raise ProvisionError("Network XML name does not match selected name")
    ips = root.findall("./ip")
    if len(ips) != 1 or ips[0].get("family", "ipv4") != "ipv4":
        raise ProvisionError("Expected one bridge IPv4 and no IPv6 addresses")
    netmask = ips[0].get("netmask")
    prefix = ips[0].get("prefix")
    address = ips[0].get("address")
    if not address:
        raise ProvisionError("Selected network lacks a gateway IP")
    prefix_len = ipaddress.IPv4Network(
        "0.0.0.0/" + (netmask or (prefix or ""))).prefixlen
    target = ipaddress.IPv4Network(desired_ip + "/" + mask, strict=False)
    selected = ipaddress.IPv4Network(address + "/" + str(prefix_len), strict=False)
    if target != selected:
        raise ProvisionError("Selected network subnet does not match static guest IPv4 subnet")
    bridge = root.find("bridge")
    if bridge is None or not bridge.get("name"):
        raise ProvisionError("No isolated libvirt bridge name")
    return bridge.get("name")


def safe_destinations(path: Path) -> None:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise ProvisionError(f"Root-controlled destination directory required: {path}")
    s = path.stat()
    if s.st_uid != 0 or s.st_mode & 0o022:
        raise ProvisionError(f"Directory not root controlled or is writable by others: {path}")


def disk_and_nvram_paths(item: dict, profile: dict) -> tuple[Path, Path]:
    disk = Path(profile["disk_dir"]) / (item["name"] + ".qcow2")
    vars = Path(profile["nvram_dir"]) / (item["name"] + "_VARS.fd")
    if disk.exists() or disk.is_symlink() or vars.exists() or vars.is_symlink():
        raise ProvisionError(f"Destination data already exists for {item['name']}; refusing overwrite")
    return disk, vars


def preflight(profile: dict, count: int, mode: str) -> tuple[list[dict], str, str, str, str]:
    if mode == "apply" and os.geteuid() != 0:
        raise ProvisionError("Apply mode requires root")
    if virsh("domstate", profile["master"]) != "shut off":
        raise ProvisionError("Master VM must remain shut off during cloning")
    names = set(virsh("list", "--all", "--name").splitlines())
    items = candidates(count, profile, set(names))
    bridge = check_network(profile["network"], profile["first_ipv4"], profile["mask"])
    if virsh("net-info", profile["network"]).find("Active:") < 0:
        raise ProvisionError("Cannot inspect network state")
    if not re.search(r"^\s*Active:\s+yes\s*$", virsh("net-info", profile["network"]), re.M):
        raise ProvisionError("Selected analysis network is not active")
    safe_destinations(Path(profile["disk_dir"]))
    safe_destinations(Path(profile["nvram_dir"]))
    top, chain, size = export_cold_master_disk.source_state(
        profile["master"], profile["snapshot"])
    if len(chain) < 2:
        raise ProvisionError("Master does not have expected external snapshots")
    master_xml = virsh("dumpxml", "--inactive", profile["master"])
    root = ET.fromstring(master_xml)
    nvram = root.find("./os/nvram")
    if nvram is None or not nvram.text or not Path(nvram.text).is_file():
        raise ProvisionError("Master UEFI NVRAM copy source is missing")
    if os.path.realpath(nvram.text) in chain:
        raise ProvisionError("Invalid shared NVRAM / disk path")
    for item in items:
        disk, vars = disk_and_nvram_paths(item, profile)
        export_cold_master_disk.check_destination(disk, chain, size)
        clone_domain_xml.render(master_xml, name=item["name"],
            uuid_value=str(uuid.uuid5(uuid.UUID(root.findtext("uuid")),
                                "cape-clone:" + item["name"])),
            mac=make_mac(root.findtext("uuid"),item["name"]),
            clone_disk=str(disk),clone_nvram=str(vars),
            isolated_network=profile["network"])
    available=shutil.disk_usage(profile["disk_dir"]).free
    if available < count*size+RESERVE:
        raise ProvisionError("Insufficient conservative storage for requested count")
    ram=root.find("./memory")
    if ram is None or ram.get("unit","KiB").lower() != "kib":
        raise ProvisionError("Unsupported source memory unit")
    per_vm=int(ram.text)*1024
    meminfo=Path("/proc/meminfo").read_text()
    free_match=re.search(r"^MemAvailable:\s+(\d+)\s+kB",meminfo,re.M)
    if free_match is None or count*per_vm > int(free_match.group(1))*1024*0.75:
        raise ProvisionError("Insufficient host RAM for simultaneous requested clones")
    if mode == "apply":
        for tool in ("qemu-img","virt-win-reg","virsh","apparmor_parser"):
            if not shutil.which(tool):
                raise ProvisionError(f"Required compatible host tool missing: {tool}")
        if not profile.get("benign_test_only_acknowledged",False):
            raise ProvisionError("Operator must acknowledge harmless test boots only in the reviewed profile")
    return items,master_xml,top,bridge,nvram.text.strip()


def make_mac(master_uuid: str, name: str) -> str:
    import hashlib
    digest=hashlib.sha256((master_uuid+":"+name).encode()).digest()[:5]
    return "02:"+":".join(f"{x:02x}" for x in digest)


def copy_nvram(source: str, target: Path) -> None:
    data=Path(source).read_bytes()
    if not data or len(data)>32*1024*1024:
        raise ProvisionError("Invalid OVMF variable store size")
    fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def define(vm_xml: str) -> None:
    fd,path=tempfile.mkstemp(prefix="cape-clone-",suffix=".xml")
    try:
        with os.fdopen(fd,"w") as f:
            f.write(vm_xml)
        virsh("define",path)
    finally:
        os.unlink(path)


def snapshot_running(name: str, snapshot: str) -> None:
    virsh("snapshot-create-as","--domain",name,"--name",snapshot,
          "--description","CAPE agent verified; clone clean analysis baseline",
          "--atomic",timeout=180)
    xml=ET.fromstring(virsh("snapshot-dumpxml",name,snapshot))
    if xml.findtext("./name")!=snapshot or xml.findtext("./state")!="running":
        raise ProvisionError(f"Snapshot {snapshot} not confirmed as running-state")
    mem = xml.find("./memory")
    if mem is None or mem.get("snapshot") == "no":
        raise ProvisionError("CAPE baseline did not capture running guest memory state")


def guest_shutdown(name: str, limit: int=120) -> None:
    if virsh("domstate",name)=="shut off":
        return
    virsh("shutdown",name)
    stop=time.monotonic()+limit
    while time.monotonic()<stop:
        if virsh("domstate",name)=="shut off":
            return
        time.sleep(3)
    raise ProvisionError(f"VM {name} did not shut down gracefully after verification")


def create_one(item: dict, profile: dict, master_xml: str,
               master_nvram: str, journal) -> dict:
    root=ET.fromstring(master_xml)
    source_uuid=root.findtext("uuid")
    if not source_uuid:
        raise ProvisionError("Master UUID missing")
    disk, vars=disk_and_nvram_paths(item,profile)
    out={"name":item["name"],"ip":item["ip"],"status":"NOT_CREATED"}
    def record(state):
        out["status"]=state
        journal({"vm":item["name"],"state":state})
    record("COLD_EXPORT_START")
    export_cold_master_disk.export(profile["master"],profile["snapshot"],disk,dry_run=False)
    record("COLD_EXPORT_COMPLETE")
    personalize_clone_windows.prepare(
        disk,profile["old_ipv4"],item["ip"],item["windows_hostname"],
        profile["mask"],profile["gateway"],"apply",profile["dns"])
    record("GUEST_STATIC_IP_OFFLINE_UPDATED")
    copy_nvram(master_nvram,vars)
    record("INDEPENDENT_NVRAM_CREATED")
    rendered=clone_domain_xml.render(
        master_xml,name=item["name"],
        uuid_value=str(uuid.uuid5(uuid.UUID(source_uuid),
                                  "cape-clone:"+item["name"])),
        mac=make_mac(source_uuid,item["name"]),
        clone_disk=str(disk),clone_nvram=str(vars),
        isolated_network=profile["network"])
    define(rendered)
    record("VM_DEFINED_NOT_STARTED")
    # These are ONLY harmless Windows/agent boot-health checks. No samples.
    virsh("start",item["name"],timeout=180)
    record("GUEST_BOOTED_BENIGN_CHECK")
    try:
        health=verify_clone_agent.wait_for_agent(item["ip"],timeout=240)
    except Exception:
        # The new VM is untrusted or misconfigured: power it off without
        # changing master or continuing to configure other clones.
        try:
            virsh("destroy",item["name"],timeout=90)
        except Exception:
            pass
        raise
    out["agent_verification"]=health
    record("PING_AND_CAPE_AGENT_VERIFIED")
    snapshot_running(item["name"],profile["snapshot_name"])
    record("RUNNING_STATE_SNAPSHOT_CREATED")
    guest_shutdown(item["name"])
    record("POST_SNAPSHOT_GRACEFUL_SHUTDOWN")
    # Restart test reproduces the AppArmor/snapshot issue found on SSL-55.
    virsh("start", item["name"], timeout=180)
    verify_clone_agent.wait_for_agent(item["ip"], timeout=240)
    record("RESTART_PING_AND_CAPE_AGENT_VERIFIED")
    guest_shutdown(item["name"])
    # This is a fresh, disposable clone: explicitly test the real CAPE
    # rollback primitive before registering it as an analysis machine.
    virsh("snapshot-revert", item["name"], profile["snapshot_name"],
          "--running", timeout=240)
    verify_clone_agent.wait_for_agent(item["ip"], timeout=240)
    record("SNAPSHOT_REVERT_PING_AND_CAPE_AGENT_VERIFIED")
    guest_shutdown(item["name"])
    record("CLONE_SHUT_OFF_READY_FOR_CAPE_REGISTRATION")
    return out


def write_report(reportdir: Path, data: dict) -> Path:
    reportdir.mkdir(mode=0o700,parents=True,exist_ok=True)
    path=reportdir / ("cape_command2_"+datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")+"_"+str(os.getpid())+".json")
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as file:
        json.dump(data,file,indent=2,sort_keys=True)
    return path


def run(profile: dict, count: int, mode: str, reportdir: Path) -> dict:
    output={"mode":mode,"count":count,"status":"PREFLIGHT",
            "completed":[],"failure":None,
            "master_never_modified":True,
            "live_malware_not_authorized":True}
    try:
        items, master_xml, _top, bridge, master_nvram = preflight(profile,count,mode)
        output["proposed"]=[{"name":x["name"],"ip":x["ip"],
                             "windows_hostname":x["windows_hostname"]}
                            for x in items]
        output["network_bridge"]=bridge
        if mode=="plan":
            output["status"]="PLAN_ONLY_NO_CHANGES"
            return output
        if not Path(profile["cape_config"]).is_file():
            raise ProvisionError("Expected existing CAPE kvm.conf missing")
        # Confirm config can be rendered before creating a clone, but with
        # future name inventory simulated. Existing placeholders are preserved
        # in source config and retired from the active machine list if absent.
        source_config=Path(profile["cape_config"]).read_text()
        current=set(virsh("list","--all","--name").splitlines())
        preview=[{"name":x["name"],"ip":x["ip"]} for x in items]
        register_cape_clones.render_config(
            source_config,preview,libvirt_existing=current|{x["name"] for x in items},
            snapshot=profile["snapshot_name"],interface=bridge)
        def journal(entry):
            output["completed"].append(entry)
            write_report(reportdir,{"journal_event":entry,
                         "master_never_modified":True})
        success=[]
        for item in items:
            result=create_one(item,profile,master_xml,master_nvram,journal)
            success.append(result)
        # Every clone is shut off and has a running-state snapshot before
        # introducing it to CAPE. No stale CAPE entry is silently clobbered.
        current=set(virsh("list","--all","--name").splitlines())
        new_config=register_cape_clones.render_config(
            source_config,preview,libvirt_existing=current,
            snapshot=profile["snapshot_name"],interface=bridge)
        saved=register_cape_clones.apply_config(Path(profile["cape_config"]),new_config)
        output["cape_backup"]=str(saved)
        output["status"]="CLONES_VERIFIED_CAPE_CONFIG_UPDATED_RESTART_PENDING"
        output["ready"]=success
        output["warnings"]=[
            "CAPE snapshots were reverted once on fresh clones; periodic recovery tests remain necessary",
            "CAPE services were not restarted; inspect ongoing analyses before restart",
            "No real malware until institutional approval and guest IPv4/IPv6 isolation tests",
            "Windows software remains copied from master; BitLocker/TPM rekey and Windows activation require verification",
        ]
        return output
    except Exception as exc:
        output["status"]="STOPPED_REQUIRES_OPERATOR_REVIEW"
        output["failure"]=str(exc)[:1600]
        return output


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile",required=True,type=Path)
    parser.add_argument("--mode",choices=("plan","apply"),default="plan")
    parser.add_argument("--count",type=int,help="Omit for interactive count prompt")
    parser.add_argument("--reportdir",type=Path,default=Path.home()/"cape_clone_reports")
    a=parser.parse_args(argv)
    try:
        if a.count is None:
            if not sys.stdin.isatty():
                raise ProvisionError("Noninteractive use requires --count N")
            try:
                a.count=int(input("How many Windows analysis VMs should be created? ").strip())
            except (ValueError,EOFError) as exc:
                raise ProvisionError("Enter a whole-number VM count") from exc
        profile=load_profile(a.profile)
        report=run(profile,a.count,a.mode,a.reportdir)
        path=write_report(a.reportdir,report)
        print("Report:",path)
        print("Result:",report["status"])
        print("Master source snapshots unchanged by command.")
        if report.get("failure"):
            print("STOP:",report["failure"],file=sys.stderr)
        return 0 if report["status"] in (
            "PLAN_ONLY_NO_CHANGES",
            "CLONES_VERIFIED_CAPE_CONFIG_UPDATED_RESTART_PENDING") else 2
    except (ProvisionError,OSError,ValueError,json.JSONDecodeError) as exc:
        print(f"STOP: {exc}",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
