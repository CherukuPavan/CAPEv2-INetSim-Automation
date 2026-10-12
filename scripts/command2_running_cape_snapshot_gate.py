#!/usr/bin/env python3
"""Guarded CAPE *running* snapshot on a dedicated OTHER KVM host.

Plan and capture ONLY; NEVER restore, start/stop VMs, attach NICs,
reconfigure CAPE, or act on protected SSL-55. Capture needs separately
validated, recorded isolation + guest acceptance; this module cannot
itself prove guest network isolation or swtpm/UEFI revert correctness.

CAPE expects a snapshot of a running Windows agent, not a cold disk copy.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import command2_cape_agent_probe as agentprobe

SENTINEL = Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
LOCK = Path("/run/lock/cape-command2-running-snapshot.lock")
VM_RE = re.compile(r"win11_([1-9]|1[0-6])\Z")
SNAP_RE = re.compile(r"cape_ready_win11_([1-9]|1[0-6])\Z")
MAX_RECEIPT_BYTES = 65536


class SnapshotBlocked(RuntimeError):
    pass


def require(test, msg):
    if not test:
        raise SnapshotBlocked(msg)


def readcmd(*argv, timeout=30):
    try:
        res = subprocess.run(argv, check=False, capture_output=True,
                             text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as err:
        raise SnapshotBlocked("Host command failed or timed out: "+argv[0]) from err
    require(res.returncode == 0, "Host command returned failure: "+argv[0])
    return res.stdout.strip()


def virsh(*argv, timeout=30):
    return readcmd("virsh", "-c", "qemu:///system", *argv, timeout=timeout)


def target_guard(expected_host):
    name = socket.gethostname().split(".", 1)[0].lower()
    require(name not in ("ssl-55", "cse-ssl-55") and
            not SENTINEL.exists() and not SENTINEL.is_symlink(),
            "REFERENCE_HOST_PROTECTED: snapshot prohibited")
    require(re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}", expected_host or ""),
            "Approved target hostname required")
    require(name == expected_host, "Approved target is not this host")


def planned_name(name):
    require(type(name) is str and VM_RE.fullmatch(name) is not None,
            "VM name must be win11_1..win11_16")
    return "cape_ready_" + name


def saved_xml_checks(name, expected_uuid, expected_mac, expected_ip, subnet):
    """Read actual running domain and validate exact single isolated NIC."""
    require(virsh("domstate", name) == "running",
            "CAPE snapshot requires RUNNING Windows guest")
    actual_uuid = virsh("domuuid", name).lower()
    require(actual_uuid == expected_uuid,
            "libvirt UUID differs from authoritative reservation")
    raw = virsh("dumpxml", name)
    root = ET.fromstring(raw)
    require(root.tag == "domain" and root.get("type") == "kvm" and
            root.findtext("name") == name and root.findtext("uuid") == expected_uuid,
            "Live KVM domain identity differs")
    # A generic internal disk+memory snapshot is not safe for a live
    # Windows guest whose OVMF pflash varstore remains RAW. Restore
    # compatibility must be validated separately, never inferred from
    # a snapshot-create-as --print-xml success.
    loader = root.find("./os/loader")
    nvram = root.find("./os/nvram")
    require(not (
        loader is not None and loader.get("type") == "pflash" and
        nvram is not None and nvram.get("format", "raw") == "raw"
    ), "RAW_PFLASH_NVRAM_INTERNAL_SNAPSHOT_NOT_APPROVED: use validated "
       "memory/disk/UEFI/TPM restore design; no generic --atomic capture")
    devices = root.find("devices")
    require(devices is not None, "VM has no reviewed devices")
    nics = devices.findall("interface")
    require(len(nics) == 1 and nics[0].get("type") == "network" and
            nics[0].find("source") is not None and
            nics[0].find("source").get("network") == "cape-analysis-isolated" and
            nics[0].find("mac") is not None and
            nics[0].find("mac").get("address", "").lower() == expected_mac,
            "CAPE VM lacks its one exact isolated analysis NIC")
    require(not any(devices.findall(tag) for tag in
                    ("hostdev","filesystem","redirdev","channel","shmem","vsock")),
            "Unapproved host-connected device on analysis guest")
    disks = devices.findall("./disk[@device='disk']")
    require(len(disks) == 1 and disks[0].get("type") == "file" and
            disks[0].find("driver") is not None and
            disks[0].find("driver").get("type") == "qcow2" and
            disks[0].find("source") is not None and
            disks[0].find("source").get("file", "").endswith(
                "/" + name + ".command2.qcow2"),
            "Unexpected unreviewed guest disk/format")
    tpm = devices.find("tpm")
    require(tpm is not None and tpm.find("backend") is not None and
            tpm.find("backend").get("type") == "emulator" and
            tpm.find("backend").get("version") == "2.0",
            "Guest TPM not independently reviewed")
    require(root.findtext("./os/nvram", "").endswith(
        "/" + name + ".command2_VARS.fd"),
        "Guest UEFI variables path not independent")
    network_status = virsh("net-info", "cape-analysis-isolated")
    require(re.search(r"^Active:\s+yes\s*$", network_status, re.M|re.I) is not None,
            "Isolated libvirt network is not active")
    try:
        network = ipaddress.IPv4Network(subnet, strict=True)
        assigned = ipaddress.IPv4Address(expected_ip)
        ordinal = int(VM_RE.fullmatch(name).group(1))
    except (ValueError, TypeError, AttributeError) as exc:
        raise SnapshotBlocked("Invalid exact guest subnet/IP") from exc
    rfc1918 = (ipaddress.IPv4Network("10.0.0.0/8"),
               ipaddress.IPv4Network("172.16.0.0/12"),
               ipaddress.IPv4Network("192.168.0.0/16"))
    require(network.prefixlen == 24 and
            any(network.subnet_of(net) for net in rfc1918) and
            assigned == ipaddress.IPv4Address(
                int(network.network_address) + 100 + ordinal),
            "Guest IP does not match reserved private /24 and VM index")
    return hashlib.sha256(raw.encode()).hexdigest()


REQUIRED_RECEIPT_GATES = (
    "host_ipv4_external_egress_negative_test",
    "host_ipv6_external_egress_negative_test",
    "nft_guard_reboot_persistence_verified",
    "l2_lateral_guest_containment_verified",
    "cape_agent_http_positive_test",
    "guest_windows_hostname_verified",
    "guest_static_ipv4_verified",
    "guest_tpm_uefi_boot_verified",
    "master_unchanged_verified",
    "benign_testing_only",
)


def read_receipt(path, expected_name, expected_uuid, expected_mac, expected_ip):
    """Receipt is human-signed evidence only, NOT self-proving cryptography."""
    p = Path(path)
    require(p.is_absolute() and not p.is_symlink() and p.is_file(),
            "Expected signed acceptance receipt file missing")
    st = p.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
            stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and
            st.st_size <= MAX_RECEIPT_BYTES, "Acceptance receipt permissions invalid")
    receipt = json.loads(p.read_text(encoding="utf-8"))
    require(type(receipt) is dict and
            receipt.get("kind") == "COMMAND2_SEPARATE_HOST_ACCEPTANCE_V1" and
            receipt.get("vm") == expected_name and
            receipt.get("uuid") == expected_uuid and
            receipt.get("mac") == expected_mac and
            receipt.get("guest_ip") == expected_ip,
            "Acceptance receipt not associated with this exact VM")
    require(all(receipt.get(k) is True for k in REQUIRED_RECEIPT_GATES),
            "Isolated guest/CAPE acceptance evidence incomplete")
    require(isinstance(receipt.get("operator"), str) and
            len(receipt["operator"]) >= 3 and
            receipt.get("approved_target_host") == socket.gethostname().split(".",1)[0].lower(),
            "Operator acceptance host/identity missing")
    return hashlib.sha256(p.read_bytes()).hexdigest()


def check_snapshot_absence(name, snapshot):
    listing = virsh("snapshot-list", name, "--name")
    require(snapshot not in listing.splitlines(), "CAPE snapshot already exists")


def plan(name, target_host, expected_uuid, expected_mac, guest_ip, receipt=None, subnet="192.168.240.0/24"):
    target_guard(target_host)
    snapshot = planned_name(name)
    require(re.fullmatch(r"[0-9a-f-]{36}", expected_uuid or "") is not None and
            re.fullmatch(r"02:(?:[0-9a-f]{2}:){4}[0-9a-f]{2}",
                         expected_mac or "") is not None,
            "Expected reserved VM UUID and MAC required")
    xml_sha = saved_xml_checks(name, expected_uuid, expected_mac, guest_ip, subnet)
    check_snapshot_absence(name, snapshot)
    receipt_sha = None
    if receipt is not None:
        receipt_sha = read_receipt(receipt, name, expected_uuid, expected_mac, guest_ip)
    return {
        "result":"COMMAND2_RUNNING_CAPE_SNAPSHOT_PLAN_ONLY",
        "vm":name,"snapshot_name":snapshot,
        "domain_live_xml_sha256":xml_sha,
        "host":target_host,
        "required_acceptance_receipt_provided":receipt_sha is not None,
        "receipt_sha256":receipt_sha,
        "snapshot_created":False,
        "restore_tested":False,
        "tpm_uefi_snapshot_restore_proven":False,
        "cape_usable_proven":False,
        "no_host_mutation":True,
    }


def capture(name, target_host, expected_uuid, expected_mac, guest_ip, receipt, subnet="192.168.240.0/24"):
    target_guard(target_host)
    require(os.geteuid() == 0, "Root required for guarded capture")
    require(sys.stdin.isatty(), "Direct interactive terminal required")
    pre = plan(name,target_host,expected_uuid,expected_mac,guest_ip,receipt,subnet)
    require(pre["receipt_sha256"] is not None,
            "Prior separate-host acceptance evidence required")
    phrase = "CAPTURE-RUNNING-" + name.upper()
    require(input("Type " + phrase + " to capture a running CAPE VM snapshot: ") == phrase,
            "Explicit operator confirmation missing")
    require(not LOCK.is_symlink(), "Unsafe CAPE snapshot lock")
    fd = os.open(LOCK, os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
                stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,
                "Unsafe snapshot lock metadata")
        fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        again = plan(name,target_host,expected_uuid,expected_mac,guest_ip,receipt,subnet)
        # A signed/recorded acceptance receipt alone is not live proof.
        # Check that the *running* guest actually serves the CAPE agent
        # with administrator privileges before taking memory snapshot.
        live_agent = agentprobe.probe_agent(guest_ip)
        require(live_agent["result"] == "COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
                "Guest agent did not pass live HTTP readiness check")
        require(again["domain_live_xml_sha256"] == pre["domain_live_xml_sha256"]
                and again["receipt_sha256"] == pre["receipt_sha256"],
                "Snapshot inputs changed since operator confirmation")
        # CAPE documented running-state snapshot. Fail rather than fall back
        # to a disk-only snapshot if QEMU/libvirt/swtpm reports unsupported.
        virsh("snapshot-create-as","--domain",name,
              "--name",pre["snapshot_name"],"--atomic",
              timeout=1800)
        info = virsh("snapshot-dumpxml",name,pre["snapshot_name"])
        root = ET.fromstring(info)
        memory = root.find("memory")
        disks = root.findall("./disks/disk")
        require(memory is not None and
                memory.get("snapshot") == "internal" and
                len(disks) == 1 and
                disks[0].get("snapshot") == "internal",
                "CAPE running snapshot must have exactly one INTERNAL disk and INTERNAL memory; no disk-only fallback")
        require(virsh("domstate", name) == "running",
                "Guest stopped unexpectedly during snapshot")
        return {
            "result":"COMMAND2_RUNNING_CAPE_SNAPSHOT_CAPTURED_NOT_RESTORE_PROVEN",
            "vm":name,"snapshot":pre["snapshot_name"],
            "memory_and_disk_metadata_present":True,
            "guest_still_running":True,"capture_receipt_sha256":pre["receipt_sha256"],
            "guest_agent_http_verified_before_capture":True,
            "snapshot_revert_tested":False,"tpm_uefi_revert_tested":False,
            "cape_cycle_tested":False,"production_ready":False,
        }
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan","capture"), default="plan")
    parser.add_argument("--vm", required=True)
    parser.add_argument("--approved-host", required=True)
    parser.add_argument("--expected-uuid", required=True)
    parser.add_argument("--expected-mac", required=True)
    parser.add_argument("--guest-ip", required=True)
    parser.add_argument("--subnet", default="192.168.240.0/24")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "capture":
            require(args.receipt is not None, "Acceptance receipt is mandatory")
            report = capture(args.vm,args.approved_host,args.expected_uuid,
                             args.expected_mac,args.guest_ip,args.receipt,args.subnet)
        else:
            report = plan(args.vm,args.approved_host,args.expected_uuid,
                          args.expected_mac,args.guest_ip,args.receipt,args.subnet)
        print(json.dumps(report,indent=2,sort_keys=True))
        return 0
    except (SnapshotBlocked,OSError,ValueError,ET.ParseError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
