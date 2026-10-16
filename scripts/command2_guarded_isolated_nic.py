#!/usr/bin/env python3
"""Separate-host guarded per-guest CAPE NIC attach, NEVER SSL-55.

Plan (read-only) or attach (--config, shut-off guest only).
Requires reviewed guest+network acceptance receipt and real libvirt/nft
readbacks. Receipt alone is NOT a cryptographic network proof, and
physical egress, L2 segregation, reboot-persistence must be witnessed.
No DHCP/NAT/host firewall changes, no VM boot or snapshot created.
"""
from __future__ import annotations
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

SENTINEL = Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
LOCK = Path("/run/lock/cape-command2-nic-attach.lock")
NETWORK = "cape-analysis-isolated"
BRIDGE = "cape-lab0"
TABLE = "cape_analysis_cmd2_guard"
VM_PATTERN = re.compile(r"win11_([1-9]|1[0-6])\Z")
MAC_PATTERN = re.compile(r"02:(?:[0-9a-f]{2}:){4}[0-9a-f]{2}\Z")
RFC1918 = tuple(ipaddress.IPv4Network(x) for x in
                ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"))


class NicBlocked(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise NicBlocked(reason)


def cmd(*args, timeout=20):
    try:
        p = subprocess.run(args, text=True, capture_output=True,
                           timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise NicBlocked("Host command unavailable or timed out: "+args[0]) from e
    need(p.returncode == 0,
         "Host inspection/action failed: "+args[0]+" exit="+str(p.returncode))
    return p.stdout.strip()


def virsh(*args):
    return cmd("virsh","-c","qemu:///system",*args)


def guard_host(approved_host):
    actual = socket.gethostname().split(".",1)[0].lower()
    need(actual not in ("ssl-55","cse-ssl-55",
                        "ssl-46","cse-ssl-46") and
         not SENTINEL.exists() and not SENTINEL.is_symlink(),
         "SSL55_REFERENCE_ONLY: NIC attachment blocked (also SSL46 protected)")
    need(re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}",approved_host or "")
         and actual == approved_host, "Wrong approved separate host")


def vm_identity(vm, uuid, mac, subnet):
    match = VM_PATTERN.fullmatch(vm or "")
    need(match is not None and MAC_PATTERN.fullmatch(mac or "") is not None,
         "Unexpected VM or reserved MAC")
    import uuid as uuidlib
    try:
        canonical = str(uuidlib.UUID(uuid))
        net = ipaddress.IPv4Network(subnet, strict=True)
    except (ValueError, TypeError, AttributeError) as e:
        raise NicBlocked("VM UUID/subnet malformed") from e
    need(uuid == canonical and net.prefixlen == 24 and
         any(net.subnet_of(x) for x in RFC1918) and
         str(net) != "192.168.122.0/24", "Unexpected VM UUID or subnet")
    index = int(match.group(1))
    guest_ip = str(ipaddress.IPv4Address(int(net.network_address)+100+index))
    bridge_ip = str(ipaddress.IPv4Address(int(net.network_address)+1))
    return guest_ip, bridge_ip


def verify_network_live(subnet, bridge_ip):
    info = virsh("net-info",NETWORK)
    need(re.search(r"^Active:\s+yes\s*$",info,re.M|re.I) is not None and
         re.search(r"^Persistent:\s+yes\s*$",info,re.M|re.I) is not None,
         "Analysis network inactive/nonpersistent")
    root = ET.fromstring(virsh("net-dumpxml",NETWORK))
    need(root.tag == "network" and root.findtext("name") == NETWORK and
         root.find("forward") is None and
         not root.findall(".//route") and not root.findall(".//dhcp"),
         "Analysis network contains forwarding/NAT/DHCP/route")
    bridge = root.find("bridge")
    port = root.find("port")
    ipnodes = root.findall("ip")
    dns = root.find("dns")
    need(port is not None and port.get("isolated") == "yes",
         "Guest-to-guest Linux bridge port isolation not configured")
    need(bridge is not None and bridge.get("name") == BRIDGE and
         len(ipnodes) == 1 and ipnodes[0].get("address") == bridge_ip and
         ipnodes[0].get("netmask") == "255.255.255.0" and
         dns is not None and dns.get("enable") == "no",
         "Unexpected CAPE bridge, address, IPv6 or DNS mode")
    nft = cmd("nft","-a","list","table","inet",TABLE)
    need("table inet "+TABLE in nft and
         re.search(r"\bchain cape_guest_forward\b",nft) and
         re.search(r"\bchain cape_guest_input\b",nft),
         "Dedicated CAPE nft input/forward chains missing")
    lines = nft.splitlines()
    need(any(re.search(r'hook forward priority -150; policy accept;',x)
             for x in lines) and
         any(re.search(r'hook input priority -150; policy accept;',x)
             for x in lines),
         "Unreviewed CAPE nft chain priority/policies")
    def ruled(pattern):
        return any(re.search(pattern,line) for line in lines)
    need(ruled(r'iifname "cape-lab0".*\bdrop\b') and
         ruled(r'iifname "cape-lab0" meta nfproto ipv6.*\bdrop\b') and
         ruled(r'iifname "cape-lab0" ip daddr != ' +
               re.escape(bridge_ip) + r'.*\bdrop\b'),
         "Required guest L3 drops not found in live nft state")
    # CAUTION: nft readback cannot prove actual packet-path efficacy,
    # bridge L2 segregation or service/reboot persistence by itself.
    return True


def verify_clone_no_nic(vm, expected_uuid):
    need(virsh("domuuid",vm).lower()==expected_uuid and
         virsh("domstate",vm).strip() == "shut off",
         "Wrong/running clone; config-only NIC attachment requires shutoff")
    inactive = virsh("dumpxml","--inactive",vm)
    root = ET.fromstring(inactive)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==vm and root.findtext("uuid")==expected_uuid,
         "Unexpected clone definition/identity")
    need(not root.findall("./devices/interface"),
         "Guest already has NIC; no automatic replacement")
    need(len(root.findall("./devices/disk[@device='disk']"))==1 and
         root.findtext("./os/nvram","").endswith(
             "/"+vm+".command2_VARS.fd") and
         root.find("./devices/tpm/backend") is not None,
         "Not a reviewed independent analysis clone")
    return inactive


# The legacy v1 acceptance route requires the guest Windows identity to
# have already been witnessed on a ZERO-NIC boot. The optional v2 route is
# explicitly for a separately approved, trusted Windows SYSTEM bootstrap
# installed BEFORE cloning, with a single isolated NIC attached before
# the first guest boot. The v2 route does NOT assert Windows renamed yet.
BOOTSTRAP_FIRST_PROOF_FIELDS = (
    "source_master_system_bootstrap_verified",
    "source_master_shut_off_verified",
    "one_nic_firstboot_pending",
    "zero_guest_default_gateway_in_config_verified",
)
BOOTSTRAP_PIN_RE=re.compile(r"[0-9a-f]{64}\Z")
CANONICAL_UUID_RE=re.compile(
    r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")

PROOF_FIELDS = ("host_ipv4_external_egress_negative_test",
                "host_ipv6_external_egress_negative_test",
                "nft_guard_reboot_persistence_verified",
                "l2_lateral_guest_containment_verified",
                "cape_host_guest_positive_path_verified",
                "shared_host_firewall_unchanged_verified",
                "windows_zero_nic_identity_verified")


def read_acceptance_receipt(path, vm, uid, mac, guest_ip, host):
    p=Path(path)
    need(p.is_absolute() and p.is_file() and not p.is_symlink(),
         "Missing acceptance receipt")
    s=p.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and
         stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<65536,
         "Untrusted acceptance receipt ownership/mode")
    report=json.loads(p.read_text(encoding="utf-8"))
    need(type(report) is dict and
         report.get("kind") in (
             "COMMAND2_SEPARATE_HOST_NETWORK_ACCEPTANCE_V1",
             "COMMAND2_SEPARATE_HOST_NETWORK_ACCEPTANCE_V2") and
         report.get("approved_host")==host and report.get("vm")==vm and
         report.get("uuid")==uid and report.get("mac")==mac and
         report.get("guest_ip")==guest_ip and
         type(report.get("operator")) is str and
         len(report["operator"])>=3 and
         all(report.get(key) is True for key in
             PROOF_FIELDS if key != "windows_zero_nic_identity_verified"),
         "Acceptance receipt does not attest exact isolated VM/network")
    if report["kind"]=="COMMAND2_SEPARATE_HOST_NETWORK_ACCEPTANCE_V1":
        need(report.get("windows_zero_nic_identity_verified") is True,
             "Legacy Windows zero-NIC identity witness required")
    else:
        need(all(report.get(key) is True for key in
                 BOOTSTRAP_FIRST_PROOF_FIELDS) and
             report.get("windows_zero_nic_identity_verified") is False and
             type(report.get("source_master_uuid")) is str and
             CANONICAL_UUID_RE.fullmatch(report["source_master_uuid"]) is not None
             and report["source_master_uuid"] != uid and
             all(type(report.get(key)) is str and
                 BOOTSTRAP_PIN_RE.fullmatch(report[key]) is not None for key in
                     ("source_master_runner_sha256",
                      "source_master_personalizer_sha256")),
             "One-NIC first-boot receipt requires independently verified "
             "master task, exact source UUID/hashes, zero gateway, and "
             "an explicit PENDING Windows identity (not invented proof)")
    # This is human-supplied private evidence, NOT proof of physical
    # isolation or task installation. The exact host/VM/network gate above
    # is still mandatory and the Windows guest must later be checked.
    return True


def plan(vm, host, uid, mac, subnet, receipt=None):
    guard_host(host)
    guest_ip, bridge_ip = vm_identity(vm,uid,mac,subnet)
    xml = verify_clone_no_nic(vm,uid)
    verify_network_live(subnet,bridge_ip)
    receipt_recorded = (read_acceptance_receipt(receipt,vm,uid,mac,guest_ip,host)
                        if receipt is not None else False)
    return {"result":"COMMAND2_ISOLATED_NIC_ATTACH_PLAN_ONLY",
            "vm":vm,"reserved_mac":mac,"guest_ip":guest_ip,
            "network":NETWORK,"bridge":BRIDGE,
            "target_host":host,"acceptance_receipt_checked":receipt_recorded,
            "changes_made":False,"guest_booted":False,
            "nic_attached":False,"runtime_egress_proved_by_this_tool":False,
            "note":"Host nft/libvirt checks are necessary but NOT sufficient "
                   "to prove IPv4/IPv6 or L2 containment."}


def attach(vm,host,uid,mac,subnet,receipt):
    guard_host(host)
    need(os.geteuid()==0,"Root required for NIC attachment")
    need(sys.stdin.isatty(),"Direct terminal confirmation required")
    first=plan(vm,host,uid,mac,subnet,receipt)
    need(first["acceptance_receipt_checked"],"Real network acceptance receipt required")
    phrase="ATTACH-CAPE-ONLY-"+vm.upper()
    need(input("Type "+phrase+" to attach one isolated NIC: ")==phrase,
         "Operator refused NIC attachment")
    need(not LOCK.is_symlink(),"Unsafe NIC attachment lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,
             "Unsafe NIC lock metadata")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        second=plan(vm,host,uid,mac,subnet,receipt)
        need(second==first,"NIC network/host plan changed under lock")
        # Match proven original Windows e1000e adapter model; do not
        # assume the standalone Windows template includes virtio-net.
        virsh("attach-interface","--domain",vm,
              "--type","network","--source",NETWORK,
              "--model","e1000e","--mac",mac,"--config")
        root=ET.fromstring(virsh("dumpxml","--inactive",vm))
        nics=root.findall("./devices/interface")
        need(len(nics)==1 and
             nics[0].get("type")=="network" and
             nics[0].find("source") is not None and
             nics[0].find("source").get("network")==NETWORK and
             nics[0].find("mac") is not None and
             nics[0].find("mac").get("address","").lower()==mac and
             virsh("domstate",vm)=="shut off",
             "NIC post-attach verify failed; STOP without blind retry")
        return {"result":"COMMAND2_SINGLE_ISOLATED_NIC_SAVED_NOT_BOOTED",
                "vm":vm,"nic_mac":mac,"network":NETWORK,
                "guest_still_shutoff":True,"host_firewall_unmodified":True,
                "guest_ip_applied_in_windows":False,
                "snapshot_created":False,"production_ready":False}
    finally:
        os.close(fd)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode",choices=("plan","attach"),default="plan")
    ap.add_argument("--vm",required=True)
    ap.add_argument("--approved-host",required=True)
    ap.add_argument("--uuid",required=True)
    ap.add_argument("--mac",required=True)
    ap.add_argument("--subnet",default="192.168.240.0/24")
    ap.add_argument("--receipt",type=Path)
    a=ap.parse_args()
    try:
        if a.mode=="attach":
            need(a.receipt is not None,"Required acceptance receipt missing")
            result=attach(a.vm,a.approved_host,a.uuid,a.mac,a.subnet,a.receipt)
        else:
            result=plan(a.vm,a.approved_host,a.uuid,a.mac,a.subnet,a.receipt)
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except (NicBlocked,OSError,ET.ParseError,ValueError,AttributeError,TypeError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
