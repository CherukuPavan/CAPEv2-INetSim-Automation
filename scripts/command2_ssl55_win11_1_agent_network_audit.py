#!/usr/bin/env python3
"""Read-only SSL55 RUNNING win11_1: isolated IPv4 agent + host path audit.

One bounded benign HTTP GET to fixed 192.168.240.101:8000, explicitly
bound to cape-lab0 host IPv4 192.168.240.1. Never uploads/executions,
changes VM, network, guest, firewall, snapshots, or user routes.
Host-to-guest agent success is NOT negative internet-egress or L2 proof.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, "/usr/local/libexec/cape-command2")
import command2_ssl55_existing_guard_readonly as guard
import command2_ssl55_boot_persistence_readonly as boot

VM = "win11_1"
UUID = "732b2256-ee99-41fa-881d-fbf5c476d960"
MAC = "02:0a:30:6a:3f:50"
IP = "192.168.240.101"
HOST_IP = "192.168.240.1"
BRIDGE = "cape-lab0"
NETWORK = "cape-analysis-isolated"
OLD_IP = "192.168.122.125"


class CheckBlocked(RuntimeError):
    pass


def need(ok, why):
    if not ok:
        raise CheckBlocked(why)


def run(*argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckBlocked("Read-only host inventory unavailable: " + argv[0]) from exc
    need(p.returncode == 0, "Read-only host inventory failed: " + argv[0])
    return p.stdout.strip()


def virsh(*args):
    return run("virsh", "-c", "qemu:///system", *args)


def properties(raw, delimiter=":"):
    output = {}
    for line in raw.splitlines():
        k, sep, v = line.partition(delimiter)
        if sep:
            k = k.strip().lower()
            need(k not in output, "Duplicate status property: " + k)
            output[k] = v.strip().lower()
    return output


def check_vm():
    need(os.geteuid() == 0, "Root required for protected-host inspection")
    host = socket.gethostname().split(".", 1)[0].lower()
    need(host in ("ssl-55", "cse-ssl-55") and
         guard.SENTINEL.is_dir() and not guard.SENTINEL.is_symlink(),
         "Not the protected SSL-55 reference machine")
    need(virsh("domuuid", VM).lower() == UUID and
         virsh("domstate", VM).strip() == "running",
         "Existing analysis guest UUID or running state changed")
    need(virsh("list", "--name").splitlines() == [VM],
         "Unexpected additional libvirt guest running")
    for name, uid, count in (("win11", guard.MASTER_UUID, 1),
                             ("win11_trial_1", guard.TRIAL_UUID, 0)):
        need(virsh("domuuid", name).lower() == uid and
             virsh("domstate", name).strip() == "shut off" and
             boot.domain_autostart(name) is False,
             "Protected original/trial state or identity changed")
        source = ET.fromstring(virsh("dumpxml", "--inactive", name))
        need(source.findtext("name") == name and
             source.findtext("uuid") == uid and
             len(source.findall("./devices/interface")) == count,
             "Protected original/trial NIC count or UUID differs")
    need(boot.domain_autostart(VM) is False,
         "Analysis VM should not autostart")
    for xml_args in (("dumpxml", "--inactive", VM), ("dumpxml", VM)):
        root = ET.fromstring(virsh(*xml_args))
        need(root.tag == "domain" and root.findtext("name") == VM and
             root.findtext("uuid") == UUID, "Guest libvirt XML identity differs")
        nics = root.findall("./devices/interface")
        need(len(nics) == 1 and nics[0].get("type") == "network",
             "Expected one libvirt analysis NIC")
        mac = nics[0].find("mac")
        network = nics[0].find("source")
        need(mac is not None and mac.get("address", "").lower() == MAC and
             network is not None and network.get("network") == NETWORK,
             "Unexpected guest MAC or network")
    return {"correct_guest_running": True,
            "other_protected_vms_shutoff": True,
            "original_master_nic_untouched": True}


def check_lab():
    info = properties(virsh("net-info", NETWORK))
    need(info.get("active") == "yes" and
         info.get("autostart") == "no" and
         info.get("persistent") == "yes" and
         info.get("bridge") == BRIDGE,
         "Private CAPE network runtime state changed")
    root = ET.fromstring(virsh("net-dumpxml", NETWORK))
    b = root.find("bridge")
    port = root.find("port")
    dns = root.find("dns")
    ip = root.findall("ip")
    need(root.findtext("name") == NETWORK and
         b is not None and b.get("name") == BRIDGE and
         port is not None and port.get("isolated") == "yes" and
         dns is not None and dns.get("enable") == "no" and
         root.find("forward") is None and
         not root.findall(".//dhcp") and
         not root.findall(".//route") and
         len(ip) == 1 and ip[0].get("address") == HOST_IP and
         ip[0].get("netmask") == "255.255.255.0",
         "CAPE network definition no longer no-forward/no-DHCP/isolated")
    services = properties(run(
        "systemctl", "show", "--no-pager",
        "--property=LoadState,UnitFileState,ActiveState,Result,ExecMainStatus",
        "cape-analysis-guard.service"), "=")
    need(services.get("loadstate") == "loaded" and
         services.get("unitfilestate") == "enabled" and
         services.get("activestate") == "active" and
         services.get("result") == "success" and
         services.get("execmainstatus") == "0",
         "Current boot CAPE firewall guard service not successful")
    baseline = properties(run(
        "systemctl", "show", "--no-pager",
        "--property=LoadState,UnitFileState,ActiveState",
        "nftables.service"), "=")
    need(baseline.get("unitfilestate") == "disabled" and
         baseline.get("activestate") == "inactive",
         "Original nftables.service unexpectedly changed")
    guard.guard_policy_structure(
        run("nft", "-j", "list", "table", "inet", guard.TABLE),
        run("nft", "list", "table", "inet", guard.TABLE))
    return {"cape_guard_service_active_success": True,
            "expected_legacy_cape_nft_guard_present": True,
            "libvirt_no_nat_no_dhcp_isolated_ports_configured": True,
            "original_nftables_service_still_disabled": True}


def check_ipv4_route():
    try:
        d = json.loads(run("ip", "-j", "-4", "route", "get", IP))
    except (TypeError, ValueError) as exc:
        raise CheckBlocked("Host route to isolated guest unavailable") from exc
    need(type(d) is list and len(d) == 1 and type(d[0]) is dict,
         "Unexpected host route result shape")
    one = d[0]
    need(one.get("dev") == BRIDGE and one.get("prefsrc", one.get("src")) == HOST_IP and
         one.get("gateway") in (None, ""),
         "Host route to guest would escape the isolated bridge")
    return {"destination": IP, "source": HOST_IP, "dev": BRIDGE,
            "host_to_guest_route_on_isolated_bridge": True}


def probe_agent():
    """Only one benign GET to numeric IPv4 and fixed TCP 8000, no proxy."""
    conn = None
    try:
        conn = http.client.HTTPConnection(IP, 8000, timeout=4,
                                          source_address=(HOST_IP, 0))
        conn.request("GET", "/", headers={"Accept": "application/json"})
        response = conn.getresponse()
        status = response.status
        payload = response.read(8193)
        if status != 200:
            return {"status": "http_response_non_200",
                    "http_status": status,
                    "agent_identity_verified": False}
        if len(payload) > 8192:
            return {"status": "oversized_response",
                    "agent_identity_verified": False}
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeError):
            return {"status": "non_json_response",
                    "agent_identity_verified": False}
        if (type(decoded) is dict and
            decoded.get("message") == "CAPE Agent!" and
            type(decoded.get("version")) is str and
            len(decoded["version"]) < 50 and
            decoded.get("is_user_admin") is True):
            return {"status": "verified",
                    "agent_identity_verified": True,
                    "agent_reports_administrator": True,
                    "agent_version": decoded["version"]}
        return {"status": "unexpected_agent_identity_or_privilege",
                "agent_identity_verified": False,
                "response_keys": sorted(decoded)[:16]
                 if type(decoded) is dict else []}
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        return {"status": "unreachable_or_http_error",
                "agent_identity_verified": False,
                "exception_kind": type(exc).__name__}
    finally:
        if conn is not None:
            conn.close()


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()
    try:
        vm = check_vm()
        lab = check_lab()
        route = check_ipv4_route()
        agent = probe_agent()
        result = {"result": "SSL55_WIN11_1_READONLY_NETWORK_AGENT_OBSERVATION",
                  "host_guest_vm": vm, "network_firewall": lab,
                  "host_to_guest_route": route, "cape_agent_probe": agent,
                  "guest_hostname_WIN11_1_from_user_verified_screenshot": True,
                  "guest_ipv4_192_168_240_101_from_user_verified_screenshot": True,
                  "guest_zero_ipv4_ipv6_default_routes_from_user_screenshot": True,
                  "actual_guest_external_ipv4_negative_probe": False,
                  "actual_guest_external_ipv6_negative_probe": False,
                  "real_l2_guest_to_guest_negative_probe": False,
                  "full_cold_uefi_swtpm_restore_tested": False,
                  "running_snapshot_created": False,
                  "safe_for_malware_execution": False,
                  "host_guest_changes": False,
                  "probe_only_one_host_to_guest_http_request": True}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if agent["agent_identity_verified"] else 3
    except (CheckBlocked, guard.AuditBlocked, boot.BootBlocked,
            OSError, TypeError, ValueError, ET.ParseError) as exc:
        print("BLOCKED_HOST_AUDIT: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
