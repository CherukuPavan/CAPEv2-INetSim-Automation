#!/usr/bin/env python3
"""Exact-owned isolated CAPE network and nft-table rollback (OTHER host).

Only removes a network and inet nft table that were PROVEN ABSENT before
this deployment and had exact sealed live post-create readback hashes.
Refuses ANY guest which references network, any running guest, any drift,
unknown transaction progress, host mismatch or active CAPE service.
Network is shut down/undefined before the dedicated nft table is removed.
Every progress step is journaled; interrupted undo is never auto-retried.
No host default network, unrelated firewall rule, link or account touched.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

import command2_portable_network_install as network
import command2_portable_network_transaction as receipt
import command2_portable_workflow as workflow
import command123_deployment_transaction as deployment

LOCK = Path("/run/lock/cape-command2-network-rollback.lock")
NETWORK = network.NETWORK
TABLE = network.TABLE


class NetworkRollbackBlocked(RuntimeError):
    pass


def need(ok, msg):
    if not ok:
        raise NetworkRollbackBlocked(msg)


def command(*args):
    try:
        out = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL,
                             timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise NetworkRollbackBlocked("Safe network inspection/action unavailable") from error
    need(out.returncode == 0 and len(out.stdout) <= 1024 * 1024,
         "Unexpected command result from target network tool")
    return out.stdout.strip()


def virsh(*args):
    return command("virsh", "-c", "qemu:///system", *args)


def nft(*args):
    return command("nft", *args)


def dig(value):
    return hashlib.sha256(value.encode()).hexdigest()


def no_guest_using_network():
    rows = [v.strip() for v in virsh("list", "--all", "--name").splitlines()
            if v.strip()]
    need(len(rows) <= 128 and len(rows) == len(set(rows)),
         "Untrusted VM inventory")
    for vm in rows:
        need(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", vm) is not None,
             "Invalid libvirt guest name")
        root = ET.fromstring(virsh("dumpxml", "--inactive", vm))
        need(root.tag == "domain" and root.findtext("name") == vm,
             "Libvirt guest identity differs from inventory")
        # Direct bridge and macvtap attachments are NOT represented as
        # <source network="...">. Undefining our libvirt network would also
        # destroy cape-lab0 beneath any independently defined guest.
        for nic in root.findall("./devices/interface"):
            for source in nic.findall("source"):
                need(source.get("network") != NETWORK and
                     source.get("bridge") != network.BRIDGE and
                     source.get("dev") != network.BRIDGE,
                     "A VM still references isolated network/bridge; "
                     "remove owned VM first")
            for target in nic.findall("target"):
                need(target.get("dev") != network.BRIDGE,
                     "A VM still references isolated network/bridge; "
                     "remove owned VM first")
    need(not virsh("list", "--name").strip(),
         "Running VM detected; no network deletion authorized")


def inspect(host, journal):
    workflow.canonical_host(host)
    doc = receipt.read(receipt.record_path(journal))
    need(doc["host"] == host and doc["status"] == "verified",
         "Only fully sealed installed network may be automatically reversed")
    source = Path(journal)
    data = source.read_bytes()
    need(hashlib.sha256(data).hexdigest() == doc["reservation_sha256"],
         "Reservation journal changed after network installation")
    info = virsh("net-info", NETWORK)
    need(re.search(r"(?mi)^Active:\s+yes\s*$", info) and
         re.search(r"(?mi)^Persistent:\s+yes\s*$", info) and
         re.search(r"(?mi)^Autostart:\s+no\s*$", info),
         "Network is not the recorded active non-autostart libvirt network")
    live = virsh("net-dumpxml", NETWORK)
    need(dig(live) == doc["post_live_libvirt_xml_sha256"],
         "Live network XML drifted from sealed deployment")
    xml = ET.fromstring(live)
    need(xml.tag == "network" and
         xml.findtext("name") == NETWORK and
         xml.find("forward") is None and
         not xml.findall(".//dhcp") and not xml.findall(".//route") and
         xml.find("port") is not None and
         xml.find("port").get("isolated") == "yes",
         "Libvirt network has unsafe forwarding or modified isolation")
    stateless = nft("-j", "-s", "list", "table", "inet", TABLE)
    need(dig(stateless) == doc["post_nft_stateless_sha256"],
         "Owned nft table was changed; no automatic deletion")
    no_guest_using_network()
    return {
        "result": "COMMAND2_OWNED_ISOLATED_NETWORK_ROLLBACK_PLAN",
        "approved_host": host,
        "journal": str(journal),
        "libvirt_network": NETWORK,
        "nft_table": TABLE,
        "network_and_nft_were_absent_before_deployment": True,
        "live_network_xml_matches_sealed_receipt": True,
        "live_nft_table_matches_stateless_sealed_receipt": True,
        "no_domain_references_network": True,
        "all_domains_shut_off": True,
        "resource_deletion_performed": False,
        "full_deployment_rollback_complete": False,
    }


def rollback(host, journal):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Direct interactive root approval required")
    first = inspect(host, journal)
    deployment.no_live_work()
    print(json.dumps(first, sort_keys=True, indent=2), flush=True)
    phrase = "UNDEFINE-ONLY-OWNED-CAPE-ISOLATED-NETWORK"
    need(input("Type " + phrase + ": ").strip() == phrase,
         "Network rollback not approved")
    need(inspect(host, journal) == first,
         "Host networking changed after operator consent")
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600,
             "Untrusted isolated-network undo lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise NetworkRollbackBlocked("Concurrent network rollback") from error
        need(inspect(host, journal) == first,
             "Network drifted before first removal")
        deployment.no_live_work()
        # From this point onward partial progress always remains visible.
        receipt.advance(journal, "verified", "rollback_started")
        try:
            virsh("net-destroy", NETWORK)
            need(re.search(r"(?mi)^Active:\s+no\s*$",
                           virsh("net-info", NETWORK)),
                 "Libvirt network did not stop")
            receipt.advance(journal, "rollback_started", "network_inactive")
            virsh("net-undefine", NETWORK)
            need(NETWORK not in
                 [x.strip() for x in virsh("net-list", "--all", "--name").splitlines()],
                 "Libvirt network still defined")
            receipt.advance(journal, "network_inactive", "network_undefined")
            # Firewall is kept in place until libvirt network was removed.
            need(dig(nft("-j", "-s", "list", "table", "inet", TABLE)) ==
                 receipt.read(receipt.record_path(journal))["post_nft_stateless_sha256"],
                 "nft policy changed while stopping network")
            nft("delete", "table", "inet", TABLE)
            receipt.advance(journal, "network_undefined", "nft_table_removed")
            need(NETWORK not in
                 [x.strip() for x in virsh("net-list", "--all", "--name").splitlines()],
                 "Network unexpectedly reappeared")
            listing = json.loads(nft("-j", "list", "tables"))
            need(type(listing) is dict and
                 type(listing.get("nftables")) is list and
                 all(type(x) is dict and
                     (x.get("table") is None or
                      type(x.get("table")) is dict)
                     for x in listing["nftables"]),
                 "Malformed nft post-deletion inventory; stop")
            need(not any(
                x.get("table", {}).get("family") == "inet" and
                x.get("table", {}).get("name") == TABLE
                for x in listing["nftables"] if "table" in x),
                "Dedicated nft table still present")
            receipt.advance(journal, "nft_table_removed", "rollback_verified")
            return {"result": "COMMAND2_OWNED_NETWORK_AND_NFT_REVERSED",
                    "network_undefined": True,
                    "nft_table_removed": True,
                    "preexisting_resources_untouched": True,
                    "full_deployment_rollback_complete": False}
        except Exception as error:
            raise NetworkRollbackBlocked(
                "Network rollback partial/unknown; preserve exact receipt and "
                "do not auto-retry"
            ) from error
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "rollback"),
                        default="plan")
    parser.add_argument("--approved-host", required=True)
    parser.add_argument("--journal", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = (inspect(args.approved_host, args.journal)
                  if args.mode == "plan" else
                  rollback(args.approved_host, args.journal))
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (NetworkRollbackBlocked, receipt.NetworkTransactionBlocked,
            workflow.WorkflowBlocked, deployment.TransactionBlocked,
            ValueError, OSError, ET.ParseError, TypeError) as error:
        print(json.dumps({
            "result": "COMMAND2_OWNED_NETWORK_ROLLBACK_BLOCKED_OR_PARTIAL",
            "error_type": type(error).__name__,
            "never_remove_unattributed_host_network_resources": True,
        }), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
