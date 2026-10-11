#!/usr/bin/env python3
"""Pure DRAFT systemd unit for CAPE-only nft guard restore on SSL55.

This does NOT install/enable anything. A unit is useful only after
pinning the helper and its dependencies, validating actual libvirt
service names, and inspecting the host's service boot order. No guest
NIC/bridge should be attached before real reboot-persistence and packet
isolation acceptance. A systemd file alone is not fail-closed networking.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import sys


class UnitBlocked(ValueError):
    pass


LIBVIRT_UNITS=("libvirtd.service","virtqemud.service")
EXPECTED_HELPER="/usr/local/libexec/cape-command2/command2_ssl55_guard_scoped_replay.py"
EXPECTED_APPROVAL="/etc/cape-command2/ssl55-guard-replay-approved.json"


def build_unit(libvirt_unit):
    if libvirt_unit not in LIBVIRT_UNITS:
        raise UnitBlocked("Only verified Ubuntu libvirtd/virtqemud unit names allowed")
    # This is a *proposal*, not proof of the host's active libvirt unit.
    body=(
        "[Unit]\n"
        "Description=Guard-only CAPE SSL55 nft policy replay (no network activation)\n"
        "Documentation=man:nft(8)\n"
        f"Wants={libvirt_unit}\n"
        f"After={libvirt_unit} network-pre.target\n"
        "Before=libvirt-guests.service\n"
        f"ConditionPathExists={EXPECTED_APPROVAL}\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart=/usr/bin/python3 -B {EXPECTED_HELPER} --mode reconcile\n"
        "RemainAfterExit=yes\n"
        "TimeoutStartSec=120\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    forbidden=("ExecStartPre=/usr/bin/nft flush",
               "ExecStart=/usr/sbin/nft -f /etc/nftables.conf",
               "virsh net-start","virsh start","systemctl enable",
               "flush ruleset","iptables -F","ufw disable")
    if any(x in body for x in forbidden):
        raise UnitBlocked("Unsafe global host firewall or guest action in unit")
    return {
        "result":"CAPE_SSL55_CANDIDATE_SYSTEMD_UNIT_ONLY",
        "unit_name":"cape-analysis-guard.service",
        "unit_text":body,
        "unit_sha256":hashlib.sha256(body.encode()).hexdigest(),
        "requested_libvirt_service":libvirt_unit,
        "actual_libvirt_service_checked_on_host":False,
        "dependency_scripts_installed":False,
        "operator_approval_manifest_installed":False,
        "unit_installed":False,"unit_enabled":False,
        "unit_started":False,"nftables_service_enabled":False,
        "reboot_persistence_verified":False,
        "protected_guests_autostart_approved":False,
        "safe_to_attach_win11_1_nic":False,
        "host_modified":False,
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--libvirt-unit",choices=LIBVIRT_UNITS,required=True)
    args=ap.parse_args()
    try:
        print(json.dumps(build_unit(args.libvirt_unit),indent=2,sort_keys=True))
        return 0
    except UnitBlocked as err:
        print("BLOCKED: "+str(err),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
