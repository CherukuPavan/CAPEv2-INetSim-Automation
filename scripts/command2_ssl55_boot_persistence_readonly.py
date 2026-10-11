#!/usr/bin/env python3
"""SSL-55 read-only boot lifecycle audit of existing CAPE analysis guard.

Clarifies systemctl is-enabled exit status (disabled/not-found are NOT
unknown). Does not install units, edit nftables, start networks/VMs,
attach NICs, write files, reboot, or create a snapshot. Inspecting unit
metadata is NOT an actual reboot/IPv4/IPv6 egress acceptance test.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET
import command2_ssl55_existing_guard_readonly as baseline

CANDIDATE_UNITS=("nftables.service","cape-analysis-guard.service")
NFT_CONFIG=Path("/etc/nftables.conf")
MAX_CONFIG_BYTES=131072


class BootBlocked(RuntimeError):
    pass


def require(value,why):
    if not value:
        raise BootBlocked(why)


def read(*args):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=20,
                         check=False)
    except (OSError,subprocess.TimeoutExpired):
        return None
    if p.returncode:
        return None
    return p.stdout.strip()


def parse_show(payload,unit):
    if payload is None:
        return {"query_succeeded":False,"load_state":"unavailable",
                "unit_file_state":"unavailable","active_state":"unavailable",
                "boot_enabled_observed":False,"deps":[]}
    values={}
    for line in payload.splitlines():
        key,sep,value=line.partition("=")
        if sep and key in ("LoadState","UnitFileState","ActiveState",
                           "Before","After","Wants","Requires"):
            require(key not in values,"Duplicate systemd show key")
            values[key]=value.strip()
    require(all(k in values for k in ("LoadState","UnitFileState","ActiveState")),
            "Incomplete systemd state for "+unit)
    allowed={"loaded","not-found","masked","error","bad-setting","stub","merged"}
    require(values["LoadState"] in allowed,
            "Unexpected systemd load state")
    filename=values["UnitFileState"]
    enabled=values["LoadState"]=="loaded" and filename in ("enabled","enabled-runtime")
    deps=set()
    for key in ("Before","After","Wants","Requires"):
        for v in values.get(key,"").split():
            if re.fullmatch(r"[a-zA-Z0-9_.@:-]{1,120}",v):
                deps.add(v)
    return {"query_succeeded":True,
            "load_state":values["LoadState"],
            "unit_file_state":filename,
            "active_state":values["ActiveState"],
            "boot_enabled_observed":enabled,
            "deps":sorted(deps)[:100]}


def nft_config_metadata(path=NFT_CONFIG):
    try:
        st=path.lstat()
    except FileNotFoundError:
        return {"exists":False,"root_controlled":False,
                "guard_reference_present":False,"global_flush_present":False,
                "file_safe_to_inspect":False}
    safe=(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
          st.st_size<=MAX_CONFIG_BYTES and
          st.st_nlink==1 and not st.st_mode & 0o022 and
          not path.is_symlink())
    if not safe:
        return {"exists":True,"root_controlled":False,
                "guard_reference_present":False,"global_flush_present":False,
                "file_safe_to_inspect":False}
    content=path.read_text(encoding="utf-8")
    return {"exists":True,"root_controlled":True,
            "file_safe_to_inspect":True,
            "guard_reference_present":bool(re.search(
                r"\bcape_analysis_guard\b",content)),
            "global_flush_present":bool(re.search(
                r"(?m)^\s*flush\s+ruleset\b",content)),
            "includes_present":bool(re.search(r"(?m)^\s*include\s+",content)),
            "size_bytes":st.st_size}


def domain_autostart(vm):
    output=baseline.virsh("dominfo",vm)
    m=re.search(r"(?im)^Autostart:\s*(enable|disable)\s*$",output)
    require(m is not None,"Unable to determine domain autostart: "+vm)
    return m.group(1)=="enable"


def perform():
    preceding=baseline.audit()
    require(preceding["result"]=="SSL55_EXISTING_COMMAND2_NFT_PERSISTENCE_AUDIT_ONLY",
            "Expected exact SSL55 baseline audit")
    units={}
    for service in CANDIDATE_UNITS:
        output=read("systemctl","show","--no-pager",
                    "--property=LoadState,UnitFileState,ActiveState,Before,After,Wants,Requires",
                    service)
        units[service]=parse_show(output,service)
    nvram=nft_config_metadata()
    autostart={name:domain_autostart(name)
               for name in ("win11","win11_1","win11_trial_1")}
    network=preceding["analysis_network"]
    no_auto=network.get("autostart")=="no" and \
            not any(autostart.values())
    nftguard=preceding["existing_lab_firewall"].get("expected_guard_shape",False)
    # No static metadata alone can guarantee reapplication on a reboot
    # or after Docker/libvirt/nftables service restarts.
    return {
        "result":"SSL55_COMMAND2_NFT_BOOT_PERSISTENCE_INSPECTION_ONLY",
        "vm_powerstates":{x:y["power_state"] for x,y in
                          preceding["protected_domains"].items()},
        "analysis_network":network,
        "existing_guard_expected_structure_now":bool(nftguard),
        "service_show_observations":units,
        "nftables_config_metadata":nvram,
        "domain_autostart_enabled":autostart,
        "analysis_network_and_clones_autostart_disabled":no_auto,
        "safe_to_assume_guard_survives_reboot":False,
        "firewall_survival_after_service_restart_tested":False,
        "systemd_boot_order_verified":False,
        "actual_ipv4_egress_negative_probe":False,
        "actual_ipv6_egress_negative_probe":False,
        "safe_to_activate_bridge":False,
        "safe_to_attach_win11_1_nic":False,
        "network_or_guest_changed":False,
        "next":"Review existing unit load/enablement and design guarded first-time benign isolation test.",
    }


if __name__=="__main__":
    try:
        import argparse
        argparse.ArgumentParser(description=__doc__).parse_args()
        print(json.dumps(perform(),indent=2,sort_keys=True))
    except (BootBlocked,baseline.AuditBlocked,ValueError,OSError,ET.ParseError) as err:
        print("BLOCKED: "+str(err),file=sys.stderr)
        raise SystemExit(2)
