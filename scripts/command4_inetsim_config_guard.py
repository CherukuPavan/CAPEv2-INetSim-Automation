#!/usr/bin/env python3
"""Pure, fail-closed Command4 INetSim lab-bound configuration generator.

Developed against Ubuntu's signed inetsim 1.3.2 package defaults.
This module never installs packages, edits a file, starts a service,
configures routing, bypasses nft guest containment, or claims Command4
is complete. The final mutation orchestrator must require real host
network containment proof and a deployment-owned rollback receipt first.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

START = "# BEGIN CAPE-COMMAND4-OWNED-INETSIM-LAB-BIND"
END = "# END CAPE-COMMAND4-OWNED-INETSIM-LAB-BIND"
KEYS = frozenset(("service_bind_address", "dns_default_ip"))
LIMIT = 3 * 1024 * 1024
class ConfigBlocked(RuntimeError):
    pass

def need(ok, why):
    if not ok:
        raise ConfigBlocked(why)

def checked_address(text):
    need(isinstance(text, str) and
         re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", text) is not None,
         "Only a literal lab-bound IPv4 may be used")
    address = ipaddress.IPv4Address(text)
    networks = tuple(ipaddress.IPv4Network(net) for net in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    need(str(address) == text and
         any(address in network for network in networks),
         "INetSim must bind an exact RFC1918 dedicated lab IPv4")
    return str(address)

def active_directives(lines):
    keys = {}
    for line in lines:
        token = line.split("#",1)[0].strip()
        if not token:
            continue
        parts = token.split()
        if parts[0] in KEYS:
            need(len(parts) == 2, "Malformed INetSim bind/DNS directive")
            need(parts[0] not in keys, "Duplicate active INetSim directive")
            keys[parts[0]] = parts[1]
        need(parts[0] != "include",
             "Included INetSim configuration could override lab bindings")
    return keys

def render(raw, bind):
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT and
         b"\0" not in raw and b"\r" not in raw,
         "Untrusted INetSim configuration bytes")
    ip = checked_address(bind)
    try:
        original = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ConfigBlocked("Unknown INetSim configuration encoding") from e
    lines = original.splitlines()
    need(START not in lines and END not in lines,
         "Existing owned configuration: verify receipt instead of overwriting")
    need(not any(START in line or END in line for line in lines),
         "Malformed CAPE-INetSim ownership markers")
    # Preserving the entire existing configuration keeps known upstream
    # service defaults and user data exactly as found. Never overwrite a
    # previously customized or foreign service bind/DNS value.
    present = active_directives(lines)
    need(not present, "Existing explicit INetSim binding: refuse foreign override")
    added = ("\n" if original.endswith("\n") else "\n\n") + (
        START + "\n" +
        "service_bind_address " + ip + "\n" +
        "dns_default_ip " + ip + "\n" +
        END + "\n"
    )
    combined = (original + added).encode("utf-8")
    need(len(combined) <= LIMIT, "Resulting INetSim config is oversized")
    after_lines = combined.decode("utf-8").splitlines()
    # Exactly one of each effective value and no includes.
    need(active_directives(after_lines) == {
        "service_bind_address": ip, "dns_default_ip": ip},
        "Final configuration does not bind exclusively to selected lab IP")
    return combined

def plan(conf, bind):
    p = Path(conf)
    need(p.is_absolute() and not p.is_symlink() and
         p.is_file() and p.name == "inetsim.conf",
         "Expected existing INetSim package-owned config file")
    before = p.read_bytes()
    after = render(before, bind)
    return {
        "result": "COMMAND4_INETSIM_LAB_CONF_PLAN_ONLY",
        "configuration_path": str(p),
        "before_sha256": hashlib.sha256(before).hexdigest(),
        "proposed_sha256": hashlib.sha256(after).hexdigest(),
        "lab_bind_address": checked_address(bind),
        "source_bytes": len(before), "output_bytes": len(after),
        "original_configuration_overwritten": False,
        "service_started": False, "network_modified": False,
        "host_mutated": False, "production_command4_ready": False,
        "requires_approved_network_negative_egress_and_service_receipt": True
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--lab-ip", required=True)
    args=parser.parse_args()
    try:
        print(json.dumps(plan(args.config,args.lab_ip),
                         indent=2,sort_keys=True))
        return 0
    except (ConfigBlocked,OSError,ValueError,TypeError) as err:
        print(json.dumps({
            "result":"COMMAND4_INETSIM_CONF_UNSAFE",
            "reason":str(err)[:240],
            "no_file_changed":True
        },sort_keys=True),file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
