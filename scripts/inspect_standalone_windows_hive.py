#!/usr/bin/env python3
"""Inspect a separately extracted Windows SYSTEM registry hive, read-only.

No disk mounting, libvirt calls, image attachment, registry writes or commits.
Only prints allowlisted IPv4/network fields; never dumps the whole Registry.

Expected input: an independent SYSTEM hive extracted from a powered-off,
independent Windows **clone** disk, NOT an image or a live guest mount.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys

GUID = re.compile(r"^\{[0-9A-Fa-f-]{36}\}$")
REG_DWORD = 4
REG_SZ = 1
REG_MULTI_SZ = 7
MAX_BYTES = 80 * 1024 * 1024


class HiveReadError(RuntimeError):
    pass


def require_child(hive: object, parent: int, name: str) -> int:
    try:
        found = hive.node_get_child(parent, name)
    except Exception as exc:
        raise HiveReadError(f"Cannot read required Windows SYSTEM key {name}") from exc
    if not found:
        raise HiveReadError(f"Required Windows SYSTEM key absent: {name}")
    return found


def optional_value(hive: object, node: int, key: str, expected_type: int) -> bytes | None:
    """Read optional value using enumeration; missing lookup can raise on Hivex.

    Some Debian/Ubuntu python3-hivex bindings throw RuntimeError("Success")
    when node_get_value() is called for an absent registry value.
    Enumerating node_values() + value_key() avoids this ambiguous path.
    """
    try:
        found = []
        for handle in hive.node_values(node):
            name = hive.value_key(handle)
            if isinstance(name, str) and name.casefold() == key.casefold():
                found.append(handle)
        if len(found) > 1:
            raise HiveReadError(f"Duplicate Windows value {key}")
        if not found:
            return None
        typ, raw = hive.value_value(found[0])
    except HiveReadError:
        raise
    except Exception as exc:
        raise HiveReadError(f"Cannot inspect Windows value {key}") from exc
    if typ != expected_type or not isinstance(raw, bytes):
        raise HiveReadError(f"Unexpected Registry type for {key}")
    return raw


def require_value(hive: object, node: int, key: str, expected_type: int) -> bytes:
    raw = optional_value(hive, node, key, expected_type)
    if raw is None:
        raise HiveReadError(f"Required Windows SYSTEM value absent: {key}")
    return raw


def as_dword(raw: bytes, label: str) -> int:
    if len(raw) != 4:
        raise HiveReadError(f"Wrong DWORD length for {label}")
    return int.from_bytes(raw, "little")


def as_multisz(raw: bytes, label: str) -> list[str]:
    if len(raw) % 2 or len(raw) < 4:
        raise HiveReadError(f"Invalid UTF-16 Windows multi-string length: {label}")
    try:
        string = raw.decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise HiveReadError(f"Undecodable Windows multi-string: {label}") from exc
    if not string.endswith("\x00\x00"):
        raise HiveReadError(f"Missing Windows multi-string termination: {label}")
    return [v for v in string.split("\x00") if v]


def inspect(hive: object, *, expected_ip: str | None) -> dict:
    """Backend-independent, strictly read-only Registry interpretation."""
    try:
        root = hive.root()
        select = require_child(hive, root, "Select")
        current = as_dword(require_value(hive, select, "Current", REG_DWORD), "Select/Current")
        if not 1 <= current <= 999:
            raise HiveReadError("Invalid Windows current ControlSet")
        control = require_child(hive, root, f"ControlSet{current:03d}")
        services = require_child(hive, control, "Services")
        tcpip = require_child(hive, services, "Tcpip")
        params = require_child(hive, tcpip, "Parameters")
        interfaces = require_child(hive, params, "Interfaces")
        matches = []
        for node in hive.node_children(interfaces):
            guid = hive.node_name(node)
            if not isinstance(guid, str) or not GUID.fullmatch(guid):
                continue
            ip_raw = optional_value(hive, node, "IPAddress", REG_MULTI_SZ)
            if ip_raw is None:
                continue
            values = as_multisz(ip_raw, "IPAddress")
            if expected_ip is not None and expected_ip not in values:
                continue
            dhcp = as_dword(
                require_value(hive, node, "EnableDHCP", REG_DWORD), "EnableDHCP"
            )
            subnet = as_multisz(
                require_value(hive, node, "SubnetMask", REG_MULTI_SZ), "SubnetMask"
            )
            if len(values) != 1 or len(subnet) != 1:
                raise HiveReadError("Selected NIC has multiple static IPs/subnets")
            if dhcp != 0:
                raise HiveReadError("Selected interface is not statically configured")
            try:
                ipaddress.IPv4Address(values[0])
                ipaddress.IPv4Network("0.0.0.0/" + subnet[0])
            except ValueError as exc:
                raise HiveReadError("Selected NIC has invalid IPv4/subnet mask") from exc
            matches.append({
                "interface_guid": guid,
                "static_ipv4": values[0],
                "subnet_mask": subnet[0],
                "dhcp_enabled": False,
            })
        if expected_ip is not None and len(matches) != 1:
            raise HiveReadError(
                f"Expected one unique NIC with original IPv4, found {len(matches)}"
            )
        return {
            "registry_backend": "libhivex",
            "mode": "READ_ONLY",
            "controlset": current,
            "matched_static_interfaces": matches,
            "write_implemented": False,
            "clone_boot_verified": False,
        }
    except HiveReadError:
        raise
    except Exception as exc:
        raise HiveReadError(f"Unexpected hive structure: {type(exc).__name__}") from exc


def inspect_file(path: Path, expected_ip: str | None = None) -> dict:
    try:
        if not path.is_absolute() or path.is_symlink():
            raise HiveReadError("Supply an absolute regular SYSTEM-hive file")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or not 4096 <= info.st_size <= MAX_BYTES:
            raise HiveReadError("Input is not a plausible regular SYSTEM hive")
        with path.open("rb") as file:
            signature = file.read(4)
        if signature != b"regf":
            raise HiveReadError("Input is not a Windows registry hive (regf)")
        import hivex  # Ubuntu /usr/bin/python3; optional in GitHub CI
        h = hivex.Hivex(str(path), write=False)
        # Ubuntu's generated hivex.Hivex Python binding has no .close()
        # method; it owns its handle and releases it when garbage collected.
        result = inspect(h, expected_ip=expected_ip)
        del h
        result["hive_bytes"] = info.st_size
        return result
    except (OSError, ImportError) as exc:
        raise HiveReadError(f"Hivex read-only tool unavailable: {type(exc).__name__}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hive", type=Path, required=True)
    parser.add_argument("--expected-old-ip")
    args = parser.parse_args(argv)
    try:
        if args.expected_old_ip:
            ipaddress.IPv4Address(args.expected_old_ip)
        print(json.dumps(inspect_file(args.hive, args.expected_old_ip),
                         indent=2, sort_keys=True))
        return 0
    except (HiveReadError, ValueError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
