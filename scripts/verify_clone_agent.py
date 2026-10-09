#!/usr/bin/env python3
"""Ping and CAPE-agent HTTP health verification from the Ubuntu CAPE host.

Safe observations only: no malware and no guest remote code execution.
"""
from __future__ import annotations

import ipaddress
import json
import subprocess
import time


class AgentCheckError(RuntimeError):
    pass


def validate_agent_payload(payload: bytes) -> dict:
    try:
        value=json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise AgentCheckError("Agent response is not valid JSON") from exc
    if not isinstance(value,dict) or value.get("message")!="CAPE Agent!":
        raise AgentCheckError("Endpoint did not identify itself as CAPE Agent")
    if value.get("is_user_admin") is not True:
        raise AgentCheckError("CAPE Agent is not running with administrator privileges")
    features=value.get("features")
    if not isinstance(features,list) or "execute" not in features:
        raise AgentCheckError("CAPE agent does not advertise expected execute functionality")
    return {"identity":"CAPE Agent!", "version":str(value.get("version","unknown")),
            "elevated":True, "features_verified":True}


def ping_once(ip: str, interface: str | None = None) -> None:
    try:
        args=["ping","-n","-c","2","-W","2"]
        if interface:
            args.extend(["-I",interface])
        args.append(ip)
        r=subprocess.run(args,
                         capture_output=True,text=True,timeout=10,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise AgentCheckError(f"Host ping unavailable: {exc}") from exc
    if r.returncode!=0:
        raise AgentCheckError("Ubuntu ping test failed (guest unreachable or ICMP blocked)")


def agent_once(ip: str, port: int = 8000,
               interface: str | None = None) -> dict:
    # Use actual curl as requested, bypassing proxies and forcing a direct
    # connection to the guest IP rather than the corporate proxy environment.
    url=f"http://{ip}:{port}/"
    args=["curl", "--noproxy", "*", "--silent", "--show-error",
          "--fail", "--connect-timeout", "3", "--max-time", "8"]
    if interface:
        args.extend(["--interface",interface])
    args.append(url)
    try:
        r=subprocess.run(args,
            capture_output=True, text=True, timeout=12, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AgentCheckError(f"Ubuntu curl unavailable: {type(exc).__name__}") from exc
    if r.returncode != 0:
        raise AgentCheckError(f"Ubuntu curl CAPE agent probe failed (exit {r.returncode})")
    return validate_agent_payload(r.stdout.encode("utf-8"))


def verify_neighbor(ip: str, interface: str, expected_mac: str) -> None:
    try:
        r=subprocess.run(
            ["ip","-4","neigh","show","to",ip,"dev",interface],
            capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise AgentCheckError("Cannot inspect Linux bridge neighbor table") from exc
    if r.returncode!=0:
        raise AgentCheckError("Neighbor table lookup failed")
    import re
    matches=re.findall(r"\\blladdr\s+([0-9a-fA-F:]{17})\\b", r.stdout)
    if len(matches)!=1 or matches[0].lower()!=expected_mac.lower():
        raise AgentCheckError("Ping target MAC does not match the expected cloned VM")


def wait_for_agent(ip: str, *, timeout: int=180,
                   interface: str | None = None,
                   expected_mac: str | None = None) -> dict:
    address=ipaddress.ip_address(ip)
    if not isinstance(address,ipaddress.IPv4Address) or address.is_multicast or address.is_unspecified or address.is_loopback:
        raise AgentCheckError("Expected an explicit unicast guest IPv4 address")
    if timeout < 10 or timeout > 600:
        raise AgentCheckError("Guest validation timeout must be between 10 and 600 seconds")
    if (interface is None) != (expected_mac is None):
        raise AgentCheckError("Bridge interface and expected MAC must be specified together")
    if interface and ("/" in interface or len(interface)>15 or not interface.isascii()):
        raise AgentCheckError("Invalid analysis bridge device name")
    deadline=time.monotonic()+timeout
    last="No attempts"
    while time.monotonic()<deadline:
        try:
            ping_once(str(address),interface)
            if interface and expected_mac:
                verify_neighbor(str(address),interface,expected_mac)
            info=agent_once(str(address),interface=interface)
            info.update({"guest_ip":str(address),"ping":"PASS",
                         "neighbor_mac":"PASS" if interface else "NOT_CHECKED",
                         "cape_curl_equivalent":"PASS"})
            return info
        except AgentCheckError as exc:
            last=str(exc)
            time.sleep(min(5,max(0,deadline-time.monotonic())))
    raise AgentCheckError(f"Guest health verification timed out: {last}")
