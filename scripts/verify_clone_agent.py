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


def ping_once(ip: str) -> None:
    try:
        r=subprocess.run(["ping","-n","-c","2","-W","2",ip],
                         capture_output=True,text=True,timeout=10,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise AgentCheckError(f"Host ping unavailable: {exc}") from exc
    if r.returncode!=0:
        raise AgentCheckError("Ubuntu ping test failed (guest unreachable or ICMP blocked)")


def agent_once(ip: str, port: int = 8000) -> dict:
    # Use actual curl as requested, bypassing proxies and forcing a direct
    # connection to the guest IP rather than the corporate proxy environment.
    url=f"http://{ip}:{port}/"
    try:
        r=subprocess.run(
            ["curl", "--noproxy", "*", "--silent", "--show-error",
             "--fail", "--connect-timeout", "3", "--max-time", "8", url],
            capture_output=True, text=True, timeout=12, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AgentCheckError(f"Ubuntu curl unavailable: {type(exc).__name__}") from exc
    if r.returncode != 0:
        raise AgentCheckError(f"Ubuntu curl CAPE agent probe failed (exit {r.returncode})")
    return validate_agent_payload(r.stdout.encode("utf-8"))


def wait_for_agent(ip: str, *, timeout: int=180) -> dict:
    address=ipaddress.ip_address(ip)
    if not isinstance(address,ipaddress.IPv4Address) or address.is_multicast or address.is_unspecified or address.is_loopback:
        raise AgentCheckError("Expected an explicit unicast guest IPv4 address")
    if timeout < 10 or timeout > 600:
        raise AgentCheckError("Guest validation timeout must be between 10 and 600 seconds")
    deadline=time.monotonic()+timeout
    last="No attempts"
    while time.monotonic()<deadline:
        try:
            ping_once(str(address))
            info=agent_once(str(address))
            info.update({"guest_ip":str(address),"ping":"PASS","cape_curl_equivalent":"PASS"})
            return info
        except AgentCheckError as exc:
            last=str(exc)
            time.sleep(min(5,max(0,deadline-time.monotonic())))
    raise AgentCheckError(f"Guest health verification timed out: {last}")
