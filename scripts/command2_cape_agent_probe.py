#!/usr/bin/env python3
"""Bounded, read-only CAPE Windows agent check over isolated IPv4.

Only reaches a reserved private guest IPv4 at TCP/8000 with no proxies.
Does not start agents, change guest/host state, upload files or execute.
"""
from __future__ import annotations
from ipaddress import IPv4Address, IPv4Network
import json
import urllib.error
import urllib.request

RFC1918 = (IPv4Network("10.0.0.0/8"), IPv4Network("172.16.0.0/12"),
           IPv4Network("192.168.0.0/16"))


class AgentBlocked(RuntimeError):
    pass


def require(test, msg):
    if not test:
        raise AgentBlocked(msg)


def probe_agent(ip, *, opener=None):
    try:
        dest = IPv4Address(ip)
    except (TypeError, ValueError) as exc:
        raise AgentBlocked("Agent target must be an explicit IPv4 address") from exc
    require(any(dest in group for group in RFC1918) and
            not dest.is_loopback and not dest.is_multicast and
            not dest.is_link_local, "Refuse nonprivate/unsafe agent probe target")
    endpoint = "http://" + str(dest) + ":8000/"
    req = urllib.request.Request(endpoint,
                                 headers={"Accept":"application/json"},
                                 method="GET")
    call = opener or urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPRedirectHandler())
    # No redirects, DNS resolution or automatic proxy access permitted.
    # Use the exact guest address assigned by the trusted reservation.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, hdrs, newurl):
            raise AgentBlocked("Agent check unexpectedly redirected")
    if opener is None:
        call = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with call.open(req,timeout=4) as response:
            require(response.status == 200,
                    "CAPE agent returned unexpected HTTP status")
            payload = response.read(8193)
            require(len(payload) <= 8192,
                    "Agent HTTP response larger than bounded probe")
    except (OSError,urllib.error.URLError,UnicodeError,ValueError) as exc:
        raise AgentBlocked("Guest CAPE agent unreachable or invalid response") from exc
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeError,ValueError) as exc:
        raise AgentBlocked("CAPE guest agent response is not JSON") from exc
    require(type(obj) is dict and obj.get("message") == "CAPE Agent!" and
            type(obj.get("version")) is str and
            len(obj["version"]) < 50,
            "Port 8000 did not identify an expected CAPE Windows agent")
    require(obj.get("is_user_admin") is True,
            "CAPE agent does not report required administrator privileges")
    return {"result":"COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
            "guest_ip":str(dest), "port":8000,
            "version":obj["version"],
            "guest_agent_admin":True,
            "files_sent":False,
            "samples_executed":False,
            "host_guest_changes":False}
