#!/usr/bin/env python3
"""Read-only Step 6 audit. NOT permission to run malware or proof of guest isolation.

Reads libvirt/system settings; never installs, starts, stops or reconfigures networks.
Reports redact the CAPE password value. Exit 2 for a failed safety gate.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

TARGET_VARS = ("NETWORK_IFACE", "IFACE_IP", "INTERNET_IFACE", "PASSWD")
ASSIGNMENT_RE = re.compile(r'^([A-Z][A-Z0-9_]*)=(.*)$')


def read_settings(path):
    # Never execute/shell-source a third-party installer.
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"Cannot read installer: {type(exc).__name__}") from exc
    values = {}
    for line in content.splitlines():
        match = ASSIGNMENT_RE.fullmatch(line)
        if match and match.group(1) in TARGET_VARS:
            key, value = match.groups()
            if key in values:
                raise ValueError(f"Duplicate assignment: {key}")
            if key == "PASSWD":
                values[key] = "<REDACTED PRESENT>" if value.strip() else "<EMPTY>"
            else:
                # The draft only understands literal strings, not shell substitutions.
                value = value.strip()
                if (len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]):
                    value = value[1:-1]
                values[key] = value
    return values


def analyze_network(xml, settings, links, routes, name="default"):
    """Pure, fixture-testable checks. Return a report, never modify host state."""
    report = {"network": name, "checks": [], "hazards": [], "observed": {}}
    hazards = report["hazards"]
    checks = report["checks"]
    observed = report["observed"]

    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        hazards.append("Cannot parse libvirt network XML")
        report["safe_to_use_for_malware"] = False
        return report
    if root.tag != 'network':
        hazards.append("Unexpected libvirt network XML root")
        report["safe_to_use_for_malware"] = False
        return report
    xml_name = root.findtext('name')
    if xml_name != name:
        hazards.append("Requested libvirt network name differs from network XML")
    forward = root.find('forward')
    mode = (forward.get('mode') or 'nat') if forward is not None else 'none'
    bridge = root.find('bridge')
    bridge_name = bridge.get('name') if bridge is not None else None
    ipv4 = [ip.get('address') for ip in root.findall('ip') if ip.get('family', 'ipv4') == 'ipv4']
    observed.update({"network_name": xml_name, "forward_mode": mode, "bridge": bridge_name,
                     "configured_ipv4_gateway": ipv4, "host_link_names": sorted(links),
                     "default_route_interfaces": sorted(set(routes))})
    if forward is not None:
        hazards.append(f"Libvirt network forward mode is {mode}; it is NOT a validated isolated analysis network")
    else:
        checks.append("Network XML has no forward element (libvirt isolated mode only; runtime containment still unverified)")
    for key in TARGET_VARS:
        if key not in settings:
            hazards.append(f"Missing literal {key} assignment in cape2.sh (source-version compatibility unclear)")
    selected = settings.get('NETWORK_IFACE')
    if selected and selected not in links:
        hazards.append(f"NETWORK_IFACE={selected!r} is not among host interfaces")
    if bridge_name and selected and selected != bridge_name:
        hazards.append(f"NETWORK_IFACE={selected!r} differs from libvirt bridge {bridge_name!r}")
    ip_config = settings.get('IFACE_IP')
    if ip_config and ip_config not in ipv4:
        hazards.append("IFACE_IP differs from configured IPv4 address(es) of libvirt network")
    uplink = settings.get('INTERNET_IFACE')
    if uplink and uplink not in links:
        hazards.append(f"Configured INTERNET_IFACE={uplink!r} does not exist on host")
    if uplink and any(c in uplink for c in ("$", "`", " ")):
        hazards.append("INTERNET_IFACE is not a simple literal interface name; inspect source manually")
    if uplink and uplink in links and uplink not in routes:
        checks.append("Configured INTERNET_IFACE exists but is not in the observed default route interface list; review")
    if settings.get('PASSWD') == '<REDACTED PRESENT>':
        checks.append("Password assignment detected; value REDACTED. Secret stored in installer text; review secure provisioning and rotation")
    elif settings.get('PASSWD') == '<EMPTY>':
        hazards.append("Password assignment is empty")
    report['safe_to_use_for_malware'] = False  # XML alone never proves guest/host isolation.
    checks.append("No guest negative-connectivity tests, forwarding/firewall audit or containment validation performed")
    return report


def run_read_only(argv):
    try:
        return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError(f"Read-only query failed ({argv[0]}): {type(exc).__name__}") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installer', required=True, type=Path, help='Path to CAPEv2/installer/cape2.sh')
    parser.add_argument('--network', default='default', help='Existing libvirt network name (no create/start)')
    parser.add_argument('--report', type=Path, help='Write sanitized JSON report to this path')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', args.network):
        parser.error('Invalid libvirt network name')
    try:
        settings = read_settings(args.installer)
        link_list = json.loads(run_read_only(['ip', '-j', 'link', 'show']))
        route_list = json.loads(run_read_only(['ip', '-j', 'route', 'show', 'default']))
        xml = run_read_only(['virsh', '-c', 'qemu:///system', 'net-dumpxml', args.network])
        links = {x['ifname'] for x in link_list if isinstance(x, dict) and 'ifname' in x}
        routes = [x['dev'] for x in route_list if isinstance(x, dict) and 'dev' in x]
        report = analyze_network(xml, settings, links, routes, args.network)
    except (ValueError, json.JSONDecodeError, KeyError, TypeError) as exc:
        # Do not print raw installer lines, command stderr, or credential values.
        report = {'network': args.network, 'safe_to_use_for_malware': False,
                  'hazards': [f'Audit incomplete: {exc}'], 'checks': [], 'observed': {}}
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.report:
        try:
            # Refuse overwriting existing file, writing symlinks and disclosing secrets.
            with args.report.open('x', encoding='utf-8') as f:
                f.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
                f.flush()
        except OSError as exc:
            print(f'Report write failed: {type(exc).__name__}', file=sys.stderr)
            return 2
    # This is a diagnostics-only tool. No run can pass the malware safety gate
    # without separate guest-side negative connectivity and host firewall tests.
    return 2 if report['hazards'] or not report['safe_to_use_for_malware'] else 0


if __name__ == '__main__':
    sys.exit(main())
