#!/usr/bin/env python3
"""Read-only host outbound-interface discovery for CAPEv2 deployment preflight.

No network packets are sent, no commands or config files are modified, and
this NEVER authorizes an analysis VM to use the host uplink.
"""
import argparse
import ipaddress
import json
import re
import subprocess
import sys

BRIDGE_PREFIXES = ('virbr', 'docker', 'br-', 'veth')
TUNNEL_PREFIXES = ('tun', 'tap', 'wg', 'tailscale', 'zt', 'ppp')
TUNNEL_KINDS = {'tun', 'tap', 'wireguard', 'gre', 'gretap', 'vxlan', 'ipip', 'sit', 'vti'}


class DiscoveryError(Exception):
    pass


def run(argv):
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=True)
        return cp.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise DiscoveryError('Required read-only networking query failed: ' + argv[0]) from exc


def parse_route_get(text):
    """Parse ip -4 route get output; no assumptions about device names."""
    lines = [line.strip() for line in text.splitlines()
             if line.strip() and not line.strip().startswith('cache')]
    if len(lines) != 1:
        raise DiscoveryError('Route lookup returned zero/multiple rows')
    parts = lines[0].split()
    if parts[0] in ('unreachable', 'prohibit', 'blackhole', 'throw'):
        raise DiscoveryError('Outbound route is blocked or absent')
    def field(name):
        matches = [parts[i + 1] for i in range(len(parts) - 1) if parts[i] == name]
        return matches[0] if len(matches) == 1 else None
    if not field('dev') or not field('src'):
        raise DiscoveryError('Route lookup lacks a unique interface and IPv4 source')
    try:
        ipaddress.IPv4Address(field('src'))
    except ipaddress.AddressValueError as exc:
        raise DiscoveryError('Route source is not an IPv4 address') from exc
    return {'interface': field('dev'), 'source': field('src'), 'gateway': field('via')}


def classify_link(link):
    name = link['ifname']
    kind = (link.get('linkinfo') or {}).get('info_kind', '')
    if name.startswith(BRIDGE_PREFIXES) or kind in {'bridge', 'veth'}:
        return 'virtual-bridge-or-container'
    if name.startswith(TUNNEL_PREFIXES) or kind in TUNNEL_KINDS:
        return 'tunnel-or-vpn'
    if name == 'lo' or link.get('link_type') == 'loopback':
        return 'loopback'
    return 'physical-or-other'


def select_interface(lookup, links, addresses, defaults, rules=None, override=None):
    """Pure function: return candidate, evidence, and review requirements.

    An explicit override is checked but never silently treated as a routing fact.
    """
    problems, review = [], []
    by_name = {link['ifname']: link for link in links if isinstance(link, dict) and link.get('ifname')}
    route = parse_route_get(lookup)
    chosen = route['interface']
    if chosen not in by_name:
        problems.append('Selected route interface does not exist')
    else:
        link = by_name[chosen]
        flags = link.get('flags', [])
        if 'UP' not in flags or link.get('operstate') == 'DOWN':
            problems.append('Selected route interface is administratively or operationally down')
        elif link.get('operstate') in ('UNKNOWN', 'DORMANT', 'LOWERLAYERDOWN'):
            review.append('Interface link-layer operational state is not confirmed up')
        classification = classify_link(link)
        if classification == 'virtual-bridge-or-container' or classification == 'loopback':
            problems.append('Selected interface belongs to virtual/container or loopback networking')
        elif classification == 'tunnel-or-vpn':
            review.append('A tunnel or VPN was selected; policy/security review required')
    assigned = {address for iface in addresses if iface.get('ifname') == chosen
                for item in iface.get('addr_info', [])
                if item.get('family') == 'inet'
                for address in [item.get('local')] if address}
    if route['source'] not in assigned:
        problems.append('Route source IPv4 address is not assigned to the selected interface')
    default_ifaces = {x.get('dev') for x in defaults if x.get('dev')}
    if len(default_ifaces) > 1:
        review.append('Multiple IPv4 default-route interfaces are present')
    elif len(defaults) > 1:
        review.append('Multiple IPv4 default-route entries require manual review')
    if not defaults:
        review.append('No main-table IPv4 default route was returned; policy-based routing needs inspection')
    elif chosen not in default_ifaces:
        review.append('Route-selected interface differs from main-table default-route interfaces')
    if rules is not None:
        nonstandard = [item for item in rules if item.get('priority') not in (0, 32766, 32767)]
        if nonstandard:
            review.append('Nonstandard IPv4 policy-routing rules require manual review')
    if override:
        if override not in by_name:
            problems.append('Explicit override does not match an existing interface')
        elif override != chosen:
            problems.append('Explicit override conflicts with actual lookup for target destination')
    return {
        'selected_route_interface': chosen,
        'route_source_ipv4': route['source'],
        'route_gateway_ipv4': route['gateway'],
        'override': override,
        'default_route_interfaces': sorted(default_ifaces),
        'problems': problems,
        'manual_review': review,
        'usable_as_host_uplink_candidate': not (problems or review),
        'internet_reachability_tested': False,
        'guest_network_isolation_verified': False,
        'safe_for_malware_analysis': False,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--target', default='1.1.1.1', help='Route lookup destination, not a connectivity test')
    ap.add_argument('--override', help='Candidate interface override; must match the actual route')
    ap.add_argument('--report', help='Optional new JSON report file; never overwrites an existing file')
    args = ap.parse_args()
    try:
        target = str(ipaddress.IPv4Address(args.target))
        if args.override and not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,32}', args.override):
            raise DiscoveryError('Invalid interface override')
        lookup = run(['ip', '-4', 'route', 'get', target])
        links = json.loads(run(['ip', '-j', '-d', 'link', 'show']))
        addresses = json.loads(run(['ip', '-4', '-j', 'addr', 'show']))
        defaults = json.loads(run(['ip', '-4', '-j', 'route', 'show', 'default']))
        rules = json.loads(run(['ip', '-4', '-j', 'rule', 'show']))
        result = select_interface(lookup, links, addresses, defaults, rules, args.override)
        result['route_lookup_target'] = target
    except (ValueError, DiscoveryError, TypeError, KeyError) as exc:
        result = {'problems': [str(exc)], 'manual_review': [],
                  'usable_as_host_uplink_candidate': False,
                  'internet_reachability_tested': False,
                  'guest_network_isolation_verified': False,
                  'safe_for_malware_analysis': False}
    out = json.dumps(result, indent=2, sort_keys=True)
    print(out)
    if args.report:
        try:
            with open(args.report, 'x', encoding='utf-8') as f:
                f.write(out + '\n')
        except OSError:
            print('Cannot create requested report without overwriting', file=sys.stderr)
            return 2
    return 0 if result['usable_as_host_uplink_candidate'] else 2


if __name__ == '__main__':
    sys.exit(main())
