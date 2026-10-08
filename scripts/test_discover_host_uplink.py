import unittest
from discover_host_uplink import select_interface, parse_route_get, DiscoveryError


def link(name, flags=('BROADCAST', 'UP', 'LOWER_UP'), state='UP', kind=None):
    return {'ifname': name, 'flags': list(flags), 'operstate': state,
            'linkinfo': {'info_kind': kind} if kind else {}}


def addr(name, ip):
    return {'ifname': name, 'addr_info': [{'family': 'inet', 'local': ip}]}

class HostRouteTests(unittest.TestCase):
    def setUp(self):
        self.links = [link('enp0s31f6'), link('wlp0s20f3'), link('virbr0', kind='bridge'), link('docker0', kind='bridge')]
        self.addresses = [addr('enp0s31f6', '192.0.2.55'), addr('wlp0s20f3', '198.51.100.20'), addr('virbr0', '192.168.122.1')]
        self.defaults = [{'dst': 'default', 'dev': 'enp0s31f6', 'gateway': '192.0.2.1'}]
        self.lookup = '1.1.1.1 via 192.0.2.1 dev enp0s31f6 src 192.0.2.55 uid 1006\n'
        self.rules = [{'priority': 0}, {'priority': 32766}, {'priority': 32767}]
    def run_case(self, lookup=None, links=None, addresses=None, defaults=None, rules=None, override=None):
        return select_interface(lookup or self.lookup, links if links is not None else self.links,
                addresses if addresses is not None else self.addresses,
                defaults if defaults is not None else self.defaults,
                rules if rules is not None else self.rules, override)
    def test_ssl55_route(self):
        got=self.run_case()
        self.assertEqual(got['selected_route_interface'], 'enp0s31f6')
        self.assertTrue(got['usable_as_host_uplink_candidate'])
        self.assertFalse(got['safe_for_malware_analysis'])
        self.assertFalse(got['internet_reachability_tested'])
    def test_wifi_only(self):
        got=self.run_case('1.1.1.1 dev wlan0 src 192.0.2.17', [link('wlan0')],
            [addr('wlan0','192.0.2.17')],[{'dev':'wlan0'}])
        self.assertTrue(got['usable_as_host_uplink_candidate'])
    def test_indented_route_cache_suffix(self):
        got=self.run_case(self.lookup + '    cache \n')
        self.assertTrue(got['usable_as_host_uplink_candidate'])
    def test_same_interface_multiple_default_entries_requires_review(self):
        defaults=self.defaults+[{'dev':'enp0s31f6','gateway':'192.0.2.254'}]
        self.assertFalse(self.run_case(defaults=defaults)['usable_as_host_uplink_candidate'])
    def test_multiple_default_interfaces_requires_review(self):
        got=self.run_case(defaults=self.defaults+[{'dev':'wlp0s20f3'}])
        self.assertFalse(got['usable_as_host_uplink_candidate'])
        self.assertIn('Multiple IPv4 default-route interfaces are present',got['manual_review'])
    def test_vpn_requires_review(self):
        got=self.run_case('1.1.1.1 dev tun0 src 10.8.0.2', [link('tun0',kind='tun')],
            [addr('tun0','10.8.0.2')], [{'dev':'tun0'}])
        self.assertFalse(got['usable_as_host_uplink_candidate'])
    def test_no_default_requires_review(self):
        self.assertFalse(self.run_case(defaults=[])['usable_as_host_uplink_candidate'])
    def test_container_bridge_refused(self):
        got=self.run_case('1.1.1.1 dev docker0 src 172.17.0.1',self.links,
            self.addresses+[addr('docker0','172.17.0.1')],[{'dev':'docker0'}])
        self.assertTrue(got['problems'])
    def test_down_interface_refused(self):
        links=[link('enp0s31f6',flags=('BROADCAST',),state='DOWN')]
        got=self.run_case(links=links)
        self.assertFalse(got['usable_as_host_uplink_candidate'])
    def test_source_mismatch_refused(self):
        got=self.run_case(addresses=[addr('enp0s31f6','192.0.2.54')])
        self.assertTrue(got['problems'])
    def test_override_matching(self):
        self.assertTrue(self.run_case(override='enp0s31f6')['usable_as_host_uplink_candidate'])
    def test_override_conflicts(self):
        self.assertFalse(self.run_case(override='wlp0s20f3')['usable_as_host_uplink_candidate'])
    def test_override_missing(self):
        self.assertFalse(self.run_case(override='eno1')['usable_as_host_uplink_candidate'])
    def test_policy_rule_needs_review(self):
        self.assertFalse(self.run_case(rules=self.rules+[{'priority':1000}])['usable_as_host_uplink_candidate'])
    def test_blocked_route(self):
        with self.assertRaises(DiscoveryError):
            parse_route_get('unreachable 1.1.1.1 dev lo')
    def test_no_device(self):
        with self.assertRaises(DiscoveryError):
            parse_route_get('1.1.1.1 via 192.0.2.1')
    def test_multiple_route_lines(self):
        with self.assertRaises(DiscoveryError):
            parse_route_get(self.lookup+self.lookup)
    def test_route_interface_missing(self):
        self.assertTrue(self.run_case(links=[link('another')])['problems'])
    def test_incorrect_default_route_needs_review(self):
        self.assertFalse(self.run_case(defaults=[{'dev':'wlp0s20f3'}])['usable_as_host_uplink_candidate'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
