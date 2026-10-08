import json
import tempfile
import unittest
from pathlib import Path
from audit_libvirt_cape_network import analyze_network, read_settings

NAT = '''<network><name>default</name><forward mode="nat"/><bridge name="virbr0"/><ip address="192.168.122.1" netmask="255.255.255.0"/></network>'''
ISOLATED = '''<network><name>analysis</name><bridge name="virbr9"/><ip address="192.0.2.1" netmask="255.255.255.0"/></network>'''

class NetworkAuditTests(unittest.TestCase):
    def setUp(self):
        self.cfg={'NETWORK_IFACE':'virbr0','IFACE_IP':'192.168.122.1','INTERNET_IFACE':'eno1','PASSWD':'<REDACTED PRESENT>'}
        self.links={'lo','virbr0','enp0s31f6','wlp0s20f3','docker0'}
        self.routes=['enp0s31f6','wlp0s20f3']
    def test_nat_is_unsafe(self):
        r=analyze_network(NAT,self.cfg,self.links,self.routes)
        self.assertFalse(r['safe_to_use_for_malware'])
        self.assertEqual(r['observed']['forward_mode'],'nat')
        self.assertTrue(any('NOT a validated isolated' in x for x in r['hazards']))
    def test_nonexistent_uplink_detected(self):
        r=analyze_network(NAT,self.cfg,self.links,self.routes)
        self.assertTrue(any('does not exist' in x for x in r['hazards']))
    def test_unresolved_shell_expression_uplink_is_refused(self):
        cfg={**self.cfg,'INTERNET_IFACE':"$(ip route | head -1)"}
        r=analyze_network(NAT,cfg,self.links,self.routes)
        self.assertTrue(any('simple literal' in x for x in r['hazards']))

    def test_no_password_value_leaked(self):
        secret='SENSITIVE_TEST_FAKE_SECRET_ONLY_9876'
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'cape2.sh'; p.write_text('NETWORK_IFACE=virbr0\nIFACE_IP="192.168.122.1"\nINTERNET_IFACE=eno1\nPASSWD="'+secret+'"\n')
            v=read_settings(p)
            self.assertNotIn(secret, repr(v))
            r=analyze_network(NAT,v,self.links,self.routes)
            self.assertNotIn(secret,json.dumps(r))
    def test_source_substitution_not_executed(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); p=root/'cape2.sh'; marker=root/'RUNS'
            p.write_text('NETWORK_IFACE=$(touch '+str(marker)+')\nPASSWD="secret"\n')
            self.assertIn('NETWORK_IFACE',read_settings(p));self.assertFalse(marker.exists())
    def test_isolated_xml_not_proof_of_guest_isolation(self):
        cfg={**self.cfg,'NETWORK_IFACE':'virbr9','IFACE_IP':'192.0.2.1','INTERNET_IFACE':'enp0s31f6'}
        r=analyze_network(ISOLATED,cfg,self.links|{'virbr9'},self.routes,name='analysis')
        self.assertEqual(r['hazards'],[])
        self.assertFalse(r['safe_to_use_for_malware'])
    def test_malformed_network_xml_fails_closed(self):
        r=analyze_network('<network',self.cfg,self.links,self.routes)
        self.assertTrue(r['hazards'])
        self.assertFalse(r['safe_to_use_for_malware'])
    def test_wrong_bridge_fails(self):
        cfg={**self.cfg,'NETWORK_IFACE':'virbr1','INTERNET_IFACE':'enp0s31f6'}
        r=analyze_network(NAT,cfg,self.links|{'virbr1'},self.routes)
        self.assertTrue(any('differs from libvirt bridge' in x for x in r['hazards']))
    def test_missing_variable_fails(self):
        cfg={k:v for k,v in self.cfg.items() if k!='IFACE_IP'}
        r=analyze_network(NAT,cfg,self.links,self.routes)
        self.assertTrue(any('Missing literal IFACE_IP' in x for x in r['hazards']))
    def test_invalid_password_empty_fails(self):
        cfg={**self.cfg,'PASSWD':'<EMPTY>'}
        r=analyze_network(NAT,cfg,self.links,self.routes)
        self.assertIn('Password assignment is empty',r['hazards'])
    def test_duplicate_variable_refused(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'cape2.sh';p.write_text('NETWORK_IFACE=a\nNETWORK_IFACE=b\n')
            with self.assertRaisesRegex(ValueError,'Duplicate'):
                read_settings(p)

if __name__=='__main__': unittest.main(verbosity=2)
