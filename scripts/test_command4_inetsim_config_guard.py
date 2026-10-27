"""No-host-change INetSim Command4 configuration and containment tests."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import command4_inetsim_config_guard as c


class INetSimConfigTests(unittest.TestCase):
    def setUp(self):
        self.base=tempfile.TemporaryDirectory(prefix="cape-command4-")
        self.addCleanup(self.base.cleanup)
        self.path=Path(self.base.name)/"inetsim.conf"
        self.default=b"""# INetSim upstream defaults
start_service dns
start_service http
#service_bind_address 10.10.10.1
#dns_default_ip 10.10.10.1
"""

    def test_render_exact_lab_bound_including_fake_dns(self):
        done=c.render(self.default,"192.168.122.1")
        self.assertTrue(done.startswith(self.default))
        self.assertEqual(c.active_directives(done.decode().splitlines()),{
            "service_bind_address":"192.168.122.1",
            "dns_default_ip":"192.168.122.1"})
        self.assertEqual(done.count(c.START.encode()),1)
        self.assertEqual(done.count(c.END.encode()),1)
        self.assertNotIn(b"0.0.0.0",done)

    def test_plan_is_readonly_preserves_package_configuration(self):
        self.path.write_bytes(self.default)
        before=self.path.stat().st_mtime_ns
        v=c.plan(self.path,"192.168.122.1")
        self.assertEqual(v["result"],"COMMAND4_INETSIM_LAB_CONF_PLAN_ONLY")
        self.assertFalse(v["production_command4_ready"])
        self.assertFalse(v["service_started"])
        self.assertEqual(self.path.read_bytes(),self.default)
        self.assertEqual(before,self.path.stat().st_mtime_ns)
        self.assertEqual(v["before_sha256"],
                         hashlib.sha256(self.default).hexdigest())

    def test_never_override_foreign_existing_bind(self):
        for key in ("service_bind_address","dns_default_ip"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(c.ConfigBlocked,"foreign override"):
                    c.render(self.default + (
                        key+" 10.20.30.40\n").encode(),"192.168.122.1")

    def test_duplicate_value_is_rejected(self):
        p=(self.default+b"service_bind_address 192.168.122.1\n"
           +b"service_bind_address 192.168.122.1\n")
        with self.assertRaises(c.ConfigBlocked):
            c.render(p,"192.168.122.1")

    def test_no_include_file_override(self):
        with self.assertRaisesRegex(c.ConfigBlocked,"Included"):
            c.render(self.default+b"include /opt/unreviewed.conf\n",
                     "192.168.122.1")

    def test_already_owned_config_cannot_be_written_again(self):
        once=c.render(self.default,"192.168.122.1")
        with self.assertRaisesRegex(c.ConfigBlocked,"receipt"):
            c.render(once,"192.168.122.1")

    def test_reject_public_reserved_ipv4_and_injection(self):
        for ip in ("0.0.0.0","127.0.0.1","1.1.1.1","169.254.1.2",
                   "240.0.0.1","198.18.0.1","192.168.122.1\nstart_service telnet",
                   "192.168.122.001"):
            with self.subTest(ip=ip), self.assertRaises((c.ConfigBlocked,ValueError)):
                c.render(self.default,ip)

    def test_requires_distro_expected_config_basename(self):
        self.path.write_bytes(self.default)
        with self.assertRaisesRegex(c.ConfigBlocked,"package-owned"):
            c.plan(self.path.with_name("other.conf"),"192.168.122.1")

    def test_wrong_encoding_and_carriage_return_block(self):
        for data in (b"start_service dns\r\n",b"\xff\xfe"):
            with self.assertRaises(c.ConfigBlocked):
                c.render(data,"192.168.122.1")


if __name__=="__main__":
    unittest.main()
