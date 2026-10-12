"""Synthetic-only exact CAPE registration discovery tests; no host mutations."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_ssl55_cape_nat_registration_discovery as g

CONFIG=("[kvm]\nmachines = win11,win11_1\n"
        "\n[win11]\nlabel = win11\nip = 192.168.122.125\n"
        "\n[win11_1]\nlabel = win11_1\n"
        "ip = 192.168.240.101\nsnapshot = cape_candidate_win11_1\n"
        "interface = cape-lab0\nplatform = windows\n"
        "password = NEVER_REPORT_THIS_SECRET\n")
DUAL={"reservation_present_in_live_and_config":True}
class CAPEReadOnly(unittest.TestCase):
    def test_existing_stanza_is_update_not_duplicate_creation(self):
        x=g.inspect_kvm(CONFIG)
        self.assertEqual(x["win11_1_registration_decision"],
                         "UPDATE_EXISTING_STANZA")
        self.assertEqual(x["win11_1_targeted_fields_only"]["ip"],
                         "192.168.240.101")
        self.assertNotIn("NEVER_REPORT_THIS_SECRET",str(x))
        self.assertFalse(x["cape_config_or_services_modified"])

    def test_empty_stanza_requires_create(self):
        x=g.inspect_kvm("[kvm]\nmachines = win11\n[win11]\nip = 1.1.1.1\n")
        self.assertEqual(x["win11_1_registration_decision"],
                         "CREATE_NEW_STANZA")
        x=g.inspect_kvm("[kvm]\nmachines = win11\n"
                         "[win11]\nip = 1.1.1.1\n"
                         "[win11_1]\nlabel = win11_1\n")
        self.assertEqual(x["win11_1_registration_decision"],
                         "REPAIR_UNLISTED_STANZA")

    def test_duplicate_machine_names_and_invalid_parse_rejected(self):
        for xml in (
          "[kvm]\nmachines = win11,win11_1,win11_1\n",
          "[kvm]\nmachines = win11_1\n",
          "password = bad outside section\n[kvm]\nmachines = win11\n"
        ):
            with self.subTest(xml=xml),self.assertRaises(g.CapeDiscoveryBlocked):
                g.inspect_kvm(xml)

    def test_select_existing_configuration_and_full_read_only_report(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"conf"/"kvm.conf"
            p.parent.mkdir()
            p.write_text(CONFIG)
            with patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g.socket,"gethostname",
                              return_value="CSE-SSL-55"),\
                 patch.object(g.reserve,"inspect",return_value=DUAL):
                report=g.inspect(str(p))
            self.assertEqual(report["result"],
                "SSL55_CAPE_REGISTRATION_DISCOVERY_READONLY")
            self.assertEqual(report["registration"]["win11_1_registration_decision"],
                             "UPDATE_EXISTING_STANZA")
            self.assertFalse(report["cape_conf_write_authorized"])
            self.assertNotIn("NEVER_REPORT_THIS_SECRET",str(report))
            self.assertFalse(report["vm_guest_service_or_snapshot_modified"])
            with patch.object(g,"possible_paths",return_value=[p,p]):
                with self.assertRaisesRegex(g.CapeDiscoveryBlocked,
                                             "exactly one"):
                    g.select_conf()

    def test_untrusted_config_symlink_refused(self):
        with tempfile.TemporaryDirectory() as td:
            main=Path(td)/"conf"/"kvm.conf"
            main.parent.mkdir()
            main.write_text(CONFIG)
            link=Path(td)/"other"/"conf"/"kvm.conf"
            link.parent.mkdir(parents=True)
            link.symlink_to(main)
            with self.assertRaises(g.CapeDiscoveryBlocked):
                g.select_conf(str(link))

    def test_no_changes_allowed(self):
        source=Path(g.__file__).read_text()
        for bad in ('"net-update"','"snapshot-create"','"snapshot-revert"',
                    '"virsh","define"','"systemctl","restart"',
                    'os.replace(', 'os.unlink(', 'shell=True',
                    '"POST"'):
            self.assertNotIn(bad,source)
if __name__=="__main__":unittest.main()
