"""Offline-only non-secret CAPE/INetSim topology and legacy registration."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import command2_ssl55_cape_inetsim_nat_topology_audit as s

KVM=("[kvm]\nmachines = cuckoo1\ninterface = cape-lab0\n"
     "[cuckoo1]\nlabel = cuckoo1\nip = 192.168.240.11\n"
     "snapshot = baseline\n"
     "password = SUPERSECRET_DO_NOT_ECHO\n")
class Topology(unittest.TestCase):
    def test_selected_cape_fields_never_expose_credentials(self):
        data=s.cape_selected_fields(KVM)
        self.assertEqual(data["kvm"]["interface"],"cape-lab0")
        self.assertEqual(data["cuckoo1"]["ip"],"192.168.240.11")
        self.assertNotIn("SUPERSECRET_DO_NOT_ECHO",str(data))

    def test_inetsim_bindings_are_nonsecret_and_ip_checked(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"inetsim.conf"
            p.write_text(
                "# mock configuration\n"
                "service_bind_address 192.168.240.1\n"
                "dns_default_ip 192.168.240.1\n"
                "dns_default_hostname evil.test\n"
                "admin_password SUPERSECRET_DO_NOT_ECHO\n"
                "service_bind_address_unknown SECRET\n")
            x=s.inetsim_selected_fields(p)
        self.assertTrue(x["config_file_present"])
        self.assertEqual(x["selected_network_bindings"]
                         ["service_bind_address"],"192.168.240.1")
        self.assertFalse(x["inetsim_bindings_confirmed"])
        self.assertNotIn("SUPERSECRET_DO_NOT_ECHO",str(x))

    def test_missing_inetsim_config_is_unknown_not_success(self):
        with tempfile.TemporaryDirectory() as td:
            x=s.inetsim_selected_fields(Path(td)/"missing.conf")
        self.assertFalse(x["config_file_present"])
        self.assertFalse(x["inetsim_bindings_confirmed"])

    def test_exact_ssl55_readonly_end_to_end_preview_preserves_cuckoo1(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"kvm.conf";p.write_text(KVM)
            before=p.read_bytes()
            evidence={"registration":{
                "win11_1_registration_decision":"CREATE_NEW_STANZA"},
                "current_nat_agent_http_positive":True}
            with patch.object(s.os,"geteuid",return_value=0),\
                 patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(s,"KVM",p),\
                 patch.object(s.discovery,"inspect",return_value=evidence),\
                 patch.object(s,"inetsim_selected_fields",
                   return_value={"config_file_present":False}),\
                 patch.object(s,"service_state",return_value={
                   "query_available":True,"ActiveState":"active"}),\
                 patch.object(s,"listening_ports",return_value={
                   "query_available":True,"selected_listener_inventory":[]}):
                out=s.inspect()
            self.assertEqual(before,p.read_bytes())
            self.assertEqual(out["registration_plan"]
              ["cape_machine_list_after_append"],["cuckoo1","win11_1"])
            self.assertEqual(out["registration_plan"]
              ["candidate_guest_nat_ips"],["192.168.122.131"])
            self.assertFalse(out["final_cape_registration_permitted"])
            self.assertFalse(out["host_vm_config_or_snapshot_modified"])
            self.assertNotIn("SUPERSECRET_DO_NOT_ECHO",str(out))

    def test_guest_modification_not_exposed(self):
        source=Path(s.__file__).read_text()
        for word in (
            'os.replace(', 'os.unlink(', 'write_text(', 'write_bytes(',
            '"net-update"','"snapshot-revert"','"snapshot-create"',
            '"restart"','"stop"','shell=True','"POST"',
        ):
            self.assertNotIn(word,source)

if __name__=="__main__":unittest.main()
