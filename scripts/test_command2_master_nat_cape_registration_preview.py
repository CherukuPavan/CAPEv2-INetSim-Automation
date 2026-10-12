"""Pure CAPE NAT registration preview must retain existing cuckoo1."""
from pathlib import Path
import unittest

import command2_master_nat_cape_registration_preview as m

BASE=("[kvm]\n"
      "machines = cuckoo1   # active machine list\n"
      "interface = cape-lab0\n"
      "dsn = qemu:///system\n\n"
      "[cuckoo1]\n"
      "label = cuckoo1\n"
      "ip = 192.168.240.11\n"
      "snapshot = baseline\n"
      "password = legacy-SENSITIVE-KEEP-UNCHANGED\n")
def guests(n=1):
    return [{"name":"win11_"+str(i),"ip":"192.168.122."+str(130+i),
             "snapshot":"cape_ready_win11_"+str(i)}
            for i in range(1,n+1)]

class Caperender(unittest.TestCase):
    def test_real_one_existing_cuckoo1_preserved_and_one_nat_guest_appended(self):
        r,config=m.render(BASE,guests())
        self.assertEqual(r["existing_machine_names_preserved"],["cuckoo1"])
        self.assertEqual(r["cape_machine_list_after_append"],["cuckoo1","win11_1"])
        self.assertIn("machines = cuckoo1,win11_1   # active machine list",config)
        self.assertIn("snapshot = cape_ready_win11_1\ninterface = virbr0",config)
        self.assertIn("password = legacy-SENSITIVE-KEEP-UNCHANGED",config)
        self.assertEqual(config.count("[cuckoo1]"),1)
        self.assertFalse(r["auto_apply_authorized"])
        self.assertFalse(r["tpm_restoration_physically_verified"])
        self.assertFalse(r["configuration_was_written"])
        self.assertNotIn("SENSITIVE",str(r))

    def test_count_driven_cape_additions_no_duplicate_names(self):
        r,config=m.render(BASE,guests(16))
        self.assertEqual(len(r["candidate_new_guest_names"]),16)
        self.assertIn("[win11_16]",config)
        self.assertEqual(r["cape_machine_list_after_append"][-1],"win11_16")
        bad=guests(2)
        bad[1]["ip"]=bad[0]["ip"]
        with self.assertRaises(m.CapeNatCandidateBlocked):
            m.render(BASE,bad)
        bad=guests(2)
        bad[1]["name"]=bad[0]["name"]
        with self.assertRaises(m.CapeNatCandidateBlocked):
            m.render(BASE,bad)

    def test_never_replace_existing_registration_or_baseline(self):
        for wrong in (
            BASE.replace("machines = cuckoo1",
                         "machines = cuckoo1,win11_1"),
            BASE+"\n[win11_1]\nip = 192.168.240.101\n",
            BASE.replace("[cuckoo1]","[unknown]"),
            BASE.replace("[kvm]","[other]"),
            BASE+BASE,
        ):
            with self.subTest(wrong=wrong),self.assertRaises(
                    m.CapeNatCandidateBlocked):
                m.render(wrong,guests(1))

    def test_denies_invalid_snapshot_and_addresses(self):
        for name,ip,snap in [
            ("win11_1","192.168.122.1","cape_ready_win11_1"),
            ("win11_1","192.168.122.255","cape_ready_win11_1"),
            ("win11_1","192.168.240.101","cape_ready_win11_1"),
            ("win11_1","192.168.122.131","cape_candidate_win11_1"),
            ("../../","192.168.122.131","cape_ready_../../"),
        ]:
            with self.subTest(name=name,ip=ip,snap=snap),\
                 self.assertRaises(m.CapeNatCandidateBlocked):
                m.render(BASE,[{"name":name,"ip":ip,"snapshot":snap}])

    def test_module_is_side_effect_free(self):
        s=Path(m.__file__).read_text()
        for forbidden in (
            "subprocess.run(","os.replace(","os.unlink(","shell=True",
            '"net-update"','"snapshot-create"','"snapshot-revert"',
            'systemctl restart', 'write_text(', 'write_bytes('
        ):
            self.assertNotIn(forbidden,s)

if __name__=="__main__":unittest.main()
