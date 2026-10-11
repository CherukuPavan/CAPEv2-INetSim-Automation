"""Offline strict previous-verified-Windows-clone +1 IP planning tests."""
import unittest
import command2_sequential_guest_ip as m


def known(index, ip):
    return {"libvirt_name":f"win11_{index}","ipv4":ip,
            "verified_in_windows":True,
            "verification_source":"guest_os_readback"}


class SequentialIPTests(unittest.TestCase):
    def test_fresh_one_five_sixteen(self):
        for count in (1,5,16):
            with self.subTest(count=count):
                report=m.allocate(count)
                self.assertEqual(report["new_guest_count"],count)
                self.assertEqual(report["new_guests"][0]["planned_ipv4"],
                                 "192.168.240.101")
                self.assertEqual(report["new_guests"][-1]["planned_ipv4"],
                                 f"192.168.240.{100+count}")
                self.assertTrue(report["master_vm_excluded_from_sequence"])
                self.assertFalse(report["guest_static_ips_applied"])

    def test_existing_one_uses_exact_last_ip_plus_one(self):
        report=m.allocate(5,existing_verified=[known(1,"192.168.240.101")])
        self.assertEqual(report["new_guest_count"],4)
        self.assertEqual(report["new_guests"][0]["planned_ipv4"],"192.168.240.102")
        self.assertEqual(report["new_guests"][-1]["planned_ipv4"],"192.168.240.105")

    def test_existing_three_verified_guest_contiguous_sequence(self):
        data=[known(i,f"192.168.240.{100+i}") for i in range(1,4)]
        report=m.allocate(5,existing_verified=data)
        self.assertEqual([x["planned_ipv4"] for x in report["new_guests"]],
                         ["192.168.240.104","192.168.240.105"])
        self.assertEqual(len(report["existing_guests"]),3)

    def test_wrong_unverified_or_gap_in_existing_refused(self):
        for rows in (
            [dict(known(1,"192.168.240.101"),verified_in_windows=False)],
            [dict(known(1,"192.168.240.101"),verification_source="libvirt_guess")],
            [known(2,"192.168.240.102")],
            [known(1,"192.168.240.103")],
            [known(1,"192.168.240.101"),known(2,"192.168.240.105")],
        ):
            with self.subTest(rows=rows),self.assertRaises(m.SequentialIPBlocked):
                m.allocate(5,existing_verified=rows)

    def test_exact_plus_one_collision_fails_instead_of_skipping(self):
        with self.assertRaisesRegex(m.SequentialIPBlocked,"occupied"):
            m.allocate(2,existing_verified=[known(1,"192.168.240.101")],
                       occupied_other_ips=["192.168.240.102"])
        with self.assertRaisesRegex(m.SequentialIPBlocked,"overlaps"):
            m.allocate(2,existing_verified=[known(1,"192.168.240.101")],
                       occupied_other_ips=["192.168.240.101"])

    def test_non_private_default_nat_and_bad_cidr_blocked(self):
        for cidr in ("8.8.8.0/24","169.254.1.0/24","192.168.122.0/24",
                     "192.168.240.0/16","192.168.240.8/24","invalid"):
            with self.subTest(cidr=cidr),self.assertRaises(m.SequentialIPBlocked):
                m.allocate(5,cidr)

    def test_subnet_can_be_changed_without_coding_new_address(self):
        report=m.allocate(3,"10.240.22.0/24")
        self.assertEqual([x["planned_ipv4"] for x in report["new_guests"]],
                         ["10.240.22.101","10.240.22.102","10.240.22.103"])

    def test_existing_count_not_overwritten_and_range_refused(self):
        self.assertEqual(m.allocate(1,existing_verified=[
            known(1,"192.168.240.101")])["new_guest_count"],0)
        for n in (0,17,False,100):
            with self.subTest(n=n),self.assertRaises(m.SequentialIPBlocked):
                m.allocate(n)

    def test_no_vm_or_host_side_effect_interfaces(self):
        from pathlib import Path
        source=Path(m.__file__).read_text()
        body=source[source.index("from __future__ import annotations"):]
        for code in ("subprocess.run(", "os.system(", "virsh(", "nft ", "socket.socket",
                     "write_text(", "New-NetIPAddress"):
            self.assertNotIn(code,body)


if __name__=="__main__":
    unittest.main()
