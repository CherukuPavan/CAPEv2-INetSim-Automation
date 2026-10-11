"""Pure, host-independent tests: no libvirt or VM operations."""
import unittest
import command2_portable_fresh_count_plan as p

PROFILE = {"disk_dir":"/var/lib/libvirt/images/analysis",
           "nvram_dir":"/var/lib/libvirt/qemu/nvram",
           "analysis_subnet":"192.168.240.0/24",
           "free_gib":512, "existing_domains":("win11",)}

class Tests(unittest.TestCase):
    def test_fresh_one_vm_with_preserved_command1_master(self):
        x=p.plan_fresh(1,**PROFILE)
        self.assertEqual(x["target_vm_total"],1)
        self.assertEqual(x["planned_vms"][0]["libvirt_name"],"win11_1")
        self.assertEqual(x["planned_vms"][0]["hostname"],"WIN11-1")
        self.assertEqual(x["planned_vms"][0]["planned_ipv4"],"192.168.240.101")
        self.assertFalse(x["deployment_authorized"])
        self.assertFalse(x["network_isolation_verified"])
        self.assertTrue(x["no_vm_created"])

    def test_five_vm_total(self):
        x=p.plan_fresh(5,**PROFILE)
        self.assertEqual([r["libvirt_name"] for r in x["planned_vms"]],
                         [f"win11_{i}" for i in range(1,6)])
        self.assertEqual([r["planned_ipv4"] for r in x["planned_vms"]],
                         [f"192.168.240.{i}" for i in range(101,106)])
        self.assertEqual(x["conservative_required_gib"],350)

    def test_sixteen_vm_upper_bound(self):
        x=p.plan_fresh(16,**dict(PROFILE,free_gib=2048))
        self.assertEqual(x["planned_vms"][-1]["hostname"],"WIN11-16")
        self.assertEqual(x["planned_vms"][-1]["planned_ipv4"],"192.168.240.116")

    def test_insufficient_host_capacity_denies_deploy(self):
        x=p.plan_fresh(5,**dict(PROFILE,free_gib=96.11))
        self.assertFalse(x["capacity_estimate_pass"])
        self.assertFalse(x["deployment_authorized"])

    def test_existing_guest_name_and_disk_refused(self):
        with self.assertRaisesRegex(p.PortablePlanBlocked,"VM collision"):
            p.plan_fresh(2,**dict(PROFILE,existing_domains=("win11","win11_2")))
        with self.assertRaisesRegex(p.PortablePlanBlocked,"disk/NVRAM collision"):
            p.plan_fresh(2,**dict(PROFILE,occupied_artifacts=(
                "/var/lib/libvirt/images/analysis/win11_2.command2.qcow2",)))

    def test_unsafe_network_and_path_refused(self):
        for net in ("192.168.122.0/24","8.8.8.0/24","127.0.0.0/8","192.168.240.0/28"):
            with self.subTest(net=net), self.assertRaises(p.PortablePlanBlocked):
                p.plan_fresh(5,**dict(PROFILE,analysis_subnet=net))
        for path in ("relative","/tmp/../master"):
            with self.subTest(path=path), self.assertRaises(p.PortablePlanBlocked):
                p.plan_fresh(1,**dict(PROFILE,disk_dir=path))

    def test_invalid_count_and_unreviewed_trial(self):
        for count in (0,17,-1,1.2,True):
            with self.subTest(count=count), self.assertRaises(p.PortablePlanBlocked):
                p.plan_fresh(count,**PROFILE)
        with self.assertRaisesRegex(p.PortablePlanBlocked,"trial VM"):
            p.plan_fresh(1,**dict(PROFILE,existing_domains=("win11","win11_trial_1")))

if __name__ == "__main__":
    unittest.main()
