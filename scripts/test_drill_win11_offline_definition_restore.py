#!/usr/bin/env python3
"""Pure synthetic libvirt XML tests; no host writes."""
import unittest
from unittest.mock import patch
import drill_win11_offline_definition_restore as drill
import plan_win11_maintenance_xml as planner
from test_plan_win11_maintenance_xml import DOMAIN, OLD, NEW

def fake(xml):
    def read(*a):
        return {"domstate":"shut off","snapshot-current":"finalshutoffversion",
                "dumpxml":xml}[a[0]]
    return read

class Tests(unittest.TestCase):
    def test_original_readback(self):
        with patch.object(drill,"virsh",side_effect=fake(DOMAIN)):
            self.assertEqual(drill.check_original(),DOMAIN)

    def test_maintenance_readback(self):
        planned,_=planner.plan(DOMAIN,OLD,NEW)
        with patch.object(drill,"virsh",side_effect=fake(planned)):
            self.assertTrue(drill.check_maintenance(DOMAIN))

    def test_extra_network_refused(self):
        planned,_=planner.plan(DOMAIN,OLD,NEW)
        planned=planned.replace("</devices>",
           "<interface type='network'><source network='default'/>"
           "</interface></devices>")
        with patch.object(drill,"virsh",side_effect=fake(planned)):
            with self.assertRaisesRegex(drill.DrillError,"Unwanted"):
                drill.check_maintenance(DOMAIN)

    def test_wrong_original_disk_refused(self):
        changed=DOMAIN.replace(OLD,"/tmp/wrong-disk.qcow2")
        with patch.object(drill,"virsh",side_effect=fake(changed)):
            with self.assertRaisesRegex(drill.DrillError,"disk source"):
                drill.check_original()

if __name__=="__main__":
    unittest.main()
