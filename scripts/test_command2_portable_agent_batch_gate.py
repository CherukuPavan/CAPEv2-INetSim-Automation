"""All-N Windows CAPE Agent verification is read-only and count-bound."""
import unittest
from pathlib import Path
from unittest.mock import patch
import command2_portable_agent_batch_gate as g

HOST="other-safe-host"
def row(i):
    return {"libvirt_name":f"win11_{i}",
            "libvirt_uuid_candidate":f"12345678-1234-4234-8234-{i:012d}",
            "guest_static_ipv4_target":f"192.168.240.{100+i}",
            "disk_target":f"/private/win11_{i}.command2.qcow2",
            "uefi_nvram_target":f"/private/win11_{i}.command2_VARS.fd",
            "mac_candidate":f"02:aa:bb:cc:dd:{i:02x}"}

class AgentBatch(unittest.TestCase):
    def run_mock(self,agents=(True,True)):
        rows=[row(1),row(2)]
        with patch.object(g.workflow,"canonical_host",return_value=HOST),\
             patch.object(g.os,"geteuid",return_value=0),\
             patch.object(g.batch,"private_evidence_folder"),\
             patch.object(g.batch,"reservation_rows",return_value=rows),\
             patch.object(g.workflow,"load_guest",
                 side_effect=lambda journal,host,vm:(next(x for x in rows
                    if x["libvirt_name"]==vm),"192.168.240.0/24",None)),\
             patch.object(g,"virsh",return_value="shut off"),\
             patch.object(g.nic,"verify_network_live",return_value=True),\
             patch.object(g,"check_one_live",side_effect=lambda r:{
                  "vm":r["libvirt_name"],
                  "uuid":r["libvirt_uuid_candidate"],
                  "expected_ip":r["guest_static_ipv4_target"],
                  "guest_running":True}),\
             patch.object(g.agent,"probe_agent",side_effect=lambda ip:{
                 "result":"COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
                 "guest_ip":ip,"guest_agent_admin":agents[int(ip.rsplit(".",1)[1])-101],
                 "version":"0.23"}),\
             patch.object(g,"need",wraps=g.need):
            return g.audit(HOST,Path("/private/command2-identity-reservation.json"))

    def test_all_windows_agents_must_pass_with_exact_ips(self):
        out=self.run_mock()
        self.assertEqual(out["positive_agent_count"],2)
        self.assertTrue(out["all_agent_probes_passed"])
        self.assertFalse(out["tpm_firmware_restore_proven"])
        self.assertFalse(out["command2_complete"])

    def test_second_agent_failure_cannot_certify_all(self):
        out=self.run_mock((True,False))
        self.assertFalse(out["all_agent_probes_passed"])
        self.assertEqual(out["positive_agent_count"],1)
        self.assertEqual(out["guests"][1]["status"],"BLOCKED")

    def test_reject_forged_guest_count_result(self):
        with patch.object(g.workflow,"canonical_host",return_value=HOST),\
             patch.object(g.os,"geteuid",return_value=0),\
             patch.object(g.batch,"private_evidence_folder"),\
             patch.object(g.batch,"reservation_rows",return_value=[]):
            with self.assertRaisesRegex(g.AgentBatchBlocked,"Empty"):
                g.audit(HOST,Path("/private/command2-identity-reservation.json"))

    def test_host_guard_blocks_ssl55(self):
        with patch.object(g.workflow.socket,"gethostname",
                          return_value="CSE-SSL-55"):
            with self.assertRaisesRegex(g.workflow.WorkflowBlocked,"Protected"):
                g.audit("cse-ssl-55",Path("/private/command2-identity-reservation.json"))

    def test_no_vm_or_network_mutators(self):
        code=Path(g.__file__).read_text()
        for bad in ('virsh("start"','virsh("destroy"',
                    'virsh("shutdown"','virsh("attach-interface"',
                    'virsh("snapshot-create"','virsh("snapshot-revert"'):
            self.assertNotIn(bad,code)

if __name__=="__main__":
    unittest.main()
