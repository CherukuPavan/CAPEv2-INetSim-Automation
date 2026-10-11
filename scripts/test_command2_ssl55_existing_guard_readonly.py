"""Synthetic-only protected SSL55 CAPE nft/firewall readiness tests."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_ssl55_existing_guard_readonly as s


def xml(name,uid,nic=""):
    return (f'<domain type="kvm"><name>{name}</name><uuid>{uid}</uuid>'
            f'<devices>{nic}</devices></domain>')


NIC=('<interface type="network"><source network="default"/>'
     '<model type="e1000e"/></interface>')
NETWORKXML=('<network><name>cape-analysis-isolated</name>'
            '<bridge name="cape-lab0"/><ip address="192.168.240.1" '
            'netmask="255.255.255.0"/></network>')
ACTIONS={"cape_forward":("forward",["drop","drop"]),
         "cape_input":("input",["accept","drop"]),
         "cape_output":("output",["accept","drop"])}


def nft_json():
    rows=[{"table":{"family":"inet","name":"cape_analysis_guard"}}]
    for name,(hook,verdict) in ACTIONS.items():
        rows.append({"chain":{"family":"inet","table":"cape_analysis_guard",
                   "name":name,"type":"filter","hook":hook,"prio":-50,
                   "policy":"accept"}})
        for v in verdict:
            rows.append({"rule":{"family":"inet","table":"cape_analysis_guard",
                   "chain":name,"expr":[{"match":{"op":"=="}},{v:None}]}})
    return json.dumps({"nftables":rows})


NFT_TEXT=('table inet cape_analysis_guard { '
          'iifname "cape-lab0" oifname "cape-lab0" '
          '192.168.240.1 192.168.240.0/24 '
          'tcp dport 8000 ct state established,related }')


def virsh_fake(*a):
    if a==("list","--all","--name"):
        return "win11\nwin11_1\nwin11_trial_1"
    if a[0]=="domuuid":
        return {"win11":s.MASTER_UUID,"win11_1":s.CLONE_UUID,
                "win11_trial_1":s.TRIAL_UUID}[a[1]]
    if a[0]=="domstate":
        return "shut off" if a[1]!="win11_trial_1" else "running"
    if a[0]=="dumpxml":
        name=a[-1]
        return xml(name,{"win11":s.MASTER_UUID,"win11_1":s.CLONE_UUID,
                         "win11_trial_1":s.TRIAL_UUID}[name],
                   NIC if name=="win11" else "")
    if a==("net-info",s.NETWORK):
        return "Active: no\nAutostart: no\nPersistent: yes\nBridge: cape-lab0"
    if a==("net-dumpxml",s.NETWORK):
        return NETWORKXML
    raise AssertionError("Unexpected libvirt command "+str(a))


def command_fake(*a):
    if a==("ip","-j","link","show"):
        return '[{"ifname":"eno1","address":"00:13:33:aa:bb:cc"}]'
    if a==("nft","-j","list","table","inet",s.TABLE): return nft_json()
    if a==("nft","list","table","inet",s.TABLE): return NFT_TEXT
    if a[:2]==("systemctl","is-enabled"):return "disabled"
    if a[:2]==("systemctl","is-active"):return "inactive"
    raise AssertionError("Unexpected read-only command "+str(a))


class SSL55GuardReadOnlyTests(unittest.TestCase):
    def test_pure_expected_existing_policy_structure(self):
        got=s.guard_policy_structure(nft_json(),NFT_TEXT)
        self.assertTrue(got["expected_chain_hooks_and_order"])
        self.assertFalse(got["ipv4_ipv6_packet_path_tested"])
        self.assertEqual(got["rule_verdict_sequences"]["cape_output"],
                         ["accept","drop"])

    def test_pure_refuses_missing_ipv6_and_agent_tokens(self):
        for text in (NFT_TEXT.replace("tcp dport 8000","tcp dport 443"),
                     NFT_TEXT.replace("192.168.240.1","192.168.240.2"),
                     NFT_TEXT.replace('iifname "cape-lab0"',"")):
            with self.subTest(text=text),self.assertRaises(s.AuditBlocked):
                s.guard_policy_structure(nft_json(),text)

    def test_pure_refuses_unexpected_chain_verdict_order(self):
        bad=json.loads(nft_json())
        for node in bad["nftables"]:
            if "rule" in node and node["rule"]["chain"]=="cape_output":
                node["rule"]["expr"][-1]={"accept":None}
        with self.assertRaisesRegex(s.AuditBlocked,"verdict"):
            s.guard_policy_structure(json.dumps(bad),NFT_TEXT)

    def test_actual_audit_mock_is_readonly_never_authorizes_nic(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(s,"SENTINEL",Path(td)),\
                 patch.object(s.os,"geteuid",return_value=0),\
                 patch.object(s,"virsh",side_effect=virsh_fake),\
                 patch.object(s,"command",side_effect=command_fake):
                out=s.audit()
        self.assertEqual(out["result"],
                         "SSL55_EXISTING_COMMAND2_NFT_PERSISTENCE_AUDIT_ONLY")
        self.assertTrue(out["existing_lab_firewall"]["expected_guard_shape"])
        self.assertTrue(out["win11_1_candidate_nic_not_applied"]
                        ["mac_inventory_complete"])
        self.assertFalse(out["win11_1_candidate_nic_not_applied"]
                         ["host_or_libvirt_mac_collision"])
        self.assertFalse(out["win11_1_candidate_nic_not_applied"]
                         ["approval_to_attach"])
        self.assertEqual(out["analysis_network"]["active"],"no")
        self.assertEqual(out["protected_domains"]["win11_1"]["nic_counts"]
                         ["inactive"],0)
        for k in ("reboot_persistence_actually_tested",
                  "safe_to_attach_analysis_nic",
                  "safe_to_capture_running_snapshot",
                  "ipv6_external_egress_negative_test",
                  "ipv4_external_egress_negative_test",
                  "no_vm_or_network_changes"):
            self.assertEqual(out[k],k=="no_vm_or_network_changes")

    def test_refuse_reference_host_mismatch_before_host_queries(self):
        with patch.object(s.socket,"gethostname",return_value="random-host"),\
             patch.object(s,"virsh",side_effect=AssertionError("No access")):
            with self.assertRaisesRegex(s.AuditBlocked,"protected SSL-55"):
                s.audit()

    def test_missing_guard_yields_blocking_status_not_approval(self):
        def unavailable(*a):
            if a[:1]==("nft",): return None
            return command_fake(*a)
        with tempfile.TemporaryDirectory() as td:
            with patch.object(s.socket,"gethostname",return_value="SSL-55"),\
                 patch.object(s,"SENTINEL",Path(td)),\
                 patch.object(s.os,"geteuid",return_value=0),\
                 patch.object(s,"virsh",side_effect=virsh_fake),\
                 patch.object(s,"command",side_effect=unavailable):
                out=s.audit()
        self.assertFalse(out["existing_lab_firewall"]["guard_present"])
        self.assertFalse(out["safe_to_attach_analysis_nic"])

    def test_candidate_mac_conflict_with_host_blocks_safe_attachment(self):
        import hashlib
        digest=hashlib.sha256(
            ("CAPE_COMMAND2_SSL55_WIN11_1|" + s.CLONE_UUID).encode()
        ).digest()[:5]
        collision="02:"+":".join(f"{x:02x}" for x in digest)
        def host(*a):
            if a==("ip","-j","link","show"):
                return json.dumps([{"ifname":"eno1","address":collision}])
            raise AssertionError("Unexpected command "+str(a))
        with patch.object(s,"virsh",side_effect=virsh_fake),\
             patch.object(s,"command",side_effect=host):
            plan=s.proposed_analysis_mac()
        self.assertTrue(plan["host_or_libvirt_mac_collision"])
        self.assertFalse(plan["approval_to_attach"])

    def test_unavailable_mac_inventory_fails_closed(self):
        with patch.object(s,"virsh",side_effect=virsh_fake),\
             patch.object(s,"command",return_value=None):
            with self.assertRaisesRegex(s.AuditBlocked,"MAC inventory"):
                s.proposed_analysis_mac()

    def test_source_does_not_expose_write_capable_commands(self):
        text=Path(s.__file__).read_text()
        body=text[text.index("from __future__ import annotations"):]
        for token in ('"net-start"', '"net-define"', '"attach-interface"',
                      '"snapshot-create"', '"snapshot-revert"', '"nft","-f"',
                      '"nft","add"', '"systemctl","enable"',
                      '"systemctl","start"', 'shutil.copyfile'):
            self.assertNotIn(token,body)


if __name__=="__main__":
    unittest.main()
