#!/usr/bin/env python3
"""Dry fixture tests for guarded scoped CAPE nft install; no actual nft writes."""
import json
import unittest
from unittest.mock import patch,MagicMock
import install_cape_lab_guard_nft as m
import dryrun_cape_lab_guard_nft as d

def nft_json():
    obj={"nftables":[{"metainfo":{"version":"1.0"}},
        {"table":{"family":"inet","name":m.NAME}}]}
    for label,hook in (("cape_forward","forward"),
                       ("cape_input","input"),("cape_output","output")):
        obj["nftables"].append({"chain":{
             "family":"inet","table":m.NAME,"name":label,
             "type":"filter","hook":hook,"prio":-50,"policy":"accept"}})
    for label,actions in (
        ("cape_forward",("drop","drop")),
        ("cape_input",("accept","drop")),
        ("cape_output",("accept","drop"))):
        for action in actions:
            obj["nftables"].append({"rule":{
                "family":"inet","table":m.NAME,"chain":label,
                "expr":[{"match":{"left":"INTERFACE","right":d.BRIDGE}},
                        {action:None}]}})
    return json.dumps(obj)

class Tests(unittest.TestCase):
    def test_nft_readback_enforces_scope_chain_and_verdict_order(self):
        with patch.object(m,"execute",side_effect=[
            nft_json(),
            'table inet cape_analysis_guard { iifname "cape-lab0" '
            'oifname "cape-lab0" ip daddr 192.168.240.1 '
            'ip daddr 192.168.240.0/24 tcp dport 8000 '
            'ct state established,related accept }'
        ]):
            self.assertTrue(m.verify_installed())

    def test_malformed_chain_priority_refused(self):
        payload=nft_json().replace('"prio": -50','"prio": 0',1)
        with patch.object(m,"execute",return_value=payload):
            with self.assertRaisesRegex(m.GuardInstallBlocked,"priority"):
                m.verify_installed()

    def test_verdict_order_refused(self):
        payload=nft_json()
        blob=json.loads(payload)
        first=next(x["rule"] for x in blob["nftables"] if "rule" in x)
        first["expr"][-1]={"accept":None}
        with patch.object(m,"execute",return_value=json.dumps(blob)):
            with self.assertRaisesRegex(m.GuardInstallBlocked,"ordering"):
                m.verify_installed()

    def test_plan_never_changes_host(self):
        with patch.object(m,"preflight",return_value=d.policy_text()),\
             patch.object(m,"execute") as exec_mock:
            from contextlib import redirect_stdout
            import io
            stream=io.StringIO()
            with redirect_stdout(stream):
                rc=m.main(["--mode","plan"])
            self.assertEqual(rc,0)
            self.assertIn("CAPE_GUARD_INSTALL_PLAN_ONLY",stream.getvalue())
            exec_mock.assert_not_called()

    def test_preflight_rejects_existing_nft_table(self):
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(d,"check_guest_and_network"),\
             patch.object(m,"has_table",return_value=True):
            with self.assertRaisesRegex(m.GuardInstallBlocked,"already exists"):
                m.preflight()

    def test_published_guard_survives_failed_readback_fail_closed(self):
        # If readback fails post installation, guard should NOT be deleted.
        # This protects future clients from an unintended short open window.
        self.assertNotIn("delete table",m.install.__code__.co_consts)
if __name__=="__main__": unittest.main()
