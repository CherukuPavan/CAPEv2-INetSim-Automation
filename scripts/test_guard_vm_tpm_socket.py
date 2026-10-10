#!/usr/bin/env python3
"""Offline fixture tests for exact clone swtpm AppArmor policy."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import guard_vm_tpm_socket as m

UUID="a1a1a1a1-1234-4444-8888-bbbbbbbbbbbb"

class TPMTests(unittest.TestCase):
    def test_generates_exact_clone_socket_rule(self):
        target,rule=m.expected("win11_3",UUID)
        self.assertIn("98-cape-swtpm-",str(target))
        self.assertIn("*-win11_3-swtpm.sock rw,",rule)
        self.assertNotIn("win11_4",rule)

    def test_exact_trial_clone_socket_rule(self):
        target,rule=m.expected("win11_trial_1",UUID)
        self.assertEqual(target.name,"98-cape-swtpm-"+UUID)
        self.assertEqual(
            rule,
            "  /run/libvirt/qemu/swtpm/*-win11_trial_1-swtpm.sock rw,\\n"
        )
        self.assertNotIn("*-win11-swtpm.sock",rule)

    def test_rejects_master_or_glob(self):
        for vm in ["win11", "win11_0","win11_*","win11_01","cuckoo1",
                   "win11_trial_0","win11_trial_01","win11_trial_*"]:
            with self.subTest(vm=vm):
                with self.assertRaises(m.PolicyError):
                    m.expected(vm,UUID)

    def test_plan_is_no_write(self):
        with TemporaryDirectory() as t:
            target=Path(t)/("98-cape-swtpm-"+UUID)
            with patch.object(m,"expected",return_value=(target,"expected rule\n")),\
                 patch.object(m,"ensure_shutdown"),\
                 patch.object(m.guard,"ensure_supported"):
                result=m.prepare("win11_1",UUID,False)
            self.assertEqual(result["status"],"WOULD_CREATE")
            self.assertFalse(target.exists())

    def test_apply_and_reapply_idempotent(self):
        with TemporaryDirectory() as t:
            d=Path(t)
            policy=d/("98-cape-swtpm-"+UUID)
            with patch.object(m,"expected",return_value=(policy,"rule\n")),\
                 patch.object(m,"LOCK",d/"lock"),\
                 patch.object(m.guard,"RULEDIR",d),\
                 patch.object(m,"ensure_shutdown"),\
                 patch.object(m.guard,"ensure_supported"),\
                 patch.object(m.guard,"parse_profile"),\
                 patch.object(m.os,"geteuid",return_value=0):
                first=m.prepare("win11_1",UUID,True)
                again=m.prepare("win11_1",UUID,True)
            self.assertTrue(first["changed"])
            self.assertFalse(again["changed"])
            self.assertEqual(policy.read_text(),"rule\n")

    def test_parser_failure_removes_owned_policy_only(self):
        with TemporaryDirectory() as t:
            d=Path(t)
            policy=d/("98-cape-swtpm-"+UUID)
            with patch.object(m,"expected",return_value=(policy,"rule\n")),\
                 patch.object(m,"LOCK",d/"lock"),\
                 patch.object(m.guard,"RULEDIR",d),\
                 patch.object(m,"ensure_shutdown"),\
                 patch.object(m.guard,"ensure_supported"),\
                 patch.object(m.guard,"parse_profile",side_effect=[
                     m.guard.GuardError("bad"),None]),\
                 patch.object(m.os,"geteuid",return_value=0):
                with self.assertRaisesRegex(m.PolicyError,"validation"):
                    m.prepare("win11_1",UUID,True)
            self.assertFalse(policy.exists())

if __name__=="__main__":
    unittest.main()
