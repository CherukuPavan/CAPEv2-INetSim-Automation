"""Mocked Command3 deployment-only systemd reversal; never calls live systemd."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch
from types import SimpleNamespace
import json

import command3_service_owned_rollback as rollback


def state(unit, active, invocation, enabled="enabled"):
    return {
        "Id":unit, "LoadState":"loaded",
        "ActiveState":"active" if active else "inactive",
        "UnitFileState":enabled,
        "FragmentPath":"/usr/lib/systemd/system/"+unit,
        "InvocationID":invocation
    }


def sample():
    before={}
    after={}
    for i,unit in enumerate(rollback.UNITS):
        before[unit]=state(unit,i>=2,"a"*32 if i>=2 else "")
        after[unit]=state(unit,True,"b"*32)
    return {
        "result":"COMMAND3_FIVE_SERVICE_RESTARTS_ACTIVE_VERIFIED",
        "target_host":"target",
        "approved_units":list(rollback.UNITS),
        "completed":list(rollback.UNITS),
        "all_five_active_after_restart_verified":True,
        "service_states_before":before,
        "service_states_after":after,
    }


class ServiceOwnershipTests(TestCase):
    def test_exact_five_only_and_no_restore_of_preexisting_active(self):
        receipt=sample()
        with patch.object(rollback,"snapshot",
                          return_value=deepcopy(receipt["service_states_after"])):
            plan=rollback.plan_from_receipt(receipt)
        self.assertEqual(
            [r["unit"] for r in plan["actions"]
             if r["action"]=="STOP_ONLY_DEPLOYMENT_STARTED"],
            list(rollback.UNITS[:2]))
        self.assertEqual(plan["preexisting_active_units_preserved"],
                         list(rollback.UNITS[2:]))
        self.assertFalse(plan["all_services_can_be_reverted"])
        self.assertTrue(plan["some_runtime_restarts_irreversible"])
        self.assertFalse(plan["full_host_rollback_complete"])

    def test_refuse_partial_restart_receipt(self):
        incomplete=sample()
        incomplete["result"]="COMMAND3_RESTART_PARTIAL_OR_UNKNOWN"
        with patch.object(rollback,"snapshot") as actual, \
             self.assertRaisesRegex(
                 rollback.ServiceOwnershipBlocked,"Partial or unverified"):
            rollback.plan_from_receipt(incomplete)
        actual.assert_not_called()

    def test_refuse_current_external_invocation_drift(self):
        doc=sample()
        observed=deepcopy(doc["service_states_after"])
        observed[rollback.UNITS[0]]["InvocationID"]="c"*32
        with patch.object(rollback,"snapshot",return_value=observed):
            out=rollback.plan_from_receipt(doc)
        self.assertEqual(out["blocked_units"],[rollback.UNITS[0]])
        self.assertFalse(out["all_services_can_be_reverted"])

    def test_refuse_unit_file_enabled_or_fragment_drift(self):
        doc=sample()
        changed=deepcopy(doc)
        changed["service_states_after"][rollback.UNITS[0]]["UnitFileState"]="disabled"
        with patch.object(rollback,"snapshot",
                          return_value=changed["service_states_after"]):
            planned=rollback.plan_from_receipt(changed)
        self.assertEqual(planned["actions"][0]["action"],
                         "BLOCKED_UNIT_CHANGED_DURING_RESTART")

    def test_reject_wrong_or_malformed_receipts(self):
        doc=sample()
        for kind in ("wrong-units","missing-before","invalid-active-id"):
            trial=deepcopy(doc)
            if kind=="wrong-units":
                trial["approved_units"].append("ssh.service")
            elif kind=="missing-before":
                trial.pop("service_states_before")
            else:
                trial["service_states_before"][rollback.UNITS[2]][
                    "InvocationID"]="INJECTED"
            with self.subTest(kind=kind), \
                 patch.object(rollback,"snapshot") as actual, \
                 self.assertRaises(rollback.ServiceOwnershipBlocked):
                rollback.plan_from_receipt(trial)
            actual.assert_not_called()

    def test_reject_protected_reference_hosts(self):
        for protected in ("CSE-SSL-55","CSE-SSL-46"):
            with patch.object(rollback.socket,"gethostname",
                              return_value=protected), \
                 self.assertRaisesRegex(
                    rollback.ServiceOwnershipBlocked, "protected"):
                rollback.host_guard(protected)

    def test_rollback_stops_exactly_two_newly_started_services(self):
        doc=sample()
        current=deepcopy(doc["service_states_after"])
        notes=[]
        stopped=[]
        path=Path("/receipts/command3-five-units.123456.json")
        def stop(unit):
            stopped.append(unit)
            current[unit]["ActiveState"]="inactive"
            current[unit]["InvocationID"]=""
        with patch.object(rollback.os,"geteuid",return_value=0), \
             patch.object(rollback.sys.stdin,"isatty",return_value=True), \
             patch.object(rollback,"host_guard",return_value="target"), \
             patch.object(rollback,"trusted_receipt",return_value=doc), \
             patch.object(rollback,"snapshot",side_effect=lambda:deepcopy(current)), \
             patch.object(rollback,"unit_state",
                          side_effect=lambda unit:deepcopy(current[unit])), \
             patch.object(rollback,"no_live_guest"), \
             patch("builtins.input",
                   return_value="UNDO-ONLY-DEPLOYMENT-STARTED-CAPE-SERVICES"), \
             patch.object(rollback,"stop_owned",side_effect=stop), \
             patch("command3_cape_restart_verified.record",
                   side_effect=lambda p, d, **kwargs: notes.append(deepcopy(d))):
            result=rollback.rollback(path,"target")
        self.assertEqual(stopped,list(rollback.UNITS[:2]))
        self.assertEqual(result["stopped_units"],list(rollback.UNITS[:2]))
        self.assertEqual(result["preexisting_active_services_preserved"],
                         list(rollback.UNITS[2:]))
        self.assertTrue(notes[0]["result"].endswith("STARTED"))
        self.assertTrue(notes[-1]["result"].endswith("STOPPED"))
        self.assertFalse(result["full_deployment_rollback_complete"])

    def test_rollback_refuses_partial_without_stopping_any(self):
        doc=sample()
        doc["service_states_after"][rollback.UNITS[0]]["UnitFileState"]="disabled"
        with patch.object(rollback.os,"geteuid",return_value=0), \
             patch.object(rollback.sys.stdin,"isatty",return_value=True), \
             patch.object(rollback,"host_guard",return_value="target"), \
             patch.object(rollback,"trusted_receipt",return_value=doc), \
             patch.object(rollback,"snapshot",
                          return_value=doc["service_states_after"]), \
             patch.object(rollback,"stop_owned") as stop, \
             self.assertRaisesRegex(
                 rollback.ServiceOwnershipBlocked, "no partial"):
            rollback.rollback(
                Path("/receipts/command3-five-units.receipt.json"),"target")
        stop.assert_not_called()

    def test_not_root_denies_before_probing_systemd(self):
        with patch.object(rollback.os,"geteuid",return_value=1000), \
             patch.object(rollback,"unit_state") as inspect, \
             self.assertRaisesRegex(
                 rollback.ServiceOwnershipBlocked, "root"):
            rollback.rollback(Path("/foo"),"target")
        inspect.assert_not_called()


if __name__ == "__main__":
    main()
