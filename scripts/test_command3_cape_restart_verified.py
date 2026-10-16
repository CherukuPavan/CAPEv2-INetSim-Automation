"""Mock-only Command3 five-systemd-unit restart acceptance tests.

No live systemd, rooter, host services, windows guests or network changes.
"""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import command3_cape_restart_verified as m

def report():
    return {
        "all_five_units_loaded":True,
        "tmpfs_ready":True,
        "routing_reference_matches_operator_values":True,
        # Synthetic-only accepted evidence. The real inspect() function
        # deliberately sets all three false until physical qualification.
        "external_ipv4_ipv6_egress_negative_test_verified":True,
        "guest_l2_containment_independently_verified":True,
        "swtpm_coherent_two_cycle_restore_verified":True,
        "routing_file_sha256":"a"*64,
        "approved_five_units":list(m.UNITS),
    }
def systemd_ok(unit):
    return {"unit":unit,"loaded":True,"active":True,
            "active_state":"active","last_result":"success",
            "installed_fragment":True}

class RestartTests(unittest.TestCase):
    def test_exact_operator_five_service_order(self):
        self.assertEqual(list(m.UNITS),[
            "cape.service","cape-processor.service",
            "cape-rooter.service","cape-web.service",
            "suricata.service"])

    def test_plan_sees_live_units_and_mount_without_writing(self):
        with patch.object(m.routing,"read_conf",
                          return_value=(b"ROUTE",SimpleNamespace())), \
             patch.object(m.routing,"proposed_diff",
                          return_value=(b"ROUTE",[])), \
             patch.object(m.routing.guard,"sha",return_value="a"*64), \
             patch.object(m.tmpfs,"assess",
                          return_value={"cape_tmpfs_prerequisite_ready":True}), \
             patch.object(m.services,"systemd_status",
                          side_effect=systemd_ok):
            x=m.inspect(Path("/opt/CAPEv2/conf/routing.conf"),
                        Path("/opt/CAPEv2/conf/cuckoo.conf"))
        self.assertTrue(x["all_five_units_loaded"])
        self.assertTrue(x["tmpfs_ready"])
        self.assertTrue(x["routing_reference_matches_operator_values"])
        self.assertFalse(x["restart_executed"])
        self.assertFalse(x["safe_to_analyze_untrusted_samples"])
        self.assertFalse(x["external_ipv4_ipv6_egress_negative_test_verified"])
        self.assertFalse(x["guest_l2_containment_independently_verified"])
        self.assertFalse(x["swtpm_coherent_two_cycle_restore_verified"])
        with self.assertRaisesRegex(m.RestartBlocked, "independent proof"):
            m.admitted_status(x)

    def test_rejects_unmounted_tmpfs_and_uninstalled_units(self):
        for flag in ("tmpfs_ready","all_five_units_loaded",
                     "routing_reference_matches_operator_values"):
            with self.subTest(flag=flag):
                values=report()
                values[flag]=False
                with self.assertRaises(m.RestartBlocked):
                    m.admitted_status(values)

    def test_service_restart_refused_if_any_security_proof_missing(self):
        for field in (
                "external_ipv4_ipv6_egress_negative_test_verified",
                "guest_l2_containment_independently_verified",
                "swtpm_coherent_two_cycle_restore_verified"):
            with self.subTest(field=field):
                sample=report()
                sample[field]=False
                with self.assertRaisesRegex(m.RestartBlocked, "independent proof"):
                    m.admitted_status(sample)

    def test_never_restart_with_unqualified_host_even_if_operator_approves(self):
        sample=report()
        sample["external_ipv4_ipv6_egress_negative_test_verified"]=False
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.sys.stdin,"isatty",return_value=True), \
             patch.object(m,"target_host",return_value="target"), \
             patch.object(m,"inspect",return_value=sample), \
             patch("builtins.input",return_value=m.APPROVAL), \
             patch.object(m,"restart_exact",
                 side_effect=AssertionError("Unsafe services must never start")):
            with self.assertRaisesRegex(m.RestartBlocked, "independent proof"):
                m.apply("target",Path("route"),Path("cuckoo"),Path("receipts"))

    def test_protected_ssl46_cannot_restart_services(self):
        for host in ("ssl-46", "CSE-SSL-46"):
            with patch.object(m.socket,"gethostname",return_value=host), \
                 self.assertRaisesRegex(m.RestartBlocked,"SSL-46"):
                m.target_host(host)

    def test_refuses_ssl55_mutation_even_when_root(self):
        with patch.object(m.socket,"gethostname",
                          return_value="CSE-SSL-55"), \
             self.assertRaisesRegex(m.RestartBlocked,"protected SSL-55"):
            m.target_host("CSE-SSL-55")
        with patch.object(m.socket,"gethostname",
                          return_value="random-new-host"), \
             self.assertRaisesRegex(m.RestartBlocked,"different host"):
            m.target_host("another-host")

    def test_requires_root_and_direct_terminal(self):
        with patch.object(m.os,"geteuid",return_value=1000), \
             patch.object(m,"inspect",
                          side_effect=AssertionError("No preflight")), \
             self.assertRaisesRegex(m.RestartBlocked,"interactive"):
            m.apply("target",Path("route"),Path("cuckoo"),Path("receipts"))

    def test_denied_consent_never_restarts(self):
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.sys.stdin,"isatty",return_value=True), \
             patch.object(m,"target_host",return_value="target"), \
             patch.object(m,"inspect",return_value=report()), \
             patch("builtins.input",return_value="NO"), \
             patch.object(m,"restart_exact",
                          side_effect=AssertionError("Never restart")), \
             self.assertRaisesRegex(m.RestartBlocked,"declined"):
            m.apply("target",Path("route"),Path("cuckoo"),Path("receipts"))

    def test_expected_five_only_and_no_shell_execution(self):
        with patch.object(m.subprocess,"run",
             return_value=SimpleNamespace(returncode=0)) as run:
            m.restart_exact("cape-rooter.service")
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0],[
            "systemctl","restart","cape-rooter.service"])
        self.assertFalse(run.call_args.kwargs["check"])
        with self.assertRaisesRegex(m.RestartBlocked,"Non-operator"):
            m.restart_exact("ssh.service")

    def test_approved_restart_tracks_exact_successful_sequence(self):
        seen=[]
        states=[]
        def witness(path,data,**kwargs):
            seen.append(deepcopy(data))
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.sys.stdin,"isatty",return_value=True), \
             patch.object(m,"target_host",return_value="target"), \
             patch.object(m,"inspect",return_value=report()), \
             patch("builtins.input",return_value=m.APPROVAL), \
             patch.object(m,"witness_dir",return_value=Path("/receipts")), \
             patch.object(m,"record",side_effect=witness), \
             patch.object(m,"restart_exact",
                          side_effect=lambda unit:states.append(unit)), \
             patch.object(m,"wait_active",return_value=[
                 systemd_ok(u) for u in m.UNITS]):
            output=m.apply("target",Path("route"),Path("cuckoo"),
                           Path("/receipts"))
        self.assertEqual(states,list(m.UNITS))
        self.assertEqual(output["result"],
                        "COMMAND3_FIVE_SERVICE_RESTARTS_ACTIVE_VERIFIED")
        self.assertTrue(output["systemd_units_active_at_check"])
        self.assertFalse(output["CAPE_READY_FOR_SAMPLE_ANALYSIS"])
        self.assertEqual(seen[-1]["completed"],list(m.UNITS))
        self.assertTrue(seen[-1]["all_five_active_after_restart_verified"])

    def test_unit_failure_stops_and_records_partial_without_retry(self):
        seq=[]
        seen=[]
        def child(unit):
            seq.append(unit)
            if len(seq)==3:
                raise m.RestartBlocked("SENSITIVE ERROR")
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.sys.stdin,"isatty",return_value=True), \
             patch.object(m,"target_host",return_value="target"), \
             patch.object(m,"inspect",return_value=report()), \
             patch("builtins.input",return_value=m.APPROVAL), \
             patch.object(m,"witness_dir",return_value=Path("/receipts")), \
             patch.object(m,"record",side_effect=lambda path,record,**kw:
                         seen.append(deepcopy(record))), \
             patch.object(m,"restart_exact",side_effect=child), \
             patch.object(m,"wait_active",
                          side_effect=AssertionError("Do not verify partial")), \
             self.assertRaisesRegex(m.RestartBlocked,"PARTIAL_OR_UNKNOWN"):
            m.apply("target",Path("route"),Path("cuckoo"),Path("/receipts"))
        self.assertEqual(len(seq),3)
        self.assertEqual(seen[-1]["result"],
                         "COMMAND3_RESTART_PARTIAL_OR_UNKNOWN")
        self.assertEqual(seen[-1]["completed"],list(m.UNITS[:2]))
        self.assertNotIn("SENSITIVE ERROR",str(seen[-1]))

    def test_routing_drift_blocks_before_third_restart(self):
        seq=[]
        seen=[]
        a=report()
        b=report();b["routing_file_sha256"]="b"*64
        def next_read(*arg):
            # approval preflight 2 reads, then one for first restart,
            # then drift before second restart.
            next_read.calls+=1
            return a if next_read.calls<4 else b
        next_read.calls=0
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.sys.stdin,"isatty",return_value=True), \
             patch.object(m,"target_host",return_value="target"), \
             patch.object(m,"inspect",side_effect=next_read), \
             patch("builtins.input",return_value=m.APPROVAL), \
             patch.object(m,"witness_dir",return_value=Path("/receipts")), \
             patch.object(m,"record",side_effect=lambda path,record,**kw:
                         seen.append(deepcopy(record))), \
             patch.object(m,"restart_exact",
                          side_effect=lambda unit:seq.append(unit)), \
             self.assertRaisesRegex(m.RestartBlocked,"PARTIAL_OR_UNKNOWN"):
            m.apply("target",Path("route"),Path("cuckoo"),Path("/receipts"))
        self.assertEqual(seq,[m.UNITS[0]])
        self.assertEqual(seen[-1]["completed"],[m.UNITS[0]])
        self.assertEqual(seen[-1]["result"],
                         "COMMAND3_RESTART_PARTIAL_OR_UNKNOWN")

    def test_restart_loop_not_accepted_after_timeout(self):
        clock=[0]
        def tick():
            clock[0]+=5
            return clock[0]
        with patch.object(m.time,"monotonic",side_effect=tick), \
             patch.object(m.time,"sleep",return_value=None), \
             patch.object(m.services,"systemd_status",return_value={
                 "unit":"cape.service","active":False,"loaded":True,
                 "last_result":"exit-code"}), \
             self.assertRaisesRegex(m.RestartBlocked,"timed out"):
            m.wait_active(timeout=9)

    def test_no_vm_routing_revert_or_host_reinstall_calls_in_runner(self):
        src=Path(m.__file__).read_text()
        for banned in ('"snapshot-revert"','"virsh"','"net-update"',
                       '"destroy"','"iptables"', '"apt-get"',
                       "shell=True","os.system(","subprocess.Popen("):
            self.assertNotIn(banned,src)

if __name__=="__main__":
    unittest.main()
