"""Read-only unit tests: libvirt PAUSED/suspended must never pass rollback."""
from __future__ import annotations

from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

import command123_libvirt_quiescence as q


class LibvirtQuiescenceTests(TestCase):
    def test_no_domains_allows_recovery_with_two_inventories(self):
        with patch.object(q,"read_virsh",return_value="") as call:
            doc=q.no_nonshutoff_domains()
        self.assertEqual(doc["defined_domain_count"],0)
        self.assertTrue(doc["only_shutoff_domains_observed"])
        self.assertFalse(any("running" in " ".join(c.args) for c in call.call_args_list))
        self.assertEqual(call.call_count,2)

    def test_multiple_shutoff_domains_allowed_readonly(self):
        seen=[]
        def tool(*args):
            seen.append(args)
            if args==("list","--all","--name"):
                return "win11_2\nwin11\n"
            if args[:1]==("domstate",):
                return "shut off\n"
            raise AssertionError(args)
        with patch.object(q,"read_virsh",side_effect=tool):
            out=q.no_nonshutoff_domains()
        self.assertEqual(out["defined_domain_count"],2)
        self.assertEqual(
            seen,
            [("list","--all","--name"),
             ("domstate","win11"),("domstate","win11_2"),
             ("list","--all","--name")])

    def test_paused_pmsuspended_crashed_and_unknown_are_blocked(self):
        for state in ("paused","pmsuspended","running","crashed",
                      "in shutdown","idle","unknown","shut off (saved)"):
            with self.subTest(state=state):
                with patch.object(q,"read_virsh",
                     side_effect=["win11_1\n",state+"\n"]) as tool:
                    with self.assertRaisesRegex(
                        q.QuiescenceBlocked, "live, paused, suspended"):
                        q.no_nonshutoff_domains()
                self.assertEqual(tool.call_count,2)

    def test_new_domain_appears_during_state_scan(self):
        with patch.object(q,"read_virsh",side_effect=[
            "win11\n","shut off\n","win11\nwin11_1\n"]):
            with self.assertRaisesRegex(
                q.QuiescenceBlocked,"inventory drift"):
                q.no_nonshutoff_domains()

    def test_duplicate_domain_inventory_is_refused(self):
        with patch.object(q,"read_virsh",return_value="win11\nwin11\n"):
            with self.assertRaisesRegex(
                q.QuiescenceBlocked,"duplicate"):
                q.no_nonshutoff_domains()

    def test_virsh_nonzero_and_timeout_are_blocked(self):
        with patch.object(q.subprocess,"run",return_value=SimpleNamespace(
               returncode=1,stdout="")):
            with self.assertRaisesRegex(q.QuiescenceBlocked,"inventory"):
                q.no_nonshutoff_domains()
        from subprocess import TimeoutExpired
        with patch.object(q.subprocess,"run",side_effect=TimeoutExpired(
              cmd=["virsh"],timeout=1)):
            with self.assertRaisesRegex(q.QuiescenceBlocked,"inspect"):
                q.no_nonshutoff_domains()

    def test_only_readonly_virsh_list_and_domstate_argv(self):
        calls=[]
        def runner(argv,**kw):
            calls.append(argv)
            if "list" in argv:
                return SimpleNamespace(returncode=0,stdout="win11\n")
            return SimpleNamespace(returncode=0,stdout="shut off\n")
        with patch.object(q.subprocess,"run",side_effect=runner):
            q.no_nonshutoff_domains()
        self.assertEqual(calls,[
            ["virsh","-c","qemu:///system","list","--all","--name"],
            ["virsh","-c","qemu:///system","domstate","win11"],
            ["virsh","-c","qemu:///system","list","--all","--name"],
        ])
        for argv in calls:
            for forbidden in ("start","destroy","undefine","snapshot-revert"):
                self.assertNotIn(forbidden,argv)


if __name__=="__main__":
    main()
