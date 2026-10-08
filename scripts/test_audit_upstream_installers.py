#!/usr/bin/env python3
"""Static source risk-audit tests; no actual installers executed."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
import json

import audit_upstream_installers as m


class UpstreamRiskTests(TestCase):
    def test_kvm_host_wide_masks_are_blocked(self):
        r = m.audit_text("#!/bin/bash\nsystemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target\n",
                         "kvm")
        mask = next(x for x in r["rules"] if x["risk"] == "sleep-target masks")
        self.assertTrue(mask["found"])
        self.assertEqual(mask["severity"], "BLOCK")
        self.assertEqual(r["blocking_patterns"], 1)

    def test_cape_global_changes_are_detected(self):
        source = 'PASSWD="SECRET_DONT_EXPOSE"\ntimedatectl set-timezone UTC\naa-disable /usr/sbin/tcpdump\n'
        r = m.audit_text(source, "cape")
        self.assertGreaterEqual(r["blocking_patterns"], 3)
        self.assertNotIn("SECRET_DONT_EXPOSE", repr(r))

    def test_upstream_nothing_executes(self):
        with TemporaryDirectory() as folder:
            p = Path(folder) / "cape2.sh"
            p.write_text("#!/bin/bash\nsystemctl restart cape\n")
            r = m.read_script(p, "cape")
            self.assertEqual(r["script_name"], "cape2.sh")
            self.assertNotIn("systemctl restart cape", repr(r))
            self.assertEqual(len(r["sha256"]), 64)

    def test_known_env_glob_is_visible_as_review(self):
        r = m.audit_text("for x in conf/default/*.env; do :; done\n", "cape")
        matches = [x for x in r["rules"] if x["risk"] == "shell glob env-copy"]
        self.assertEqual(len(matches), 1)
        self.assertTrue(matches[0]["found"])


if __name__ == "__main__":
    main()
