#!/usr/bin/env python3
"""Offline tests: no sudo, network, pip install or host changes."""
import json
import tempfile
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

import install_cape_optional_deps as m


class NormalizeTests(TestCase):
    def test_pep503_equivalence(self):
        self.assertEqual(m.normalized("Image_Hash.name"), "image-hash-name")

    def test_conflict_against_core_lockfile(self):
        self.assertEqual(
            m.conflicts([
                {"name": "requests", "version": "2.40.0"},
                {"name": "new-addon", "version": "1.0"},
                {"name": "networkx", "version": "3.5"},
            ], {"requests": "2.32.0", "networkx": "3.5"}),
            ["requests proposed=2.40.0 locked=2.32.0"],
        )

    def test_new_extra_is_not_a_lock_conflict(self):
        self.assertEqual(m.conflicts([{"name": "ImageHash", "version": "4.3.2"}],
                                     {"requests": "2.32.0"}), [])

    def test_parse_poetry_lock(self):
        content = '[[package]]\nname="requests"\nversion="2.31.0"\n\n'
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "poetry.lock"
            path.write_text(content)
            self.assertEqual(m.locked_versions(path), {"requests": "2.31.0"})


class ServiceAccountTests(TestCase):
    def test_wrong_user_test_not_used(self):
        path = "/home/cape/.cache/pypoetry/virtualenvs/virtual/bin/python"
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(m, "call", side_effect=[(0, path), (0, "")]) as runner:
            self.assertEqual(m.service_python(), Path(path))
            for arg in runner.call_args_list:
                self.assertEqual(arg.args[0][:5], ["sudo", "-n", "-u", "cape", "-H"])

    def test_no_permission_is_unknown(self):
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(m, "call", return_value=(1, "")):
            self.assertIsNone(m.service_python())

    def test_multiline_path_refused(self):
        with patch.object(Path, "is_file", return_value=True), \
             patch.object(m, "call", return_value=(0, "/bin/python\nunsafe")):
            self.assertIsNone(m.service_python())

    def test_package_versions_from_service_python(self):
        val = {"ImageHash": "4.3.2", "deepdiff": None}
        with patch.object(m, "call", return_value=(0, json.dumps(val))) as runner:
            self.assertEqual(m.sample_versions(Path("/sbin/venv/bin/python")), val)
        self.assertEqual(runner.call_args.args[0][:5], ["sudo", "-n", "-u", "cape", "-H"])

    def test_pip_resolution_dryrun_no_install_by_host(self):
        plan = {"proposed": [{"name": "ImageHash", "version": "4.3.2"}]}
        with patch.object(m, "call", return_value=(0, json.dumps(plan))) as runner:
            self.assertEqual(m.proposed_changes(Path("/venv/bin/python"), Path("/opt/CAPEv2/extra/optional_dependencies.txt")), plan)
        cmd = runner.call_args.args[0]
        self.assertEqual(cmd[:5], ["sudo", "-n", "-u", "cape", "-H"])
        self.assertIn("--dry-run", m.RESOLVE_CODE)
        self.assertNotIn("--upgrade", cmd)

    def test_resolver_failure_blocks_install(self):
        with patch.object(m, "call", return_value=(0, '{"error":"resolver-failed","code":1}')):
            with self.assertRaisesRegex(RuntimeError, "dry-run failed"):
                m.proposed_changes(Path("/venv/bin/python"), Path("/opt/CAPEv2/extra/optional_dependencies.txt"))


if __name__ == "__main__":
    main()
