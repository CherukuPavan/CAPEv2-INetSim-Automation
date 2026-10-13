"""Synthetic-only tests for operator's exact Step 13.2.3 cuckoo.conf."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import command3_cape_cuckoo as c

DSN = "postgresql://cape:FAKE_TEST_ONLY_PASSWORD@localhost:5432/cape"

# SSL-55 operator confirmed three real cleaner keys without _days suffix.
# The user also overrode the guide's resultserver IP with 0.0.0.0.
BEFORE = b"""# CAPE settings (do not replace the entire config)
[cuckoo]
machinery_screenshots = off
memory_dump = off
reschedule = off
freespace = 50000
freespace_processing = 15000
unrelated = CONTINUE

[resultserver]
ip = 192.168.1.1
store_csvs = off
upload_max_size = 100000000

[processing]
analysis_size_limit = 200000000

[database]
connection =
timeout =

[timeouts]
default = 200
critical = 60
vm_state = 300

[tmpfs]
enabled = off
freespace = 2000

[cleaner]
enabled = no
binaries = 5
tmp = 5
analysis = 5
mongo = no
unused_files_in_mongodb = no

[another_section]
connection = PRIVATE_UNRELATED_PASSWORD
ip = 10.20.30.40
"""


class Step3Tests(unittest.TestCase):
    def setup_conf(self, directory, content=BEFORE):
        base = Path(directory) / "CAPE" / "conf"
        base.mkdir(parents=True)
        path = base / "cuckoo.conf"
        path.write_bytes(content)
        path.chmod(0o640)
        return path

    def test_all_22_exact_changes_with_external_database_dsn(self):
        new, changes = c.transform(BEFORE, DSN)
        self.assertEqual(c.EXPECTED_COUNT, 22)
        self.assertEqual(len(changes), 22)
        self.assertIn(b"[resultserver]\nip = 0.0.0.0\n", new)
        self.assertNotIn(b"ip = 192.168.122.1", new)
        self.assertIn(b"upload_max_size = 1000000000\n", new)
        self.assertIn(b"analysis_size_limit = 1000000000\n", new)
        self.assertIn(b"[cleaner]\nenabled = yes\nbinaries = 0\n"
                      b"tmp = 0\nanalysis = 0\n", new)
        self.assertNotIn(b"binaries_days", new)
        self.assertNotIn(b"tmp_days", new)
        self.assertNotIn(b"analysis_days", new)
        self.assertIn(b"[another_section]\nconnection = "
                      b"PRIVATE_UNRELATED_PASSWORD\nip = 10.20.30.40\n", new)
        self.assertIn(b"unrelated = CONTINUE\n", new)
        self.assertEqual(c.transform(new), (new, []))
        self.assertNotIn(DSN, str(changes))
        db_change = [x for x in changes
                     if (x["section"], x["key"]) == ("database", "connection")]
        self.assertEqual(db_change[0]["target"], "<private-local-postgresql-dsn>")

    def test_valid_existing_db_dsn_is_preserved_without_separate_secret(self):
        existing = BEFORE.replace(b"connection =\n",
                                  ("connection = " + DSN + "\n").encode())
        new, changes = c.transform(existing)
        self.assertIn(("connection = " + DSN + "\n").encode(), new)
        self.assertEqual(len(changes), 21)
        self.assertFalse(any(x["key"] == "connection" for x in changes))
        self.assertEqual(c.transform(new), (new, []))

    def test_file_and_sections_keep_line_endings_and_comments(self):
        original = BEFORE.replace(b"\n", b"\r\n")
        edited, changed = c.transform(original, DSN)
        self.assertEqual(len(changed), 22)
        self.assertEqual(edited.replace(b"\r\n", b"").count(b"\n"), 0)
        self.assertIn(b"[resultserver]\r\nip = 0.0.0.0\r\n", edited)
        self.assertEqual(c.transform(edited), (edited, []))

    def test_strict_cleanup_actual_keys_not_wrong_pdf_alias(self):
        for alias in ("binaries_days", "tmp_days", "analysis_days"):
            modified = BEFORE.replace(b"binaries = 5\n",
                        b"binaries = 5\n" + (alias + " = 5\n").encode())
            with self.subTest(alias=alias), self.assertRaisesRegex(
                    c.CuckooBlocked, "PDF-style"):
                c.transform(modified, DSN)
        for original, wrong in ((b"binaries = 5\n", b"binaries_days = 5\n"),
                                (b"tmp = 5\n", b"tmp_days = 5\n"),
                                (b"analysis = 5\n", b"analysis_days = 5\n")):
            with self.subTest(missing=original), self.assertRaises(c.CuckooBlocked):
                c.transform(BEFORE.replace(original, wrong), DSN)

    def test_missing_duplicate_or_malformed_target_never_guessed(self):
        bad_files = (
            BEFORE.replace(b"memory_dump = off\n", b""),
            BEFORE.replace(b"memory_dump = off\n",
                           b"memory_dump = off\nmemory_dump = on\n"),
            BEFORE.replace(b"[cleaner]", b"[not_cleaner]"),
            BEFORE + b"\n[resultserver]\nip = 0.0.0.0\n",
            BEFORE.replace(b"vm_state = 300\n", b"vm_state = maybe\n"),
            BEFORE.replace(b"store_csvs = off", b"store_csvs: off"),
        )
        for bad in bad_files:
            with self.subTest(bad=bad[-70:]), self.assertRaises(c.CuckooBlocked):
                c.transform(bad, DSN)

    def test_bad_or_placeholder_dsn_never_accepted_or_echoed(self):
        for bad in (
            "", "postgresql://cape:<DB_PASSWORD>@localhost:5432/cape",
            "postgresql://cape:fake@10.0.0.1:5432/cape",
            "postgresql://cape:fake@localhost:1234/cape",
            "postgresql://postgres:fake@localhost:5432/cape",
            "postgresql://cape:fake@localhost:5432/other",
            "postgresql://cape:fake@localhost:5432/cape\nPASSWORD",
            "file:///etc/shadow",
        ):
            with self.subTest(dsn=bad), self.assertRaises(c.CuckooBlocked):
                c.safe_dsn(bad)
        self.assertEqual(c.safe_dsn(DSN), DSN)
        self.assertNotIn(DSN, str(c.transform(BEFORE, DSN)[1]))

    def test_empty_db_connection_requires_separate_private_secret(self):
        with tempfile.TemporaryDirectory() as folder:
            config = self.setup_conf(folder)
            with self.assertRaisesRegex(c.CuckooBlocked, "connection|PostgreSQL"):
                c.plan(config)
            self.assertEqual(config.read_bytes(), BEFORE)
            # Root ownership is not available in unprivileged GitHub Actions.
            token = Path(folder) / "secret"
            token.write_text(DSN + "\n")
            token.chmod(0o600)
            with patch.object(c, "private_dsn_file", return_value=DSN):
                result = c.plan(config, token)
            self.assertEqual(result["targets"], 22)
            self.assertEqual(len(result["changes"]), 22)
            self.assertEqual(result["database_dsn_from"], "root_private_file")
            self.assertFalse(result["database_password_disclosed"])
            self.assertNotIn("FAKE_TEST_ONLY_PASSWORD", str(result))

    def test_private_dsn_rejects_symlinks_and_unprivileged_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            secret = Path(folder) / "dsn"
            secret.write_text(DSN + "\n")
            secret.chmod(0o644)
            with self.assertRaisesRegex(c.CuckooBlocked, "root-owned"):
                c.private_dsn_file(secret)
            link = Path(folder) / "dsn-link"
            link.symlink_to(secret)
            with self.assertRaisesRegex(c.CuckooBlocked, "Symlink"):
                c.private_dsn_file(link)
            secret.chmod(0o600)
            with patch.object(c.os, "fstat", return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1,
                    st_size=len((DSN + "\n").encode()))):
                self.assertEqual(c.private_dsn_file(secret), DSN)

    def test_plan_does_not_write_or_expose_database_secret(self):
        with tempfile.TemporaryDirectory() as folder:
            data = BEFORE.replace(b"connection =\n",
                ("connection = " + DSN + "\n").encode())
            conf = self.setup_conf(folder, data)
            with patch.object(c.os, "replace",
                              side_effect=AssertionError("No writes in plan")):
                output = c.plan(conf)
            self.assertEqual(conf.read_bytes(), data)
            self.assertFalse(output["host_modified"])
            self.assertFalse(output["service_restarted"])
            self.assertTrue(output["requires_trusted_firewall_before_service_restart"])
            self.assertNotIn("FAKE_TEST_ONLY_PASSWORD", str(output))

    def test_declined_approval_does_not_modify_host(self):
        with tempfile.TemporaryDirectory() as folder:
            conf = self.setup_conf(folder, BEFORE.replace(
                b"connection =\n", ("connection = " + DSN + "\n").encode()))
            backups = Path(folder) / "backup"
            before = conf.read_bytes()
            with patch.object(c.os, "geteuid", return_value=0), \
                 patch.object(c.sys.stdin, "isatty", return_value=True), \
                 patch("builtins.input", return_value="DECLINE"), \
                 self.assertRaisesRegex(c.CuckooBlocked, "declined"):
                c.apply(conf, backups)
            self.assertEqual(conf.read_bytes(), before)
            self.assertFalse(backups.exists())

    def test_atomic_apply_private_backup_readback_and_repeat_noop(self):
        with tempfile.TemporaryDirectory() as folder:
            initial = BEFORE.replace(
                b"connection =\n", ("connection = " + DSN + "\n").encode())
            conf = self.setup_conf(folder, initial)
            backups = Path(folder) / "backups"
            source_mode = stat.S_IMODE(conf.stat().st_mode)
            def fake_backup_dir(path):
                Path(path).mkdir(mode=0o700)
                return Path(path)
            with patch.object(c.os, "geteuid", return_value=0), \
                 patch.object(c.sys.stdin, "isatty", return_value=True), \
                 patch.object(c.guard, "safe_backup_dir",
                              side_effect=fake_backup_dir), \
                 patch("builtins.input", return_value=c.APPROVAL):
                output = c.apply(conf, backups)
            self.assertTrue(output["applied"])
            self.assertFalse(output["service_restarted"])
            self.assertFalse(output["postgresql_connection_or_network_runtime_verified"])
            self.assertEqual(stat.S_IMODE(conf.stat().st_mode), source_mode)
            self.assertEqual(c.transform(conf.read_bytes())[1], [])
            self.assertNotIn("FAKE_TEST_ONLY_PASSWORD", str(output))
            backup = Path(output["backup_path"])
            self.assertEqual(backup.read_bytes(), initial)
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(backups.stat().st_mode), 0o700)
            with patch.object(c.os, "geteuid", return_value=0), \
                 patch.object(c.sys.stdin, "isatty", return_value=True), \
                 patch("builtins.input",
                       side_effect=AssertionError("No prompt on second run")):
                again = c.apply(conf, backups)
            self.assertFalse(again["applied"])
            self.assertFalse(again["backup_created"])
            self.assertEqual(len(list(backups.iterdir())), 1)

    def test_change_after_operator_approval_blocks_before_backup(self):
        with tempfile.TemporaryDirectory() as folder:
            initial = BEFORE.replace(
                b"connection =\n", ("connection = " + DSN + "\n").encode())
            conf = self.setup_conf(folder, initial)
            backups = Path(folder) / "backups"
            def modify(_prompt):
                conf.write_bytes(initial.replace(b"unrelated = CONTINUE",
                                                 b"unrelated = changed"))
                return c.APPROVAL
            with patch.object(c.os, "geteuid", return_value=0), \
                 patch.object(c.sys.stdin, "isatty", return_value=True), \
                 patch("builtins.input", side_effect=modify), \
                 self.assertRaisesRegex(c.CuckooBlocked, "changed"):
                c.apply(conf, backups)
            self.assertFalse(backups.exists())
            self.assertIn(b"unrelated = changed", conf.read_bytes())


if __name__ == "__main__":
    unittest.main()
