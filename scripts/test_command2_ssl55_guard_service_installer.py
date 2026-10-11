"""Offline root-only CAPE service installer tests; all host I/O mocked."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import command2_ssl55_guard_service_installer as m


def template():
    return {
        "result":"SSL55_CAPE_ONLY_SERVICE_INSTALL_PLAN",
        "libvirt_service":"libvirtd.service",
        "unit_text":"[Unit]\nDescription=Test CAPE service\n[Service]\nType=oneshot\n",
        "unit_sha256":"a"*64,
        "original_guard_sha256":m.replay.POLICY_SHA256,
        "expected_sources":{},
        "approval_path":str(m.AUTH_FILE),
        "install_dir":str(m.INSTALL_DIR),
        "base_nftables_service_touched":False,
        "nft_rules_modified":False,
        "analysis_network_started":False,
        "guest_changed":False,"systemd_unit_installed":False,
        "systemd_unit_enabled":False,"reboot_persistence_verified":False,
        "production_network_approved":False,"host_modified":False,
    }


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self._td=tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.temp=Path(self._td.name)

    def test_git_blob_pins_original_dependency_sources(self):
        root=Path(__file__).parent
        for name, expected in m.SOURCE_BLOBS.items():
            with self.subTest(name=name):
                self.assertEqual(m.git_blob((root/name).read_bytes()),expected)

    def test_stage_source_integrity_and_python_parse(self):
        stage=self.temp/"sources"
        stage.mkdir()
        root=Path(__file__).parent
        for name in m.SOURCE_BLOBS:
            (stage/name).write_bytes((root/name).read_bytes())
        self.assertEqual(len(m.inspect_sources(stage)),len(m.SOURCE_BLOBS))
        with (stage/"dryrun_cape_lab_guard_nft.py").open("ab") as outfile:
            outfile.write(b"\n# changed")
        with self.assertRaisesRegex(m.InstallerBlocked,"SHA mismatch"):
            m.inspect_sources(stage)

    def test_development_deps_cannot_be_overwritten_on_host(self):
        with patch.object(m,"INSTALL_DIR",self.temp):
            with self.assertRaisesRegex(m.InstallerBlocked,"refuse overwrite"):
                m.no_existing_installation()

    def test_libvirt_active_unit_selection_exact_one(self):
        def stat_request(*args):
            unit=args[-1]
            if unit=="libvirtd.service":
                return "LoadState=loaded\nUnitFileState=enabled\nActiveState=active"
            return "LoadState=not-found\nUnitFileState=\nActiveState=inactive"
        with patch.object(m.boot,"read",side_effect=stat_request):
            selection,status=m.service_observations()
        self.assertEqual(selection,"libvirtd.service")
        self.assertEqual(status["virtqemud.service"]["load_state"],"not-found")

    def test_multiple_active_libvirt_backends_block_install(self):
        with patch.object(m.boot,"read",return_value=(
            "LoadState=loaded\nUnitFileState=enabled\nActiveState=active")):
            with self.assertRaisesRegex(m.InstallerBlocked,"exactly one"):
                m.service_observations()

    def test_no_current_guard_or_unapproved_host_blocks_plan(self):
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m.replay,"plan",return_value={
                 "existing_guard_state":"missing"}):
            with self.assertRaisesRegex(m.InstallerBlocked,"not present"):
                m.plan(self.temp)

    def test_plan_reads_sources_and_existing_guard_without_changes(self):
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m.replay,"plan",return_value={
                 "existing_guard_state":"present_verified"}),\
             patch.object(m.boot,"perform",return_value={
                 "analysis_network_and_clones_autostart_disabled":True,
                 "safe_to_attach_win11_1_nic":False,
                 "service_show_observations":{
                     "nftables.service":{"unit_file_state":"disabled"},
                     "cape-analysis-guard.service":{"load_state":"not-found"}}}),\
             patch.object(m,"inspect_sources",return_value={
                 "dryrun_cape_lab_guard_nft.py":b"benign synthetic"}),\
             patch.object(m,"service_observations",return_value=(
                 "libvirtd.service",{})),\
             patch.object(m,"no_existing_installation"),\
             patch.object(m,"command",side_effect=AssertionError("No write")):
            out=m.plan(self.temp)
        self.assertFalse(out["host_modified"])
        self.assertFalse(out["systemd_unit_enabled"])
        self.assertEqual(out["libvirt_service"],"libvirtd.service")

    def test_no_interactive_stdin_and_no_approved_plan_refuses_install(self):
        with patch.object(m.sys.stdin,"isatty",return_value=False),\
             patch.object(m,"command",side_effect=AssertionError("No write")):
            with self.assertRaisesRegex(m.InstallerBlocked,"interactive"):
                m.apply(self.temp,"a"*64)
        with patch.object(m.sys.stdin,"isatty",return_value=True),\
             patch.object(m,"command",side_effect=AssertionError("No write")):
            with self.assertRaisesRegex(m.InstallerBlocked,"checksum"):
                m.apply(self.temp,"not-a-sha")

    def test_hash_mismatch_cannot_create_service(self):
        with patch.object(m.sys.stdin,"isatty",return_value=True),\
             patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m,"plan",return_value=template()),\
             patch.object(m,"command",side_effect=AssertionError("No write")):
            with self.assertRaisesRegex(m.InstallerBlocked,"STALE"):
                m.apply(self.temp,"0"*64)

    def test_install_changes_only_service_and_root_owned_files(self):
        base=template()
        encoded=json.dumps(base,sort_keys=True,separators=(",",":")).encode()
        import hashlib
        plan_sha=hashlib.sha256(encoded).hexdigest()
        writes=[]
        root=self.temp
        source={"command2_ssl55_guard_scoped_replay.py":b"mock-only"}
        lock=self.temp/"installer.lock"
        lckmeta=type("LockStat",(),{"st_mode":stat.S_IFREG|0o600,
                                   "st_uid":0,"st_nlink":1})()
        def only_systemd(*cmd,**kw):
            writes.append(cmd)
            if cmd[:2] not in (("systemctl","daemon-reload"),
                               ("systemctl","enable")):
                raise AssertionError("Unexpected mutation: "+str(cmd))
            return ""
        with patch.object(m,"INSTALL_DIR",root/"bin"),\
             patch.object(m,"AUTH_DIR",root/"etc"),\
             patch.object(m,"AUTH_FILE",root/"etc"/"approved.json"),\
             patch.object(m,"UNIT_FILE",root/"guard.service"),\
             patch.object(m,"LOCK",lock),\
             patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m.sys.stdin,"isatty",return_value=True),\
             patch.object(m.os,"fstat",return_value=lckmeta),\
             patch.object(m,"plan",return_value=base),\
             patch.object(m,"inspect_sources",return_value=source),\
             patch.object(m,"verify_after",return_value={"load_state":"loaded"}),\
             patch.object(m,"command",side_effect=only_systemd),\
             patch("builtins.input",return_value=m.AUTH_PHRASE):
            out=m.apply(root,plan_sha)
        self.assertEqual(out["result"],
                         "SSL55_CAPE_ONLY_GUARD_UNIT_INSTALLED_ENABLED_NOT_STARTED")
        self.assertFalse(out["reboot_persistence_verified"])
        self.assertEqual(writes,[("systemctl","daemon-reload"),
                                 ("systemctl","enable","cape-analysis-guard.service")])
        self.assertTrue((root/"bin"/"command2_ssl55_guard_scoped_replay.py").is_file())
        self.assertTrue((root/"etc"/"approved.json").is_file())
        self.assertTrue((root/"guard.service").is_file())
        self.assertEqual(stat.S_IMODE((root/"etc"/"approved.json").stat().st_mode),0o600)

    def test_no_unsafe_global_host_firewall_action_in_source(self):
        code=Path(m.__file__).read_text()
        impl=code[code.index("from __future__ import annotations"):]
        for bad in ('"net-start"', '"attach-interface"',
                    '"snapshot-create-as"','"systemctl","restart"',
                    '"systemctl","enable","nftables.service"',
                    '"nft","flush"', '"nft","--file"',
                    'virsh("start"'):
            self.assertNotIn(bad,impl)


if __name__=="__main__":
    unittest.main()
