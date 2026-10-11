"""Synthetic atomic candidate-reservation journal tests: temp dirs only."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_portable_fresh_count_plan as count
import command2_guest_identity_blueprint as identity
import command2_identity_reservation_journal as journal


def sample(n=2):
    raw=count.plan_fresh(n,disk_dir="/var/lib/libvirt/images/analysis",
          nvram_dir="/var/lib/libvirt/qemu/nvram",
          analysis_subnet="192.168.240.0/24",
          free_gib=2048,existing_domains=("win11",))
    preflight={"result":"COMMAND2_READ_ONLY_TARGET_HOST_PREFLIGHT",
               "preflight_pass":True,"ssl55_new_vm_prohibited":False,
               "host_modified":False,"deploy_authorized":False,
               "analysis_subnet":"192.168.240.0/24",
               "requested_vm_count":n, "planned_vms":raw["planned_vms"]}
    return identity.blueprint(preflight)


class JournalTests(unittest.TestCase):
    def test_atomic_record_and_exact_replay(self):
        blueprint=sample()
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/"reservations"
            folder.mkdir(mode=0o700)
            with patch.object(journal.socket,"gethostname",return_value="approved-test-host"):
                first=journal.reserve(blueprint,folder,expected_host="approved-test-host")
                second=journal.reserve(blueprint,folder,expected_host="approved-test-host")
            self.assertFalse(first["reused"])
            self.assertTrue(second["reused"])
            self.assertEqual(first["sha256"],second["sha256"])
            self.assertEqual(list(folder.glob("command2-identity-reservation.json")).__len__(),1)
            self.assertFalse(list(folder.glob(".command2-identity-pending-*")))
            stored=json.loads((folder/journal.RECORD_NAME).read_text())
            self.assertEqual(stored["guest_count"],2)
            self.assertFalse(stored["libvirt_domains_created"])
            self.assertFalse(stored["host_network_modified"])
            self.assertEqual((folder/journal.RECORD_NAME).stat().st_mode & 0o777,0o600)

    def test_conflicting_blueprint_never_overwrites(self):
        blueprint=sample()
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/"reserved"
            folder.mkdir(mode=0o700)
            with patch.object(journal.socket,"gethostname",return_value="approved-test-host"):
                journal.reserve(blueprint,folder,expected_host="approved-test-host")
                before=(folder/journal.RECORD_NAME).read_bytes()
                with self.assertRaisesRegex(journal.ReservationBlocked,"conflict"):
                    journal.reserve(sample(),folder,expected_host="approved-test-host")
            self.assertEqual(before,(folder/journal.RECORD_NAME).read_bytes())

    def test_reference_host_rejects_before_touching_disk(self):
        blueprint=sample(1)
        with tempfile.TemporaryDirectory() as td:
            private=Path(td)/"not-created"
            with patch.object(journal.socket,"gethostname",return_value="CSE-SSL-55.university"):
                with self.assertRaisesRegex(journal.ReservationBlocked,"SSL55_REFERENCE_ONLY"):
                    journal.reserve(blueprint,private,expected_host="cse-ssl-55")
            self.assertFalse(private.exists())

    def test_wrong_host_and_symlink_directory_refused(self):
        bp=sample(1)
        with tempfile.TemporaryDirectory() as td:
            real=Path(td)/"real";real.mkdir(mode=0o700)
            link=Path(td)/"linked";link.symlink_to(real)
            with patch.object(journal.socket,"gethostname",return_value="test-server"):
                with self.assertRaisesRegex(journal.ReservationBlocked,"Wrong target host"):
                    journal.reserve(bp,real,expected_host="other-host")
                with self.assertRaisesRegex(journal.ReservationBlocked,"Private directory"):
                    journal.reserve(bp,link,expected_host="test-server")
            self.assertFalse((real/journal.RECORD_NAME).exists())

    def test_world_accessible_directory_refused(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/"open"
            folder.mkdir(mode=0o755)
            with patch.object(journal.socket,"gethostname",return_value="safe-server"):
                with self.assertRaisesRegex(journal.ReservationBlocked,"0700"):
                    journal.reserve(sample(1),folder,expected_host="safe-server")
            self.assertFalse((folder/journal.LOCK_NAME).exists())

    def test_pending_file_blocks_restart_without_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/"private";folder.mkdir(mode=0o700)
            pending=folder/(journal.PENDING_PREFIX+"crashed")
            pending.write_text("incomplete")
            with patch.object(journal.socket,"gethostname",return_value="safe-server"):
                with self.assertRaisesRegex(journal.ReservationBlocked,"Incomplete"):
                    journal.reserve(sample(1),folder,expected_host="safe-server")
            self.assertEqual(pending.read_text(),"incomplete")
            self.assertFalse((folder/journal.RECORD_NAME).exists())

    def test_symlinked_lock_or_record_refused(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/"private";folder.mkdir(mode=0o700)
            target=folder/"target";target.write_text("preserve")
            lock=folder/journal.LOCK_NAME
            lock.symlink_to(target)
            with patch.object(journal.socket,"gethostname",return_value="test-server"):
                with self.assertRaises(OSError):
                    journal.reserve(sample(1),folder,expected_host="test-server")
            lock.unlink()
            (folder/journal.RECORD_NAME).symlink_to(target)
            with patch.object(journal.socket,"gethostname",return_value="test-server"):
                with self.assertRaises(OSError):
                    journal.reserve(sample(1),folder,expected_host="test-server")
            self.assertEqual(target.read_text(),"preserve")

    def test_malformed_blueprint_never_persists(self):
        bp=sample(2)
        bp["candidates"][1]["disk_target"]=bp["candidates"][0]["disk_target"]
        with tempfile.TemporaryDirectory() as td:
            private=Path(td)/"private";private.mkdir(mode=0o700)
            with patch.object(journal.socket,"gethostname",return_value="test-server"):
                with self.assertRaisesRegex(journal.ReservationBlocked,"colliding"):
                    journal.reserve(bp,private,expected_host="test-server")
            self.assertFalse((private/journal.RECORD_NAME).exists())

    def test_module_has_no_vm_or_network_mutation_primitives(self):
        source=Path(journal.__file__).read_text()
        self.assertNotIn("subprocess",source)
        for forbidden in ("virsh start","virsh define","nft flush","qemu-img convert",
                          "libvirt.open","socket.connect(","os.system(","rclone "):
            self.assertNotIn(forbidden,source)
        self.assertIn('"libvirt_domains_created": False',source)


if __name__=="__main__":
    unittest.main()
