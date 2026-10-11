"""Offline mocked checks for the user-only rclone uploader."""
from pathlib import Path
import os
import subprocess
import tempfile
import time
import unittest

UPLOADER = Path(__file__).with_name("command2_upload_approved_reports.sh")
SETUP = Path(__file__).with_name("command2_setup_auto_report_sync.sh")


class ReportSyncTests(unittest.TestCase):
    def test_shell_syntax(self):
        for s in (UPLOADER, SETUP):
            result = subprocess.run(("bash", "-n", str(s)),
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_setup_requires_controlling_tty_even_with_heredoc_stdin(self):
        # Installer can be launched through a reviewed heredoc wrapper.
        # stdin is then NOT a TTY. Opt-in must read /dev/tty explicitly.
        script = SETUP.read_text(encoding="utf-8")
        self.assertIn("ACK </dev/tty", script)
        self.assertIn("-r /dev/tty && -w /dev/tty", script)
        self.assertIn("ENABLE-CAPE-AUTO-REPORTS", script)
        self.assertNotIn("[[ -t 0 ]]", script)
        self.assertIn("id -u", script)
        self.assertNotIn("sudo ", script)

    def test_user_only_no_vm_or_unapproved_copy(self):
        text = UPLOADER.read_text(encoding="utf-8")
        self.assertIn("CAPE_SSL55_AutoReports", text)
        self.assertIn("CAPE_Command2_OfflinePreflightTests_", text)
        self.assertIn("--immutable", text)
        self.assertIn("OwnerAuth", text)
        self.assertNotIn("sudo ", text)
        for bad in ("virsh ", "qemu-img ", "nft ", "rclone sync",
                    "rclone delete", "rm -rf", "systemctl"):
            self.assertNotIn(bad, text)

    def test_mock_upload_only_whitelist_and_skip_secrets_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            input_dir = home / "CAPE_Approved_Reports"
            input_dir.mkdir(mode=0o700)
            bin_dir = home / "bin"
            bin_dir.mkdir()
            log = home / "remote.log"
            shim = bin_dir / "rclone"
            shim.write_text("""#!/bin/sh
if [ "$1" = listremotes ]; then
    echo "cape_reports:"
elif [ "$1" = copyto ]; then
    printf "%s\\n" "$2 -> $3" >> "$FAKE_RCLONE_LOG"
else
    exit 9
fi
""")
            shim.chmod(0o700)
            valid = input_dir / "CAPE_Command2_OfflinePreflightTests_20261011_103641_ZnSj1eKa.txt"
            valid.write_text("PASS: approved synthetic test\\n")
            secret = input_dir / "CAPE_Command2_OfflinePreflightTests_20261011_103642_AaBbCcDd.txt"
            secret.write_text("OwnerAuth: do-not-upload\\n")
            other = input_dir / "secret-malware-contents.txt"
            other.write_text("unsafe generic file")
            symlink = input_dir / "CAPE_Command2_OfflinePreflightTests_20261011_103643_AaBbCcDd.txt"
            symlink.symlink_to(other)
            now = time.time() - 180
            os.utime(valid, (now, now))
            os.utime(secret, (now, now))
            env = dict(os.environ, HOME=str(home),
                       PATH=str(bin_dir)+os.pathsep+os.environ.get("PATH", ""),
                       FAKE_RCLONE_LOG=str(log))
            result = subprocess.run(("bash", str(UPLOADER)), env=env,
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)  # secret rejected
            sent = log.read_text()
            self.assertIn(valid.name, sent)
            self.assertNotIn(secret.name, sent)
            self.assertNotIn(other.name, sent)
            self.assertNotIn(symlink.name, sent)
            self.assertIn("cape_reports:CAPE_SSL55_AutoReports", sent)

    def test_missing_remote_fails_without_any_attempted_upload(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home/"CAPE_Approved_Reports").mkdir(mode=0o700)
            shimdir = home/"bin"; shimdir.mkdir()
            shim = shimdir/"rclone"
            shim.write_text("#!/bin/sh\nexit 1\n")
            shim.chmod(0o700)
            env = dict(os.environ,HOME=str(home),
                       PATH=str(shimdir)+os.pathsep+os.environ.get("PATH", ""))
            result = subprocess.run(("bash",str(UPLOADER)),env=env,
                                    capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn("BLOCKED:",result.stdout+result.stderr)


if __name__=="__main__":
    unittest.main()
