#!/usr/bin/env python3
"""Offline tests for local Windows media hashing. No real media or extraction."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
import hashlib

import inspect_windows_media as m


class InspectWindowsMediaTests(TestCase):
    def test_detects_7z_magic_and_hash(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"candidate.7z"
            contents=b"7z\xbc\xaf\x27\x1c"+b"offline fixture"
            p.write_bytes(contents)
            result=m.inspect(p)
            self.assertEqual(result["header_format"], "7z archive")
            self.assertEqual(result["sha256"], hashlib.sha256(contents).hexdigest())
            self.assertEqual(result["trust_status"], "UNVERIFIED")
            self.assertFalse(result["archive_extracted"])

    def test_detects_zip(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"candidate.zip"
            p.write_bytes(b"PK\x03\x04fixture")
            self.assertEqual(m.inspect(p)["header_format"], "ZIP archive")

    def test_partial_download_rejected(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"file.7z.crdownload"
            p.write_bytes(b"123")
            with self.assertRaisesRegex(ValueError, "incomplete"):
                m.inspect(p)

    def test_symbolic_link_rejected(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"source.7z"
            p.write_bytes(b"data")
            link=Path(d)/"link.7z"
            link.symlink_to(p)
            with self.assertRaisesRegex(ValueError, "symlink"):
                m.inspect(link)

    def test_detects_iso9660_cd001_descriptor(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "Win11.iso"
            payload = bytearray(16 * 2048 + 6)
            payload[16 * 2048 + 1:16 * 2048 + 6] = b"CD001"
            p.write_bytes(payload)
            data = m.inspect(p)
            self.assertTrue(data["iso9660_pvd_detected"])
            self.assertIn("descriptor detected", data["header_format"])
            self.assertEqual(data["trust_status"], "UNVERIFIED")
            self.assertFalse(data["iso_boot_tested"])

    def test_iso_extension_is_not_authenticated(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"install.iso"
            p.write_bytes(b"random data")
            data=m.inspect(p)
            self.assertIn("extension only", data["header_format"])
            self.assertEqual(data["trust_status"], "UNVERIFIED")

    def test_official_expected_digest_matches_when_supplied(self):
        import json
        from unittest.mock import patch
        with TemporaryDirectory() as d:
            image = Path(d) / "Win11.iso"
            image.write_bytes(b"fixture")
            report = Path(d) / "verify.json"
            sha = hashlib.sha256(b"fixture").hexdigest()
            with patch("sys.argv", ["inspector", str(image),
                                     "--expected-sha256", sha, "--report", str(report)]):
                self.assertEqual(m.main(), 0)
            data = json.loads(report.read_text())
            self.assertTrue(data["matches_expected_sha256"])
            self.assertEqual(data["trust_status"], "MATCHES_SUPPLIED_EXPECTED_DIGEST")

    def test_mismatched_digest_exits_nonzero(self):
        import json
        from unittest.mock import patch
        with TemporaryDirectory() as d:
            image = Path(d) / "Win11.iso"
            image.write_bytes(b"fixture")
            report = Path(d) / "verify.json"
            with patch("sys.argv", ["inspector", str(image),
                                     "--expected-sha256", "0" * 64,
                                     "--report", str(report)]):
                self.assertEqual(m.main(), 2)
            data = json.loads(report.read_text())
            self.assertFalse(data["matches_expected_sha256"])
            self.assertEqual(data["trust_status"], "MISMATCH_SUPPLIED_EXPECTED_DIGEST")

    def test_empty_file_rejected(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"file.7z"
            p.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "empty"):
                m.inspect(p)

if __name__ == "__main__":
    main()
