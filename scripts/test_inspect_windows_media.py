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

    def test_iso_extension_is_not_authenticated(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"install.iso"
            p.write_bytes(b"random data")
            data=m.inspect(p)
            self.assertIn("extension only", data["header_format"])
            self.assertEqual(data["trust_status"], "UNVERIFIED")

    def test_empty_file_rejected(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"file.7z"
            p.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "empty"):
                m.inspect(p)

if __name__ == "__main__":
    main()
