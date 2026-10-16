"""Synthetic tests for intentionally CI-only native wheel debug normalization."""
from __future__ import annotations

import base64
import csv
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
import zipfile

import ci_normalize_python_tlsh_wheel as normalizer


class NativeWheelNormalizationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="tlsh-wheel-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.left = self.root / "cape-built-wheels"
        self.right = self.root / "cape-replayed-wheels"
        self.left.mkdir()
        self.right.mkdir()
        self.allowed = frozenset((str(self.left), str(self.right)))
        for parent in (self.left, self.right):
            self.create_test_wheel(parent / normalizer.WHEEL)

    def create_test_wheel(self, target, malformed_so=False):
        ext = (b"not a shared object" if malformed_so
               else b"\x7fELF" + b"A" * 40000)
        blobs = {
            normalizer.SO: ext,
            "python_tlsh-4.5.0.dist-info/METADATA": b"Name: python-tlsh\n",
            "python_tlsh-4.5.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
            "python_tlsh-4.5.0.dist-info/top_level.txt": b"tlsh\n",
        }
        rows = [
            [
                name,
                "sha256="+base64.urlsafe_b64encode(
                    hashlib.sha256(raw).digest()).decode().rstrip("="),
                str(len(raw)),
            ] for name, raw in blobs.items()
        ]
        rows.append([normalizer.RECORD, "", ""])
        stream = StringIO(newline="")
        csv.writer(stream, lineterminator="\n").writerows(rows)
        blobs[normalizer.RECORD] = stream.getvalue().encode()
        with zipfile.ZipFile(target,"w") as out:
            for name, payload in blobs.items():
                out.writestr(name, payload, compress_type=zipfile.ZIP_DEFLATED)

    def fake_objcopy(self, args, **kwargs):
        self.assertEqual(
            args[1:3],
            ["--strip-debug", "--remove-section=.note.gnu.build-id"]
        )
        Path(args[-1]).write_bytes(b"\x7fELF" + b"B" * 30000)
        return SimpleNamespace(returncode=0, stderr=b"", stdout=b"")

    def test_unapproved_host_can_never_modify_wheel(self):
        wheel = self.left / normalizer.WHEEL
        before = wheel.read_bytes()
        with mock.patch.dict(os.environ,{"GITHUB_ACTIONS":""}):
            with self.assertRaisesRegex(
                    normalizer.NormalizationBlocked, "outside disposable CI"):
                normalizer.normalize(wheel)
        self.assertEqual(wheel.read_bytes(), before)

    def test_refuses_wrong_package_identity_even_inside_ci(self):
        candidate = self.left / "different-4.5.0.whl"
        candidate.write_bytes(b"not a real package")
        with mock.patch.dict(os.environ,{"GITHUB_ACTIONS":"true"}), \
             mock.patch.object(normalizer,"ALLOWED_CI_DIRECTORIES",self.allowed):
            with self.assertRaisesRegex(
                    normalizer.NormalizationBlocked,"Only two ephemeral"):
                normalizer.normalize(candidate)

    def test_two_source_archives_reproducible_after_synthetic_strip(self):
        with mock.patch.dict(os.environ,{"GITHUB_ACTIONS":"true"}), \
             mock.patch.object(normalizer,"ALLOWED_CI_DIRECTORIES",self.allowed), \
             mock.patch.object(normalizer.subprocess,"run",
                               side_effect=self.fake_objcopy):
            result = normalizer.main([
                str(self.left/normalizer.WHEEL),
                str(self.right/normalizer.WHEEL),
            ])
        self.assertEqual(result,0)
        a=(self.left/normalizer.WHEEL).read_bytes()
        b=(self.right/normalizer.WHEEL).read_bytes()
        self.assertEqual(a,b)
        with zipfile.ZipFile(self.left/normalizer.WHEEL) as wheel:
            self.assertIsNone(wheel.testzip())
            expected_so=b"\x7fELF"+b"B"*30000
            self.assertEqual(wheel.read(normalizer.SO),expected_so)
            record=list(csv.reader(StringIO(wheel.read(
                normalizer.RECORD).decode())))
            match=[r for r in record if r[0]==normalizer.SO]
            self.assertEqual(len(match),1)
            self.assertEqual(match[0][2],str(len(expected_so)))
            expected="sha256="+base64.urlsafe_b64encode(
                hashlib.sha256(expected_so).digest()).decode().rstrip("=")
            self.assertEqual(match[0][1],expected)

    def test_invalid_source_elf_fails_closed_without_running_objcopy(self):
        wheel=self.left/normalizer.WHEEL
        self.create_test_wheel(wheel,malformed_so=True)
        with mock.patch.dict(os.environ,{"GITHUB_ACTIONS":"true"}), \
             mock.patch.object(normalizer,"ALLOWED_CI_DIRECTORIES",self.allowed), \
             mock.patch.object(normalizer.subprocess,"run") as child:
            with self.assertRaisesRegex(
                    normalizer.NormalizationBlocked, "reviewed ELF shape"):
                normalizer.normalize(wheel)
        child.assert_not_called()

    def test_subprocess_failure_preserves_original(self):
        wheel=self.left/normalizer.WHEEL
        before=wheel.read_bytes()
        with mock.patch.dict(os.environ,{"GITHUB_ACTIONS":"true"}), \
             mock.patch.object(normalizer,"ALLOWED_CI_DIRECTORIES",self.allowed), \
             mock.patch.object(normalizer.subprocess,"run",
                 return_value=SimpleNamespace(returncode=4,stderr=b"bad")):
            with self.assertRaisesRegex(
                    normalizer.NormalizationBlocked,
                    "objcopy rejected"):
                normalizer.normalize(wheel)
        self.assertEqual(wheel.read_bytes(),before)


if __name__ == "__main__":
    unittest.main()
