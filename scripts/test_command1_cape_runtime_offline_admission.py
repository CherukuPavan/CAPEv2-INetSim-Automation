"""Synthetic offline CAPE wheelhouse admission tests; no network or host writes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

import command1_cape_runtime_offline_admission as subject


class WheelAdmissionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="cape-wheel-safe-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.wheels = self.root / "wheels"
        self.wheels.mkdir()
        self.manifest = self.root / "manifest.json"
        self.lock = self.root / "dependencies.lock"
        self.packages = {
            "gevent": ("24.2.1", "gevent-24.2.1-py3-none-any.whl"),
            "greenlet": ("3.0.3", "greenlet-3.0.3-py3-none-any.whl"),
        }
        self.rebuild()

    def rebuild(self):
        metadata = {}
        for name, (version, filename) in self.packages.items():
            path = self.wheels / filename
            if not path.exists():
                with zipfile.ZipFile(path, "w") as output:
                    output.writestr(
                        name+"-"+version+".dist-info/METADATA",
                        "Name: "+name+"\nVersion: "+version+"\n")
                    output.writestr(name+"/__init__.py", "OK=True\n")
            b = path.read_bytes()
            metadata[name] = {
                "wheel": filename,
                "version": version,
                "size": len(b),
                "sha256": hashlib.sha256(b).hexdigest()
            }
        data = "".join(
            k+"=="+v["version"]+" --hash=sha256:"+v["sha256"]+"\n"
            for k,v in sorted(metadata.items()))
        self.lock.write_text(data)
        payload = {
            "source_commit": "a"*40,
            "python_version": "3.12.12",
            "uv_build_version": "0.9.15",
            "platform": "ubuntu-26.04-amd64",
            "wheel_count": len(metadata),
            "total_wheel_bytes": sum(v["size"] for v in metadata.values()),
            "lock_sha256": hashlib.sha256(self.lock.read_bytes()).hexdigest(),
            "wheels": metadata,
            "not_an_approved_host_installer": True
        }
        self.manifest.write_text(json.dumps(payload, sort_keys=True))
        self.hash = hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    def check(self):
        return subject.plan(
            self.manifest, self.lock, self.wheels,
            self.hash, min_count=2
        )

    def test_positive_two_wheel_synthetic_lock(self):
        result = self.check()
        self.assertEqual(result["packages_verified"],2)
        self.assertEqual(result["approved_manifest_sha256"],self.hash)
        self.assertFalse(result["host_modified"])
        self.assertFalse(result["production_installation_executed"])

    def test_reject_unreviewed_manifest_sha(self):
        with self.assertRaisesRegex(
                subject.AdmissionBlocked, "externally approved"):
            subject.plan(self.manifest,self.lock,self.wheels,
                         "b"*64,min_count=2)

    def test_reject_wheel_digest_or_length_drift(self):
        file = self.wheels / self.packages["gevent"][1]
        file.write_bytes(file.read_bytes()+b"changed")
        with self.assertRaisesRegex(subject.AdmissionBlocked, "mismatch"):
            self.check()

    def test_reject_unexpected_wheel_or_missing_wheel(self):
        extra=self.wheels/"untracked.whl"
        extra.write_bytes(b"foreign")
        with self.assertRaisesRegex(subject.AdmissionBlocked,
                                    "Unexpected files"):
            self.check()
        extra.unlink()
        (self.wheels/self.packages["gevent"][1]).unlink()
        with self.assertRaisesRegex(subject.AdmissionBlocked,
                                    "Unexpected files"):
            self.check()

    def test_reject_manifest_and_lock_inconsistency(self):
        self.lock.write_bytes(self.lock.read_bytes()+b"\n")
        with self.assertRaisesRegex(subject.AdmissionBlocked,
                                    "Dependency hash lock"):
            self.check()

    def test_reject_sha_approved_but_semantically_wrong_arch(self):
        item=json.loads(self.manifest.read_text())
        item["platform"]="ubuntu-24.04-amd64"
        self.manifest.write_text(json.dumps(item))
        self.hash=hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with self.assertRaisesRegex(subject.AdmissionBlocked,
                                    "Unexpected runtime provenance"):
            self.check()

    def test_reject_wheel_symlink_alias_even_with_exact_content(self):
        target=self.wheels/self.packages["gevent"][1]
        data=target.read_bytes()
        target.unlink()
        original=self.root/"external-wheel"
        original.write_bytes(data)
        target.symlink_to(original)
        with self.assertRaisesRegex(subject.AdmissionBlocked, "symlink"):
            self.check()

    def test_reject_zip_path_traversal_even_if_attested(self):
        p=self.wheels/self.packages["gevent"][1]
        p.unlink()
        with zipfile.ZipFile(p,"w") as artifact:
            artifact.writestr("../outside.py","bad")
        self.rebuild()
        with self.assertRaisesRegex(subject.AdmissionBlocked,
                                    "Untrusted wheel ZIP member"):
            self.check()

    def test_cannot_review_unsafe_absolute_and_relative_file_paths(self):
        with self.assertRaisesRegex(subject.AdmissionBlocked,"Untrusted path"):
            subject.plan(Path("manifest.json"), self.lock, self.wheels,
                         self.hash,min_count=2)

    def test_requires_real_project_wheel_count_in_default_mode(self):
        with self.assertRaisesRegex(subject.AdmissionBlocked, "Wrong package"):
            subject.plan(self.manifest,self.lock,self.wheels,self.hash)


if __name__=="__main__":
    unittest.main()
