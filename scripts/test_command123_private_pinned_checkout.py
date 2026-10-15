"""Offline trust-boundary regressions for private pinned checkout."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError

import command123_private_pinned_checkout as c


REV = "a" * 40
TREE = "b" * 40
SOURCE = {
    "README.md": b"hello\n",
    "scripts/deploy.sh": b"#!/bin/sh\nexit 0\n",
}


def entries():
    return {k: (c.git_hash(v), len(v),
                "100755" if k.endswith(".sh") else "100644")
            for k, v in SOURCE.items()}


def build_tar(members=None):
    buf = io.BytesIO()
    root = "CherukuPavan-CAPEv2-INetSim-Automation-" + REV
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        parent = tarfile.TarInfo(root)
        parent.type = tarfile.DIRTYPE
        tar.addfile(parent)
        for name, data in (members or SOURCE).items():
            file = tarfile.TarInfo(root + "/" + name)
            file.size = len(data)
            tar.addfile(file, io.BytesIO(data))
    return buf.getvalue()


class CheckoutTests(unittest.TestCase):
    def test_git_object_hash(self):
        data = b"test content\n"
        expected = hashlib.sha1(b"blob 13\0" + data).hexdigest()
        self.assertEqual(c.git_hash(data), expected)

    def test_tree_checks_pinned_commit_and_modes(self):
        def responder(path, token):
            self.assertEqual(token, "a-secret-token")
            if path.startswith("/git/commits/"):
                return {"sha": REV, "tree": {"sha": TREE}}
            return {
                "sha": TREE, "truncated": False, "tree": [
                    {"path": n, "sha": sha, "mode": mode,
                     "type": "blob", "size": sz}
                    for n, (sha, sz, mode) in entries().items()
                ]}
        with mock.patch.object(c, "api_json", side_effect=responder):
            self.assertEqual(c.tree_entries(REV, "a-secret-token"), entries())

    def test_truncated_tree_and_symlink_both_refused(self):
        with mock.patch.object(c, "api_json", side_effect=[
            {"sha": REV, "tree": {"sha": TREE}},
            {"sha": TREE, "truncated": True, "tree": []},
        ]):
            with self.assertRaises(c.CheckoutBlocked):
                c.tree_entries(REV, "token")
        with mock.patch.object(c, "api_json", side_effect=[
            {"sha": REV, "tree": {"sha": TREE}},
            {"sha": TREE, "truncated": False, "tree": [
                {"path": "escape", "sha": "c" * 40,
                 "type": "blob", "mode": "120000", "size": 12}
            ]},
        ]):
            with self.assertRaises(c.CheckoutBlocked):
                c.tree_entries(REV, "token")

    def test_extract_complete_matching_git_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "repo.tar.gz"
            archive.write_bytes(build_tar())
            out = root / "out"
            out.mkdir()
            c.extract_verified(archive, out, entries())
            for k, data in SOURCE.items():
                self.assertEqual((out / k).read_bytes(), data)
            self.assertTrue((out / "scripts/deploy.sh").stat().st_mode & 0o100)

    def test_extract_tampering_extra_member_and_missing_file_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "repo.tar.gz"
            out = root / "out"
            out.mkdir()
            archive.write_bytes(build_tar({"README.md": b"tampered"}))
            with self.assertRaises(c.CheckoutBlocked):
                c.extract_verified(archive, out, entries())
            archive.write_bytes(build_tar({"README.md": SOURCE["README.md"],
                                          "unknown": b"bad"}))
            with self.assertRaises(c.CheckoutBlocked):
                c.extract_verified(archive, out, entries())
            archive.write_bytes(build_tar({"README.md": SOURCE["README.md"]}))
            with self.assertRaises(c.CheckoutBlocked):
                c.extract_verified(archive, out, entries())

    def test_extract_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tar:
                r = tarfile.TarInfo("top")
                r.type = tarfile.DIRTYPE
                tar.addfile(r)
                m = tarfile.TarInfo("top/README.md")
                m.type = tarfile.SYMTYPE
                m.linkname = "/etc/passwd"
                tar.addfile(m)
            archive = root / "s.tar.gz"
            archive.write_bytes(buf.getvalue())
            out = root / "out"
            out.mkdir()
            with self.assertRaises(c.CheckoutBlocked):
                c.extract_verified(archive, out, entries())
            self.assertFalse((out / "README.md").exists())

    def test_acquire_atomic_verified_install_and_existing_checkout_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            tar_bytes = build_tar()

            def mock_archive(sha, token, folder):
                path = folder / "package.tar.gz"
                path.write_bytes(tar_bytes)
                return path

            with mock.patch.object(c, "tree_entries", return_value=entries()), \
                 mock.patch.object(c, "archive_to_temp", side_effect=mock_archive):
                root = c.acquire(REV, "dummy-secret-token", home)
                self.assertEqual(root.name, REV)
                self.assertEqual((root / "README.md").read_bytes(), SOURCE["README.md"])
                with self.assertRaises(c.CheckoutBlocked):
                    c.acquire(REV, "dummy-secret-token", home)

    def test_redirect_fails_closed_on_unapproved_origin(self):
        headers = {"Location": "https://other.example/" + REV}
        exception = HTTPError(c.API + "/tarball/" + REV, 302, "Redirect",
                              headers, None)
        opener = mock.Mock()
        opener.open.side_effect = exception
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(c, "build_opener", return_value=opener):
            with self.assertRaises(c.CheckoutBlocked):
                c.archive_to_temp(REV, "dummy-secret-token", Path(tmp))

    def test_no_authorization_header_leaks_on_redirect(self):
        headers = {"Location": "https://codeload.github.com/" + c.REPO +
                               "/legacy.tar.gz/" + REV + "?token=SIGNED"}
        exception = HTTPError(c.API + "/tarball/" + REV, 302, "Redirect",
                              headers, None)
        opener = mock.Mock()
        opener.open.side_effect = exception
        observed = []

        def opened(request, timeout):
            observed.append((request.full_url, dict(request.header_items())))
            return io.BytesIO(b"zipbytes")

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(c, "build_opener", return_value=opener), \
             mock.patch.object(c, "urlopen", side_effect=opened):
            path = c.archive_to_temp(REV, "dummy-secret-token", Path(tmp))
            self.assertEqual(path.read_bytes(), b"zipbytes")
            self.assertEqual(len(observed), 1)
            self.assertNotIn("Authorization", observed[0][1])


if __name__ == "__main__":
    unittest.main()
