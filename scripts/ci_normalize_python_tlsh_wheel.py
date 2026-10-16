#!/usr/bin/env python3
"""CI-only deterministic python-tlsh 4.5.0 wheel metadata normalization.

Exactly two independent source builds currently contain volatile pip-wheel
temporary directories in .debug_line_str. GNU build IDs then differ, even
though executable text is identical. GNU objcopy drops ONLY DWARF debug
sections and the corresponding build-ID note in a disposable, no-secrets
Ubuntu 26.04 CI runner. The wheel RECORD checksum/size for that extension
is recomputed, and ZIP metadata/order are retained.

Never download, compile, run root installers, or normalize arbitrary wheels.
A reproducible resulting wheel is a NEW reviewed artifact; the original
sdist SHA256 and CI build provenance must still be retained separately.
"""
from __future__ import annotations

import base64
import csv
import hashlib
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

WHEEL = "python_tlsh-4.5.0-cp312-cp312-linux_x86_64.whl"
SO = "tlsh.cpython-312-x86_64-linux-gnu.so"
RECORD = "python_tlsh-4.5.0.dist-info/RECORD"
ALLOWED_CI_DIRECTORIES = frozenset((
    "/tmp/cape-built-wheels", "/tmp/cape-replayed-wheels",
))
MAX_BYTES = 5 * 1024 * 1024


class NormalizationBlocked(RuntimeError):
    pass


def need(ok, why):
    if not ok:
        raise NormalizationBlocked(why)


def safe_source(path):
    p = Path(path)
    need(p.is_absolute() and p.name == WHEEL and
         str(p.parent) in ALLOWED_CI_DIRECTORIES and
         not p.is_symlink(), "Only two ephemeral pinned wheel paths allowed")
    st = p.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
         0 < st.st_size <= MAX_BYTES, "Unexpected native wheel metadata")
    return p, st


def normalize(path):
    need(os.environ.get("GITHUB_ACTIONS") == "true",
         "Wheel binary normalization is disabled outside disposable CI")
    p, st = safe_source(path)
    with p.open("rb") as stream:
        original = stream.read(MAX_BYTES + 1)
    need(len(original) == st.st_size,
         "Wheel data changed during original-byte read")
    before_sha = hashlib.sha256(original).hexdigest()

    try:
        with zipfile.ZipFile(BytesIO(original), "r") as archive:
            members = archive.infolist()
            names = [item.filename for item in members]
            need(len(names) == len(set(names)) and
                 SO in names and RECORD in names and
                 4 <= len(names) <= 15 and
                 all(not name.startswith("/") and
                     ".." not in name.split("/") and
                     "\\" not in name for name in names),
                 "Unexpected native wheel ZIP inventory")
            blobs = {name: archive.read(name) for name in names}
    except (zipfile.BadZipFile, ValueError) as exc:
        raise NormalizationBlocked("Invalid native wheel ZIP") from exc
    need(blobs[SO].startswith(b"\x7fELF") and
         10000 <= len(blobs[SO]) <= 1000000,
         "Native extension bytes are not the reviewed ELF shape")
    previous_so_sha = hashlib.sha256(blobs[SO]).hexdigest()

    # Compiled source already came from sha-locked sdist dependencies.
    # objcopy is used in a temporary CI directory, never against a live
    # CAPE install or an artifact on an operator machine.
    with tempfile.TemporaryDirectory(prefix="cape-tlsh-strip-") as temp:
        before = Path(temp) / "input.so"
        after = Path(temp) / "output.so"
        before.write_bytes(blobs[SO])
        result = subprocess.run(
            ["/usr/bin/objcopy", "--strip-debug",
             "--remove-section=.note.gnu.build-id",
             str(before), str(after)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False)
        need(result.returncode == 0 and after.is_file(),
             "GNU objcopy rejected reviewed ELF normalization")
        normalized = after.read_bytes()
    need(normalized.startswith(b"\x7fELF") and
         20000 <= len(normalized) < len(blobs[SO]),
         "Debug stripping removed unexpected executable content")
    blobs[SO] = normalized

    rows = list(csv.reader(StringIO(blobs[RECORD].decode("utf-8"))))
    selected = [row for row in rows if len(row) == 3 and row[0] == SO]
    need(len(selected) == 1 and all(len(row) == 3 for row in rows),
         "Invalid source wheel RECORD format")
    digest = base64.urlsafe_b64encode(
        hashlib.sha256(normalized).digest()).decode("ascii").rstrip("=")
    selected[0][1] = "sha256=" + digest
    selected[0][2] = str(len(normalized))
    buffer = StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerows(rows)
    blobs[RECORD] = buffer.getvalue().encode("utf-8")

    # Preserve original members' timestamp, permissions, order and
    # compression type. SOURCE_DATE_EPOCH was fixed for both builds.
    out = BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for member in members:
            archive.writestr(member, blobs[member.filename])
    post_bytes = out.getvalue()
    need(0 < len(post_bytes) <= MAX_BYTES, "Oversized normalized wheel")
    with zipfile.ZipFile(BytesIO(post_bytes)) as check:
        need(check.testzip() is None, "Normalized wheel ZIP CRC mismatch")

    need(not p.is_symlink() and
         p.stat().st_ino == st.st_ino and p.stat().st_size == st.st_size,
         "Original wheel changed while normalizing")
    with tempfile.NamedTemporaryFile(
            prefix=".cape-tlsh-normalize-", suffix=".whl",
            dir=p.parent, delete=False) as stage:
        temp_path = Path(stage.name)
        try:
            stage.write(post_bytes)
            stage.flush()
            os.fsync(stage.fileno())
            os.fchmod(stage.fileno(), stat.S_IMODE(st.st_mode))
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
    try:
        os.replace(temp_path, p)
        dfd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        temp_path.unlink(missing_ok=True)
    return {
        "result": "CAPE_CI_TLSH_FIXED_DEBUG_NORMALIZED",
        "wheel_filename": WHEEL,
        "original_wheel_sha256": before_sha,
        "original_native_so_sha256": previous_so_sha,
        "normalized_native_so_sha256":
            hashlib.sha256(normalized).hexdigest(),
        "normalized_wheel_sha256":
            hashlib.sha256(post_bytes).hexdigest(),
        "normalized_elf_debug_sections_removed": True,
        "normalized_elf_build_id_note_removed": True,
        "source_sdist_or_checkout_modified": False,
        "CI_only": True,
    }


def main(argv=None):
    paths = sys.argv[1:] if argv is None else argv
    if len(paths) != 2:
        raise SystemExit("Expected both independent disposable wheel paths")
    try:
        before = [safe_source(p)[0] for p in paths]
        need(set(str(p.parent) for p in before) ==
             ALLOWED_CI_DIRECTORIES,
             "Expected one wheel from each independent build")
        result = [normalize(p) for p in before]
        need(result[0]["normalized_wheel_sha256"] ==
             result[1]["normalized_wheel_sha256"],
             "Normalized independent native builds are still different")
        print(json.dumps({
            "result":"CAPE_CI_INDEPENDENT_TLSH_NORMALIZATION_IDENTICAL",
            "witnesses": result,
            "approved_operator_install":False
        },sort_keys=True))
        return 0
    except (NormalizationBlocked, OSError, ValueError,
            subprocess.TimeoutExpired, UnicodeDecodeError) as exc:
        print(json.dumps({
            "result":"CAPE_CI_TLSH_NORMALIZATION_BLOCKED",
            "error_type":type(exc).__name__,
            "no_production_install_attempted":True
        }),file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
