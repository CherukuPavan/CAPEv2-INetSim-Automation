#!/usr/bin/env python3
"""Read-only GPT Windows-volume encryption guard for CAPE cold QCOW2 sources.

Uses qemu-img dd to inspect a few GPT/header sectors only. It never mounts
NTFS, opens BitLocker, asks for secrets, or starts a VM. UNKNOWN fails closed.
The positive cleartext result is *not* a proof that Registry editing/boot works.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import uuid
import zlib

SECTOR = 512
WINDOW_LIMIT = 128
BASIC_DATA = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")
RECOVERY = uuid.UUID("de94bba4-06d1-4d40-a16a-bfd50179d6ac")

class VolumeProbeError(RuntimeError):
    pass


def gpt_entries(header: bytes, entry_data: bytes) -> list[dict]:
    """Parse and CRC-check GPT without trusting guest-supplied lengths."""
    if len(header) != SECTOR or header[:8] != b"EFI PART":
        raise VolumeProbeError("Missing or unsupported primary GPT")
    size = struct.unpack_from("<I", header, 12)[0]
    if size < 92 or size > SECTOR:
        raise VolumeProbeError("Invalid GPT header size")
    expected_crc = struct.unpack_from("<I", header, 16)[0]
    normalized = bytearray(header[:size])
    normalized[16:20] = b"\x00" * 4
    if zlib.crc32(normalized) != expected_crc:
        raise VolumeProbeError("Invalid primary GPT header CRC")
    if struct.unpack_from("<Q", header, 24)[0] != 1:
        raise VolumeProbeError("Primary GPT is not at LBA 1")
    start_lba = struct.unpack_from("<Q", header, 72)[0]
    count, entry_size, entries_crc = struct.unpack_from("<III", header, 80)
    if start_lba < 2 or start_lba > 32:
        raise VolumeProbeError("GPT partition array location unsupported")
    if not 1 <= count <= 256 or entry_size not in (128, 256):
        raise VolumeProbeError("GPT entry count/size unsupported")
    nbytes = count * entry_size
    if nbytes > 65536 or len(entry_data) < nbytes:
        raise VolumeProbeError("GPT partition entries truncated")
    if zlib.crc32(entry_data[:nbytes]) != entries_crc:
        raise VolumeProbeError("Invalid GPT partition entries CRC")
    rows = []
    for idx in range(count):
        entry = entry_data[idx*entry_size:(idx+1)*entry_size]
        if entry[:16] == b"\x00" * 16:
            continue
        kind = uuid.UUID(bytes_le=entry[:16])
        first, last = struct.unpack_from("<QQ", entry, 32)
        if first < 34 or last < first:
            raise VolumeProbeError("Invalid GPT partition extent")
        rows.append({"index": idx + 1, "first_lba": first,
                     "last_lba": last, "type_guid": str(kind)})
    return rows


def classify_boot_sector(data: bytes) -> str:
    if len(data) != SECTOR:
        raise VolumeProbeError("Truncated partition header")
    signature = data[3:11]
    if signature == b"-FVE-FS-":
        return "BITLOCKER"
    if signature == b"NTFS    ":
        return "NTFS"
    if signature == b"EXFAT   ":
        return "EXFAT"
    return "UNKNOWN"


def decide(partitions: list[dict]) -> str:
    basic = [p for p in partitions
             if p["type_guid"] == str(BASIC_DATA)]
    if not basic:
        raise VolumeProbeError("No Microsoft basic-data partition found")
    if any(p["filesystem"] == "BITLOCKER" for p in partitions):
        return "BITLOCKER_BLOCKED"
    if any(p["filesystem"] != "NTFS" for p in basic):
        return "UNKNOWN_BLOCKED"
    return "CLEAR_NTFS_CANDIDATE_NOT_BOOT_VERIFIED"


def inspect_image(image: Path) -> dict:
    if not image.is_absolute() or not image.is_file() or image.is_symlink():
        raise VolumeProbeError("Expected absolute regular cold QCOW2 image")
    if not re.fullmatch(r"/[A-Za-z0-9_./+@-]{1,4095}", str(image)):
        raise VolumeProbeError("Unsafe QCOW2 path")
    with tempfile.TemporaryDirectory(prefix="cape-cold-volume-check-") as tmp:
        def read_window(lba: int, sectors: int) -> bytes:
            if lba < 0 or sectors < 1 or sectors > WINDOW_LIMIT:
                raise VolumeProbeError("Out-of-range disk sector read")
            out = Path(tmp) / "sector.raw"
            if out.exists():
                out.unlink()
            args = [
                "qemu-img", "dd", "-f", "qcow2", "-O", "raw",
                f"bs={SECTOR}", f"count={sectors}", f"skip={lba}",
                "if="+str(image), "of="+str(out)
            ]
            try:
                subprocess.run(args, check=True, capture_output=True,
                               timeout=90)
                value=out.read_bytes()
            except (OSError, subprocess.CalledProcessError,
                    subprocess.TimeoutExpired) as exc:
                raise VolumeProbeError(
                    "qemu-img could not read selected cold disk sectors"
                ) from exc
            if len(value) != SECTOR*sectors:
                raise VolumeProbeError("Incomplete QCOW2 sector read")
            return value

        mbr=read_window(0, 1)
        if mbr[510:512] != b"\x55\xaa":
            raise VolumeProbeError("Missing protective MBR signature")
        header=read_window(1, 1)
        if header[:8] != b"EFI PART":
            raise VolumeProbeError("GPT header unavailable")
        array_lba=struct.unpack_from("<Q", header, 72)[0]
        count, entry_size=struct.unpack_from("<II", header, 80)
        if count < 1 or count > 256 or entry_size not in (128, 256):
            raise VolumeProbeError("Invalid GPT entry dimensions")
        sectors=(count*entry_size + SECTOR - 1)//SECTOR
        if sectors > WINDOW_LIMIT or array_lba < 2 or array_lba > 32:
            raise VolumeProbeError("Untrusted GPT array range")
        parts=gpt_entries(header, read_window(array_lba, sectors))
        result=[]
        for part in parts:
            typ=classify_boot_sector(read_window(part["first_lba"],1))
            result.append({
                "index":part["index"],
                "type_guid":part["type_guid"],
                "filesystem":typ,
            })
        decision=decide(result)
        return {"schema":"cape-cold-volume-crypto-v1",
                "mode":"READ_ONLY_NO_MOUNT_NO_NBD",
                "decision":decision,
                "partitions":result,
                "windows_registry_readable":decision ==
                    "CLEAR_NTFS_CANDIDATE_NOT_BOOT_VERIFIED",
                "modified_image":False}


def require_cleartext_candidate(image: Path) -> dict:
    info=inspect_image(image)
    if not info["windows_registry_readable"]:
        raise VolumeProbeError(
            "BitLocker or unknown Windows volume on cold master: "
            + info["decision"]
            + "; require separately authorized unlocked clone template"
        )
    return info


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disk",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        details=inspect_image(args.disk)
        print(json.dumps(details, indent=2,sort_keys=True))
        return 0 if details["windows_registry_readable"] else 2
    except (VolumeProbeError,ValueError) as exc:
        print("BLOCKED:",str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
