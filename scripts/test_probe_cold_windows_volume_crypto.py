#!/usr/bin/env python3
"""Offline synthetic GPT/BitLocker-detection tests. No host images used."""
import struct
import unittest
import uuid
import zlib
import probe_cold_windows_volume_crypto as crypto

def make_gpt(part_types):
    part_bytes=bytearray(128*128)
    for i, guid in enumerate(part_types):
        pos=i*128
        part_bytes[pos:pos+16]=uuid.UUID(str(guid)).bytes_le
        part_bytes[pos+16:pos+32]=uuid.uuid5(uuid.NAMESPACE_DNS,"test"+str(i)).bytes_le
        struct.pack_into("<QQ",part_bytes,pos+32,2048 + 5120*i,4095+5120*i)
    header=bytearray(512)
    header[0:8]=b"EFI PART"
    struct.pack_into("<I",header,8,0x00010000)
    struct.pack_into("<I",header,12,92)
    struct.pack_into("<QQQQ",header,24,1,131071,34,131038)
    struct.pack_into("<Q",header,72,2)
    struct.pack_into("<III",header,80,128,128,zlib.crc32(part_bytes))
    struct.pack_into("<I",header,16,zlib.crc32(header[:92]))
    return bytes(header),bytes(part_bytes)

class Tests(unittest.TestCase):
    def test_bitlocker_signature(self):
        sector=b"\xeb\x58\x90-FVE-FS-" + b"\x00"*501
        self.assertEqual(crypto.classify_boot_sector(sector),"BITLOCKER")

    def test_plain_ntfs_candidate_only(self):
        head,data=make_gpt([crypto.BASIC_DATA,crypto.RECOVERY])
        rows=crypto.gpt_entries(head,data)
        self.assertEqual(len(rows),2)
        rows[0]["filesystem"]="NTFS"
        rows[1]["filesystem"]="NTFS"
        self.assertEqual(crypto.decide(rows),
                         "CLEAR_NTFS_CANDIDATE_NOT_BOOT_VERIFIED")

    def test_real_report_bitlocker_partition_blocks(self):
        head,data=make_gpt([crypto.BASIC_DATA,crypto.RECOVERY])
        rows=crypto.gpt_entries(head,data)
        rows[0]["filesystem"]="BITLOCKER"
        rows[1]["filesystem"]="NTFS"
        self.assertEqual(crypto.decide(rows),"BITLOCKER_BLOCKED")

    def test_unknown_basic_volume_blocks(self):
        head,data=make_gpt([crypto.BASIC_DATA])
        rows=crypto.gpt_entries(head,data)
        rows[0]["filesystem"]="UNKNOWN"
        self.assertEqual(crypto.decide(rows),"UNKNOWN_BLOCKED")

    def test_header_crc_change_refused(self):
        head,data=make_gpt([crypto.BASIC_DATA])
        altered=bytearray(head)
        altered[30]^=1
        with self.assertRaisesRegex(crypto.VolumeProbeError,"CRC"):
            crypto.gpt_entries(bytes(altered),data)

    def test_partition_entries_crc_change_refused(self):
        head,data=make_gpt([crypto.BASIC_DATA])
        altered=bytearray(data)
        altered[20]^=1
        with self.assertRaisesRegex(crypto.VolumeProbeError,"CRC"):
            crypto.gpt_entries(head,bytes(altered))

    def test_missing_partition_refused(self):
        head,data=make_gpt([crypto.RECOVERY])
        rows=crypto.gpt_entries(head,data)
        rows[0]["filesystem"]="NTFS"
        with self.assertRaisesRegex(crypto.VolumeProbeError,"basic-data"):
            crypto.decide(rows)

    def test_qemu_img_dd_sector_probe_blocks_actual_bitlocker_layout(self):
        from pathlib import Path
        from unittest.mock import patch
        import tempfile
        header, entries=make_gpt([crypto.BASIC_DATA,crypto.RECOVERY])
        mbr=bytearray(512)
        mbr[510:512]=b"\x55\xaa"
        bitlocker=b"\xeb\x58\x90-FVE-FS-"+b"\x00"*501
        ntfs=b"\xeb\x52\x90NTFS    "+b"\x00"*501
        contents={
            (0,1):bytes(mbr),
            (1,1):header,
            (2,32):entries,
            (2048,1):bitlocker,
            (7168,1):ntfs,
        }
        calls=[]
        def fake_run(args, **kwargs):
            calls.append(args)
            offset=int(next(a[5:] for a in args if a.startswith("skip=")))
            length=int(next(a[6:] for a in args if a.startswith("count=")))
            output=Path(next(a[3:] for a in args if a.startswith("of=")))
            output.write_bytes(contents[(offset,length)])
            class Result: pass
            return Result()
        with tempfile.TemporaryDirectory() as td:
            disk=Path(td)/"detached-clone.qcow2"
            disk.write_bytes(b"QFI\xfb")
            with patch.object(crypto.subprocess,"run",side_effect=fake_run):
                info=crypto.inspect_image(disk)
            self.assertFalse(info["windows_registry_readable"])
            self.assertEqual(info["decision"],"BITLOCKER_BLOCKED")
            self.assertEqual(disk.read_bytes(),b"QFI\xfb")
        self.assertTrue(calls)
        self.assertTrue(all(call[1]=="dd" and "-U" not in call for call in calls))

    def test_incomplete_boot_sector_refused(self):
        with self.assertRaisesRegex(crypto.VolumeProbeError,"Truncated"):
            crypto.classify_boot_sector(b"-FVE-FS-")

if __name__=="__main__":
    unittest.main()
