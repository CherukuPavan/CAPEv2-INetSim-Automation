"""Offline static safety regression for Windows benign snapshot witness."""
from pathlib import Path
import unittest

FILE=Path(__file__).with_name("command2_windows_benign_snapshot_witness.ps1")

class TestSnapshotWitness(unittest.TestCase):
    def test_requires_explicit_modes_and_benign_marker(self):
        src=FILE.read_text(encoding="utf-8")
        self.assertIn("[ValidateSet('Baseline','Mark','Verify')]",src)
        self.assertIn("CAPE_Command2_BenignSnapshotMutation.marker",src)
        self.assertIn("MARK-BENIGN-SNAPSHOT-DISK",src)
        self.assertIn("[System.IO.FileMode]::CreateNew",src)
        self.assertIn("DISK_MARKER_ABSENT_AFTER_REVERT",src)

    def test_tpm_ek_public_sha_is_read_only_additional_identity_witness(self):
        src=FILE.read_text(encoding="utf-8")
        self.assertIn("TPM_EK_PUBLIC_SHA256",src)
        self.assertIn("Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256",src)
        self.assertIn("^[0-9a-fA-F]{64}$",src)
        self.assertIn("INCONCLUSIVE_OR_NOT_PRESENT",src)
        self.assertNotIn("Clear-Tpm",src)
        self.assertNotIn("Export-Tpm",src)

    def test_witness_does_not_claim_full_tpm_uefi_revert(self):
        src=FILE.read_text(encoding="utf-8")
        self.assertIn("TPM_UEFI_FULL_STATE_ROLLBACK_PROVEN' 'FALSE",src)
        self.assertIn("FULL_TPM_UEFI_CONSISTENCY_TESTED' 'FALSE",src)
        self.assertIn("REQUIRES_COMPARISON_WITH_PREVIOUS_WITNESS' 'TRUE",src)

    def test_reads_without_disabling_security_or_reaching_external_ips(self):
        src=FILE.read_text(encoding="utf-8")
        self.assertIn("Get-Tpm",src)
        self.assertIn("Get-BitLockerVolume",src)
        self.assertIn("Confirm-SecureBootUEFI",src)
        self.assertIn("Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop",src)
        self.assertIn("Get-NetRoute -AddressFamily IPv6 -ErrorAction Stop",src)
        for token in ("Set-MpPreference","Disable-NetAdapter","Set-NetRoute",
                      "Remove-NetRoute","New-NetIPAddress","Set-NetIPInterface",
                      "Set-ExecutionPolicy","Clear-Tpm","Disable-BitLocker",
                      "Invoke-Expression","Start-BitsTransfer",
                      "Invoke-WebRequest -Uri 'https:"):
            self.assertNotIn(token,src)

    def test_off_guest_evidence_caveat_is_recorded(self):
        src=FILE.read_text(encoding="utf-8")
        self.assertIn("SAVE_REPORT_OFF_GUEST",src)
        self.assertIn("GUEST_CLEAN_SHUTDOWN",src)
        self.assertIn("http://127.0.0.1:8000/",src)

if __name__=="__main__":
    unittest.main()
