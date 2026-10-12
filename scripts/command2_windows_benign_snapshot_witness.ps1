#Requires -Version 5.1
<#
Benign Windows 11 snapshot/revert evidence: Baseline, Mark, Verify.
Never changes network, firewall, Defender, BitLocker, TPM or firmware.
Mark writes ONE harmless marker in Public Documents, after snapshot.
Verify checks that marker disappeared after revert. This is NOT sufficient
to prove swtpm persistent/UEFI state rollback; second-host operator proof.
#>
[CmdletBinding()]
param(
    [ValidateSet('Baseline','Mark','Verify')]
    [string]$Mode='Baseline'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$HomeDir=Join-Path $env:PUBLIC 'Documents'
$Marker=Join-Path $HomeDir 'CAPE_Command2_BenignSnapshotMutation.marker'
$When=Get-Date -Format 'yyyyMMdd_HHmmss'
$Report=Join-Path $HomeDir ("CAPE_Command2_SnapshotWitness_"+$Mode+"_"+$When+".txt")
$Rows=New-Object 'System.Collections.Generic.List[string]'
function Record([string]$Key,[string]$Value) {
    [void]$Rows.Add(($Key+'='+$Value))
}
function Optional([string]$Key,[scriptblock]$Task) {
    try { Record $Key ([string](& $Task)) }
    catch { Record $Key ('INCONCLUSIVE_'+$_.Exception.GetType().Name) }
}
Record 'RESULT_TYPE' 'COMMAND2_BENIGN_SNAPSHOT_WITNESS_V1'
Record 'MODE' $Mode
Record 'TIME_UTC' ([DateTime]::UtcNow.ToString('o'))
Record 'HOSTNAME' ([Environment]::MachineName)
Record 'MARKER_LOCATION' $Marker
Record 'GUEST_SECURITY_SETTINGS_MODIFIED' 'FALSE'
Record 'MALWARE_OR_EXTERNAL_DOWNLOAD_USED' 'FALSE'
Record 'TPM_UEFI_FULL_STATE_ROLLBACK_PROVEN' 'FALSE'
Record 'REQUIRES_COMPARISON_WITH_PREVIOUS_WITNESS' 'TRUE'

if ([Environment]::MachineName -notmatch '^WIN11-([1-9]|1[0-6])$') {
    Record 'EXPECTED_WINDOWS_IDENTITY' 'FAIL'
} else {
    Record 'EXPECTED_WINDOWS_IDENTITY' 'PASS'
}
Optional 'WINDOWS_VERSION' { [Environment]::OSVersion.Version.ToString() }
Optional 'SYSTEM_UUID' {
    (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID
}
Optional 'TPM_PRESENT' { (Get-Tpm -ErrorAction Stop).TpmPresent }
Optional 'TPM_READY' { (Get-Tpm -ErrorAction Stop).TpmReady }
Optional 'TPM_ENABLED' { (Get-Tpm -ErrorAction Stop).TpmEnabled }
Optional 'TPM_ACTIVATED' { (Get-Tpm -ErrorAction Stop).TpmActivated }
# EK PUBLIC-key hash can help identify TPM replacement after a revert.
# It does not contain a secret key or prove rollback of TPM persistent state.
Optional 'TPM_EK_PUBLIC_SHA256' {
    $ek=Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256 -ErrorAction Stop
    if ($ek.IsPresent -eq $true -and
        [string]$ek.PublicKeyHash -match '^[0-9a-fA-F]{64}$') {
        ([string]$ek.PublicKeyHash).ToLowerInvariant()
    } else {
        'INCONCLUSIVE_OR_NOT_PRESENT'
    }
}
Optional 'SECURE_BOOT_ENABLED' { Confirm-SecureBootUEFI -ErrorAction Stop }
Optional 'BITLOCKER_PROTECTION' {
    (Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus
}
Optional 'BITLOCKER_VOLUME_STATUS' {
    (Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).VolumeStatus
}
Optional 'UP_PHYSICAL_NIC_COUNT' {
    @((Get-NetAdapter -Physical -ErrorAction Stop) |
        Where-Object { $_.Status -eq 'Up' }).Count
}
Optional 'NONLOOPBACK_IPV4' {
    (@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
      Where-Object { $_.IPAddress -ne '127.0.0.1' } |
      ForEach-Object { $_.IPAddress+'/'+$_.PrefixLength }) | Sort-Object) -join ','
}
Optional 'DEFAULT_IPV4_ROUTE_COUNT' {
    @((Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop) |
      Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }).Count
}
Optional 'DEFAULT_IPV6_ROUTE_COUNT' {
    @((Get-NetRoute -AddressFamily IPv6 -ErrorAction Stop) |
      Where-Object { $_.DestinationPrefix -eq '::/0' }).Count
}
Optional 'CAPE_AGENT_LOCAL_HTTP' {
    $req=Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8000/' `
         -TimeoutSec 4 -ErrorAction Stop
    $response=ConvertFrom-Json -InputObject $req.Content -ErrorAction Stop
    if ($req.StatusCode -eq 200 -and $response.message -eq 'CAPE Agent!' -and
        $response.is_user_admin -eq $true) { 'VERIFIED_ADMIN' }
    else { 'INVALID_AGENT_RESPONSE' }
}
switch ($Mode) {
    Baseline {
        Record 'POST_SNAPSHOT_DISK_MARKER_EXISTS' ([string](Test-Path -LiteralPath $Marker))
        Record 'NEXT_ACTION' 'SAVE_REPORT_OFF_GUEST_THEN_CAPTURE_RUNNING_SNAPSHOT'
    }
    Mark {
        if (Test-Path -LiteralPath $Marker) {
            Record 'MARKER_CREATED' 'FALSE_PREEXISTING_REFUSE'
        } else {
            $phrase=Read-Host 'Type MARK-BENIGN-SNAPSHOT-DISK for ONE harmless marker file'
            if ($phrase -ne 'MARK-BENIGN-SNAPSHOT-DISK') {
                Record 'MARKER_CREATED' 'FALSE_OPERATOR_DECLINED'
            } else {
                $payload='Benign snapshot disk rollback marker; no sample content.'
                $fs=[System.IO.File]::Open($Marker,
                      [System.IO.FileMode]::CreateNew,
                      [System.IO.FileAccess]::Write,
                      [System.IO.FileShare]::None)
                try {
                    $data=[System.Text.Encoding]::UTF8.GetBytes($payload)
                    $fs.Write($data,0,$data.Length)
                    $fs.Flush($true)
                } finally { $fs.Dispose() }
                Record 'MARKER_CREATED' 'TRUE'
                Record 'NEXT_ACTION' 'GUEST_CLEAN_SHUTDOWN_THEN_APPROVED_DISPOSABLE_HOST_REVERT'
            }
        }
    }
    Verify {
        $found=Test-Path -LiteralPath $Marker
        Record 'POST_SNAPSHOT_DISK_MARKER_EXISTS' ([string]$found)
        Record 'DISK_MARKER_ABSENT_AFTER_REVERT' ([string](-not $found))
        Record 'FULL_TPM_UEFI_CONSISTENCY_TESTED' 'FALSE'
        Record 'NEXT_ACTION' 'COMPARE_WITNESS_WITH_OFF_GUEST_BASELINE_AND_REPEAT_BENIGN_REVERT'
    }
}
try {
    $Rows | Set-Content -LiteralPath $Report -Encoding UTF8 -ErrorAction Stop
    Write-Host ('SNAPSHOT_WITNESS_REPORT: '+$Report)
    Start-Process -FilePath "$env:SystemRoot\system32\notepad.exe" `
                  -ArgumentList ('"'+$Report+'"')
} catch {
    Write-Host ('REPORT_NOT_SAVED: '+$_.Exception.GetType().Name)
    foreach ($r in $Rows) { Write-Host $r }
}
