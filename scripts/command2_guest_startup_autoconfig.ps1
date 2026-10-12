#Requires -Version 5.1
<#
Command 2 Windows guest bootstrap, intended to be installed ONCE
in an authorized pre-provisioned Windows 11 analysis template by
the operator/Command 1.

- INSTALL is guarded by exact SMBIOS UUID, admin rights and explicit
  -ApproveInstall; installs a SYSTEM startup task, no network changes.
- RUN is the startup task. Requires exactly one read-only optical disk
  labeled CAPE_CMD2 with a per-guest config JSON and SHA256 file.
- ZERO NIC: calls the separately pinned guest-personalization Identity
  mode (WIN11-N rename and reboot). Does NOT create a NIC.
- ONE NIC: only with exact host-issued isolation approval JSON and
  hash on the optical disk, calls Network mode to configure static IP.
- NO external downloads or disabling Windows security/update features.

NOT a complete host isolation proof. The host must first prove its
IPv4/IPv6 isolation and reboot persistence before emitting the approval.
The config+hash on optical media provide integrity only, NOT an
independent digital signature of approval. Secure host creation/attachment
of approved media remains to be implemented and tested in Command 2.
#>
[CmdletBinding()]
param(
    [ValidateSet("Install","Verify","Run")][string]$Mode="Run",
    [string]$ExpectedTemplateUuid,
    [string]$ExpectedRunnerSha256,
    [string]$ExpectedPersonalizerSha256,
    [switch]$ApproveInstall
)
Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"
$Root=Join-Path $env:ProgramData "CAPECommand2"
$LocalRunner=Join-Path $Root "command2_guest_startup_autoconfig.ps1"
$LocalPersonalize=Join-Path $Root "command2_guest_personalize.ps1"
$TaskName="CAPECommand2GuestInit"

function Deny([string]$why) { throw ("COMMAND2_GUEST_BOOTSTRAP_BLOCKED: "+$why) }
function UUID {
    try { return [guid]([string](Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID) }
    catch { Deny "Windows SMBIOS UUID is missing or invalid" }
}
function RequireAdmin {
    $me=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=New-Object Security.Principal.WindowsPrincipal($me)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Deny "Local Administrator/System privilege required"
    }
}
function ExactSha([string]$path,[string]$shaFile) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
        -not (Test-Path -LiteralPath $shaFile -PathType Leaf)) {
        Deny "Missing config or integrity digest on trusted optical media"
    }
    $expected=(Get-Content -LiteralPath $shaFile -Raw -Encoding ASCII).Trim()
    if ($expected -cnotmatch "^[0-9a-fA-F]{64}$") {
        Deny "Malformed config SHA256"
    }
    $actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($actual -ine $expected) { Deny "Configuration hash mismatch" }
    return $expected
}
function CopyVerified([string]$from,[string]$to) {
    if (-not (Test-Path -LiteralPath $from -PathType Leaf)) {
        Deny "Expected local installer file missing"
    }
    $src=(Get-FileHash -LiteralPath $from -Algorithm SHA256).Hash
    if (Test-Path -LiteralPath $to -PathType Leaf) {
        $dst=(Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash
        if ($src -ine $dst) {
            Deny "Existing Windows bootstrap file differs; refuse overwrite"
        }
        return
    }
    Copy-Item -LiteralPath $from -Destination $to -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash -ine $src) {
        Deny "Installed script did not match approved local source"
    }
}
function AssertPinnedSha([string]$file,[string]$expected,[string]$what) {
    if ($expected -cnotmatch "^[0-9a-fA-F]{64}$") {
        Deny ("Missing reviewed 64-hex SHA256 for "+$what)
    }
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Deny ("Bootstrap file missing: "+$what)
    }
    $actual=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    if ($actual -ine $expected) {
        Deny ("Bootstrap file differs from reviewed SHA256: "+$what)
    }
}
function ExactBootTask {
    $existing=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $existing) { Deny "Windows SYSTEM bootstrap scheduled task missing" }
    if ($existing.State -eq "Disabled" -or -not $existing.Settings.Enabled) {
        Deny "Windows SYSTEM bootstrap scheduled task disabled"
    }
    if ([string]$existing.Principal.UserId -notin @("SYSTEM","NT AUTHORITY\SYSTEM") -or
        [string]$existing.Principal.RunLevel -ne "Highest" -or
        [string]$existing.Principal.LogonType -ne "ServiceAccount") {
        Deny "Bootstrap scheduled task principal differs from privileged SYSTEM"
    }
    $expectedArgs='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+
                  $LocalRunner+'" -Mode Run'
    $actions=@($existing.Actions)
    $triggers=@($existing.Triggers)
    if ($actions.Count -ne 1 -or
        [string]$actions[0].Execute -ine "powershell.exe" -or
        [string]$actions[0].Arguments -cne $expectedArgs -or
        $triggers.Count -ne 1 -or
        $triggers[0].CimClass.CimClassName -cne "MSFT_TaskBootTrigger" -or
        -not $triggers[0].Enabled) {
        Deny "Bootstrap scheduled task action or startup trigger differs"
    }
}
function OpticalConfig {
    # Wait for optical media after boot; this is a local read-only scan.
    for ($attempt=0; $attempt -lt 8; $attempt++) {
        $volumes=@(Get-Volume -FileSystemLabel "CAPE_CMD2" -ErrorAction SilentlyContinue)
        if ($volumes.Count -gt 0) { break }
        Start-Sleep -Seconds 8
    }
    if ($volumes.Count -eq 0) { return $null }
    if ($volumes.Count -ne 1) { Deny "More than one CAPE config disk found" }
    $drive=[string]$volumes[0].DriveLetter
    if ($drive -cnotmatch "^[A-Z]$") { Deny "Config media has no safe drive letter" }
    $device=$drive+":"
    $logical=Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='"+$device+"'")
    if ($null -eq $logical -or [int]$logical.DriveType -ne 5) {
        Deny "Configuration must be delivered on read-only CD-ROM media"
    }
    return $device+"\"
}
function CallPersonalizer([string]$mode,[string]$conf,[string]$digest,[bool]$isolation) {
    if (-not (Test-Path -LiteralPath $LocalPersonalize -PathType Leaf)) {
        Deny "Local guest personalization script was not installed"
    }
    $shell=Join-Path $PSHOME "powershell.exe"
    $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+
               $LocalPersonalize+'" -Mode '+$mode+' -ConfigFile "'+
               $conf+'" -ExpectedSha256 '+$digest
    if ($mode -eq "Identity") { $arguments+=" -RestartAfterIdentity" }
    if ($isolation) { $arguments+=" -HostIsolationVerified" }
    $p=Start-Process -FilePath $shell -ArgumentList $arguments -PassThru -Wait -ErrorAction Stop
    if ($p.ExitCode -ne 0) { Deny "Personalization phase failed: "+$mode }
}

RequireAdmin

if ($Mode -eq "Install" -or $Mode -eq "Verify") {
    if ($ExpectedTemplateUuid -notmatch
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$") {
        Deny "Exact expected Windows template UUID required for installation or verification"
    }
    if ((UUID) -ne [guid]$ExpectedTemplateUuid) {
        Deny "Windows template UUID differs from authorized source"
    }
    $installerDir=Split-Path -Parent $PSCommandPath
    $sourcePersonalizer=Join-Path $installerDir "command2_guest_personalize.ps1"
    AssertPinnedSha $PSCommandPath $ExpectedRunnerSha256 "bootstrap runner"
    AssertPinnedSha $sourcePersonalizer $ExpectedPersonalizerSha256 "guest personalizer"
}
if ($Mode -eq "Verify") {
    # Read-only installed source and scheduled-task acceptance: verify that the
    # exact separately reviewed source hashes match installed ProgramData files.
    AssertPinnedSha $LocalRunner $ExpectedRunnerSha256 "installed runner"
    AssertPinnedSha $LocalPersonalize $ExpectedPersonalizerSha256 "installed personalizer"
    ExactBootTask
    [pscustomobject]@{result="COMMAND1_WINDOWS_BOOTSTRAP_READONLY_VERIFIED"
        source_uuid=[string](UUID);task=$TaskName
        installed_runner_sha256=$ExpectedRunnerSha256.ToLowerInvariant()
        installed_personalizer_sha256=$ExpectedPersonalizerSha256.ToLowerInvariant()
        boot_trigger_verified=$true;system_principal_verified=$true
        auto_guest_network_executed_here=$false;no_changes_made=$true
        source_master_clone_ready_by_this_check_alone=$false} | ConvertTo-Json -Compress
    exit 0
}

if ($Mode -eq "Install") {
    if (-not $ApproveInstall) {
        Deny "Explicit operator approval required to install startup automation"
    }
     if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        New-Item -Path $Root -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    CopyVerified $PSCommandPath $LocalRunner
    CopyVerified $sourcePersonalizer $LocalPersonalize
    $existing=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Deny "Existing startup task requires human review (no blind overwrite)"
    }
    $trigger=New-ScheduledTaskTrigger -AtStartup
    $taskArgs='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+
              $LocalRunner+'" -Mode Run'
    $action=New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArgs
    $principal=New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
    # Verify the newly registered task rather than assuming creation implies
    # an effective SYSTEM startup trigger.
    ExactBootTask
    [pscustomobject]@{result="COMMAND2_GUEST_STARTUP_TASK_INSTALLED"
        vm_uuid=[string](UUID);network_changed=$false
        guest_identity_changed=$false;task=$TaskName} | ConvertTo-Json -Compress
    exit 0
}

$media=OpticalConfig
if ($null -eq $media) {
    [pscustomobject]@{result="COMMAND2_GUEST_BOOTSTRAP_WAITING_FOR_OPTICAL_CONFIG"
        network_changed=$false;hostname_changed=$false} | ConvertTo-Json -Compress
    exit 0
}
$conf=Join-Path $media "guest-config.json"
$digest=ExactSha $conf (Join-Path $media "guest-config.sha256")
try { $config=Get-Content -LiteralPath $conf -Encoding UTF8 -Raw | ConvertFrom-Json }
catch { Deny "Invalid guest configuration JSON" }
if ($config.format -cne "COMMAND2_GUEST_PERSONALIZATION_V1") {
    Deny "Not a Command2 guest configuration"
}
if ([guid]([string]$config.expected_machine_uuid) -ne (UUID)) {
    Deny "Config CD-ROM is for a DIFFERENT Windows VM"
}
$adapters=@(Get-NetAdapter -Physical -ErrorAction Stop)
if ($adapters.Count -eq 0) {
    CallPersonalizer "Identity" $conf $digest $false
    exit 0
}
if ($adapters.Count -ne 1) {
    Deny "Unexpected number of physical NICs; manual isolation review required"
}
$approval=Join-Path $media "network-approved.json"
$approvalSha=Join-Path $media "network-approved.sha256"
if (-not (Test-Path -LiteralPath $approval -PathType Leaf)) {
    [pscustomobject]@{result="COMMAND2_GUEST_BOOTSTRAP_WAITING_FOR_HOST_NETWORK_ISOLATION"
        nic_count=1;ip_changed=$false} | ConvertTo-Json -Compress
    exit 0
}
[void](ExactSha $approval $approvalSha)
try { $proof=Get-Content -LiteralPath $approval -Encoding UTF8 -Raw | ConvertFrom-Json }
catch { Deny "Invalid host network approval JSON" }
if ($proof.format -cne "COMMAND2_HOST_NETWORK_APPROVAL_V1" -or
    [guid]([string]$proof.guest_uuid) -ne (UUID) -or
    [string]$proof.guest_name -cne [string]$config.guest_name -or
    [string]$proof.guest_mac -cne [string]$config.nic_mac -or
    $proof.host_ipv4_negative_egress_verified -ne $true -or
    $proof.host_ipv6_negative_egress_verified -ne $true -or
    $proof.reboot_persistence_verified -ne $true -or
    $proof.guest_l2_separation_verified -ne $true) {
    Deny "Host network acceptance missing/mismatched; static IP not applied"
}
# The host-issued approval must ONLY be created after independent
# isolation testing. The guest cannot cryptographically attest the
# host and does not alter the VM NIC or firewall itself.
CallPersonalizer "Network" $conf $digest $true
[pscustomobject]@{result="COMMAND2_GUEST_AUTOMATIC_STATIC_IPV4_REQUESTED"
    guest=$config.guest_name;ip=$config.ipv4
    expected_mac=$config.nic_mac
    host_side_egress_independently_proven_here=$false} | ConvertTo-Json -Compress
