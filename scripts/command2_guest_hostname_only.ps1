# Command 2A - safely stage hostname-only personalization in a ZERO-NIC Windows clone.
# Run INSIDE the Windows guest as Administrator, never on the Ubuntu host.
# Read-only by default. Rename mode changes the Windows hostname only; it does not touch NICs, IPs, firewall, TPM, CAPE, or reboot.
# Test invocation:
#   .\command2_guest_hostname_only.ps1 -ExpectedUuid '732b2256-ee99-41fa-881d-fbf5c476d960' -OldName 'Win' -NewName 'WIN11-1'
# Authorized guest-only rename:
#   .\command2_guest_hostname_only.ps1 -ExpectedUuid '732b2256-ee99-41fa-881d-fbf5c476d960' -OldName 'Win' -NewName 'WIN11-1' -Mode Rename
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExpectedUuid,
    [Parameter(Mandatory=$true)][string]$OldName,
    [Parameter(Mandatory=$true)][string]$NewName,
    [ValidateSet('Plan','Rename')][string]$Mode = 'Plan'
)
$ErrorActionPreference = 'Stop'
function Block([string]$Reason) { throw ('BLOCKED: ' + $Reason) }
if ($NewName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$' -or
    $NewName -match '^[0-9]+$') {
    Block 'Target must be a valid <=15-character nonnumeric Windows hostname.'
}
if ($OldName -ieq $NewName) { Block 'Old and new hostname must differ.' }
try { $id = [guid]$ExpectedUuid } catch { Block 'Expected UUID is malformed.' }
try { $guestId = [guid]((Get-CimInstance Win32_ComputerSystemProduct).UUID) }
catch { Block 'Cannot read guest SMBIOS UUID.' }
if ($guestId -ne $id) { Block 'Wrong Windows guest UUID; no changes made.' }
$current = [Environment]::MachineName
if ($current -ieq $NewName) {
    Write-Output 'ALREADY_TARGET_NAME: restart and verification may have been completed separately.'
    exit 0
}
if ($current -ine $OldName) { Block 'Guest hostname differs from expected source.' }
$win = Get-CimInstance Win32_ComputerSystem
if ($win.PartOfDomain) { Block 'Unexpected domain-joined Windows installation.' }
$adapters = @(Get-NetAdapter -ErrorAction Stop)
if ($adapters.Count -ne 0) { Block 'A guest network adapter is present; refusing hostname-only acceptance.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Block 'Elevated Administrator PowerShell is required.' }
Write-Output ('PREFLIGHT_PASS: UUID=' + $guestId.ToString())
Write-Output ('PREFLIGHT_PASS: CurrentName=' + $current + '; TargetName=' + $NewName)
Write-Output 'PREFLIGHT_PASS: Get-NetAdapter has zero adapters; guest is not domain-joined.'
if ($Mode -eq 'Plan') {
    Write-Output 'PLAN_ONLY: Nothing changed. Re-run with -Mode Rename only after approval.'
    exit 0
}
$ack = Read-Host ('Type RENAME-' + $NewName + ' to authorize guest-only hostname rename')
if ($ack -cne ('RENAME-' + $NewName)) {
    Write-Output 'ABORTED: No changes made.'
    exit 2
}
# No -Restart. A deliberate separate Windows restart will be approved later.
Rename-Computer -NewName $NewName -Force -ErrorAction Stop
Write-Output 'RENAME_REQUESTED: Windows hostname update submitted successfully.'
Write-Output 'RESTART_REQUIRED: Do NOT restart automatically; operator should inspect output.'
Write-Output 'NO_NETWORK_CHANGES: No IP, NIC, gateway, firewall or host settings were modified.'
