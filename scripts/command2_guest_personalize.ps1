#Requires -Version 5.1
<#
This script executes ONLY inside the authorized Windows 11 analysis clone.
Phases: Plan, Identity (ZERO NIC), Network (host isolation verified), Verify.
The future Command 1 bootstrap must install/invoke it: this file is not
automatically executed by a libvirt guest definition.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ConfigFile,
  [Parameter(Mandatory=$true)][string]$ExpectedSha256,
  [ValidateSet("Plan","Identity","Network","Verify")][string]$Mode="Plan",
  [switch]$HostIsolationVerified,
  [switch]$RestartAfterIdentity
)
Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

function Deny([string]$why) { throw ("COMMAND2_BLOCKED: "+$why) }
function GuestAdminRequired {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  $principal=New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Deny "Guest administrator privileges required"
  }
}
function CleanMac([string]$value) {
  if ($null -eq $value) { return "" }
  return ($value.ToUpperInvariant() -replace "[^0-9A-F]","")
}
function IPv4Number([string]$value) {
  try { $parsed=[System.Net.IPAddress]::Parse($value) }
  catch { Deny "Malformed IPv4 address" }
  if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    Deny "Not an IPv4 address"
  }
  $b=$parsed.GetAddressBytes()
  return (([uint64]$b[0] -shl 24) -bor ([uint64]$b[1] -shl 16) -bor ([uint64]$b[2] -shl 8) -bor [uint64]$b[3])
}

if ($ConfigFile.StartsWith("\\") -or -not [System.IO.Path]::IsPathRooted($ConfigFile)) {
  Deny "Config must be local absolute path, not UNC"
}
if ($ExpectedSha256 -notmatch "^[a-fA-F0-9]{64}$" -or
    -not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) {
  Deny "Trusted configuration and SHA256 are required"
}
$actualHash=(Get-FileHash -LiteralPath $ConfigFile -Algorithm SHA256).Hash
if ($actualHash -ine $ExpectedSha256) { Deny "Guest config SHA256 mismatch" }
try { $cfg=Get-Content -LiteralPath $ConfigFile -Encoding UTF8 -Raw | ConvertFrom-Json }
catch { Deny "Invalid JSON config" }
if ($cfg.format -cne "COMMAND2_GUEST_PERSONALIZATION_V1") { Deny "Unexpected config schema" }
if ([string]$cfg.guest_name -cnotmatch "^win11_([1-9][0-9]{0,2})$") {
  Deny "Unexpected guest name"
}
$index=[int]$Matches[1]
if ([string]$cfg.hostname -cne ("WIN11-"+$index)) { Deny "Wrong Windows hostname" }
if ([string]$cfg.nic_mac -cnotmatch "^02:(?:[0-9a-f]{2}:){4}[0-9a-f]{2}$") {
  Deny "Wrong reserved NIC MAC"
}
if ($cfg.default_gateway -ne $null -or
    $cfg.auto_apply_network -ne $false -or
    $cfg.host_isolation_must_be_independently_verified -ne $true) {
  Deny "Automatic networking or a default gateway was requested"
}
$prefix=[int]$cfg.prefix_length
if ($prefix -lt 16 -or $prefix -gt 30) { Deny "Invalid prefix length" }
if ([string]$cfg.subnet -cnotmatch "^([0-9.]+)/([0-9]{1,2})$") {
  Deny "Malformed analysis subnet"
}
$netText=[string]$Matches[1]
$netPrefix=[int]$Matches[2]
if ($prefix -ne $netPrefix) { Deny "IPv4 prefix and subnet disagree" }
$net=IPv4Number $netText
$addr=IPv4Number ([string]$cfg.ipv4)
$mask=(([uint64]0xffffffff -shl (32-$prefix)) -band [uint64]0xffffffff)
$bcast=($net -bor ((-bnot $mask) -band [uint64]0xffffffff))
if (($net -band $mask) -ne $net -or ($addr -band $mask) -ne $net -or
    $addr -eq $net -or $addr -eq $bcast) {
  Deny "Requested guest IPv4 is not a usable on-subnet address"
}
try { $vmid=[guid]([string]$cfg.expected_machine_uuid) }
catch { Deny "Invalid expected guest libvirt UUID" }
try { $actual=[guid]([string](Get-CimInstance Win32_ComputerSystemProduct).UUID) }
catch { Deny "Guest does not expose a valid SMBIOS UUID" }
if ($actual -ne $vmid) { Deny "Wrong VM! SMBIOS UUID mismatch" }

$adapters=@(Get-NetAdapter -Physical -ErrorAction Stop)
$current=[Environment]::MachineName
if ($Mode -eq "Plan") {
  [pscustomobject]@{ result="COMMAND2_GUEST_PERSONALIZATION_PLAN_ONLY"
    uuid_verified=$true; actual_hostname=$current; target_hostname=$cfg.hostname
    target_ipv4=$cfg.ipv4; physical_nic_count=$adapters.Count; no_changes_made=$true } | ConvertTo-Json -Compress
  exit 0
}
if ($Mode -eq "Identity") {
  GuestAdminRequired
  if ($adapters.Count -ne 0) { Deny "Identity phase requires ZERO guest NICs" }
  if ($current -ieq [string]$cfg.hostname) {
    [pscustomobject]@{ result="COMMAND2_WINDOWS_HOSTNAME_ALREADY_SET"; changed=$false } | ConvertTo-Json -Compress
    exit 0
  }
  Rename-Computer -NewName ([string]$cfg.hostname) -Force -ErrorAction Stop
  [pscustomobject]@{ result="COMMAND2_WINDOWS_RENAME_REQUESTED_REBOOT_REQUIRED"
    target=$cfg.hostname; network_changed=$false } | ConvertTo-Json -Compress
  if ($RestartAfterIdentity) { Restart-Computer -Force }
  exit 0
}
if ($current -ine [string]$cfg.hostname) { Deny "Hostname has not been renamed/rebooted" }
$wantedMac=CleanMac ([string]$cfg.nic_mac)
$matching=@($adapters | Where-Object { (CleanMac ([string]$_.MacAddress)) -eq $wantedMac })
if ($adapters.Count -ne 1 -or $matching.Count -ne 1) {
  Deny "Exactly one reserved isolated NIC must be present"
}
$nic=$matching[0]
$routes=@(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $nic.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
if ($routes.Count -ne 0) { Deny "Unexpected default route on isolated guest NIC" }
$addresses=@(Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction Stop)
$other=@($addresses | Where-Object {
  $_.IPAddress -ne [string]$cfg.ipv4 -and $_.IPAddress -notlike "169.254.*"
})
if ($other.Count -ne 0) { Deny "Unexpected existing guest IP; no overwrite" }
$matchingIP=@($addresses | Where-Object {
  $_.IPAddress -eq [string]$cfg.ipv4 -and $_.PrefixLength -eq $prefix
})
if ($Mode -eq "Verify") {
  [pscustomobject]@{ result="COMMAND2_GUEST_NETWORK_READONLY_VERIFICATION"
    hostname_verified=$true; nic_mac_verified=$true
    expected_static_ipv4_present=($matchingIP.Count -eq 1)
    default_route_present=$false; no_changes_made=$true } | ConvertTo-Json -Compress
  exit 0
}
if ($Mode -ne "Network") { Deny "Invalid personalization mode" }
if (-not $HostIsolationVerified) {
  Deny "Host must independently prove IPv4/IPv6 isolation and reboot persistence before NETWORK mode"
}
GuestAdminRequired
if ($matchingIP.Count -eq 0) {
  Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
  New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress ([string]$cfg.ipv4) -PrefixLength $prefix -AddressFamily IPv4 -ErrorAction Stop | Out-Null
}
[pscustomobject]@{ result="COMMAND2_WINDOWS_STATIC_IPV4_APPLIED_OR_VERIFIED"
  hostname=$cfg.hostname; ipv4=$cfg.ipv4; mac=$cfg.nic_mac
  gateway_added=$false } | ConvertTo-Json -Compress
