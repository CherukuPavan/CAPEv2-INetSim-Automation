#Requires -Version 5.1
<#
Command2 first ONE-NIC benign configuration on isolated Windows clone.
Generic for win11_1..win11_16. Requires exact SMBIOS UUID and NIC MAC,
one physical adapter, no IPv4/IPv6 default routes, no other non-APIPA
IPv4, elevated administrator, explicit -ApproveBenignSetup.
Does not disable Windows firewall/security, add gateway/DNS, download,
execute samples, or claim IPv4/IPv6 containment. Rename needs guest reboot.
Modes: Plan, Apply, Verify (all return JSON only).
#>
[CmdletBinding()]
param(
 [ValidateSet("Plan","Apply","Verify")][string]$Mode="Plan",
 [Parameter(Mandatory=$true)][ValidateRange(1,16)][int]$GuestIndex,
 [Parameter(Mandatory=$true)][string]$ExpectedUuid,
 [Parameter(Mandatory=$true)][string]$ExpectedMac,
 [Parameter(Mandatory=$true)][string]$ExpectedIPv4,
 [switch]$ApproveBenignSetup
)
Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

function Block([string]$Message) { throw ("COMMAND2_ONE_NIC_BLOCKED: "+$Message) }
function NormalMac([string]$Mac) { return (($Mac.ToUpperInvariant() -replace '[^0-9A-F]','')) }
function Admin {
  $current=[Security.Principal.WindowsIdentity]::GetCurrent()
  $who=New-Object Security.Principal.WindowsPrincipal($current)
  if (-not $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Block "Run elevated as local Windows administrator"
  }
}
function Emit([string]$Result,[bool]$Changed,[bool]$IpOk,[bool]$NameOk) {
  [pscustomobject]@{
    result=$Result
    guest_index=$GuestIndex
    expected_hostname=("WIN11-"+$GuestIndex)
    expected_ipv4=$ExpectedIPv4
    expected_mac=$ExpectedMac
    hostname_matches=$NameOk
    static_ipv4_matches=$IpOk
    no_ipv4_or_ipv6_default_gateway=$true
    changes_applied=$Changed
    host_egress_isolation_proved=$false
    malware_analysis_authorized=$false
    running_snapshot_verified=$false
  } | ConvertTo-Json -Compress
}

if ($ExpectedUuid -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
  Block "Expected UUID not lowercase canonical"
}
if ($ExpectedMac -cnotmatch '^02:(?:[0-9a-f]{2}:){4}[0-9a-f]{2}$') {
  Block "Wrong reserved lowercase MAC format"
}
try { $actualUuid=[guid]([string](Get-CimInstance Win32_ComputerSystemProduct).UUID) }
catch { Block "Could not read SMBIOS UUID" }
if ($actualUuid -ne [guid]$ExpectedUuid) { Block "Wrong guest SMBIOS UUID" }
if (-not $ExpectedIPv4.StartsWith("192.168.240.")) {
  Block "Unexpected isolated CAPE subnet"
}
$expectedIP="192.168.240."+(100+$GuestIndex)
if ($ExpectedIPv4 -cne $expectedIP) { Block "Guest IPv4 does not match sequential IP allocation" }
$adapterList=@(Get-NetAdapter -Physical -ErrorAction Stop)
if ($adapterList.Count -ne 1) { Block "Exactly one physical NIC required" }
$nic=$adapterList[0]
if ((NormalMac ([string]$nic.MacAddress)) -cne (NormalMac $ExpectedMac)) {
  Block "Actual NIC MAC differs from host reservation"
}
$routes4=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue)
$routes6=@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "::/0" -ErrorAction SilentlyContinue)
if ($routes4.Count -ne 0 -or $routes6.Count -ne 0) {
  Block "Unexpected IPv4/IPv6 default route (do not configure under uncertain routing)"
}
$allV4=@(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $nic.ifIndex -ErrorAction Stop)
$unexpected=@($allV4 | Where-Object {
  $_.IPAddress -ne $ExpectedIPv4 -and $_.IPAddress -notlike "169.254.*"
})
if ($unexpected.Count -ne 0) { Block "Unexpected existing IPv4 address" }
$valid=@($allV4 | Where-Object {
  $_.IPAddress -eq $ExpectedIPv4 -and $_.PrefixLength -eq 24
})
$invalidPrefix=@($allV4 | Where-Object {
  $_.IPAddress -eq $ExpectedIPv4 -and $_.PrefixLength -ne 24
})
if ($invalidPrefix.Count -ne 0) { Block "Expected IP exists with wrong subnet prefix" }
$name="WIN11-"+$GuestIndex
$correctName=[Environment]::MachineName -ieq $name
$correctIp=$valid.Count -eq 1
if ($Mode -eq "Plan") {
  Emit "COMMAND2_ONE_NIC_GUEST_READONLY_PLAN" $false $correctIp $correctName
  exit 0
}
if ($Mode -eq "Verify") {
  Emit "COMMAND2_ONE_NIC_GUEST_READONLY_VERIFY" $false $correctIp $correctName
  if (-not $correctIp -or -not $correctName) { exit 2 }
  exit 0
}
Admin
if (-not $ApproveBenignSetup) { Block "Explicit benign-only change approval missing" }
$changed=$false
if (-not $correctIp) {
  Set-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
  New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $ExpectedIPv4 -PrefixLength 24 -AddressFamily IPv4 -ErrorAction Stop | Out-Null
  $changed=$true
}
if (-not $correctName) {
  Rename-Computer -NewName $name -Force -ErrorAction Stop
  $changed=$true
}
# Verify applied address and still no default routes; hostname rename
# is reboot-pending, so not claim updated hostname before guest restart.
$after=@(Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction Stop |
  Where-Object { $_.IPAddress -eq $ExpectedIPv4 -and $_.PrefixLength -eq 24 })
if ($after.Count -ne 1) { Block "Guest static IPv4 postcondition failed" }
if (@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue).Count -ne 0 -or
    @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "::/0" -ErrorAction SilentlyContinue).Count -ne 0) {
  Block "A default gateway appeared after benign configuration"
}
Emit "COMMAND2_ONE_NIC_BENIGN_STATIC_IP_SET_GUEST_RENAME_MAY_NEED_REBOOT" $changed $true $correctName
