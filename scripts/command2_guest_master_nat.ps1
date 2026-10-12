#Requires -Version 5.1
<#
Command2 BENIGN Windows 11 master-style NAT personalization.
Never replaces the existing isolated-CAPE guest personalization script.
Requires separate JSON profile generated from host-verified default-NAT
libvirt one-NIC+DHCP reservations, pinned SHA256 and matching SMBIOS UUID.
Plan/Verify read-only; Apply changes only the exact Windows NIC to DHCP
(DNS from DHCP), and optionally requests a hostname change WITHOUT
automatically rebooting. Do not use while malware is running.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ConfigFile,
    [Parameter(Mandatory=$true)][string]$ExpectedSha256,
    [ValidateSet("Plan","Apply","Verify")][string]$Mode="Plan",
    [switch]$ApproveBenignNat,
    [switch]$ApproveRename,
    [switch]$RequireHTTPS
)
Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

function Deny([string]$message) {
    throw ("COMMAND2_MASTER_NAT_WINDOWS_BLOCKED: "+$message)
}
function AdminRequired {
    $user=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($user)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Deny "Guest Administrator/System required for configuration"
    }
}
function NormalMac([string]$mac) {
    return ($mac.ToUpperInvariant() -replace '[^0-9A-F]','')
}
function IPv4Number([string]$inputValue) {
    try { $address=[Net.IPAddress]::Parse($inputValue) }
    catch { Deny "Malformed candidate IPv4 field" }
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        Deny "IPv4 required for guest default NAT"
    }
    $x=$address.GetAddressBytes()
    return (([uint64]$x[0] -shl 24) -bor ([uint64]$x[1] -shl 16) -bor
            ([uint64]$x[2] -shl 8) -bor [uint64]$x[3])
}
function RequireGuest([object]$c) {
    if ([string]$c.format -cne "COMMAND2_MASTER_NAT_WINDOWS_V1") {
        Deny "Unexpected isolated or untrusted Windows configuration"
    }
    if ([string]$c.guest_name -cnotmatch '^win11_([1-9]|1[0-6])$') {
        Deny "Only count-driven win11_1..16 is allowed"
    }
    $number=[int]$Matches[1]
    if ([string]$c.hostname -cne ("WIN11-"+$number) -or
        [string]$c.nic_mac -cnotmatch '^02:(?:[0-9a-f]{2}:){4}[0-9a-f]{2}$' -or
        [string]$c.nic_network -cne "default" -or
        [string]$c.bridge -cne "virbr0" -or
        [string]$c.addressing -cne "libvirt_dhcp_reservation" -or
        [int]$c.expected_nic_count -ne 1 -or
        [int]$c.prefix_length -ne 24 -or
        $c.malware_public_internet_authorized -ne $false -or
        $c.network_isolation_proved_by_this_profile -ne $false) {
        Deny "Guest NAT profile identity, no-isolation or DHCP contract differs"
    }
    try {
        $expected=[guid]([string]$c.expected_machine_uuid)
        $actual=[guid]([string](Get-CimInstance Win32_ComputerSystemProduct).UUID)
    } catch { Deny "Windows SMBIOS identity cannot be checked" }
    if ($expected -ne $actual) { Deny "Wrong Windows guest UUID" }
    $netParts=[string]$c.subnet -split '/'
    if ($netParts.Count -ne 2 -or $netParts[1] -cne "24") {
        Deny "Master equivalent NAT requires canonical /24"
    }
    $subnet=IPv4Number $netParts[0]
    $gateway=IPv4Number ([string]$c.default_gateway)
    $dns=IPv4Number ([string]$c.dns_ipv4)
    $ipv4=IPv4Number ([string]$c.ipv4)
    if ($subnet -ne ($subnet -band [uint64]0xffffff00) -or
        $gateway -ne ($subnet+1) -or $dns -ne $gateway -or
        $ipv4 -lt ($subnet+201) -or $ipv4 -gt ($subnet+216)) {
        Deny "Guest IP/Gateway/DNS do not match approved master NAT pool"
    }
    $first=[int](($subnet -shr 24) -band 255)
    $second=[int](($subnet -shr 16) -band 255)
    if (-not ($first -eq 10 -or ($first -eq 172 -and
        $second -ge 16 -and $second -le 31) -or
        ($first -eq 192 -and $second -eq 168))) {
        Deny "Unexpected non-RFC1918 NAT address"
    }
    $adapters=@(Get-NetAdapter -Physical -ErrorAction Stop)
    if ($adapters.Count -ne 1 -or
        (NormalMac ([string]$adapters[0].MacAddress)) -cne
        (NormalMac ([string]$c.nic_mac))) {
        Deny "Exactly ONE expected NAT NIC MAC must be present"
    }
    return $adapters[0]
}
if ($ConfigFile.StartsWith("\\") -or
    -not [IO.Path]::IsPathRooted($ConfigFile) -or
    -not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) {
    Deny "Only existing absolute local JSON profile allowed"
}
if ($ExpectedSha256 -cnotmatch '^[0-9a-fA-F]{64}$') {
    Deny "Expected pinned 64-character SHA256 digest"
}
if ((Get-FileHash -LiteralPath $ConfigFile -Algorithm SHA256).Hash -ine
    $ExpectedSha256) {
    Deny "Master NAT Windows JSON SHA256 mismatch"
}
try {
    $conf=Get-Content -LiteralPath $ConfigFile -Encoding UTF8 -Raw |
        ConvertFrom-Json
} catch { Deny "Invalid Windows NAT JSON configuration" }
$nic=RequireGuest $conf
$index=[int]$nic.ifIndex
$ipinterfaces=@(Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop)
if ($ipinterfaces.Count -ne 1) { Deny "Ambiguous matching IPv4 interface" }
$ipv4s=@(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop)
$unapproved=@($ipv4s | Where-Object {
    $_.IPAddress -ne [string]$conf.ipv4 -and
    $_.IPAddress -notlike "169.254.*"
})
if ($unapproved.Count -ne 0) {
    Deny "Existing foreign IPv4 on expected NIC; refuse overwrite"
}
$existingTarget=@($ipv4s | Where-Object {
    $_.IPAddress -eq [string]$conf.ipv4 -and $_.PrefixLength -eq 24
})
if ($existingTarget.Count -gt 1) { Deny "Duplicate target IPv4" }

if ($Mode -eq "Plan") {
    [pscustomobject]@{
        result="COMMAND2_WINDOWS_MASTER_NAT_PLAN_ONLY"
        nic_verified=$true
        uuid_verified=$true
        expected_ipv4=[string]$conf.ipv4
        existing_target_ipv4=($existingTarget.Count -eq 1)
        current_dhcp=[string]$ipinterfaces[0].Dhcp
        target_hostname=[string]$conf.hostname
        actual_hostname=[Environment]::MachineName
        guest_changes_made=$false
        sample_execution_authorized=$false
    } | ConvertTo-Json -Compress
    exit 0
}

if ($Mode -eq "Apply") {
    AdminRequired
    if (-not $ApproveBenignNat) {
        Deny "Explicit -ApproveBenignNat required to configure internet"
    }
    # DHCP may already be working, as proven on SSL55. A legacy static
    # IP that differs from the chosen reservation is NOT silently removed.
    if ([string]$ipinterfaces[0].Dhcp -ne "Enabled") {
        if ($existingTarget.Count -ne 0) {
            Deny "Existing static IPv4 requires separate manual review"
        }
        Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop
    }
    # Return to DHCP-provided DNS rather than leaving cloned master DNS.
    Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses -ErrorAction Stop
    & ipconfig.exe /renew ([string]$nic.Name) | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Deny "Windows DHCP renewal failed; do not restart automatically"
    }
    $renameRequested=$false
    if ([Environment]::MachineName -ine [string]$conf.hostname) {
        if (-not $ApproveRename) {
            Deny "Expected hostname differs; explicit -ApproveRename required"
        }
        Rename-Computer -NewName ([string]$conf.hostname) -Force
        $renameRequested=$true
    }
    [pscustomobject]@{
        result="COMMAND2_WINDOWS_MASTER_NAT_DHCP_APPLY_ATTEMPTED"
        expected_mac=[string]$conf.nic_mac
        target_ip=[string]$conf.ipv4
        hostname_restart_needed=$renameRequested
        independent_Verify_mode_required=$true
        malicious_sample_execution_authorized=$false
    } | ConvertTo-Json -Compress
    exit 0
}

if ([Environment]::MachineName -ine [string]$conf.hostname) {
    Deny "Unique Windows hostname not effective; reboot after explicit rename"
}
if ([string]$ipinterfaces[0].Dhcp -ne "Enabled" -or
    $existingTarget.Count -ne 1) {
    Deny "DHCP enabled and exact NAT IP/prefix not yet verified"
}
$routes=@(Get-NetRoute -InterfaceIndex $index -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
    Where-Object { $_.NextHop -eq [string]$conf.default_gateway })
if ($routes.Count -ne 1) {
    Deny "NAT IPv4 default gateway route differs"
}
$servers=@(Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop)
if ($servers.Count -ne 1 -or
    [string]$conf.dns_ipv4 -notin @($servers[0].ServerAddresses)) {
    Deny "Windows NAT DNS differs from verified default gateway"
}
$httpsOk=$false
if ($RequireHTTPS) {
    $tcp=Test-NetConnection -ComputerName www.microsoft.com -Port 443 -InformationLevel Detailed -WarningAction SilentlyContinue
    if ($tcp.TcpTestSucceeded -ne $true -or
        [string]$tcp.SourceAddress -ne [string]$conf.ipv4) {
        Deny "External HTTPS/TCP 443 did not use the expected NAT IPv4"
    }
    try {
        $head=Invoke-WebRequest -Uri "https://www.microsoft.com" -Method Head -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
    } catch { Deny "Windows real HTTPS HEAD failed; no internet claim" }
    $httpsOk=([int]$head.StatusCode -ge 200 -and
              [int]$head.StatusCode -lt 400)
    if (-not $httpsOk) { Deny "HTTPS status outside accepted 2xx/3xx" }
}
[pscustomobject]@{
    result="COMMAND2_WINDOWS_MASTER_NAT_READONLY_VERIFIED"
    vm_name=[string]$conf.guest_name
    hostname_verified=$true
    one_nic_mac_verified=$true
    dhcp_reserved_ip_observed=$true
    gateway_verified=$true
    dns_verified=$true
    external_https_witnessed=$httpsOk
    sample_execution_authorized=$false
    this_command_modified_guest=$false
} | ConvertTo-Json -Compress
