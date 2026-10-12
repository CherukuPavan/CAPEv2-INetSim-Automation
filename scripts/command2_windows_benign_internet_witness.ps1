#requires -Version 5.1
<#
BENIGN Windows 11 temporary NAT Internet witness, READ-ONLY.
Requires previously approved trusted-setup Ubuntu session to be active.
Does NOT change networking, Windows security, snapshots or execute samples.
#>
[CmdletBinding()]
param(
    [string]$ExpectedMAC='02:CA:55:11:01:01',
    [string]$TestHost='www.microsoft.com'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$target=($ExpectedMAC -replace '[:-]','').ToUpperInvariant()
$report=[ordered]@{
    result='COMMAND2_WINDOWS_TRUSTED_SETUP_INTERNET_WITNESS'
    temporary_nic_present=$false
    nic_up=$false
    ipv4_dhcp_enabled=$false
    ipv4_address_present=$false
    ipv4_default_gateway_present=$false
    external_dns_a_record_resolved=$false
    external_tcp443_reachable=$false
    https_response_received=$false
    internet_verified=$false
    malware_analysis_authorized=$false
    modifications_made=$false
    errors=@()
}
function Check([string]$label,[scriptblock]$script) {
    try { & $script }
    catch { $report.errors+=($label+': '+$_.Exception.Message) }
}
Check 'adapter' {
    $matching=@(Get-NetAdapter -ErrorAction Stop | Where-Object {
        (($_.MacAddress -replace '[:-]','').ToUpperInvariant()) -eq $target
    })
    if ($matching.Count -ne 1) {
        throw "Expected exactly one temporary NIC matching $ExpectedMAC"
    }
    $nic=$matching[0]
    $report.temporary_nic_present=$true
    $report.nic_up=($nic.Status -eq 'Up')
    if (-not $report.nic_up) { throw 'Adapter is not Up' }
    $intf=Get-NetIPInterface -InterfaceIndex $nic.ifIndex -AddressFamily IPv4
    $report.ipv4_dhcp_enabled=($intf.Dhcp -eq 'Enabled')
    $cfg=Get-NetIPConfiguration -InterfaceIndex $nic.ifIndex
    $report.ipv4_address_present=($null -ne $cfg.IPv4Address)
    $report.ipv4_default_gateway_present=($null -ne $cfg.IPv4DefaultGateway)
}
if ($report.nic_up -and $report.ipv4_dhcp_enabled -and $report.ipv4_address_present -and $report.ipv4_default_gateway_present) {
    Check 'dns' {
        $answer=@(Resolve-DnsName -Name $TestHost -Type A -ErrorAction Stop)
        $report.external_dns_a_record_resolved=(@($answer | Where-Object { $_.Type -eq 'A' -and $_.IPAddress }).Count -gt 0)
    }
    if ($report.external_dns_a_record_resolved) {
        Check 'tcp443' {
            $report.external_tcp443_reachable=[bool](Test-NetConnection -ComputerName $TestHost -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue)
        }
        Check 'https' {
            $response=Invoke-WebRequest -Uri ('https://'+$TestHost+'/') -Method Get -UseBasicParsing -TimeoutSec 20 -MaximumRedirection 5
            $report.https_response_received=($response.StatusCode -ge 200 -and $response.StatusCode -lt 400)
        }
    }
}
$report.internet_verified=(
    $report.temporary_nic_present -and $report.nic_up -and
    $report.ipv4_dhcp_enabled -and $report.ipv4_address_present -and
    $report.ipv4_default_gateway_present -and
    $report.external_dns_a_record_resolved -and
    $report.external_tcp443_reachable -and
    $report.https_response_received
)
$report | ConvertTo-Json -Depth 5
if (-not $report.internet_verified) { exit 2 }
exit 0
