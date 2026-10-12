#Requires -Version 5.1
<#
BENIGN isolated-guest proof, SSL55 pilot win11_1 ONLY.
Read-only Windows NIC/routes, 4 outbound *benign* bounded TCP attempts.
No downloads, payload transfer, sample execution, config or firewall changes.
Do not infer L2/peer isolation or general internet denial from 4 probes.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Report=Join-Path $env:PUBLIC 'Documents\CAPE_Command2_GuestEgressProbe.txt'
$ExpectedHost='WIN11-1'
$ExpectedMac='02-0A-30-6A-3F-50'
$ExpectedIPv4='192.168.240.101'
$ExpectedPrefix=24
$rows=New-Object 'System.Collections.Generic.List[string]'
function Record([string]$key,[string]$value) {
    [void]$rows.Add(($key+'='+$value))
}
function Probe-TCP([string]$target,[int]$port) {
    $client=New-Object System.Net.Sockets.TcpClient
    try {
        $ip=[System.Net.IPAddress]::Parse($target)
        $task=$client.BeginConnect($ip,$port,$null,$null)
        try {
            if (-not $task.AsyncWaitHandle.WaitOne(2500,$false)) { return 'TIMEOUT' }
            try {
                $client.EndConnect($task)
                return 'CONNECTED_UNSAFE'
            } catch {
                return 'FAILED_'+$_.Exception.GetType().Name
            }
        } finally {
            $task.AsyncWaitHandle.Close()
        }
    } catch {
        return 'ERROR_'+$_.Exception.GetType().Name
    } finally {
        $client.Dispose()
    }
}
$fail=$false
try {
    Record 'RESULT_TYPE' 'BENIGN_GUEST_IPV4_IPV6_EGRESS_PROBES_V1'
    Record 'DATE_LOCAL' ([DateTime]::Now.ToString('o'))
    $hostName=[Environment]::MachineName
    Record 'WINDOWS_HOSTNAME' $hostName
    if ($hostName -ne $ExpectedHost) { $fail=$true; Record 'HOSTNAME' 'UNEXPECTED' }
    $physical=@(Get-NetAdapter -Physical -ErrorAction Stop)
    $connected=@($physical | Where-Object { $_.Status -eq 'Up' })
    Record 'PHYSICAL_NIC_COUNT' ([string]$physical.Count)
    Record 'CONNECTED_PHYSICAL_NIC_COUNT' ([string]$connected.Count)
    if ($connected.Count -ne 1) { $fail=$true; Record 'ONE_PHYSICAL_NIC' 'FAILED' }
    if ($connected.Count -eq 1) {
        $card=$connected[0]
        Record 'CONNECTED_MAC' ([string]$card.MacAddress)
        if ($card.MacAddress.ToUpperInvariant() -ne $ExpectedMac) {
            $fail=$true
            Record 'EXPECTED_MAC' 'FAILED'
        }
        $ips=@(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $card.ifIndex -ErrorAction Stop |
            Where-Object { $_.IPAddress -ne '127.0.0.1' })
        $matching=@($ips | Where-Object { $_.IPAddress -eq $ExpectedIPv4 -and
                    $_.PrefixLength -eq $ExpectedPrefix })
        Record 'EXPECTED_STATIC_IPV4' ([string]($matching.Count -eq 1))
        Record 'NON_LOOPBACK_IPV4_COUNT' ([string]$ips.Count)
        if ($matching.Count -ne 1 -or $ips.Count -ne 1) { $fail=$true }
    }
    $routes4=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop)
    $routes6=@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction Stop)
    Record 'IPv4_DEFAULT_ROUTE_COUNT' ([string]$routes4.Count)
    Record 'IPv6_DEFAULT_ROUTE_COUNT' ([string]$routes6.Count)
    if ($routes4.Count -ne 0 -or $routes6.Count -ne 0) {
        $fail=$true
        Record 'GUEST_DEFAULT_ROUTE_GUARD' 'FAILED'
    } else {
        Record 'GUEST_DEFAULT_ROUTE_GUARD' 'PASS'
    }
    $outcomes=@{}
    $outcomes['IPv4_1_1_1_1_443']=Probe-TCP '1.1.1.1' 443
    $outcomes['IPv4_8_8_8_8_53']=Probe-TCP '8.8.8.8' 53
    $outcomes['IPv6_2606_4700_4700__1111_443']=Probe-TCP '2606:4700:4700::1111' 443
    $outcomes['IPv6_2001_4860_4860__8888_443']=Probe-TCP '2001:4860:4860::8888' 443
    foreach ($key in @($outcomes.Keys | Sort-Object)) {
        Record $key $outcomes[$key]
        if ($outcomes[$key] -eq 'CONNECTED_UNSAFE' -or
            $outcomes[$key].StartsWith('ERROR_')) {
            $fail=$true
        }
    }
    Record 'ALL_FOUR_BENIGN_CONNECTIONS_DENIED' ([string](
        @($outcomes.Values | Where-Object { $_ -ne 'CONNECTED_UNSAFE' -and
           (-not $_.StartsWith('ERROR_')) }).Count -eq 4))
    Record 'GUEST_NEGATIVE_PROBE_RESULT' $(if ($fail) { 'FAIL_OR_INCONCLUSIVE' } else { 'PASS_TARGETED_PROBES_ONLY' })
    Record 'REAL_L2_LATERAL_TEST' 'NOT_PERFORMED'
    Record 'FULL_HOST_EGRESS_GUARANTEE' 'NOT_PROVEN'
    Record 'WINDOWS_NETWORK_CHANGES' 'NONE'
} catch {
    Record 'GUEST_NEGATIVE_PROBE_RESULT' 'FAIL_OR_INCONCLUSIVE'
    Record 'PROBE_ERROR_KIND' $_.Exception.GetType().Name
    Record 'REAL_L2_LATERAL_TEST' 'NOT_PERFORMED'
    Record 'WINDOWS_NETWORK_CHANGES' 'NONE'
}
try {
    $rows | Set-Content -LiteralPath $Report -Encoding UTF8 -ErrorAction Stop
    Write-Host ('PROBE_REPORT: '+$Report)
    Start-Process -FilePath "$env:SystemRoot\system32\notepad.exe" -ArgumentList ('"'+$Report+'"')
} catch {
    Write-Host ('CANNOT_SAVE_PROBE_REPORT: '+$_.Exception.GetType().Name)
    foreach ($row in $rows) { Write-Host $row }
}
