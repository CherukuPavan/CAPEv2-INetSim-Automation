#Requires -Version 5.1
<#
Benign guest-only IPv4/IPv6 egress probe v2. SSL55 win11_1 only.
No networking changes, payloads, samples, DNS, downloads or firewall edits.
Route inventory enumerates ALL routes before filtering default routes;
a missing 0.0.0.0/0 or ::/0 MUST be reported as zero, not a CIM error.
Socket results only prove those targets at that time; not L2 isolation.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Report=Join-Path $env:PUBLIC 'Documents\CAPE_Command2_GuestEgressProbe_V2.txt'
$ExpectedHost='WIN11-1'
$ExpectedMac='02-0A-30-6A-3F-50'
$ExpectedIPv4='192.168.240.101'
$ExpectedPrefix=24
$rows=New-Object 'System.Collections.Generic.List[string]'
$inconclusive=$false
$unsafe=$false
function Record([string]$key,[string]$value) {
    [void]$rows.Add(($key+'='+$value))
}
function Probe-TCP([string]$target,[int]$port) {
    $client=$null
    $async=$null
    try {
        $ip=[System.Net.IPAddress]::Parse($target)
        $client=[System.Net.Sockets.TcpClient]::new($ip.AddressFamily)
        $async=$client.BeginConnect($ip,$port,$null,$null)
        if (-not $async.AsyncWaitHandle.WaitOne(2500,$false)) {
            return 'TIMEOUT'
        }
        try {
            $client.EndConnect($async)
            return 'CONNECTED_UNSAFE'
        } catch [System.Net.Sockets.SocketException] {
            return ('SOCKET_FAILED_'+[string]$_.Exception.SocketErrorCode)
        }
    } catch [System.Net.Sockets.SocketException] {
        return ('SOCKET_FAILED_'+[string]$_.Exception.SocketErrorCode)
    } catch {
        return ('PROBE_ERROR_'+$_.Exception.GetType().Name)
    } finally {
        if ($null -ne $async) { $async.AsyncWaitHandle.Close() }
        if ($null -ne $client) { $client.Dispose() }
    }
}
function Get-DefaultRoutesCount([string]$family,[string]$prefix) {
    # Query ALL family routes; no exact-prefix CIM query is permitted here.
    try {
        $all=@(Get-NetRoute -AddressFamily $family -ErrorAction Stop)
        $defaults=@($all | Where-Object { $_.DestinationPrefix -eq $prefix })
        Record ($family+'_ROUTE_QUERY') 'SUCCESS'
        Record ($family+'_DEFAULT_ROUTE_COUNT') ([string]$defaults.Count)
        return $defaults.Count
    } catch {
        Record ($family+'_ROUTE_QUERY') ('INCONCLUSIVE_'+$_.Exception.GetType().Name)
        Record ($family+'_DEFAULT_ROUTE_COUNT') 'UNKNOWN'
        $script:inconclusive=$true
        return $null
    }
}
try {
    Record 'RESULT_TYPE' 'BENIGN_GUEST_IPV4_IPV6_EGRESS_PROBES_V2'
    Record 'DATE_LOCAL' ([DateTime]::Now.ToString('o'))
    $hostname=[Environment]::MachineName
    Record 'WINDOWS_HOSTNAME' $hostname
    if ($hostname -ne $ExpectedHost) { $inconclusive=$true; Record 'EXPECTED_HOSTNAME' 'FALSE' }
    $physical=@(Get-NetAdapter -Physical -ErrorAction Stop)
    $connected=@($physical | Where-Object { $_.Status -eq 'Up' })
    Record 'PHYSICAL_NIC_COUNT' ([string]$physical.Count)
    Record 'CONNECTED_PHYSICAL_NIC_COUNT' ([string]$connected.Count)
    if ($physical.Count -ne 1 -or $connected.Count -ne 1) {
        $inconclusive=$true
        Record 'ONE_PHYSICAL_NIC' 'FALSE'
    } else {
        Record 'ONE_PHYSICAL_NIC' 'TRUE'
    }
    if ($connected.Count -eq 1) {
        $card=$connected[0]
        Record 'CONNECTED_MAC' ([string]$card.MacAddress)
        if ($card.MacAddress.ToUpperInvariant() -ne $ExpectedMac) {
            $inconclusive=$true
            Record 'EXPECTED_MAC' 'FALSE'
        } else {
            Record 'EXPECTED_MAC' 'TRUE'
        }
        $ips=@(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $card.ifIndex -ErrorAction Stop |
            Where-Object { $_.IPAddress -ne '127.0.0.1' })
        $matching=@($ips | Where-Object { $_.IPAddress -eq $ExpectedIPv4 -and
                     $_.PrefixLength -eq $ExpectedPrefix })
        Record 'EXPECTED_STATIC_IPV4' ([string]($matching.Count -eq 1))
        Record 'NON_LOOPBACK_IPV4_COUNT' ([string]$ips.Count)
        if ($matching.Count -ne 1 -or $ips.Count -ne 1) { $inconclusive=$true }
    }
    $v4=Get-DefaultRoutesCount 'IPv4' '0.0.0.0/0'
    $v6=Get-DefaultRoutesCount 'IPv6' '::/0'
    if ($null -ne $v4 -and $null -ne $v6) {
        if ($v4 -eq 0 -and $v6 -eq 0) {
            Record 'GUEST_DEFAULT_ROUTE_GUARD' 'PASS'
        } else {
            Record 'GUEST_DEFAULT_ROUTE_GUARD' 'FAIL'
            $unsafe=$true
        }
    } else {
        Record 'GUEST_DEFAULT_ROUTE_GUARD' 'INCONCLUSIVE'
    }
    $targets=@(
      @('IPv4_1_1_1_1_443','1.1.1.1',443),
      @('IPv4_8_8_8_8_53','8.8.8.8',53),
      @('IPv6_2606_4700_4700__1111_443','2606:4700:4700::1111',443),
      @('IPv6_2001_4860_4860__8888_443','2001:4860:4860::8888',443)
    )
    $blocked=0
    foreach ($t in $targets) {
        $status=Probe-TCP ([string]$t[1]) ([int]$t[2])
        Record ([string]$t[0]) $status
        if ($status -eq 'CONNECTED_UNSAFE') {
            $unsafe=$true
        } elseif ($status -eq 'TIMEOUT' -or $status.StartsWith('SOCKET_FAILED_')) {
            $blocked++
        } else {
            $inconclusive=$true
        }
    }
    Record 'ALL_FOUR_BENIGN_CONNECTIONS_DENIED' ([string]($blocked -eq 4))
    if ($unsafe) {
        Record 'GUEST_NEGATIVE_PROBE_RESULT' 'FAIL_UNEXPECTED_ROUTE_OR_CONNECTION'
    } elseif ($inconclusive -or $blocked -ne 4) {
        Record 'GUEST_NEGATIVE_PROBE_RESULT' 'INCONCLUSIVE'
    } else {
        Record 'GUEST_NEGATIVE_PROBE_RESULT' 'PASS_TARGETED_PROBES_ONLY'
    }
} catch {
    Record 'GUEST_NEGATIVE_PROBE_RESULT' 'INCONCLUSIVE'
    Record 'PROBE_ERROR_KIND' $_.Exception.GetType().Name
}
Record 'REAL_L2_LATERAL_TEST' 'NOT_PERFORMED'
Record 'FULL_HOST_EGRESS_GUARANTEE' 'NOT_PROVEN'
Record 'WINDOWS_NETWORK_CHANGES' 'NONE'
try {
    $rows | Set-Content -LiteralPath $Report -Encoding UTF8 -ErrorAction Stop
    Write-Host ('PROBE_REPORT: '+$Report)
    Start-Process -FilePath "$env:SystemRoot\system32\notepad.exe" -ArgumentList ('"'+$Report+'"')
} catch {
    Write-Host ('CANNOT_SAVE_PROBE_REPORT: '+$_.Exception.GetType().Name)
    foreach ($row in $rows) { Write-Host $row }
}
