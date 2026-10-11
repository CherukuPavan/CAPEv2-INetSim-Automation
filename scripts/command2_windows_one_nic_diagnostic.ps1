#Requires -Version 5.1
<#
Read-only Windows one-NIC diagnostic from optical media.
No IP/MAC/firewall/route/hostname mutations, no network requests.
Writes an easy-to-share report to Windows Public Documents and opens
it in Notepad. Used before assigning a benign static address.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Report=Join-Path $env:PUBLIC 'Documents\CAPE_Command2_Win11_1_NetworkDiagnostics.txt'
$lines=New-Object 'System.Collections.Generic.List[string]'
function Log([string]$s) { [void]$lines.Add($s) }
function Section([string]$s) { Log ''; Log ('=== '+$s+' ===') }
function ShowProperty($items,$props) {
    if (@($items).Count -eq 0) { Log '[none]'; return }
    foreach ($item in @($items)) {
        $parts=@()
        foreach ($prop in $props) {
            $value=$item.$prop
            if ($null -ne $value) { $parts+=($prop+'='+[string]$value) }
        }
        Log ($parts -join ' ; ')
    }
}

Log 'COMMAND2_WINDOWS_ONE_NIC_DIAG_READONLY_V1'
Log ('Date='+[DateTime]::Now.ToString('o'))
Log ('ComputerName='+[Environment]::MachineName)
try {
    $system=Get-CimInstance -ClassName Win32_ComputerSystemProduct
    Log ('SMBIOS_UUID='+[string]$system.UUID)
} catch { Log ('SMBIOS_UUID_QUERY_ERROR='+$_.Exception.Message) }
Section 'Physical Windows NICs'
try {
    $nics=@(Get-NetAdapter -Physical -ErrorAction Stop)
    ShowProperty $nics @('Name','InterfaceDescription','InterfaceIndex','MacAddress','Status','LinkSpeed')
} catch { Log ('NIC_QUERY_ERROR='+$_.Exception.Message) }
Section 'IPv4 Default Routes'
try {
    $routes4=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop)
    ShowProperty $routes4 @('InterfaceIndex','InterfaceAlias','DestinationPrefix','NextHop','RouteMetric','PolicyStore','State')
} catch { Log ('ROUTE_IPV4_QUERY_ERROR='+$_.Exception.Message) }
Section 'IPv6 Default Routes'
try {
    $routes6=@(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction Stop)
    ShowProperty $routes6 @('InterfaceIndex','InterfaceAlias','DestinationPrefix','NextHop','RouteMetric','PolicyStore','State')
} catch { Log ('ROUTE_IPV6_QUERY_ERROR='+$_.Exception.Message) }
Section 'IPv4 Local Addresses'
try {
    $ips4=@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop)
    ShowProperty $ips4 @('InterfaceIndex','InterfaceAlias','IPAddress','PrefixLength','AddressState','PrefixOrigin','SuffixOrigin')
} catch { Log ('IPV4_QUERY_ERROR='+$_.Exception.Message) }
Section 'IPv6 Local Addresses'
try {
    $ips6=@(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction Stop)
    ShowProperty $ips6 @('InterfaceIndex','InterfaceAlias','IPAddress','PrefixLength','AddressState','PrefixOrigin')
} catch { Log ('IPV6_QUERY_ERROR='+$_.Exception.Message) }
Section 'Network Adapter IPv4 / IPv6 Interface State'
try {
    $ifaces=@(Get-NetIPInterface -ErrorAction Stop)
    ShowProperty $ifaces @('InterfaceIndex','InterfaceAlias','AddressFamily','Dhcp','ConnectionState','RouterDiscovery')
} catch { Log ('INTERFACE_QUERY_ERROR='+$_.Exception.Message) }
Section 'Next step'
Log 'DO NOT remove routes, add a gateway, or turn off Windows Firewall.'
Log 'Send a screenshot of this report for the safe one-guest configuration.'
Log 'This script made NO networking or firewall changes.'
$lines | Set-Content -LiteralPath $Report -Encoding UTF8
Start-Process -FilePath "$env:SystemRoot\system32\notepad.exe" -ArgumentList ('"'+$Report+'"')
