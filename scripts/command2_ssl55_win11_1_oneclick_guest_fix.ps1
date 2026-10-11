#Requires -Version 5.1
<#
Command 2: SAFE pilot-only Windows OLD-NAT->isolated-static address repair.
For existing win11_1 ONLY. Delivered through a verified read-only ISO.
The original golden VM and all other guests MUST fail UUID/MAC checks.

Supported starting IP: 192.168.122.125/24, old optional IPv4
default route ONLY 192.168.122.1 on the reserved NIC. Target is
192.168.240.101/24 with NO default gateway. Unexpected routes,
other IPv4, DHCP or unexpected IPv6 BLOCK before mutation.
Automatic Notepad report; no Windows command-pasting necessary.
-Mode Plan makes NO networking changes. -Mode Apply additionally
requires elevated local administrator and an interactive YES.
#>
[CmdletBinding()]
param(
 [ValidateSet("Plan","Apply","Verify")][string]$Mode="Plan"
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$VmUuid=[guid]'732b2256-ee99-41fa-881d-fbf5c476d960'
$VmMac='020A306A3F50'
$ExpectedName='WIN11-1'
$OldIp='192.168.122.125'
$OldPrefix=24
$OldGateway='192.168.122.1'
$NewIp='192.168.240.101'
$NewPrefix=24
$Report=Join-Path $env:PUBLIC 'Documents\CAPE_Command2_Win11_1_GuestSetup.txt'
$Log=New-Object 'System.Collections.Generic.List[string]'
$ExitCode=0
$Changed=$false

function WriteLog([string]$Message) {
 [void]$Log.Add($Message)
 Write-Host $Message
}
function Block([string]$Reason) { throw ("COMMAND2_BLOCKED: "+$Reason) }
function NormalMac([string]$Value) { return ($Value.ToUpperInvariant() -replace '[^0-9A-F]','') }
function IsAdmin {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $principal=New-Object Security.Principal.WindowsPrincipal($id)
 return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Routes4 {
 return @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
}
function Routes6 {
 return @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue)
}
function GuardRouting([int]$Index,[bool]$OldState) {
 $r4=@(Routes4)
 $r6=@(Routes6)
 WriteLog ("IPv4 default route count="+$r4.Count)
 foreach ($row in $r4) {
   WriteLog ("ROUTE4 ifIndex="+$row.InterfaceIndex+" nextHop="+$row.NextHop+" metric="+$row.RouteMetric)
 }
 WriteLog ("IPv6 default route count="+$r6.Count)
 foreach ($row in $r6) {
   WriteLog ("ROUTE6 ifIndex="+$row.InterfaceIndex+" nextHop="+$row.NextHop+" metric="+$row.RouteMetric)
 }
 if ($r6.Count -ne 0) { Block 'Unexpected IPv6 default route. No changes.' }
 if ($OldState) {
   if ($r4.Count -gt 1) { Block 'Multiple IPv4 default routes. No changes.' }
   if ($r4.Count -eq 1) {
     if ($r4[0].InterfaceIndex -ne $Index -or $r4[0].NextHop -ne $OldGateway) {
       Block 'Unexpected IPv4 default route or gateway. No changes.'
     }
   }
 } elseif ($r4.Count -ne 0) {
   Block 'A default route remains after isolated address change'
 }
 return $r4
}
function GuestState {
 $actual=[guid]([string](Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop).UUID)
 WriteLog ("SMBIOS_UUID="+$actual)
 if ($actual -ne $VmUuid) { Block 'VM SMBIOS UUID does not match win11_1' }
 $current=[Environment]::MachineName
 WriteLog ("WINDOWS_HOSTNAME="+$current)
 if ($current -ine $ExpectedName) { Block 'Windows hostname is not WIN11-1; no rename automatically' }
 $nics=@(Get-NetAdapter -Physical -ErrorAction Stop)
 WriteLog ("PHYSICAL_NIC_COUNT="+$nics.Count)
 if ($nics.Count -ne 1) { Block 'Exactly one NIC required' }
 $n=$nics[0]
 WriteLog ("NIC="+$n.Name+" mac="+$n.MacAddress+" ifIndex="+$n.ifIndex)
 if ((NormalMac ([string]$n.MacAddress)) -cne $VmMac) { Block 'Reserved NIC MAC mismatch' }
 if ($n.Status -ne 'Up') { Block 'Isolated NIC not connected' }
 $v4=@(Get-NetIPAddress -InterfaceIndex $n.ifIndex -AddressFamily IPv4 -ErrorAction Stop)
 foreach ($v in $v4) {
   WriteLog ("IPV4="+$v.IPAddress+" prefix="+$v.PrefixLength+" origin="+$v.PrefixOrigin)
 }
 $v6=@(Get-NetIPAddress -InterfaceIndex $n.ifIndex -AddressFamily IPv6 -ErrorAction Stop)
 foreach ($v in $v6) {
   WriteLog ("IPV6="+$v.IPAddress+" prefix="+$v.PrefixLength)
   if (-not $v.IPAddress.StartsWith('fe80:')) {
     Block 'Unexpected non-link-local guest IPv6 address'
   }
 }
 $nonApipa=@($v4 | Where-Object { $_.IPAddress -notlike '169.254.*' })
 if ($nonApipa.Count -ne 1) { Block 'Exactly one non-APIPA guest IPv4 required' }
 $old=($nonApipa[0].IPAddress -eq $OldIp -and $nonApipa[0].PrefixLength -eq $OldPrefix)
 $new=($nonApipa[0].IPAddress -eq $NewIp -and $nonApipa[0].PrefixLength -eq $NewPrefix)
 if (-not $old -and -not $new) { Block 'Unexpected guest IPv4 or subnet prefix' }
 $ipInterface=Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $n.ifIndex -ErrorAction Stop
 WriteLog ("IPv4 DHCP="+$ipInterface.Dhcp)
 if ([string]$ipInterface.Dhcp -ne 'Disabled') {
   Block 'Unexpected DHCP enabled on preserved source NIC'
 }
 $routes=@(GuardRouting $n.ifIndex $old)
 return @{ Index=[int]$n.ifIndex; Old=$old; New=$new; Routes=$routes }
}

try {
 WriteLog 'COMMAND2_WIN11_1_GUEST_OLD_IP_TO_ISOLATED_IP_V1'
 WriteLog ("MODE="+$Mode)
 WriteLog ("DATE="+[DateTime]::Now.ToString('o'))
 $state=GuestState
 if ($Mode -eq 'Plan') {
   WriteLog 'PLAN_ONLY: No guest networking changes were made'
 } elseif ($Mode -eq 'Verify') {
   if (-not $state.New) { Block 'Static 192.168.240.101/24 not yet present' }
   WriteLog 'VERIFY_PASS: expected isolated IP, no default IPv4/IPv6 route'
 } else {
   if (-not (IsAdmin)) { Block 'Administrator approval required' }
   if ($state.New) {
     WriteLog 'ALREADY_CONFIGURED: exact isolated IP, no default IPv4/IPv6 route'
   } else {
     WriteLog 'Ready: remove ONLY old 192.168.122.125/24 and optional 192.168.122.1 route.'
     WriteLog 'Ready: install 192.168.240.101/24 WITHOUT gateway/DNS.'
     $answer=Read-Host 'Type YES to apply this exact BENIGN configuration'
     if ($answer -cne 'YES') { Block 'Operator declined guest configuration' }
     # A route to the original NAT bridge must never survive the conversion.
     if ($state.Routes.Count -eq 1) {
       Remove-NetRoute -InterfaceIndex $state.Index -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -NextHop $OldGateway -Confirm:$false -ErrorAction Stop
       WriteLog 'CHANGED: Removed ONLY the legacy 192.168.122.1 IPv4 default route'
       $Changed=$true
     }
     Remove-NetIPAddress -InterfaceIndex $state.Index -IPAddress $OldIp -Confirm:$false -ErrorAction Stop
     WriteLog 'CHANGED: Removed ONLY old 192.168.122.125/24'
     $Changed=$true
     New-NetIPAddress -InterfaceIndex $state.Index -IPAddress $NewIp -PrefixLength $NewPrefix -AddressFamily IPv4 -ErrorAction Stop | Out-Null
     WriteLog 'CHANGED: Added 192.168.240.101/24; no gateway requested'
     $final=GuestState
     if (-not $final.New -or $final.Routes.Count -ne 0) {
       Block 'Post-change network validation failed: manual inspection required'
     }
     WriteLog 'SUCCESS: WIN11-1 has isolated 192.168.240.101/24 with no default IPv4/IPv6 route'
   }
 }
} catch {
 $ExitCode=2
 WriteLog ("BLOCKED_OR_PARTIAL: "+$_.Exception.Message)
 if ($Changed) { WriteLog 'WARNING: Changes may be partial; do not rerun blindly' }
} finally {
 WriteLog 'No Windows Firewall/Defender changes. No sample execution.'
 WriteLog 'Host L2/IPv4/IPv6 packet-containment proof and CAPE agent remain pending.'
 try {
   $Log | Set-Content -LiteralPath $Report -Encoding UTF8 -ErrorAction Stop
   Start-Process -FilePath (Join-Path $env:SystemRoot 'system32\notepad.exe') -ArgumentList ('"'+$Report+'"')
 } catch { Write-Host ("Could not open report: "+$_.Exception.Message) }
}
exit $ExitCode
