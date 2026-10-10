# Read-only Windows guest acceptance for isolated Command 2A clone win11_1.
# Run ONLY inside the win11_1 Windows PowerShell console after visual login.
# Network is intentionally DISCONNECTED. Never run samples in this stage.
# Writes only one TXT file to the current Windows user's Desktop.
$ErrorActionPreference = 'Stop'
$desktop = [Environment]::GetFolderPath('Desktop')
if (-not (Test-Path -LiteralPath $desktop -PathType Container)) {
    throw 'Cannot locate Desktop; no report was written.'
}
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$report = Join-Path $desktop ("CAPE_Command2A_Win11_1_Guest_$stamp.txt")
$script:rows = New-Object 'System.Collections.Generic.List[string]'
$script:rows.Add('CAPE COMMAND2A WINDOWS GUEST OBSERVATION - NOT NETWORK APPROVAL')
$script:rows.Add('EXPECTED LIBVIRT DOMAIN: win11_1 (verify in virt-manager yourself)')
$script:rows.Add('CAPTURED: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'))
$script:rows.Add('This script makes no Windows network, firewall, service, registry or VM changes.')

function Add-Observation {
    param([string]$Heading, [scriptblock]$ReadOnlyProbe)
    $script:rows.Add('')
    $script:rows.Add("=== $Heading ===")
    try {
        $value = (& $ReadOnlyProbe 2>&1 | Out-String -Width 240).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) { $value = '(no output)' }
        $script:rows.Add($value)
    } catch {
        $script:rows.Add('UNVERIFIED / ERROR: ' + $_.Exception.Message)
    }
}

Add-Observation 'WINDOWS SESSION AND HOSTNAME' {
    'COMPUTERNAME=' + $env:COMPUTERNAME
    'USERNAME=' + $env:USERNAME
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, LastBootUpTime | Format-List
}
Add-Observation 'PYTHON (SYSTEM PATH)' {
    $python = Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $python) {
        'python.exe is not on PATH'
    } else {
        'PYTHON_COMMAND=' + $python.Source
        & $python.Source --version 2>&1
        & $python.Source -c 'import sys; print("EXECUTABLE=" + sys.executable)' 2>&1
    }
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $launcher) {
        'py.exe launcher is not on PATH'
    } else {
        & $launcher.Source --list-paths 2>&1
    }
}
Add-Observation 'LOCAL CAPE AGENT HTTP /status (NO INTERNET)' {
    $response = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/status' -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
    'HTTP_STATUS=' + $response.StatusCode
    # Windows PowerShell may return System.Byte[] for this API.
    # Decode UTF-8 bytes instead of printing one decimal byte per line.
    if ($response.Content -is [byte[]]) {
        $body = [System.Text.Encoding]::UTF8.GetString($response.Content)
    } elseif ($response.Content -is [string]) {
        $body = $response.Content
    } else {
        $body = [string]$response.Content
    }
    'BODY=' + $body.Substring(0, [Math]::Min(1500, $body.Length))
}
Add-Observation 'TCP PORT 8000 LISTENER' {
    Get-NetTCPConnection -State Listen -LocalPort 8000 |
        Select-Object LocalAddress, LocalPort, State, OwningProcess | Format-Table
}
Add-Observation 'VISIBLE AND HIDDEN NETWORK ADAPTERS (READ ONLY)' {
    Get-NetAdapter -IncludeHidden |
        Select-Object Name, InterfaceDescription, Status, MacAddress |
        Format-Table -AutoSize
}
Add-Observation 'ASSIGNED IP ADDRESSES (READ ONLY)' {
    Get-NetIPAddress |
        Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength |
        Format-Table -AutoSize
}
Add-Observation 'TPM OBSERVATION (READ ONLY)' {
    Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated |
        Format-List
}
Add-Observation 'BITLOCKER C: STATUS (READ ONLY)' {
    & manage-bde.exe -status C: 2>&1
}

$script:rows.Add('')
$script:rows.Add('END OF REPORT - no hostname/IP personalization or network test performed.')
$script:rows | Set-Content -LiteralPath $report -Encoding UTF8 -ErrorAction Stop
Write-Output ('REPORT_SAVED=' + $report)
$script:rows | ForEach-Object { Write-Output $_ }
