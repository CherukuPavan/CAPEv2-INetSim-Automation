#Requires -Version 5.1
# Read-only: identify Python interpreter/launcher availability in the Windows guest.
# This is NOT the CAPE agent and does not install or modify software.
$ErrorActionPreference = 'Continue'
Write-Output '========== STEP 13B: WINDOWS PYTHON PREREQUISITES =========='
Write-Output 'CAPE agent is distinct from optional QEMU guest agent.'
foreach ($name in @('py.exe', 'python.exe')) {
    $entry = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $entry) {
        Write-Output ("{0}: NOT FOUND" -f $name)
        continue
    }
    if ($entry.Source -like '*\Microsoft\WindowsApps\*') {
        Write-Output ("{0}: MICROSOFT STORE ALIAS ONLY" -f $name)
        continue
    }
    if ($name -eq 'py.exe') {
        Write-Output '--- Registered Python launcher runtimes ---'
        & $entry.Source -0 2>&1 | ForEach-Object { Write-Output "$_" }
    } else {
        Write-Output '--- Default python.exe version and process architecture ---'
        & $entry.Source -c 'import sys,struct; print("Python:",sys.version.split()[0]); print("Bits:",struct.calcsize("P")*8)' 2>&1 | ForEach-Object { Write-Output "$_" }
    }
}
Write-Output '========== COMPLETE: NO CHANGES MADE =========='
