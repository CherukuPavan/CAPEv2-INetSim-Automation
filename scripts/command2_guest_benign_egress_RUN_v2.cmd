@echo off
setlocal
title CAPE Command 2 - Benign IPv4 IPv6 Egress Probe V2
echo ==================================================
echo    Corrected CAPE benign IPv4 and IPv6 check V2
echo ==================================================
echo Read-only NIC and route inventory with bounded public TCP probes.
echo No network or firewall settings will change.
echo No malware or CAPE sample analysis.
echo.
powershell.exe -NoProfile -File "%~dp0CAPE_BenignEgressProbe_V2.ps1"
set "result=%ERRORLEVEL%"
if not "%result%"=="0" echo Unable to complete PowerShell probe. Review screen.
echo Report opens in Notepad and saves under Public Documents.
echo Targeted probes do not establish full egress or L2 isolation.
pause
exit /b %result%
