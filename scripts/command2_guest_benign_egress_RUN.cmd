@echo off
setlocal
title CAPE Command 2 - Benign IPv4 IPv6 Egress Probe
echo ====================================================
echo   CAPE BENIGN WINDOWS IPv4 / IPv6 EGRESS CHECK
echo ====================================================
echo Only public TCP connection attempts; NO sample runs.
echo No guest networking or security settings will change.
echo The report will open in Notepad after completion.
echo.
powershell.exe -NoProfile -File "%~dp0CAPE_BenignEgressProbe.ps1"
set "result=%ERRORLEVEL%"
if not "%result%"=="0" echo Probe launch reported an error; inspect Windows screen.
echo.
echo Finished. Save/report a screenshot of the Notepad result.
echo These probes do not establish guest-to-guest L2 containment.
pause
exit /b %result%
