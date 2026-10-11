@echo off
setlocal
title CAPE Command 2 - WIN11-1 Verified Static IP
echo CAPE: Verify the exact Windows clone and replace only old NAT IP.
echo No internet or Windows command copy-pasting needed.
echo Windows will show an Administrator permission dialog.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$f=Join-Path '%~dp0' 'FIX.PS1'; if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ine '__PS_SHA256__') { throw 'BLOCKED: ISO Windows script checksum mismatch' }; $a='-NoProfile -ExecutionPolicy Bypass -File ' + [char]34 + $f + [char]34 + ' -Mode Apply'; $p=Start-Process -FilePath 'powershell.exe' -ArgumentList $a -Verb RunAs -Wait -PassThru; exit $p.ExitCode"
set "rc=%errorlevel%"
echo.
if not "%rc%"=="0" (echo BLOCKED: See Windows Notepad report. Do not retry.) else (echo SUCCESS: See Windows Notepad verification report.)
echo No Windows firewall, Defender or original master VM changed.
pause
exit /b %rc%
