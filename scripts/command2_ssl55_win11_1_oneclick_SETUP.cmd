@echo off
setlocal
title CAPE Command 2 - WIN11-1 Isolated IP Setup
echo CAPE COMMAND 2: setup only the verified isolated WIN11-1 guest.
echo No internet connection or command typing needed.
fltmc >NUL 2>&1
if errorlevel 1 (
  echo Windows will now request Administrator approval via UAC.
  powershell.exe -NoProfile -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c ""%~f0""' -Verb RunAs"
  exit /b
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$f=Join-Path '%~dp0' 'FIX.PS1'; if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ine '__PS_SHA256__') { throw 'BLOCKED: ISO script SHA256 integrity mismatch' }; & $f -Mode Apply"
set "rc=%errorlevel%"
echo.
if not "%rc%"=="0" (echo BLOCKED: No further Windows changes - read Notepad report.) else (echo SUCCESS: See Notepad report for verified isolated IPv4.)
echo No Windows firewall or host libvirt changes requested.
pause
exit /b %rc%
