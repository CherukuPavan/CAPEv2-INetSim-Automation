@echo off
setlocal
title CAPE Command 2 - Read-only Windows Network Check
echo COMMAND2: read-only Windows network and route diagnosis
echo No internet, clipboard, administrator command typing, or changes needed.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0DIAG.PS1"
set "result=%ERRORLEVEL%"
echo.
if not "%result%"=="0" (echo BLOCKED: diagnostic failed - photograph this screen.) else (echo PASS: report opened in Notepad. Take a screenshot or photograph.)
echo No VM, firewall, routing or static IP modifications made.
pause
exit /b %result%
