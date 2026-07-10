@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%collect-kerberos-wna-diagnostics.ps1" %*
exit /b %ERRORLEVEL%
