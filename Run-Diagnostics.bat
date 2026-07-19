@echo off
title GPU Driver Diagnostics Launcher
cls

echo ==========================================================
echo           GPU Driver Diagnostics Launcher
echo ==========================================================
echo.

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :admin
) else (
    goto :elevate
)

:elevate
echo [INFO] Requesting Administrator privileges to run diagnostics...
powershell -Command "Start-Process '%~f0' -Verb RunAs"
exit /b

:admin
:: Ensure the working directory is the script folder
cd /d "%~dp0"
echo [ OK ] Running with Administrator privileges.
echo.
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Get-GPUDriverDiagnostics.ps1" -ApplyFix
echo.
echo ==========================================================
echo Script completed. Press any key to exit.
echo ==========================================================
pause >nul
