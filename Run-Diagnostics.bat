@echo off
title Automated Game & System Crash Diagnostics
cls

echo ========================================================================
echo   AUTOMATED GAME & SYSTEM CRASH DIAGNOSTICS
echo ========================================================================
echo.
echo [INFO] Running zero-prompt system and crash telemetry analysis...
echo.

cd /d "%~dp0"
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1"

echo.
echo ========================================================================
echo Diagnostic scan complete. You can review the report above.
echo Press any key to close this window...
echo ========================================================================
pause >nul
