@echo off
setlocal EnableDelayedExpansion
title Automated Game & System Crash Diagnostics
cd /d "%~dp0"

:menu
cls
echo ========================================================================
echo   AUTOMATED GAME & SYSTEM CRASH DIAGNOSTIC SUITE (v4.0)
echo   Evidence-Based Engine (Crash Dumps, Logs, Telemetry, Hardware)
echo ========================================================================
echo.
echo   [1] Full Crash Diagnostics + Open HTML Report (Recommended)
echo   [2] Quick Scan (Past 24 Hours)
echo   [3] Deep Scan (Past 7 Days)
echo   [4] Export Support Bundle (HTML Report + ZIP for Discord/Support)
echo   [5] Hardware Health & Missing Drivers Audit (PnP)
echo   [6] GPU Driver Health & Downgrade Prevention
echo   [7] Power, Fast Startup & Sleep Transition Audit
echo   [8] Maintenance Tools (Clean Cache, Terminate Zombies)
echo   [0] Exit
echo.
echo ========================================================================
set /p choice="Select an option [1-8, default is 1]: "

if "%choice%"=="" set choice=1
if "%choice%"=="1" goto full_scan
if "%choice%"=="2" goto quick_scan
if "%choice%"=="3" goto deep_scan
if "%choice%"=="4" goto export_bundle
if "%choice%"=="5" goto pnp_audit
if "%choice%"=="6" goto gpu_audit
if "%choice%"=="7" goto power_audit
if "%choice%"=="8" goto maintenance
if "%choice%"=="0" goto exit_tool
goto menu

:full_scan
cls
echo [INFO] Running full diagnostic scan and generating HTML report...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -Hours 48 -ExportHtml -OpenReport
goto finish

:quick_scan
cls
echo [INFO] Running quick scan (past 24 hours)...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -Hours 24 -ExportHtml -OpenReport
goto finish

:deep_scan
cls
echo [INFO] Running deep scan (past 7 days)...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -DeepScan -ExportHtml -OpenReport
goto finish

:export_bundle
cls
echo [INFO] Analyzing crashes and creating support bundle ZIP...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -Hours 72 -ExportZip -ExportHtml -OpenReport
goto finish

:pnp_audit
cls
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Get-PnpDeviceDiagnostics.ps1"
goto finish

:gpu_audit
cls
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Get-GPUDriverDiagnostics.ps1"
goto finish

:power_audit
cls
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Get-PowerAndSleepDiagnostics.ps1"
goto finish

:maintenance
cls
echo ========================================================================
echo   MAINTENANCE & REMEDIATION UTILITIES
echo ========================================================================
echo   [1] Purge Steam CEF Browser HTML Cache
echo   [2] Clean Stale Game Configs & Shader Caches (with .bak backup)
echo   [3] Terminate Hung / Zombie Steam Processes
echo   [4] Optimize Ethernet Adapter Stability (Requires Admin)
echo   [0] Return to Main Menu
echo.
set /p mchoice="Select an option [1-4]: "
if "%mchoice%"=="1" PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Clean-SteamCache.ps1" & goto finish
if "%mchoice%"=="2" PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Clean-GameConfig.ps1" & goto finish
if "%mchoice%"=="3" PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -KillHungSteam & goto finish
if "%mchoice%"=="4" PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Repair-EthernetSettings.ps1" & goto finish
goto menu

:finish
echo.
echo ========================================================================
echo Action completed. Review any findings or open reports above.
echo ========================================================================
pause
goto menu

:exit_tool
exit /b 0
