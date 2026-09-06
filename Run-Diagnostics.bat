@echo off
setlocal EnableDelayedExpansion
title Automated Game ^& System Crash Diagnostics
cd /d "%~dp0"

:: Auto-unblock extracted scripts on Windows to bypass Mark-of-the-Web restrictions
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path '%~dp0' -Recurse | Unblock-File -ErrorAction SilentlyContinue" >nul 2>&1

:menu
cls
echo ========================================================================
echo   AUTOMATED GAME ^& SYSTEM CRASH DIAGNOSTIC SUITE (v4.1.0)
echo   Evidence-Based Engine (Crash Dumps, Logs, Telemetry, Hardware)
echo ========================================================================
echo.
echo   [1] Full Crash Diagnostics + Open HTML Report (Recommended)
echo   [2] Quick Scan (Past 24 Hours)
echo   [3] Deep Scan (Past 7 Days)
echo   [4] Export Support Bundle (HTML Report + ZIP for Discord/Support)
echo   [5] Hardware Health ^& Missing Drivers Audit (PnP)
echo   [6] Display, EDID Timings ^& DP Scaler Saturation Audit
echo   [7] GPU Driver Health ^& Downgrade Prevention Audit
echo   [8] Apply GPU Downgrade Protection (Lock Windows Update Drivers)
echo   [9] Power, Fast Startup ^& Sleep Transition Audit
echo   [10] Maintenance ^& Cache Cleaning Tools
echo   [0] Exit
echo.
echo ========================================================================
set "choice="
set /p choice="Select an option [0-10, default is 1]: "

if defined choice set "choice=%choice: =%"
if "%choice%"=="" set choice=1
if "%choice%"=="10" goto maintenance
if /i "%choice%"=="M" goto maintenance
if "%choice%"=="1" goto full_scan
if "%choice%"=="2" goto quick_scan
if "%choice%"=="3" goto deep_scan
if "%choice%"=="4" goto export_bundle
if "%choice%"=="5" goto pnp_audit
if "%choice%"=="6" goto display_audit
if "%choice%"=="7" goto gpu_audit
if "%choice%"=="8" goto gpu_fix
if "%choice%"=="9" goto power_audit
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

:display_audit
cls
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Get-DisplayDiagnostics.ps1"
goto finish

:gpu_audit
cls
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Get-GPUDriverDiagnostics.ps1"
goto finish

:gpu_fix
cls
echo [INFO] Applying GPU Driver Downgrade Protection (Requires Admin)...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Get-GPUDriverDiagnostics.ps1" -ApplyFix
goto finish

:power_audit
cls
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Get-PowerAndSleepDiagnostics.ps1"
goto finish

:maintenance
cls
echo ========================================================================
echo   MAINTENANCE ^& REMEDIATION UTILITIES
echo ========================================================================
echo   [1] Purge DirectX ^& GPU Shader Caches (Fix Shader Timeouts / Hangs)
echo   [2] Clean Stale Game Configs ^& Shader Caches (with .bak backup)
echo   [3] Purge Steam CEF Browser HTML Cache
echo   [4] Terminate Hung / Zombie Steam Processes
echo   [5] Optimize Ethernet Adapter Stability (Requires Admin)
echo   [0] Return to Main Menu
echo.
set "mchoice="
set /p mchoice="Select an option [0-5]: "
if defined mchoice set "mchoice=%mchoice: =%"
if "%mchoice%"=="1" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Clean-ShaderCache.ps1" & goto finish )
if "%mchoice%"=="2" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Clean-GameConfig.ps1" & goto finish )
if "%mchoice%"=="3" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Clean-SteamCache.ps1" & goto finish )
if "%mchoice%"=="4" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -KillHungSteam & goto finish )
if "%mchoice%"=="5" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Repair-EthernetSettings.ps1" & goto finish )
if "%mchoice%"=="0" goto menu
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
