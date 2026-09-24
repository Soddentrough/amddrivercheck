@echo off
setlocal EnableDelayedExpansion
title Automated Game ^& System Crash Diagnostics
cd /d "%~dp0"

:: Auto-unblock extracted scripts on Windows to bypass Mark-of-the-Web restrictions
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path '%~dp0' -Recurse | Unblock-File -ErrorAction SilentlyContinue" >nul 2>&1

:menu
cls
echo ========================================================================
echo   AUTOMATED GAME ^& SYSTEM CRASH DIAGNOSTIC SUITE (v4.5.0)
echo   Evidence-Based Engine (Crash Dumps, Logs, Telemetry, Hardware)
echo ========================================================================
echo.
echo   [1] Diagnose Latest Crash ^& Open HTML Report (Recommended)
echo   [2] Scan Full Incident History (All Recent Incidents)
echo   [3] Export Support Bundle (HTML Report + ZIP for Discord/Support)
echo   [4] Motherboard, Chipset Drivers ^& PnP Hardware Health Audit
echo   [5] Display, EDID Timings ^& DP Scaler Saturation Audit
echo   [6] GPU Driver Health ^& Downgrade Prevention Audit
echo   [7] Apply GPU Downgrade Protection (Lock Windows Update Drivers)
echo   [8] Power, Fast Startup ^& Sleep Transition Audit
echo   [9] Maintenance ^& Cache Cleaning Tools
echo   [0] Exit
echo.
echo ========================================================================
set "choice="
set /p choice="Select an option [0-9, default is 1]: "

if defined choice set "choice=%choice: =%"
if "%choice%"=="" set choice=1
if "%choice%"=="9" goto maintenance
if /i "%choice%"=="M" goto maintenance
if "%choice%"=="1" goto latest_scan
if "%choice%"=="2" goto history_scan
if "%choice%"=="3" goto export_bundle
if "%choice%"=="4" goto pnp_audit
if "%choice%"=="5" goto display_audit
if "%choice%"=="6" goto gpu_audit
if "%choice%"=="7" goto gpu_fix
if "%choice%"=="8" goto power_audit
if "%choice%"=="0" goto exit_tool
goto menu

:latest_scan
cls
echo [INFO] Scanning backward for latest crash incident and generating HTML report...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -ExportHtml -OpenReport
goto finish

:history_scan
cls
echo [INFO] Scanning full system incident history and generating HTML report...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -AllIncidents -ExportHtml -OpenReport
goto finish

:export_bundle
cls
echo [INFO] Analyzing crashes and creating support bundle ZIP...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -ExportZip -ExportHtml -OpenReport
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
echo   [6] Disable PCIe Link State Power Management (Fix GPU Timeouts ^& Sleep Crashes)
echo   [7] Scan ^& Disable Rogue Kernel I/O Drivers (Fix inpoutx64 / 0x93 BSODs)
echo   [8] Optimize GPU Watchdog Timeout (Increase TdrDelay to 8s - Zero Power Impact)
echo   [0] Return to Main Menu
echo.
set "mchoice="
set /p mchoice="Select an option [0-8]: "
if defined mchoice set "mchoice=%mchoice: =%"
if "%mchoice%"=="1" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Clean-ShaderCache.ps1" & goto finish )
if "%mchoice%"=="2" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Clean-GameConfig.ps1" & goto finish )
if "%mchoice%"=="3" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Clean-SteamCache.ps1" & goto finish )
if "%mchoice%"=="4" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -KillHungSteam & goto finish )
if "%mchoice%"=="5" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Repair-EthernetSettings.ps1" & goto finish )
if "%mchoice%"=="6" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Repair-PciePowerSettings.ps1" & goto finish )
if "%mchoice%"=="7" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Disable-RogueKernelDrivers.ps1" & goto finish )
if "%mchoice%"=="8" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Repair-GpuSleepSettings.ps1" & goto finish )
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
