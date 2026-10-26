@echo off
setlocal EnableDelayedExpansion
title DriverCheck - Game ^& PC Crash Troubleshooter
cd /d "%~dp0"

:: Auto-unblock extracted scripts on Windows to bypass Mark-of-the-Web restrictions
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path '%~dp0' -Recurse | Unblock-File -ErrorAction SilentlyContinue" >nul 2>&1

:menu
cls
echo ========================================================================
echo   DriverCheck - Game ^& PC Crash Troubleshooter (v4.5.0)
echo ========================================================================
echo.
echo   [1] Crash check and Report (Recommended)
echo   [2] Check full crash history
echo   [3] Create support ZIP (for Discord / tech support)
echo   [4] Check motherboard, chipset, and device drivers
echo   [5] Check monitor and refresh rate settings
echo   [6] Check GPU driver status and version
echo   [7] Stop Windows Update from overwriting GPU drivers
echo   [8] Check power and sleep settings
echo   [9] Check network connection and drops
echo   [M] Fixes and cleanup tools
echo   [0] Exit
echo.
echo ========================================================================
set "choice="
set /p choice="Select an option [0-9, M, default is 1]: "

if defined choice set "choice=%choice: =%"
if "%choice%"=="" set choice=1
if /i "%choice%"=="M" goto maintenance
if "%choice%"=="1" goto latest_scan
if "%choice%"=="2" goto history_scan
if "%choice%"=="3" goto export_bundle
if "%choice%"=="4" goto pnp_audit
if "%choice%"=="5" goto display_audit
if "%choice%"=="6" goto gpu_audit
if "%choice%"=="7" goto gpu_fix
if "%choice%"=="8" goto power_audit
if "%choice%"=="9" goto network_audit
if "%choice%"=="0" goto exit_tool
goto menu

:latest_scan
cls
echo Checking for recent crashes and creating your report...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -ExportHtml -OpenReport
goto finish

:history_scan
cls
echo Checking full crash history and creating your report...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -AllIncidents -ExportHtml -OpenReport
goto finish

:export_bundle
cls
echo Running crash check and saving support ZIP...
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
echo Stopping Windows Update from overwriting your GPU drivers (Admin)...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Get-GPUDriverDiagnostics.ps1" -ApplyFix
goto finish

:power_audit
cls
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Get-PowerAndSleepDiagnostics.ps1"
goto finish

:network_audit
cls
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Get-NetworkDiagnostics.ps1"
goto finish

:maintenance
cls
echo ========================================================================
echo   Fixes ^& Cleanup Tools
echo ========================================================================
echo   [1] Clear shader caches (fixes game freezes and GPU timeouts)
echo   [2] Reset game configs and crash locks (keeps .bak backups)
echo   [3] Clear Steam browser cache
echo   [4] Close stuck Steam processes
echo   [5] Fix Ethernet drops and expand network ports (Admin)
echo   [6] Turn off PCIe power saving (fixes GPU timeouts)
echo   [7] Disable conflicting RGB / hardware drivers (Admin)
echo   [8] Increase GPU wake timeout for 4K / HDMI 2.1 displays (Admin)
echo   [0] Back to Main Menu
echo.
set "mchoice="
set /p mchoice="Select an option [0-8]: "
if defined mchoice set "mchoice=%mchoice: =%"
if "%mchoice%"=="1" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Clean-ShaderCache.ps1" & goto finish )
if "%mchoice%"=="2" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Clean-GameConfig.ps1" & goto finish )
if "%mchoice%"=="3" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Clean-SteamCache.ps1" & goto finish )
if "%mchoice%"=="4" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Analyze-LatestCrash.ps1" -KillHungSteam & goto finish )
if "%mchoice%"=="5" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Repair-EthernetSettings.ps1" -ExpandUdpPorts & goto finish )
if "%mchoice%"=="6" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Repair-PciePowerSettings.ps1" & goto finish )
if "%mchoice%"=="7" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Disable-RogueKernelDrivers.ps1" & goto finish )
if "%mchoice%"=="8" ( PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Repair-GpuSleepSettings.ps1" & goto finish )
if "%mchoice%"=="0" goto menu
goto menu

:finish
echo.
echo ========================================================================
echo Done. Review the results above or press any key to return to the menu.
echo ========================================================================
pause
goto menu

:exit_tool
exit /b 0
