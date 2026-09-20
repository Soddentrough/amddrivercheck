<#
.SYNOPSIS
    Rogue & Legacy Kernel I/O Driver Audit & Remediation Tool
.DESCRIPTION
    Audits Windows for notorious third-party legacy kernel port I/O drivers (inpoutx64.sys,
    WinRing0x64.sys, ene.sys, AsrOmgDrv.sys, gdrv.sys) commonly left behind by RGB and hardware
    monitoring software. Safely disables their autostart services to eliminate INVALID_KERNEL_HANDLE
    (0x93) BSODs, anti-cheat collisions, and game freezes where audio continues playing.
.PARAMETER Force
    Automatically disable all detected rogue kernel drivers without interactive confirmation.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcHardwareHealth.psm1") -Force
Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  ROGUE & LEGACY KERNEL I/O DRIVER AUDIT & REMEDIATION" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

$report = Get-DcProblematicKernelDrivers

if ($report.Drivers.Count -eq 0) {
    Write-Host "[OK] Clean system: No known rogue or legacy kernel port I/O drivers detected." -ForegroundColor Green
    Write-Host "No services matching inpoutx64, WinRing0, ENE, or related drivers found." -ForegroundColor DarkGray
    return
}

Write-Host "Detected Third-Party Kernel I/O Drivers:" -ForegroundColor Cyan
foreach ($d in $report.Drivers) {
    $statusColor = if ($d.IsDisabled) { [ConsoleColor]::Green } elseif ($d.IsActive) { [ConsoleColor]::Red } else { [ConsoleColor]::Yellow }
    $statusText = if ($d.IsDisabled) { "DISABLED (Safe)" } elseif ($d.IsActive) { "ACTIVE / AUTO-START (HAZARD)" } else { "PRESENT" }

    Write-Host "  * $($d.FileName) [Service: $($d.ServiceName)]" -ForegroundColor White
    Write-Host "    +- Status:    $statusText (StartType: $($d.StartType))" -ForegroundColor $statusColor
    Write-Host "    +- Software:  $($d.Software) ($($d.Vendor))" -ForegroundColor DarkGray
    Write-Host "    +- Risk:      $($d.RiskReason)" -ForegroundColor DarkYellow
}

$activeDrivers = $report.Drivers | Where-Object { $_.IsActive -and -not $_.IsDisabled }

if ($activeDrivers.Count -eq 0) {
    Write-Host "`n[OK] All detected legacy drivers are already DISABLED in Windows service manager." -ForegroundColor Green
    return
}

Write-Host "`n[!] $($activeDrivers.Count) driver(s) are actively configured to load on boot." -ForegroundColor Red
Write-Host "These drivers frequently conflict with modern anti-cheat systems and cause 0x93 BSODs or game freezes." -ForegroundColor Yellow

if (-not (Test-DcIsAdmin)) {
    Write-Host "`n[ERROR] Administrator elevation is required to disable kernel driver services." -ForegroundColor Red
    Write-Host "Please re-run this tool in an elevated terminal (Run as Administrator) or run:" -ForegroundColor Yellow
    foreach ($ad in $activeDrivers) {
        Write-Host "  sc config $($ad.ServiceName) start= disabled" -ForegroundColor White
    }
    return
}

Write-Host ""
foreach ($ad in $activeDrivers) {
    Write-Host "Disabling service '$($ad.ServiceName)' ($($ad.FileName))..." -ForegroundColor Yellow
    Disable-DcProblematicKernelDriver -DriverName $ad.ServiceName
}

Write-Host "`n[DONE] Kernel driver remediation routine complete. Please restart Windows to finalize changes." -ForegroundColor Green
