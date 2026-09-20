<#
.SYNOPSIS
    GPU Driver Diagnostics & Downgrade Prevention Tool
.DESCRIPTION
    Diagnoses display adapter driver health, detects automatic version downgrades,
    resolves dual-GPU driver conflicts, and prevents Windows Update from silently
    overwriting official GPU drivers (preventing DRIVER_POWER_STATE_FAILURE / BSOD 0x9F).
.PARAMETER Hours
    Hours back to scan for driver crash telemetry (default: 48).
.PARAMETER ApplyFix
    (Admin) Apply registry protections and align graphics drivers to prevent Windows Update overwrites.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 48,

    [Parameter(Mandatory = $false)]
    [switch]$ApplyFix
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Import DriverCheck Modules
$modulesDir = Join-Path $PSScriptRoot "scripts\modules"
Import-Module (Join-Path $modulesDir "DcHardwareHealth.psm1") -Force
Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  GPU DRIVER DIAGNOSTICS & DOWNGRADE PREVENTION TOOL" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Windows Update Driver Search Policies
Write-Host "=== Checking Windows Update & Driver Search Policies ===" -ForegroundColor Yellow
$hwInfo = Get-DcGpuDriverHealth

Write-Host "  1. Driver Searching Policy (SearchOrderConfig):" -NoNewline -ForegroundColor White
if ($hwInfo.SearchOrderConfig -eq 0) {
    Write-Host " [PROTECTED] Disabled (0) - Windows Update will not search for drivers." -ForegroundColor Green
} else {
    Write-Host " [EXPOSED] Enabled (1) - Windows Update may overwrite graphics drivers." -ForegroundColor Yellow
}

Write-Host "  2. Quality Update Driver Exclusion (ExcludeWUDriversInQualityUpdate):" -NoNewline -ForegroundColor White
if ($hwInfo.ExcludeWUDrivers -eq 1) {
    Write-Host " [PROTECTED] Enabled (1) - Drivers are excluded from Windows Quality Updates." -ForegroundColor Green
} else {
    Write-Host " [EXPOSED] Not Configured - Windows Update can install driver downgrades." -ForegroundColor Yellow
}
Write-Host ""

# 2. Inspect Active GPUs
Write-Host "=== Inspecting Active Display Adapters ===" -ForegroundColor Yellow
$hasIssues = $false

foreach ($gpu in $hwInfo.Gpus) {
    $statusColor = if ($gpu.IsGeneric) { [ConsoleColor]::Red } else { [ConsoleColor]::Green }
    Write-Host "  * $($gpu.Name)" -ForegroundColor White
    Write-Host "    +- Vendor:         $($gpu.Vendor)" -ForegroundColor DarkGray
    Write-Host "    +- Driver Version: $($gpu.DriverVersion)" -ForegroundColor DarkGray
    Write-Host "    +- Release Date:   $($gpu.DriverDate)" -ForegroundColor DarkGray
    Write-Host "    +- Provider:       $($gpu.Provider)" -ForegroundColor DarkGray
    Write-Host "    +- Status:         $($gpu.Status)" -ForegroundColor $statusColor

    if ($gpu.IsGeneric) {
        Write-Host "    [!] WARNING: Running on generic Microsoft Basic Display Adapter driver!" -ForegroundColor Red
        $hasIssues = $true
    }
}
Write-Host ""

# 3. Check Dual-GPU Conflict
if ($hwInfo.DualGpuConflict) {
    Write-Host "[!] CONFLICT DETECTED: $($hwInfo.DualGpuDetails)" -ForegroundColor Red
    $hasIssues = $true
} else {
    Write-Host "[ OK ] No dual-GPU driver stack conflicts detected." -ForegroundColor Green
}
Write-Host ""

# 4. Action / Fix Routine
if ($ApplyFix) {
    Write-Host "=== Applying GPU Driver Protections ===" -ForegroundColor Cyan
    if (-not (Test-DcIsAdmin)) {
        Write-Host "[ERROR] Administrator elevation is required to apply policy fixes." -ForegroundColor Red
        Write-Host "Please re-run PowerShell as Administrator." -ForegroundColor Yellow
        exit 1
    }

    Repair-DcAmdDriverAlignment -BlockWindowsUpdateDrivers
} else {
    if ($hasIssues -or -not $hwInfo.IsWUDriverBlocked) {
        Write-Host "------------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "Recommendations:" -ForegroundColor Yellow
        if (-not $hwInfo.IsWUDriverBlocked) {
            Write-Host "  * Windows Update is allowed to overwrite graphics drivers." -ForegroundColor White
            Write-Host "    To lock drivers and prevent automatic downgrades, run with:" -ForegroundColor White
            Write-Host "    .\Get-GPUDriverDiagnostics.ps1 -ApplyFix" -ForegroundColor Cyan
        }
        if ($hwInfo.DualGpuConflict) {
            Write-Host "  * Align discrete and integrated GPU drivers using the official AMD installer," -ForegroundColor White
            Write-Host "    or disable integrated graphics in BIOS if not using motherboard display ports." -ForegroundColor White
        }
    } else {
        Write-Host "[ OK ] Graphics hardware and Windows Update policies are properly aligned." -ForegroundColor Green
    }
}

Write-Host ""
