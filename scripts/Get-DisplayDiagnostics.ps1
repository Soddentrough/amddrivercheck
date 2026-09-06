<#
.SYNOPSIS
    Display, EDID & Monitor Timing Diagnostics
.DESCRIPTION
    Inspects connected displays, parses binary EDID Detailed Timing Descriptors (DTDs),
    calculates Pixel Clock (MHz) and blanking intervals, and identifies high-risk
    factory overclocks on DisplayPort 1.2a scalers that cause periodic 2-3s blackouts.
#>

[CmdletBinding()]
param()

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcHardwareHealth.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  DISPLAY, EDID & MONITOR TIMING DIAGNOSTICS" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

$diag = Get-DcDisplayDiagnostics

if ($diag.Displays.Count -gt 0) {
    Write-Host "Connected Display Inventory ($($diag.Displays.Count) display(s) detected):" -ForegroundColor Cyan
    Write-Host ""

    foreach ($d in $diag.Displays) {
        $nameColor = if ($d.HasTimingRisk) { [ConsoleColor]::Red } else { [ConsoleColor]::Yellow }
        Write-Host "  * Display: $($d.Name)" -ForegroundColor $nameColor
        Write-Host "    +- Connection:     $($d.Connection)" -ForegroundColor DarkGray
        Write-Host "    +- Monitor ID:     $($d.MonitorId)" -ForegroundColor DarkGray
        Write-Host "    +- Active Mode:    $($d.ActiveResolution) @ $($d.ActiveRefreshRate) Hz" -ForegroundColor White

        if ($d.Timings.Count -gt 0) {
            Write-Host "    +- EDID Detailed Timings:" -ForegroundColor DarkGray
            foreach ($t in ($d.Timings | Select-Object -First 5)) {
                $isRisk = ($t.PixelClockMHz -ge 585 -or $t.VTotal -ge 1500) -and ($t.RefreshRate -gt 144)
                $timingColor = if ($isRisk) { [ConsoleColor]::Red } else { [ConsoleColor]::DarkGray }
                $riskMarker = if ($isRisk) { " [!] HIGH SCALER RISK" } else { "" }
                Write-Host "       - $($t.HActive)x$($t.VActive) @ $($t.RefreshRate) Hz | Pixel Clock: $($t.PixelClockMHz) MHz | V-Total: $($t.VTotal) lines$riskMarker" -ForegroundColor $timingColor
            }
        }

        if ($d.HasTimingRisk) {
            Write-Host "    [!] TIMING HAZARD: High Pixel Clock / Scaler Saturation Detected!" -ForegroundColor Red
        }
        Write-Host ""
    }

    if ($diag.HighRiskTimingsDetected) {
        Write-Host "========================================================================" -ForegroundColor Red
        Write-Host "  HIGH-RISK DISPLAY TIMING / SCALER OVERCLOCK IDENTIFIED" -ForegroundColor Red
        Write-Host "========================================================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "  $($diag.RiskSummary)" -ForegroundColor White
        Write-Host ""
        Write-Host "  [ ACTIONABLE REMEDIATION ]:" -ForegroundColor Green
        Write-Host "  $($diag.Guidance)" -ForegroundColor White
        Write-Host ""
    } else {
        Write-Host "[ OK ] All display EDID timings and pixel clocks are within safe VESA scaler thresholds." -ForegroundColor Green
    }
} else {
    Write-Host "[!] No active displays or EDID descriptors found." -ForegroundColor Yellow
}

Write-Host ""
