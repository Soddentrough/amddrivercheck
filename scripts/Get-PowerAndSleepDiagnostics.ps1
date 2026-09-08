<#
.SYNOPSIS
    Power, Fast Startup, and Sleep/Wake Transition Diagnostics
.DESCRIPTION
    Audits Windows Fast Startup, hibernation settings, unexpected shutdowns (Event 6008),
    dirty reboots (Event 41), and sleep/wake power state transitions.
.PARAMETER Hours
    Hours back to scan for power telemetry (default: 48).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 48
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcSystemTelemetry.psm1") -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  POWER, FAST STARTUP & SLEEP TRANSITION DIAGNOSTICS" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

# 1. Fast Startup & Hibernation Configuration
$powerReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -ErrorAction SilentlyContinue
$fastStartup = ($powerReg -and $powerReg.HiberbootEnabled -eq 1)

Write-Host "Power Configuration Audit:" -ForegroundColor Cyan
if ($fastStartup) {
    Write-Host "  [!] Fast Startup (HiberbootEnabled) : ENABLED (1)" -ForegroundColor Yellow
    Write-Host "      Notice: Fast Startup saves hybrid kernel session states to disk on shutdown." -ForegroundColor DarkYellow
    Write-Host "      If hardware drivers fail power IRPs, this causes recurring 0x9F crash loops." -ForegroundColor DarkYellow
} else {
    Write-Host "  [ OK ] Fast Startup (HiberbootEnabled) : DISABLED (0 - Clean Cold Boot)" -ForegroundColor Green
}

$pciePower = Get-DcPciePowerManagementStatus
if ($pciePower.IsEnabled) {
    Write-Host "  [!] PCIe Link State Power Management : ENABLED ($($pciePower.ACSettingName))" -ForegroundColor Red
    Write-Host "      Power Plan: $($pciePower.SchemeName)" -ForegroundColor DarkGray
    Write-Host "      Hazard: Puts PCIe bus into low-power L0s/L1 states during idle/video." -ForegroundColor Yellow
    Write-Host "      Modern GPUs (PCIe 4.0/5.0) can timeout (TDR 4101) or crash waking from sleep." -ForegroundColor Yellow
    Write-Host "      Remediation: Run '.\scripts\Repair-PciePowerSettings.ps1' to set Link State to OFF." -ForegroundColor Cyan
} else {
    Write-Host "  [ OK ] PCIe Link State Power Management : OFF (Continuous high-speed link clock)" -ForegroundColor Green
}

# 2. Sleep / Wake Events & Power Transitions
$cutoff = (Get-Date).AddHours(-$Hours)
Write-Host "`nRecent Sleep & Power Transition Telemetry (Past $Hours hours):" -ForegroundColor Cyan

# Note: Event 6008 comes from EventLog provider, Event 41 from Kernel-Power, Event 1 from Power-Troubleshooter
$powerEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object {
        ($_.Id -in @(1, 42, 107, 566) -and $_.ProviderName -match 'Power-Troubleshooter|Kernel-Power') -or
        ($_.Id -eq 41 -and $_.ProviderName -match 'Kernel-Power') -or
        ($_.Id -eq 6008)
    }

if ($powerEvents) {
    foreach ($pe in ($powerEvents | Select-Object -First 15)) {
        $color = if ($pe.Id -in @(41, 6008)) { [ConsoleColor]::Red } elseif ($pe.Id -eq 1) { [ConsoleColor]::Green } else { [ConsoleColor]::DarkGray }
        Write-Host "  * [$($pe.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] Event $($pe.Id) ($($pe.ProviderName))" -ForegroundColor $color
        if ($pe.Id -eq 1) {
            $msgSnippet = ($pe.Message -split "`r?`n" | Select-Object -First 2) -join " "
            Write-Host "    Wake: $msgSnippet" -ForegroundColor DarkGray
        } elseif ($pe.Id -eq 41) {
            Write-Host "    Critical: System rebooted without cleanly shutting down first (Power cut or hard crash)." -ForegroundColor Red
        } elseif ($pe.Id -eq 6008) {
            Write-Host "    Critical: The previous system shutdown was unexpected." -ForegroundColor Red
        } elseif ($pe.Id -eq 42) {
            Write-Host "    Info: The system is entering sleep." -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host "  [ OK ] No power transition errors or unexpected shutdowns recorded." -ForegroundColor Green
}

Write-Host ""
