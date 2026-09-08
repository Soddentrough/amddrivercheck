<#
.SYNOPSIS
    Motherboard, BIOS, and Chipset Driver Diagnostics
.DESCRIPTION
    Audits motherboard model, BIOS version/date, installed chipset software package
    (AMD Chipset Software / Intel Chipset Device Software), and core platform controller
    drivers (AMD GPIO, I2C, PCI, PSP, 3D V-Cache / Intel MEI).
#>

[CmdletBinding()]
param()

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
if (Test-Path (Join-Path $modulesDir "DcHardwareHealth.psm1")) {
    Import-Module (Join-Path $modulesDir "DcHardwareHealth.psm1") -Force
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  MOTHERBOARD, BIOS & CHIPSET DRIVER DIAGNOSTICS" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

$mb = Get-DcMotherboardAndChipsetHealth

# 1. Motherboard & BIOS
Write-Host "Motherboard & Firmware:" -ForegroundColor Cyan
Write-Host "  Motherboard : $($mb.MotherboardManufacturer) $($mb.MotherboardProduct) $($mb.MotherboardVersion)" -ForegroundColor White
$biosAgeNotice = if ($mb.BiosAgeYears) { " ($($mb.BiosAgeYears) years old)" } else { "" }
$biosColor = if ($mb.IsBiosOutdated) { [ConsoleColor]::Yellow } else { [ConsoleColor]::White }
Write-Host "  BIOS Version: $($mb.BiosVersion) | Released: $($mb.BiosReleaseDate)$biosAgeNotice" -ForegroundColor $biosColor
if ($mb.IsBiosOutdated) {
    Write-Host "  [!] Notice: BIOS appears to be >3 years old. Consider updating motherboard BIOS if experiencing PCIe link errors, USB dropouts, or RAM instability." -ForegroundColor DarkYellow
}
Write-Host ""

# 2. Processor & Chipset Package
Write-Host "Platform & Chipset Software:" -ForegroundColor Cyan
Write-Host "  CPU         : $($mb.CpuName)" -ForegroundColor White
if ($mb.ChipsetSoftware) {
    Write-Host "  [ OK ] Installed Software : $($mb.ChipsetSoftware) v$($mb.ChipsetVersion)" -ForegroundColor Green
    if ($mb.ChipsetInstallDate) {
        Write-Host "         Install Date       : $($mb.ChipsetInstallDate)" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  [!] Installed Software : Not detected in standard uninstall registry." -ForegroundColor Yellow
    Write-Host "      (If you have not installed official motherboard chipset drivers, install them from your vendor or AMD/Intel)." -ForegroundColor DarkYellow
}
Write-Host ""

# 3. Core Platform Controllers
Write-Host "Core Platform Drivers (PnP Audit):" -ForegroundColor Cyan
foreach ($c in $mb.ChipsetControllers) {
    $statusColor = if ($c.Status -eq "OK" -or $c.Status -eq "Running") { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
    Write-Host "  +- $($c.Controller):" -ForegroundColor White
    Write-Host "     Status   : $($c.Status)" -ForegroundColor $statusColor
    Write-Host "     Driver   : $($c.DriverVer) ($($c.Provider))" -ForegroundColor DarkGray
}

if ($mb.MissingControllers.Count -gt 0) {
    Write-Host ""
    Write-Host "  [!] Chipset Driver Warning: Potential missing or uninitialized controllers:" -ForegroundColor Red
    foreach ($mc in $mb.MissingControllers) {
        Write-Host "      * $mc" -ForegroundColor Red
    }
    Write-Host "  Recommendation: Download and run the latest official chipset driver package from your motherboard support page or AMD.com / Intel.com." -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "  [ OK ] All audited platform chipset controllers are active and reporting healthy." -ForegroundColor Green
}

Write-Host ""
