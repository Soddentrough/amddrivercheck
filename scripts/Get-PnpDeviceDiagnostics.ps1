<#
.SYNOPSIS
    Plug and Play (PnP) Hardware Health & Missing Driver Diagnostics
.DESCRIPTION
    Audits present hardware devices across all classes to identify missing drivers (Code 28),
    device failures (Code 43), failed starts (Code 10), and disabled hardware.
#>

[CmdletBinding()]
param()

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Import Hardware Module if available
$modulesDir = Join-Path $PSScriptRoot "modules"
if (Test-Path (Join-Path $modulesDir "DcHardwareHealth.psm1")) {
    Import-Module (Join-Path $modulesDir "DcHardwareHealth.psm1") -Force
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  PLUG AND PLAY (PnP) HARDWARE HEALTH AUDIT" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

$badDevices = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -ne "OK" }

if ($badDevices) {
    Write-Host "[!] Found $($badDevices.Count) active device(s) with errors or missing drivers:" -ForegroundColor Red
    Write-Host ""
    foreach ($bd in $badDevices) {
        $remedy = switch ($bd.ConfigManagerErrorCode) {
            28 { "Install official motherboard chipset, audio, or vendor drivers for this device." }
            43 { "Hardware or driver crash. Clean reinstall device driver or test hardware." }
            10 { "Resource or firmware initialization failed. Update BIOS or reinstall driver." }
            14 { "Reboot required to complete device driver installation." }
            22 { "Device is currently disabled in Device Manager." }
            default { "Check Windows Device Manager properties for error details." }
        }

        Write-Host "  Device:      $($bd.FriendlyName)" -ForegroundColor Yellow
        Write-Host "  Status:      $($bd.Status) (Problem: $($bd.Problem))" -ForegroundColor Red
        Write-Host "  Error Code:  $($bd.ConfigManagerErrorCode)" -ForegroundColor DarkYellow
        Write-Host "  Instance ID: $($bd.InstanceId)" -ForegroundColor DarkGray
        Write-Host "  Action:      $remedy" -ForegroundColor White
        Write-Host "------------------------------------------------------------------------" -ForegroundColor DarkGray
    }
} else {
    Write-Host "[ OK ] All present PnP devices are reporting 100% HEALTHY (Status: OK)." -ForegroundColor Green
    Write-Host "Zero missing drivers, uninitialized PCI devices, or Code 28 errors detected." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Motherboard & Chipset Environment:" -ForegroundColor Cyan
$mb = Get-DcMotherboardAndChipsetHealth
Write-Host "  Motherboard : $($mb.MotherboardManufacturer) $($mb.MotherboardProduct)" -ForegroundColor White
Write-Host "  BIOS        : $($mb.BiosVersion) ($($mb.BiosReleaseDate))" -ForegroundColor White
Write-Host "  Chipset     : $($mb.Summary)" -ForegroundColor if ($mb.IsHealthy) { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }
if ($mb.MissingControllers.Count -gt 0) {
    Write-Host "  [!] Missing Controllers: $($mb.MissingControllers -join ', ')" -ForegroundColor Red
}
Write-Host ""
