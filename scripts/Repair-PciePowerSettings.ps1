<#
.SYNOPSIS
    PCI Express Link State Power Management Optimizer
.DESCRIPTION
    Disables PCI Express Link State Power Management (ASPM) in the active Windows Power Scheme.
    Prevents the PCIe link between the CPU and GPU from dropping to low-power L0s/L1 states during
    idle or video playback, resolving random GPU driver timeouts (TDR 4101), blackouts, and sleep-wake crashes.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param()

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force
Import-Module (Join-Path $modulesDir "DcSystemTelemetry.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  PCIE LINK STATE POWER MANAGEMENT (ASPM) OPTIMIZER" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

$before = Get-DcPciePowerManagementStatus
Write-Host "Current Configuration:" -ForegroundColor Cyan
Write-Host "  Power Plan : $($before.SchemeName) ($($before.SchemeGuid))" -ForegroundColor White
Write-Host "  AC Setting : $($before.ACSettingName)" -ForegroundColor $(if ($before.IsEnabled) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green })
Write-Host "  DC Setting : $($before.DCSettingName)" -ForegroundColor DarkGray
Write-Host ""

if (-not $before.IsEnabled) {
    Write-Host "[OK] PCIe Link State Power Management is already set to OFF." -ForegroundColor Green
    Write-Host "No changes needed." -ForegroundColor DarkGray
    return
}

$success = Repair-DcPciePowerSettings
if ($success) {
    $after = Get-DcPciePowerManagementStatus
    Write-Host "`nUpdated Configuration:" -ForegroundColor Cyan
    Write-Host "  AC Setting : $($after.ACSettingName)" -ForegroundColor Green
    Write-Host "  DC Setting : $($after.DCSettingName)" -ForegroundColor Green
    Write-Host "`n[SUCCESS] PCIe Link State Power Management has been disabled." -ForegroundColor Green
    Write-Host "The PCIe bus will maintain active high-frequency clocking without power-state throttling." -ForegroundColor DarkGray
} else {
    Write-Host "`n[NOTICE] Configuration was not applied or skipped." -ForegroundColor Yellow
}
