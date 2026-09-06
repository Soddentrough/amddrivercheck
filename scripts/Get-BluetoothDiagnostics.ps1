<#
.SYNOPSIS
    Bluetooth Controller, Audio, and Radio Diagnostics
.DESCRIPTION
    Audits Bluetooth radio status, connected gaming controllers (DualSense, Xbox, VR, Stadia),
    audio devices, BTHUSB driver errors, and connection reset telemetry.
.PARAMETER Hours
    Hours back to scan for Bluetooth errors in event log (default: 48).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 48
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  BLUETOOTH HARDWARE & GAMING CONTROLLER AUDIT" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

# 1. Enumerate Bluetooth Radios & Adapters
$btDevices = Get-PnpDevice -Class Bluetooth -PresentOnly -ErrorAction SilentlyContinue
$radios = $btDevices | Where-Object { $_.FriendlyName -match '(?i)Adapter|Radio|Bluetooth Device' -and $_.FriendlyName -notmatch 'LE Generic|Enumerator' }
$controllers = $btDevices | Where-Object { $_.FriendlyName -match '(?i)Controller|DualSense|Xbox|Stadia|VR|Sense' }
$audio = $btDevices | Where-Object { $_.FriendlyName -match '(?i)Buds|Headphones|Headset|AirPods|WH-|WF-' }

Write-Host "Bluetooth Radios & Hardware Adapters:" -ForegroundColor Cyan
if ($radios) {
    foreach ($r in $radios) {
        $color = if ($r.Status -eq "OK") { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
        Write-Host "  * $($r.FriendlyName) [$($r.Status)]" -ForegroundColor $color
    }
} else {
    Write-Host "  [!] No Bluetooth radio adapter found." -ForegroundColor Yellow
}

Write-Host "`nGaming Controllers & Input Devices:" -ForegroundColor Cyan
if ($controllers) {
    foreach ($c in $controllers) {
        Write-Host "  * $($c.FriendlyName) (Status: $($c.Status))" -ForegroundColor White
    }
} else {
    Write-Host "  No Bluetooth controllers currently connected." -ForegroundColor DarkGray
}

Write-Host "`nAudio Devices & Headsets:" -ForegroundColor Cyan
if ($audio) {
    foreach ($a in $audio) {
        Write-Host "  * $($a.FriendlyName) (Status: $($a.Status))" -ForegroundColor White
    }
} else {
    Write-Host "  No Bluetooth audio devices currently connected." -ForegroundColor DarkGray
}

# 2. Check for Bluetooth Errors / Dropouts in Event Log
$cutoff = (Get-Date).AddHours(-$Hours)
Write-Host "`nBluetooth Event Telemetry (Past $Hours hours):" -ForegroundColor Cyan

$btEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=@('BTHUSB','BthLEEnum','Bluetooth-BthLEEnum'); StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object { $_.LevelDisplayName -match 'Error|Warning' }

if ($btEvents) {
    foreach ($be in ($btEvents | Select-Object -First 5)) {
        Write-Host "  [!] [$($be.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] $($be.ProviderName) Event $($be.Id): $($be.Message.Trim())" -ForegroundColor Red
    }
    Write-Host "`n  Tip: Bluetooth dropouts during gaming are often caused by USB 3.0 RF interference" -ForegroundColor Yellow
    Write-Host "       or USB Selective Suspend power saving settings in Windows Power Options." -ForegroundColor Yellow
} else {
    Write-Host "  [ OK ] Zero Bluetooth driver dropouts or BTHUSB errors recorded." -ForegroundColor Green
}

Write-Host ""
