<#
.SYNOPSIS
    Bluetooth Device & USB Host Diagnostic Tool
.DESCRIPTION
    Inspects active Bluetooth adapters, PnP error codes, Bluetooth Support Service status,
    and scans System logs for BTHUSB Event ID 3 timeouts and disconnection events.
#>

[CmdletBinding()]
param()

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host ""
Write-Host "=== BLUETOOTH ADAPTER & PNP DEVICE STATUS ===" -ForegroundColor Cyan
$btDevices = Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -eq 'Bluetooth' -or $_.Name -match 'Bluetooth|MediaTek' }

if ($btDevices) {
    foreach ($dev in $btDevices) {
        Write-Host "----------------------------------------------------" -ForegroundColor Gray
        Write-Host "Device Name:           $($dev.Name)" -ForegroundColor Yellow
        Write-Host "Status:                $($dev.Status)" -ForegroundColor White
        Write-Host "PNP Device ID:         $($dev.PNPDeviceID)" -ForegroundColor White
        $errCode = $dev.ConfigManagerErrorCode
        if ($errCode -ne 0) {
            Write-Host "Config Error Code:     $errCode (Warning: Device Error State)" -ForegroundColor Red
        } else {
            Write-Host "Config Error Code:     0 (OK)" -ForegroundColor Green
        }
    }
} else {
    Write-Host "No Bluetooth class devices detected." -ForegroundColor DarkGray
}

Write-Host "`n=== RECENT BLUETOOTH SYSTEM EVENT LOGS (PAST 48 HOURS) ===" -ForegroundColor Cyan
$startTime = (Get-Date).AddHours(-48)
$btEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$startTime} -ErrorAction SilentlyContinue | 
    Where-Object { $_.ProviderName -match 'BTHUSB|BTHPORT|Bluetooth|HidBth' -or $_.Message -match 'Bluetooth' }

if ($btEvents) {
    foreach ($e in $btEvents) {
        Write-Host "----------------------------------------------------" -ForegroundColor Gray
        Write-Host "Time:     $($e.TimeCreated)" -ForegroundColor Yellow
        Write-Host "ID:       $($e.Id) ($($e.ProviderName))" -ForegroundColor Yellow
        Write-Host "Message:  $($e.Message.Trim())" -ForegroundColor White
    }
} else {
    Write-Host "No Bluetooth/BTHUSB events in System log in the past 48 hours." -ForegroundColor DarkGray
}

Write-Host "`n=== BLUETOOTH SUPPORT SERVICES STATUS ===" -ForegroundColor Cyan
Get-Service -Name "bthserv", "bthhfsrv", "BluetoothUserService*" -ErrorAction SilentlyContinue | Format-Table Name, Status, StartType -AutoSize
Write-Host ""
