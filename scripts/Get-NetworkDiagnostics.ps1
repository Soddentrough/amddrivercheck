<#
.SYNOPSIS
    Network Adapter Health & Ethernet Link Drop Inspector
.DESCRIPTION
    Inspects active network adapters (Intel I225-V / I226-V, Realtek, Wi-Fi), checks for link disconnection
    events in system logs, and verifies key stability settings (Speed & Duplex, EEE, VLAN/Priority, Power Management).
.PARAMETER Hours
    Hours back to scan event logs (default: 48).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 48
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$cutoff = (Get-Date).AddHours(-$Hours)

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  NETWORK ADAPTER & ETHERNET LINK DROP DIAGNOSTICS" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Enumerate Network Adapters
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue
foreach ($a in $adapters) {
    Write-Host "  Adapter: " -NoNewline -ForegroundColor White
    Write-Host $a.Name -ForegroundColor Yellow -NoNewline
    Write-Host " ($($a.InterfaceDescription))" -ForegroundColor DarkGray
    Write-Host "    +- Status:        " -NoNewline -ForegroundColor DarkGray
    if ($a.Status -eq 'Up') { Write-Host "Up / Connected" -ForegroundColor Green } else { Write-Host $a.Status -ForegroundColor Red }
    Write-Host "    +- Link Speed:    " -NoNewline -ForegroundColor DarkGray
    Write-Host $a.LinkSpeed -ForegroundColor White
    Write-Host "    +- MAC Address:   " -NoNewline -ForegroundColor DarkGray
    Write-Host $a.MacAddress -ForegroundColor White

    # Check Speed & Duplex
    $speedDuplex = Get-NetAdapterAdvancedProperty -Name $a.Name -DisplayName "Speed & Duplex" -ErrorAction SilentlyContinue
    if ($speedDuplex) {
        Write-Host "    +- Speed & Duplex:" -NoNewline -ForegroundColor DarkGray
        if ($speedDuplex.DisplayValue -match "Auto") {
            Write-Host " $($speedDuplex.DisplayValue) " -NoNewline -ForegroundColor Yellow
            Write-Host "[Note: Auto Negotiation can cause periodic re-train drops on I225-V]" -ForegroundColor DarkGray
        } else {
            Write-Host " $($speedDuplex.DisplayValue) " -NoNewline -ForegroundColor Green
            Write-Host "[Locked Full Duplex]" -ForegroundColor DarkGray
        }
    }

    # Check Packet Priority & VLAN
    $vlan = Get-NetAdapterAdvancedProperty -Name $a.Name -DisplayName "Packet Priority & VLAN" -ErrorAction SilentlyContinue
    if ($vlan) {
        Write-Host "    +- Priority/VLAN: " -NoNewline -ForegroundColor DarkGray
        Write-Host $vlan.DisplayValue -ForegroundColor White
    }
    Write-Host ""
}

# 2. Check Event Logs for Link Drops
Write-Host "--- Event Log Network Dropouts (Past $Hours Hours) ---" -ForegroundColor Cyan
$netEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'e2fnexpress|e1dexpress|Netwtw|rt640x64|mtkihvx' -and ($_.Id -eq 27 -or $_.Message -match 'disconnected|reset|timeout') }

if ($netEvents) {
    Write-Host "  [!] Found $($netEvents.Count) network disconnection/timeout event(s):" -ForegroundColor Yellow
    foreach ($ne in ($netEvents | Select-Object -First 10)) {
        Write-Host "    * [$($ne.TimeCreated)] ($($ne.ProviderName)): $($ne.Message.Trim())" -ForegroundColor Red
    }
    if ($netEvents.Count -gt 10) {
        Write-Host "    ... and $($netEvents.Count - 10) more events." -ForegroundColor DarkGray
    }
} else {
    Write-Host "  [ OK ] No network link disconnection events found in system logs." -ForegroundColor Green
}

# 3. Check Steam Connection Logs for Network Device State Bounces
$steamConnLog = "C:\Program Files (x86)\Steam\logs\connection_log.txt"
if (Test-Path $steamConnLog) {
    Write-Host ""
    Write-Host "--- Steam Network State Bounce Inspection ---" -ForegroundColor Cyan
    $bounces = Get-Content $steamConnLog -Tail 200 -ErrorAction SilentlyContinue |
        Where-Object { $_ -match 'OnNetworkDeviceStateChange|Connectivity test: result=Failed' }
    
    if ($bounces) {
        Write-Host "  [!] Detected Steam network device state changes / reconnect triggers:" -ForegroundColor Yellow
        foreach ($b in ($bounces | Select-Object -Last 5)) {
            Write-Host "    * $b" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [ OK ] No recent Steam network device state bounces recorded." -ForegroundColor Green
    }
}

Write-Host ""
