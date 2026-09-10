<#
.SYNOPSIS
    Network Adapter Health & Stability Diagnostics
.DESCRIPTION
    Audits network adapter link speed, duplex negotiation, packet priority/VLAN configuration,
    and event log telemetry for link dropouts or driver resets.
.PARAMETER Hours
    Hours back to scan for network event errors (default: 48).
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
Write-Host "  NETWORK ADAPTER HEALTH & LINK STABILITY AUDIT" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

$adapters = Get-NetAdapter -ErrorAction SilentlyContinue

Write-Host "Active Network Adapters:" -ForegroundColor Cyan
foreach ($a in $adapters) {
    $speedDuplex = Get-NetAdapterAdvancedProperty -Name $a.Name -DisplayName "Speed & Duplex" -ErrorAction SilentlyContinue
    $sdVal = if ($speedDuplex) { $speedDuplex.DisplayValue } else { "N/A" }

    $vlan = Get-NetAdapterAdvancedProperty -Name $a.Name -DisplayName "Packet Priority & VLAN" -ErrorAction SilentlyContinue
    $vlanVal = if ($vlan) { $vlan.DisplayValue } else { "N/A" }

    $color = if ($a.Status -eq "Up") { [ConsoleColor]::Green } else { [ConsoleColor]::DarkGray }
    Write-Host "  * $($a.Name) - $($a.InterfaceDescription)" -ForegroundColor White
    Write-Host "    +- Status:        $($a.Status)" -ForegroundColor $color
    Write-Host "    +- Link Speed:    $($a.LinkSpeed)" -ForegroundColor DarkGray
    Write-Host "    +- Speed/Duplex:  $sdVal" -ForegroundColor DarkGray
    Write-Host "    +- Priority/VLAN: $vlanVal" -ForegroundColor DarkGray
}

$cutoff = (Get-Date).AddHours(-$Hours)
Write-Host "`nNetwork Driver Telemetry & Link Flapping (Past $Hours hours):" -ForegroundColor Cyan

$nicEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object {
        $_.ProviderName -match '(?i)e2fexpress|e1dexpress|Netwtw|rt640x64|Tcpip|DNS Client Events' -and
        ($_.LevelDisplayName -match 'Error|Warning' -or $_.Id -in @(27, 32, 1014, 4202, 4266))
    }

$ncsiEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NCSI/Operational'; StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 4042 -and ($_.Message -match 'Capability:\s*None|SuspectArpProbeFailed') }

$wlanEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(8000, 11000) }

$hasNetIssue = $false
if ($nicEvents) {
    $hasNetIssue = $true
    foreach ($ne in ($nicEvents | Select-Object -First 5)) {
        Write-Host "  [!] [$($ne.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] $($ne.ProviderName) (Event $($ne.Id)): $($ne.Message.Trim())" -ForegroundColor Red
    }
}
if ($ncsiEvents) {
    $hasNetIssue = $true
    foreach ($ne in ($ncsiEvents | Select-Object -First 5)) {
        $msg = $ne.Message.Replace("`r`n", " ").Trim()
        Write-Host "  [!] [$($ne.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] NCSI (Event 4042): $msg" -ForegroundColor Red
    }
}
if ($wlanEvents) {
    $hasNetIssue = $true
    foreach ($we in ($wlanEvents | Select-Object -First 3)) {
        $msg = $we.Message.Split("`n")[0].Trim()
        Write-Host "  [!] [$($we.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] WLAN-AutoConfig (Event $($we.Id)): $msg" -ForegroundColor Yellow
    }
}

if (-not $hasNetIssue) {
    Write-Host "  [ OK ] Zero network link disconnects, DNS timeouts, ARP probe failures, or NIC driver resets recorded." -ForegroundColor Green
}

Write-Host ""
