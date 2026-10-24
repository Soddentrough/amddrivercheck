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

$modulesDir = Join-Path $PSScriptRoot "modules"
if (Test-Path (Join-Path $modulesDir "DriverCheck.psm1")) {
    Import-Module (Join-Path $modulesDir "DriverCheck.psm1") -Force
}

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

Write-Host "`nWindows Dynamic (Ephemeral) Port Allocation:" -ForegroundColor Cyan
$udpDynamicV4 = & netsh int ipv4 show dynamicport udp 2>$null
$tcpDynamicV4 = & netsh int ipv4 show dynamicport tcp 2>$null
$udpStart = $null; $udpNum = $null
$tcpStart = $null; $tcpNum = $null

if ($udpDynamicV4) {
    foreach ($line in $udpDynamicV4) {
        if ($line -match 'Start Port\s*:\s*(\d+)') { $udpStart = [int]$matches[1] }
        if ($line -match 'Number of Ports\s*:\s*(\d+)') { $udpNum = [int]$matches[1] }
    }
}
if ($tcpDynamicV4) {
    foreach ($line in $tcpDynamicV4) {
        if ($line -match 'Start Port\s*:\s*(\d+)') { $tcpStart = [int]$matches[1] }
        if ($line -match 'Number of Ports\s*:\s*(\d+)') { $tcpNum = [int]$matches[1] }
    }
}

Write-Host "  * TCP Dynamic Port Range: $tcpStart-$($tcpStart + $tcpNum - 1) ($tcpNum ports)" -ForegroundColor DarkGray
if ($udpNum -and $udpNum -lt 30000 -and $tcpNum -ge 30000) {
    Write-Host "  * UDP Dynamic Port Range: $udpStart-$($udpStart + $udpNum - 1) ($udpNum ports)" -ForegroundColor Yellow
    Write-Host "    [!] CAUTION: UDP dynamic port space is constrained to $udpNum ports (vs TCP $tcpNum)." -ForegroundColor Yellow
    Write-Host "        Steam/game matchmaking and server queries can rapidly exhaust 16k UDP ports, triggering" -ForegroundColor DarkYellow
    Write-Host "        Tcpip Event 4266 errors, ARP/DNS probe timeouts, and socket stalls." -ForegroundColor DarkYellow
    Write-Host "        Remediation: run '.\scripts\Repair-EthernetSettings.ps1 -ExpandUdpPorts' as Administrator." -ForegroundColor Cyan
} else {
    Write-Host "  * UDP Dynamic Port Range: $udpStart-$($udpStart + $udpNum - 1) ($udpNum ports)" -ForegroundColor Green
}

$cutoff = (Get-Date).AddHours(-$Hours)
Write-Host "`nNetwork Driver Telemetry & Link Flapping (Past $Hours hours):" -ForegroundColor Cyan

$netIds = @(27, 32, 33, 1014, 4202, 4227, 4231, 4266, 5002, 5005, 5007, 10400)
$rawNicEvents = if (Get-Command Get-DcWinEventsTargeted -ErrorAction SilentlyContinue) {
    Get-DcWinEventsTargeted -LogName 'System' -Ids $netIds -StartTime $cutoff
} else {
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=$netIds; StartTime=$cutoff} -ErrorAction SilentlyContinue
}
$nicEvents = $rawNicEvents | Where-Object {
    $_.ProviderName -match '(?i)e2fn?express|e1dexpress|Netwtw|rt640x64|rt68|ndis|Tcpip|DNS Client Events' -or
    $_.Message -match '(?i)Network link is disconnected|link has been disconnected'
}

$ncsiEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NCSI/Operational'; Id=4042; StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Capability:\s*None|SuspectArpProbeFailed' }

$pciResets = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PCI/Operational'; Id=1; StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Begin state transition from STARTED to UNINITIALIZED' }

$wlanEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; Id=@(8000, 11000); StartTime=$cutoff} -ErrorAction SilentlyContinue

$hasNetIssue = $false
if ($pciResets) {
    $hasNetIssue = $true
    # Cache PnP PCI devices by location string for hardware PDO resolution
    $pciLocationMap = @{}
    try {
        $pciDevices = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'PCI*' }
        foreach ($pd in $pciDevices) {
            $loc = (Get-PnpDeviceProperty -InstanceId $pd.InstanceId -KeyName 'DEVPKEY_Device_LocationInfo' -ErrorAction SilentlyContinue).Data
            if ($loc) {
                $pciLocationMap[$loc.Trim().ToLower()] = [PSCustomObject]@{
                    FriendlyName = $pd.FriendlyName
                    Location     = $loc.Trim()
                }
            }
        }
    } catch {}

    foreach ($pr in ($pciResets | Select-Object -First 5)) {
        $pdo = if ($pr.Message -match '\[PDO\]\s*\((.*?)\)') { $Matches[1] } else { "Unknown" }
        $devLabel = "Hardware PDO ($pdo)"
        if ($pdo -match '0x([0-9a-fA-F]+)\.0x([0-9a-fA-F]+)\.0x([0-9a-fA-F]+)') {
            try {
                $b = [Convert]::ToInt32($Matches[1], 16)
                $d = [Convert]::ToInt32($Matches[2], 16)
                $f = [Convert]::ToInt32($Matches[3], 16)
                $locKey = "pci bus $b, device $d, function $f"
                if ($pciLocationMap.ContainsKey($locKey)) {
                    $m = $pciLocationMap[$locKey]
                    $devLabel = "$($m.FriendlyName) ($($m.Location))"
                }
            } catch {}
        }
        Write-Host "  [!] [$($pr.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] Microsoft-Windows-PCI (Event 1): $devLabel underwent bus uninitialization/reset." -ForegroundColor Red
    }
}
if ($nicEvents) {
    $hasNetIssue = $true
    foreach ($ne in ($nicEvents | Select-Object -First 10)) {
        $color = if ($ne.Id -eq 4266) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Red }
        Write-Host "  [!] [$($ne.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] $($ne.ProviderName) (Event $($ne.Id)): $($ne.Message.Trim())" -ForegroundColor $color
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
        $msg = ($we.Message.Split("`n")[0].Trim()) -replace '(?i)SSID:\s*([^\s,\r\n]+)', 'SSID: [Redacted]'
        Write-Host "  [!] [$($we.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] WLAN-AutoConfig (Event $($we.Id)): $msg" -ForegroundColor Yellow
    }
}

if (-not $hasNetIssue) {
    Write-Host "  [ OK ] Zero network link disconnects, DNS timeouts, ARP probe failures, PCI bus resets, or NIC driver resets recorded." -ForegroundColor Green
}

Write-Host ""
