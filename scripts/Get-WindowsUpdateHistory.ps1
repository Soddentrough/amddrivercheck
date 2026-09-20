<#
.SYNOPSIS
    Windows Update & Component Installation History Inspector
.DESCRIPTION
    Audits recently installed Quality Updates, Defender Security Intelligence updates,
    Gaming Filter drivers (gameflt.sys), and Microsoft Store gaming packages.
    Helps detect stealth background updates that coincide with crash cascades.
.PARAMETER Days
    Number of days back to scan for update events (default: 14).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Days = 14
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$cutoff = (Get-Date).AddDays(-$Days)

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  WINDOWS UPDATE & COMPONENT INSTALLATION AUDIT (PAST $Days DAYS)" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Hotfix List
Write-Host "--- Installed Windows Quality Hotfixes (Get-HotFix) ---" -ForegroundColor Yellow
$hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
if ($hotfixes) {
    foreach ($hf in ($hotfixes | Select-Object -First 10)) {
        $instDate = if ($hf.InstalledOn) { $hf.InstalledOn.ToString('yyyy-MM-dd') } else { "Unknown" }
        Write-Host "  * $($hf.HotFixID) " -NoNewline -ForegroundColor White
        Write-Host "($($hf.Description)) " -NoNewline -ForegroundColor DarkGray
        Write-Host "- Installed: $instDate by $($hf.InstalledBy)" -ForegroundColor DarkCyan
    }
} else {
    Write-Host "  [!] Unable to query hotfix list." -ForegroundColor DarkGray
}

# 2. Windows Update Client Event Log
Write-Host ""
Write-Host "--- Windows Update Client Installation History ---" -ForegroundColor Yellow
$wuEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(19, 20, 21, 22) -or $_.Message -match 'Installation (Successful|Started)' }

if ($wuEvents) {
    $successfulInstalls = $wuEvents | Where-Object { $_.Message -match 'Installation Successful' }
    Write-Host "  Found $($successfulInstalls.Count) package installation(s) in the past $Days days:" -ForegroundColor White
    foreach ($wue in ($successfulInstalls | Select-Object -First 15)) {
        $cleanMsg = ($wue.Message -split "`r`n")[0].Trim()
        Write-Host "  * [$($wue.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] $cleanMsg" -ForegroundColor DarkGray
    }
    if ($successfulInstalls.Count -gt 15) {
        Write-Host "    ... and $($successfulInstalls.Count - 15) more package installations." -ForegroundColor DarkGray
    }
} else {
    Write-Host "  [ OK ] No recent Windows Update installation events recorded." -ForegroundColor Green
}

# 3. Gaming Services & Filter Driver Checks (gameflt.sys)
Write-Host ""
Write-Host "--- Gaming Filter & Overlay Drivers ---" -ForegroundColor Yellow
$gameflt = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\gameflt" -ErrorAction SilentlyContinue
if ($gameflt) {
    Write-Host "  * Microsoft Gaming Filter Driver (gameflt.sys): Installed (StartType: $($gameflt.Start))" -ForegroundColor White
}
$setupApi = "C:\Windows\INF\setupapi.dev.log"
if (Test-Path $setupApi) {
    $recentInstalls = Get-Content $setupApi -Tail 150 -ErrorAction SilentlyContinue |
        Select-String -Pattern "Section start|Selected driver package" | Select-Object -Last 6
    if ($recentInstalls) {
        Write-Host "  Recent Driver Store Activations (SetupAPI Log):" -ForegroundColor DarkGray
        foreach ($ri in $recentInstalls) {
            Write-Host "    $ri" -ForegroundColor DarkGray
        }
    }
}

Write-Host ""
