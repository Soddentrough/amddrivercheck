<#
.SYNOPSIS
    Windows Update & Driver Installation History Audit
.DESCRIPTION
    Audits recently installed Windows Quality Updates, driver updates, and Defender
    definitions to identify changes that correlate with new crashes.
.PARAMETER Days
    Number of days back to inspect (default: 14).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Days = 14
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  WINDOWS UPDATE & DRIVER INSTALLATION HISTORY AUDIT" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

$cutoff = (Get-Date).AddDays(-$Days)
Write-Host "Inspecting updates installed between $($cutoff.ToString('yyyy-MM-dd')) and $((Get-Date).ToString('yyyy-MM-dd'))..." -ForegroundColor DarkGray
Write-Host ""

$foundUpdates = $false

# 1. Query Windows Update Session History (COM)
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $totalCount = $searcher.GetTotalHistoryCount()
    if ($totalCount -gt 0) {
        $history = $searcher.QueryHistory(0, [math]::Min(30, $totalCount))
        $recent = $history | Where-Object { $_.Date -ge $cutoff }
        if ($recent) {
            $foundUpdates = $true
            Write-Host "Recent Windows Updates (from Windows Update Agent):" -ForegroundColor Cyan
            foreach ($u in $recent) {
                Write-Host "  * [$($u.Date.ToString('yyyy-MM-dd HH:mm'))] $($u.Title)" -ForegroundColor White
            }
            Write-Host ""
        }
    }
} catch {
    # Fallback to WMI
}

# 2. Query Installed Hotfixes (WMI QuickFixEngineering)
$hotfixes = Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue |
    Where-Object {
        $instDate = [datetime]::MinValue
        if ([datetime]::TryParse($_.InstalledOn, [ref]$instDate)) {
            $instDate -ge $cutoff
        } else {
            $true
        }
    } | Select-Object -First 10

if ($hotfixes) {
    $foundUpdates = $true
    Write-Host "Installed Windows Hotfixes (Win32_QuickFixEngineering):" -ForegroundColor Cyan
    foreach ($hf in $hotfixes) {
        Write-Host "  * [$($hf.InstalledOn)] $($hf.HotFixID): $($hf.Description)" -ForegroundColor White
    }
    Write-Host ""
}

if (-not $foundUpdates) {
    Write-Host "[ OK ] No new Windows quality updates or hotfixes recorded in the past $Days days." -ForegroundColor Green
}

Write-Host ""
