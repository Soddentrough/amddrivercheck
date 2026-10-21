<#
.SYNOPSIS
    Windows Update & Driver Installation History Audit
.DESCRIPTION
    Audits recently installed Windows Quality Updates, driver updates, and Defender
    definitions to identify changes that correlate with new crashes or resolved issues.
.PARAMETER Days
    Number of days back to inspect (default: 14).
.PARAMETER IncludeDefinitions
    Include daily Windows Defender Security Intelligence / Definition updates (KB2267602).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Days = 14,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDefinitions
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
        $fetchLimit = [math]::Min([math]::Max(200, $Days * 8), $totalCount)
        $history = $searcher.QueryHistory(0, $fetchLimit)
        $recent = $history | Where-Object {
            $_.Date -ge $cutoff -and (
                $IncludeDefinitions -or
                ($_.Title -notmatch '(?i)KB2267602|Security Intelligence Update|Definition Update for Microsoft Defender|Windows Malicious Software Removal Tool')
            )
        } | Sort-Object Date -Descending
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
    ForEach-Object {
        $instDate = [datetime]::MinValue
        $hasValidDate = ($_.InstalledOn -and [datetime]::TryParse("$($_.InstalledOn)", [ref]$instDate))
        [PSCustomObject]@{
            HotFixID     = $_.HotFixID
            Description  = $_.Description
            InstalledOn  = $_.InstalledOn
            ParsedDate   = if ($hasValidDate) { $instDate } else { $null }
            HasValidDate = $hasValidDate
        }
    } |
    Where-Object {
        $_.HasValidDate -and $_.ParsedDate -ge $cutoff
    } |
    Sort-Object ParsedDate -Descending |
    Select-Object -First 25

if ($hotfixes) {
    $foundUpdates = $true
    Write-Host "Installed Windows Hotfixes (Win32_QuickFixEngineering):" -ForegroundColor Cyan
    foreach ($hf in $hotfixes) {
        Write-Host "  * [$($hf.ParsedDate.ToString('yyyy-MM-dd'))] $($hf.HotFixID): $($hf.Description)" -ForegroundColor White
    }
    Write-Host ""
}

if (-not $foundUpdates) {
    Write-Host "[ OK ] No new Windows quality updates or hotfixes recorded in the past $Days days." -ForegroundColor Green
}

Write-Host ""
