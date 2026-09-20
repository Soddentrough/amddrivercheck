<#
.SYNOPSIS
    Steam IPC, CEF WebHelper, and Sleep/Resume Log Inspector
.DESCRIPTION
    Inspects Steam client, overlay, webhelper, and connection logs for cross-thread
    pipe stalls (pipes.cpp), ExitOnFatalAssert events, and sleep/wake crashes,
    suppressing benign normal hook detachment.
.PARAMETER Hours
    Hours back to scan (default: 48).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 48
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcEngineLogs.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  STEAM IPC, OVERLAY & SLEEP LOG INSPECTOR" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

$cutoff = (Get-Date).AddHours(-$Hours)
$steamLogs = Get-DcSteamLogs -Cutoff $cutoff

if ($steamLogs.Count -gt 0) {
    foreach ($sl in $steamLogs) {
        Write-Host "Log: $($sl.FullName)" -ForegroundColor Yellow
        Write-Host "Timestamp: $($sl.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
        foreach ($err in $sl.ErrorLines) {
            Write-Host "  * $err" -ForegroundColor Red
        }
        Write-Host ""
    }
} else {
    Write-Host "[ OK ] No Steam IPC pipe stalls, fatal assertions, or overlay crash signatures found in the past $Hours hours." -ForegroundColor Green
}

Write-Host ""
