<#
.SYNOPSIS
    Standalone Crash Dump & Binary Minidump Inspector
.DESCRIPTION
    Directly scans and analyzes binary minidump streams (MDMP) across Windows BSODs,
    User-Mode WER dumps, Steam, Unreal Engine, and Unity.
.PARAMETER Hours
    Hours back to scan for crash dumps (default: 48).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 48
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Import Minidump Engine
$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcCrashDump.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  CRASH DUMP & BINARY MINIDUMP INSPECTOR" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

$cutoff = (Get-Date).AddHours(-$Hours)
Write-Host "Scanning monitored dump directories for crash artifacts (Past $Hours hours)..." -ForegroundColor DarkGray
Write-Host ""

$dumps = Get-DcCrashDumps -Cutoff $cutoff

if ($dumps.Count -gt 0) {
    Write-Host "Found $($dumps.Count) crash dump file(s):" -ForegroundColor Cyan
    Write-Host ""
    foreach ($df in $dumps) {
        $parsed = Read-DcMinidump -Path $df.FullName
        if ($parsed) {
            Write-Host "------------------------------------------------------------------------" -ForegroundColor Gray
            Write-Host "Dump File:        $($parsed.FileName)" -ForegroundColor Yellow
            Write-Host "Location:         $($parsed.FullName)" -ForegroundColor White
            Write-Host "Timestamp:        $($parsed.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')) | $($parsed.SizeMb) MB | $($parsed.Architecture)" -ForegroundColor DarkGray
            if ($parsed.ExceptionCode) {
                Write-Host "Exception Code:   $($parsed.ExceptionCode) ($($parsed.ExceptionMeaning))" -ForegroundColor Red
                Write-Host "Faulting Address: $($parsed.FaultingIP)" -ForegroundColor White
            }
            if ($parsed.Assertions.Count -gt 0) {
                Write-Host "Assertions Found:" -ForegroundColor Red
                foreach ($a in $parsed.Assertions) {
                    Write-Host "  * $a" -ForegroundColor Red
                }
            }
        }
    }
} else {
    Write-Host "[ OK ] No crash dump files found in monitored directories." -ForegroundColor Green
}

Write-Host ""
