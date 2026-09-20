<#
.SYNOPSIS
    Game Engine Log Inspector
.DESCRIPTION
    Scans and analyzes crash logs across Unreal Engine, Unity, idTech, Source 2, and Godot.
.PARAMETER Hours
    Hours back to scan for engine logs (default: 48).
.PARAMETER TailLines
    Number of tail lines to inspect per log (default: 40).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 48,

    [Parameter(Mandatory = $false)]
    [int]$TailLines = 40
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcEngineLogs.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  GAME ENGINE CRASH LOG INSPECTOR" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

$cutoff = (Get-Date).AddHours(-$Hours)
Write-Host "Scanning game engine log directories (Past $Hours hours)..." -ForegroundColor DarkGray
Write-Host ""

$logs = Get-DcEngineLogs -Cutoff $cutoff

if ($logs.Count -gt 0) {
    foreach ($l in $logs) {
        Write-Host "------------------------------------------------------------------------" -ForegroundColor Gray
        Write-Host "Engine:    $($l.Engine)" -ForegroundColor Cyan
        Write-Host "Log File:  $($l.FullName)" -ForegroundColor Yellow
        Write-Host "Modified:  $($l.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
        Write-Host "Error Signatures Found:" -ForegroundColor Red
        foreach ($e in ($l.ErrorLines | Select-Object -Last 6)) {
            Write-Host "  * $e" -ForegroundColor Red
        }
    }
} else {
    Write-Host "[ OK ] No game engine crash logs or fatal error signatures found in monitored directories." -ForegroundColor Green
}

Write-Host ""
