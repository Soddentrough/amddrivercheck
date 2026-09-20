<#
.SYNOPSIS
    Steam CEF Browser HTML Cache Cleaner
.DESCRIPTION
    Safely purges the Steam client embedded browser HTML cache (%LOCALAPPDATA%\Steam\htmlcache).
.PARAMETER Force
    Terminate active Steam processes if running to unlock the cache folder.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  STEAM CEF HTML BROWSER CACHE CLEANER" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

Clear-DcSteamCache -KillRunningSteam:$Force
Write-Host ""
