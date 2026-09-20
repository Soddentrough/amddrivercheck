<#
.SYNOPSIS
    Game Configuration & Cache Cleaner (with Automatic Backups)
.DESCRIPTION
    Safely purges stale game configurations and shader caches while creating .bak
    backups to prevent losing user keybindings and sensitivities.
.PARAMETER Game
    Target game: "TheGreatCircle", "DOOMEternal", "DOOMTheDarkAges", "CrimsonDesert", or "All" (default).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("TheGreatCircle", "DOOMEternal", "DOOMTheDarkAges", "CrimsonDesert", "All")]
    [string]$Game = "All"
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  GAME CONFIGURATION & CACHE CLEANER" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

Clear-DcGameConfig -Game $Game -Backup
Write-Host ""
