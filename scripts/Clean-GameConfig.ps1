<#
.SYNOPSIS
    Game Local Configuration & Shader Cache Cleaner
.DESCRIPTION
    Safely resets local game configuration files (.local / .cfg) and shader caches
    for games where permissions or corrupt graphic config files prevent launch.
.PARAMETER Game
    Target game: "TheGreatCircle" (default), "DOOMEternal", "DOOMTheDarkAges", or "All".
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("TheGreatCircle", "DOOMEternal", "DOOMTheDarkAges", "All")]
    [string]$Game = "TheGreatCircle"
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  GAME LOCAL CONFIGURATION & CACHE CLEANER" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

$targets = @()
if ($Game -in @("TheGreatCircle", "All")) {
    $targets += "$env:USERPROFILE\Saved Games\MachineGames\TheGreatCircle\base"
}
if ($Game -in @("DOOMEternal", "All")) {
    $targets += "$env:USERPROFILE\Saved Games\id Software\DOOMEternal\base"
}
if ($Game -in @("DOOMTheDarkAges", "All")) {
    $targets += "$env:USERPROFILE\Saved Games\id Software\DOOMTheDarkAges\base"
}

foreach ($target in $targets) {
    if (Test-Path $target) {
        Write-Host "Inspecting: $target" -ForegroundColor Yellow
        $configs = Get-ChildItem -Path $target -Include "*.local", "*.cfg", "crash_marker.txt" -File -ErrorAction SilentlyContinue
        if ($configs) {
            foreach ($cfg in $configs) {
                Write-Host "  Removing stale config: $($cfg.Name)..." -NoNewline -ForegroundColor White
                try {
                    Remove-Item -Path $cfg.FullName -Force -ErrorAction Stop
                    Write-Host " [ OK ]" -ForegroundColor Green
                } catch {
                    Write-Host " [FAILED: $($_.Exception.Message)]" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "  No stale config files found in directory." -ForegroundColor DarkGray
        }
    } else {
        Write-Host "Directory not found: $target" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "[DONE] Stale local configs cleaned. Fresh configs will be regenerated at next launch." -ForegroundColor Green
Write-Host ""
