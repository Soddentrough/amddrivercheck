<#
.SYNOPSIS
    DriverCheck - One-Line Web Quick-Launch Bootstrapper
.DESCRIPTION
    Allows users to run DriverCheck instantly from PowerShell without manual download/extraction:
    irm https://raw.githubusercontent.com/Soddentrough/amddrivercheck/main/run.ps1 | iex
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 48
)

$ErrorActionPreference = "Stop"
$destDir = Join-Path $env:TEMP "DriverCheck_Live"
$zipUrl = "https://github.com/Soddentrough/amddrivercheck/releases/latest/download/drivercheck-v4.2.0.zip"
$zipFile = Join-Path $env:TEMP "drivercheck_temp.zip"

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  DRIVERCHECK CLOUD BOOTSTRAPPER" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Downloading DriverCheck to temporary workspace..." -ForegroundColor DarkGray

try {
    # If running from a local checkout, use local scripts directly
    if (Test-Path (Join-Path $PSScriptRoot "Analyze-LatestCrash.ps1")) {
        & (Join-Path $PSScriptRoot "Analyze-LatestCrash.ps1") -Hours $Hours -ExportHtml -OpenReport
        return
    }

    if (Test-Path $destDir) { Remove-Item $destDir -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $zipFile) { Remove-Item $zipFile -Force -ErrorAction SilentlyContinue }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing
    Expand-Archive -Path $zipFile -DestinationPath $destDir -Force

    $engine = Join-Path $destDir "Analyze-LatestCrash.ps1"
    if (Test-Path $engine) {
        & $engine -Hours $Hours -ExportHtml -OpenReport
    } else {
        Write-Host "[ERROR] Could not find engine script in extracted package." -ForegroundColor Red
    }
} catch {
    Write-Host "[ERROR] Cloud launch failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please download the portable zip directly from: https://github.com/Soddentrough/amddrivercheck/releases" -ForegroundColor Yellow
} finally {
    if (Test-Path $zipFile) { Remove-Item $zipFile -Force -ErrorAction SilentlyContinue }
}
