<#
.SYNOPSIS
    DriverCheck - One-Line Web Quick-Launch Bootstrapper
.DESCRIPTION
    Allows users to run DriverCheck instantly from PowerShell without manual download/extraction.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$AllIncidents,

    [Parameter(Mandatory = $false)]
    [int]$Hours = 0,

    [Parameter(Mandatory = $false)]
    [string]$DownloadUrl = ""
)

$ErrorActionPreference = "Stop"
$destDir = Join-Path $env:TEMP "DriverCheck_Live"

# Determine download URL from parameter, environment, or default repository
$zipUrl = if ($DownloadUrl) {
    $DownloadUrl
} elseif ($env:DRIVERCHECK_ZIP_URL) {
    $env:DRIVERCHECK_ZIP_URL
} else {
    $repo = if ($env:DRIVERCHECK_REPO) { $env:DRIVERCHECK_REPO } else { "Soddentrough/amddrivercheck" }
    "https://github.com/$repo/releases/latest/download/drivercheck-v4.5.0.zip"
}
$zipFile = Join-Path $env:TEMP "drivercheck_temp.zip"

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  DRIVERCHECK CLOUD BOOTSTRAPPER (v4.5.0)" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Downloading DriverCheck to temporary workspace..." -ForegroundColor DarkGray

$scanParams = @{ ExportHtml = $true; OpenReport = $true }
if ($AllIncidents) { $scanParams['AllIncidents'] = $true }
if ($Hours -gt 0) { $scanParams['Hours'] = $Hours }

try {
    # If running from a local checkout, use local scripts directly
    if (Test-Path (Join-Path $PSScriptRoot "Analyze-LatestCrash.ps1")) {
        & (Join-Path $PSScriptRoot "Analyze-LatestCrash.ps1") @scanParams
        return
    }

    if (Test-Path $destDir) { Remove-Item $destDir -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $zipFile) { Remove-Item $zipFile -Force -ErrorAction SilentlyContinue }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing
    Expand-Archive -Path $zipFile -DestinationPath $destDir -Force

    $engine = Join-Path $destDir "Analyze-LatestCrash.ps1"
    if (Test-Path $engine) {
        & $engine @scanParams
    } else {
        Write-Host "[ERROR] Could not find engine script in extracted package." -ForegroundColor Red
    }
} catch {
    Write-Host "[ERROR] Cloud launch failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please download the portable zip directly from your distribution source." -ForegroundColor Yellow
} finally {
    if (Test-Path $zipFile) { Remove-Item $zipFile -Force -ErrorAction SilentlyContinue }
}
