<#
.SYNOPSIS
    Build Release Package for drivercheck
.DESCRIPTION
    Packages all runtime files, modules, helper scripts, launchers, and documentation
    into a clean, distributable portable ZIP file with SHA256 checksums.
.PARAMETER Version
    Release version tag (default: "4.0.0").
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Version = "4.0.0"
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$rootDir = $PSScriptRoot
$distDir = Join-Path $rootDir "dist"
$stageName = "drivercheck-v$Version"
$stageDir = Join-Path $distDir $stageName
$zipFile = Join-Path $distDir "$stageName.zip"

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  BUILDING DRIVERCHECK RELEASE PACKAGE (v$Version)" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# Clean previous build artifacts
if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force }
if (Test-Path $zipFile) { Remove-Item $zipFile -Force }
New-Item -Path $stageDir -ItemType Directory -Force | Out-Null

Write-Host "Staging files..." -ForegroundColor Yellow

# Copy Root Files
$rootFiles = @(
    "Analyze-LatestCrash.ps1",
    "Get-GPUDriverDiagnostics.ps1",
    "Run-Diagnostics.bat",
    "README.md",
    "QUICKSTART.txt",
    "run.ps1"
)

foreach ($rf in $rootFiles) {
    $src = Join-Path $rootDir $rf
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $stageDir $rf) -Force
        Write-Host "  + Staged: $rf" -ForegroundColor DarkGray
    } else {
        Write-Host "  [!] Missing expected file: $rf" -ForegroundColor Red
    }
}

# Copy Scripts & Modules Directory
$destScripts = Join-Path $stageDir "scripts"
Copy-Item -Path (Join-Path $rootDir "scripts") -Destination $destScripts -Recurse -Force
Write-Host "  + Staged: scripts/ directory and modules" -ForegroundColor DarkGray

# Create Distributable ZIP
Write-Host "`nCompressing release archive..." -ForegroundColor Yellow
if (Test-Path $zipFile) { Remove-Item $zipFile -Force }
Compress-Archive -Path "$stageDir\*" -DestinationPath $zipFile -Force

# Clean Staging Directory
Remove-Item $stageDir -Recurse -Force

# Calculate SHA256 Checksum
$hash = (Get-FileHash -Path $zipFile -Algorithm SHA256).Hash
$sizeMb = [math]::Round((Get-Item $zipFile).Length / 1KB, 2)

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "  BUILD COMPLETE!" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "  Package: $zipFile" -ForegroundColor White
Write-Host "  Size:    $sizeMb KB" -ForegroundColor White
Write-Host "  SHA256:  $hash" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Green
Write-Host ""
