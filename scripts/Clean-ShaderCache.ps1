<#
.SYNOPSIS
    DirectX & GPU Shader Cache Cleaner
.DESCRIPTION
    Safely purges DirectX (D3DSCache), AMD (DxCache/GLCache/OclCache), and NVIDIA shader caches.
    Forces games to recompile shaders cleanly from scratch, resolving shader compilation hangs,
    corrupted shader caches, and shader compile crash loops.
.PARAMETER Target
    Target vendor cache: "DirectX", "AMD", "NVIDIA", or "All" (default).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("DirectX", "AMD", "NVIDIA", "All")]
    [string]$Target = "All"
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  DIRECTX & GPU SHADER CACHE PURGE TOOL" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

Clear-DcShaderCache -Target $Target
Write-Host ""
