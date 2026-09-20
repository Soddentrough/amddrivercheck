<#
.SYNOPSIS
    Network Adapter Stability Optimizer
.DESCRIPTION
    Applies recommended stability fixes to Ethernet adapters (Intel I225/I226 and Realtek):
      1. Locks Speed & Duplex to user-specified rate (2.5 Gbps, 1.0 Gbps Full Duplex, or Auto) to prevent PHY retraining drops.
      2. Disables Packet Priority & VLAN tagging to minimize jitter.
.PARAMETER Speed
    Target speed: "2.5G" (default), "1.0G", or "Auto".
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("2.5G", "1.0G", "Auto")]
    [string]$Speed = "2.5G"
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  NETWORK ADAPTER STABILITY OPTIMIZER" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

Repair-DcEthernetSettings -Speed $Speed
Write-Host ""
