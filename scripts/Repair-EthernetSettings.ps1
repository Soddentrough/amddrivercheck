<#
.SYNOPSIS
    Network Adapter & Ephemeral Port Stability Optimizer
.DESCRIPTION
    Applies recommended stability fixes to Ethernet adapters (Intel I225/I226 and Realtek)
    and expands Windows UDP ephemeral dynamic port ranges:
      1. Locks Speed & Duplex to user-specified rate (2.5 Gbps, 1.0 Gbps Full Duplex, or Auto) to prevent PHY retraining drops.
      2. Disables Packet Priority & VLAN tagging to minimize jitter.
      3. Expands Windows UDP ephemeral dynamic port space (start 1024, count 64511) to eliminate socket exhaustion (Event 4266).
.PARAMETER Speed
    Target speed: "Current" (default - preserves existing rate), "2.5G", "1.0G", or "Auto".
.PARAMETER ExpandUdpPorts
    Expand Windows dynamic UDP ephemeral port range to match TCP (1024-65535, 64,511 ports), preventing Event 4266 port exhaustion under heavy Steam/game matchmaking socket traffic.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Current", "2.5G", "1.0G", "Auto")]
    [string]$Speed = "Current",

    [Parameter(Mandatory = $false)]
    [switch]$ExpandUdpPorts
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  NETWORK ADAPTER & SOCKET STABILITY OPTIMIZER" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

if ($PSBoundParameters.ContainsKey('ExpandUdpPorts') -and -not $PSBoundParameters.ContainsKey('Speed')) {
    Repair-DcUdpPortRange
} else {
    Repair-DcEthernetSettings -Speed $Speed -ExpandUdpPorts:$ExpandUdpPorts
}
Write-Host ""
