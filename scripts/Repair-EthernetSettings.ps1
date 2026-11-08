<#
.SYNOPSIS
    Network Adapter & Ephemeral Port Stability Optimizer
.DESCRIPTION
    Applies recommended stability fixes to Ethernet adapters (Intel I225/I226 and Realtek)
    and expands Windows UDP ephemeral dynamic port ranges:
      1. Disables NetAdapterCx 5-second idle power-down (*IdleRestriction=1), ULPMode, ReduceSpeedOnPowerDown, ModernStandbyWoL, and EEE.
      2. Restores IEEE 802.3bz Auto-Negotiation (*SpeedDuplex=0) if forced to 2.5 Gbps, or sets user-specified rate, and sets Flow Control to Auto.
      3. Disables Packet Priority & VLAN tagging to minimize jitter.
      4. Expands Windows UDP ephemeral dynamic port space (start 1024, count 64511) to eliminate socket exhaustion (Event 4266).
.PARAMETER Speed
    Target speed: "Current" (default - preserves existing rate or restores Auto from forced 2.5G), "Auto", "1.0G", or "2.5G".
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
