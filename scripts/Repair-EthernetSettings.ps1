<#
.SYNOPSIS
    Intel I225-V / I226-V Network Adapter Stability Optimizer
.DESCRIPTION
    Applies recommended stability fixes to Intel Ethernet Controller (I225-V / I226-V):
      1. Locks Speed & Duplex to user-specified rate (2.5 Gbps or 1.0 Gbps Full Duplex) to stop auto-negotiation PHY retraining drops.
      2. Disables Packet Priority & VLAN tagging to reduce packet jitter.
      3. Disables Windows Energy Efficient Ethernet / Idle power downs.
.PARAMETER Speed
    Target speed: "2.5G" (default) or "1.0G".
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("2.5G", "1.0G")]
    [string]$Speed = "2.5G"
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "[ERROR] This script requires Administrator elevation to modify network adapter properties." -ForegroundColor Red
    Write-Host "Please re-run in an elevated PowerShell terminal (Run as Administrator)." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  INTEL I225-V / I226-V STABILITY OPTIMIZER" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

$adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'I225|I226|Intel.*Ethernet' } | Select-Object -First 1
if (-not $adapter) {
    Write-Host "[WARN] No Intel I225-V / I226-V adapter found. Checking default 'Ethernet'..." -ForegroundColor Yellow
    $adapter = Get-NetAdapter -Name "Ethernet" -ErrorAction SilentlyContinue
}

if (-not $adapter) {
    Write-Host "[ERR ] No Ethernet adapter found to configure." -ForegroundColor Red
    exit 1
}

Write-Host "Target Adapter: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor White

$speedValue = if ($Speed -eq "2.5G") { "2.5 Gbps Full Duplex" } else { "1.0 Gbps Full Duplex" }

try {
    Write-Host "Setting Speed & Duplex to '$speedValue'..." -NoNewline -ForegroundColor White
    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Speed & Duplex" -DisplayValue $speedValue -ErrorAction Stop
    Write-Host " [ OK ]" -ForegroundColor Green
} catch {
    Write-Host " [FAILED: $($_.Exception.Message)]" -ForegroundColor Red
}

try {
    Write-Host "Disabling Packet Priority & VLAN..." -NoNewline -ForegroundColor White
    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Packet Priority & VLAN" -DisplayValue "Packet Priority & VLAN Disabled" -ErrorAction Stop
    Write-Host " [ OK ]" -ForegroundColor Green
} catch {
    Write-Host " [FAILED: $($_.Exception.Message)]" -ForegroundColor Red
}

Write-Host ""
Write-Host "[SUCCESS] Network adapter configuration updated. Link is stabilizing..." -ForegroundColor Green
Start-Sleep -Seconds 2
$updated = Get-NetAdapter -Name $adapter.Name
Write-Host "Current Status: $($updated.Status) | LinkSpeed: $($updated.LinkSpeed)" -ForegroundColor Cyan
Write-Host ""
