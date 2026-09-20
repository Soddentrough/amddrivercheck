<#
.SYNOPSIS
    GPU Watchdog Timeout and Sleep Recovery Optimizer (Zero Power Impact by Default)
.DESCRIPTION
    Applies proven stability fixes for GPU display driver timeouts (TDR 0x141 / AMD Watchdog)
    that occur when resuming from sleep or during high-resolution display link negotiation.

    DEFAULT ACTION (Zero Power Impact):
      - Increases TdrDelay and TdrDdiDelay to 8 seconds in HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers.
        This gives 4K/high-refresh HDMI 2.1 FRL / DP DSC displays sufficient time to train
        links and handshake upon wake without tripping the Windows watchdog.
      - Preserves all GPU sleep states, C-states, and energy savings.

    LAST RESORT / TEMPORARY WORKAROUND ONLY (-DisableUlps):
      - Disables Ultra-Low Power State (ULPS) in the registry.
      - WARNING: Disabling ULPS prevents the GPU from entering deep power-saving sleep.
        Only use this as a temporary diagnostic step if TdrDelay optimization does not resolve
        wake hangs. Re-enable after testing.
.PARAMETER TdrDelaySeconds
    Seconds to wait before Windows Graphics Watchdog initiates a TDR recovery (default: 8).
    Zero power impact.
.PARAMETER DisableUlps
    [TEMPORARY WORKAROUND / LAST RESORT ONLY]
    Disables Ultra-Low Power State (ULPS). Increases idle power consumption.
.PARAMETER DisableFastStartup
    [OPTIONAL]
    Disables Windows Fast Startup (HiberbootEnabled = 0).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [int]$TdrDelaySeconds = 8,

    [Parameter(Mandatory = $false)]
    [switch]$DisableUlps,

    [Parameter(Mandatory = $false)]
    [switch]$DisableFastStartup
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$modulesDir = Join-Path $PSScriptRoot "modules"
Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host "  GPU WATCHDOG TIMEOUT & DISPLAY WAKE OPTIMIZER" -ForegroundColor Magenta
Write-Host "========================================================================" -ForegroundColor Magenta
Write-Host ""

Repair-DcGpuSleepSettings -TdrDelaySeconds $TdrDelaySeconds -DisableUlps:$DisableUlps -DisableFastStartup:$DisableFastStartup
Write-Host ""
