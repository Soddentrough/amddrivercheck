<#
.SYNOPSIS
    Automated Game & System Crash Diagnostic Suite (Unified Engine)
.DESCRIPTION
    A hierarchical, evidence-based diagnostic tool following strict analysis precedence:
      1. Tier 1 (Primary Ground Truth): Crash Dumps & Exceptions (BSOD, WER, Steam, Unreal, Unity).
      2. Tier 2 (Secondary Evidence):   Application & Game Logs (Engine logs, Steam overlay/IPC, asserts).
      3. Tier 3 (Tertiary Telemetry):  System Event Logs (WHEA errors, GPU TDR resets, BugChecks, Fast Startup).
      4. Tier 4 (Contextual Audit):     Hardware Health & Configuration (PnP errors, GPU drivers, Dual-GPU alignment, Network).
.PARAMETER AllIncidents
    Scan full incident history (past 30 days or specified Hours) instead of focusing on the latest crash.
.PARAMETER MaxLookbackDays
    Maximum days to search backward for the latest crash incident (default: 30).
.PARAMETER Hours
    Custom hours back to scan for crash telemetry (overrides default incident-anchored window if specified).
.PARAMETER DeepScan
    Legacy alias for -AllIncidents.
.PARAMETER ExportHtml
    Generate a self-contained, responsive dark-mode HTML diagnostic report.
.PARAMETER ExportJson
    Export structured telemetry data as JSON.
.PARAMETER ExportZip
    Create a complete diagnostic support bundle (HTML report + logs) for sharing.
.PARAMETER OpenReport
    Automatically open the generated HTML report in the default web browser.
.PARAMETER AuditPower
    Run dedicated deep audit of Windows Power, Fast Startup, and sleep/wake transitions.
.PARAMETER AuditDevices
    Run dedicated deep audit of Plug and Play (PnP) hardware health and missing drivers.
.PARAMETER AuditBluetooth
    Run dedicated deep audit of Bluetooth controllers, audio devices, and radio health.
.PARAMETER AuditDisplays
    Run dedicated deep audit of Connected Displays, EDID Detailed Timings, and DisplayPort 1.2a Scaler Saturation risks.
.PARAMETER AuditKernelDrivers
    Run dedicated audit for rogue/legacy third-party kernel I/O drivers (inpoutx64.sys, WinRing0, ENE).
.PARAMETER AuditMotherboard
    Run dedicated audit of Motherboard, BIOS version/date, and platform chipset driver software.
.PARAMETER DisablePciePowerSavings
    Disable PCI Express Link State Power Management (ASPM) in the active Windows Power Scheme.
.PARAMETER DisableRogueDrivers
    (Admin) Disable autostart services for detected rogue kernel I/O drivers (inpoutx64.sys, WinRing0, ENE).
.PARAMETER FixDrivers
    Inspect Windows Driver Store for GPU driver downgrades and lock Windows Update driver policies.
.PARAMETER RepairNetwork
    (Admin) Apply stability settings to Ethernet adapters (Speed/Duplex lock, VLAN disable).
.PARAMETER Speed
    Target speed when using -RepairNetwork: "2.5G" (default), "1.0G", or "Auto".
.PARAMETER ExpandUdpPorts
    (Admin) Expand Windows dynamic UDP ephemeral port range to match TCP (1024-65535, 64,511 ports), preventing Event 4266 socket exhaustion during Steam/game matchmaking.
.PARAMETER CleanConfig
    Clean stale game configuration files and shader caches (with automatic .bak backup).
.PARAMETER Game
    Target game when using -CleanConfig: "TheGreatCircle", "DOOMEternal", "DOOMTheDarkAges", "All" (default).
.PARAMETER CleanSteamCache
    Purge Steam CEF HTML browser cache (%LOCALAPPDATA%\Steam\htmlcache).
.PARAMETER KillHungSteam
    Terminate lingering headless or zombie Steam processes blocking relaunch.
.PARAMETER InvestigateResolved
    Investigate historical timeouts/crashes (up to 365 days back by default) that have since resolved themselves, clustering historical incident episodes and correlating system changes (driver updates, BIOS, registry/power mitigations) that stopped them.
.PARAMETER Quiet
    Suppress interactive banner output and return only the structured report object.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [Alias("History", "DeepScan")]
    [switch]$AllIncidents,

    [Parameter(Mandatory = $false)]
    [Alias("Resolved", "WhyResolved")]
    [switch]$InvestigateResolved,

    [Parameter(Mandatory = $false)]
    [int]$MaxLookbackDays = 30,

    [Parameter(Mandatory = $false)]
    [int]$Hours = 0,

    [Parameter(Mandatory = $false)]
    [switch]$ExportHtml,

    [Parameter(Mandatory = $false)]
    [switch]$ExportJson,

    [Parameter(Mandatory = $false)]
    [switch]$ExportZip,

    [Parameter(Mandatory = $false)]
    [switch]$OpenReport,

    [Parameter(Mandatory = $false)]
    [switch]$AuditPower,

    [Parameter(Mandatory = $false)]
    [switch]$AuditDevices,

    [Parameter(Mandatory = $false)]
    [switch]$AuditBluetooth,

    [Parameter(Mandatory = $false)]
    [switch]$AuditDisplays,

    [Parameter(Mandatory = $false)]
    [switch]$AuditKernelDrivers,

    [Parameter(Mandatory = $false)]
    [switch]$AuditMotherboard,

    [Parameter(Mandatory = $false)]
    [switch]$DisablePciePowerSavings,

    [Parameter(Mandatory = $false)]
    [switch]$DisableRogueDrivers,

    [Parameter(Mandatory = $false)]
    [switch]$FixDrivers,

    [Parameter(Mandatory = $false)]
    [switch]$RepairGpuSleep,

    [Parameter(Mandatory = $false)]
    [switch]$DisableUlps,

    [Parameter(Mandatory = $false)]
    [switch]$RepairNetwork,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Current", "2.5G", "1.0G", "Auto")]
    [string]$Speed = "Current",

    [Parameter(Mandatory = $false)]
    [switch]$ExpandUdpPorts,

    [Parameter(Mandatory = $false)]
    [switch]$CleanConfig,

    [Parameter(Mandatory = $false)]
    [ValidateSet("TheGreatCircle", "DOOMEternal", "DOOMTheDarkAges", "CrimsonDesert", "All")]
    [string]$Game = "All",

    [Parameter(Mandatory = $false)]
    [switch]$CleanShaderCache,

    [Parameter(Mandatory = $false)]
    [ValidateSet("DirectX", "AMD", "NVIDIA", "All")]
    [string]$ShaderTarget = "All",

    [Parameter(Mandatory = $false)]
    [switch]$CleanSteamCache,

    [Parameter(Mandatory = $false)]
    [switch]$KillHungSteam,

    [Parameter(Mandatory = $false)]
    [switch]$Quiet,

    [Parameter(Mandatory = $false)]
    [switch]$NoInteractive,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Import Unified Modular Engine
$modulesDir = Join-Path $PSScriptRoot "scripts\modules"
$rootModule = Join-Path $modulesDir "DriverCheck.psm1"
if (Test-Path $rootModule) {
    Import-Module $rootModule -Force
} else {
    Import-Module (Join-Path $modulesDir "DcCrashDump.psm1") -Force
    Import-Module (Join-Path $modulesDir "DcEngineLogs.psm1") -Force
    Import-Module (Join-Path $modulesDir "DcSystemTelemetry.psm1") -Force
    Import-Module (Join-Path $modulesDir "DcHardwareHealth.psm1") -Force
    Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force
    Import-Module (Join-Path $modulesDir "DcReportGenerator.psm1") -Force
}

$isCustomHours = ($PSBoundParameters.ContainsKey('Hours') -and $Hours -gt 0)

# Execute Dedicated Remediation or Audit Switches Immediately (Fast-Path before Event Log Scans)
$ranDedicatedSwitch = $false
if ($KillHungSteam -and -not $CleanSteamCache) {
    Write-Host "`n=== HUNG / ZOMBIE PROCESS TERMINATOR ===" -ForegroundColor Magenta
    Stop-DcZombieProcesses
    Write-Host "`n[DONE] Process termination routine complete." -ForegroundColor Green
    $ranDedicatedSwitch = $true
}
if ($CleanSteamCache) {
    Write-Host "`n=== STEAM CEF HTML BROWSER CACHE CLEANER ===" -ForegroundColor Magenta
    Clear-DcSteamCache -KillRunningSteam:$KillHungSteam
    $ranDedicatedSwitch = $true
}
if ($CleanShaderCache) {
    Write-Host "`n=== DIRECTX & GPU SHADER CACHE PURGE ===" -ForegroundColor Magenta
    Clear-DcShaderCache -Target $ShaderTarget
    Write-Host "`n[DONE] Shader cache cleaning complete." -ForegroundColor Green
    $ranDedicatedSwitch = $true
}
if ($CleanConfig) {
    Write-Host "`n=== GAME CONFIGURATION & CACHE CLEANER (WITH BACKUPS) ===" -ForegroundColor Magenta
    Clear-DcGameConfig -Game $Game -Backup
    Write-Host "`n[DONE] Game configuration cleaning complete." -ForegroundColor Green
    $ranDedicatedSwitch = $true
}
if ($DisablePciePowerSavings) {
    & (Join-Path $PSScriptRoot "scripts\Repair-PciePowerSettings.ps1")
    $ranDedicatedSwitch = $true
}
if ($RepairNetwork) {
    Write-Host "`n=== NETWORK ADAPTER STABILITY OPTIMIZER ===" -ForegroundColor Magenta
    Repair-DcEthernetSettings -Speed $Speed -ExpandUdpPorts:$ExpandUdpPorts
    $ranDedicatedSwitch = $true
}
if ($ExpandUdpPorts -and -not $RepairNetwork) {
    Write-Host "`n=== WINDOWS UDP EPHEMERAL PORT SPACE OPTIMIZER ===" -ForegroundColor Magenta
    Repair-DcUdpPortRange
    $ranDedicatedSwitch = $true
}
if ($RepairGpuSleep) {
    & (Join-Path $PSScriptRoot "scripts\Repair-GpuSleepSettings.ps1") -DisableUlps:$DisableUlps
    $ranDedicatedSwitch = $true
}
if ($FixDrivers) {
    Write-Host "`n=== GPU DRIVER STORE ALIGNMENT & DOWNGRADE PROTECTION ===" -ForegroundColor Magenta
    Repair-DcAmdDriverAlignment -BlockWindowsUpdateDrivers
    $ranDedicatedSwitch = $true
}
if ($DisableRogueDrivers) {
    & (Join-Path $PSScriptRoot "scripts\Disable-RogueKernelDrivers.ps1")
    $ranDedicatedSwitch = $true
}
if ($ranDedicatedSwitch) {
    exit 0
}
if ($AuditPower) {
    $pwrHours = if ($isCustomHours) { $Hours } else { 48 }
    & (Join-Path $PSScriptRoot "scripts\Get-PowerAndSleepDiagnostics.ps1") -Hours $pwrHours
    exit 0
}
if ($AuditDevices) {
    & (Join-Path $PSScriptRoot "scripts\Get-PnpDeviceDiagnostics.ps1")
    exit 0
}
if ($AuditBluetooth) {
    & (Join-Path $PSScriptRoot "scripts\Get-BluetoothDiagnostics.ps1")
    exit 0
}
if ($AuditDisplays) {
    & (Join-Path $PSScriptRoot "scripts\Get-DisplayDiagnostics.ps1")
    exit 0
}
if ($AuditKernelDrivers) {
    & (Join-Path $PSScriptRoot "scripts\Disable-RogueKernelDrivers.ps1")
    exit 0
}
if ($AuditMotherboard) {
    & (Join-Path $PSScriptRoot "scripts\Get-MotherboardAndChipsetDiagnostics.ps1")
    exit 0
}

# Determine Scan Mode & Temporal Windows
$isCustomHours = ($PSBoundParameters.ContainsKey('Hours') -and $Hours -gt 0)
if ($InvestigateResolved -and -not $PSBoundParameters.ContainsKey('MaxLookbackDays')) {
    $MaxLookbackDays = 365
}

if ($InvestigateResolved) {
    $scanMode = "InvestigateResolved"
    $incidentAnchor = Find-DcLatestIncident -MaxLookbackDays $MaxLookbackDays
    if ($incidentAnchor.HasIncident) {
        $cutoff = $incidentAnchor.IncidentStart
        $endTime = $incidentAnchor.IncidentEnd
    } else {
        $cutoff = (Get-Date).AddDays(-$MaxLookbackDays)
        $endTime = Get-Date
    }
} elseif ($AllIncidents) {
    $scanMode = "AllIncidents"
    $scanHours = if ($isCustomHours) { $Hours } else { $MaxLookbackDays * 24 }
    $cutoff = (Get-Date).AddHours(-$scanHours)
    $endTime = Get-Date
    $incidentAnchor = $null
} elseif ($isCustomHours) {
    $scanMode = "CustomHours"
    $cutoff = (Get-Date).AddHours(-$Hours)
    $endTime = Get-Date
    $incidentAnchor = $null
} else {
    # Default: Scan backward in time looking for the latest incident
    $incidentAnchor = Find-DcLatestIncident -MaxLookbackDays $MaxLookbackDays
    if ($incidentAnchor.HasIncident) {
        $scanMode = "LatestIncident"
        $cutoff = $incidentAnchor.IncidentStart
        $endTime = $incidentAnchor.IncidentEnd
    } else {
        $scanMode = "LatestIncidentClean"
        $cutoff = $incidentAnchor.IncidentStart
        $endTime = $incidentAnchor.IncidentEnd
    }
}

# =========================================================================
# DEDICATED ACTION / REMEDIATION SWITCHES
# =========================================================================

if ($ExpandUdpPorts -and -not $RepairNetwork) {
    Write-Host "`n=== WINDOWS UDP EPHEMERAL PORT SPACE OPTIMIZER ===" -ForegroundColor Magenta
    Repair-DcUdpPortRange
    exit 0
}

if ($RepairNetwork) {
    Write-Host "`n=== NETWORK ADAPTER STABILITY OPTIMIZER ===" -ForegroundColor Magenta
    Repair-DcEthernetSettings -Speed $Speed -ExpandUdpPorts:$ExpandUdpPorts
    exit 0
}

if ($CleanConfig) {
    Write-Host "`n=== GAME CONFIGURATION & CACHE CLEANER (WITH BACKUPS) ===" -ForegroundColor Magenta
    Clear-DcGameConfig -Game $Game -Backup
    Write-Host "`n[DONE] Game configuration cleaning complete." -ForegroundColor Green
    exit 0
}

if ($CleanShaderCache) {
    Write-Host "`n=== DIRECTX & GPU SHADER CACHE PURGE ===" -ForegroundColor Magenta
    Clear-DcShaderCache -Target $ShaderTarget
    Write-Host "`n[DONE] Shader cache cleaning complete." -ForegroundColor Green
    exit 0
}

if ($CleanSteamCache) {
    Write-Host "`n=== STEAM CEF HTML BROWSER CACHE CLEANER ===" -ForegroundColor Magenta
    Clear-DcSteamCache -KillRunningSteam:$KillHungSteam
    exit 0
}

if ($KillHungSteam) {
    Write-Host "`n=== HUNG / ZOMBIE PROCESS TERMINATOR ===" -ForegroundColor Magenta
    Stop-DcZombieProcesses
    Write-Host "`n[DONE] Process termination routine complete." -ForegroundColor Green
    exit 0
}

if ($FixDrivers) {
    Write-Host "`n=== GPU DRIVER STORE ALIGNMENT & DOWNGRADE PROTECTION ===" -ForegroundColor Magenta
    Repair-DcAmdDriverAlignment -BlockWindowsUpdateDrivers
    exit 0
}

if ($DisablePciePowerSavings) {
    & (Join-Path $PSScriptRoot "scripts\Repair-PciePowerSettings.ps1")
    exit 0
}

if ($DisableRogueDrivers) {
    & (Join-Path $PSScriptRoot "scripts\Disable-RogueKernelDrivers.ps1")
    exit 0
}

if ($RepairGpuSleep) {
    & (Join-Path $PSScriptRoot "scripts\Repair-GpuSleepSettings.ps1") -DisableUlps:$DisableUlps
    exit 0
}

# =========================================================================
# SPECIALIZED AUDIT MODES
# =========================================================================

if ($AuditPower) {
    $pwrHours = if ($isCustomHours) { $Hours } else { 48 }
    & (Join-Path $PSScriptRoot "scripts\Get-PowerAndSleepDiagnostics.ps1") -Hours $pwrHours
    exit 0
}

if ($AuditDevices) {
    & (Join-Path $PSScriptRoot "scripts\Get-PnpDeviceDiagnostics.ps1")
    exit 0
}

if ($AuditBluetooth) {
    & (Join-Path $PSScriptRoot "scripts\Get-BluetoothDiagnostics.ps1")
    exit 0
}

if ($AuditDisplays) {
    & (Join-Path $PSScriptRoot "scripts\Get-DisplayDiagnostics.ps1")
    exit 0
}

if ($AuditKernelDrivers) {
    & (Join-Path $PSScriptRoot "scripts\Disable-RogueKernelDrivers.ps1")
    exit 0
}

if ($AuditMotherboard) {
    & (Join-Path $PSScriptRoot "scripts\Get-MotherboardAndChipsetDiagnostics.ps1")
    exit 0
}

# =========================================================================
# MAIN UNIFIED 4-TIER DIAGNOSTIC FLOW
# =========================================================================

if (-not $Quiet) {
    Write-Host ""
    Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |            DriverCheck - Game & PC Crash Troubleshooter              |" -ForegroundColor Cyan
    Write-Host "  |                  Crash Check & Report (v4.5.0)                       |" -ForegroundColor Cyan
    Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor Cyan
    if ($scanMode -eq "InvestigateResolved") {
        Write-Host "  Scan Mode:    Historical Resolution Analysis (Past $MaxLookbackDays Days)" -ForegroundColor Cyan
        if ($incidentAnchor -and $incidentAnchor.HasIncident) {
            Write-Host "  Latest Event: $($incidentAnchor.Source) ($($incidentAnchor.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')) - $($incidentAnchor.AgeDescription))" -ForegroundColor Yellow
        } else {
            Write-Host "  Status:       Searching historical archives, DriverStore, and setup logs ($MaxLookbackDays days)..." -ForegroundColor White
        }
    } elseif ($scanMode -eq "LatestIncident") {
        Write-Host "  Scan Mode:    Latest Incident (Anchored: $($incidentAnchor.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')) - $($incidentAnchor.AgeDescription))" -ForegroundColor Yellow
        Write-Host "  Incident:     $($incidentAnchor.Source) - $($incidentAnchor.Details)" -ForegroundColor White
        Write-Host "  Scan Window:  $($cutoff.ToString('yyyy-MM-dd HH:mm')) to $($endTime.ToString('yyyy-MM-dd HH:mm')) (Pre-crash telemetry correlated)" -ForegroundColor DarkGray
    } elseif ($scanMode -eq "LatestIncidentClean") {
        Write-Host "  Scan Mode:    Latest Incident (Scanned backward $MaxLookbackDays days - Clean)" -ForegroundColor Green
        Write-Host "  Status:       No crash dumps, driver timeouts, or BSODs detected in the past $MaxLookbackDays days." -ForegroundColor White
    } elseif ($scanMode -eq "AllIncidents") {
        Write-Host "  Scan Mode:    Full Incident History (Past $MaxLookbackDays Days)" -ForegroundColor Yellow
        Write-Host "  Scan Window:  $($cutoff.ToString('yyyy-MM-dd HH:mm')) to $($endTime.ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor DarkGray
    } else {
        Write-Host "  Scan Window:  $($cutoff.ToString('yyyy-MM-dd HH:mm')) to $($endTime.ToString('yyyy-MM-dd HH:mm')) ($Hours hours)" -ForegroundColor DarkGray
    }
    Write-Host "  Precedence:   [1] Crash Dumps -> [2] App Logs -> [3] System Logs -> [4] System Config" -ForegroundColor DarkGray
    Write-Host ""
}

# -------------------------------------------------------------------------
# TIER 1: CRASH DUMPS & BINARY THREAD INSPECTION
# -------------------------------------------------------------------------
if (-not $Quiet) {
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host "  [1/4] CHECKING CRASH DUMPS" -ForegroundColor Magenta
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host ""
}

$dumpFiles = Get-DcCrashDumps -Cutoff $cutoff -EndTime $endTime
$parsedDumps = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($dumpFiles.Count -gt 0) {
    foreach ($df in $dumpFiles) {
        $dumpObj = Read-DcMinidump -Path $df.FullName
        if ($dumpObj) {
            $parsedDumps.Add($dumpObj)
            if (-not $Quiet) {
                Write-Host "------------------------------------------------------------------------" -ForegroundColor Gray
                Write-Host "Dump File:     $($dumpObj.FileName)" -ForegroundColor Yellow
                Write-Host "Location:      $($dumpObj.FullName)" -ForegroundColor White
                Write-Host "Timestamp:     $($dumpObj.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')) | $($dumpObj.SizeMb) MB | $($dumpObj.Architecture)" -ForegroundColor DarkGray
                if ($dumpObj.ExceptionCode) {
                    Write-Host "  +- Exception:        $($dumpObj.ExceptionCode) ($($dumpObj.ExceptionMeaning))" -ForegroundColor Red
                    Write-Host "  +- Faulting Module:  $($dumpObj.FaultingIP)" -ForegroundColor White
                }
                if ($dumpObj.GpuDriverVersion) {
                    Write-Host "  +- Dump GPU Driver:  v$($dumpObj.GpuDriverVersion)" -ForegroundColor Cyan
                }
                if ($dumpObj.Assertions.Count -gt 0) {
                    Write-Host "  +- Assertions / Error Strings Found:" -ForegroundColor Red
                    foreach ($a in $dumpObj.Assertions) {
                        Write-Host "       * $a" -ForegroundColor Red
                    }
                }
            }
        }
    }
} else {
    if (-not $Quiet) {
        Write-Host "  [ OK ] No crash dump files found in monitored directories." -ForegroundColor Green
    }
}

# Check Live Steam Zombie Processes
$zombieProcesses = [System.Collections.Generic.List[PSCustomObject]]::new()
$liveSteam = Get-Process -Name steam -ErrorAction SilentlyContinue
if ($liveSteam) {
    foreach ($sp in $liveSteam) {
        $hasWindow = ($sp.MainWindowHandle -ne [IntPtr]::Zero)
        $isHung = ($sp.Responding -eq $false)
        $isHeadlessStall = ($sp.Threads.Count -le 3 -and -not $hasWindow)
        if ($isHung -or $isHeadlessStall) {
            $zombieProcesses.Add([PSCustomObject]@{
                ProcessName = $sp.ProcessName
                PID         = $sp.Id
                StartTime   = $sp.StartTime
                Threads     = $sp.Threads.Count
                Responding  = $sp.Responding
            })
            if (-not $Quiet) {
                Write-Host "`n  [!] LIVE PROCESS ZOMBIE DETECTED: $($sp.ProcessName) (PID: $($sp.Id))" -ForegroundColor Red
                Write-Host "      Process is headless or not responding, blocking single-instance relaunch mutex." -ForegroundColor DarkYellow
            }
        }
    }
}
if (-not $Quiet) { Write-Host "" }

# -------------------------------------------------------------------------
# TIER 2: APPLICATION & GAME ENGINE LOGS
# -------------------------------------------------------------------------
if (-not $Quiet) {
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host "  [2/4] CHECKING GAME & STEAM LOGS" -ForegroundColor Magenta
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host ""
}

$engineLogs = Get-DcEngineLogs -Cutoff $cutoff -EndTime $endTime
$steamLogs = Get-DcSteamLogs -Cutoff $cutoff -EndTime $endTime

if ($engineLogs.Count -gt 0 -or $steamLogs.Count -gt 0) {
    if (-not $Quiet) {
        foreach ($el in $engineLogs) {
            Write-Host "  [$($el.Engine)] Log: $($el.FullName)" -ForegroundColor Yellow
            foreach ($err in ($el.ErrorLines | Select-Object -Last 4)) {
                Write-Host "    * $err" -ForegroundColor Red
            }
        }
        foreach ($sl in $steamLogs) {
            Write-Host "  [Steam Telemetry] Log: $($sl.FullName)" -ForegroundColor Yellow
            foreach ($err in ($sl.ErrorLines | Select-Object -Last 4)) {
                Write-Host "    * $err" -ForegroundColor DarkYellow
            }
        }
    }
} else {
    if (-not $Quiet) {
        Write-Host "  [ OK ] No application or game engine log errors recorded in this timeframe." -ForegroundColor Green
    }
}
if (-not $Quiet) { Write-Host "" }

# -------------------------------------------------------------------------
# TIER 3: SYSTEM LOGS & HARDWARE TELEMETRY
# -------------------------------------------------------------------------
if (-not $Quiet) {
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host "  [3/4] CHECKING WINDOWS EVENT LOGS (GPU, POWER & NETWORK)" -ForegroundColor Magenta
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host ""
}

$telemetry = Get-DcSystemTelemetry -Cutoff $cutoff -EndTime $endTime
if (-not $Quiet) {
    if ($telemetry.FastStartup.FastStartupEnabled) {
        Write-Host "  [!] Power Configuration: Windows Fast Startup is ENABLED (HiberbootEnabled = 1)" -ForegroundColor Yellow
        Write-Host "      Notice: Fast Startup persists kernel power states and can cause 0x9F power loop crashes." -ForegroundColor DarkYellow
    } else {
        Write-Host "  [ OK ] Power Configuration: Fast Startup is Disabled (Clean Cold Boot Enabled)." -ForegroundColor Green
    }

    if ($telemetry.PciePowerManagement.IsEnabled) {
        Write-Host "  [!] PCIe Power Configuration: Link State Power Management is ENABLED ($($telemetry.PciePowerManagement.ACSettingName))" -ForegroundColor Yellow
        Write-Host "      Notice: Low-power L0s/L1 bus states trigger TDR timeouts (4101) on PCIe 4.0/5.0 GPUs." -ForegroundColor DarkYellow
    } else {
        Write-Host "  [ OK ] PCIe Power Configuration: Link State Power Management is Disabled (High-Speed Link Maintained)." -ForegroundColor Green
    }

    if ($telemetry.WheaErrors.Count -gt 0) {
        foreach ($w in $telemetry.WheaErrors) {
            Write-Host "  [!] WHEA Hardware Error [$($w.TimeCreated)]: $($w.Message)" -ForegroundColor Red
        }
    }
    if ($telemetry.TdrEvents.Count -gt 0) {
        foreach ($tdr in $telemetry.TdrEvents) {
            Write-Host "  [!] GPU Driver TDR Reset [$($tdr.TimeCreated)]: $($tdr.Message)" -ForegroundColor Red
        }
    }
    if ($telemetry.KernelBugChecks.Count -gt 0) {
        foreach ($bc in $telemetry.KernelBugChecks) {
            Write-Host "  [!] Kernel BugCheck (BSOD) [$($bc.TimeCreated)]: $($bc.Code) - $($bc.Meaning)" -ForegroundColor Red
        }
    }
    if ($telemetry.AbruptReboots.Count -gt 0) {
        foreach ($ar in $telemetry.AbruptReboots) {
            Write-Host "  [!] Kernel-Power Event 41 (Abrupt Reboot) [$($ar.TimeCreated)]" -ForegroundColor Red
        }
    }
    if ($telemetry.UnexpectedShutdowns.Count -gt 0) {
        foreach ($us in $telemetry.UnexpectedShutdowns) {
            Write-Host "  [!] Unexpected Shutdown (Event 6008) [$($us.TimeCreated)]" -ForegroundColor Red
        }
    }

    if ($telemetry.NetworkDrops.Count -gt 0) {
        foreach ($nd in ($telemetry.NetworkDrops | Select-Object -First 5)) {
            Write-Host "  [!] Network Link Drop [$($nd.TimeCreated)]: $($nd.Message)" -ForegroundColor Red
        }
    }
    if ($telemetry.PciDeviceResets -and $telemetry.PciDeviceResets.Count -gt 0) {
        foreach ($pr in ($telemetry.PciDeviceResets | Select-Object -First 3)) {
            Write-Host "  [!] PCI Bus Device Reset [$($pr.TimeCreated)]: $($pr.Message)" -ForegroundColor Red
        }
    }
    if ($telemetry.UdpPortExhaustions -and $telemetry.UdpPortExhaustions.Count -gt 0) {
        foreach ($upe in ($telemetry.UdpPortExhaustions | Select-Object -First 3)) {
            Write-Host "  [!] UDP Dynamic Port Exhaustion [$($upe.TimeCreated)]: $($upe.Message)" -ForegroundColor Yellow
        }
    }
    if ($telemetry.WlanFailovers.Count -gt 0) {
        foreach ($wf in ($telemetry.WlanFailovers | Select-Object -First 3)) {
            Write-Host "  [!] WLAN Failover Event [$($wf.TimeCreated)]: $($wf.Message)" -ForegroundColor Yellow
        }
    }

    if ($telemetry.CpuThrottlingEvents -and $telemetry.CpuThrottlingEvents.Count -gt 0) {
        foreach ($ct in ($telemetry.CpuThrottlingEvents | Select-Object -First 3)) {
            Write-Host "  [!] CPU Thermal / VRM Throttling [$($ct.TimeCreated)]: $($ct.Message)" -ForegroundColor Red
        }
    }

    if ($telemetry.SleepTransitions -and $telemetry.SleepTransitions.Count -gt 0) {
        foreach ($st in ($telemetry.SleepTransitions | Select-Object -First 3)) {
            Write-Host "  [i] Sleep/Wake Transition [$($st.WakeTime)]: $($st.Message)" -ForegroundColor Cyan
        }
    }

    if ($telemetry.WheaErrors.Count -eq 0 -and $telemetry.TdrEvents.Count -eq 0 -and $telemetry.KernelBugChecks.Count -eq 0 -and $telemetry.AbruptReboots.Count -eq 0 -and $telemetry.NetworkDrops.Count -eq 0 -and $telemetry.PciDeviceResets.Count -eq 0 -and $telemetry.UdpPortExhaustions.Count -eq 0 -and $telemetry.CpuThrottlingEvents.Count -eq 0) {
        Write-Host "  [ OK ] No GPU driver TDR resets, Kernel BugChecks, network drops, or hardware errors in event telemetry." -ForegroundColor Green
    }
    Write-Host ""
}

# -------------------------------------------------------------------------
# TIER 4: SYSTEM HARDWARE & CONFIGURATION
# -------------------------------------------------------------------------
if (-not $Quiet) {
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host "  [4/4] CHECKING HARDWARE & DRIVER STATUS" -ForegroundColor Magenta
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host ""
}

$pnpIssues = Get-DcPnpHealth
$gpuHealth = Get-DcGpuDriverHealth
$mbHealth = Get-DcMotherboardAndChipsetHealth
$memHealth = Get-DcMemoryHealth
$storageHealth = Get-DcStorageHealth
$netHealth = Get-DcNetworkHealth
$displayHealth = Get-DcDisplayDiagnostics
$kernelDriverHealth = Get-DcProblematicKernelDrivers

if (-not $Quiet) {
    # Motherboard & Chipset Overview
    Write-Host "  Motherboard : $($mbHealth.MotherboardManufacturer) $($mbHealth.MotherboardProduct) $($mbHealth.MotherboardVersion)" -ForegroundColor White
    $biosAgeStr = if ($mbHealth.BiosAgeYears) { " ($($mbHealth.BiosAgeYears) yrs old)" } else { "" }
    Write-Host "  BIOS        : $($mbHealth.BiosVersion) | Released: $($mbHealth.BiosReleaseDate)$biosAgeStr" -ForegroundColor $(if ($mbHealth.IsBiosOutdated) { [ConsoleColor]::Yellow } else { [ConsoleColor]::White })
    Write-Host "  Chipset     : $($mbHealth.Summary)" -ForegroundColor $(if ($mbHealth.IsHealthy) { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow })
    if ($mbHealth.MissingControllers.Count -gt 0) {
        Write-Host "  [!] Missing Chipset Controllers: $($mbHealth.MissingControllers -join ', ')" -ForegroundColor Red
    }

    # System Memory (RAM)
    $memColor = if ($memHealth.IsRunningBaseJedec) { [ConsoleColor]::Yellow } else { [ConsoleColor]::White }
    Write-Host "  RAM         : $($memHealth.Summary)" -ForegroundColor $memColor
    if ($memHealth.IsRunningBaseJedec) {
        Write-Host "  [!] Notice: RAM appears to be running at base JEDEC speed ($($memHealth.ConfiguredClockSpeed) MT/s) while rated for $($memHealth.MaxSpeed) MT/s. Consider enabling XMP/EXPO in BIOS." -ForegroundColor DarkYellow
    }

    # Storage Free Space
    $lowDisks = @($storageHealth | Where-Object { $_.IsLowSpace })
    if ($lowDisks.Count -gt 0) {
        foreach ($ld in $lowDisks) {
            Write-Host "  [!] Low Storage Warning: Drive $($ld.DeviceID) ($($ld.VolumeName)) has only $($ld.FreeGb) GB free ($($ld.PercentFree)%). Low free space can cause shader compiler timeouts and pagefile exhaustion." -ForegroundColor Red
        }
    }

    if ($pnpIssues.Count -gt 0) {
        Write-Host "  [!] PnP Hardware Health Warning: Detected $($pnpIssues.Count) device(s) with errors/missing drivers:" -ForegroundColor Red
        foreach ($pi in $pnpIssues) {
            Write-Host "      * [$($pi.Status)] $($pi.FriendlyName): $($pi.Explanation)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [ OK ] PnP Hardware Health: All present devices are reporting HEALTHY (Status: OK)." -ForegroundColor Green
    }

    foreach ($g in $gpuHealth.Gpus) {
        Write-Host "  GPU: $($g.Name) ($($g.Vendor))" -ForegroundColor Yellow
        Write-Host "    +- Driver Version: $($g.DriverVersion) | Date: $($g.DriverDate)" -ForegroundColor DarkGray
        $installTypeStr = if ($g.AmdInstallType) { " | Install: $($g.AmdInstallType)" } else { "" }
        Write-Host "    +- Provider:       $($g.Provider) | Status: $($g.Status)$installTypeStr" -ForegroundColor DarkGray
        if ($g.CrashDefenderActive) {
            Write-Host "    +- Note: AMD Crash Defender service (AMDFendrSR) is active" -ForegroundColor DarkGray
        }
    }

    if ($gpuHealth.RebarStatus.IsSupported) {
        $rebarColor = if ($gpuHealth.RebarStatus.IsEnabled) { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }
        Write-Host "  Resizable BAR: $($gpuHealth.RebarStatus.Details)" -ForegroundColor $rebarColor
    }

    if ($gpuHealth.HasGhostDrivers) {
        foreach ($gd in $gpuHealth.GhostGpuDrivers) {
            Write-Host "  [!] Conflicting Driver Warning: $gd" -ForegroundColor Red
        }
    }

    if ($gpuHealth.DualGpuConflict) {
        Write-Host "  [!] WARNING: $($gpuHealth.DualGpuDetails)" -ForegroundColor Red
    } elseif ($gpuHealth.HybridMultiGpu) {
        Write-Host "  [i] Multi-GPU Setup: $($gpuHealth.HybridMultiGpuDetails)" -ForegroundColor Cyan
    }

    foreach ($d in $displayHealth.Displays) {
        $dispColor = if ($d.HasTimingRisk) { [ConsoleColor]::Red } else { [ConsoleColor]::White }
        Write-Host "  Display: $($d.Name) ($($d.Connection))" -ForegroundColor $dispColor
        Write-Host "    +- Active Mode:    $($d.ActiveResolution) @ $($d.ActiveRefreshRate) Hz" -ForegroundColor DarkGray
        if ($d.HasTimingRisk) {
            Write-Host "    [!] HAZARD: High-Risk EDID Timings / DP 1.2a Scaler Saturation Detected!" -ForegroundColor Red
        }
    }

    if ($kernelDriverHealth.RogueDriversDetected) {
        Write-Host "  [!] Rogue Kernel I/O Driver Warning: Detected legacy port access driver(s) active on boot:" -ForegroundColor Red
        foreach ($kd in ($kernelDriverHealth.Drivers | Where-Object { $_.IsActive -and -not $_.IsDisabled })) {
            Write-Host "      * $($kd.FileName) (Service: $($kd.ServiceName), Start: $($kd.StartType)) - $($kd.Software)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [ OK ] Kernel Driver Security: No problematic legacy I/O drivers (inpoutx64/WinRing0/ENE) detected." -ForegroundColor Green
    }

    foreach ($net in $netHealth) {
        Write-Host "  Adapter: $($net.Name) ($($net.InterfaceDescription))" -ForegroundColor White
        $portStr = if ($net.UdpPortRange) { " | UDP Ports: $($net.UdpPortRange)" } else { "" }
        Write-Host "    +- Status: $($net.Status) | Speed/Duplex: $($net.SpeedDuplex) | VLAN: $($net.PriorityVLAN)$portStr" -ForegroundColor DarkGray
        if ($net.IsUdpConstrained) {
            Write-Host "    [!] CAUTION: UDP dynamic port space is constrained ($($net.UdpPortRange) vs TCP $($net.TcpPortRange))." -ForegroundColor Yellow
            Write-Host "        Bursty matchmaking and server queries can exhaust UDP ports, causing socket drops." -ForegroundColor DarkYellow
            Write-Host "        Remediation: run '.\Analyze-LatestCrash.ps1 -ExpandUdpPorts' as Administrator." -ForegroundColor DarkYellow
        }
    }
    Write-Host ""
}

# -------------------------------------------------------------------------
# EXECUTIVE ROOT CAUSE DETERMINATION (MULTI-FINDING RULE ENGINE)
# -------------------------------------------------------------------------
$findingResult = Resolve-DcDiagnosticFindings `
    -ParsedDumps $parsedDumps `
    -Telemetry $telemetry `
    -GpuHealth $gpuHealth `
    -PnpIssues $pnpIssues `
    -MotherboardHealth $mbHealth `
    -DisplayHealth $displayHealth `
    -KernelDriverHealth $kernelDriverHealth `
    -NetworkHealth $netHealth `
    -ZombieProcesses $zombieProcesses `
    -ScanMode $scanMode `
    -MaxLookbackDays $MaxLookbackDays `
    -IncidentAnchor $incidentAnchor

$rootCauseTitle = $findingResult.RootCauseTitle
$rootCauseDesc = $findingResult.RootCauseDescription
$rootCauseGuidance = $findingResult.RootCauseGuidance
$rootCauseSeverity = $findingResult.RootCauseSeverity
$allFindings = @($findingResult.Findings)
$secondaryFindings = @($findingResult.SecondaryFindings)

# -------------------------------------------------------------------------
# HISTORICAL RESOLVED TIMEOUT & SYSTEM CHANGE CORRELATION
# -------------------------------------------------------------------------
$resolvedHistory = $null
if ($InvestigateResolved -or $scanMode -eq "LatestIncidentClean") {
    $histLookback = if ($InvestigateResolved) { $MaxLookbackDays } else { [math]::Max($MaxLookbackDays, 180) }
    $activeGpuDrvVer = $null
    if ($gpuHealth -and $gpuHealth.Gpus -and $gpuHealth.Gpus.Count -gt 0) {
        $primaryGpu = $gpuHealth.Gpus | Where-Object { -not $_.IsGeneric } | Select-Object -First 1
        if ($primaryGpu) { $activeGpuDrvVer = $primaryGpu.DriverVersion }
    }
    $resolvedHistory = Find-DcResolvedIncidentHistory -LookbackDays $histLookback -CurrentGpuDriverVersion $activeGpuDrvVer

    if ($resolvedHistory -and $resolvedHistory.HasResolvedEpisodes -and $resolvedHistory.PrimaryResolvedEpisode) {
        $ep = $resolvedHistory.PrimaryResolvedEpisode
        if ($InvestigateResolved -or $rootCauseSeverity -eq "Healthy") {
            $rootCauseTitle = "HISTORICAL TIMEOUT EPISODE RESOLVED ($($ep.QuietDaysSinceEnd) DAYS CRASH-FREE)"
            $drvDiffText = if ($ep.HistoricalDriverVersion -and $ep.CurrentDriverVersion -and ($ep.HistoricalDriverVersion -ne $ep.CurrentDriverVersion)) {
                " Driver changed from v$($ep.HistoricalDriverVersion) during the crashes to v$($ep.CurrentDriverVersion) currently."
            } elseif ($ep.CurrentDriverVersion) {
                " Active GPU driver: v$($ep.CurrentDriverVersion)."
            } else { "" }
            $rootCauseDesc = "Detected a resolved historical episode of $($ep.IncidentCount) incident(s) between $($ep.StartTime.ToString('yyyy-MM-dd HH:mm')) and $($ep.EndTime.ToString('yyyy-MM-dd HH:mm')) (Historical Cause: $($ep.HistoricalRootCause)).$drvDiffText The system has been stable for $($ep.QuietDaysSinceEnd) days since the last timeout."
            if ($ep.ResolutionFactors -and $ep.ResolutionFactors.Count -gt 0) {
                $topFactorsText = @(
                    $ep.ResolutionFactors | Select-Object -First 3 | ForEach-Object {
                        "[$($_.Confidence)] $($_.Title) ($($_.DeltaFromLast)) - Source: $($_.Source)"
                    }
                ) -join "`n  * "
                $rootCauseGuidance = "What Changed to Resolve It:`n  * $topFactorsText"
            } else {
                $rootCauseGuidance = "No explicit driver or registry change was recorded in the immediate post-incident window; resolution likely resulted from an application/game update or workload change after $($ep.EndTime.ToString('yyyy-MM-dd'))."
            }
            $rootCauseSeverity = "Healthy"
        }
    } elseif ($InvestigateResolved) {
        $rootCauseTitle = "NO RESOLVED HISTORICAL TIMEOUT EPISODE IDENTIFIED"
        $rootCauseDesc = $resolvedHistory.Summary
        $rootCauseGuidance = "If historical logs were cleared by a clean Windows install or log rotation, inspect preserved minidumps or increase -MaxLookbackDays."
    }

    if (-not $Quiet -and ($InvestigateResolved -or ($resolvedHistory -and $resolvedHistory.HasResolvedEpisodes))) {
        Write-Host "========================================================================" -ForegroundColor Magenta
        Write-Host "  HISTORICAL TIMEOUT & RESOLUTION CORRELATION (PAST $histLookback DAYS)" -ForegroundColor Magenta
        Write-Host "========================================================================" -ForegroundColor Magenta
        Write-Host ""
        if ($resolvedHistory -and $resolvedHistory.HasResolvedEpisodes -and $resolvedHistory.PrimaryResolvedEpisode) {
            $ep = $resolvedHistory.PrimaryResolvedEpisode
            Write-Host "  Episode Window      : $($ep.StartTime.ToString('yyyy-MM-dd HH:mm')) .. $($ep.EndTime.ToString('yyyy-MM-dd HH:mm')) ($($ep.IncidentCount) incident(s))" -ForegroundColor Yellow
            Write-Host "  Crash-Free Duration : $($ep.QuietDaysSinceEnd) days since last incident" -ForegroundColor Green
            Write-Host "  Historical Cause    : $($ep.HistoricalRootCause)" -ForegroundColor White
            $histDrvStr = if ($ep.HistoricalDriverVersion) { "v$($ep.HistoricalDriverVersion)" } else { "Unrecorded" }
            $currDrvStr = if ($ep.CurrentDriverVersion) { "v$($ep.CurrentDriverVersion)" } else { "Unknown" }
            Write-Host "  Driver Version Diff : $histDrvStr (at crash) -> $currDrvStr (current)" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  Ranked 'What Changed to Resolve It' Findings:" -ForegroundColor Cyan
            if ($ep.ResolutionFactors -and $ep.ResolutionFactors.Count -gt 0) {
                foreach ($rf in ($ep.ResolutionFactors | Select-Object -First 6)) {
                    $confColor = switch ($rf.Confidence) {
                        "High"       { [ConsoleColor]::Green }
                        "Medium"     { [ConsoleColor]::Yellow }
                        default      { [ConsoleColor]::Gray }
                    }
                    $tsStr = if ($rf.Timestamp) { $rf.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { "Active State" }
                    Write-Host "    * [$($rf.Confidence)] [$tsStr | $($rf.DeltaFromLast)] $($rf.Title)" -ForegroundColor $confColor
                    Write-Host "      Source: $($rf.Source) | $($rf.Details)" -ForegroundColor DarkGray
                }
            } else {
                Write-Host "    * No timestamped driver or registry changes found in primary inflection window." -ForegroundColor DarkGray
            }
        } else {
            Write-Host "  [i] $($resolvedHistory.Summary)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}

if (-not $Quiet) {
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "  CRASH CHECK SUMMARY & HOW TO FIX IT" -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host ""
    $color = if ($rootCauseSeverity -eq "Critical") { [ConsoleColor]::Red } elseif ($rootCauseSeverity -eq "Warning") { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }
    Write-Host "  Main Issue: $rootCauseTitle" -ForegroundColor $color
    Write-Host "  $rootCauseDesc" -ForegroundColor White
    Write-Host ""
    Write-Host "  How to Fix:" -ForegroundColor Green
    $primaryStepsToPrint = if ($findingResult.PrimaryFinding -and $findingResult.PrimaryFinding.PSObject.Properties['Steps'] -and $findingResult.PrimaryFinding.Steps.Count -gt 0 -and ($rootCauseGuidance -eq $findingResult.RootCauseGuidance)) {
        @($findingResult.PrimaryFinding.Steps)
    } else {
        @($rootCauseGuidance -split '(?:\r?\n\s*(?:\*|\d+\.)\s*)|(?:\s+\*\s+)|(?:^\s*(?:\*|\d+\.)\s*)' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $stepNum = 1
    foreach ($st in $primaryStepsToPrint) {
        Write-Host "    $stepNum. $($st.Trim())" -ForegroundColor White
        $stepNum++
    }
    Write-Host ""

    if ($secondaryFindings.Count -gt 0) {
        Write-Host "  ----------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Other Issues Found ($($secondaryFindings.Count)):" -ForegroundColor Yellow
        Write-Host ""
        $secIdx = 2
        foreach ($sf in $secondaryFindings) {
            $sfColor = if ($sf.Severity -eq "Critical") { [ConsoleColor]::Red } elseif ($sf.Severity -eq "Warning") { [ConsoleColor]::Yellow } else { [ConsoleColor]::Cyan }
            Write-Host "  [$secIdx] [$($sf.Severity.ToUpper())] $($sf.Title)" -ForegroundColor $sfColor
            Write-Host "      $($sf.Description)" -ForegroundColor Gray
            $sfStepsToPrint = if ($sf.PSObject.Properties['Steps'] -and $sf.Steps.Count -gt 0) {
                @($sf.Steps)
            } else {
                @($sf.Guidance -split '(?:\r?\n\s*(?:\*|\d+\.)\s*)|(?:\s+\*\s+)|(?:^\s*(?:\*|\d+\.)\s*)' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            }
            foreach ($sfs in $sfStepsToPrint) {
                Write-Host "      -> $($sfs.Trim())" -ForegroundColor DarkCyan
            }
            Write-Host ""
            $secIdx++
        }
    }

    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "  DIAGNOSTIC REPORT COMPLETE" -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Compile Report Object
$reportObject = [PSCustomObject]@{
    GeneratedAt          = Get-Date
    Version              = "4.5.0"
    ScanMode             = $scanMode
    HoursScanned         = if ($isCustomHours) { $Hours } else { [math]::Round(((Get-Date) - $cutoff).TotalHours, 1) }
    IncidentAnchor       = $incidentAnchor
    CutoffTime           = $cutoff
    EndTime              = $endTime
    RootCauseTitle       = $rootCauseTitle
    RootCauseDescription = $rootCauseDesc
    RootCauseGuidance    = $rootCauseGuidance
    RootCauseSeverity    = $rootCauseSeverity
    Findings             = $allFindings
    SecondaryFindings    = $secondaryFindings
    ResolvedHistory      = $resolvedHistory
    Dumps                = @($parsedDumps)
    ZombieProcesses      = @($zombieProcesses)
    EngineLogs           = @($engineLogs)
    SteamLogs            = @($steamLogs)
    SystemTelemetry      = $telemetry
    HardwareHealth       = [PSCustomObject]@{
        Gpus                       = @($gpuHealth.Gpus)
        DualGpuConflict            = $gpuHealth.DualGpuConflict
        DualGpuDetails             = $gpuHealth.DualGpuDetails
        HybridMultiGpu             = $gpuHealth.HybridMultiGpu
        HybridMultiGpuDetails      = $gpuHealth.HybridMultiGpuDetails
        IsUlpsEnabled              = $gpuHealth.IsUlpsEnabled
        Motherboard                = $mbHealth
        Memory                     = $memHealth
        Storage                    = @($storageHealth)
        RebarStatus                = $gpuHealth.RebarStatus
        GhostGpuDrivers            = @($gpuHealth.GhostGpuDrivers)
        PnpIssues                  = @($pnpIssues)
        Displays                   = @($displayHealth.Displays)
        HighRiskDisplays           = $displayHealth.HighRiskTimingsDetected
        KernelDrivers              = @($kernelDriverHealth.Drivers)
        RogueKernelDriversDetected = $kernelDriverHealth.RogueDriversDetected
        NetworkAdapters            = @($netHealth)
    }
}

# Export HTML if requested
$htmlFile = $null
if ($ExportHtml -or $OpenReport) {
    $htmlFile = Export-DcHtmlReport -ReportData $reportObject
    if (-not $Quiet) {
        Write-Host "  [HTML REPORT] Saved to: $htmlFile" -ForegroundColor Cyan
    }
    if ($OpenReport) {
        Start-Process $htmlFile
    }
}

# Export JSON if requested
if ($ExportJson) {
    $jsonFile = Join-Path $PWD ("CrashReport_" + (Get-Date).ToString("yyyyMMdd_HHmmss") + ".json")
    $jsonText = $reportObject | ConvertTo-Json -Depth 6
    if ($env:USERPROFILE) {
        $jsonText = $jsonText.Replace($env:USERPROFILE.Replace('\', '\\'), "%USERPROFILE%")
        $jsonText = $jsonText.Replace($env:USERPROFILE, "%USERPROFILE%")
    }
    $jsonText = $jsonText -replace '(?i)[a-zA-Z]:\\\\Users\\\\[^\\"\r\n]+', '%USERPROFILE%'
    $jsonText = $jsonText -replace '(?i)[a-zA-Z]:\\Users\\[^\\"\r\n]+', '%USERPROFILE%'
    $jsonText = $jsonText -replace '(?i)User:\s*[^\r\n"\\]+\\\\[^\r\n"\.]+', 'User: [REDACTED]'
    $jsonText = $jsonText -replace '(?i)User:\s*[^\r\n"\\]+\\[^\r\n"\.]+', 'User: [REDACTED]'
    $jsonText = $jsonText -replace '\[U:\d+:\d+\]', '[U:1:REDACTED]'
    [System.IO.File]::WriteAllText($jsonFile, $jsonText, [System.Text.Encoding]::UTF8)
    if (-not $Quiet) {
        Write-Host "  [JSON REPORT] Saved to: $jsonFile" -ForegroundColor Cyan
    }
}

# Export Support Bundle ZIP if requested
if ($ExportZip) {
    $zipFile = Export-DcSupportBundle -ReportData $reportObject
    if (-not $Quiet) {
        Write-Host "  [SUPPORT BUNDLE] Saved to: $zipFile" -ForegroundColor Green
    }
}

$recommendedActions = if ($findingResult.PSObject.Properties['RecommendedActions'] -and $findingResult.RecommendedActions) {
    @($findingResult.RecommendedActions)
} else {
    @()
}

if (-not $Quiet -and -not $NoInteractive -and $recommendedActions.Count -gt 0) {
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Green
    Write-Host "  RECOMMENDED FIXES (SELECT TO APPLY NOW)" -ForegroundColor Green
    Write-Host "========================================================================" -ForegroundColor Green
    Write-Host ""
    $isAdminNow = Test-DcIsAdmin
    for ($i = 0; $i -lt $recommendedActions.Count; $i++) {
        $act = $recommendedActions[$i]
        $num = $i + 1
        $adminTag = if ($act.RequiresAdmin -and -not $isAdminNow) { " [Requires Admin - UAC Prompt]" } elseif ($act.RequiresAdmin) { " [Admin]" } else { "" }
        Write-Host "  [$num] $($act.Label)$adminTag" -ForegroundColor Yellow
        Write-Host "      $($act.Description)" -ForegroundColor Gray
    }
    if ($recommendedActions.Count -gt 1) {
        Write-Host "  [A] Apply All Recommended Fixes (1-$($recommendedActions.Count))" -ForegroundColor Cyan
    }
    Write-Host "  [Q] Skip / Exit without applying changes" -ForegroundColor DarkGray
    Write-Host ""

    $promptLabel = if ($recommendedActions.Count -gt 1) {
        "Select fix(es) to run now (e.g. 1, 1,2, A=All, or Enter/Q to skip)"
    } else {
        "Run recommended fix [1] now? (1/Y=Run, Enter/Q=Skip)"
    }

    $choice = $null
    try {
        if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
            $choice = Read-Host "  $promptLabel"
        }
    } catch {
        $choice = $null
    }

    if (-not [string]::IsNullOrWhiteSpace($choice)) {
        $trimmedChoice = $choice.Trim()
        $selectedActions = [System.Collections.Generic.List[object]]::new()

        if ($trimmedChoice -match '^(?i)(a|all)$') {
            foreach ($act in $recommendedActions) { $selectedActions.Add($act) }
        } elseif ($trimmedChoice -match '^(?i)(y|yes)$' -and $recommendedActions.Count -eq 1) {
            $selectedActions.Add($recommendedActions[0])
        } elseif ($trimmedChoice -notmatch '^(?i)(q|quit|n|no|skip|exit)$') {
            $tokens = $trimmedChoice -split '[,\s]+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            foreach ($tok in $tokens) {
                $idxNum = 0
                if ([int]::TryParse($tok, [ref]$idxNum)) {
                    if ($idxNum -ge 1 -and $idxNum -le $recommendedActions.Count) {
                        $candidate = $recommendedActions[$idxNum - 1]
                        if (-not ($selectedActions | Where-Object { $_.Id -eq $candidate.Id })) {
                            $selectedActions.Add($candidate)
                        }
                    }
                }
            }
        }

        if ($selectedActions.Count -gt 0) {
            Write-Host ""
            $elevatedSwitches = [System.Collections.Generic.List[string]]::new()
            foreach ($act in $selectedActions) {
                if ($act.RequiresAdmin -and -not (Test-DcIsAdmin)) {
                    switch ($act.Id) {
                        "RepairNetwork"       { if (-not $elevatedSwitches.Contains("-RepairNetwork")) { $elevatedSwitches.Add("-RepairNetwork") } }
                        "ExpandUdpPorts"      { if (-not $elevatedSwitches.Contains("-ExpandUdpPorts")) { $elevatedSwitches.Add("-ExpandUdpPorts") } }
                        "RepairGpuSleep"      { if (-not $elevatedSwitches.Contains("-RepairGpuSleep")) { $elevatedSwitches.Add("-RepairGpuSleep") } }
                        "FixDrivers"          { if (-not $elevatedSwitches.Contains("-FixDrivers")) { $elevatedSwitches.Add("-FixDrivers") } }
                        "DisableRogueDrivers" { if (-not $elevatedSwitches.Contains("-DisableRogueDrivers")) { $elevatedSwitches.Add("-DisableRogueDrivers") } }
                    }
                    continue
                }

                Write-Host "  [RUNNING] $($act.Label)..." -ForegroundColor Cyan
                switch ($act.Id) {
                    "CleanShaderCache" {
                        Clear-DcShaderCache -Target $ShaderTarget
                    }
                    "CleanConfigCrimsonDesert" {
                        Clear-DcGameConfig -Game "CrimsonDesert" -Backup
                    }
                    "CleanSteamCache" {
                        Clear-DcSteamCache
                    }
                    "KillHungSteam" {
                        Stop-DcZombieProcesses
                    }
                    "DisablePciePowerSavings" {
                        & (Join-Path $PSScriptRoot "scripts\Repair-PciePowerSettings.ps1")
                    }
                    "RepairNetwork" {
                        Repair-DcEthernetSettings -Speed $Speed
                    }
                    "ExpandUdpPorts" {
                        Repair-DcUdpPortRange
                    }
                    "RepairGpuSleep" {
                        & (Join-Path $PSScriptRoot "scripts\Repair-GpuSleepSettings.ps1") -DisableUlps:$DisableUlps
                    }
                    "FixDrivers" {
                        Repair-DcAmdDriverAlignment -BlockWindowsUpdateDrivers
                    }
                    "DisableRogueDrivers" {
                        & (Join-Path $PSScriptRoot "scripts\Disable-RogueKernelDrivers.ps1")
                    }
                }
            }

            if ($elevatedSwitches.Count -gt 0) {
                Write-Host "  [ADMIN ELEVATION] Launching elevated session for: $($elevatedSwitches -join ' ')..." -ForegroundColor Yellow
                [void](Request-DcAdminElevation -ScriptPath $PSCommandPath -Arguments @($elevatedSwitches) -Wait)
            }
            Write-Host ""
            Write-Host "  [COMPLETE] Selected remediation actions finished." -ForegroundColor Green
        }
    }
}

if ($Quiet -or $PassThru) {
    return $reportObject
}
