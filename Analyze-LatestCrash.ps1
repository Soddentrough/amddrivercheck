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

# Report evidence sources that exist but cannot be read, instead of silently skipping them.
$unreadableSources = [System.Collections.Generic.List[string]]::new()
foreach ($probe in @((Join-Path $env:SystemRoot "Minidump"), (Join-Path $env:SystemRoot "LiveKernelReports"))) {
    if (Test-Path -LiteralPath $probe -ErrorAction SilentlyContinue) {
        try {
            [void](Get-ChildItem -LiteralPath $probe -Force -ErrorAction Stop | Select-Object -First 1)
        } catch {
            $unreadableSources.Add("$probe - Windows crash dump location found (requires Administrator privileges). Install WinDbg from the Microsoft Store ('winget install Microsoft.WinDbg') and re-run DriverCheck from an Administrator PowerShell to analyze these dumps.")
        }
    }
}
if (-not $Quiet) {
    foreach ($u in $unreadableSources) { Write-Host "  [i] $u" -ForegroundColor Cyan }
}

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
                if ($dumpObj.ApiContext) {
                    Write-Host "  +- API Context:      $($dumpObj.ApiContext)" -ForegroundColor Magenta
                }
                if ($dumpObj.CallStack -and $dumpObj.CallStack.Count -gt 0) {
                    Write-Host "  +- Call Stack ($($dumpObj.CallStack.Count) frames):" -ForegroundColor DarkGray
                    foreach ($fr in ($dumpObj.CallStack | Select-Object -First 4)) {
                        Write-Host "       * $fr" -ForegroundColor Gray
                    }
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
$steamGameSessions = Get-DcSteamGameSessions -Cutoff $cutoff -EndTime $endTime

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
        Write-Host "  [i] Config: Windows Fast Startup is enabled (HiberbootEnabled = 1)" -ForegroundColor Gray
    } else {
        Write-Host "  [i] Config: Windows Fast Startup is disabled" -ForegroundColor Gray
    }

    if ($telemetry.PciePowerManagement.IsEnabled) {
        Write-Host "  [i] Config: PCIe Link State Power Management is enabled ($($telemetry.PciePowerManagement.ACSettingName))" -ForegroundColor Gray
    } else {
        Write-Host "  [i] Config: PCIe Link State Power Management is disabled" -ForegroundColor Gray
    }

    if ($telemetry.WheaErrors.Count -gt 0) {
        foreach ($w in $telemetry.WheaErrors) {
            Write-Host "  [!] WHEA Hardware Error [$($w.TimeCreated)]: $($w.Message)" -ForegroundColor Red
        }
    }
    if ($telemetry.TdrEvents.Count -gt 0) {
        foreach ($tdr in $telemetry.TdrEvents) {
            Write-Host "  [!] GPU watchdog event [$($tdr.TimeCreated)]: $($tdr.Message)" -ForegroundColor Red
        }
    }
    if ($telemetry.PSObject.Properties['TdrWorkloads'] -and $telemetry.TdrWorkloads.Count -gt 0) {
        foreach ($tw in ($telemetry.TdrWorkloads | Select-Object -First 3)) {
            Write-Host "  [!] Pre-TDR GPU Workload [$($tw.TimeCreated)]: $($tw.Message)" -ForegroundColor Yellow
        }
    }
    if ($telemetry.PSObject.Properties['DisplayHotplugEvents'] -and $telemetry.DisplayHotplugEvents.Count -gt 0) {
        foreach ($dhp in ($telemetry.DisplayHotplugEvents | Select-Object -First 3)) {
            Write-Host "  [!] Display Hotplug / Link Loss [$($dhp.TimeCreated)]: $($dhp.Message)" -ForegroundColor Yellow
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
        Write-Host "  [i] No GPU timeout events, bugchecks, network drops, or hardware error reports were found in the event logs that were read." -ForegroundColor Gray
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
        Write-Host "  [i] Devices without a loaded driver: $($mbHealth.MissingControllers -join ', ')" -ForegroundColor Red
    }

    # System Memory (RAM)
    $memColor = if ($memHealth.IsRunningBaseJedec) { [ConsoleColor]::Yellow } else { [ConsoleColor]::White }
    Write-Host "  RAM         : $($memHealth.Summary)" -ForegroundColor $memColor
    if ($memHealth.IsRunningBaseJedec) {
        Write-Host "  [i] RAM configured speed is $($memHealth.ConfiguredClockSpeed) MT/s; module rated speed is $($memHealth.MaxSpeed) MT/s." -ForegroundColor Gray
    }

    # Storage Free Space
    $lowDisks = @($storageHealth | Where-Object { $_.IsLowSpace })
    if ($lowDisks.Count -gt 0) {
        foreach ($ld in $lowDisks) {
            Write-Host "  [i] Low free space: Drive $($ld.DeviceID) ($($ld.VolumeName)) has $($ld.FreeGb) GB free ($($ld.PercentFree)%)." -ForegroundColor Red
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
            Write-Host "  [i] Additional GPU driver entries present: $gd" -ForegroundColor Gray
        }
    }

    if ($gpuHealth.DualGpuConflict) {
        Write-Host "  [i] $($gpuHealth.DualGpuDetails)" -ForegroundColor Gray
    } elseif ($gpuHealth.HybridMultiGpu) {
        Write-Host "  [i] Multi-GPU Setup: $($gpuHealth.HybridMultiGpuDetails)" -ForegroundColor Cyan
    }

    foreach ($d in $displayHealth.Displays) {
        $dispColor = if ($d.HasTimingRisk) { [ConsoleColor]::Red } else { [ConsoleColor]::White }
        Write-Host "  Display: $($d.Name) ($($d.Connection))" -ForegroundColor $dispColor
        Write-Host "    +- Active Mode:    $($d.ActiveResolution) @ $($d.ActiveRefreshRate) Hz" -ForegroundColor DarkGray
        if ($d.HasTimingRisk) {
            Write-Host "    [i] EDID timing heuristic matched (pixel clock / blanking thresholds); this is a heuristic, not an observed fault." -ForegroundColor Gray
        }
    }

    if ($kernelDriverHealth.RogueDriversDetected) {
        Write-Host "  [i] Legacy port-I/O kernel driver(s) present and set to start on boot:" -ForegroundColor Gray
        foreach ($kd in ($kernelDriverHealth.Drivers | Where-Object { $_.IsActive -and -not $_.IsDisabled })) {
            Write-Host "      * $($kd.FileName) (Service: $($kd.ServiceName), Start: $($kd.StartType)) - $($kd.Software)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [i] No legacy port-I/O kernel drivers (inpoutx64/WinRing0/ENE) found." -ForegroundColor Gray
    }

    foreach ($net in $netHealth) {
        Write-Host "  Adapter: $($net.Name) ($($net.InterfaceDescription))" -ForegroundColor White
        $portStr = if ($net.UdpPortRange) { " | UDP Ports: $($net.UdpPortRange)" } else { "" }
        Write-Host "    +- Status: $($net.Status) | Speed/Duplex: $($net.SpeedDuplex) | VLAN: $($net.PriorityVLAN)$portStr" -ForegroundColor DarkGray
        if ($net.PowerSavingSummary -and $net.PowerSavingSummary -ne "Default") {
            Write-Host "    +- Power States: $($net.PowerSavingSummary)" -ForegroundColor $(if ($net.HasPowerSavingRisk) { [ConsoleColor]::Yellow } else { [ConsoleColor]::DarkGray })
        }
        if ($net.HasPowerSavingRisk) {
            Write-Host "    [i] Config: adapter idle power-down / ULP / EEE settings are active on $($net.Name)." -ForegroundColor Gray
        }
        if ($net.HasForced25GSpeed) {
            Write-Host "    [i] Config: Speed & Duplex is forced to 2.5 Gbps (*SpeedDuplex=2500)." -ForegroundColor Gray
        }
        if ($net.IsUdpConstrained) {
            Write-Host "    [i] Config: UDP dynamic port range is $($net.UdpPortRange); TCP range is $($net.TcpPortRange)." -ForegroundColor Gray
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
    -IncidentAnchor $incidentAnchor `
    -SteamGameSessions $steamGameSessions `
    -UnreadableSources @($unreadableSources) `
    -EngineLogs @($engineLogs) `
    -SteamLogs @($steamLogs)

$rootCauseTitle = $findingResult.RootCauseTitle
$rootCauseDesc = $findingResult.RootCauseDescription
$rootCauseGuidance = $findingResult.RootCauseGuidance
$rootCauseSeverity = $findingResult.RootCauseSeverity
$allFindings = @($findingResult.Findings)
$secondaryFindings = @($findingResult.SecondaryFindings)
$leads = if ($findingResult.PSObject.Properties['Leads'] -and $findingResult.Leads) { @($findingResult.Leads) } else { @() }

# The historical "what changed to resolve it" correlation was removed: it inferred causes
# from coincident timestamps. Nothing here is inferred.
$resolvedHistory = $null
if ($InvestigateResolved) {
    Write-Host "  [i] -InvestigateResolved no longer produces cause/resolution attributions (they were inferred, not observed)." -ForegroundColor Yellow
}

if (-not $Quiet) {
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "  EVENT SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host ""
    $color = if ($rootCauseSeverity -eq "Critical") { [ConsoleColor]::Red } elseif ($rootCauseSeverity -eq "Warning") { [ConsoleColor]::Yellow } else { [ConsoleColor]::Gray }
    Write-Host "  $rootCauseTitle" -ForegroundColor $color
    Write-Host "  $rootCauseDesc" -ForegroundColor White
    Write-Host ""

    if ($secondaryFindings.Count -gt 0) {
        Write-Host "  ----------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Other recorded events ($($secondaryFindings.Count)):" -ForegroundColor Yellow
        Write-Host ""
        $lastGroup = $null
        foreach ($sf in $secondaryFindings) {
            $grp = if ($sf.Id -eq 'KERNEL_BUGCHECK') { 'SYSTEM CRASHES (BSOD / BugCheck)' }
                   elseif ($sf.Id -eq 'CRASH_DUMP') { 'PROCESS CRASH DUMPS' }
                   elseif ($sf.Id -eq 'GPU_TIMEOUT_EVENT') { 'GPU DRIVER TIMEOUTS (TDR)' }
                   elseif ($sf.Id -in @('KERNEL_POWER_41', 'EVENTLOG_6008')) { 'SYSTEM RESTARTS (Unclean Shutdown)' }
                   elseif ($sf.Kind -eq 'Evidence') { 'CRASH DUMP LOCATIONS REQUIRING ELEVATION' }
                   else { 'OTHER EVENTS' }
            if ($grp -ne $lastGroup) {
                Write-Host "  == $grp ==" -ForegroundColor Cyan
                Write-Host ""
                $lastGroup = $grp
            }
            $ts = if ($sf.Timestamp -is [datetime]) { $sf.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } elseif ($sf.Kind -eq 'Evidence') { 'info' } else { 'unknown time' }
            $tsColor = if ($sf.Kind -eq 'Evidence') { [ConsoleColor]::Cyan } else { [ConsoleColor]::Yellow }
            Write-Host "  * [$ts] $($sf.Title)" -ForegroundColor $tsColor
            Write-Host "      $($sf.Description)" -ForegroundColor Gray
            Write-Host "      Source: $($sf.Source)" -ForegroundColor DarkGray
            Write-Host ""
        }
    }

    if ($leads.Count -gt 0) {
        Write-Host "  ----------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  NEXT INVESTIGATION STEPS:" -ForegroundColor Green
        Write-Host ""
        $li = 1
        foreach ($ld in $leads) {
            Write-Host "  $li. $($ld.Lead)" -ForegroundColor White
            Write-Host "     Based on: $($ld.BasedOn)" -ForegroundColor DarkGray
            Write-Host ""
            $li++
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
    Leads                = $leads
    PrimaryFinding       = $findingResult.PrimaryFinding
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

# Interactive "recommended fixes" menu removed: this tool reports observations only.

if ($Quiet -or $PassThru) {
    return $reportObject
}
