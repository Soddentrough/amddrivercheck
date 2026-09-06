<#
.SYNOPSIS
    Automated Game & System Crash Diagnostic Suite (Unified Engine)
.DESCRIPTION
    A hierarchical, evidence-based diagnostic tool following strict analysis precedence:
      1. Tier 1 (Primary Ground Truth): Crash Dumps & Exceptions (BSOD, WER, Steam, Unreal, Unity).
      2. Tier 2 (Secondary Evidence):   Application & Game Logs (Engine logs, Steam overlay/IPC, asserts).
      3. Tier 3 (Tertiary Telemetry):  System Event Logs (WHEA errors, GPU TDR resets, BugChecks, Fast Startup).
      4. Tier 4 (Contextual Audit):     Hardware Health & Configuration (PnP errors, GPU drivers, Dual-GPU alignment, Network).
.PARAMETER Hours
    Hours back to scan for crash telemetry (default: 48).
.PARAMETER DeepScan
    Extend scan window to 7 days (168 hours).
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
.PARAMETER FixDrivers
    Inspect Windows Driver Store for GPU driver downgrades and lock Windows Update driver policies.
.PARAMETER RepairNetwork
    (Admin) Apply stability settings to Ethernet adapters (Speed/Duplex lock, VLAN disable).
.PARAMETER Speed
    Target speed when using -RepairNetwork: "2.5G" (default), "1.0G", or "Auto".
.PARAMETER CleanConfig
    Clean stale game configuration files and shader caches (with automatic .bak backup).
.PARAMETER Game
    Target game when using -CleanConfig: "TheGreatCircle", "DOOMEternal", "DOOMTheDarkAges", "All" (default).
.PARAMETER CleanSteamCache
    Purge Steam CEF HTML browser cache (%LOCALAPPDATA%\Steam\htmlcache).
.PARAMETER KillHungSteam
    Terminate lingering headless or zombie Steam processes blocking relaunch.
.PARAMETER Quiet
    Suppress interactive banner output and return only the structured report object.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 48,

    [Parameter(Mandatory = $false)]
    [switch]$DeepScan,

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
    [switch]$FixDrivers,

    [Parameter(Mandatory = $false)]
    [switch]$RepairNetwork,

    [Parameter(Mandatory = $false)]
    [ValidateSet("2.5G", "1.0G", "Auto")]
    [string]$Speed = "2.5G",

    [Parameter(Mandatory = $false)]
    [switch]$CleanConfig,

    [Parameter(Mandatory = $false)]
    [ValidateSet("TheGreatCircle", "DOOMEternal", "DOOMTheDarkAges", "All")]
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
    [switch]$Quiet
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Import Modular Engine
$modulesDir = Join-Path $PSScriptRoot "scripts\modules"
Import-Module (Join-Path $modulesDir "DcCrashDump.psm1") -Force
Import-Module (Join-Path $modulesDir "DcEngineLogs.psm1") -Force
Import-Module (Join-Path $modulesDir "DcSystemTelemetry.psm1") -Force
Import-Module (Join-Path $modulesDir "DcHardwareHealth.psm1") -Force
Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force
Import-Module (Join-Path $modulesDir "DcReportGenerator.psm1") -Force

# Apply -DeepScan override
if ($DeepScan) { $Hours = 168 }
$cutoff = (Get-Date).AddHours(-$Hours)

# =========================================================================
# DEDICATED ACTION / REMEDIATION SWITCHES
# =========================================================================

if ($RepairNetwork) {
    Write-Host "`n=== NETWORK ADAPTER STABILITY OPTIMIZER ===" -ForegroundColor Magenta
    Repair-DcEthernetSettings -Speed $Speed
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

# =========================================================================
# SPECIALIZED AUDIT MODES
# =========================================================================

if ($AuditPower) {
    & (Join-Path $PSScriptRoot "scripts\Get-PowerAndSleepDiagnostics.ps1") -Hours $Hours
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

# =========================================================================
# MAIN UNIFIED 4-TIER DIAGNOSTIC FLOW
# =========================================================================

if (-not $Quiet) {
    Write-Host ""
    Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |          AUTOMATED SYSTEM & GAME CRASH DIAGNOSTIC SUITE               |" -ForegroundColor Cyan
    Write-Host "  |             4-Tier Evidence Hierarchy Engine v4.0                     |" -ForegroundColor Cyan
    Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  Scan Window: $($cutoff.ToString('yyyy-MM-dd HH:mm')) to $((Get-Date).ToString('yyyy-MM-dd HH:mm')) ($Hours hours)" -ForegroundColor DarkGray
    Write-Host "  Precedence:  [1] Crash Dumps -> [2] App Logs -> [3] System Logs -> [4] System Config" -ForegroundColor DarkGray
    Write-Host ""
}

# -------------------------------------------------------------------------
# TIER 1: CRASH DUMPS & BINARY THREAD INSPECTION
# -------------------------------------------------------------------------
if (-not $Quiet) {
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host "  TIER 1: CRASH DUMPS & BINARY THREAD INSPECTOR (PRIMARY GROUND TRUTH)" -ForegroundColor Magenta
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host ""
}

$dumpFiles = Get-DcCrashDumps -Cutoff $cutoff
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
    Write-Host "  TIER 2: APPLICATION & GAME ENGINE LOGS (SECONDARY EVIDENCE)" -ForegroundColor Magenta
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host ""
}

$engineLogs = Get-DcEngineLogs -Cutoff $cutoff
$steamLogs = Get-DcSteamLogs -Cutoff $cutoff

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
    Write-Host "  TIER 3: SYSTEM LOGS & HARDWARE TELEMETRY (TERTIARY TELEMETRY)" -ForegroundColor Magenta
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host ""
}

$telemetry = Get-DcSystemTelemetry -Cutoff $cutoff
if (-not $Quiet) {
    if ($telemetry.FastStartup.FastStartupEnabled) {
        Write-Host "  [!] Power Configuration: Windows Fast Startup is ENABLED (HiberbootEnabled = 1)" -ForegroundColor Yellow
        Write-Host "      Notice: Fast Startup persists kernel power states and can cause 0x9F power loop crashes." -ForegroundColor DarkYellow
    } else {
        Write-Host "  [ OK ] Power Configuration: Fast Startup is Disabled (Clean Cold Boot Enabled)." -ForegroundColor Green
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

    if ($telemetry.WheaErrors.Count -eq 0 -and $telemetry.TdrEvents.Count -eq 0 -and $telemetry.KernelBugChecks.Count -eq 0 -and $telemetry.AbruptReboots.Count -eq 0) {
        Write-Host "  [ OK ] No GPU driver TDR resets, Kernel BugChecks, or hardware errors in event telemetry." -ForegroundColor Green
    }
    Write-Host ""
}

# -------------------------------------------------------------------------
# TIER 4: SYSTEM HARDWARE & CONFIGURATION
# -------------------------------------------------------------------------
if (-not $Quiet) {
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host "  TIER 4: SYSTEM CONFIGURATION & HARDWARE INVENTORY (CONTEXTUAL AUDIT)" -ForegroundColor Magenta
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host ""
}

$pnpIssues = Get-DcPnpHealth
$gpuHealth = Get-DcGpuDriverHealth
$netHealth = Get-DcNetworkHealth

if (-not $Quiet) {
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
        Write-Host "    +- Provider:       $($g.Provider) | Status: $($g.Status)" -ForegroundColor DarkGray
    }

    if ($gpuHealth.DualGpuConflict) {
        Write-Host "  [!] WARNING: $($gpuHealth.DualGpuDetails)" -ForegroundColor Red
    }

    foreach ($net in $netHealth) {
        Write-Host "  Adapter: $($net.Name) ($($net.InterfaceDescription))" -ForegroundColor White
        Write-Host "    +- Status: $($net.Status) | Speed/Duplex: $($net.SpeedDuplex) | VLAN: $($net.PriorityVLAN)" -ForegroundColor DarkGray
    }
    Write-Host ""
}

# -------------------------------------------------------------------------
# EXECUTIVE ROOT CAUSE DETERMINATION (EVALUATED BY PRECEDENCE TIER)
# -------------------------------------------------------------------------
$rootCauseTitle = "SYSTEM HEALTHY"
$rootCauseDesc = "No critical hardware faults, GPU driver crashes, or unhandled exceptions detected in the scan window."
$rootCauseGuidance = "Your system is reporting normal stability telemetry. If you experienced a game crash, it may have terminated cleanly without writing a dump or occurred outside the $Hours-hour scan window."
$rootCauseSeverity = "Healthy"

if ($zombieProcesses.Count -gt 0) {
    $rootCauseTitle = "ACTIVE ZOMBIE / HUNG STEAM PROCESS"
    $rootCauseDesc = "steam.exe (PID: $($zombieProcesses[0].PID)) is lingering headless in background, blocking the single-instance mutex and preventing relaunch."
    $rootCauseGuidance = "Run '.\Analyze-LatestCrash.ps1 -KillHungSteam' or terminate steam.exe in Task Manager."
    $rootCauseSeverity = "Warning"
} elseif ($parsedDumps.Count -gt 0 -and ($parsedDumps | Where-Object { $_.ExceptionCode })) {
    $firstCrash = $parsedDumps | Where-Object { $_.ExceptionCode } | Select-Object -First 1
    if ($firstCrash.IsShaderCompiler -or ($firstCrash.FaultingModule -match '(?i)amdxc|amdxx|nvwgf2|oo2core')) {
        $rootCauseTitle = "SHADER COMPILATION / GRAPHICS RUNTIME CRASH ($($firstCrash.FaultingModule))"
        $rootCauseDesc = "Exception $($firstCrash.ExceptionCode): $($firstCrash.ExceptionMeaning) in shader compiler / decompression DLL ($($firstCrash.FaultingModule))."
        $rootCauseGuidance = "Purge corrupt shader caches using '.\Analyze-LatestCrash.ps1 -CleanShaderCache'. Shader compilation places heavy AVX2/AVX-512 load across all CPU cores and RAM; if crashes persist, test CPU/RAM stability or disable aggressive PBO/Curve Optimizer undervolts."
    } elseif ($firstCrash.ExceptionCode -match '0x887A0006|0x887A0005') {
        $rootCauseTitle = "GRAPHICS DEVICE HUNG / REMOVED (0x887A0006 / 0x887A0005)"
        $rootCauseDesc = "DirectX graphics device lost or timed out ($($firstCrash.ExceptionMeaning)) in $($firstCrash.FaultingModule)."
        $rootCauseGuidance = "The display driver crashed or timed out during a render pass. Check GPU temperatures and power cables, lower in-game ray tracing / VRAM texture settings, or clean reinstall GPU drivers."
    } elseif ($firstCrash.ExceptionCode -match '0xC0000005') {
        $rootCauseTitle = "APPLICATION MEMORY ACCESS VIOLATION (0xC0000005)"
        $rootCauseDesc = "Exception 0xC0000005: Native memory access violation in $($firstCrash.FaultingModule) ($($firstCrash.FileName))."
        $rootCauseGuidance = "Memory access violation in $($firstCrash.FaultingModule). Verify game integrity via Steam/Launcher and update Visual C++ Redistributables. If overclocked, test with stock memory/XMP timings."
    } else {
        $rootCauseTitle = "UNHANDLED APPLICATION CRASH (Tier 1 Crash Dump)"
        $rootCauseDesc = "Exception $($firstCrash.ExceptionCode): $($firstCrash.ExceptionMeaning) in $($firstCrash.FaultingModule) ($($firstCrash.FileName))."
        $rootCauseGuidance = "Verify game integrity via Steam/Launcher and report the faulting module ($($firstCrash.FaultingModule)) to the game developer."
    }
    $rootCauseSeverity = "Critical"
} elseif ($gpuHealth.DualGpuConflict) {
    $rootCauseTitle = "DUAL-GPU DRIVER VERSION MISMATCH"
    $rootCauseDesc = $gpuHealth.DualGpuDetails
    $rootCauseGuidance = "Align both AMD display drivers using '.\Analyze-LatestCrash.ps1 -FixDrivers' or disable CPU Integrated Graphics in Motherboard BIOS if not using motherboard display ports."
    $rootCauseSeverity = "Warning"
} elseif ($telemetry.PcieWheaErrors.Count -gt 0) {
    $firstPcie = $telemetry.PcieWheaErrors[0]
    $rootCauseTitle = "PCIe BUS / RISER CABLE INTEGRITY ERROR (WHEA Event 17)"
    $rootCauseDesc = "Windows detected PCIe link communication errors ($($telemetry.PcieWheaErrors.Count) incident(s)). This is frequently caused by PCIe 4.0/5.0 riser cables, loose GPU PCIe slot seating, or motherboard PCIe signal degradation."
    $rootCauseGuidance = "Reseat your graphics card. If using a vertical GPU mount or PCIe riser cable, test with the GPU plugged directly into the motherboard PCIe slot, or configure PCIe link speed to Gen 3 / Gen 4 in BIOS."
    $rootCauseSeverity = "Critical"
} elseif ($telemetry.MemoryExhaustion.Count -gt 0) {
    $rootCauseTitle = "VIRTUAL MEMORY / COMMIT LIMIT EXHAUSTION (Event 2004)"
    $rootCauseDesc = "Windows ran out of virtual memory / pagefile commit limit while games or shader compilation were active ($($telemetry.MemoryExhaustion.Count) incident(s))."
    $rootCauseGuidance = "Ensure your Windows Paging File (Pagefile) is set to 'System managed size' on an SSD with at least 20 GB free space. Do not disable or severely restrict pagefile size."
    $rootCauseSeverity = "Critical"
} elseif ($telemetry.TdrEvents.Count -gt 0) {
    $rootCauseTitle = "GPU DISPLAY DRIVER TIMEOUT (TDR / 0x141)"
    $rootCauseDesc = "The GPU display driver stopped responding and was recovered by Windows ($($telemetry.TdrEvents.Count) incident(s))."
    $rootCauseGuidance = "Clean reinstall your graphics driver using AMD Clean Utility or DDU. Disable GPU hardware scheduling or aggressive overclocks if crashes persist."
    $rootCauseSeverity = "Critical"
} elseif ($telemetry.KernelBugChecks.Count -gt 0) {
    $firstBc = $telemetry.KernelBugChecks[0]
    $rootCauseTitle = "KERNEL BUGCHECK BSOD ($($firstBc.Code))"
    $rootCauseDesc = "$($firstBc.Meaning) - $($firstBc.Message)"
    $rootCauseGuidance = "A kernel driver caused a fatal system fault. Check Tier 4 hardware devices for missing or uninstalled drivers."
    $rootCauseSeverity = "Critical"
} elseif ($telemetry.WheaErrors.Count -gt 0) {
    $firstWhea = $telemetry.WheaErrors[0]
    $rootCauseTitle = "WHEA HARDWARE ARCHITECTURE ERROR (Event $($firstWhea.Id))"
    $rootCauseDesc = "A fatal or corrected hardware exception was reported by the CPU/motherboard hardware subsystem ($($firstWhea.Message))."
    $rootCauseGuidance = "This indicates hardware or bus instability (CPU undervolt, unstable memory EXPO/XMP, or overheating). Disable CPU Curve Optimizer or RAM overclocks to restore baseline stability."
    $rootCauseSeverity = "Critical"
} elseif ($telemetry.AbruptReboots.Count -gt 0 -and ($telemetry.AbruptReboots | Where-Object { $_.BugcheckCode -eq 0 })) {
    $rootCauseTitle = "DIRTY POWER RESET / INSTANT BLACK SCREEN (Event 41 BugcheckCode 0)"
    $rootCauseDesc = "The system lost power or restarted abruptly without generating a BugCheck crash dump ($($telemetry.AbruptReboots.Count) incident(s))."
    $rootCauseGuidance = "When occurring during gaming or 3D load, this typically points to PSU transient spike trips (GPU power draw exceeding PSU peak wattage), loose 12VHPWR/PCIe 8-pin power cables, or aggressive GPU power limits."
    $rootCauseSeverity = "Warning"
} elseif ($pnpIssues.Count -gt 0) {
    $rootCauseTitle = "HARDWARE DEVICE ERRORS / MISSING DRIVERS"
    $rootCauseDesc = "$($pnpIssues.Count) device(s) are reporting errors or missing drivers in Windows Device Manager."
    $rootCauseGuidance = "Install official motherboard chipset drivers and check Device Manager for yellow exclamation marks."
    $rootCauseSeverity = "Warning"
} elseif ($telemetry.FastStartup.FastStartupEnabled -and $telemetry.AbruptReboots.Count -gt 0) {
    $rootCauseTitle = "ABRUPT REBOOT WITH FAST STARTUP ENABLED"
    $rootCauseDesc = "The system experienced unexpected reboots while Windows Fast Startup was enabled."
    $rootCauseGuidance = "Disable Windows Fast Startup (Control Panel -> Power Options -> Choose what the power buttons do -> Turn off Fast Startup) to ensure clean cold reboots."
    $rootCauseSeverity = "Warning"
}

if (-not $Quiet) {
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "  EXECUTIVE ROOT CAUSE SUMMARY & GUIDANCE" -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host ""
    $color = if ($rootCauseSeverity -eq "Critical") { [ConsoleColor]::Red } elseif ($rootCauseSeverity -eq "Warning") { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }
    Write-Host "  [ $rootCauseTitle ]" -ForegroundColor $color
    Write-Host "  $rootCauseDesc" -ForegroundColor White
    Write-Host ""
    Write-Host "  [ ACTIONABLE GUIDANCE ]:" -ForegroundColor Green
    Write-Host "  * $rootCauseGuidance" -ForegroundColor White
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host "  DIAGNOSTIC REPORT COMPLETE" -ForegroundColor Cyan
    Write-Host "========================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Compile Report Object
$reportObject = [PSCustomObject]@{
    GeneratedAt          = Get-Date
    HoursScanned         = $Hours
    RootCauseTitle       = $rootCauseTitle
    RootCauseDescription = $rootCauseDesc
    RootCauseGuidance    = $rootCauseGuidance
    RootCauseSeverity    = $rootCauseSeverity
    Dumps                = @($parsedDumps)
    ZombieProcesses      = @($zombieProcesses)
    EngineLogs           = @($engineLogs)
    SteamLogs            = @($steamLogs)
    SystemTelemetry      = $telemetry
    HardwareHealth       = [PSCustomObject]@{
        Gpus             = @($gpuHealth.Gpus)
        DualGpuConflict  = $gpuHealth.DualGpuConflict
        PnpIssues        = @($pnpIssues)
        NetworkAdapters  = @($netHealth)
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
    $reportObject | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonFile -Encoding UTF8
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

return $reportObject
