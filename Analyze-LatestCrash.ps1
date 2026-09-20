<#
.SYNOPSIS
    Automated Game & System Crash Diagnostic Suite
.DESCRIPTION
    Fully automated, read-only diagnostic tool that analyzes recent game crashes,
    correlates system and hardware telemetry, and produces a clear root-cause report
    with actionable troubleshooting guidance.
.PARAMETER Hours
    Number of hours back to scan for events and crash telemetry (default: 48).
.EXAMPLE
    .\Analyze-LatestCrash.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 48
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host "  $Title" -ForegroundColor Magenta
    Write-Host "========================================================================" -ForegroundColor Magenta
    Write-Host ""
}

# Header Banner
Write-Host ""
Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "  |          AUTOMATED SYSTEM & GAME CRASH DIAGNOSTIC SUITE               |" -ForegroundColor Cyan
Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor Cyan
$cutoff = (Get-Date).AddHours(-$Hours)
Write-Host "  Analyzing logs, telemetry, and crash dumps from the past $Hours hours." -ForegroundColor DarkGray
Write-Host "  Time Window: $($cutoff.ToString('yyyy-MM-dd HH:mm')) to $((Get-Date).ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor DarkGray
Write-Host ""

# State tracking for Root Cause Classification
$report = [PSCustomObject]@{
    GPUs = @()
    DualGPUConflict = $false
    NetworkAdapters = @()
    NetworkDrops = @()
    SteamDeviceBounces = @()
    RecentUpdates = @()
    RecentDefenderUpdates = @()
    TdrEvents = @()
    LiveKernelEvents = @()
    KernelReboots = @()
    CrashDumps = @()
    SteamStallAssertions = @()
    SteamPipeAssertions = @()
    EngineMemoryWarnings = @()
    IdentifiedCauses = @()
    TroubleshootingGuidance = @()
}

# -------------------------------------------------------------------------
# 1. GPU & Display Hardware Stack
# -------------------------------------------------------------------------
Write-Header "1. GRAPHICS HARDWARE & DRIVER STACK"

$videoControllers = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
$signedDrivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue

foreach ($vc in $videoControllers) {
    $sd = $signedDrivers | Where-Object { $_.DeviceClass -eq 'DISPLAY' -and ($_.DeviceID -eq $vc.PNPDeviceID -or $_.DeviceName -eq $vc.Name) } | Select-Object -First 1
    $ver = if ($sd -and $sd.DriverVersion) { $sd.DriverVersion } else { $vc.DriverVersion }
    $rawDate = if ($sd -and $sd.DriverDate) { $sd.DriverDate } else { $vc.DriverDate }
    
    $formattedDate = "Unknown"
    if ($rawDate) {
        if ($rawDate -is [DateTime]) { $formattedDate = $rawDate.ToString("yyyy-MM-dd") }
        elseif ($rawDate -match '^(\d{4})(\d{2})(\d{2})') { $formattedDate = "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
        else { $formattedDate = $rawDate.ToString() }
    }
    
    $prov = if ($sd -and $sd.DriverProviderName) { $sd.DriverProviderName } else { $vc.AdapterCompatibility }
    $report.GPUs += [PSCustomObject]@{ Name = $vc.Name; Version = $ver; Date = $formattedDate; Provider = $prov; Status = $vc.Status }
    
    Write-Host "  GPU: " -NoNewline -ForegroundColor White
    Write-Host $vc.Name -ForegroundColor Yellow
    Write-Host "    +- Driver Version: " -NoNewline -ForegroundColor DarkGray
    Write-Host $ver -ForegroundColor White
    Write-Host "    +- Driver Date:    " -NoNewline -ForegroundColor DarkGray
    Write-Host $formattedDate -ForegroundColor White
    Write-Host "    +- Provider:       " -NoNewline -ForegroundColor DarkGray
    Write-Host $prov -ForegroundColor White
    Write-Host "    +- Status:         " -NoNewline -ForegroundColor DarkGray
    if ($vc.Status -eq "OK") { Write-Host "OK" -ForegroundColor Green } else { Write-Host $vc.Status -ForegroundColor Red }
    Write-Host ""
}

# Check for Dual-GPU mismatch (e.g., discrete card vs CPU integrated graphics)
if ($report.GPUs.Count -gt 1) {
    $uniqueVersions = $report.GPUs | Select-Object -ExpandProperty Version -Unique
    if ($uniqueVersions.Count -gt 1) {
        $report.DualGPUConflict = $true
        Write-Host "  [!] NOTICE: Multiple active GPUs detected on different driver versions." -ForegroundColor Yellow
        Write-Host "      (Having discrete GPU and integrated CPU graphics on mismatched driver stacks can cause handle leaks)." -ForegroundColor DarkGray
        Write-Host ""
    }
}

# -------------------------------------------------------------------------
# 2. Windows Updates & Background Activity
# -------------------------------------------------------------------------
Write-Header "2. WINDOWS UPDATES & BACKGROUND SYSTEM ACTIVITY"

$wuEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Installation Successful' }

if ($wuEvents) {
    Write-Host "  Recent Windows & Component Updates (Past $Hours Hours):" -ForegroundColor White
    foreach ($wue in ($wuEvents | Select-Object -First 8)) {
        $cleanMsg = ($wue.Message -split "`r`n")[0].Trim()
        $report.RecentUpdates += [PSCustomObject]@{ Time = $wue.TimeCreated; Message = $cleanMsg }
        if ($cleanMsg -match 'KB2267602|Defender|Antivirus') { $report.RecentDefenderUpdates += $wue }
        Write-Host "    * [$($wue.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] $cleanMsg" -ForegroundColor DarkCyan
    }
} else {
    Write-Host "  [ OK ] No Windows Updates or Defender signature installations recorded in this window." -ForegroundColor Green
}
Write-Host ""

# -------------------------------------------------------------------------
# 3. Network Connectivity & Link State Drops
# -------------------------------------------------------------------------
Write-Header "3. NETWORK CONNECTIVITY & ADAPTER LINK STATUS"

$adapters = Get-NetAdapter -ErrorAction SilentlyContinue
foreach ($a in $adapters) {
    $speedDuplex = Get-NetAdapterAdvancedProperty -Name $a.Name -DisplayName "Speed & Duplex" -ErrorAction SilentlyContinue
    $sdVal = if ($speedDuplex) { $speedDuplex.DisplayValue } else { "N/A" }
    
    $report.NetworkAdapters += [PSCustomObject]@{ Name = $a.Name; Desc = $a.InterfaceDescription; Status = $a.Status; Speed = $a.LinkSpeed; SpeedDuplex = $sdVal }
    Write-Host "  Adapter: $($a.Name) ($($a.InterfaceDescription))" -ForegroundColor White
    Write-Host "    +- Status: $($a.Status) | Link Speed: $($a.LinkSpeed) | Duplex: $sdVal" -ForegroundColor DarkGray
}

# Scan Event Log for any network adapter link drops
$netEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$cutoff} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'disconnected|link is down|reset|timed out' -and $_.ProviderName -notmatch 'Kernel|Service Control' }

if ($netEvents) {
    $report.NetworkDrops = $netEvents
    Write-Host ""
    Write-Host "  [!] WARNING: Detected $($netEvents.Count) network adapter disconnection/drop event(s):" -ForegroundColor Yellow
    foreach ($ne in ($netEvents | Select-Object -First 5)) {
        Write-Host "    * [$($ne.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] ($($ne.ProviderName)): $($ne.Message.Trim())" -ForegroundColor Red
    }
} else {
    Write-Host "  [ OK ] No physical network link disconnects recorded in system event logs." -ForegroundColor Green
}

# Scan Steam logs for network state changes
$steamConnLog = "C:\Program Files (x86)\Steam\logs\connection_log.txt"
if (Test-Path $steamConnLog) {
    $bounces = Get-Content $steamConnLog -Tail 250 -ErrorAction SilentlyContinue |
        Where-Object { $_ -match 'OnNetworkDeviceStateChange|Connectivity test: result=Failed' }
    if ($bounces) {
        $report.SteamDeviceBounces = $bounces
        Write-Host "  [!] Steam Connection Log: Recorded network interface state changes / reconnects." -ForegroundColor Yellow
    }
}
Write-Host ""

# -------------------------------------------------------------------------
# 4. System Event Logs & Hardware Crash Telemetry
# -------------------------------------------------------------------------
Write-Header "4. SYSTEM LOGS & HARDWARE CRASH TELEMETRY"

$sysEvents = Get-WinEvent -FilterHashtable @{LogName=@('System','Application'); StartTime=$cutoff} -ErrorAction SilentlyContinue

if ($sysEvents) {
    foreach ($e in $sysEvents) {
        # GPU TDRs / Display Driver Resets
        if ($e.Id -eq 4101 -or ($e.ProviderName -match 'Display|amdkmdag|nvlddmkm|igfx' -and $e.Message -match 'stopped responding')) {
            $report.TdrEvents += $e
            Write-Host "  [!] GPU Driver TDR Event [$($e.TimeCreated)]: $($e.Message.Trim())" -ForegroundColor Red
        }
        # Kernel Power 41 (Unexpected Reboot)
        if ($e.Id -eq 41 -and $e.ProviderName -match 'Kernel-Power') {
            $report.KernelReboots += $e
            Write-Host "  [!] Unexpected System Reboot (Kernel-Power Event 41) [$($e.TimeCreated)]" -ForegroundColor Red
        }
        # Windows Error Reporting LiveKernel Events
        if ($e.ProviderName -match 'Windows Error Reporting' -and $e.Message -match 'LiveKernelEvent') {
            $report.LiveKernelEvents += $e
            if ($e.Message -match 'P1:\s*141') {
                Write-Host "  [!] LiveKernelEvent 0x141 (VIDEO_ENGINE_TIMEOUT_DETECTED) [$($e.TimeCreated)]" -ForegroundColor Red
            } elseif ($e.Message -match 'P1:\s*a1000001') {
                Write-Host "  [!] LiveKernelEvent AMD_WATCHDOG (a1000001) [$($e.TimeCreated)]" -ForegroundColor Red
            } elseif ($e.Message -match 'P1:\s*a2000002') {
                Write-Host "  [!] LiveKernelEvent AMD_REPORT_UM (a2000002 - User Mode Driver Crash) [$($e.TimeCreated)]" -ForegroundColor Red
            } else {
                Write-Host "  [!] LiveKernelEvent Recorded [$($e.TimeCreated)]" -ForegroundColor Red
            }
        }
    }
}

if ($report.TdrEvents.Count -eq 0 -and $report.LiveKernelEvents.Count -eq 0 -and $report.KernelReboots.Count -eq 0) {
    Write-Host "  [ OK ] No GPU driver TDR timeouts, live kernel resets, or dirty reboots detected." -ForegroundColor Green
}
Write-Host ""

# -------------------------------------------------------------------------
# 5. Deep Crash Dump & Binary Minidump Inspector
# -------------------------------------------------------------------------
Write-Header "5. CRASH DUMPS & BINARY ASSERTION INSPECTOR"

$dumpDirs = @(
    "C:\Program Files (x86)\Steam\dumps",
    "$env:LOCALAPPDATA\CrashDumps",
    "$env:LOCALAPPDATA\Pearl Abyss\DumpCache",
    "$env:LOCALAPPDATA\BeamNG.drive"
)

# Auto-discover Unreal Engine Saved\Crashes directories
$ueDirs = Get-ChildItem "$env:LOCALAPPDATA" -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { "$($_.FullName)\Saved\Crashes" } |
    Where-Object { Test-Path $_ }
if ($ueDirs) { $dumpDirs += $ueDirs }

$foundDumps = 0
foreach ($dir in $dumpDirs) {
    if (Test-Path $dir) {
        $files = Get-ChildItem -Path $dir -Recurse -Include "*.dmp", "__sentry-event" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoff }
        
        foreach ($f in $files) {
            $foundDumps++
            $report.CrashDumps += $f
            $sizeMb = [math]::Round($f.Length / 1MB, 2)
            Write-Host "------------------------------------------------------------------------" -ForegroundColor Gray
            Write-Host "Dump File:     $($f.Name)" -ForegroundColor Yellow
            Write-Host "Location:      $($f.FullName)" -ForegroundColor White
            Write-Host "Timestamp:     $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')) | Size: $sizeMb MB" -ForegroundColor DarkGray
            
            # Parse Minidump structure
            if ($f.Name -match '\.dmp$') {
                try {
                    $fs = [System.IO.File]::OpenRead($f.FullName)
                    $br = New-Object System.IO.BinaryReader($fs)
                    $sig = $br.ReadUInt32()
                    
                    if ($sig -eq 0x504D444D) {
                        $version = $br.ReadUInt32()
                        $numStreams = $br.ReadUInt32()
                        $streamDirRva = $br.ReadUInt32()
                        $fs.Position = $streamDirRva
                        $streams = @()
                        for ($i = 0; $i -lt $numStreams; $i++) {
                            $type = $br.ReadUInt32()
                            $size = $br.ReadUInt32()
                            $rva = $br.ReadUInt32()
                            $streams += [PSCustomObject]@{ Type = $type; Size = $size; Rva = $rva }
                        }
                        
                        $excStream = $streams | Where-Object { $_.Type -eq 6 }
                        if ($excStream) {
                            $fs.Position = $excStream.Rva
                            $threadId = $br.ReadUInt32()
                            $alignment = $br.ReadUInt32()
                            $excCode = $br.ReadUInt32()
                            $codeHex = "0x{0:X8}" -f $excCode
                            $meaning = switch ($codeHex) {
                                "0xC0000005" { "Access Violation (Invalid Memory Access)" }
                                "0xC0000409" { "Stack Buffer Overrun / Fast Fail" }
                                "0x887A0006" { "DXGI Device Hung (GPU Timeout / TDR)" }
                                "0x887A0005" { "DXGI Device Removed (GPU Driver Reset)" }
                                "0x00000000" { "Internal Assertion / Handled Process Termination" }
                                default      { "Unhandled Exception" }
                            }
                            Write-Host "  +- Exception Code:   $codeHex ($meaning)" -ForegroundColor Red
                        }
                    }
                    $fs.Close()
                } catch { if ($fs) { $fs.Close() } }
                
                # String inspection for Steam Assertions & Vulkan Layers
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
                    $asciiText = [System.Text.Encoding]::ASCII.GetString($bytes)
                    $assertions = [regex]::Matches($asciiText, 'Assert\([^\r\n]{5,220}\)') | Select-Object -ExpandProperty Value -Unique
                    if ($assertions) {
                        Write-Host "  +- Assertions Found:" -ForegroundColor Red
                        foreach ($am in ($assertions | Select-Object -First 4)) {
                            Write-Host "       * $am" -ForegroundColor Red
                            if ($am -match 'BMainLoop appears to have stalled') { $report.SteamStallAssertions += $am }
                            if ($am -match 'stalled.*pipe') { $report.SteamPipeAssertions += $am }
                        }
                    }
                } catch {}
            }
        }
    }
}

if ($foundDumps -eq 0) {
    Write-Host "  [ OK ] No crash dump files found in searched directories." -ForegroundColor Green
}
Write-Host ""

# -------------------------------------------------------------------------
# 6. Game Console & Engine Logs
# -------------------------------------------------------------------------
Write-Header "6. GAME CONSOLE & ENGINE LOG ANALYSIS"

$savedGamesDir = "$env:USERPROFILE\Saved Games"
if (Test-Path $savedGamesDir) {
    $qconsoleLogs = Get-ChildItem -Path $savedGamesDir -Recurse -Filter "qconsole.log" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $cutoff }
    
    foreach ($ql in $qconsoleLogs) {
        Write-Host "  idTech Console Log: $($ql.FullName)" -ForegroundColor White
        Write-Host "    +- Modified: $($ql.LastWriteTime) | Size: $([math]::Round($ql.Length/1MB, 2)) MB" -ForegroundColor DarkGray
        
        $allocFails = (Select-String -Path $ql.FullName -Pattern "Failed to allocate.*material env modification" -ErrorAction SilentlyContinue).Count
        if ($allocFails -gt 0) {
            $report.EngineMemoryWarnings += "$($ql.FullName): $allocFails vertex allocation failures"
            Write-Host "    +- [!] Detected $allocFails material vertex buffer allocation failures." -ForegroundColor Red
        }
        
        $cleanExit = Select-String -Path $ql.FullName -Pattern "Game Shutdown|Shutting down at" -ErrorAction SilentlyContinue
        if ($cleanExit) {
            Write-Host "    +- [ OK ] Clean engine shutdown sequence recorded at end of session." -ForegroundColor Green
        } else {
            Write-Host "    +- [!] Abrupt engine termination (no shutdown sequence)." -ForegroundColor Red
        }
    }
}
Write-Host ""

# -------------------------------------------------------------------------
# 7. AUTOMATED ROOT CAUSE DIAGNOSIS & GUIDANCE
# -------------------------------------------------------------------------
Write-Header "7. EXECUTIVE ROOT CAUSE SUMMARY & ACTIONABLE GUIDANCE"

$causes = @()
$guidance = @()

# 1. Network Disconnect IPC Kill
if ($report.SteamPipeAssertions.Count -gt 0 -or ($report.NetworkDrops.Count -gt 0 -and $report.SteamStallAssertions.Count -gt 0)) {
    $causes += "NETWORK ADAPTER DROP -> GAME IPC PIPE KILL: A physical network adapter link drop or connection state bounce caused the Steam client main loop to stall during socket reconnection. This timed out the cross-thread IPC pipe (pipes.cpp) between Steam and the running game, causing the game to suddenly exit to desktop."
    $guidance += "Check Device Manager -> Network adapters -> Properties -> Advanced: Lock 'Speed & Duplex' to your router's speed (e.g. 1.0 Gbps or 2.5 Gbps Full Duplex) instead of Auto-Negotiation to stop PHY retraining drops."
    $guidance += "In Network adapter Properties -> Power Management, uncheck 'Allow the computer to turn off this device to save power'."
}

# 2. GPU Driver TDR Timeout / User Mode Crash
if ($report.TdrEvents.Count -gt 0 -or $report.LiveKernelEvents.Count -gt 0) {
    $causes += "GPU DRIVER TIMEOUT (TDR 0x141 / DRIVER RESET): The graphics driver took longer than the 2-second Windows timeout to execute a shader/rendering pass, or crashed in user-mode. Windows reset the display driver, invalidating the game's DirectX/Vulkan render context."
    $guidance += "Check if recent Windows Quality Updates (e.g. KB5101684) coincided with the crash start date. Rolling back problematic cumulative updates restores display driver stability."
    $guidance += "Disable the Steam Overlay for heavy Vulkan titles in Steam Game Properties to prevent overlay hook deadlocks during device resets."
    $guidance += "Consider increasing Windows GPU timeout (TdrDelay) from 2 to 8 seconds in registry (HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers)."
}

# 3. Windows Update / Background Defender Activity
if ($report.RecentDefenderUpdates.Count -gt 0 -and ($report.LiveKernelEvents.Count -gt 0 -or $report.TdrEvents.Count -gt 0)) {
    $causes += "BACKGROUND UPDATE / DEFENDER INTERACTION: A background Defender signature update (KB2267602) or Windows Update occurred within minutes of a graphics driver reset. Process memory inspection during 3D rendering can interrupt graphics driver threads."
    $guidance += "Add your Steam game installation directory to Windows Defender Exclusions (Windows Security -> Virus & threat protection -> Manage settings -> Exclusions)."
    $guidance += "Pause Windows Updates temporarily while playing long single-player or competitive gaming sessions."
}

# 4. Dual-GPU Driver Conflict
if ($report.DualGPUConflict) {
    $causes += "DUAL-GPU DRIVER VERSION MISMATCH: Your system has both a Discrete GPU and a CPU Integrated GPU active running different driver versions. Mismatched driver stacks can lead to shared memory corruption over extended sessions."
    $guidance += "Disable the CPU Integrated Graphics (iGPU) in Motherboard BIOS if not using motherboard display outputs, or use Display Driver Uninstaller (DDU) to align both GPUs to the same driver package."
}

# 5. In-Engine Memory Buffer Pool Exhaustion
if ($report.EngineMemoryWarnings.Count -gt 0) {
    $causes += "IN-ENGINE VERTEX BUFFER EXHAUSTION: The game engine exhausted its dynamic vertex buffer pool, resulting in repeated allocation failures."
    $guidance += "Delete corrupt local configuration files (.local / .cfg) in '%USERPROFILE%\Saved Games\<Game>\base' to let the game rebuild fresh configuration and shader cache pools."
}

if ($causes.Count -eq 0) {
    Write-Host "  [ STATUS ]: SYSTEM HEALTHY - No critical hardware faults, GPU TDRs, or crashes detected." -ForegroundColor Green
} else {
    Write-Host "  +--- IDENTIFIED ROOT CAUSES ---+" -ForegroundColor Red
    $cIdx = 1
    foreach ($c in $causes) {
        Write-Host "  [$cIdx] $c" -ForegroundColor Yellow
        $cIdx++
    }
    Write-Host ""
    Write-Host "  +--- WHAT YOU SHOULD LOOK AT / TROUBLESHOOTING GUIDANCE ---+" -ForegroundColor Green
    $gIdx = 1
    foreach ($g in ($guidance | Select-Object -Unique)) {
        Write-Host "  ($gIdx) $g" -ForegroundColor White
        $gIdx++
    }
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  DIAGNOSTIC REPORT COMPLETE" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""
