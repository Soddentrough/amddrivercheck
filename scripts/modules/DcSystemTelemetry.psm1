<#
.SYNOPSIS
    DriverCheck - System Telemetry & Event Log Correlator Module
.DESCRIPTION
    Audits Windows Fast Startup, Event Log telemetry (WHEA, GPU TDR 4101, BugChecks 1001,
    Kernel-Power 41, Unexpected Shutdowns 6008, Kernel-PnP 219, Storage I/O errors, Application Crashes 1000/1002).
#>

function Protect-DcTelemetryText {
    param([string]$Text)
    if (-not $Text) { return $Text }
    $s = $Text
    if ($env:USERPROFILE) {
        $s = $s.Replace($env:USERPROFILE, "%USERPROFILE%")
    }
    $s = $s -replace '(?i)[a-zA-Z]:\\Users\\[^\\"\r\n]+(?=\\)', '%USERPROFILE%'
    $s = $s -replace '(?i)[a-zA-Z]:\\Users\\[^\\"\r\n\s]+', '%USERPROFILE%'
    $s = $s -replace '(?i)User:\s*[^\r\n\.]+', 'User: [REDACTED]'
    return $s
}

function Get-DcBugCheckMeaning {
    param([string]$CodeHex)

    switch -Regex ($CodeHex) {
        '0x0*116' { "VIDEO_TDR_ERROR (Display Driver Timeout & Recovery Failure)" }
        '0x0*119' { "VIDEO_SCHEDULER_INTERNAL_ERROR (DirectX Graphics Kernel Watchdog)" }
        '0x0*193' { "VIDEO_DXGKRNL_LIVEDUMP (DirectX Graphics Kernel Deadlock / Watchdog Live Dump)" }
        '0x0*141' { "VIDEO_ENGINE_TDR_TIMEOUT (GPU Engine Hung & Recovered)" }
        '0x0*117' { "VIDEO_TDR_TIMEOUT_DETECTED (Display Driver Failed to Respond)" }
        '0x0*9F'  { "DRIVER_POWER_STATE_FAILURE (Driver Failed Power IRP / Sleep-Wake Deadlock)" }
        '0x0*3B'  { "SYSTEM_SERVICE_EXCEPTION (Kernel Mode Exception in Driver)" }
        '0x0*50'  { "PAGE_FAULT_IN_NONPAGED_AREA (Invalid Memory Address Referenced by Kernel/Driver)" }
        '0x0*7E'  { "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (Unhandled Exception in Kernel Driver)" }
        '0x0*124' { "WHEA_UNCORRECTABLE_ERROR (Fatal CPU/PCIe/Memory Bus Hardware Error)" }
        '0x0*D1'  { "DRIVER_IRQL_NOT_LESS_OR_EQUAL (Driver Accessing Paged Memory at High IRQL)" }
        '0x0*133' { "DPC_WATCHDOG_VIOLATION (Driver Spent Excessive Time in ISR/DPC Routine)" }
        '0x0*139' { "KERNEL_SECURITY_CHECK_FAILURE (Kernel Data Structure Corruption)" }
        '0x0*1E'  { "KMODE_EXCEPTION_NOT_HANDLED (Kernel Mode Fault)" }
        '0x0*A'   { "IRQL_NOT_LESS_OR_EQUAL (Kernel Routine Paged Memory Violation)" }
        '0x0*93'  { "INVALID_KERNEL_HANDLE (Driver Passed or Closed an Invalid Kernel Handle)" }
        default   { "Kernel BugCheck ($CodeHex)" }
    }
}

function Get-DcFastStartupStatus {
    [CmdletBinding()]
    param()

    $powerReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -ErrorAction SilentlyContinue
    $enabled = ($powerReg -and $powerReg.HiberbootEnabled -eq 1)

    return [PSCustomObject]@{
        FastStartupEnabled = $enabled
        HiberbootValue     = if ($powerReg) { $powerReg.HiberbootEnabled } else { $null }
        Description        = if ($enabled) {
            "Fast Startup is ENABLED (HiberbootEnabled = 1). Hybrid kernel state is saved to disk across shutdowns; this commonly causes recurring 0x9F power state crashes with mismatched drivers."
        } else {
            "Fast Startup is DISABLED (Clean cold boots enabled)."
        }
    }
}

function Get-DcPciePowerManagementStatus {
    [CmdletBinding()]
    param()

    $result = [PSCustomObject]@{
        SchemeName      = "Unknown"
        SchemeGuid      = $null
        ACSettingIndex  = $null
        DCSettingIndex  = $null
        ACSettingName   = "Unknown"
        DCSettingName   = "Unknown"
        IsEnabled       = $false
        IsHighRisk      = $false
        RiskExplanation = $null
    }

    try {
        $pcfg = & powercfg /query SCHEME_CURRENT 501a4d13-42af-4429-9e56-9d9c20330821 ee12f906-d277-404b-b6da-e5fa1a576df5 2>$null
        if ($pcfg) {
            foreach ($line in $pcfg) {
                if ($line -match 'Power Scheme GUID:\s*([a-f0-9\-]+)\s*\((.*?)\)') {
                    $result.SchemeGuid = $matches[1]
                    $result.SchemeName = $matches[2]
                }
                if ($line -match 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)') {
                    $result.ACSettingIndex = [convert]::ToInt32($matches[1], 16)
                }
                if ($line -match 'Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)') {
                    $result.DCSettingIndex = [convert]::ToInt32($matches[1], 16)
                }
            }
        }
    } catch { }

    # Fallback to Registry if powercfg CLI was unavailable or returned nothing
    if ($null -eq $result.ACSettingIndex) {
        try {
            $schemesReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes" -ErrorAction SilentlyContinue
            if ($schemesReg -and $schemesReg.ActivePowerScheme) {
                $result.SchemeGuid = $schemesReg.ActivePowerScheme
                $aspmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$($result.SchemeGuid)\501a4d13-42af-4429-9e56-9d9c20330821\ee12f906-d277-404b-b6da-e5fa1a576df5"
                if (Test-Path $aspmPath) {
                    $aspmReg = Get-ItemProperty -Path $aspmPath -ErrorAction SilentlyContinue
                    if ($aspmReg) {
                        $result.ACSettingIndex = $aspmReg.ACSettingIndex
                        $result.DCSettingIndex = $aspmReg.DCSettingIndex
                    }
                }
            }
        } catch { }
    }

    # Map indices to friendly names (0 = Off, 1 = Moderate, 2 = Maximum)
    $indexMap = @{
        0 = "Off"
        1 = "Moderate power savings"
        2 = "Maximum power savings"
    }

    if ($null -ne $result.ACSettingIndex) {
        $result.ACSettingName = if ($indexMap.ContainsKey($result.ACSettingIndex)) { $indexMap[$result.ACSettingIndex] } else { "Setting $($result.ACSettingIndex)" }
    }
    if ($null -ne $result.DCSettingIndex) {
        $result.DCSettingName = if ($indexMap.ContainsKey($result.DCSettingIndex)) { $indexMap[$result.DCSettingIndex] } else { "Setting $($result.DCSettingIndex)" }
    }

    # Moderate (1) or Maximum (2) enables PCIe low power states (L0s/L1) on AC power
    if ($result.ACSettingIndex -in @(1, 2)) {
        $result.IsEnabled = $true
        $result.IsHighRisk = $true
        $settingText = $result.ACSettingName
        $result.RiskExplanation = "PCI Express Link State Power Management (ASPM) is set to '$settingText' in the active '$($result.SchemeName)' power plan. When enabled, Windows puts the PCIe link between the CPU and GPU into low-power states (L0s/L1) during idle or light load. High-power modern GPUs (especially PCIe Gen 4/5) frequently suffer latency spikes or fail to wake, causing random GPU driver timeouts (TDR Event 4101 / 0x141), sleep-wake freezes, or blackouts."
    }

    return $result
}

function Get-DcGraphicsDriverSettings {
    [CmdletBinding()]
    param()

    $gfxPath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    $tdrDelay = $null
    $tdrLevel = $null
    $tdrDdiDelay = $null
    $hwSchMode = $null

    if (Test-Path $gfxPath) {
        $props = Get-ItemProperty -Path $gfxPath -ErrorAction SilentlyContinue
        if ($props) {
            $tdrDelay = $props.TdrDelay
            $tdrLevel = $props.TdrLevel
            $tdrDdiDelay = $props.TdrDdiDelay
            $hwSchMode = $props.HwSchMode
        }
    }

    $hagsStatus = switch ($hwSchMode) {
        2 { "Enabled (Hardware-Accelerated GPU Scheduling)" }
        1 { "Disabled" }
        default { "Default / Not Configured" }
    }

    $ulpsEnabled = $false
    try {
        $classKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
        if (Test-Path $classKey) {
            $subkeys = Get-ChildItem -Path $classKey -ErrorAction SilentlyContinue
            foreach ($sk in $subkeys) {
                $p = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
                if ($p -and ($p.DriverDesc -match '(?i)Radeon|AMD' -or $null -ne $p.EnableUlps) -and $p.EnableUlps -eq 1) {
                    $ulpsEnabled = $true
                    break
                }
            }
        }
    } catch {}

    return [PSCustomObject]@{
        TdrDelay      = $tdrDelay
        TdrLevel      = $tdrLevel
        TdrDdiDelay   = $tdrDdiDelay
        HwSchMode     = $hwSchMode
        HAGSStatus    = $hagsStatus
        IsUlpsEnabled = $ulpsEnabled
    }
}

function Get-DcSystemTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddHours(-48),

        [Parameter(Mandatory = $false)]
        [datetime]$EndTime = (Get-Date)
    )

    $results = [PSCustomObject]@{
        CutoffTime             = $Cutoff
        EndTime                = $EndTime
        FastStartup            = Get-DcFastStartupStatus
        PciePowerManagement    = Get-DcPciePowerManagementStatus
        GraphicsDriverSettings = Get-DcGraphicsDriverSettings
        WheaErrors             = [System.Collections.Generic.List[PSCustomObject]]::new()
        PcieWheaErrors         = [System.Collections.Generic.List[PSCustomObject]]::new()
        MemoryExhaustion       = [System.Collections.Generic.List[PSCustomObject]]::new()
        TdrEvents              = [System.Collections.Generic.List[PSCustomObject]]::new()
        KernelBugChecks        = [System.Collections.Generic.List[PSCustomObject]]::new()
        UnexpectedShutdowns    = [System.Collections.Generic.List[PSCustomObject]]::new()
        AbruptReboots          = [System.Collections.Generic.List[PSCustomObject]]::new()
        PnpDriverFailures      = [System.Collections.Generic.List[PSCustomObject]]::new()
        StorageErrors          = [System.Collections.Generic.List[PSCustomObject]]::new()
        AppCrashes             = [System.Collections.Generic.List[PSCustomObject]]::new()
        AppHangs               = [System.Collections.Generic.List[PSCustomObject]]::new()
        NetworkDrops           = [System.Collections.Generic.List[PSCustomObject]]::new()
        UdpPortExhaustions     = [System.Collections.Generic.List[PSCustomObject]]::new()
        PciDeviceResets        = [System.Collections.Generic.List[PSCustomObject]]::new()
        WlanFailovers          = [System.Collections.Generic.List[PSCustomObject]]::new()
        SleepTransitions       = [System.Collections.Generic.List[PSCustomObject]]::new()
        CpuThrottlingEvents    = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    # Query System Events within time window
    $sysFilter = @{LogName='System'; StartTime=$Cutoff}
    if ($EndTime -and $EndTime -lt (Get-Date)) { $sysFilter['EndTime'] = $EndTime }
    $sysEvents = Get-WinEvent -FilterHashtable $sysFilter -ErrorAction SilentlyContinue

    if ($sysEvents) {
        foreach ($e in $sysEvents) {
            # Sleep & Wake Transitions (Power-Troubleshooter Event 1)
            if ($e.Id -eq 1 -and $e.ProviderName -match 'Power-Troubleshooter') {
                $wakeSource = "Unknown"
                if ($e.Message -match 'Wake Source:\s*([^\r\n]+)') { $wakeSource = $Matches[1].Trim() }
                $sleepTime = $null
                if ($e.Message -match 'Sleep Time:\s*([^\r\n]+)') {
                    try { $sleepTime = [datetime]::Parse($Matches[1].Trim()) } catch {}
                }
                $results.SleepTransitions.Add([PSCustomObject]@{
                    WakeTime   = $e.TimeCreated
                    SleepTime  = $sleepTime
                    WakeSource = $wakeSource
                    Message    = "System resumed from sleep at $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) (Wake Source: $wakeSource)."
                })
            }

            # 1. WHEA Hardware Errors
            if ($e.ProviderName -match 'WHEA-Logger') {
                $isPcie = ($e.Id -eq 17 -or $e.Message -match '(?i)PCI Express|PCIe')
                $wheaObj = [PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    IsPcieError  = $isPcie
                    Message      = $e.Message.Trim()
                }
                $results.WheaErrors.Add($wheaObj)
                if ($isPcie) {
                    $results.PcieWheaErrors.Add($wheaObj)
                }
            }

            # Physical Ethernet Link Drops (Intel I225-V / Realtek / Marvell Event 27 / 32)
            if ($e.Id -in @(27, 32) -and ($e.ProviderName -match '(?i)e2f|e1d|rt64|rt68|tcpip' -or $e.Message -match '(?i)Network link is disconnected|link has been disconnected')) {
                $results.NetworkDrops.Add([PSCustomObject]@{
                    TimeCreated   = $e.TimeCreated
                    Id            = $e.Id
                    Provider      = $e.ProviderName
                    InterfaceGuid = ""
                    InterfaceName = $e.ProviderName
                    Reason        = "Hardware Link Disconnect"
                    Message       = "Ethernet link dropped by network driver ($($e.ProviderName)): $($e.Message.Trim())"
                })
            }

            # UDP Ephemeral Port Exhaustion (Tcpip Event 4266)
            if ($e.Id -eq 4266 -and $e.ProviderName -match 'Tcpip') {
                $results.UdpPortExhaustions.Add([PSCustomObject]@{
                    TimeCreated = $e.TimeCreated
                    Id          = $e.Id
                    Provider    = $e.ProviderName
                    Message     = "Global UDP ephemeral port space exhausted: $($e.Message.Trim())"
                })
            }

            # 2. GPU Driver TDR Resets (Event 4101 or display driver stop)
            if ($e.Id -eq 4101 -or ($e.ProviderName -match 'Display|amdkmdag|nvlddmkm|igfx' -and $e.Message -match 'stopped responding')) {
                $results.TdrEvents.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    Code         = "4101"
                    DumpPath     = ""
                    Meaning      = "Display Driver Stopped Responding and Successfully Recovered (Event 4101)"
                    Message      = $e.Message.Trim()
                })
            }

            # 3. Kernel BugCheck (BSOD) via EventLog / WER
            if ($e.Id -eq 1001 -and ($e.ProviderName -match 'WER-SystemErrorReporting|Microsoft-Windows-WER-SystemErrorReporting|BugCheck' -or $e.Message -match 'bugcheck')) {
                $bugcheckCode = "Unknown"
                if ($e.Message -match '0x[0-9a-fA-F]+') { $bugcheckCode = $Matches[0] }
                $results.KernelBugChecks.Add([PSCustomObject]@{
                    TimeCreated   = $e.TimeCreated
                    Id            = $e.Id
                    Provider      = $e.ProviderName
                    Code          = $bugcheckCode
                    Meaning       = Get-DcBugCheckMeaning $bugcheckCode
                    Message       = $e.Message.Trim()
                })
            }

            # 4. Unexpected Shutdowns (Event 6008)
            if ($e.Id -eq 6008) {
                $results.UnexpectedShutdowns.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    Message      = $e.Message.Trim()
                })
            }

            # 5. Abrupt Reboots (Kernel-Power Event 41)
            if ($e.Id -eq 41 -and $e.ProviderName -match 'Kernel-Power') {
                $bugCode = 0
                try {
                    $xml = [xml]$e.ToXml()
                    $bcNode = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'BugcheckCode' }
                    if ($bcNode -and $bcNode.'#text') {
                        $bugCode = [int64]$bcNode.'#text'
                    }
                } catch {}

                $msg = if ($bugCode -eq 0) {
                    "Abrupt power loss or instant freeze (BugcheckCode: 0 - Power drop, PSU transient trip, or hard lock)."
                } else {
                    ("System rebooted following BugCheck code 0x{0:X}." -f $bugCode)
                }

                $results.AbruptReboots.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    BugcheckCode = $bugCode
                    Message      = $msg
                })
            }

            # 6. Kernel-PnP Driver Load Failures (Event 219)
            if ($e.Id -eq 219 -and $e.ProviderName -match 'Kernel-PnP') {
                $results.PnpDriverFailures.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    Message      = $e.Message.Trim()
                })
            }

            # 7. Storage / Disk / NVMe Timeouts (Events 11, 15, 129, 153, 51)
            if ($e.ProviderName -match 'stornvme|disk|Ntfs|iaStor|volsnap' -and $e.LevelDisplayName -match 'Error|Critical|Warning') {
                $results.StorageErrors.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    Message      = $e.Message.Trim()
                })
            }

            # 8. CPU Firmware Thermal & VRM Throttling (Kernel-Processor-Power Event 37)
            if ($e.Id -eq 37 -and $e.ProviderName -match 'Kernel-Processor-Power') {
                $results.CpuThrottlingEvents.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    Message      = $e.Message.Trim()
                })
            }
        }
    }

    # Query Virtual Memory / Commit Limit Exhaustion (Event 2004)
    $memFilter = @{LogName='System'; ProviderName='Microsoft-Windows-Resource-Exhaustion-Detector'; Id=2004; StartTime=$Cutoff}
    if ($EndTime -and $EndTime -lt (Get-Date)) { $memFilter['EndTime'] = $EndTime }
    $memEvents = Get-WinEvent -FilterHashtable $memFilter -ErrorAction SilentlyContinue
    if (-not $memEvents) {
        $memOpFilter = @{LogName='Microsoft-Windows-Resource-Exhaustion-Detector/Operational'; Id=2004; StartTime=$Cutoff}
        if ($EndTime -and $EndTime -lt (Get-Date)) { $memOpFilter['EndTime'] = $EndTime }
        $memEvents = Get-WinEvent -FilterHashtable $memOpFilter -ErrorAction SilentlyContinue
    }
    if ($memEvents) {
        foreach ($me in ($memEvents | Select-Object -First 5)) {
            $results.MemoryExhaustion.Add([PSCustomObject]@{
                TimeCreated = $me.TimeCreated
                Id          = $me.Id
                Provider    = $me.ProviderName
                Message     = $me.Message.Trim()
            })
        }
    }

    # Query Application Events for Crashes (1000) and Hangs (1002)
    $appFilter = @{LogName='Application'; ProviderName='Application Error'; Id=1000; StartTime=$Cutoff}
    if ($EndTime -and $EndTime -lt (Get-Date)) { $appFilter['EndTime'] = $EndTime }
    $appEvents = Get-WinEvent -FilterHashtable $appFilter -ErrorAction SilentlyContinue
    if ($appEvents) {
        foreach ($ae in ($appEvents | Select-Object -First 10)) {
            $faultingApp = "Unknown"
            $faultingMod = "Unknown"
            $excCode = "Unknown"
            if ($ae.Message -match 'Faulting application name:\s*([^\r\n,]+)') { $faultingApp = $Matches[1].Trim() }
            if ($ae.Message -match 'Faulting module name:\s*([^\r\n,]+)') { $faultingMod = $Matches[1].Trim() }
            if ($ae.Message -match 'Exception code:\s*(0x[0-9a-fA-F]+)') { $excCode = $Matches[1].Trim() }

            $results.AppCrashes.Add([PSCustomObject]@{
                TimeCreated     = $ae.TimeCreated
                Application     = $faultingApp
                FaultingModule  = $faultingMod
                ExceptionCode   = $excCode
                ExceptionMeaning= Get-DcBugCheckMeaning $excCode
                Message         = (Protect-DcTelemetryText $ae.Message.Trim())
            })
        }
    }

    $hangFilter = @{LogName='Application'; ProviderName='Application Hang'; Id=1002; StartTime=$Cutoff}
    if ($EndTime -and $EndTime -lt (Get-Date)) { $hangFilter['EndTime'] = $EndTime }
    $appHangs = Get-WinEvent -FilterHashtable $hangFilter -ErrorAction SilentlyContinue
    if ($appHangs) {
        foreach ($ah in ($appHangs | Select-Object -First 5)) {
            $hangApp = "Unknown"
            if ($ah.Message -match 'The program\s*([^\r\n]+?)\s*version') { $hangApp = $Matches[1].Trim() }
            $results.AppHangs.Add([PSCustomObject]@{
                TimeCreated = $ah.TimeCreated
                Application = $hangApp
                Message     = (Protect-DcTelemetryText $ah.Message.Trim())
            })
        }
    }

    # Query Application Events for LiveKernelEvent TDRs & AMD Watchdog Hangs (Event 1001)
    $werFilter = @{LogName='Application'; ProviderName='Windows Error Reporting'; Id=1001; StartTime=$Cutoff}
    if ($EndTime -and $EndTime -lt (Get-Date)) { $werFilter['EndTime'] = $EndTime }
    $werLiveEvents = Get-WinEvent -FilterHashtable $werFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'LiveKernelEvent' }
    if ($werLiveEvents) {
        foreach ($we in $werLiveEvents) {
            $p1 = ""
            if ($we.Message -match 'P1:\s*([a-fA-F0-9]+)') { $p1 = $Matches[1].ToLower() }

            if ($p1 -in @('141', '117', '193', 'a1000001', 'a2000002', '1b8', '1a8')) {
                $attachedFile = ""
                $dumpTime = $we.TimeCreated
                if ($we.Message -match '(?s)Attached files:\s*(?<block>.+?)(?:\r?\n\s*\r?\n|\r?\nThese files may be available|\z)') {
                    $blockText = $Matches['block']
                    $candidateLines = @(
                        $blockText -split '\r?\n' |
                            ForEach-Object { $_.Trim() } |
                            Where-Object { $_ -and $_ -match '[\\/]' }
                    )
                    $bestPath = $candidateLines | Where-Object { $_ -match '(?i)\.(dmp|wer|mdmp)$' } | Select-Object -First 1
                    if (-not $bestPath -and $candidateLines.Count -gt 0) {
                        $bestPath = $candidateLines[0]
                    }
                    if ($bestPath) {
                        $attachedFile = Protect-DcTelemetryText $bestPath
                        if ($attachedFile -match '(?<year>\d{4})(?<month>\d{2})(?<day>\d{2})-(?<hour>\d{2})(?<min>\d{2})') {
                            try {
                                $dumpTime = [datetime]::new(
                                    [int]$Matches['year'], [int]$Matches['month'], [int]$Matches['day'],
                                    [int]$Matches['hour'], [int]$Matches['min'], 0
                                )
                            } catch {}
                        }
                    }
                }

                if ($dumpTime -ge $Cutoff -and $dumpTime -le $EndTime) {
                    $meaning = switch ($p1) {
                        '141'      { "LiveKernelEvent 0x141 (VIDEO_ENGINE_TDR_TIMEOUT - GPU Engine Hung & Recovered)" }
                        '117'      { "LiveKernelEvent 0x117 (VIDEO_TDR_TIMEOUT_DETECTED - Display Driver Failed to Respond)" }
                        '193'      {
                            if ($we.Message -match 'P2:\s*(?:0x)?0*810\b') {
                                "LiveKernelEvent 0x193 (VIDEO_DXGKRNL_LIVEDUMP - DirectX Graphics Kernel Deadlock / Watchdog [ProcessDeadlockThread (0x810)])"
                            } else {
                                "LiveKernelEvent 0x193 (VIDEO_DXGKRNL_LIVEDUMP - DirectX Graphics Kernel Deadlock / Watchdog)"
                            }
                        }
                        'a1000001' { "LiveKernelEvent 0xA1000001 (AMD_WATCHDOG - AMD Driver Hardware Hang & Watchdog Reset)" }
                        'a2000002' { "LiveKernelEvent 0xA2000002 (AMD_REPORT_UM - AMD User-Mode Driver Recovery)" }
                        default    { "LiveKernelEvent 0x$p1 (GPU Watchdog Live Dump)" }
                    }

                    $existing = @($results.TdrEvents | Where-Object { [math]::Abs(($_.TimeCreated - $dumpTime).TotalSeconds) -lt 10 -and $_.Code -eq $p1 })
                    if ($existing.Count -eq 0) {
                        $results.TdrEvents.Add([PSCustomObject]@{
                            TimeCreated  = $dumpTime
                            Id           = 1001
                            Provider     = "Windows Error Reporting (LiveKernelEvent)"
                            Code         = $p1
                            DumpPath     = $attachedFile
                            Meaning      = $meaning
                            Message      = "$meaning [Dump: $attachedFile]"
                        })
                    }
                }
            }
        }
    }

    # Cache network adapters for GUID resolution
    $adaptersByGuid = @{}
    try {
        $netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
        if ($netAdapters) {
            foreach ($na in $netAdapters) {
                if ($na.InterfaceGuid) {
                    $adaptersByGuid[$na.InterfaceGuid.ToUpper()] = "$($na.Name) ($($na.InterfaceDescription))"
                }
            }
        }
    } catch {}

    # Query Network Disconnects & Capability Drops (NCSI Event 4042)
    $ncsiEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NCSI/Operational'; StartTime=$Cutoff} -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 4042 -and ($_.Message -match 'Capability:\s*None|SuspectArpProbeFailed|SuspectDnsProbeFailed') }
    if ($ncsiEvents) {
        foreach ($ne in ($ncsiEvents | Select-Object -First 10)) {
            $reason = "Unknown"
            if ($ne.Message -match 'ChangeReason:\s*([a-zA-Z0-9]+)') { $reason = $Matches[1] }
            $ifaceGuid = "Unknown"
            if ($ne.Message -match 'Capability change on (\{[a-zA-Z0-9\-]+\})') { $ifaceGuid = $Matches[1].ToUpper() }
            $ifaceName = if ($adaptersByGuid.ContainsKey($ifaceGuid)) { $adaptersByGuid[$ifaceGuid] } else { $ifaceGuid }

            $results.NetworkDrops.Add([PSCustomObject]@{
                TimeCreated   = $ne.TimeCreated
                Id            = $ne.Id
                Provider      = "NCSI"
                InterfaceGuid = $ifaceGuid
                InterfaceName = $ifaceName
                Reason        = $reason
                Message       = "Network Internet capability dropped to None (Reason: $reason) on $ifaceName."
            })
        }
    }

    # Query WLAN AutoConfig Failovers / Reconnects (Privacy-Preserving: Redact Raw SSID)
    $wlanEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; StartTime=$Cutoff} -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in @(8000, 11000) }
    if ($wlanEvents) {
        foreach ($we in ($wlanEvents | Select-Object -First 10)) {
            $ssid = "Wi-Fi"
            if ($we.Message -match 'SSID:\s*([^\r\n]+)') { $ssid = $Matches[1].Trim() }
            # Redact personal SSID to protect physical location privacy
            $maskedSsid = if ($ssid -and $ssid -ne "Wi-Fi") { "[Redacted Wi-Fi Network]" } else { "Wi-Fi" }
            $results.WlanFailovers.Add([PSCustomObject]@{
                TimeCreated = $we.TimeCreated
                Id          = $we.Id
                Provider    = "WLAN-AutoConfig"
                SSID        = $maskedSsid
                Message     = "Wireless failover association initiated ($maskedSsid)."
            })
        }
    }

    # Query TCP/IP Ephemeral Port Exhaustion (Event 4266)
    $tcpipEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Cutoff} -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -match 'Tcpip' -and $_.Id -in @(4266, 4227, 4231) }
    if ($tcpipEvents) {
        foreach ($te in ($tcpipEvents | Select-Object -First 5)) {
            $results.NetworkDrops.Add([PSCustomObject]@{
                TimeCreated   = $te.TimeCreated
                Id            = $te.Id
                Provider      = "Tcpip"
                InterfaceGuid = ""
                InterfaceName = "Global TCP/IP"
                Reason        = "EphemeralPortExhaustion"
                Message       = $te.Message.Trim()
            })
        }
    }

    # Query PCI Operational events for hardware PDO device resets / uninitialization
    $pciEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PCI/Operational'; StartTime=$Cutoff} -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 1 -and $_.Message -match 'Begin state transition from STARTED to UNINITIALIZED' }
    if ($pciEvents) {
        foreach ($pe in ($pciEvents | Select-Object -First 5)) {
            $pdo = if ($pe.Message -match '\[PDO\]\s*\((.*?)\)') { $Matches[1] } else { "Unknown" }
            $results.PciDeviceResets.Add([PSCustomObject]@{
                TimeCreated = $pe.TimeCreated
                Id          = $pe.Id
                Provider    = "Microsoft-Windows-PCI"
                Pdo         = $pdo
                Message     = "PCI Bus Device Reset on PDO ($pdo): $($pe.Message.Trim())"
            })
        }
    }

    return $results
}

function Get-DcWerReportArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddDays(-365),

        [Parameter(Mandatory = $false)]
        [datetime]$EndTime = (Get-Date),

        [Parameter(Mandatory = $false)]
        [string[]]$CustomArchivePaths
    )

    $reports = [System.Collections.Generic.List[PSCustomObject]]::new()
    $searchDirs = [System.Collections.Generic.List[string]]::new()

    if ($CustomArchivePaths) {
        foreach ($cp in $CustomArchivePaths) {
            if (Test-Path $cp) { $searchDirs.Add($cp) }
        }
    } else {
        $progData = if ($env:ProgramData) { $env:ProgramData } else { "C:\ProgramData" }
        $sysWerDirs = @(
            (Join-Path $progData "Microsoft\Windows\WER\ReportArchive"),
            (Join-Path $progData "Microsoft\Windows\WER\ReportQueue")
        )
        foreach ($d in $sysWerDirs) {
            if (Test-Path $d) { $searchDirs.Add($d) }
        }
        if ($env:LOCALAPPDATA) {
            $userWerDirs = @(
                (Join-Path $env:LOCALAPPDATA "Microsoft\Windows\WER\ReportArchive"),
                (Join-Path $env:LOCALAPPDATA "Microsoft\Windows\WER\ReportQueue")
            )
            foreach ($ud in $userWerDirs) {
                if (Test-Path $ud) { $searchDirs.Add($ud) }
            }
        }
    }

    foreach ($baseDir in $searchDirs) {
        $werFiles = Get-ChildItem -Path $baseDir -Recurse -Filter "Report.wer" -File -ErrorAction SilentlyContinue
        if (-not $werFiles) { continue }

        foreach ($wf in $werFiles) {
            try {
                $parentName = if ($wf.Directory) { $wf.Directory.Name } else { "" }
                if ($parentName -and $parentName -notmatch '(?i)^(Kernel_|LiveKernel|AppCrash_|AppHang_|Critical_)') {
                    continue
                }

                $lines = Get-Content -Path $wf.FullName -ErrorAction SilentlyContinue
                if (-not $lines) { continue }

                $eventType = ""
                $friendlyName = ""
                $appName = ""
                $appPath = ""
                $eventTime = $wf.LastWriteTime
                $sigs = @{}
                $sigNames = @{}
                $loadedMods = [System.Collections.Generic.List[string]]::new()

                foreach ($line in $lines) {
                    if ($line -match '^EventType=(.+)$') {
                        $eventType = $Matches[1].Trim()
                    } elseif ($line -match '^FriendlyEventName=(.+)$') {
                        $friendlyName = $Matches[1].Trim()
                    } elseif ($line -match '^NsAppName=(.+)$' -and -not $appName) {
                        $appName = $Matches[1].Trim()
                    } elseif ($line -match '^AppName=(.+)$') {
                        $appName = $Matches[1].Trim()
                    } elseif ($line -match '^AppPath=(.+)$') {
                        $appPath = $Matches[1].Trim()
                    } elseif ($line -match '^EventTime=(\d+)$') {
                        try {
                            $ft = [int64]$Matches[1]
                            if ($ft -gt 0) {
                                $eventTime = [datetime]::FromFileTime($ft)
                            }
                        } catch {}
                    } elseif ($line -match '^Sig\[(\d+)\]\.Name=(.+)$') {
                        $sigNames[$Matches[1]] = $Matches[2].Trim()
                    } elseif ($line -match '^Sig\[(\d+)\]\.Value=(.+)$') {
                        $sigs[$Matches[1]] = (Protect-DcTelemetryText $Matches[2].Trim())
                    } elseif ($line -match '^LoadedModule\[\d+\]=(.+)$') {
                        $modVal = Protect-DcTelemetryText $Matches[1].Trim()
                        if ($modVal) { $loadedMods.Add($modVal) }
                    }
                }

                if ($eventTime -lt $Cutoff -or $eventTime -gt $EndTime) {
                    continue
                }

                $p1 = if ($sigs.ContainsKey('0')) { $sigs['0'].ToLower() } else { "" }
                $p2 = if ($sigs.ContainsKey('1')) { $sigs['1'] } else { "" }
                $p3 = if ($sigs.ContainsKey('2')) { $sigs['2'] } else { "" }
                $p4 = if ($sigs.ContainsKey('3')) { $sigs['3'] } else { "" }

                if (-not $p1 -and $parentName -match '(?i)^Kernel_([0-9a-fA-F]+)_') {
                    $p1 = $Matches[1].ToLower()
                }

                $werGpuDrvVer = $null
                if ($sigs.ContainsKey('4') -and ($p4 -match '(?i)amdkmdag|amdxc|amdhdl|atidxx|nvlddmkm|nvwgf2|igdkmd') -and ($sigs['4'] -match '^\d+\.\d+\.\d+\.\d+$')) {
                    $werGpuDrvVer = $sigs['4']
                }

                $isTdrOrGpu = (
                    ($eventType -match '(?i)LiveKernelEvent' -and $p1 -in @('141', '117', '193', 'a1000001', 'a2000002', '1b8', '1a8')) -or
                    ($parentName -match '(?i)^Kernel_(141|117|193|a1000001|a1000002|a2000002|1b8|1a8)_') -or
                    ($eventType -match '(?i)APPCRASH|BEX64' -and ($p4 -match '(?i)amdkmdag|amdxc|amdhdl|atidxx|nvlddmkm|nvwgf2|igdkmd|dxgi|d3d12|d3d11'))
                )

                $cleanReportPath = Protect-DcTelemetryText $wf.FullName
                $cleanAppPath = Protect-DcTelemetryText $appPath

                $reports.Add([PSCustomObject]@{
                    ReportPath        = $cleanReportPath
                    FolderName        = $parentName
                    Timestamp         = $eventTime
                    EventType         = $eventType
                    FriendlyEventName = $friendlyName
                    AppName           = $appName
                    AppPath           = $cleanAppPath
                    BugCheckOrCode    = $p1
                    Parameter1        = $p1
                    Parameter2        = $p2
                    Parameter3        = $p3
                    Parameter4        = $p4
                    GpuDriverVersion  = $werGpuDrvVer
                    Signatures        = $sigs
                    SignatureNames    = $sigNames
                    LoadedModules     = @($loadedMods)
                    IsTdrOrGpu        = $isTdrOrGpu
                })
            } catch {}
        }
    }

    return @($reports | Sort-Object Timestamp -Descending)
}

function Find-DcLatestIncident {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MaxLookbackDays = 30
    )

    $lookbackCutoff = (Get-Date).AddDays(-$MaxLookbackDays)
    $candidates = [System.Collections.Generic.List[PSCustomObject]]::new()

    # 1. Tier 1: Check newest crash dump file
    try {
        if (Get-Command Get-DcLatestDumpFile -ErrorAction SilentlyContinue) {
            $latestDump = Get-DcLatestDumpFile -LookbackDays $MaxLookbackDays
            if ($latestDump) {
                $candidates.Add([PSCustomObject]@{
                    Timestamp = $latestDump.LastWriteTime
                    Tier      = 1
                    Source    = "Minidump File"
                    Details   = "$($latestDump.Name) ($([math]::Round($latestDump.Length / 1MB, 2)) MB)"
                    Item      = $latestDump
                })
            }
        }
    } catch {}

    # 2. Tier 2: Check Game Engine Fatal Crash Logs
    try {
        if ($env:LOCALAPPDATA -and (Test-Path $env:LOCALAPPDATA)) {
            $ueLogDirs = Get-ChildItem "$env:LOCALAPPDATA" -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { Join-Path $_.FullName "Saved\Logs" } |
                Where-Object { Test-Path $_ }
            foreach ($dir in $ueLogDirs) {
                $recentLogs = Get-ChildItem -Path $dir -Filter "*.log" -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -ge $lookbackCutoff } |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 3
                foreach ($rl in $recentLogs) {
                    $tail = Get-Content $rl.FullName -Tail 150 -ErrorAction SilentlyContinue
                    if ($tail -match '(?i)Fatal error|DXGI_ERROR|CrashReportClient|Fatal assert') {
                        $candidates.Add([PSCustomObject]@{
                            Timestamp = $rl.LastWriteTime
                            Tier      = 2
                            Source    = "Game Engine Fatal Log"
                            Details   = "$($rl.Name) (Unreal Engine crash log)"
                            Item      = $rl
                        })
                        break
                    }
                }
            }
        }
    } catch {}

    # 3. Tier 3: Event Log Telemetry - Display Driver TDR (4101)
    try {
        $tdr = Get-WinEvent -FilterHashtable @{LogName='System'; Id=4101; StartTime=$lookbackCutoff} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($tdr) {
            $candidates.Add([PSCustomObject]@{
                Timestamp = $tdr.TimeCreated
                Tier      = 3
                Source    = "GPU Driver Timeout (TDR 4101)"
                Details   = $tdr.Message.Trim()
                Item      = $tdr
            })
        }
    } catch {}

    # 3b. Tier 3: WER LiveKernelEvent TDR (141 / 117 / 193 / a1000001 / a2000002 / 1b8 / 1a8)
    try {
        $liveEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Windows Error Reporting'; Id=1001; StartTime=$lookbackCutoff} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'LiveKernelEvent' -and $_.Message -match 'P1:\s*(141|117|193|a1000001|a2000002|1b8|1a8)\b' }
        if ($liveEvents) {
            foreach ($liveEv in $liveEvents) {
                $p1Code = if ($liveEv.Message -match 'P1:\s*([a-fA-F0-9]+)') { $Matches[1].ToLower() } else { "141" }
                $evTime = $liveEv.TimeCreated
                if ($liveEv.Message -match '(?s)Attached files:\s*(?<block>.+?)(?:\r?\n\s*\r?\n|\r?\nThese files may be available|\z)') {
                    $blockText = $Matches['block']
                    $candidateLines = @(
                        $blockText -split '\r?\n' |
                            ForEach-Object { $_.Trim() } |
                            Where-Object { $_ -and $_ -match '[\\/]' }
                    )
                    $bestPath = $candidateLines | Where-Object { $_ -match '(?i)\.(dmp|wer|mdmp)$' } | Select-Object -First 1
                    if (-not $bestPath -and $candidateLines.Count -gt 0) { $bestPath = $candidateLines[0] }
                    if ($bestPath -and $bestPath -match '(?<year>\d{4})(?<month>\d{2})(?<day>\d{2})-(?<hour>\d{2})(?<min>\d{2})') {
                        try {
                            $evTime = [datetime]::new(
                                [int]$Matches['year'], [int]$Matches['month'], [int]$Matches['day'],
                                [int]$Matches['hour'], [int]$Matches['min'], 0
                            )
                        } catch {}
                    }
                }
                if ($evTime -ge $lookbackCutoff) {
                    $candidates.Add([PSCustomObject]@{
                        Timestamp = $evTime
                        Tier      = 3
                        Source    = "GPU LiveKernelEvent TDR (0x$p1Code)"
                        Details   = "LiveKernelEvent 0x$p1Code GPU Watchdog Timeout"
                        Item      = $liveEv
                    })
                    break
                }
            }
        }
    } catch {}

    # 3c. Tier 3: WER ReportArchive TDR / Crash Reports
    try {
        $werArch = Get-DcWerReportArchive -Cutoff $lookbackCutoff | Where-Object { $_.IsTdrOrGpu } | Select-Object -First 1
        if ($werArch) {
            $candidates.Add([PSCustomObject]@{
                Timestamp = $werArch.Timestamp
                Tier      = 3
                Source    = "WER Archive GPU Timeout ($($werArch.BugCheckOrCode))"
                Details   = "$($werArch.EventType) ($($werArch.FolderName))"
                Item      = $werArch
            })
        }
    } catch {}

    # 4. Tier 3: Kernel BugCheck (Event 1001)
    try {
        $bc = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; Id=1001; StartTime=$lookbackCutoff} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($bc) {
            $bcCode = "Unknown"
            if ($bc.Message -match '0x[0-9a-fA-F]+') { $bcCode = $Matches[0] }
            $candidates.Add([PSCustomObject]@{
                Timestamp = $bc.TimeCreated
                Tier      = 3
                Source    = "Kernel BugCheck BSOD ($bcCode)"
                Details   = "$bcCode - $(Get-DcBugCheckMeaning $bcCode)"
                Item      = $bc
            })
        }
    } catch {}

    # 5. Tier 3: Kernel-Power Event 41 (Abrupt Reboot / Power Loss)
    try {
        $kp = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41; StartTime=$lookbackCutoff} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($kp) {
            $candidates.Add([PSCustomObject]@{
                Timestamp = $kp.TimeCreated
                Tier      = 3
                Source    = "Dirty Power Cut / Black Screen (Event 41)"
                Details   = "Abrupt power loss or dirty system restart (Event 41)"
                Item      = $kp
            })
        }
    } catch {}

    # 6. Tier 3: Unexpected Shutdown (Event 6008)
    try {
        $us = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='EventLog'; Id=6008; StartTime=$lookbackCutoff} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($us) {
            $candidates.Add([PSCustomObject]@{
                Timestamp = $us.TimeCreated
                Tier      = 3
                Source    = "Unexpected Shutdown (Event 6008)"
                Details   = "Previous system shutdown was unexpected."
                Item      = $us
            })
        }
    } catch {}

    # 7. Tier 3: Virtual Memory Exhaustion (Event 2004)
    try {
        $mem = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Resource-Exhaustion-Detector'; Id=2004; StartTime=$lookbackCutoff} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($mem) {
            $candidates.Add([PSCustomObject]@{
                Timestamp = $mem.TimeCreated
                Tier      = 3
                Source    = "Virtual Memory Exhaustion (Event 2004)"
                Details   = $mem.Message.Trim()
                Item      = $mem
            })
        }
    } catch {}

    # 8. Tier 3: Application Error Crash (Event 1000)
    try {
        $appErr = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Application Error'; Id=1000; StartTime=$lookbackCutoff} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($appErr) {
            $appFaultName = "Unknown"
            if ($appErr.Message -match 'Faulting application name:\s*([^\r\n,]+)') { $appFaultName = $Matches[1].Trim() }
            $candidates.Add([PSCustomObject]@{
                Timestamp = $appErr.TimeCreated
                Tier      = 3
                Source    = "Application Crash (Event 1000: $appFaultName)"
                Details   = $appErr.Message.Trim()
                Item      = $appErr
            })
        }
    } catch {}

    # 9. Tier 3: WHEA Hardware Errors
    try {
        $whea = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=$lookbackCutoff} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($whea) {
            $candidates.Add([PSCustomObject]@{
                Timestamp = $whea.TimeCreated
                Tier      = 3
                Source    = "WHEA Hardware Error (Event $($whea.Id))"
                Details   = $whea.Message.Trim()
                Item      = $whea
            })
        }
    } catch {}

    if ($candidates.Count -gt 0) {
        $latest = $candidates | Sort-Object Timestamp -Descending | Select-Object -First 1
        $now = Get-Date
        $age = $now - $latest.Timestamp
        $ageStr = if ($age.TotalMinutes -lt 60) {
            "{0:N0} minutes ago" -f [Math]::Max(1, $age.TotalMinutes)
        } elseif ($age.TotalHours -lt 48) {
            "{0:N1} hours ago" -f $age.TotalHours
        } else {
            "{0:N1} days ago" -f $age.TotalDays
        }

        $incStart = $latest.Timestamp.AddHours(-2)
        $incEnd = if ($latest.Timestamp.AddMinutes(15) -lt $now) { $latest.Timestamp.AddMinutes(15) } else { $now }

        return [PSCustomObject]@{
            HasIncident      = $true
            Timestamp        = $latest.Timestamp
            Source           = $latest.Source
            Details          = (Protect-DcTelemetryText $latest.Details)
            Tier             = $latest.Tier
            AgeDescription   = $ageStr
            IncidentStart    = $incStart
            IncidentEnd      = $incEnd
            LookbackDays     = $MaxLookbackDays
            CandidatesFound  = $candidates.Count
        }
    }

    return [PSCustomObject]@{
        HasIncident      = $false
        Timestamp        = $null
        Source           = "Clean"
        Details          = "No crash dumps, driver timeouts, BSOD bugchecks, or unexpected shutdowns recorded in the past $MaxLookbackDays days."
        Tier             = 0
        AgeDescription   = "N/A"
        IncidentStart    = (Get-Date).AddDays(-$MaxLookbackDays)
        IncidentEnd      = (Get-Date)
        LookbackDays     = $MaxLookbackDays
        CandidatesFound  = 0
    }
}

function Get-DcRegistryKeyLastWriteTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RegistryPath
    )

    try {
        if (-not ([System.Management.Automation.PSTypeName]'DcAdvapi32RegInfo').Type) {
            $sig = @'
using System;
using System.Runtime.InteropServices;

public static class DcAdvapi32RegInfo {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey, int ulOptions, int samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int RegQueryInfoKey(
        IntPtr hKey, IntPtr lpClass, IntPtr lpcchClass, IntPtr lpReserved,
        IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen,
        IntPtr lpcValues, IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen,
        IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegCloseKey(IntPtr hKey);

    public static DateTime? GetLastWriteTime(long hiveHandle, string subKey) {
        IntPtr hKey = IntPtr.Zero;
        int KEY_QUERY_VALUE = 0x0001;
        int rc = RegOpenKeyEx(new IntPtr(hiveHandle), subKey, 0, KEY_QUERY_VALUE, out hKey);
        if (rc != 0 || hKey == IntPtr.Zero) return null;
        try {
            long ft = 0;
            int qrc = RegQueryInfoKey(hKey, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft);
            if (qrc == 0 && ft > 0) {
                return DateTime.FromFileTime(ft);
            }
        } finally {
            RegCloseKey(hKey);
        }
        return null;
    }
}
'@
            Add-Type -TypeDefinition $sig -ErrorAction SilentlyContinue
        }

        if (([System.Management.Automation.PSTypeName]'DcAdvapi32RegInfo').Type) {
            $cleanPath = $RegistryPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
            $subKey = ""
            $hivePtrVal = 0
            if ($cleanPath -match '^(?i)(HKLM:|HKEY_LOCAL_MACHINE)[\\/](.+)$') {
                $hivePtrVal = -2147483646 # 0x80000002 (HKEY_LOCAL_MACHINE)
                $subKey = $Matches[2]
            } elseif ($cleanPath -match '^(?i)(HKCU:|HKEY_CURRENT_USER)[\\/](.+)$') {
                $hivePtrVal = -2147483647 # 0x80000001 (HKEY_CURRENT_USER)
                $subKey = $Matches[2]
            }
            if ($subKey -and $hivePtrVal -ne 0) {
                $dt = [DcAdvapi32RegInfo]::GetLastWriteTime($hivePtrVal, $subKey)
                if ($dt) { return [datetime]$dt }
            }
        }
    } catch {}

    return $null
}

function Get-DcSystemChangeHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddDays(-365),

        [Parameter(Mandatory = $false)]
        [string]$SetupApiLogPath,

        [Parameter(Mandatory = $false)]
        [string]$DriverStorePath
    )

    $changes = [System.Collections.Generic.List[PSCustomObject]]::new()

    # 1. GPU & Chipset Driver Install Events (Kernel-PnP Configuration & UserPnp DeviceInstall)
    try {
        $pnpConfigEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-PnP/Configuration'; Id=@(400, 410, 411); StartTime=$Cutoff} -ErrorAction SilentlyContinue
        if ($pnpConfigEvents) {
            foreach ($ev in $pnpConfigEvents) {
                $msg = if ($ev.Message) { $ev.Message } else { "" }
                if ($msg -match '(?i)display|amdkmdag|amdxc|u0\d+\.inf|c0\d+\.inf|nv_dispi|iigd_dch|VEN_1002|VEN_10DE|VEN_8086|amdgpio|amdpsp|amdi00') {
                    $drvVer = $null
                    if ($msg -match '(?i)Driver Version\s*:\s*([0-9\.]+)') { $drvVer = $Matches[1] }
                    $infName = $null
                    if ($msg -match '(?i)Driver Name\s*:\s*([^\r\n]+)') { $infName = $Matches[1].Trim() }
                    $cat = if ($msg -match '(?i)amdgpio|amdpsp|amdi00|chipset') { "ChipsetDriverUpdate" } else { "GpuDriverUpdate" }
                    $title = if ($cat -eq "GpuDriverUpdate") {
                        "GPU Display Driver Configured" + $(if ($drvVer) { " (v$drvVer)" } else { "" })
                    } else {
                        "Chipset Controller Driver Configured" + $(if ($drvVer) { " (v$drvVer)" } else { "" })
                    }
                    $changes.Add([PSCustomObject]@{
                        Timestamp = $ev.TimeCreated
                        Category  = $cat
                        Source    = "Kernel-PnP/Configuration (Event $($ev.Id))"
                        Title     = $title
                        Version   = $drvVer
                        Details   = ($msg -split '\r?\n' | Select-Object -First 3) -join ' | '
                    })
                }
            }
        }
    } catch {}

    try {
        $userPnpEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-UserPnp/DeviceInstall'; Id=@(20001, 20003); StartTime=$Cutoff} -ErrorAction SilentlyContinue
        if ($userPnpEvents) {
            foreach ($uev in $userPnpEvents) {
                $msg = if ($uev.Message) { $uev.Message } else { "" }
                if ($msg -match '(?i)amdkmdag|u0\d+\.inf|c0\d+\.inf|nv_dispi|iigd_dch|VEN_1002|VEN_10DE|amdgpio|amdpsp') {
                    $drvVer = $null
                    if ($msg -match '([0-9]{2}\.[0-9]{1,2}\.[0-9]{1,5}\.[0-9]{1,5})') { $drvVer = $Matches[1] }
                    $changes.Add([PSCustomObject]@{
                        Timestamp = $uev.TimeCreated
                        Category  = "GpuDriverUpdate"
                        Source    = "UserPnp/DeviceInstall (Event $($uev.Id))"
                        Title     = "Device Driver Package Installed" + $(if ($drvVer) { " (v$drvVer)" } else { "" })
                        Version   = $drvVer
                        Details   = ($msg -split '\r?\n' | Select-Object -First 2) -join ' | '
                    })
                }
            }
        }
    } catch {}

    # 2. Parse C:\Windows\INF\setupapi.dev.log for historical GPU / Chipset driver installs
    $setupLog = if ($SetupApiLogPath) { $SetupApiLogPath } elseif ($env:SystemRoot) { Join-Path $env:SystemRoot "INF\setupapi.dev.log" } else { $null }
    if ($setupLog -and (Test-Path $setupLog)) {
        try {
            $logLines = Get-Content -Path $setupLog -ErrorAction SilentlyContinue
            if ($logLines) {
                $currentHeader = ""
                $currentSectionTime = $null
                $currentDriverVer = $null
                $currentInfName = $null
                foreach ($line in $logLines) {
                    if ($line -match '^>>>\s+\[(?<header>Device Install[^\]]*|Driver Install[^\]]*)\]') {
                        $currentHeader = $Matches['header']
                        $currentSectionTime = $null
                        $currentDriverVer = $null
                        $currentInfName = $null
                    } elseif ($currentHeader -and $line -match '^>>>\s+Section start\s+(?<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})') {
                        try {
                            $currentSectionTime = [datetime]::ParseExact($Matches['ts'], 'yyyy/MM/dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
                        } catch {}
                    } elseif ($currentHeader -and $line -match '(?i)DriverVer\s*=\s*(?<dDate>\d{2}/\d{2}/\d{4})\s*,\s*(?<dVer>[0-9\.]+)') {
                        $currentDriverVer = $Matches['dVer']
                    } elseif ($currentHeader -and -not $currentInfName -and $line -match '(?i)\b(?<inf>(?:u0\d+|c0\d+|nv_dispi|iigd_dch|amdgpio\d*|amdpsp|amdpcidev)\.inf)\b') {
                        $currentInfName = $Matches['inf']
                    } elseif ($currentHeader -and ($line -match '^<<<\s+\[Exit status:' -or $line -match '^<<<\s+Section end')) {
                        if ($line -notmatch '(?i)FAILURE') {
                            if ($currentSectionTime -and $currentSectionTime -ge $Cutoff) {
                                $combinedCtx = "$currentHeader $currentInfName"
                                if ($combinedCtx -match '(?i)VEN_1002|VEN_10DE|VEN_8086|u0\d+\.inf|c0\d+\.inf|nv_dispi|iigd_dch|Display|Radeon|GeForce|AMDI00|amdgpio|amdpsp|amdpcidev') {
                                    $cat = if ($combinedCtx -match '(?i)AMDI00|amdgpio|amdpsp|amdpcidev|chipset') { "ChipsetDriverUpdate" } else { "GpuDriverUpdate" }
                                    $title = if ($cat -eq "GpuDriverUpdate") {
                                        "SetupAPI Display Driver Install" + $(if ($currentDriverVer) { " (v$currentDriverVer)" } else { "" })
                                    } else {
                                        "SetupAPI Chipset Driver Install" + $(if ($currentDriverVer) { " (v$currentDriverVer)" } else { "" })
                                    }
                                    $changes.Add([PSCustomObject]@{
                                        Timestamp = $currentSectionTime
                                        Category  = $cat
                                        Source    = "setupapi.dev.log"
                                        Title     = $title
                                        Version   = $currentDriverVer
                                        Details   = "$currentHeader" + $(if ($currentInfName) { " [$currentInfName]" } else { "" }) + $(if ($currentDriverVer) { " (DriverVer: $currentDriverVer)" } else { "" })
                                    })
                                }
                            }
                        }
                        if ($line -match '^<<<\s+\[Exit status:') {
                            $currentHeader = ""
                        }
                    }
                }
            }
        } catch {}
    }

    # 3. Inspect C:\Windows\System32\DriverStore\FileRepository for staged GPU & chipset packages
    $repoDir = if ($DriverStorePath) { $DriverStorePath } elseif ($env:SystemRoot) { Join-Path $env:SystemRoot "System32\DriverStore\FileRepository" } else { $null }
    if ($repoDir -and (Test-Path $repoDir)) {
        try {
            $pkgDirs = Get-ChildItem -Path $repoDir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)^(u0\d+|c0\d+|nv_dispi|iigd_dch|amdgpio\w*|amdpsp\w*|amdpcidev\w*)\.inf_amd64_' }
            foreach ($pd in $pkgDirs) {
                $pkgTime = if ($pd.CreationTime -gt $pd.LastWriteTime) { $pd.CreationTime } else { $pd.LastWriteTime }
                if ($pkgTime -ge $Cutoff) {
                    $drvVer = $null
                    $drvDate = $null
                    $infFile = Get-ChildItem -Path $pd.FullName -Filter "*.inf" -File -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($infFile) {
                        $verLine = Select-String -Path $infFile.FullName -Pattern '^\s*DriverVer\s*=\s*([0-9/\-]+)\s*,\s*([0-9\.]+)' -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($verLine -and $verLine.Matches.Count -gt 0) {
                            $drvDate = $verLine.Matches[0].Groups[1].Value.Trim()
                            $drvVer = $verLine.Matches[0].Groups[2].Value.Trim()
                        }
                    }
                    $cat = if ($pd.Name -match '(?i)^(amdgpio|amdpsp|amdpcidev)') { "ChipsetDriverUpdate" } else { "GpuDriverUpdate" }
                    $changes.Add([PSCustomObject]@{
                        Timestamp = $pkgTime
                        Category  = $cat
                        Source    = "DriverStore FileRepository ($($pd.Name))"
                        Title     = "$(if ($cat -eq 'GpuDriverUpdate') { 'GPU Driver Staged in DriverStore' } else { 'Chipset Driver Staged in DriverStore' })" + $(if ($drvVer) { " (v$drvVer)" } else { "" })
                        Version   = $drvVer
                        Details   = "Package: $($pd.Name)" + $(if ($drvVer) { " | DriverVer: $drvVer ($drvDate)" } else { "" })
                    })
                }
            }
        } catch {}
    }

    # 4. Chipset Install Date, BIOS Release Date & System Firmware Update Events
    try {
        if (Get-Command Get-DcMotherboardAndChipsetHealth -ErrorAction SilentlyContinue) {
            $mb = Get-DcMotherboardAndChipsetHealth
            if ($mb) {
                if ($mb.ChipsetInstallDate) {
                    $csDate = [datetime]::MinValue
                    $parsedOk = $false
                    if ($mb.ChipsetInstallDate -match '^(?<y>\d{4})(?<m>\d{2})(?<d>\d{2})$') {
                        try {
                            $csDate = [datetime]::new([int]$Matches['y'], [int]$Matches['m'], [int]$Matches['d'])
                            $parsedOk = $true
                        } catch {}
                    } elseif ([datetime]::TryParse("$($mb.ChipsetInstallDate)", [ref]$csDate)) {
                        $parsedOk = $true
                    }
                    if ($parsedOk -and $csDate -ge $Cutoff) {
                        $changes.Add([PSCustomObject]@{
                            Timestamp = $csDate
                            Category  = "ChipsetDriverUpdate"
                            Source    = "Registry Uninstall ($($mb.ChipsetSoftware))"
                            Title     = "Installed $($mb.ChipsetSoftware) v$($mb.ChipsetVersion)"
                            Version   = $mb.ChipsetVersion
                            Details   = "Platform chipset driver package updated to v$($mb.ChipsetVersion)."
                        })
                    }
                }
                if ($mb.BiosReleaseDate) {
                    $bDate = [datetime]::MinValue
                    if ([datetime]::TryParse("$($mb.BiosReleaseDate)", [ref]$bDate) -and $bDate -ge $Cutoff) {
                        $changes.Add([PSCustomObject]@{
                            Timestamp = $bDate
                            Category  = "BiosUpdate"
                            Source    = "SMBIOS (Win32_BIOS)"
                            Title     = "Motherboard BIOS Firmware Updated ($($mb.BiosVersion))"
                            Version   = $mb.BiosVersion
                            Details   = "Active BIOS version $($mb.BiosVersion) released on $($mb.BiosReleaseDate)."
                        })
                    }
                }
            }
        }
        $fwEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Boot'; Id=20; StartTime=$Cutoff} -ErrorAction SilentlyContinue
        if ($fwEvents) {
            foreach ($fwe in ($fwEvents | Select-Object -First 3)) {
                $changes.Add([PSCustomObject]@{
                    Timestamp = $fwe.TimeCreated
                    Category  = "BiosUpdate"
                    Source    = "Kernel-Boot (Event 20)"
                    Title     = "System Firmware / BIOS Environment Updated"
                    Version   = $null
                    Details   = $fwe.Message.Trim()
                })
            }
        }
    } catch {}

    # 5. Active Registry Mitigations & LastWriteTime
    try {
        # 5a. GraphicsDrivers (TdrDelay / TdrDdiDelay / HwSchMode / TdrLevel)
        $gfxPath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
        $gfxSettings = Get-DcGraphicsDriverSettings
        $gfxWriteTime = Get-DcRegistryKeyLastWriteTime -RegistryPath $gfxPath
        if ($gfxSettings) {
            if ($gfxSettings.TdrDelay -ge 6 -or $gfxSettings.TdrDdiDelay -ge 6) {
                $changes.Add([PSCustomObject]@{
                    Timestamp = $gfxWriteTime
                    Category  = "RegistryMitigation"
                    Source    = "Registry ($gfxPath)"
                    Title     = "GPU Watchdog Timeout Extended (TdrDelay = $($gfxSettings.TdrDelay)s)"
                    Version   = $null
                    Details   = "TdrDelay=$($gfxSettings.TdrDelay)s, TdrDdiDelay=$($gfxSettings.TdrDdiDelay)s prevents premature 2-second display wake and shader compile TDR timeouts."
                })
            }
            if ($null -ne $gfxSettings.TdrLevel -and $gfxSettings.TdrLevel -eq 0) {
                $changes.Add([PSCustomObject]@{
                    Timestamp = $gfxWriteTime
                    Category  = "RegistryMitigation"
                    Source    = "Registry ($gfxPath)"
                    Title     = "GPU TDR Recovery Detection Modified (TdrLevel = 0)"
                    Version   = $null
                    Details   = "TdrLevel=0 disables Windows GPU timeout detection and recovery."
                })
            }
            if ($gfxSettings.HwSchMode -in @(1, 2)) {
                $changes.Add([PSCustomObject]@{
                    Timestamp = $gfxWriteTime
                    Category  = "RegistryMitigation"
                    Source    = "Registry ($gfxPath)"
                    Title     = "Hardware-Accelerated GPU Scheduling Configured ($($gfxSettings.HAGSStatus))"
                    Version   = $null
                    Details   = "HwSchMode=$($gfxSettings.HwSchMode) ($($gfxSettings.HAGSStatus))."
                })
            }
        }

        # 5b. PCIe Link State Power Management (ASPM)
        $pcieStatus = Get-DcPciePowerManagementStatus
        if ($pcieStatus -and $pcieStatus.ACSettingIndex -eq 0) {
            $aspmWriteTime = $null
            if ($pcieStatus.SchemeGuid) {
                $aspmKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$($pcieStatus.SchemeGuid)\501a4d13-42af-4429-9e56-9d9c20330821\ee12f906-d277-404b-b6da-e5fa1a576df5"
                $aspmWriteTime = Get-DcRegistryKeyLastWriteTime -RegistryPath $aspmKey
            }
            $changes.Add([PSCustomObject]@{
                Timestamp = $aspmWriteTime
                Category  = "PowerMitigation"
                Source    = "Power Scheme ($($pcieStatus.SchemeName))"
                Title     = "PCIe Link State Power Management (ASPM) Disabled (Off)"
                Version   = $null
                Details   = "PCIe ASPM ACSettingIndex=0 (Off) prevents L0s/L1 bus wake latency spikes that trigger TDR 4101 / 0x141 timeouts."
            })
        }

        # 5c. Fast Startup Disabled
        $fsStatus = Get-DcFastStartupStatus
        if ($fsStatus -and $fsStatus.HiberbootValue -eq 0) {
            $pwrKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
            $pwrWriteTime = Get-DcRegistryKeyLastWriteTime -RegistryPath $pwrKey
            $changes.Add([PSCustomObject]@{
                Timestamp = $pwrWriteTime
                Category  = "PowerMitigation"
                Source    = "Registry ($pwrKey)"
                Title     = "Windows Fast Startup Disabled (HiberbootEnabled = 0)"
                Version   = $null
                Details   = "Clean cold boots enabled, preventing hybrid kernel power state corruption (BSOD 0x9F) across shutdowns."
            })
        }

        # 5d. ULPS Disabled on AMD Display Class Key
        $classKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
        if (Test-Path $classKey) {
            $subkeys = Get-ChildItem -Path $classKey -ErrorAction SilentlyContinue
            foreach ($sk in $subkeys) {
                $p = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
                if ($p -and $null -ne $p.EnableUlps -and $p.EnableUlps -eq 0) {
                    $skWriteTime = Get-DcRegistryKeyLastWriteTime -RegistryPath $sk.PSPath
                    $changes.Add([PSCustomObject]@{
                        Timestamp = $skWriteTime
                        Category  = "PowerMitigation"
                        Source    = "Registry ($($sk.PSPath))"
                        Title     = "AMD Ultra-Low Power State (ULPS) Disabled (EnableUlps = 0)"
                        Version   = $null
                        Details   = "Disabled deep-sleep ULPS on $($p.DriverDesc) ($($sk.PSChildName))."
                    })
                    break
                }
            }
        }

        # 5e. Windows Update Driver Overwrite Lock
        $dsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $dsReg = Get-ItemProperty -Path $dsPath -ErrorAction SilentlyContinue
        $wuReg = Get-ItemProperty -Path $wuPath -ErrorAction SilentlyContinue
        if (($dsReg -and $dsReg.SearchOrderConfig -eq 0) -or ($wuReg -and $wuReg.ExcludeWUDriversInQualityUpdate -eq 1)) {
            $lockTime = Get-DcRegistryKeyLastWriteTime -RegistryPath $wuPath
            if (-not $lockTime) { $lockTime = Get-DcRegistryKeyLastWriteTime -RegistryPath $dsPath }
            $changes.Add([PSCustomObject]@{
                Timestamp = $lockTime
                Category  = "DriverPolicyMitigation"
                Source    = "Registry (WindowsUpdate / DriverSearching)"
                Title     = "Windows Update Automatic Driver Overwrite Locked"
                Version   = $null
                Details   = "SearchOrderConfig=0 / ExcludeWUDriversInQualityUpdate=1 prevents Windows Update from silently downgrading GPU drivers."
            })
        }

        # 5f. Disabled Rogue Kernel Drivers
        foreach ($rogueSvc in @('inpoutx64', 'inpout32', 'WinRing0_1_2_0', 'WinRing0x64', 'ene', 'AsrOmgDrv', 'gdrv')) {
            $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$rogueSvc"
            if (Test-Path $svcPath) {
                $svcProp = Get-ItemProperty -Path $svcPath -ErrorAction SilentlyContinue
                if ($svcProp -and $svcProp.Start -eq 4) {
                    $svcTime = Get-DcRegistryKeyLastWriteTime -RegistryPath $svcPath
                    $changes.Add([PSCustomObject]@{
                        Timestamp = $svcTime
                        Category  = "KernelDriverMitigation"
                        Source    = "Registry ($svcPath)"
                        Title     = "Rogue Kernel Driver Service Disabled ($rogueSvc)"
                        Version   = $null
                        Details   = "Service '$rogueSvc' set to Start=4 (Disabled), resolving anti-cheat handle blocks and BugCheck 0x93."
                    })
                }
            }
        }

        # 5g. CRU EDID_OVERRIDE Present on Display
        $dispEnum = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"
        if (Test-Path $dispEnum) {
            $edidOverrides = Get-ChildItem -Path $dispEnum -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -eq "EDID_OVERRIDE" }
            foreach ($eo in $edidOverrides) {
                $eoTime = Get-DcRegistryKeyLastWriteTime -RegistryPath $eo.PSPath
                $changes.Add([PSCustomObject]@{
                    Timestamp = $eoTime
                    Category  = "DisplayMitigation"
                    Source    = "Registry ($($eo.PSPath))"
                    Title     = "Custom EDID Timing Override Applied (CRU EDID_OVERRIDE)"
                    Version   = $null
                    Details   = "Custom monitor timing override configured in registry, mitigating DisplayPort scaler saturation."
                })
            }
        }
    } catch {}

    # 6. Windows Quality Updates (WUA History + QuickFixEngineering) & In-Place OS Upgrades
    try {
        $wuaSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
        if ($wuaSession) {
            $wuaSearcher = $wuaSession.CreateUpdateSearcher()
            $wuaTotal = $wuaSearcher.GetTotalHistoryCount()
            if ($wuaTotal -gt 0) {
                $wuaLimit = [math]::Min(400, $wuaTotal)
                $wuaHistory = $wuaSearcher.QueryHistory(0, $wuaLimit) | Where-Object {
                    $_.Date -ge $Cutoff -and
                    $_.Title -notmatch '(?i)KB2267602|Security Intelligence Update|Definition Update for Microsoft Defender|Windows Malicious Software Removal Tool'
                }
                foreach ($wu in ($wuaHistory | Select-Object -First 25)) {
                    $isDriverWu = ($wu.Title -match '(?i)Display|Advanced Micro Devices|AMD|NVIDIA|Intel.*Graphics|System - ')
                    $wuCat = if ($isDriverWu) { "GpuDriverUpdate" } else { "WindowsUpdate" }
                    $kbMatch = if ($wu.Title -match '(KB\d+)') { $Matches[1] } elseif ($wu.Title -match '([0-9]{2}\.[0-9]{1,2}\.[0-9]{1,5}\.[0-9]{1,5})') { $Matches[1] } else { $null }
                    $changes.Add([PSCustomObject]@{
                        Timestamp = $wu.Date
                        Category  = $wuCat
                        Source    = "Windows Update Agent (WUA)"
                        Title     = "Windows Update Installed: $($wu.Title)"
                        Version   = $kbMatch
                        Details   = $wu.Title
                    })
                }
            }
        }
    } catch {}

    try {
        $hotfixes = Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue
        if ($hotfixes) {
            foreach ($hf in $hotfixes) {
                $instDate = [datetime]::MinValue
                if ($hf.InstalledOn -and [datetime]::TryParse("$($hf.InstalledOn)", [ref]$instDate)) {
                    if ($instDate -ge $Cutoff) {
                        $dupWu = $changes | Where-Object { $_.Category -eq "WindowsUpdate" -and $_.Version -eq $hf.HotFixID }
                        if (-not $dupWu) {
                            $changes.Add([PSCustomObject]@{
                                Timestamp = $instDate
                                Category  = "WindowsUpdate"
                                Source    = "Win32_QuickFixEngineering"
                                Title     = "Windows Quality Update Installed ($($hf.HotFixID))"
                                Version   = $hf.HotFixID
                                Details   = "$($hf.HotFixID): $($hf.Description)"
                            })
                        }
                    }
                }
            }
        }
    } catch {}

    try {
        $setupSubKeys = Get-ChildItem -Path "HKLM:\SYSTEM\Setup" -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^Source OS' }
        foreach ($sk in $setupSubKeys) {
            $sp = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
            $upTime = Get-DcRegistryKeyLastWriteTime -RegistryPath $sk.PSPath
            if ($upTime -and $upTime -ge $Cutoff) {
                $buildNum = if ($sp -and $sp.CurrentBuild) { $sp.CurrentBuild } else { "Unknown" }
                $changes.Add([PSCustomObject]@{
                    Timestamp = $upTime
                    Category  = "OsUpgrade"
                    Source    = "Registry ($($sk.PSChildName))"
                    Title     = "Windows In-Place OS Upgrade / Feature Update (From Build $buildNum)"
                    Version   = $buildNum
                    Details   = "OS feature upgrade recorded in $($sk.PSChildName)."
                })
            }
        }
    } catch {}

    # 7. Win32_ReliabilityRecords Installer / Driver / System Update Records
    try {
        $relUpdates = Get-CimInstance -ClassName Win32_ReliabilityRecords -Filter "EventIdentifier = 19 or SourceName = 'MsiInstaller'" -ErrorAction SilentlyContinue |
            Where-Object {
                $_.TimeGenerated -ge $Cutoff -and
                $_.Message -match '(?i)AMD|Radeon|NVIDIA|Display|Graphics|Chipset|Vulkan|DirectX|KB\d+' -and
                $_.Message -notmatch '(?i)KB2267602|Security Intelligence|Defender'
            } | Select-Object -First 25
        if ($relUpdates) {
            foreach ($ru in $relUpdates) {
                $changes.Add([PSCustomObject]@{
                    Timestamp = $ru.TimeGenerated
                    Category  = "SoftwareOrUpdateInstall"
                    Source    = "Reliability Monitor ($($ru.SourceName))"
                    Title     = "System / Driver Update Recorded ($($ru.ProductName))"
                    Version   = $null
                    Details   = (Protect-DcTelemetryText $ru.Message.Trim())
                })
            }
        }
    } catch {}

    return @($changes | Sort-Object { if ($_.Timestamp) { $_.Timestamp } else { [datetime]::MinValue } } -Descending)
}

function Find-DcResolvedIncidentHistory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$LookbackDays = 365,

        [Parameter(Mandatory = $false)]
        [int]$ClusterGapDays = 14,

        [Parameter(Mandatory = $false)]
        [double]$MinResolvedQuietDays = 7.0,

        [Parameter(Mandatory = $false)]
        [object[]]$HistoricalIncidents,

        [Parameter(Mandatory = $false)]
        [object[]]$ChangeHistory,

        [Parameter(Mandatory = $false)]
        [string]$CurrentGpuDriverVersion
    )

    $now = Get-Date
    $cutoff = $now.AddDays(-$LookbackDays)
    $allIncidents = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($PSBoundParameters.ContainsKey('HistoricalIncidents') -and $null -ne $HistoricalIncidents) {
        foreach ($inc in $HistoricalIncidents) {
            if ($inc.Timestamp -ge $cutoff) {
                $allIncidents.Add($inc)
            }
        }
    } else {
        # 1. Event Log Telemetry across LookbackDays
        try {
            $telem = Get-DcSystemTelemetry -Cutoff $cutoff -EndTime $now
            if ($telem) {
                foreach ($tdr in $telem.TdrEvents) {
                    $allIncidents.Add([PSCustomObject]@{
                        Timestamp        = $tdr.TimeCreated
                        Category         = "GpuTdrTimeout"
                        Code             = $tdr.Code
                        Source           = $tdr.Provider
                        Application      = $null
                        FaultingModule   = "Display Driver"
                        GpuDriverVersion = $null
                        Details          = $tdr.Message
                    })
                }
                foreach ($bc in $telem.KernelBugChecks) {
                    $cat = if ($bc.Code -match '0x0*(116|119)') {
                        "GpuTdrBugCheck"
                    } elseif ($bc.Code -match '0x0*9F') {
                        "PowerStateBugCheck"
                    } elseif ($bc.Code -match '0x0*93') {
                        "RogueKernelBugCheck"
                    } else {
                        "KernelBugCheck"
                    }
                    $allIncidents.Add([PSCustomObject]@{
                        Timestamp        = $bc.TimeCreated
                        Category         = $cat
                        Code             = $bc.Code
                        Source           = "WER-SystemErrorReporting"
                        Application      = "System"
                        FaultingModule   = $null
                        GpuDriverVersion = $null
                        Details          = "$($bc.Code) - $($bc.Meaning)"
                    })
                }
                foreach ($pcie in $telem.PcieWheaErrors) {
                    $allIncidents.Add([PSCustomObject]@{
                        Timestamp        = $pcie.TimeCreated
                        Category         = "PcieWheaError"
                        Code             = "WHEA-$($pcie.Id)"
                        Source           = "WHEA-Logger"
                        Application      = "System"
                        FaultingModule   = "PCI Express Root Port"
                        GpuDriverVersion = $null
                        Details          = $pcie.Message
                    })
                }
                foreach ($ac in $telem.AppCrashes) {
                    $isGpuRelated = ($ac.FaultingModule -match '(?i)amdkmdag|amdxc|amdhdl|atidxx|nvlddmkm|nvwgf2|igdkmd|dxgi|d3d12|d3d11' -or $ac.ExceptionCode -match '0x887A000[156]')
                    $allIncidents.Add([PSCustomObject]@{
                        Timestamp        = $ac.TimeCreated
                        Category         = if ($isGpuRelated) { "GraphicsAppCrash" } else { "AppCrash" }
                        Code             = $ac.ExceptionCode
                        Source           = "Application Error (Event 1000)"
                        Application      = $ac.Application
                        FaultingModule   = $ac.FaultingModule
                        GpuDriverVersion = $null
                        Details          = "Crash in $($ac.Application) (Module: $($ac.FaultingModule), Code: $($ac.ExceptionCode))"
                    })
                }
            }
        } catch {}

        # 2. WER ReportArchive & ReportQueue
        try {
            $werArchives = Get-DcWerReportArchive -Cutoff $cutoff -EndTime $now
            foreach ($wa in $werArchives) {
                if ($wa.IsTdrOrGpu -or $wa.EventType -match '(?i)LiveKernelEvent|BlueScreen') {
                    $dup = $allIncidents | Where-Object {
                        [math]::Abs(($_.Timestamp - $wa.Timestamp).TotalSeconds) -le 30 -and
                        ($_.Code -eq $wa.BugCheckOrCode -or $_.Category -match 'Tdr')
                    }
                    if (-not $dup) {
                        $allIncidents.Add([PSCustomObject]@{
                            Timestamp        = $wa.Timestamp
                            Category         = if ($wa.IsTdrOrGpu) { "GpuTdrTimeout" } else { "KernelBugCheck" }
                            Code             = if ($wa.BugCheckOrCode) { $wa.BugCheckOrCode } else { $wa.EventType }
                            Source           = "WER ReportArchive ($($wa.FolderName))"
                            Application      = $wa.AppName
                            FaultingModule   = $wa.Parameter4
                            GpuDriverVersion = $wa.GpuDriverVersion
                            Details          = "$($wa.EventType) ($($wa.BugCheckOrCode)) - $($wa.FriendlyEventName)"
                        })
                    } elseif ($wa.GpuDriverVersion) {
                        foreach ($d in $dup) {
                            if (-not $d.GpuDriverVersion) { $d.GpuDriverVersion = $wa.GpuDriverVersion }
                        }
                    }
                }
            }
        } catch {}

        # 3. Crash Dumps (Minidump & LiveKernelReports)
        try {
            if (Get-Command Get-DcCrashDumps -ErrorAction SilentlyContinue) {
                $dumps = Get-DcCrashDumps -Cutoff $cutoff -EndTime $now
                foreach ($df in $dumps) {
                    $parsed = Read-DcMinidump -Path $df.FullName
                    if ($parsed) {
                        $cat = if ($parsed.IsShaderCompiler) {
                            "ShaderCompilerCrash"
                        } elseif ($parsed.IsRogueKernelDriver) {
                            "RogueKernelCrash"
                        } elseif ($parsed.IsGraphicsCrash -or $parsed.FullName -match '(?i)LiveKernelReports|WATCHDOG') {
                            "GpuTdrTimeout"
                        } elseif ($parsed.IsKernelDump) {
                            "KernelBugCheck"
                        } else {
                            "CrashDump"
                        }
                        $allIncidents.Add([PSCustomObject]@{
                            Timestamp        = $parsed.Timestamp
                            Category         = $cat
                            Code             = if ($parsed.ExceptionCode) { $parsed.ExceptionCode } else { "MINIDUMP" }
                            Source           = "Minidump ($($parsed.FileName))"
                            Application      = $parsed.MainExecutable
                            FaultingModule   = $parsed.FaultingModule
                            GpuDriverVersion = $parsed.GpuDriverVersion
                            DriverModules    = $parsed.DriverModuleVersions
                            Details          = "Dump $($parsed.FileName): $($parsed.ExceptionCode) in $($parsed.FaultingModule)" + $(if ($parsed.GpuDriverVersion) { " [GPU Driver: v$($parsed.GpuDriverVersion)]" } else { "" })
                        })
                    }
                }
            }
        } catch {}

        # 4. Win32_ReliabilityRecords for historical Windows Hardware Errors (LiveKernelEvent 141/117/193)
        try {
            $relFaults = Get-CimInstance -ClassName Win32_ReliabilityRecords -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.TimeGenerated -ge $cutoff -and
                    ($_.ProductName -match '(?i)Windows|Hardware' -or $_.Message -match '(?i)LiveKernelEvent|141|117|193|amdkmdag|nvlddmkm|stopped responding')
                } | Select-Object -First 50
            foreach ($rf in $relFaults) {
                if ($rf.Message -match '(?i)141|117|193|a1000001|LiveKernelEvent|stopped responding') {
                    $dup = $allIncidents | Where-Object { [math]::Abs(($_.Timestamp - $rf.TimeGenerated).TotalMinutes) -le 5 }
                    if (-not $dup) {
                        $relCode = if ($rf.Message -match '(?i)\b(193|117|a1000001)\b') { $Matches[1].ToLower() } else { "141" }
                        $allIncidents.Add([PSCustomObject]@{
                            Timestamp        = $rf.TimeGenerated
                            Category         = "GpuTdrTimeout"
                            Code             = $relCode
                            Source           = "Reliability Monitor"
                            Application      = $rf.ProductName
                            FaultingModule   = "Display Driver"
                            GpuDriverVersion = $null
                            Details          = (Protect-DcTelemetryText $rf.Message.Trim())
                        })
                    }
                }
            }
        } catch {}
    }

    if ($allIncidents.Count -eq 0) {
        return [PSCustomObject]@{
            HasHistoricalIncidents = $false
            HasResolvedEpisodes    = $false
            LookbackDays           = $LookbackDays
            TotalIncidentsFound    = 0
            Episodes               = @()
            PrimaryResolvedEpisode = $null
            SystemChanges          = @()
            Summary                = "No historical timeout or crash incidents found in the past $LookbackDays days."
        }
    }

    # Sort chronologically ascending to cluster into episodes
    $sortedAsc = @($allIncidents | Sort-Object Timestamp)
    $rawClusters = [System.Collections.Generic.List[object]]::new()
    $currentCluster = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($inc in $sortedAsc) {
        if ($currentCluster.Count -eq 0) {
            $currentCluster.Add($inc)
        } else {
            $prevTime = $currentCluster[$currentCluster.Count - 1].Timestamp
            $gapDays = ($inc.Timestamp - $prevTime).TotalDays
            if ($gapDays -gt $ClusterGapDays) {
                $rawClusters.Add(@($currentCluster))
                $currentCluster = [System.Collections.Generic.List[PSCustomObject]]::new()
            }
            $currentCluster.Add($inc)
        }
    }
    if ($currentCluster.Count -gt 0) {
        $rawClusters.Add(@($currentCluster))
    }

    # Gather system changes if not explicitly passed
    $changes = if ($PSBoundParameters.ContainsKey('ChangeHistory') -and $null -ne $ChangeHistory) {
        @($ChangeHistory)
    } else {
        @(Get-DcSystemChangeHistory -Cutoff $cutoff)
    }

    # Determine active GPU driver version if not passed
    if (-not $CurrentGpuDriverVersion) {
        try {
            if (Get-Command Get-DcGpuDriverHealth -ErrorAction SilentlyContinue) {
                $gh = Get-DcGpuDriverHealth
                if ($gh -and $gh.Gpus -and $gh.Gpus.Count -gt 0) {
                    $discrete = $gh.Gpus | Where-Object { -not $_.IsGeneric } | Select-Object -First 1
                    if ($discrete) { $CurrentGpuDriverVersion = $discrete.DriverVersion }
                }
            }
        } catch {}
    }

    $episodes = [System.Collections.Generic.List[PSCustomObject]]::new()
    $epIndex = 1

    foreach ($cluster in $rawClusters) {
        $tFirst = $cluster[0].Timestamp
        $tLast = $cluster[$cluster.Count - 1].Timestamp
        $count = $cluster.Count
        $quietDays = [math]::Round(($now - $tLast).TotalDays, 1)
        $spanDays = [math]::Round(($tLast - $tFirst).TotalDays, 1)

        $meanIntervalDays = if ($count -gt 1) {
            [math]::Round(($tLast - $tFirst).TotalDays / ($count - 1), 2)
        } else {
            0.0
        }

        # Episode is considered resolved if quiet duration >= MinResolvedQuietDays
        # AND (if count > 1, quietDays >= 3 * meanIntervalDays or quietDays >= MinResolvedQuietDays)
        $isResolved = ($quietDays -ge $MinResolvedQuietDays) -and ($count -eq 1 -or $meanIntervalDays -le 0 -or $quietDays -ge ($meanIntervalDays * 2.5) -or $quietDays -ge 14)

        # Dominant symptom / category
        $dominantCatGroup = $cluster | Group-Object Category | Sort-Object Count -Descending | Select-Object -First 1
        $dominantCategory = if ($dominantCatGroup) { $dominantCatGroup.Name } else { "GpuTdrTimeout" }

        $codes = @($cluster | Where-Object { $_.Code } | Select-Object -ExpandProperty Code -Unique)
        $apps = @($cluster | Where-Object { $_.Application -and $_.Application -notin @('Unknown', 'System', 'Windows') } | Select-Object -ExpandProperty Application -Unique)
        $faultMods = @($cluster | Where-Object { $_.FaultingModule -and $_.FaultingModule -ne 'Unknown' } | Select-Object -ExpandProperty FaultingModule -Unique)

        # Historical GPU driver version during episode:
        # 1. Check minidump VS_FIXEDFILEINFO GpuDriverVersion in cluster
        $histDriverVer = ($cluster | Where-Object { $_.GpuDriverVersion } | Select-Object -Last 1).GpuDriverVersion
        # 2. Fallback: latest GPU driver update installed on or before T_last
        if (-not $histDriverVer) {
            $priorDrvChange = $changes | Where-Object {
                $_.Category -eq "GpuDriverUpdate" -and $_.Version -and $_.Timestamp -and $_.Timestamp -le $tLast
            } | Sort-Object Timestamp -Descending | Select-Object -First 1
            if ($priorDrvChange) {
                $histDriverVer = $priorDrvChange.Version
            }
        }

        # Historical root cause inference
        $histCause = switch ($dominantCategory) {
            "ShaderCompilerCrash" { "Shader Compiler Crash / Corrupt Shader Cache ($($faultMods -join ', '))" }
            "RogueKernelCrash"    { "Rogue Kernel I/O Driver Conflict ($($faultMods -join ', '))" }
            "RogueKernelBugCheck" { "Rogue Kernel I/O Driver BugCheck (0x93 INVALID_KERNEL_HANDLE)" }
            "PowerStateBugCheck"  { "Driver Power State Transition Failure (BSOD 0x9F / Fast Startup / Sleep-Wake)" }
            "PcieWheaError"       { "PCI Express Link / Bus Communication Fault (WHEA Event 17 / ASPM)" }
            "GpuTdrBugCheck"      { "Fatal GPU Display Driver Timeout BugCheck ($($codes -join ', '))" }
            "GpuTdrTimeout"       { "GPU Display Driver Watchdog Timeout (TDR $($codes -join ', '))" }
            default               { "Application / Graphics Stability Fault ($($codes -join ', '))" }
        }
        if ($histDriverVer) {
            $histCause += " on GPU Driver v$histDriverVer"
        }

        # Correlate candidate resolution changes around T_last
        # Primary inflection window: [T_last - 6 hours, T_last + 14 days]
        $windowStart = $tLast.AddHours(-6)
        $windowEnd = $tLast.AddDays(14)

        $correlatedFactors = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($ch in $changes) {
            $isTimestamped = ($null -ne $ch.Timestamp -and $ch.Timestamp -gt [datetime]::MinValue)
            $inPrimaryWindow = $false
            $afterLastTimeout = $false
            $deltaDesc = "Active mitigation (exact timestamp unrecorded)"
            $deltaHours = $null

            if ($isTimestamped) {
                $deltaSpan = $ch.Timestamp - $tLast
                $deltaHours = [math]::Round($deltaSpan.TotalHours, 1)
                $inPrimaryWindow = ($ch.Timestamp -ge $windowStart -and $ch.Timestamp -le $windowEnd)
                $afterLastTimeout = ($ch.Timestamp -ge $windowStart)

                if (-not $afterLastTimeout) {
                    # Change occurred well before the last timeout -> did not resolve the episode
                    continue
                }

                $absHours = [math]::Abs($deltaSpan.TotalHours)
                $absDays = [math]::Round([math]::Abs($deltaSpan.TotalDays), 1)
                $dirStr = if ($deltaSpan.TotalMinutes -ge 0) { "after last timeout" } else { "before last timeout" }
                $deltaDesc = if ($absHours -lt 48) {
                    "{0:+0.0;-0.0;0.0} hours ({1})" -f $deltaSpan.TotalHours, $dirStr
                } else {
                    "{0:+0.0;-0.0;0.0} days ({1})" -f $deltaSpan.TotalDays, $dirStr
                }
            }

            # Score relevance & confidence based on symptom match and timing proximity
            $symptomMatch = $false
            switch ($ch.Category) {
                "GpuDriverUpdate" {
                    if ($dominantCategory -in @("GpuTdrTimeout", "GpuTdrBugCheck", "ShaderCompilerCrash", "GraphicsAppCrash", "PowerStateBugCheck")) {
                        $symptomMatch = $true
                    }
                }
                "ChipsetDriverUpdate" {
                    if ($dominantCategory -in @("GpuTdrTimeout", "GpuTdrBugCheck", "PcieWheaError", "PowerStateBugCheck")) {
                        $symptomMatch = $true
                    }
                }
                "BiosUpdate" {
                    if ($dominantCategory -in @("GpuTdrTimeout", "PcieWheaError", "KernelBugCheck", "PowerStateBugCheck")) {
                        $symptomMatch = $true
                    }
                }
                "PowerMitigation" {
                    if ($dominantCategory -in @("GpuTdrTimeout", "GpuTdrBugCheck", "PcieWheaError", "PowerStateBugCheck")) {
                        $symptomMatch = $true
                    }
                }
                "RegistryMitigation" {
                    if ($dominantCategory -in @("GpuTdrTimeout", "GpuTdrBugCheck", "GraphicsAppCrash")) {
                        $symptomMatch = $true
                    }
                }
                "DriverPolicyMitigation" {
                    if ($dominantCategory -in @("GpuTdrTimeout", "PowerStateBugCheck", "GpuTdrBugCheck")) {
                        $symptomMatch = $true
                    }
                }
                "KernelDriverMitigation" {
                    if ($dominantCategory -in @("RogueKernelCrash", "RogueKernelBugCheck", "KernelBugCheck")) {
                        $symptomMatch = $true
                    }
                }
                "DisplayMitigation" {
                    if ($dominantCategory -in @("GpuTdrTimeout", "GraphicsAppCrash")) {
                        $symptomMatch = $true
                    }
                }
            }

            $confidence = "Contextual"
            $score = 25
            if ($inPrimaryWindow -and $symptomMatch) {
                $confidence = "High"
                $score = if ([math]::Abs($deltaHours) -le 48) { 95 } else { 85 }
            } elseif ($inPrimaryWindow) {
                $confidence = "Medium"
                $score = 65
            } elseif ($symptomMatch -and $isTimestamped -and $afterLastTimeout) {
                $confidence = "Medium"
                $score = 60
            } elseif ($symptomMatch -and -not $isTimestamped) {
                $confidence = "Medium"
                $score = 55
            }

            $correlatedFactors.Add([PSCustomObject]@{
                Timestamp       = $ch.Timestamp
                DeltaFromLast   = $deltaDesc
                DeltaHours      = $deltaHours
                Confidence      = $confidence
                Score           = $score
                Category        = $ch.Category
                Title           = $ch.Title
                Details         = $ch.Details
                Source          = $ch.Source
                Version         = $ch.Version
                InPrimaryWindow = $inPrimaryWindow
                SymptomMatch    = $symptomMatch
            })
        }

        # Check if driver version changed between historical minidump/episode and current active GPU driver
        if ($histDriverVer -and $CurrentGpuDriverVersion -and ($histDriverVer -ne $CurrentGpuDriverVersion)) {
            $alreadyHasDrvDiff = $correlatedFactors | Where-Object { $_.Category -eq "GpuDriverUpdate" -and $_.Version -eq $CurrentGpuDriverVersion }
            if (-not $alreadyHasDrvDiff) {
                $correlatedFactors.Add([PSCustomObject]@{
                    Timestamp       = $null
                    DeltaFromLast   = "Updated since last incident"
                    DeltaHours      = $null
                    Confidence      = "High"
                    Score           = 90
                    Category        = "GpuDriverUpdate"
                    Title           = "GPU Driver Updated from v$histDriverVer to v$CurrentGpuDriverVersion"
                    Details         = "Crash artifacts during the incident window loaded GPU driver v$histDriverVer, whereas the system is now running v$CurrentGpuDriverVersion."
                    Source          = "Minidump VS_FIXEDFILEINFO vs Active GPU Driver"
                    Version         = $CurrentGpuDriverVersion
                    InPrimaryWindow = $true
                    SymptomMatch    = $true
                })
            }
        }

        # Workload / single-application cessation check
        if ($apps.Count -eq 1) {
            $singleApp = $apps[0]
            $correlatedFactors.Add([PSCustomObject]@{
                Timestamp       = $tLast
                DeltaFromLast   = "0.0 hours (at last timeout)"
                DeltaHours      = 0.0
                Confidence      = "Contextual"
                Score           = 40
                Category        = "WorkloadChange"
                Title           = "Application-Specific Fault Pattern ($singleApp)"
                Details         = "All incidents in this episode were associated with '$singleApp'. A game patch, shader cache rebuild, or no longer running that workload after $($tLast.ToString('yyyy-MM-dd')) may explain why timeouts ceased."
                Source          = "Application Fault Correlation"
                Version         = $null
                InPrimaryWindow = $true
                SymptomMatch    = $false
            })
        }

        $rankedFactors = @($correlatedFactors | Sort-Object Score -Descending)

        $episodes.Add([PSCustomObject]@{
            EpisodeIndex            = $epIndex
            StartTime               = $tFirst
            EndTime                 = $tLast
            SpanDays                = $spanDays
            IncidentCount           = $count
            MeanIntervalDays        = $meanIntervalDays
            QuietDaysSinceEnd       = $quietDays
            IsResolved              = $isResolved
            DominantCategory        = $dominantCategory
            Codes                   = $codes
            Applications            = $apps
            FaultingModules         = $faultMods
            HistoricalDriverVersion = $histDriverVer
            CurrentDriverVersion    = $CurrentGpuDriverVersion
            HistoricalRootCause     = $histCause
            ResolutionFactors       = $rankedFactors
            Incidents               = $cluster
        })
        $epIndex++
    }

    $resolvedEpisodes = @($episodes | Where-Object { $_.IsResolved } | Sort-Object EndTime -Descending)
    $primaryResolved = if ($resolvedEpisodes.Count -gt 0) { $resolvedEpisodes[0] } else { $null }

    $summaryText = if ($primaryResolved) {
        $topFix = if ($primaryResolved.ResolutionFactors.Count -gt 0) {
            "$($primaryResolved.ResolutionFactors[0].Title) [$($primaryResolved.ResolutionFactors[0].Confidence) Confidence]"
        } else {
            "No explicit driver/registry change timestamped in window (likely game patch or workload change)"
        }
        "Resolved historical episode detected ($($primaryResolved.IncidentCount) incident(s) between $($primaryResolved.StartTime.ToString('yyyy-MM-dd')) and $($primaryResolved.EndTime.ToString('yyyy-MM-dd')); crash-free for $($primaryResolved.QuietDaysSinceEnd) days). Primary correlated resolution: $topFix."
    } else {
        "Found $($allIncidents.Count) incident(s) across $($episodes.Count) episode(s), but none meet the resolved quiet threshold ($MinResolvedQuietDays days)."
    }

    return [PSCustomObject]@{
        HasHistoricalIncidents = $true
        HasResolvedEpisodes    = ($resolvedEpisodes.Count -gt 0)
        LookbackDays           = $LookbackDays
        TotalIncidentsFound    = $allIncidents.Count
        Episodes               = @($episodes | Sort-Object EndTime -Descending)
        PrimaryResolvedEpisode = $primaryResolved
        SystemChanges          = $changes
        Summary                = $summaryText
    }
}

Set-Alias -Name Invoke-DcResolvedTimeoutAnalysis -Value Find-DcResolvedIncidentHistory

Export-ModuleMember -Function Get-DcFastStartupStatus, Get-DcSystemTelemetry, Get-DcBugCheckMeaning, Get-DcGraphicsDriverSettings, Get-DcPciePowerManagementStatus, Find-DcLatestIncident, Get-DcWerReportArchive, Get-DcRegistryKeyLastWriteTime, Get-DcSystemChangeHistory, Find-DcResolvedIncidentHistory, Protect-DcTelemetryText -Alias Invoke-DcResolvedTimeoutAnalysis
