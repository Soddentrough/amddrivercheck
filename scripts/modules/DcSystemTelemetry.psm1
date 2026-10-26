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

function Get-DcEventXmlData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$EventRecord
    )

    $dataMap = @{}
    if (-not $EventRecord) { return $dataMap }

    try {
        if ($EventRecord.PSObject.Methods['ToXml']) {
            $xmlText = $EventRecord.ToXml()
            if ($xmlText) {
                $xml = [xml]$xmlText
                if ($xml -and $xml.Event -and $xml.Event.EventData -and $xml.Event.EventData.Data) {
                    $idx = 0
                    foreach ($node in $xml.Event.EventData.Data) {
                        if ($node -is [string]) {
                            $dataMap["Data_$idx"] = $node
                        } elseif ($null -ne $node) {
                            $val = if ($null -ne $node.'#text') { $node.'#text' } else { "$node" }
                            if ($node.PSObject.Properties['Name'] -and $node.Name) {
                                $dataMap[$node.Name] = $val
                            } else {
                                $dataMap["Data_$idx"] = $val
                            }
                        }
                        $idx++
                    }
                }
            }
        }
    } catch {}

    return $dataMap
}

function Get-DcWinEventsTargeted {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $false)]
        [int[]]$Ids,

        [Parameter(Mandatory = $false)]
        [string]$ProviderName,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $false)]
        [datetime]$EndTime = (Get-Date),

        [Parameter(Mandatory = $false)]
        [int]$MaxEvents = 0
    )

    $collected = [System.Collections.Generic.List[object]]::new()
    $useEndTime = ($EndTime -and $EndTime -lt (Get-Date))

    if ($Ids -and $Ids.Count -gt 0) {
        # Split into batches of <= 12 IDs to avoid Windows Event Log 22-node XPath query limits
        $batchSize = 12
        for ($i = 0; $i -lt $Ids.Count; $i += $batchSize) {
            $endIdx = [math]::Min($i + $batchSize - 1, $Ids.Count - 1)
            $batchIds = @($Ids[$i..$endIdx])
            $filter = @{
                LogName   = $LogName
                Id        = $batchIds
                StartTime = $StartTime
            }
            if ($ProviderName) { $filter['ProviderName'] = $ProviderName }
            if ($useEndTime) { $filter['EndTime'] = $EndTime }

            try {
                $evts = if ($MaxEvents -gt 0) {
                    Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                } else {
                    Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
                }
                if ($evts) {
                    foreach ($ev in $evts) { $collected.Add($ev) }
                }
            } catch {}
        }
    } else {
        $filter = @{
            LogName   = $LogName
            StartTime = $StartTime
        }
        if ($ProviderName) { $filter['ProviderName'] = $ProviderName }
        if ($useEndTime) { $filter['EndTime'] = $EndTime }

        try {
            $evts = if ($MaxEvents -gt 0) {
                Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
            } else {
                Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
            }
            if ($evts) {
                foreach ($ev in $evts) { $collected.Add($ev) }
            }
        } catch {}
    }

    return @($collected | Sort-Object TimeCreated -Descending)
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

    # Query System Events within time window using targeted Event ID batches (20x faster than full-log scan)
    $targetSysIds = @(
        1, 7, 9, 11, 14, 15, 17, 18, 19, 20, 27, 32,
        33, 37, 41, 46, 47, 51, 129, 153, 154, 157, 219, 1001,
        4101, 4227, 4231, 4266, 5002, 5005, 5007, 6008, 10400
    )
    $sysEvents = Get-DcWinEventsTargeted -LogName 'System' -Ids $targetSysIds -StartTime $Cutoff -EndTime $EndTime

    if ($sysEvents) {
        foreach ($e in $sysEvents) {
            $msgText = if ($e.Message) { $e.Message.Trim() } else { "" }

            # Sleep & Wake Transitions (Power-Troubleshooter Event 1)
            if ($e.Id -eq 1 -and $e.ProviderName -match 'Power-Troubleshooter') {
                $xmlData = Get-DcEventXmlData -EventRecord $e
                $wakeSource = if ($xmlData['WakeSourceText']) { $xmlData['WakeSourceText'] } else { "Unknown" }
                if ($wakeSource -eq "Unknown" -and $msgText -match 'Wake Source:\s*([^\r\n]+)') {
                    $wakeSource = $Matches[1].Trim()
                }
                $sleepTime = $null
                if ($xmlData['SleepTime']) {
                    try { $sleepTime = [datetime]::Parse($xmlData['SleepTime']) } catch {}
                } elseif ($msgText -match 'Sleep Time:\s*([^\r\n]+)') {
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
                $isPcie = ($e.Id -eq 17 -or $msgText -match '(?i)PCI Express|PCIe')
                $wheaObj = [PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    IsPcieError  = $isPcie
                    Message      = $msgText
                }
                $results.WheaErrors.Add($wheaObj)
                if ($isPcie) {
                    $results.PcieWheaErrors.Add($wheaObj)
                }
            }

            # Physical Ethernet Link Drops (Intel I225-V / I226-V / Realtek / Marvell / NDIS Event 27, 32, 33, 10400)
            if ($e.Id -in @(27, 32, 33, 10400) -and ($e.ProviderName -match '(?i)e2f|e1d|rt64|rt68|ndis|netwtw|mtkwl' -or $msgText -match '(?i)Network link is disconnected|link has been disconnected')) {
                $results.NetworkDrops.Add([PSCustomObject]@{
                    TimeCreated   = $e.TimeCreated
                    Id            = $e.Id
                    Provider      = $e.ProviderName
                    InterfaceGuid = ""
                    InterfaceName = $e.ProviderName
                    Reason        = "Hardware Link Disconnect"
                    Message       = "Ethernet link dropped by network driver ($($e.ProviderName)): $msgText"
                })
            }

            # TCP/IP Ephemeral Port Exhaustion (Tcpip Event 4266, 4227, 4231)
            if ($e.Id -in @(4266, 4227, 4231) -and $e.ProviderName -match 'Tcpip') {
                if ($results.UdpPortExhaustions.Count -lt 10) {
                    $results.UdpPortExhaustions.Add([PSCustomObject]@{
                        TimeCreated = $e.TimeCreated
                        Id          = $e.Id
                        Provider    = $e.ProviderName
                        Message     = "Global TCP/IP dynamic port space exhausted (Event $($e.Id)): $msgText"
                    })
                }
                if ($results.NetworkDrops.Count -lt 25) {
                    $results.NetworkDrops.Add([PSCustomObject]@{
                        TimeCreated   = $e.TimeCreated
                        Id            = $e.Id
                        Provider      = "Tcpip"
                        InterfaceGuid = ""
                        InterfaceName = "Global TCP/IP"
                        Reason        = "EphemeralPortExhaustion"
                        Message       = $msgText
                    })
                }
            }

            # 2. GPU Driver TDR Resets (Event 4101 or display driver stop)
            if ($e.Id -eq 4101 -or ($e.ProviderName -match 'Display|amdkmdag|nvlddmkm|igfx' -and $msgText -match 'stopped responding')) {
                $results.TdrEvents.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    Code         = "4101"
                    DumpPath     = ""
                    Meaning      = "Display Driver Stopped Responding and Successfully Recovered (Event 4101)"
                    Message      = $msgText
                })
            }

            # 3. Kernel BugCheck (BSOD) via EventLog / WER
            if ($e.Id -eq 1001 -and ($e.ProviderName -match 'WER-SystemErrorReporting|Microsoft-Windows-WER-SystemErrorReporting|BugCheck' -or $msgText -match 'bugcheck')) {
                $xmlData = Get-DcEventXmlData -EventRecord $e
                $bugcheckCode = if ($xmlData['param1'] -and $xmlData['param1'] -match '^0x[0-9a-fA-F]+') {
                    $xmlData['param1'].Split(' ')[0].Trim()
                } elseif ($msgText -match '0x[0-9a-fA-F]+') {
                    $Matches[0]
                } else {
                    "Unknown"
                }
                $results.KernelBugChecks.Add([PSCustomObject]@{
                    TimeCreated   = $e.TimeCreated
                    Id            = $e.Id
                    Provider      = $e.ProviderName
                    Code          = $bugcheckCode
                    Meaning       = Get-DcBugCheckMeaning $bugcheckCode
                    Message       = $msgText
                })
            }

            # 4. Unexpected Shutdowns (Event 6008)
            if ($e.Id -eq 6008) {
                $results.UnexpectedShutdowns.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    Message      = $msgText
                })
            }

            # 5. Abrupt Reboots (Kernel-Power Event 41)
            if ($e.Id -eq 41 -and $e.ProviderName -match 'Kernel-Power') {
                $bugCode = 0
                $xmlData = Get-DcEventXmlData -EventRecord $e
                if ($xmlData['BugcheckCode']) {
                    try { $bugCode = [int64]$xmlData['BugcheckCode'] } catch {}
                }

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
                    Message      = $msgText
                })
            }

            # 7. Storage / Disk / NVMe Timeouts (Events 7, 9, 11, 15, 51, 129, 153, 154, 157)
            if ($e.ProviderName -match 'stornvme|disk|Ntfs|iaStor|volsnap|storahci' -and $e.LevelDisplayName -match 'Error|Critical|Warning') {
                $results.StorageErrors.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    Message      = $msgText
                })
            }

            # 8. CPU Firmware Thermal & VRM Throttling (Kernel-Processor-Power Event 37)
            if ($e.Id -eq 37 -and $e.ProviderName -match 'Kernel-Processor-Power') {
                $results.CpuThrottlingEvents.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    Message      = $msgText
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
            $xmlData = Get-DcEventXmlData -EventRecord $ae
            $faultingApp = if ($xmlData['AppName']) { $xmlData['AppName'] } elseif ($xmlData['Data_0']) { $xmlData['Data_0'] } else { "Unknown" }
            $faultingMod = if ($xmlData['ModuleName']) { $xmlData['ModuleName'] } elseif ($xmlData['Data_3']) { $xmlData['Data_3'] } else { "Unknown" }
            $excCode = if ($xmlData['ExceptionCode']) { $xmlData['ExceptionCode'] } elseif ($xmlData['Data_6']) { $xmlData['Data_6'] } else { "Unknown" }
            if ($excCode -ne "Unknown" -and $excCode -notmatch '^0x') { $excCode = "0x$excCode" }

            if ($faultingApp -eq "Unknown" -and $ae.Message -match 'Faulting application name:\s*([^\r\n,]+)') { $faultingApp = $Matches[1].Trim() }
            if ($faultingMod -eq "Unknown" -and $ae.Message -match 'Faulting module name:\s*([^\r\n,]+)') { $faultingMod = $Matches[1].Trim() }
            if ($excCode -eq "Unknown" -and $ae.Message -match 'Exception code:\s*(0x[0-9a-fA-F]+)') { $excCode = $Matches[1].Trim() }

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
            $xmlData = Get-DcEventXmlData -EventRecord $ah
            $hangApp = if ($xmlData['AppName']) { $xmlData['AppName'] } elseif ($xmlData['Data_0']) { $xmlData['Data_0'] } else { "Unknown" }
            if ($hangApp -eq "Unknown" -and $ah.Message -match 'The program\s*([^\r\n]+?)\s*version') { $hangApp = $Matches[1].Trim() }
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

    # Query Network Disconnects & Capability Drops (NCSI Event 4042 - targeted ID)
    $ncsiFilter = @{LogName='Microsoft-Windows-NCSI/Operational'; Id=4042; StartTime=$Cutoff}
    if ($EndTime -and $EndTime -lt (Get-Date)) { $ncsiFilter['EndTime'] = $EndTime }
    $ncsiEvents = Get-WinEvent -FilterHashtable $ncsiFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'Capability:\s*None|SuspectArpProbeFailed|SuspectDnsProbeFailed' }
    if ($ncsiEvents) {
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

    # Query WLAN AutoConfig Failovers / Reconnects (Targeted IDs 8000, 11000; Privacy-Preserving: Redact Raw SSID)
    $wlanFilter = @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; Id=@(8000, 11000); StartTime=$Cutoff}
    if ($EndTime -and $EndTime -lt (Get-Date)) { $wlanFilter['EndTime'] = $EndTime }
    $wlanEvents = Get-WinEvent -FilterHashtable $wlanFilter -ErrorAction SilentlyContinue
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

    # Query PCI Operational events for hardware PDO device resets / uninitialization (Targeted ID 1)
    $pciFilter = @{LogName='Microsoft-Windows-PCI/Operational'; Id=1; StartTime=$Cutoff}
    if ($EndTime -and $EndTime -lt (Get-Date)) { $pciFilter['EndTime'] = $EndTime }
    $pciEvents = Get-WinEvent -FilterHashtable $pciFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'Begin state transition from STARTED to UNINITIALIZED' }
    if ($pciEvents) {
        # Lazy-load PnP PCI devices by location string ONLY when PCI reset events exist
        $pciLocationMap = @{}
        try {
            $pciDevices = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like 'PCI*' }
            foreach ($pd in $pciDevices) {
                $loc = (Get-PnpDeviceProperty -InstanceId $pd.InstanceId -KeyName 'DEVPKEY_Device_LocationInfo' -ErrorAction SilentlyContinue).Data
                if ($loc) {
                    $pciLocationMap[$loc.Trim().ToLower()] = [PSCustomObject]@{
                        FriendlyName = $pd.FriendlyName
                        InstanceId   = $pd.InstanceId
                        Location     = $loc.Trim()
                    }
                }
            }
        } catch {}

        foreach ($pe in ($pciEvents | Select-Object -First 5)) {
            $pdo = if ($pe.Message -match '\[PDO\]\s*\((.*?)\)') { $Matches[1] } else { "Unknown" }
            $friendlyName = $null
            $instanceId = $null
            $locationStr = $null
            if ($pdo -match '0x([0-9a-fA-F]+)\.0x([0-9a-fA-F]+)\.0x([0-9a-fA-F]+)') {
                try {
                    $b = [Convert]::ToInt32($Matches[1], 16)
                    $d = [Convert]::ToInt32($Matches[2], 16)
                    $f = [Convert]::ToInt32($Matches[3], 16)
                    $locKey = "pci bus $b, device $d, function $f"
                    if ($pciLocationMap.ContainsKey($locKey)) {
                        $matchedDev = $pciLocationMap[$locKey]
                        $friendlyName = $matchedDev.FriendlyName
                        $instanceId   = $matchedDev.InstanceId
                        $locationStr  = $matchedDev.Location
                    }
                } catch {}
            }
            $devLabel = if ($friendlyName) { "$friendlyName ($locationStr)" } else { "PDO ($pdo)" }
            $results.PciDeviceResets.Add([PSCustomObject]@{
                TimeCreated  = $pe.TimeCreated
                Id           = $pe.Id
                Provider     = "Microsoft-Windows-PCI"
                Pdo          = $pdo
                FriendlyName = $friendlyName
                InstanceId   = $instanceId
                Location     = $locationStr
                DeviceLabel  = $devLabel
                Message      = "PCI Bus Device Reset on $($devLabel): $($pe.Message.Trim())"
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

    # 10. Tier 3: PCI Bus Hardware Uninitialization / Device Reset (Microsoft-Windows-PCI Event 1)
    try {
        $pciEv = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PCI/Operational'; Id=1; StartTime=$lookbackCutoff} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'Begin state transition from STARTED to UNINITIALIZED' } |
            Select-Object -First 1
        if ($pciEv) {
            $candidates.Add([PSCustomObject]@{
                Timestamp = $pciEv.TimeCreated
                Tier      = 3
                Source    = "PCI Bus Device Reset (Event 1)"
                Details   = $pciEv.Message.Trim()
                Item      = $pciEv
            })
        }
    } catch {}

    # 11. Tier 3: Physical Network Adapter Link Drop / Port Exhaustion (Events 27, 32, 4266)
    try {
        $netEv = Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(27, 32, 4266); StartTime=$lookbackCutoff} -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -match '(?i)e2f|e1d|rt64|rt68|tcpip|ndis' -or $_.Message -match '(?i)Network link is disconnected|link has been disconnected' } |
            Select-Object -First 1
        if ($netEv) {
            $candidates.Add([PSCustomObject]@{
                Timestamp = $netEv.TimeCreated
                Tier      = 3
                Source    = "Network Adapter Link Drop ($($netEv.ProviderName) Event $($netEv.Id))"
                Details   = $netEv.Message.Trim()
                Item      = $netEv
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

        # Ensure scan window covers at least 2 hours before the anchor incident AND the last 48 hours up to $now
        # so concurrent hardware/network faults occurring before or after an older dump are never missed.
        $anchorPreWindow = $latest.Timestamp.AddHours(-2)
        $recentWindow = $now.AddHours(-48)
        $incStart = if ($anchorPreWindow -lt $recentWindow) { $anchorPreWindow } else { $recentWindow }
        $incEnd = $now

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

function Resolve-DcDiagnosticFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]]$ParsedDumps = @(),

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Telemetry,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$GpuHealth,

        [Parameter(Mandatory = $false)]
        [object[]]$PnpIssues = @(),

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$MotherboardHealth,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$DisplayHealth,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$KernelDriverHealth,

        [Parameter(Mandatory = $false)]
        [object[]]$NetworkHealth = @(),

        [Parameter(Mandatory = $false)]
        [object[]]$ZombieProcesses = @(),

        [Parameter(Mandatory = $false)]
        [string]$ScanMode = "LatestIncident",

        [Parameter(Mandatory = $false)]
        [int]$MaxLookbackDays = 30,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$IncidentAnchor
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $correlatedDrop = $null
    $steamWatchdogCrash = $null
    $userModeCrashes = @()
    $kernelWatchdogDumps = @()

    if ($ParsedDumps -and $ParsedDumps.Count -gt 0) {
        $kernelWatchdogDumps = @($ParsedDumps | Where-Object {
            $_.ExceptionCode -match '(?i)^0x(00000141|00000193|00000117|A1000001|000001B8|000001A8)$' -or
            ($_.IsKernelDump -and $_.FullName -match '(?i)LiveKernelReports|WATCHDOG')
        })
        $userModeCrashes = @($ParsedDumps | Where-Object {
            $_.ExceptionCode -and ($kernelWatchdogDumps -notcontains $_)
        })

        $steamWatchdogCrash = $userModeCrashes | Where-Object {
            ($_.Assertions -match '(?i)cross-thread pipe|pipes\.cpp|BMainLoop appears to have stalled') -or
            ($_.ExceptionCode -eq "0x00000000" -and $_.FileName -match '(?i)crash_(steam|crimsondesert|stalker|gameoverlay)')
        } | Select-Object -First 1

        if ($steamWatchdogCrash -and $Telemetry -and ($Telemetry.NetworkDrops.Count -gt 0 -or $Telemetry.WlanFailovers.Count -gt 0)) {
            $crashTime = $steamWatchdogCrash.Timestamp
            $matchedNet = $Telemetry.NetworkDrops | Where-Object {
                [Math]::Abs(($_.TimeCreated - $crashTime).TotalMinutes) -le 10
            } | Select-Object -First 1

            if (-not $matchedNet) {
                $matchedNet = $Telemetry.WlanFailovers | Where-Object {
                    [Math]::Abs(($_.TimeCreated - $crashTime).TotalMinutes) -le 10
                } | Select-Object -First 1
            }

            if ($matchedNet) {
                $correlatedDrop = $matchedNet
            }
        }
    }

    $correlatedWatchdogNote = if ($kernelWatchdogDumps.Count -gt 0) {
        $wdFirst = $kernelWatchdogDumps[0]
        " Correlated with kernel GPU watchdog live dump $($wdFirst.FileName) ($($wdFirst.ExceptionCode) - $($wdFirst.ExceptionMeaning))."
    } else { "" }

    # -------------------------------------------------------------------------
    # RULE GROUP 1: STEAM WATCHDOG & USER-MODE CRASH DUMPS
    # -------------------------------------------------------------------------
    if ($steamWatchdogCrash -and $correlatedDrop) {
        $gameTarget = if ($steamWatchdogCrash.FaultingModule -and $steamWatchdogCrash.FaultingModule -ne "Unknown") { $steamWatchdogCrash.FaultingModule } else { "the active game" }
        $dropIface = if ($correlatedDrop.InterfaceName) { $correlatedDrop.InterfaceName } else { "Ethernet" }
        $dropTime = $correlatedDrop.TimeCreated.ToString('HH:mm:ss')

        $findings.Add([PSCustomObject]@{
            Id                = "STEAM_WATCHDOG_NETWORK_DROP"
            Category          = "Network"
            Severity          = "Critical"
            PriorityScore     = 100
            Title             = "STEAM WATCHDOG CRASH TRIGGERED BY NETWORK LINK DROP ($dropIface)"
            Description       = "$gameTarget was terminated by Steam's internal watchdog assertion ('Assert( Stalled cross-thread pipe )') after Steam's engine loop stalled. Telemetry confirms this was triggered at $dropTime when $dropIface suffered an ARP probe failure (SuspectArpProbeFailed), causing Windows to initiate a Wi-Fi failover while game sockets were active."
            Guidance          = "1. Terminate lingering zombie Steam processes using '.\Analyze-LatestCrash.ps1 -KillHungSteam'.`n  2. (Recommended) Optimize Intel I225-V stability by running '.\Analyze-LatestCrash.ps1 -RepairNetwork' as Administrator (disables Packet Priority & VLAN while preserving active negotiated link speed, eliminating known I225-V ARP drops).`n  3. Disconnect or turn off Wi-Fi when plugged into Ethernet to prevent Windows from flapping between wired and wireless connections during gameplay."
            Timestamp         = $steamWatchdogCrash.Timestamp
            AffectedComponent = $dropIface
        })
    } elseif ($steamWatchdogCrash) {
        $gameTarget = if ($steamWatchdogCrash.FaultingModule -and $steamWatchdogCrash.FaultingModule -ne "Unknown") { $steamWatchdogCrash.FaultingModule } else { "the active game" }
        $findings.Add([PSCustomObject]@{
            Id                = "STEAM_WATCHDOG_PIPE_STALL"
            Category          = "Application"
            Severity          = "Critical"
            PriorityScore     = 95
            Title             = "STEAM CROSS-THREAD PIPE WATCHDOG TERMINATION (pipes.cpp:672)"
            Description       = "$gameTarget was terminated by Steam's internal cross-thread IPC pipe watchdog ('Assert( Stalled cross-thread pipe )'). Steam's main event loop hung or deadlocked, causing Steam to forcefully terminate itself, GameOverlay, and the attached game process."
            Guidance          = "1. Run '.\Analyze-LatestCrash.ps1 -KillHungSteam' to terminate lingering headless Steam processes.`n  2. Clear Steam browser cache with '.\Analyze-LatestCrash.ps1 -CleanSteamCache'.`n  3. If using an overlay or recording software, temporarily disable Steam Overlay in Steam Settings."
            Timestamp         = $steamWatchdogCrash.Timestamp
            AffectedComponent = $gameTarget
        })
    }

    if ($userModeCrashes.Count -gt 0 -and -not $steamWatchdogCrash) {
        $firstCrash = $userModeCrashes | Select-Object -First 1
        $isBackgroundShell = ($firstCrash.FileName -match '(?i)^(ApplicationFrameHost|SearchHost|SearchApp|Widgets|RuntimeBroker|ShellExperienceHost|StartMenuExperienceHost|LockApp)')
        $baseDumpPriority = if ($isBackgroundShell) { 88 } else { 93 }

        if ($firstCrash.IsShaderCompiler -or ($firstCrash.FaultingModule -match '(?i)amdxc|amdxx|nvwgf2|oo2core')) {
            $findings.Add([PSCustomObject]@{
                Id                = "SHADER_RUNTIME_CRASH"
                Category          = "GPU"
                Severity          = "Critical"
                PriorityScore     = $baseDumpPriority
                Title             = "SHADER COMPILATION / GRAPHICS RUNTIME CRASH ($($firstCrash.FaultingModule))"
                Description       = "Exception $($firstCrash.ExceptionCode): $($firstCrash.ExceptionMeaning) in shader compiler / decompression DLL ($($firstCrash.FaultingModule) in $($firstCrash.FileName)).$correlatedWatchdogNote"
                Guidance          = "Purge corrupt shader caches (including DX12 SM6 DxcCache) using '.\Analyze-LatestCrash.ps1 -CleanShaderCache'. Shader compilation places heavy AVX2/AVX-512 load across all CPU cores and RAM; if crashes persist, test CPU/RAM stability or disable aggressive PBO/Curve Optimizer undervolts."
                Timestamp         = $firstCrash.Timestamp
                AffectedComponent = $firstCrash.FaultingModule
            })
        } elseif ($firstCrash.ExceptionCode -match '0x887A0006|0x887A0005') {
            $hybridHint = if ($GpuHealth -and $GpuHealth.HybridMultiGpu) { " On hybrid iGPU + dGPU systems, disable the unused CPU integrated GPU in BIOS or verify Windows Graphics Settings GPU preference / HAGS." } else { "" }
            $findings.Add([PSCustomObject]@{
                Id                = "GRAPHICS_DEVICE_REMOVED"
                Category          = "GPU"
                Severity          = "Critical"
                PriorityScore     = $baseDumpPriority
                Title             = "GRAPHICS DEVICE HUNG / REMOVED (0x887A0006 / 0x887A0005)"
                Description       = "DirectX graphics device lost or timed out ($($firstCrash.ExceptionMeaning)) in $($firstCrash.FaultingModule) ($($firstCrash.FileName)).$correlatedWatchdogNote"
                Guidance          = "1. Purge DirectX & AMD DxcCache/DxCache shader caches using '.\Analyze-LatestCrash.ps1 -CleanShaderCache'.`n  2. Disable PCIe Link State Power Management (ASPM) using '.\Analyze-LatestCrash.ps1 -DisablePciePowerSavings'.`n  3. Check GPU temperatures and power cables, lower in-game ray tracing / VRAM texture settings, or clean reinstall GPU drivers.$hybridHint"
                Timestamp         = $firstCrash.Timestamp
                AffectedComponent = $firstCrash.FaultingModule
            })
        } elseif ($firstCrash.IsRogueKernelDriver -or ($firstCrash.FaultingModule -match '(?i)inpoutx64|inpout32|winring0|ene\.sys|asromgdrv|gdrv') -or $firstCrash.ExceptionCode -eq '0x00000093') {
            $findings.Add([PSCustomObject]@{
                Id                = "ROGUE_KERNEL_DRIVER_CRASH"
                Category          = "System"
                Severity          = "Critical"
                PriorityScore     = 97
                Title             = "ROGUE KERNEL I/O DRIVER CRASH ($($firstCrash.FaultingModule) / INVALID_KERNEL_HANDLE 0x93)"
                Description       = "Exception $($firstCrash.ExceptionCode): $($firstCrash.ExceptionMeaning) in legacy kernel driver '$($firstCrash.FaultingModule)' ($($firstCrash.FileName)). This legacy direct-hardware I/O port driver (commonly left behind by RGB or hardware monitoring utilities) bypasses modern Windows driver models. Under game anti-cheat engines (Easy Anti-Cheat, BattlEye, Vanguard) or Windows Memory Integrity, invalid handle usage causes game lockups (with audio continuing) or instant BSODs."
                Guidance          = "Disable the problematic driver service by running '.\Analyze-LatestCrash.ps1 -DisableRogueDrivers' or 'sc config inpoutx64 start= disabled' in an Administrator terminal. Modern lighting software will continue to operate normally without this legacy kernel driver."
                Timestamp         = $firstCrash.Timestamp
                AffectedComponent = $firstCrash.FaultingModule
            })
        } elseif ($firstCrash.ExceptionCode -match '0xC0000005') {
            $findings.Add([PSCustomObject]@{
                Id                = "APP_ACCESS_VIOLATION"
                Category          = "Application"
                Severity          = "Critical"
                PriorityScore     = $baseDumpPriority
                Title             = "APPLICATION MEMORY ACCESS VIOLATION (0xC0000005)"
                Description       = "Exception 0xC0000005: Native memory access violation in $($firstCrash.FaultingModule) ($($firstCrash.FileName)).$correlatedWatchdogNote"
                Guidance          = "Memory access violation in $($firstCrash.FaultingModule). Verify game integrity via Steam/Launcher, purge shader caches ('.\Analyze-LatestCrash.ps1 -CleanShaderCache'), and update Visual C++ Redistributables. If overclocked, test with stock memory/XMP timings."
                Timestamp         = $firstCrash.Timestamp
                AffectedComponent = $firstCrash.FaultingModule
            })
        } elseif ($firstCrash.FaultingModule -match '(?i)CrimsonDesert' -or ($Telemetry -and $Telemetry.AppHangs -and ($Telemetry.AppHangs | Where-Object { $_.Application -match '(?i)CrimsonDesert' }))) {
            $findings.Add([PSCustomObject]@{
                Id                = "CRIMSON_DESERT_CRASH"
                Category          = "Application"
                Severity          = "Critical"
                PriorityScore     = 93
                Title             = "CRIMSON DESERT (BLACKSPACE ENGINE) GRAPHICS HANG & SHADER STALL"
                Description       = "CrimsonDesert.exe stopped responding during scene/shader dispatch ($($firstCrash.ExceptionMeaning)). Mid-render TDRs leave uncommitted SQLite WAL journal files (.dxcache-wal, .dxcache-shm) in '%LOCALAPPDATA%\D3DSCache' and corrupted PSO cache blocks in '%LOCALAPPDATA%\AMD\DxCache', plus stale crash locks in Pearl Abyss DumpCache, causing subsequent game launches to fail or exit prematurely.$correlatedWatchdogNote"
                Guidance          = "1. Flush corrupted DirectX & AMD shader caches using '.\Analyze-LatestCrash.ps1 -CleanShaderCache'.`n  2. Purge stale crash locks and DumpCache using '.\Analyze-LatestCrash.ps1 -CleanConfig -Game CrimsonDesert'.`n  3. Fully exit and restart Steam to clear stale GameOverlay/IPC pipes.`n  4. If experiencing Intel I225-V Ethernet disconnects, run '.\Analyze-LatestCrash.ps1 -RepairNetwork' as Admin."
                Timestamp         = $firstCrash.Timestamp
                AffectedComponent = "CrimsonDesert.exe"
            })
        } else {
            $findings.Add([PSCustomObject]@{
                Id                = "UNHANDLED_APP_CRASH"
                Category          = "Application"
                Severity          = "Critical"
                PriorityScore     = $baseDumpPriority
                Title             = "UNHANDLED APPLICATION CRASH (Tier 1 Crash Dump)"
                Description       = "Exception $($firstCrash.ExceptionCode): $($firstCrash.ExceptionMeaning) in $($firstCrash.FaultingModule) ($($firstCrash.FileName)).$correlatedWatchdogNote"
                Guidance          = "Verify game integrity via Steam/Launcher and report the faulting module ($($firstCrash.FaultingModule)) to the game developer."
                Timestamp         = $firstCrash.Timestamp
                AffectedComponent = $firstCrash.FaultingModule
            })
        }
    }

    # -------------------------------------------------------------------------
    # RULE GROUP 2: APPLICATION HANGS
    # -------------------------------------------------------------------------
    if ($Telemetry -and $Telemetry.AppHangs -and ($Telemetry.AppHangs | Where-Object { $_.Application -match '(?i)CrimsonDesert' })) {
        $alreadyHasCd = @($findings | Where-Object { $_.Id -eq "CRIMSON_DESERT_CRASH" }).Count -gt 0
        if (-not $alreadyHasCd) {
            $firstHang = $Telemetry.AppHangs | Where-Object { $_.Application -match '(?i)CrimsonDesert' } | Select-Object -First 1
            $findings.Add([PSCustomObject]@{
                Id                = "CRIMSON_DESERT_APP_HANG"
                Category          = "Application"
                Severity          = "Critical"
                PriorityScore     = 89
                Title             = "CRIMSON DESERT (BLACKSPACE ENGINE) APPLICATION HANG (Event 1002)"
                Description       = "CrimsonDesert.exe stopped interacting with Windows and was closed at $($firstHang.TimeCreated.ToString('HH:mm:ss')). Following a mid-render hang or TDR, corrupted DirectX 12/AMD shader cache files (.dxcache-wal, .dxcache-shm, .parc) and Pearl Abyss DumpCache locks prevent the game from loading."
                Guidance          = "1. Flush corrupted DirectX & AMD shader caches using '.\Analyze-LatestCrash.ps1 -CleanShaderCache'.`n  2. Purge stale crash locks and DumpCache using '.\Analyze-LatestCrash.ps1 -CleanConfig -Game CrimsonDesert'.`n  3. Fully exit and restart Steam to refresh GameOverlay hooks.`n  4. If experiencing Intel I225-V Ethernet disconnects, run '.\Analyze-LatestCrash.ps1 -RepairNetwork' as Admin."
                Timestamp         = $firstHang.TimeCreated
                AffectedComponent = "CrimsonDesert.exe"
            })
        }
    }

    # -------------------------------------------------------------------------
    # RULE GROUP 3: KERNEL BUGCHECKS, WHEA HARDWARE ERRORS & MEMORY EXHAUSTION
    # -------------------------------------------------------------------------
    if ($Telemetry -and $Telemetry.KernelBugChecks -and $Telemetry.KernelBugChecks.Count -gt 0) {
        $firstBc = $Telemetry.KernelBugChecks[0]
        $findings.Add([PSCustomObject]@{
            Id                = "KERNEL_BUGCHECK_BSOD"
            Category          = "System"
            Severity          = "Critical"
            PriorityScore     = 98
            Title             = "KERNEL BUGCHECK BSOD ($($firstBc.Code))"
            Description       = "$($firstBc.Meaning) - $($firstBc.Message)"
            Guidance          = "A kernel driver caused a fatal system fault. Check Tier 4 hardware devices for missing or uninstalled drivers."
            Timestamp         = $firstBc.TimeCreated
            AffectedComponent = "Windows Kernel ($($firstBc.Code))"
        })
    }

    if ($Telemetry -and $Telemetry.PcieWheaErrors -and $Telemetry.PcieWheaErrors.Count -gt 0) {
        $firstPcie = $Telemetry.PcieWheaErrors[0]
        $findings.Add([PSCustomObject]@{
            Id                = "PCIE_WHEA_ERROR"
            Category          = "Hardware"
            Severity          = "Critical"
            PriorityScore     = 96
            Title             = "PCIe BUS / RISER CABLE INTEGRITY ERROR (WHEA Event 17)"
            Description       = "Windows detected PCIe link communication errors ($($Telemetry.PcieWheaErrors.Count) incident(s)). This is frequently caused by PCIe 4.0/5.0 riser cables, loose GPU PCIe slot seating, or motherboard PCIe signal degradation.$correlatedWatchdogNote"
            Guidance          = "Reseat your graphics card. If using a vertical GPU mount or PCIe riser cable, test with the GPU plugged directly into the motherboard PCIe slot, or configure PCIe link speed to Gen 3 / Gen 4 in BIOS. Also ensure PCIe Link State Power Management is Off ('.\Analyze-LatestCrash.ps1 -DisablePciePowerSavings')."
            Timestamp         = $firstPcie.TimeCreated
            AffectedComponent = "PCI Express Root Port"
        })
    }

    $nonPcieWhea = if ($Telemetry -and $Telemetry.WheaErrors) { @($Telemetry.WheaErrors | Where-Object { -not $_.IsPcieError }) } else { @() }
    if ($nonPcieWhea.Count -gt 0) {
        $firstWhea = $nonPcieWhea[0]
        $findings.Add([PSCustomObject]@{
            Id                = "WHEA_HARDWARE_ERROR"
            Category          = "Hardware"
            Severity          = "Critical"
            PriorityScore     = 95
            Title             = "WHEA HARDWARE ARCHITECTURE ERROR (Event $($firstWhea.Id))"
            Description       = "A fatal or corrected hardware exception was reported by the CPU/motherboard hardware subsystem ($($firstWhea.Message))."
            Guidance          = "This indicates hardware or bus instability (CPU undervolt, unstable memory EXPO/XMP, or overheating). Disable CPU Curve Optimizer or RAM overclocks to restore baseline stability."
            Timestamp         = $firstWhea.TimeCreated
            AffectedComponent = "CPU / Memory / Bus"
        })
    }

    if ($Telemetry -and $Telemetry.MemoryExhaustion -and $Telemetry.MemoryExhaustion.Count -gt 0) {
        $firstMem = $Telemetry.MemoryExhaustion[0]
        $findings.Add([PSCustomObject]@{
            Id                = "VIRTUAL_MEMORY_EXHAUSTION"
            Category          = "Memory"
            Severity          = "Critical"
            PriorityScore     = 92
            Title             = "VIRTUAL MEMORY / COMMIT LIMIT EXHAUSTION (Event 2004)"
            Description       = "Windows ran out of virtual memory / pagefile commit limit while games or shader compilation were active ($($Telemetry.MemoryExhaustion.Count) incident(s))."
            Guidance          = "Ensure your Windows Paging File (Pagefile) is set to 'System managed size' on an SSD with at least 20 GB free space. Do not disable or severely restrict pagefile size."
            Timestamp         = $firstMem.TimeCreated
            AffectedComponent = "Virtual Memory / Pagefile"
        })
    }

    # -------------------------------------------------------------------------
    # RULE GROUP 4: GPU DISPLAY DRIVER TIMEOUTS & WATCHDOG LIVE DUMPS
    # -------------------------------------------------------------------------
    $tdrCount = if ($Telemetry -and $Telemetry.TdrEvents) { $Telemetry.TdrEvents.Count } else { 0 }
    if ($tdrCount -gt 0 -or $kernelWatchdogDumps.Count -gt 0) {
        $hasHighBoostGpu = if ($GpuHealth -and $GpuHealth.Gpus) { @($GpuHealth.Gpus | Where-Object { $_.IsHighBoostCard }).Count -gt 0 } else { $false }
        $hasAmdFullInstall = if ($GpuHealth -and $GpuHealth.Gpus) { @($GpuHealth.Gpus | Where-Object { $_.AmdInstallType -like "*Full*" }).Count -gt 0 } else { $false }
        $has0x193 = ($Telemetry -and $Telemetry.TdrEvents -and (@($Telemetry.TdrEvents | Where-Object { $_.Code -eq '193' }).Count -gt 0)) -or (@($kernelWatchdogDumps | Where-Object { $_.ExceptionCode -eq '0x00000193' }).Count -gt 0)
        $tdrCountTotal = [math]::Max($tdrCount, $kernelWatchdogDumps.Count)
        $dumpDetailSuffix = if ($kernelWatchdogDumps.Count -gt 0) {
            $wd = $kernelWatchdogDumps[0]
            " Kernel watchdog dump captured: $($wd.FileName) ($($wd.ExceptionCode) - $($wd.ExceptionMeaning) in $($wd.FaultingIP))."
        } else { "" }

        $latestTdrTime = if ($tdrCount -gt 0) { $Telemetry.TdrEvents[0].TimeCreated } elseif ($kernelWatchdogDumps.Count -gt 0) { $kernelWatchdogDumps[0].Timestamp } else { Get-Date }

        $sleepTdr = $null
        if ($Telemetry -and $Telemetry.SleepTransitions -and $Telemetry.SleepTransitions.Count -gt 0) {
            foreach ($tdr in $Telemetry.TdrEvents) {
                $matchingWake = @($Telemetry.SleepTransitions | Where-Object {
                    $sec = ($tdr.TimeCreated - $_.WakeTime).TotalSeconds
                    $sec -ge -10 -and $sec -le 180
                })
                if ($matchingWake.Count -gt 0) {
                    $sleepTdr = [PSCustomObject]@{ Tdr = $tdr; Wake = $matchingWake[0] }
                    break
                }
            }
            if (-not $sleepTdr -and $kernelWatchdogDumps.Count -gt 0) {
                foreach ($kdmp in $kernelWatchdogDumps) {
                    $matchingWake = @($Telemetry.SleepTransitions | Where-Object {
                        $sec = ($kdmp.Timestamp - $_.WakeTime).TotalSeconds
                        $sec -ge -10 -and $sec -le 180
                    })
                    if ($matchingWake.Count -gt 0) {
                        $sleepTdr = [PSCustomObject]@{
                            Tdr  = [PSCustomObject]@{ TimeCreated = $kdmp.Timestamp; Meaning = $kdmp.ExceptionMeaning }
                            Wake = $matchingWake[0]
                        }
                        break
                    }
                }
            }
        }

        if ($sleepTdr) {
            $diffSec = [math]::Round([math]::Abs(($sleepTdr.Tdr.TimeCreated - $sleepTdr.Wake.WakeTime).TotalSeconds))
            $remedies = [System.Collections.Generic.List[string]]::new()
            $remedies.Add("(Recommended - Zero Power Impact) Increase TdrDelay and TdrDdiDelay to 8-10 seconds in HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers. High-refresh 4K HDMI 2.1 link training and display handshakes on wake take several seconds, exceeding Windows' default 2-second watchdog threshold. Extending the timeout allows the link to finish initializing while fully preserving all sleep and power-saving states.")
            $remedies.Add("Verify HDMI 2.1 cable integrity (Ultra High Speed 48 Gbps certified) and check TV standby / Quick Start+ settings to ensure display handshakes respond promptly.")
            $remedies.Add("(Temporary Workaround / Last Resort Only) If timeouts persist after optimizing TdrDelay, test disabling Ultra-Low Power State (ULPS) via '.\scripts\Repair-GpuSleepSettings.ps1 -DisableUlps' to isolate deep-sleep wake latency. Re-enable after testing to maintain system power efficiency.")
            $remedies.Add("Run '.\Analyze-LatestCrash.ps1 -RepairGpuSleep' or '.\scripts\Repair-GpuSleepSettings.ps1' as Administrator to apply the zero-power-impact TDR timeout fix.")

            $findings.Add([PSCustomObject]@{
                Id                = "GPU_TDR_WAKE_FROM_SLEEP"
                Category          = "GPU"
                Severity          = "Critical"
                PriorityScore     = 94
                Title             = "GPU DRIVER TIMEOUT ON WAKE FROM SLEEP (TDR 0x141 / AMD WATCHDOG)"
                Description       = "The GPU display driver stopped responding and triggered a watchdog recovery ($($sleepTdr.Tdr.Meaning)) at $($sleepTdr.Tdr.TimeCreated.ToString('HH:mm:ss')), within ${diffSec}s of waking from sleep (Wake Source: $($sleepTdr.Wake.WakeSource)).$dumpDetailSuffix"
                Guidance          = ($remedies -join "`n  * ")
                Timestamp         = $sleepTdr.Tdr.TimeCreated
                AffectedComponent = "GPU Display Driver (Sleep/Wake)"
            })
        } elseif ($Telemetry -and $Telemetry.PciePowerManagement -and $Telemetry.PciePowerManagement.IsEnabled) {
            $codeLabel = if ($has0x193) { "TDR 0x141 / DXGKRNL 0x193" } else { "TDR / 0x141" }
            $remedyList = [System.Collections.Generic.List[string]]::new()
            $remedyList.Add("Disable PCIe Link State Power Management using '.\Analyze-LatestCrash.ps1 -DisablePciePowerSavings' or '.\scripts\Repair-PciePowerSettings.ps1'.")
            $remedyList.Add("Purge DirectX & AMD DxcCache/DxCache shader caches using '.\Analyze-LatestCrash.ps1 -CleanShaderCache' (corrupt UE5 / D3D12 SM6 shaders frequently trigger mid-render TDRs and 0x193 deadlocks).")
            $remedyList.Add("If using a PCIe Gen 5 GPU (e.g. RX 9070 XT / RTX 50-series) on a PCIe Gen 4/5 motherboard or riser cable, manually set PCIEX16 Link Speed to Gen 4 in BIOS to eliminate link retraining stalls.")
            if ($hasHighBoostGpu) {
                $remedyList.Add("Enthusiast High-Boost GPU Detected: Test applying a -100 MHz to -150 MHz Max Frequency offset in AMD Software Tuning to prevent transient voltage droop under bursty UE5 D3D12 loads.")
            }
            if ($GpuHealth -and $GpuHealth.HybridMultiGpu) {
                $remedyList.Add("Hybrid Multi-GPU Detected: Disable the unused CPU integrated GPU (iGPU) in Motherboard BIOS or test toggling Hardware-Accelerated GPU Scheduling (HAGS) in Windows Graphics Settings to prevent dxgkrnl cross-adapter synchronization deadlocks (0x193).")
            }

            $findings.Add([PSCustomObject]@{
                Id                = "GPU_TDR_PCIE_ASPM"
                Category          = "GPU"
                Severity          = "Critical"
                PriorityScore     = 94
                Title             = "GPU DISPLAY DRIVER TIMEOUT ($codeLabel) - PCIE POWER SAVINGS ACTIVE"
                Description       = "The GPU display driver stopped responding or hit a DirectX graphics kernel watchdog timeout ($tdrCountTotal incident(s)).$dumpDetailSuffix Windows PCIe Link State Power Management (ASPM) is currently ENABLED ('$($Telemetry.PciePowerManagement.ACSettingName)') in power plan '$($Telemetry.PciePowerManagement.SchemeName)'. When the PCIe link enters low-power L0s/L1 states during idle or bursty D3D12 load, resumption latency spikes cause the graphics watchdog to timeout."
                Guidance          = ($remedyList -join "`n  * ")
                Timestamp         = $latestTdrTime
                AffectedComponent = "GPU Display Driver / PCIe ASPM"
            })
        } else {
            $codeLabel = if ($has0x193) { "TDR 0x141 / DXGKRNL 0x193 WATCHDOG" } else { "TDR / 0x141" }
            $remedyList = [System.Collections.Generic.List[string]]::new()
            $remedyList.Add("Clear Shader Caches: Clear your DirectX and AMD shader caches (corrupted shader files often cause mid-game GPU freezes and driver timeouts).")
            $remedyList.Add("Reinstall GPU Driver: If clearing the shader cache does not help, do a clean GPU driver reinstall using AMD Cleanup Utility or DDU in Safe Mode.")
            $remedyList.Add("Check PCIe Slot Speed in BIOS: If using a PCIe Gen 5 GPU (like RX 9070 XT or RTX 50-series) or a riser cable, set PCIEX16 Link Speed to Gen 4 in BIOS to prevent connection drops.")
            if ($hasHighBoostGpu) {
                $remedyList.Add("Lower GPU Max Boost Clock Slightly: Factory-overclocked cards can boost too high during heavy Unreal Engine 5 scenes. Try a -100 MHz Max Frequency offset in AMD Software Tuning.")
            }
            if ($GpuHealth -and $GpuHealth.HybridMultiGpu) {
                $remedyList.Add("Disable Unused Integrated Graphics: Turn off the CPU's built-in graphics (iGPU) in BIOS if your monitor is plugged into your main graphics card.")
            }
            if ($hasAmdFullInstall) {
                $remedyList.Add("Try a 'Driver Only' Install: If crashes continue, reinstall the AMD driver using the 'Driver Only' option to rule out background overlays.")
            }

            $findings.Add([PSCustomObject]@{
                Id                = "GPU_TDR_TIMEOUT"
                Category          = "GPU"
                Severity          = "Critical"
                PriorityScore     = 94
                Title             = "GPU DISPLAY DRIVER TIMEOUT ($codeLabel)"
                Description       = "The GPU display driver stopped responding or experienced a DirectX graphics kernel watchdog timeout ($tdrCountTotal incident(s)).$dumpDetailSuffix"
                Guidance          = ($remedyList -join "`n  * ")
                Timestamp         = $latestTdrTime
                AffectedComponent = "GPU Display Driver"
            })
        }
    }

    # -------------------------------------------------------------------------
    # RULE GROUP 5: PCI BUS RESETS, NETWORK ADAPTER DROPS & PORT EXHAUSTION
    # -------------------------------------------------------------------------
    $pciResetCount = if ($Telemetry -and $Telemetry.PciDeviceResets) { $Telemetry.PciDeviceResets.Count } else { 0 }
    $netDropCount  = if ($Telemetry -and $Telemetry.NetworkDrops) { $Telemetry.NetworkDrops.Count } else { 0 }
    $wlanCount     = if ($Telemetry -and $Telemetry.WlanFailovers) { $Telemetry.WlanFailovers.Count } else { 0 }
    $udpExhCount   = if ($Telemetry -and $Telemetry.UdpPortExhaustions) { $Telemetry.UdpPortExhaustions.Count } else { 0 }

    if ($pciResetCount -gt 0 -and ($netDropCount -gt 0 -or $wlanCount -gt 0)) {
        $firstPci = $Telemetry.PciDeviceResets[0]
        $devName = if ($firstPci.FriendlyName) { $firstPci.FriendlyName } elseif ($firstPci.DeviceLabel) { $firstPci.DeviceLabel } else { "PCI Network Controller ($($firstPci.Pdo))" }
        $findings.Add([PSCustomObject]@{
            Id                = "PCI_NIC_RESET_LINK_DROP"
            Category          = "Network"
            Severity          = "Critical"
            PriorityScore     = 90
            Title             = "PCI CONTROLLER UNINITIALIZATION & NETWORK LINK DROP ($devName)"
            Description       = "$devName underwent a PCI bus uninitialization / hardware reset (Microsoft-Windows-PCI Event 1: '$($firstPci.Message)') alongside $netDropCount network link disconnect(s). This controller or driver reset interrupted active network sockets, causing Windows to drop connectivity or trigger Wi-Fi failover."
            Guidance          = "1. Optimize adapter stability: run '.\Analyze-LatestCrash.ps1 -RepairNetwork' as Administrator (disables Packet Priority & VLAN while preserving active negotiated link speed, preventing known I225-V/I226-V controller hangs).`n  2. Expand UDP dynamic port space: run '.\Analyze-LatestCrash.ps1 -ExpandUdpPorts' as Administrator to prevent socket exhaustion during bursty matchmaking/server queries.`n  3. If motherboard BIOS is outdated, update BIOS to the latest version with Intel Gigabit Ethernet NVM/firmware updates."
            Timestamp         = $firstPci.TimeCreated
            AffectedComponent = $devName
        })
    } elseif ($pciResetCount -gt 0) {
        $firstPci = $Telemetry.PciDeviceResets[0]
        $devName = if ($firstPci.FriendlyName) { $firstPci.FriendlyName } elseif ($firstPci.DeviceLabel) { $firstPci.DeviceLabel } else { "PCI Device ($($firstPci.Pdo))" }
        $findings.Add([PSCustomObject]@{
            Id                = "PCI_DEVICE_RESET"
            Category          = "Hardware"
            Severity          = "Warning"
            PriorityScore     = 78
            Title             = "PCI BUS DEVICE UNINITIALIZATION / FUNCTION-LEVEL RESET ($devName)"
            Description       = "A PCI Express endpoint ($devName) underwent a hardware state transition from STARTED to UNINITIALIZED ($pciResetCount incident(s)). This indicates a device driver crash or function-level reset (FLR)."
            Guidance          = "Check Device Manager for driver warnings on $devName. If this is a network controller, run '.\Analyze-LatestCrash.ps1 -RepairNetwork' to optimize packet handling and prevent driver stalls."
            Timestamp         = $firstPci.TimeCreated
            AffectedComponent = $devName
        })
    } elseif ($netDropCount -gt 0 -and -not ($steamWatchdogCrash -and $correlatedDrop)) {
        $firstDrop = $Telemetry.NetworkDrops[0]
        $score = if ($netDropCount -ge 3) { 80 } else { 72 }
        $findings.Add([PSCustomObject]@{
            Id                = "NETWORK_LINK_DROP"
            Category          = "Network"
            Severity          = "Warning"
            PriorityScore     = $score
            Title             = "NETWORK ADAPTER LINK DISCONNECT / INTERNET CAPABILITY LOSS ($netDropCount Incident(s))"
            Description       = "Windows recorded $netDropCount network disconnect or NCSI probe failure incident(s). Latest: $($firstDrop.Message)"
            Guidance          = "1. Run '.\Analyze-LatestCrash.ps1 -RepairNetwork' to optimize Ethernet adapter stability.`n  2. Disconnect Wi-Fi while plugged into wired Ethernet to prevent Windows interface flapping.`n  3. Verify physical Ethernet cable and switch port connections."
            Timestamp         = $firstDrop.TimeCreated
            AffectedComponent = $firstDrop.InterfaceName
        })
    }

    if ($udpExhCount -gt 0) {
        $firstUdp = $Telemetry.UdpPortExhaustions[0]
        $findings.Add([PSCustomObject]@{
            Id                = "UDP_PORT_EXHAUSTION"
            Category          = "Network"
            Severity          = "Warning"
            PriorityScore     = 76
            Title             = "TCP/IP EPHEMERAL PORT EXHAUSTION (Event 4266)"
            Description       = "Windows dynamic (ephemeral) port space was exhausted during socket bursts ($udpExhCount incident(s)). This prevented applications (such as Steam and multiplayer games) from creating outgoing sockets, causing connection drops and ARP/DNS probe timeouts."
            Guidance          = "Run '.\Analyze-LatestCrash.ps1 -ExpandUdpPorts' or '.\scripts\Repair-EthernetSettings.ps1 -ExpandUdpPorts' as Administrator to expand the UDP dynamic port range to 64,511 ports (matching TCP)."
            Timestamp         = $firstUdp.TimeCreated
            AffectedComponent = "TCP/IP Ephemeral Port Stack"
        })
    } elseif ($NetworkHealth -and @($NetworkHealth | Where-Object { $_.IsUdpConstrained }).Count -gt 0 -and ($netDropCount -gt 0 -or $pciResetCount -gt 0)) {
        $constrainedNic = $NetworkHealth | Where-Object { $_.IsUdpConstrained } | Select-Object -First 1
        $findings.Add([PSCustomObject]@{
            Id                = "UDP_PORT_SPACE_CONSTRAINED"
            Category          = "Network"
            Severity          = "Warning"
            PriorityScore     = 62
            Title             = "CONSTRAINED WINDOWS UDP DYNAMIC PORT RANGE ($($constrainedNic.UdpPortRange))"
            Description       = "Windows UDP ephemeral port allocation is restricted to $($constrainedNic.UdpPortRange) (vs TCP $($constrainedNic.TcpPortRange)) while network link drops occurred. Bursty multiplayer matchmaking and server browser queries can rapidly exhaust 16,384 UDP ports."
            Guidance          = "Run '.\Analyze-LatestCrash.ps1 -ExpandUdpPorts' as Administrator to expand the UDP dynamic port range to 64,511 ports (matching TCP)."
            Timestamp         = (Get-Date)
            AffectedComponent = "UDP Ephemeral Port Range"
        })
    }

    # -------------------------------------------------------------------------
    # RULE GROUP 6: POWER, PLATFORM, DRIVERS & HARDWARE CONFIGURATION
    # -------------------------------------------------------------------------
    if ($Telemetry -and $Telemetry.AbruptReboots -and $Telemetry.AbruptReboots.Count -gt 0 -and ($Telemetry.AbruptReboots | Where-Object { $_.BugcheckCode -eq 0 })) {
        $firstReb = $Telemetry.AbruptReboots | Where-Object { $_.BugcheckCode -eq 0 } | Select-Object -First 1
        $findings.Add([PSCustomObject]@{
            Id                = "DIRTY_POWER_RESET"
            Category          = "Power"
            Severity          = "Warning"
            PriorityScore     = 82
            Title             = "DIRTY POWER RESET / INSTANT BLACK SCREEN (Event 41 BugcheckCode 0)"
            Description       = "The system lost power or restarted abruptly without generating a BugCheck crash dump ($($Telemetry.AbruptReboots.Count) incident(s))."
            Guidance          = "When occurring during gaming or 3D load, this typically points to PSU transient spike trips (GPU power draw exceeding PSU peak wattage), loose 12VHPWR/PCIe 8-pin power cables, or aggressive GPU power limits."
            Timestamp         = $firstReb.TimeCreated
            AffectedComponent = "System Power / PSU"
        })
    }

    if ($GpuHealth -and $GpuHealth.DualGpuConflict) {
        $findings.Add([PSCustomObject]@{
            Id                = "DUAL_GPU_MISMATCH"
            Category          = "GPU"
            Severity          = "Warning"
            PriorityScore     = 75
            Title             = "DUAL-GPU DRIVER VERSION MISMATCH"
            Description       = $GpuHealth.DualGpuDetails
            Guidance          = "Align both AMD display drivers using '.\Analyze-LatestCrash.ps1 -FixDrivers' or disable CPU Integrated Graphics in Motherboard BIOS if not using motherboard display ports."
            Timestamp         = (Get-Date)
            AffectedComponent = "Dual-GPU Display Subsystem"
        })
    }

    if ($PnpIssues -and $PnpIssues.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            Id                = "PNP_DEVICE_ERRORS"
            Category          = "Hardware"
            Severity          = "Warning"
            PriorityScore     = 74
            Title             = "HARDWARE DEVICE ERRORS / MISSING DRIVERS"
            Description       = "$($PnpIssues.Count) device(s) are reporting errors or missing drivers in Windows Device Manager."
            Guidance          = "Install official motherboard chipset drivers and check Device Manager for yellow exclamation marks."
            Timestamp         = (Get-Date)
            AffectedComponent = "Plug and Play Devices"
        })
    }

    if ($MotherboardHealth -and -not $MotherboardHealth.IsHealthy) {
        $findings.Add([PSCustomObject]@{
            Id                = "MISSING_CHIPSET_CONTROLLERS"
            Category          = "Hardware"
            Severity          = "Warning"
            PriorityScore     = 73
            Title             = "MISSING MOTHERBOARD CHIPSET CONTROLLERS"
            Description       = "One or more core motherboard platform controllers ($($MotherboardHealth.MissingControllers -join ', ')) are missing official drivers or reporting errors. This can cause PCIe link instability, USB disconnects, and intermittent driver hangs."
            Guidance          = "Download and install the latest official chipset drivers from your motherboard manufacturer's support site or AMD.com / Intel.com ($($MotherboardHealth.Summary))."
            Timestamp         = (Get-Date)
            AffectedComponent = "Motherboard Chipset"
        })
    }

    if ($Telemetry -and $Telemetry.FastStartup -and $Telemetry.FastStartup.FastStartupEnabled -and $Telemetry.AbruptReboots.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            Id                = "FAST_STARTUP_REBOOT"
            Category          = "Power"
            Severity          = "Warning"
            PriorityScore     = 70
            Title             = "ABRUPT REBOOT WITH FAST STARTUP ENABLED"
            Description       = "The system experienced unexpected reboots while Windows Fast Startup was enabled."
            Guidance          = "Disable Windows Fast Startup (Control Panel -> Power Options -> Choose what the power buttons do -> Turn off Fast Startup) to ensure clean cold reboots."
            Timestamp         = (Get-Date)
            AffectedComponent = "Windows Fast Startup"
        })
    }

    if ($Telemetry -and $Telemetry.PciePowerManagement -and $Telemetry.PciePowerManagement.IsEnabled -and ($Telemetry.AbruptReboots.Count -gt 0 -or $Telemetry.UnexpectedShutdowns.Count -gt 0)) {
        $findings.Add([PSCustomObject]@{
            Id                = "PCIE_ASPM_INSTABILITY"
            Category          = "Power"
            Severity          = "Warning"
            PriorityScore     = 68
            Title             = "PCIE LINK STATE POWER MANAGEMENT (ASPM) INSTABILITY"
            Description       = "The system experienced unexpected reboots or sleep-wake issues while PCIe Link State Power Management was enabled ($($Telemetry.PciePowerManagement.ACSettingName))."
            Guidance          = "Disable PCIe Link State Power Management using '.\Analyze-LatestCrash.ps1 -DisablePciePowerSavings' or '.\scripts\Repair-PciePowerSettings.ps1'."
            Timestamp         = (Get-Date)
            AffectedComponent = "PCIe Power Management (ASPM)"
        })
    }

    if ($KernelDriverHealth -and $KernelDriverHealth.RogueDriversDetected) {
        $findings.Add([PSCustomObject]@{
            Id                = "ROGUE_KERNEL_DRIVER_HAZARD"
            Category          = "System"
            Severity          = "Warning"
            PriorityScore     = 66
            Title             = "ROGUE KERNEL I/O DRIVER HAZARD (RGB / DIRECT PORT ACCESS)"
            Description       = $KernelDriverHealth.RiskSummary
            Guidance          = $KernelDriverHealth.Guidance
            Timestamp         = (Get-Date)
            AffectedComponent = "Kernel I/O Driver"
        })
    }

    if ($DisplayHealth -and $DisplayHealth.HighRiskTimingsDetected) {
        $findings.Add([PSCustomObject]@{
            Id                = "DISPLAY_TIMING_RISK"
            Category          = "GPU"
            Severity          = "Warning"
            PriorityScore     = 65
            Title             = "DISPLAYPORT BANDWIDTH / MONITOR SCALER INSTABILITY (EDID OVERCLOCK)"
            Description       = if ($DisplayHealth.RiskSummary) { $DisplayHealth.RiskSummary } else { "Connected display has aggressive factory overclock timings exceeding DisplayPort 1.2a / scaler bandwidth thresholds." }
            Guidance          = if ($DisplayHealth.Guidance) { $DisplayHealth.Guidance } else { "Lower monitor refresh rate (e.g. from 165Hz to 144Hz) in Windows Advanced Display Settings, or configure CVT-Reduced Blanking (CVT-RB) in Custom Resolution Utility (CRU) to reduce pixel clock below 580 MHz." }
            Timestamp         = (Get-Date)
            AffectedComponent = "Display EDID Timings"
        })
    }

    if ($ZombieProcesses -and $ZombieProcesses.Count -gt 0) {
        $findings.Add([PSCustomObject]@{
            Id                = "ZOMBIE_STEAM_PROCESS"
            Category          = "Application"
            Severity          = "Warning"
            PriorityScore     = 64
            Title             = "ACTIVE ZOMBIE / HUNG STEAM PROCESS"
            Description       = "steam.exe (PID: $($ZombieProcesses[0].PID)) is lingering headless in background, blocking the single-instance mutex and preventing relaunch."
            Guidance          = "Run '.\Analyze-LatestCrash.ps1 -KillHungSteam' or terminate steam.exe in Task Manager."
            Timestamp         = (Get-Date)
            AffectedComponent = "steam.exe"
        })
    }

    $actionCatalog = @{
        "CleanShaderCache" = [PSCustomObject]@{
            Id            = "CleanShaderCache"
            Label         = "Clear DirectX and GPU shader caches"
            Description   = "Deletes cached shaders so games rebuild them cleanly (fixes shader freezes and GPU timeouts)."
            SwitchHint    = "-CleanShaderCache"
            RequiresAdmin = $false
        }
        "RepairNetwork" = [PSCustomObject]@{
            Id            = "RepairNetwork"
            Label         = "Fix Ethernet adapter drops"
            Description   = "Turns off Packet Priority & VLAN on your network card to stop random disconnects (keeps your link speed)."
            SwitchHint    = "-RepairNetwork"
            RequiresAdmin = $true
        }
        "ExpandUdpPorts" = [PSCustomObject]@{
            Id            = "ExpandUdpPorts"
            Label         = "Expand Windows network port limit"
            Description   = "Increases available UDP ports so multiplayer games and server browsers do not lose connection."
            SwitchHint    = "-ExpandUdpPorts"
            RequiresAdmin = $true
        }
        "DisablePciePowerSavings" = [PSCustomObject]@{
            Id            = "DisablePciePowerSavings"
            Label         = "Turn off PCIe slot power saving"
            Description   = "Stops the PCIe slot from going into low-power sleep during games, preventing GPU timeouts."
            SwitchHint    = "-DisablePciePowerSavings"
            RequiresAdmin = $false
        }
        "RepairGpuSleep" = [PSCustomObject]@{
            Id            = "RepairGpuSleep"
            Label         = "Increase GPU wake timeout (8 seconds)"
            Description   = "Gives your GPU and monitor extra time to wake from sleep without crashing (no extra power use)."
            SwitchHint    = "-RepairGpuSleep"
            RequiresAdmin = $true
        }
        "KillHungSteam" = [PSCustomObject]@{
            Id            = "KillHungSteam"
            Label         = "Close stuck Steam and game processes"
            Description   = "Closes background Steam processes that are stuck and stopping games from launching."
            SwitchHint    = "-KillHungSteam"
            RequiresAdmin = $false
        }
        "CleanSteamCache" = [PSCustomObject]@{
            Id            = "CleanSteamCache"
            Label         = "Clear Steam browser cache"
            Description   = "Clears Steam's built-in browser cache and overlay state."
            SwitchHint    = "-CleanSteamCache"
            RequiresAdmin = $false
        }
        "CleanConfigCrimsonDesert" = [PSCustomObject]@{
            Id            = "CleanConfigCrimsonDesert"
            Label         = "Reset Crimson Desert crash locks and cache"
            Description   = "Backs up and clears stuck crash locks and cache files so the game can launch."
            SwitchHint    = "-CleanConfig -Game CrimsonDesert"
            RequiresAdmin = $false
        }
        "FixDrivers" = [PSCustomObject]@{
            Id            = "FixDrivers"
            Label         = "Stop Windows Update from overwriting GPU drivers"
            Description   = "Locks your GPU driver so Windows Update does not silently replace it with an older version."
            SwitchHint    = "-FixDrivers"
            RequiresAdmin = $true
        }
        "DisableRogueDrivers" = [PSCustomObject]@{
            Id            = "DisableRogueDrivers"
            Label         = "Disable conflicting RGB / hardware monitor drivers"
            Description   = "Turns off old kernel drivers (inpoutx64 / WinRing0) that cause crashes with game anti-cheat."
            SwitchHint    = "-DisableRogueDrivers"
            RequiresAdmin = $true
        }
    }

    $findingActionMap = @{
        "STEAM_WATCHDOG_NETWORK_DROP" = @("KillHungSteam", "RepairNetwork", "ExpandUdpPorts")
        "STEAM_WATCHDOG_PIPE_STALL"   = @("KillHungSteam", "CleanSteamCache")
        "SHADER_RUNTIME_CRASH"        = @("CleanShaderCache")
        "GRAPHICS_DEVICE_REMOVED"     = @("CleanShaderCache", "DisablePciePowerSavings")
        "ROGUE_KERNEL_DRIVER_CRASH"   = @("DisableRogueDrivers")
        "ROGUE_KERNEL_DRIVER_HAZARD"  = @("DisableRogueDrivers")
        "APP_ACCESS_VIOLATION"        = @("CleanShaderCache")
        "CRIMSON_DESERT_CRASH"        = @("CleanShaderCache", "CleanConfigCrimsonDesert")
        "CRIMSON_DESERT_APP_HANG"     = @("CleanShaderCache", "CleanConfigCrimsonDesert")
        "PCIE_WHEA_ERROR"             = @("DisablePciePowerSavings")
        "PCIE_ASPM_INSTABILITY"       = @("DisablePciePowerSavings")
        "GPU_TDR_WAKE_FROM_SLEEP"     = @("RepairGpuSleep", "CleanShaderCache")
        "GPU_TDR_PCIE_ASPM"           = @("DisablePciePowerSavings", "CleanShaderCache")
        "GPU_TDR_TIMEOUT"             = @("CleanShaderCache")
        "PCI_NIC_RESET_LINK_DROP"     = @("RepairNetwork", "ExpandUdpPorts")
        "PCI_DEVICE_RESET"            = @("RepairNetwork")
        "NETWORK_LINK_DROP"           = @("RepairNetwork")
        "UDP_PORT_EXHAUSTION"         = @("ExpandUdpPorts")
        "UDP_PORT_SPACE_CONSTRAINED"  = @("ExpandUdpPorts")
        "DUAL_GPU_MISMATCH"           = @("FixDrivers")
        "ZOMBIE_STEAM_PROCESS"        = @("KillHungSteam")
    }

    $sortedFindings = @($findings | Sort-Object -Property PriorityScore -Descending)
    $recommendedActions = [System.Collections.Generic.List[object]]::new()
    $seenActionIds = @{}
    foreach ($f in $sortedFindings) {
        $rawParts = @($f.Guidance -split '(?:\r?\n\s*(?:\*|\d+\.)\s*)|(?:\s+\*\s+)|(?:^\s*(?:\*|\d+\.)\s*)' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $cleanSteps = [System.Collections.Generic.List[string]]::new()
        foreach ($p in $rawParts) { $cleanSteps.Add($p.Trim()) }
        $f | Add-Member -NotePropertyName Steps -NotePropertyValue @($cleanSteps) -Force

        $fActions = [System.Collections.Generic.List[object]]::new()
        if ($findingActionMap.ContainsKey($f.Id)) {
            foreach ($actId in $findingActionMap[$f.Id]) {
                if ($actionCatalog.ContainsKey($actId)) {
                    $actObj = $actionCatalog[$actId]
                    $fActions.Add($actObj)
                    if (-not $seenActionIds.ContainsKey($actId)) {
                        $seenActionIds[$actId] = $true
                        $recommendedActions.Add($actObj)
                    }
                }
            }
        }
        $f | Add-Member -NotePropertyName Actions -NotePropertyValue @($fActions) -Force
    }

    if ($sortedFindings.Count -gt 0) {
        $primary = $sortedFindings[0]
        $secondary = if ($sortedFindings.Count -gt 1) { @($sortedFindings[1..($sortedFindings.Count - 1)]) } else { @() }
        $guidanceText = $primary.Guidance
        if ($ZombieProcesses -and $ZombieProcesses.Count -gt 0 -and $primary.Id -ne "ZOMBIE_STEAM_PROCESS") {
            $guidanceText += "`n  * Post-Crash Cleanup: steam.exe (PID: $($ZombieProcesses[0].PID)) is currently stuck as a zombie process from this crash; run '.\Analyze-LatestCrash.ps1 -KillHungSteam' to terminate it before relaunching Steam."
        }
        return [PSCustomObject]@{
            PrimaryFinding       = $primary
            SecondaryFindings    = $secondary
            Findings             = $sortedFindings
            RecommendedActions   = @($recommendedActions)
            RootCauseTitle       = $primary.Title
            RootCauseDescription = $primary.Description
            RootCauseGuidance    = $guidanceText
            RootCauseSeverity    = $primary.Severity
        }
    }

    # Healthy fallback when no rules matched
    $defaultDesc = if ($ScanMode -eq "LatestIncidentClean") {
        "Scanned backward $MaxLookbackDays days across crash dumps, game engine logs, and event telemetry. No crash minidumps, GPU driver timeouts (TDR 4101), BSOD bugchecks, or unexpected shutdowns were detected."
    } else {
        "No critical hardware faults, GPU driver crashes, or unhandled exceptions detected in the scan window."
    }
    $defaultGuidance = if ($ScanMode -eq "LatestIncidentClean") {
        "Your system has had no recorded crash dumps or driver timeouts in the past $MaxLookbackDays days. If you are experiencing in-game stutters or disconnects, check Tier 4 hardware health and game server status."
    } elseif ($ScanMode -eq "LatestIncident" -and $IncidentAnchor) {
        "Telemetry surrounding the latest incident ($($IncidentAnchor.Timestamp.ToString('yyyy-MM-dd HH:mm'))) reports no cascading hardware faults. If game crashes persist, verify game file integrity."
    } else {
        "Your system is reporting normal stability telemetry. If you experienced a game crash, it may have terminated cleanly without writing a dump or occurred outside the current analysis window."
    }

    $healthyFinding = [PSCustomObject]@{
        Id                = "SYSTEM_HEALTHY"
        Category          = "System"
        Severity          = "Healthy"
        PriorityScore     = 0
        Title             = "SYSTEM HEALTHY"
        Description       = $defaultDesc
        Guidance          = $defaultGuidance
        Steps             = @($defaultGuidance)
        Actions           = @()
        Timestamp         = (Get-Date)
        AffectedComponent = "System"
    }

    return [PSCustomObject]@{
        PrimaryFinding       = $healthyFinding
        SecondaryFindings    = @()
        Findings             = @($healthyFinding)
        RecommendedActions   = @()
        RootCauseTitle       = $healthyFinding.Title
        RootCauseDescription = $healthyFinding.Description
        RootCauseGuidance    = $healthyFinding.Guidance
        RootCauseSeverity    = $healthyFinding.Severity
    }
}

Set-Alias -Name Invoke-DcResolvedTimeoutAnalysis -Value Find-DcResolvedIncidentHistory

Export-ModuleMember -Function Get-DcFastStartupStatus, Get-DcSystemTelemetry, Get-DcEventXmlData, Get-DcWinEventsTargeted, Get-DcBugCheckMeaning, Get-DcGraphicsDriverSettings, Get-DcPciePowerManagementStatus, Find-DcLatestIncident, Get-DcWerReportArchive, Get-DcRegistryKeyLastWriteTime, Get-DcSystemChangeHistory, Find-DcResolvedIncidentHistory, Resolve-DcDiagnosticFindings, Protect-DcTelemetryText -Alias Invoke-DcResolvedTimeoutAnalysis
