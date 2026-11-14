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
        '0x0*1A'       { "MEMORY_MANAGEMENT" }
        '0x0*4E'       { "PFN_LIST_CORRUPT" }
        '0x0*116'      { "VIDEO_TDR_ERROR" }
        '0x0*119'      { "VIDEO_SCHEDULER_INTERNAL_ERROR" }
        '0x0*193'      { "VIDEO_DXGKRNL_LIVEDUMP" }
        '0x0*141'      { "VIDEO_ENGINE_TDR_TIMEOUT" }
        '0x0*117'      { "VIDEO_TDR_TIMEOUT_DETECTED" }
        '0x0*9F'       { "DRIVER_POWER_STATE_FAILURE" }
        '0x0*3B'       { "SYSTEM_SERVICE_EXCEPTION" }
        '0x0*50'       { "PAGE_FAULT_IN_NONPAGED_AREA" }
        '0x10*7E'      { "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED" }
        '0x0*7E'       { "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED" }
        '0x0*124'      { "WHEA_UNCORRECTABLE_ERROR" }
        '0x0*D1'       { "DRIVER_IRQL_NOT_LESS_OR_EQUAL" }
        '0x0*133'      { "DPC_WATCHDOG_VIOLATION" }
        '0x0*139'      { "KERNEL_SECURITY_CHECK_FAILURE" }
        '0x0*1E'       { "KMODE_EXCEPTION_NOT_HANDLED" }
        '0x0*A'        { "IRQL_NOT_LESS_OR_EQUAL" }
        '0x0*93'       { "INVALID_KERNEL_HANDLE" }
        '0x0*EF'       { "CRITICAL_PROCESS_DIED" }
        '0x0*154'      { "UNEXPECTED_STORE_EXCEPTION" }
        '0x0*15E'      { "BUGCODE_NDIS_DRIVER_LIVE_DUMP" }
        default        { "Kernel BugCheck ($CodeHex)" }
    }
}

function Get-DcBugCheckExplanation {
    param(
        [string]$CodeHex,
        [string]$Param1 = $null
    )

    $cleanCode = if ($CodeHex) { $CodeHex.ToLower().Trim() } else { "" }
    $p1Hex = if ($Param1) { $Param1.ToLower().Trim() } else { "" }

    switch -Regex ($cleanCode) {
        '0x0*1a' {
            if ($p1Hex -match '0x0*6000\b') {
                return "Subtype 0x6000 (MEMORY_MANAGEMENT): Windows detected a corrupted page while reading compressed memory or paging data back from disk/store (MiStoreFaultComplete). This can happen from RAM/memory-controller instability, a storage/NVMe wake hiccup, or stale memory state across idle/sleep."
            } else {
                return "Windows kernel memory management detected an invalid page table, pool corruption, or store/page fault (MEMORY_MANAGEMENT)."
            }
        }
        '0x0*4e' {
            return "Windows detected corruption in the Physical Frame Number (PFN) table tracking RAM pages (PFN_LIST_CORRUPT). Typically points to a buggy kernel driver, corrupted page/sleep transition, or memory instability."
        }
        '0x0*119' {
            if ($p1Hex -match '0x0*5\b') {
                return "Subtype 0x5: The DirectX video scheduler detected that a GPU driver command submission timed out and could not be recovered by the driver scheduler."
            } elseif ($p1Hex -match '0x0*1\b') {
                return "Subtype 0x1: The driver failed to submit a command within the allotted time."
            } elseif ($p1Hex -match '0x0*2\b') {
                return "Subtype 0x2: The driver failed to preempt a GPU execution context."
            } elseif ($p1Hex -match '0x0*3\b') {
                return "Subtype 0x3: The driver was unable to schedule a DMA buffer."
            } elseif ($p1Hex -match '0x0*400\b') {
                return "Subtype 0x400: The video memory manager detected an invalid memory operation."
            } else {
                return "The DirectX graphics kernel subsystem (dxgkrnl.sys / dxgmms2.sys) detected an unrecoverable scheduler condition or GPU driver submission timeout."
            }
        }
        '0x0*3b' {
            if ($p1Hex -match '0x0*c0000005\b') {
                return "An unhandled memory access violation (0xC0000005) occurred while executing kernel-mode system service code (a driver or kernel function attempted to read or write an invalid memory address)."
            } else {
                return "An unhandled exception occurred while executing a kernel system service routine."
            }
        }
        '0x0*116' {
            return "The display driver failed to respond to a GPU reset or watchdog timeout in a timely manner (VIDEO_TDR_ERROR)."
        }
        '0x0*141' {
            return "A GPU engine hung and timed out, triggering a live kernel recovery (VIDEO_ENGINE_TDR_TIMEOUT)."
        }
        '0x0*117' {
            return "A video timeout was detected on a display adapter (VIDEO_TDR_TIMEOUT_DETECTED)."
        }
        '0x0*9f' {
            return "A driver failed to handle a power state transition IRP within the timeout period, often during sleep, wake, or device power down (DRIVER_POWER_STATE_FAILURE)."
        }
        '0x0*124' {
            return "A fatal hardware error was detected by the Windows Hardware Error Architecture (CPU bus error, PCIe device fault, or memory error)."
        }
        '0x0*133' {
            return "A single Deferred Procedure Call (DPC) ran past its timeout or the system spent too much time at DISPATCH_LEVEL IRQL, hanging the OS scheduler (DPC_WATCHDOG_VIOLATION)."
        }
        '0x0*139' {
            return "A kernel component detected corruption of a critical data structure (buffer overflow or stack cookie failure) (KERNEL_SECURITY_CHECK_FAILURE)."
        }
        '0x0*50' {
            return "Invalid system memory was referenced by a kernel driver in a non-paged area (PAGE_FAULT_IN_NONPAGED_AREA)."
        }
        '0x0*d1' {
            return "A kernel driver accessed pageable memory at an elevated Interrupt Request Level (DRIVER_IRQL_NOT_LESS_OR_EQUAL)."
        }
        '0x10*7e' {
            if ($p1Hex -match '0x0*c0000005\b') {
                return "A kernel system thread hit an unhandled memory access violation (0xC0000005, SYSTEM_THREAD_EXCEPTION_NOT_HANDLED) — a driver or OS thread read or wrote an invalid pointer."
            } else {
                return "A system thread generated an exception that the error handler did not catch (SYSTEM_THREAD_EXCEPTION_NOT_HANDLED)."
            }
        }
        '0x0*7e' {
            return "A system thread generated an exception that the error handler did not catch (SYSTEM_THREAD_EXCEPTION_NOT_HANDLED)."
        }
        '0x0*1e' {
            return "A kernel-mode program generated an unhandled exception (KMODE_EXCEPTION_NOT_HANDLED)."
        }
        '0x0*ef' {
            return "A critical Windows process stopped unexpectedly (CRITICAL_PROCESS_DIED)."
        }
        '0x0*154' {
            return "The kernel memory store caught an unexpected I/O or page decompression error (UNEXPECTED_STORE_EXCEPTION), often pointing to an NVMe/SSD wake issue or storage driver hiccup."
        }
        '0x0*15e' {
            return "Non-fatal NDIS network miniport live kernel dump (BUGCODE_NDIS_DRIVER_LIVE_DUMP): Windows detected a network buffer (NBL) leak or miniport stall, captured a diagnostic live dump, and continued running without rebooting."
        }
        default {
            $m = Get-DcBugCheckMeaning $CodeHex
            return "Windows kernel crash ($m)."
        }
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
            "Fast Startup is enabled (HiberbootEnabled = 1)."
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
        $pcfg = & powercfg /query SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 2>$null
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
                $aspmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$($result.SchemeGuid)\501a4d13-42af-4429-9fd1-a8218c268e20\ee12f906-d277-404b-b6da-e5fa1a576df5"
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
        $result.RiskExplanation = "PCI Express Link State Power Management (ASPM) is set to '$settingText' in the active '$($result.SchemeName)' power plan."
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

    $overlayTestMode = $null
    try {
        $dwmPath = "HKLM:\SOFTWARE\Microsoft\Windows\Dwm"
        if (Test-Path $dwmPath) {
            $dwmProps = Get-ItemProperty -Path $dwmPath -ErrorAction SilentlyContinue
            if ($dwmProps -and $dwmProps.PSObject.Properties['OverlayTestMode']) {
                $overlayTestMode = $dwmProps.OverlayTestMode
            }
        }
    } catch {}

    return [PSCustomObject]@{
        TdrDelay        = $tdrDelay
        TdrLevel        = $tdrLevel
        TdrDdiDelay     = $tdrDdiDelay
        HwSchMode       = $hwSchMode
        HAGSStatus      = $hagsStatus
        IsUlpsEnabled   = $ulpsEnabled
        OverlayTestMode = $overlayTestMode
        IsMpoDisabled   = ($overlayTestMode -eq 5)
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

    $isElevated = $false
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($id)
        $isElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}

    $results = [PSCustomObject]@{
        CutoffTime             = $Cutoff
        EndTime                = $EndTime
        IsElevated             = $isElevated
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
        WerAppReports          = [System.Collections.Generic.List[PSCustomObject]]::new()
        WerKernelEvents        = [System.Collections.Generic.List[PSCustomObject]]::new()
        NetworkDrops           = [System.Collections.Generic.List[PSCustomObject]]::new()
        UdpPortExhaustions     = [System.Collections.Generic.List[PSCustomObject]]::new()
        TopUdpConsumers        = [System.Collections.Generic.List[PSCustomObject]]::new()
        StuckServices          = [System.Collections.Generic.List[PSCustomObject]]::new()
        PciDeviceResets        = [System.Collections.Generic.List[PSCustomObject]]::new()
        WlanFailovers          = [System.Collections.Generic.List[PSCustomObject]]::new()
        SleepTransitions       = [System.Collections.Generic.List[PSCustomObject]]::new()
        CpuThrottlingEvents    = [System.Collections.Generic.List[PSCustomObject]]::new()
        DisplayHotplugEvents   = [System.Collections.Generic.List[PSCustomObject]]::new()
        TdrWorkloads           = [System.Collections.Generic.List[PSCustomObject]]::new()
        DcomTimeouts           = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    # Query System Events within time window using targeted Event ID batches (20x faster than full-log scan)
    $targetSysIds = @(
        1, 7, 9, 11, 14, 15, 17, 18, 19, 20, 26, 27, 32,
        33, 37, 41, 46, 47, 51, 129, 153, 154, 157, 219, 1001,
        4101, 4227, 4231, 4266, 5002, 5005, 5007, 6008, 10029, 10400
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
            # Logged solely to UdpPortExhaustions so port pressure is not misreported as a physical NIC link drop.
            if ($e.Id -in @(4266, 4227, 4231) -and $e.ProviderName -match 'Tcpip') {
                if ($results.UdpPortExhaustions.Count -lt 10) {
                    $results.UdpPortExhaustions.Add([PSCustomObject]@{
                        TimeCreated = $e.TimeCreated
                        Id          = $e.Id
                        Provider    = $e.ProviderName
                        Message     = "Global TCP/IP dynamic port space exhausted (Event $($e.Id)): $msgText"
                    })
                }
            }

            # 2. GPU Driver TDR Resets (Event 4101 or display driver stop)
            if ($e.Id -eq 4101 -or ($e.ProviderName -match 'Display|amdkmdag|nvlddmkm|igfx' -and $msgText -match 'stopped responding')) {
                $results.TdrEvents.Add([PSCustomObject]@{
                    TimeCreated    = $e.TimeCreated
                    Id             = $e.Id
                    Provider       = $e.ProviderName
                    Code           = "4101"
                    CompanionCodes = [System.Collections.Generic.List[string]]::new()
                    DumpPath       = ""
                    Meaning        = "Display Driver Stopped Responding and Successfully Recovered (Event 4101)"
                    Message        = $msgText
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
                    WatsonBucket  = $null
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
                $pbTs = 0
                if ($xmlData['PowerButtonTimestamp']) { try { $pbTs = [int64]$xmlData['PowerButtonTimestamp'] } catch {} }
                $pbTime = $null
                if ($pbTs -gt 0) { try { $pbTime = [datetime]::FromFileTime($pbTs) } catch {} }
                $longPress = ($xmlData['LongPowerButtonPressDetected'] -eq 'true')
                $sleepIn = ($xmlData['SleepInProgress'] -and $xmlData['SleepInProgress'] -ne '0' -and $xmlData['SleepInProgress'] -ne 'false')
                $bcParams = @($xmlData['BugcheckParameter1'], $xmlData['BugcheckParameter2'], $xmlData['BugcheckParameter3'], $xmlData['BugcheckParameter4']) -join ', '

                $facts = [System.Collections.Generic.List[string]]::new()
                if ($bugCode -ne 0) {
                    $facts.Add(("Bugcheck stop code 0x{0:X} recorded before shutdown." -f $bugCode))
                } else {
                    $facts.Add("System rebooted without a clean shutdown (BugcheckCode 0). No crash dump was written; this indicates an abrupt power loss, hard reset, or system freeze.")
                }
                if ($pbTime) { $facts.Add("Power button was pressed at $($pbTime.ToString('yyyy-MM-dd HH:mm:ss')).") }
                if ($longPress) { $facts.Add("Long power-button press (hard reset) was detected.") }
                if ($sleepIn) { $facts.Add("System was entering or resuming from sleep when power was interrupted.") }

                $results.AbruptReboots.Add([PSCustomObject]@{
                    TimeCreated          = $e.TimeCreated
                    Id                   = $e.Id
                    Provider             = $e.ProviderName
                    BugcheckCode         = $bugCode
                    PowerButtonTimestamp = $pbTime
                    LongPowerButtonPress = $longPress
                    SleepInProgress      = [bool]$sleepIn
                    Message              = ($facts -join ' ')
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

            # 9. DistributedCOM Activation Timeouts (Event 10029 - e.g. Hung BcastDVRUserService Game Bar capture)
            if ($e.Id -eq 10029 -and $e.ProviderName -match 'DistributedCOM') {
                if ($results.DcomTimeouts.Count -lt 10) {
                    $results.DcomTimeouts.Add([PSCustomObject]@{
                        TimeCreated = $e.TimeCreated
                        Id          = $e.Id
                        Provider    = $e.ProviderName
                        Message     = $msgText
                    })
                }
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
            $rawMsg = if ($me.Message) { $me.Message.Trim() } else { "" }
            $topConsumers = [System.Collections.Generic.List[string]]::new()
            foreach ($cm in [regex]::Matches($rawMsg, '([^\r\n,;:(]+\.exe)\s*\(\d+\)\s*consumed\s*(\d+)\s*bytes')) {
                $pName = Split-Path ($cm.Groups[1].Value.Trim()) -Leaf
                $bytes = [double]$cm.Groups[2].Value
                $gb = [math]::Round($bytes / 1GB, 1)
                if ($gb -lt 0.1) {
                    $mb = [math]::Round($bytes / 1MB, 0)
                    $topConsumers.Add("$pName ($mb MB)")
                } else {
                    $topConsumers.Add("$pName ($gb GB)")
                }
                if ($topConsumers.Count -ge 3) { break }
            }
            $results.MemoryExhaustion.Add([PSCustomObject]@{
                TimeCreated  = $me.TimeCreated
                Id           = $me.Id
                Provider     = $me.ProviderName
                TopConsumers = @($topConsumers)
                Message      = (Protect-DcTelemetryText $rawMsg)
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

    # Query Microsoft-Windows-WerKernel/Operational (Events 1001, 1002) for exact second-level live dump timestamps & component names
    $werKernelByFile = @{}
    $werKernelByMinute = @{}
    try {
        $wkFilter = @{LogName='Microsoft-Windows-WerKernel/Operational'; Id=@(1001, 1002); StartTime=$Cutoff}
        if ($EndTime -and $EndTime -lt (Get-Date)) { $wkFilter['EndTime'] = $EndTime }
        $wkEvents = Get-WinEvent -FilterHashtable $wkFilter -ErrorAction SilentlyContinue
        if ($wkEvents) {
            foreach ($wke in $wkEvents) {
                $wkMsg = if ($wke.Message) { [string]$wke.Message } else { "" }
                $wkComp = if ($wkMsg -match 'Component\s+([A-Za-z0-9_.\-]+)') { $Matches[1].Trim() } else { $null }
                $wkFile = $null
                if ($wkMsg -match '(?<file>[A-Za-z0-9_]+-(?<tag>\d{8}-\d{4})\.dmp)') {
                    $wkFile = $Matches['file']
                    $dmpFileKey = $wkFile.ToLower()
                    $minTagKey = $Matches['tag']
                    if (-not $werKernelByFile.ContainsKey($dmpFileKey)) {
                        $werKernelByFile[$dmpFileKey] = $wke.TimeCreated
                    }
                    if (-not $werKernelByMinute.ContainsKey($minTagKey)) {
                        $werKernelByMinute[$minTagKey] = $wke.TimeCreated
                    }
                }
                if ($wkComp -or $wkFile) {
                    $wkCode = ""
                    if ($wkMsg -match '(?i)BugCheck(?:Code)?\s*[:=]\s*(?:0x)?([0-9a-fA-F]+)') {
                        $wkCode = ($Matches[1].ToLower() -replace '^0+(?=.)', '')
                    } elseif ($wkFile -match '(?i)^WATCHDOG-' -or $wkComp -match '(?i)^WATCHDOG') {
                        $wkCode = "141"
                    } elseif ($wkFile -match '(?i)^AMD_WATCHDOG-' -or $wkComp -match '(?i)^AMD_WATCHDOG') {
                        $wkCode = "a1000001"
                    } elseif ($wkFile -match '(?i)^AMD_REPORT_UM-' -or $wkComp -match '(?i)^AMD_REPORT_UM') {
                        $wkCode = "a2000002"
                    } elseif ($wkFile -match '(?i)DXGKRNL' -or $wkComp -match '(?i)ProcessDeadlockThread' -or $wkMsg -match '(?i)\b0x193\b') {
                        $wkCode = "193"
                    }
                    $results.WerKernelEvents.Add([PSCustomObject]@{
                        TimeCreated = $wke.TimeCreated
                        Id          = $wke.Id
                        Code        = $wkCode
                        Component   = $wkComp
                        DumpFile    = $wkFile
                        Message     = (Protect-DcTelemetryText $wkMsg.Trim())
                    })
                }
            }
        }
    } catch {}

    # Query Application Events for LiveKernelEvent TDRs, BlueScreen Watson buckets, AMD Watchdog Hangs & RADAR_PRE_LEAK (Event 1001)
    $werFilter = @{LogName='Application'; ProviderName='Windows Error Reporting'; Id=1001; StartTime=$Cutoff}
    if ($EndTime -and $EndTime -lt (Get-Date)) { $werFilter['EndTime'] = $EndTime }
    $werEvents1001 = @(Get-WinEvent -FilterHashtable $werFilter -ErrorAction SilentlyContinue)

    # Correlate Watson cloud buckets from WER Event 1001 BlueScreen entries onto KernelBugChecks (non-admin friendly!)
    if ($werEvents1001.Count -gt 0 -and $results.KernelBugChecks.Count -gt 0) {
        $werBlueScreens = @($werEvents1001 | Where-Object { $_.Message -match 'Event Name:\s*BlueScreen' })
        foreach ($wbs in $werBlueScreens) {
            $wbMsg = [string]$wbs.Message
            $bucket = $null
            if ($wbMsg -match 'Fault bucket\s+([^\r\n,]+?)\s*,\s*type\s+\d+') {
                $candBucket = $Matches[1].Trim()
                if ($candBucket -and $candBucket -ne '0') { $bucket = $candBucket }
            }
            if (-not $bucket) { continue }
            $bsCode = if ($wbMsg -match 'P1:\s*([a-fA-F0-9]+)') { $Matches[1].ToLower() -replace '^0+', '' } else { '' }
            foreach ($bc in $results.KernelBugChecks) {
                if ($bc.WatsonBucket) { continue }
                $bcNorm = ($bc.Code -replace '^0x', '').ToLower() -replace '^0+', ''
                $codeMatches = (-not $bsCode) -or (-not $bcNorm) -or ($bsCode -eq $bcNorm)
                if ($codeMatches -and [math]::Abs(($bc.TimeCreated - $wbs.TimeCreated).TotalMinutes) -le 15) {
                    $bc.WatsonBucket = $bucket
                    break
                }
            }
        }
    }

    $werLiveEvents = @($werEvents1001 | Where-Object { $_.Message -match 'LiveKernelEvent' })
    if ($werLiveEvents.Count -gt 0) {
        $tdrPriority = @{
            '193'      = 60
            '141'      = 50
            '117'      = 45
            '1b8'      = 40
            '1a8'      = 35
            'a1000001' = 20
            'a2000002' = 10
            '4101'     = 5
        }

        foreach ($we in $werLiveEvents) {
            $p1 = ""
            if ($we.Message -match 'P1:\s*([a-fA-F0-9]+)') { $p1 = $Matches[1].ToLower() }
            $watsonBucket = $null
            if ($we.Message -match 'Fault bucket\s+([^\r\n,]+?)\s*,\s*type\s+\d+') {
                $cand = $Matches[1].Trim()
                if ($cand -and $cand -ne '0') { $watsonBucket = $cand }
            }

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
                    $bestPath = $candidateLines | Where-Object { $_ -match '\d{8}-\d{4}' -and $_ -match '(?i)\.(dmp|wer|mdmp)$' } | Select-Object -First 1
                    if (-not $bestPath) {
                        $bestPath = $candidateLines | Where-Object { $_ -match '(?i)\.(dmp|wer|mdmp)$' } | Select-Object -First 1
                    }
                    if (-not $bestPath -and $candidateLines.Count -gt 0) {
                        $bestPath = $candidateLines[0]
                    }
                    if ($bestPath) {
                        $attachedFile = Protect-DcTelemetryText $bestPath
                        $matchedExact = $false
                        if ($attachedFile -match '(?<file>[A-Za-z0-9_]+-(?<tag>\d{8}-\d{4})\.dmp)') {
                            $dmpFileKey = $Matches['file'].ToLower()
                            $minTagKey = $Matches['tag']
                            if ($werKernelByFile.ContainsKey($dmpFileKey)) {
                                $dumpTime = $werKernelByFile[$dmpFileKey]
                                $matchedExact = $true
                            } elseif ($werKernelByMinute.ContainsKey($minTagKey)) {
                                $dumpTime = $werKernelByMinute[$minTagKey]
                                $matchedExact = $true
                            }
                        } elseif ($attachedFile -match '(?<tag>\d{8}-\d{4})') {
                            $minTagKey = $Matches['tag']
                            if ($werKernelByMinute.ContainsKey($minTagKey)) {
                                $dumpTime = $werKernelByMinute[$minTagKey]
                                $matchedExact = $true
                            }
                        }
                        if (-not $matchedExact -and $attachedFile -match '(?<year>\d{4})(?<month>\d{2})(?<day>\d{2})-(?<hour>\d{2})(?<min>\d{2})') {
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
                        '141'      { "LiveKernelEvent 0x141 (VIDEO_ENGINE_TIMEOUT_DETECTED)" }
                        '117'      { "LiveKernelEvent 0x117 (VIDEO_TDR_TIMEOUT_DETECTED)" }
                        '193'      {
                            if ($we.Message -match 'P2:\s*(?:0x)?0*810\b') {
                                "LiveKernelEvent 0x193 (VIDEO_DXGKRNL_LIVEDUMP, P2=0x810 ProcessDeadlockThread)"
                            } else {
                                "LiveKernelEvent 0x193 (VIDEO_DXGKRNL_LIVEDUMP)"
                            }
                        }
                        'a1000001' { "LiveKernelEvent 0xA1000001 (vendor-defined code)" }
                        'a2000002' { "LiveKernelEvent 0xA2000002 (vendor-defined code)" }
                        default    { "LiveKernelEvent 0x$p1" }
                    }

                    $companionMatch = $results.TdrEvents | Where-Object { [math]::Abs(($_.TimeCreated - $dumpTime).TotalSeconds) -le 60 } | Select-Object -First 1
                    if ($null -eq $companionMatch) {
                        $results.TdrEvents.Add([PSCustomObject]@{
                            TimeCreated    = $dumpTime
                            Id             = 1001
                            Provider       = "Windows Error Reporting (LiveKernelEvent)"
                            Code           = $p1
                            CompanionCodes = [System.Collections.Generic.List[string]]::new()
                            DumpPath       = $attachedFile
                            WatsonBucket   = $watsonBucket
                            Meaning        = $meaning
                            Message        = "$meaning [Dump: $attachedFile]"
                        })
                    } elseif ($companionMatch.Code -ne $p1) {
                        $currPrio = if ($tdrPriority.ContainsKey($companionMatch.Code)) { $tdrPriority[$companionMatch.Code] } else { 1 }
                        $newPrio = if ($tdrPriority.ContainsKey($p1)) { $tdrPriority[$p1] } else { 1 }
                        if (-not $companionMatch.PSObject.Properties['CompanionCodes'] -or $null -eq $companionMatch.CompanionCodes) {
                            $companionMatch | Add-Member -NotePropertyName CompanionCodes -NotePropertyValue ([System.Collections.Generic.List[string]]::new()) -Force
                        }
                        if ($newPrio -gt $currPrio) {
                            $oldTag = "0x$($companionMatch.Code.ToUpper())"
                            if (-not $companionMatch.CompanionCodes.Contains($oldTag)) {
                                $companionMatch.CompanionCodes.Add($oldTag)
                            }
                            $companionMatch.Code = $p1
                            $companionMatch.Meaning = $meaning
                            if ($attachedFile) { $companionMatch.DumpPath = $attachedFile }
                            if ($watsonBucket) { $companionMatch.WatsonBucket = $watsonBucket }
                            $companionMatch.TimeCreated = $dumpTime
                        } else {
                            $newTag = "0x$($p1.ToUpper())"
                            if (-not $companionMatch.CompanionCodes.Contains($newTag)) {
                                $companionMatch.CompanionCodes.Add($newTag)
                            }
                        }
                        $compNote = if ($companionMatch.CompanionCodes.Count -gt 0) { " [Companion dumps: $($companionMatch.CompanionCodes -join ', ')]" } else { "" }
                        $companionMatch.Message = "$($companionMatch.Meaning)$compNote [Dump: $($companionMatch.DumpPath)]"
                    }
                }
            }
        }
    }

    # Populate readable WER AppCrash / AppHang archives (works WITHOUT Admin) and backfill AppCrashes
    try {
        $werArch = @(Get-DcWerReportArchive -Cutoff $Cutoff -EndTime $EndTime)
        foreach ($wr in $werArch) {
            if (-not $wr.MetadataOnly -and $wr.EventType -match '(?i)APPCRASH|BEX|CLR20r3|AppHang|MoAppHang|MoAppCrash') {
                $results.WerAppReports.Add($wr)
                if ($wr.EventType -match '(?i)APPCRASH|BEX|CLR20r3|MoAppCrash' -and $wr.AppName) {
                    $dupApp = @($results.AppCrashes | Where-Object {
                        $_.Application -ieq $wr.AppName -and [math]::Abs(($_.TimeCreated - $wr.Timestamp).TotalSeconds) -le 15
                    })
                    if ($dupApp.Count -eq 0 -and $results.AppCrashes.Count -lt 25) {
                        $modLabel = if ($wr.FaultModule) { $wr.FaultModule } elseif ($wr.Parameter4) { $wr.Parameter4 } else { "Unknown" }
                        $excVal = if ($wr.ExceptionCode) { $wr.ExceptionCode } else { "Unknown" }
                        $results.AppCrashes.Add([PSCustomObject]@{
                            TimeCreated       = $wr.Timestamp
                            Application       = $wr.AppName
                            FaultingModule    = $modLabel
                            FaultModuleOffset = $wr.ExceptionOffset
                            ExceptionCode     = $excVal
                            ExceptionMeaning  = Get-DcBugCheckMeaning $excVal
                            IsOverlayFault    = [bool]$wr.IsOverlayFault
                            IsUnloadedModule  = [bool]$wr.IsUnloadedModule
                            WatsonBucket      = $wr.Bucket
                            Message           = "WER Archive $($wr.EventType): $($wr.AppName) faulted in $modLabel$(if ($wr.ExceptionOffset) { "+0x$($wr.ExceptionOffset -replace '^0x','')" }) ($excVal)"
                        })
                    }
                }
            }
        }
    } catch {}

    if ($results.TdrEvents.Count -gt 1) {
        $sortedTdrs = @($results.TdrEvents | Sort-Object TimeCreated -Descending)
        $results.TdrEvents.Clear()
        foreach ($st in $sortedTdrs) { $results.TdrEvents.Add($st) }
    }

    # Query Kernel-PnP Device Management Event 1010 for Display / Audio Surprise-Removal (Hotplug / HPD drop)
    try {
        $pnpMgmtFilter = @{LogName='Microsoft-Windows-Kernel-PnP/Device Management'; Id=1010; StartTime=$Cutoff}
        if ($EndTime -and $EndTime -lt (Get-Date)) { $pnpMgmtFilter['EndTime'] = $EndTime }
        $pnpSurpriseEvents = Get-WinEvent -FilterHashtable $pnpMgmtFilter -ErrorAction SilentlyContinue
        if ($pnpSurpriseEvents) {
            foreach ($pse in $pnpSurpriseEvents) {
                $xmlData = Get-DcEventXmlData -EventRecord $pse
                $devId = if ($xmlData['DeviceInstanceId']) { $xmlData['DeviceInstanceId'] }
                         elseif ($pse.Message -match 'Device instance ID:\s*([^\r\n]+)') { $Matches[1].Trim() }
                         elseif ($pse.Message -match 'Device\s+([^\s]+)\s+has been surprise removed') { $Matches[1].Trim() }
                         else { "" }
                if ($devId -match '^(?i)(DISPLAY\\|SWD\\MMDEVAPI\\|HDAUDIO\\)') {
                    $isDisplayNode = ($devId -match '^(?i)DISPLAY\\')
                    $existingHotplug = @($results.DisplayHotplugEvents | Where-Object {
                        [math]::Abs(($_.TimeCreated - $pse.TimeCreated).TotalSeconds) -le 5
                    })
                    if ($existingHotplug.Count -eq 0) {
                        $labelType = if ($isDisplayNode) { "Display monitor" } else { "Display/Audio endpoint" }
                        $results.DisplayHotplugEvents.Add([PSCustomObject]@{
                            TimeCreated      = $pse.TimeCreated
                            Id               = $pse.Id
                            DeviceInstanceId = $devId
                            IsDisplayMonitor = $isDisplayNode
                            Message          = "$labelType surprise-removed (Kernel-PnP Event 1010: $devId) - DisplayPort/HDMI link loss or monitor HPD drop."
                        })
                    } elseif ($isDisplayNode -and -not $existingHotplug[0].IsDisplayMonitor) {
                        $existingHotplug[0].DeviceInstanceId = $devId
                        $existingHotplug[0].IsDisplayMonitor = $true
                        $existingHotplug[0].Message = "Display monitor surprise-removed (Kernel-PnP Event 1010: $devId) - DisplayPort/HDMI link loss or monitor HPD drop."
                    }
                }
            }
        }
    } catch {}

    # Correlate Active GPU Compute / Benchmark Workloads Prior to TDRs (WER RADAR_PRE_LEAK + PowerShell Event 400)
    if ($results.TdrEvents.Count -gt 0) {
        if ($werEvents1001.Count -gt 0) {
            $radarEvents = @($werEvents1001 | Where-Object { $_.Message -match 'RADAR_PRE_LEAK' })
            foreach ($re in $radarEvents) {
                $appName = if ($re.Message -match 'P1:\s*([^\r\n]+)') { $Matches[1].Trim() } else { "Unknown" }
                if ($appName -and $appName -notmatch '^(?i)(svchost\.exe|explorer\.exe|SearchHost\.exe|RuntimeBroker\.exe)$') {
                    foreach ($tdr in $results.TdrEvents) {
                        $deltaSec = ($tdr.TimeCreated - $re.TimeCreated).TotalSeconds
                        if ($deltaSec -ge -60 -and $deltaSec -le 900) {
                            $dupRadar = @($results.TdrWorkloads | Where-Object {
                                $_.ProcessName -ieq $appName -and [math]::Abs(($_.TdrTime - $tdr.TimeCreated).TotalSeconds) -le 60
                            })
                            if ($dupRadar.Count -eq 0) {
                                $results.TdrWorkloads.Add([PSCustomObject]@{
                                    TimeCreated = $re.TimeCreated
                                    TdrTime     = $tdr.TimeCreated
                                    ProcessName = $appName
                                    CommandLine = ""
                                    Source      = "WER RADAR_PRE_LEAK_64"
                                    Message     = "Heavy memory/GPU process '$appName' active near TDR at $($tdr.TimeCreated.ToString('HH:mm:ss')) (WER RADAR_PRE_LEAK_64)."
                                })
                            }
                            break
                        }
                    }
                }
            }
        }

        try {
            $psFilter = @{LogName='Windows PowerShell'; Id=400; StartTime=$Cutoff}
            if ($EndTime -and $EndTime -lt (Get-Date)) { $psFilter['EndTime'] = $EndTime }
            $psEvents = Get-WinEvent -FilterHashtable $psFilter -ErrorAction SilentlyContinue
            if ($psEvents) {
                foreach ($pe in $psEvents) {
                    if ($pe.Message -match 'HostApplication=(?<cmd>[^\r\n]+)') {
                        $rawCmd = $Matches['cmd'].Trim()
                        if ($rawCmd -match '(?i)(gpubench|--dump-isa|RayScheduling|furmark|3dmark|blender|dxc\.exe|glslc\.exe)') {
                            $safeCmd = Protect-DcTelemetryText $rawCmd
                            $exeMatches = @([regex]::Matches($rawCmd, '(?i)([a-z0-9_\-]+\.exe)') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -notmatch '^(?i)(powershell|pwsh|cmd|conhost)\.exe$' })
                            $procLabel = if ($exeMatches.Count -gt 0) { $exeMatches[0] } else { "GPU Compute CLI" }
                            foreach ($tdr in $results.TdrEvents) {
                                $deltaSec = ($tdr.TimeCreated - $pe.TimeCreated).TotalSeconds
                                if ($deltaSec -ge -15 -and $deltaSec -le 300) {
                                    $dupWl = @($results.TdrWorkloads | Where-Object {
                                        $_.ProcessName -ieq $procLabel -and [math]::Abs(($_.TdrTime - $tdr.TimeCreated).TotalSeconds) -le 60
                                    })
                                    if ($dupWl.Count -gt 0) {
                                        if (-not $dupWl[0].CommandLine) {
                                            $dupWl[0].CommandLine = $safeCmd
                                            $dupWl[0].Source = "PowerShell Event 400 + WER RADAR"
                                            $dupWl[0].Message = "Active GPU compute/benchmark workload '$procLabel' ($safeCmd) started $([math]::Round($deltaSec))s before TDR at $($tdr.TimeCreated.ToString('HH:mm:ss'))."
                                        }
                                    } else {
                                        $results.TdrWorkloads.Add([PSCustomObject]@{
                                            TimeCreated = $pe.TimeCreated
                                            TdrTime     = $tdr.TimeCreated
                                            ProcessName = $procLabel
                                            CommandLine = $safeCmd
                                            Source      = "Windows PowerShell Event 400"
                                            Message     = "Active GPU compute/benchmark workload '$procLabel' ($safeCmd) started $([math]::Round($deltaSec))s before TDR at $($tdr.TimeCreated.ToString('HH:mm:ss'))."
                                        })
                                    }
                                    break
                                }
                            }
                        }
                    }
                }
            }
        } catch {}
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

            $precedingLinkDrop = @($results.NetworkDrops | Where-Object {
                $_.Reason -eq "Hardware Link Disconnect" -and
                ($ne.TimeCreated - $_.TimeCreated).TotalSeconds -ge -15 -and
                ($ne.TimeCreated - $_.TimeCreated).TotalSeconds -le 60
            })
            $isSilentDmaHang = ($reason -match 'SuspectArpProbeFailed' -and $precedingLinkDrop.Count -eq 0)
            $dropMsg = if ($isSilentDmaHang) {
                "Network Internet capability dropped to None (Reason: $reason - Silent TX/RX DMA Hang without physical link disconnect) on $ifaceName."
            } else {
                "Network Internet capability dropped to None (Reason: $reason) on $ifaceName."
            }

            $results.NetworkDrops.Add([PSCustomObject]@{
                TimeCreated     = $ne.TimeCreated
                Id              = $ne.Id
                Provider        = "NCSI"
                InterfaceGuid   = $ifaceGuid
                InterfaceName   = $ifaceName
                Reason          = $reason
                IsSilentDmaHang = $isSilentDmaHang
                Message         = $dropMsg
            })
        }
    }

    # Attribute Top Active UDP Endpoint Consumers when Ephemeral Port Exhaustion (Event 4266) occurred
    if ($results.UdpPortExhaustions.Count -gt 0) {
        try {
            $udpEps = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
            if ($udpEps) {
                $groupedUdp = $udpEps | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 5
                foreach ($g in $groupedUdp) {
                    $procId = [int]$g.Name
                    if ($procId -le 4) { continue }
                    $procObj = Get-Process -Id $procId -ErrorAction SilentlyContinue
                    $procName = if ($procObj) { "$($procObj.ProcessName).exe" } else { "PID $procId" }
                    $results.TopUdpConsumers.Add([PSCustomObject]@{
                        ProcessName   = $procName
                        PID           = $procId
                        EndpointCount = $g.Count
                    })
                }
            }
        } catch {}
    }

    # Check for Services Stuck in StopPending / StartPending (e.g., BcastDVRUserService Game Bar capture hangs)
    try {
        $stuckSvcs = Get-CimInstance Win32_Service -Filter "State = 'Stop Pending' or State = 'Start Pending'" -ErrorAction SilentlyContinue
        if ($stuckSvcs) {
            foreach ($ss in $stuckSvcs) {
                $dcomSuffix = if ($results.DcomTimeouts.Count -gt 0) { " ($($results.DcomTimeouts.Count) DCOM Event 10029 timeout(s) logged)" } else { "" }
                $results.StuckServices.Add([PSCustomObject]@{
                    Name        = $ss.Name
                    DisplayName = $ss.DisplayName
                    State       = $ss.State
                    ProcessId   = $ss.ProcessId
                    Message     = "Service '$($ss.Name)' ($($ss.DisplayName)) is stuck in '$($ss.State)' (PID: $($ss.ProcessId))$dcomSuffix."
                })
            }
        }
    } catch {}

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

    $overlayWerRegex = '(?i)^(NahimicOSD|A-Volute|SonicStudio|RTSSHooks|RTSSVkLayer|DiscordHook|GameOverlayRenderer|obs-vulkan|obs-graphics|Overwolf|OWClient|ReShade|SpecialK|MedalHook|MedalEncoder|nvspcap|bdcam|fraps|dxtory|playclaw|Action_x64)'

    foreach ($baseDir in $searchDirs) {
        $candidateFolders = [System.Collections.Generic.List[System.IO.DirectoryInfo]]::new()
        $directWer = Join-Path $baseDir "Report.wer"
        if (Test-Path -LiteralPath $directWer -ErrorAction SilentlyContinue) {
            try {
                $baseInfo = [System.IO.DirectoryInfo]::new($baseDir)
                $candidateFolders.Add($baseInfo)
            } catch {}
        }

        $topDirs = Get-ChildItem -LiteralPath $baseDir -Directory -ErrorAction SilentlyContinue
        if ($topDirs) {
            foreach ($d in $topDirs) {
                if ($d.Name -match '(?i)^(Kernel_|LiveKernel|AppCrash_|AppHang_|Critical_)') {
                    $candidateFolders.Add($d)
                } elseif ($CustomArchivePaths) {
                    $nestedDirs = Get-ChildItem -LiteralPath $d.FullName -Directory -Recurse -ErrorAction SilentlyContinue
                    if ($nestedDirs) {
                        foreach ($nd in $nestedDirs) {
                            if ($nd.Name -match '(?i)^(Kernel_|LiveKernel|AppCrash_|AppHang_|Critical_)') {
                                $candidateFolders.Add($nd)
                            }
                        }
                    }
                }
            }
        }

        foreach ($dirObj in $candidateFolders) {
            try {
                $parentName = $dirObj.Name
                if ($parentName -notmatch '(?i)^(Kernel_|LiveKernel|AppCrash_|AppHang_|Critical_)') {
                    continue
                }

                if (-not $CustomArchivePaths -and $dirObj.LastWriteTime -lt $Cutoff.AddDays(-1)) {
                    continue
                }

                $werFullPath = Join-Path $dirObj.FullName "Report.wer"
                $lines = $null
                $aclBlocked = $false

                try {
                    $fs = [System.IO.FileStream]::new(
                        $werFullPath,
                        [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::Read,
                        ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
                    )
                    try {
                        $sr = [System.IO.StreamReader]::new($fs, $true)
                        $lineList = [System.Collections.Generic.List[string]]::new()
                        while ($null -ne ($rawLn = $sr.ReadLine())) {
                            $lineList.Add($rawLn)
                        }
                        $lines = $lineList.ToArray()
                    } finally {
                        $fs.Dispose()
                    }
                } catch [System.UnauthorizedAccessException] {
                    $aclBlocked = $true
                } catch [System.Security.SecurityException] {
                    $aclBlocked = $true
                } catch [System.IO.FileNotFoundException] {
                    continue
                } catch [System.IO.DirectoryNotFoundException] {
                    continue
                } catch {
                    if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match '(?i)denied|unauthorized') {
                        $aclBlocked = $true
                    } else {
                        continue
                    }
                }

                if ($aclBlocked) {
                    if ($dirObj.LastWriteTime -lt $Cutoff -or $dirObj.LastWriteTime -gt $EndTime) {
                        continue
                    }
                    $codeFromName = if ($parentName -match '(?i)^(?:Live)?Kernel_([0-9a-fA-F]+)_') { $Matches[1].ToLower() } else { "" }
                    $isTdrMeta = ($codeFromName -in @('141', '117', '193', 'a1000001', 'a2000002', '1b8', '1a8'))
                    $metaType = if ($codeFromName) { "LiveKernelEvent" } else { "CriticalEvent" }
                    $metaFriendly = if ($codeFromName) { "Live Kernel Event 0x$codeFromName (ACL metadata only)" } else { "Critical System WER Folder (ACL metadata only)" }

                    $reports.Add([PSCustomObject]@{
                        ReportPath         = (Protect-DcTelemetryText $dirObj.FullName)
                        FolderName         = $parentName
                        Timestamp          = $dirObj.LastWriteTime
                        EventType          = $metaType
                        FriendlyEventName  = $metaFriendly
                        AppName            = ""
                        AppPath            = ""
                        BugCheckOrCode     = $codeFromName
                        Parameter1         = $codeFromName
                        Parameter2         = ""
                        Parameter3         = ""
                        Parameter4         = ""
                        Bucket             = ""
                        FaultModule        = ""
                        FaultModuleVersion = ""
                        ExceptionCode      = ""
                        ExceptionOffset    = ""
                        IsOverlayFault     = $false
                        OverlayName        = ""
                        IsUnloadedModule   = $false
                        MetadataOnly       = $true
                        GpuDriverVersion   = $null
                        Signatures         = @{}
                        SignatureNames     = @{}
                        LoadedModules      = @()
                        IsTdrOrGpu         = $isTdrMeta
                    })
                    continue
                }

                if (-not $lines) { continue }

                $eventType = ""
                $friendlyName = ""
                $appName = ""
                $appPath = ""
                $bucket = ""
                $eventTime = $dirObj.LastWriteTime
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
                    } elseif ($line -match '^(?:Response\.BucketId|Bucket)=(.+)$') {
                        $bVal = Protect-DcTelemetryText $Matches[1].Trim()
                        if ($bVal -and $bVal -ne '0') { $bucket = $bVal }
                    } elseif ($line -match '^HashedBucket=(.+)$' -and -not $bucket) {
                        $hbVal = Protect-DcTelemetryText $Matches[1].Trim()
                        if ($hbVal -and $hbVal -ne '0') { $bucket = $hbVal }
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

                if (-not $p1 -and $parentName -match '(?i)^(?:Live)?Kernel_([0-9a-fA-F]+)_') {
                    $p1 = $Matches[1].ToLower()
                }

                $faultModule = ""
                $faultModuleVersion = ""
                $exceptionCode = ""
                $exceptionOffset = ""
                foreach ($sk in $sigNames.Keys) {
                    $sName = $sigNames[$sk]
                    $sVal = if ($sigs.ContainsKey($sk)) { $sigs[$sk] } else { "" }
                    if (-not $sVal) { continue }
                    if ($sName -match '(?i)^Fault(?:ing)? Module Name$') {
                        $faultModule = $sVal
                    } elseif ($sName -match '(?i)^Fault(?:ing)? Module Version$') {
                        $faultModuleVersion = $sVal
                    } elseif ($sName -match '(?i)^Exception Code$') {
                        $exceptionCode = $sVal
                    } elseif ($sName -match '(?i)^Exception Offset$') {
                        $exceptionOffset = $sVal
                    } elseif ($sName -match '(?i)^Application Name$' -and -not $appName) {
                        $appName = $sVal
                    }
                }
                if (-not $faultModule -and ($eventType -match '(?i)APPCRASH|BEX') -and (-not $sigNames.ContainsKey('3')) -and $sigs.ContainsKey('3')) {
                    $faultModule = $sigs['3']
                    if ($sigs.ContainsKey('4')) { $faultModuleVersion = $sigs['4'] }
                    if ($sigs.ContainsKey('6')) { $exceptionCode = $sigs['6'] }
                    if ($sigs.ContainsKey('7')) { $exceptionOffset = $sigs['7'] }
                }

                $isUnloadedMod = [bool]($faultModule -match '(?i)_unloaded$|^<Unloaded_')
                $faultModClean = $faultModule -replace '(?i)_unloaded$', '' -replace '^<Unloaded_|>$', ''
                $isOverlay = $false
                $overlayFriendly = ""
                if ($faultModClean -match $overlayWerRegex) {
                    $isOverlay = $true
                    $overlayFriendly = switch -Regex ($faultModClean) {
                        '(?i)NahimicOSD|A-Volute|SonicStudio' { "Nahimic / A-Volute OSD" }
                        '(?i)RTSSHooks|RTSSVkLayer'          { "RivaTuner (RTSS) Overlay" }
                        '(?i)DiscordHook'                    { "Discord In-Game Overlay" }
                        '(?i)GameOverlayRenderer'            { "Steam Game Overlay" }
                        '(?i)obs-vulkan|obs-graphics'        { "OBS Game Capture Hook" }
                        '(?i)Overwolf|OWClient'              { "Overwolf Overlay" }
                        '(?i)ReShade'                        { "ReShade Post-Processing" }
                        '(?i)SpecialK'                       { "Special K Hook" }
                        '(?i)Medal'                          { "Medal.tv Overlay" }
                        '(?i)nvspcap'                        { "NVIDIA ShadowPlay Overlay" }
                        default                              { $faultModClean }
                    }
                }

                $werGpuDrvVer = $null
                $drvModCheck = if ($faultModule) { $faultModule } else { $p4 }
                if ($sigs.ContainsKey('4') -and ($drvModCheck -match '(?i)amdkmdag|amdxc|amdhdl|atidxx|nvlddmkm|nvwgf2|igdkmd|amdvlk') -and ($sigs['4'] -match '^\d+\.\d+\.\d+\.\d+$')) {
                    $werGpuDrvVer = $sigs['4']
                }

                $isTdrOrGpu = (
                    ($eventType -match '(?i)LiveKernelEvent' -and $p1 -in @('141', '117', '193', 'a1000001', 'a2000002', '1b8', '1a8')) -or
                    ($parentName -match '(?i)^(?:Live)?Kernel_(141|117|193|a1000001|a1000002|a2000002|1b8|1a8)_') -or
                    ($eventType -match '(?i)APPCRASH|BEX64' -and ($drvModCheck -match '(?i)amdkmdag|amdxc|amdhdl|atidxx|nvlddmkm|nvwgf2|igdkmd|amdvlk|dxgi|d3d12|d3d11'))
                )

                $cleanReportPath = Protect-DcTelemetryText $werFullPath
                $cleanAppPath = Protect-DcTelemetryText $appPath

                $reports.Add([PSCustomObject]@{
                    ReportPath         = $cleanReportPath
                    FolderName         = $parentName
                    Timestamp          = $eventTime
                    EventType          = $eventType
                    FriendlyEventName  = $friendlyName
                    AppName            = $appName
                    AppPath            = $cleanAppPath
                    BugCheckOrCode     = $p1
                    Parameter1         = $p1
                    Parameter2         = $p2
                    Parameter3         = $p3
                    Parameter4         = $p4
                    Bucket             = $bucket
                    FaultModule        = $faultModule
                    FaultModuleVersion = $faultModuleVersion
                    ExceptionCode      = $exceptionCode
                    ExceptionOffset    = $exceptionOffset
                    IsOverlayFault     = $isOverlay
                    OverlayName        = $overlayFriendly
                    IsUnloadedModule   = $isUnloadedMod
                    MetadataOnly       = $false
                    GpuDriverVersion   = $werGpuDrvVer
                    Signatures         = $sigs
                    SignatureNames     = $sigNames
                    LoadedModules      = @($loadedMods)
                    IsTdrOrGpu         = $isTdrOrGpu
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

    # 1. Tier 1: Check newest fatal crash dump file (excluding non-fatal LiveKernelReports)
    try {
        if (Get-Command Get-DcLatestDumpFile -ErrorAction SilentlyContinue) {
            $latestDump = Get-DcLatestDumpFile -LookbackDays $MaxLookbackDays -ExcludeLiveKernelReports
            if ($latestDump) {
                $candidates.Add([PSCustomObject]@{
                    Timestamp = $latestDump.LastWriteTime
                    Tier      = 1
                    Source    = "Minidump File"
                    Details   = "$($latestDump.Name) ($([math]::Round($latestDump.Length / 1MB, 2)) MB)"
                    Item      = $latestDump
                })
            }

            $latestLiveDump = Get-DcLatestDumpFile -LookbackDays $MaxLookbackDays -LiveKernelReportsOnly
            if ($latestLiveDump) {
                $candidates.Add([PSCustomObject]@{
                    Timestamp = $latestLiveDump.LastWriteTime
                    Tier      = 2
                    Source    = "Live Kernel Report (Non-Fatal)"
                    Details   = "$($latestLiveDump.Name) ($([math]::Round($latestLiveDump.Length / 1MB, 2)) MB - non-fatal live dump)"
                    Item      = $latestLiveDump
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
        $wkByFile = @{}
        $wkByMinute = @{}
        try {
            $wkEvs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WerKernel/Operational'; Id=@(1001, 1002); StartTime=$lookbackCutoff} -ErrorAction SilentlyContinue
            if ($wkEvs) {
                foreach ($wke in $wkEvs) {
                    if ($wke.Message -match '(?<file>[A-Za-z0-9_]+-(?<tag>\d{8}-\d{4})\.dmp)') {
                        $fKey = $Matches['file'].ToLower()
                        $tKey = $Matches['tag']
                        if (-not $wkByFile.ContainsKey($fKey)) { $wkByFile[$fKey] = $wke.TimeCreated }
                        if (-not $wkByMinute.ContainsKey($tKey)) { $wkByMinute[$tKey] = $wke.TimeCreated }
                    }
                }
            }
        } catch {}

        $liveEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Windows Error Reporting'; Id=1001; StartTime=$lookbackCutoff} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'LiveKernelEvent' -and $_.Message -match 'P1:\s*(141|117|193|a1000001|a2000002|1b8|1a8)\b' }
        if ($liveEvents) {
            $codePrio = @{ '193'=60; '141'=50; '117'=45; '1b8'=40; '1a8'=35; 'a1000001'=20; 'a2000002'=10 }
            $bestLiveCand = $null
            $bestLivePrio = 0
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
                    $bestPath = $candidateLines | Where-Object { $_ -match '\d{8}-\d{4}' -and $_ -match '(?i)\.(dmp|wer|mdmp)$' } | Select-Object -First 1
                    if (-not $bestPath) {
                        $bestPath = $candidateLines | Where-Object { $_ -match '(?i)\.(dmp|wer|mdmp)$' } | Select-Object -First 1
                    }
                    if (-not $bestPath -and $candidateLines.Count -gt 0) { $bestPath = $candidateLines[0] }
                    if ($bestPath) {
                        $matchedWk = $false
                        if ($bestPath -match '(?<file>[A-Za-z0-9_]+-(?<tag>\d{8}-\d{4})\.dmp)') {
                            $fKey = $Matches['file'].ToLower()
                            $tKey = $Matches['tag']
                            if ($wkByFile.ContainsKey($fKey)) { $evTime = $wkByFile[$fKey]; $matchedWk = $true }
                            elseif ($wkByMinute.ContainsKey($tKey)) { $evTime = $wkByMinute[$tKey]; $matchedWk = $true }
                        } elseif ($bestPath -match '(?<tag>\d{8}-\d{4})') {
                            $tKey = $Matches['tag']
                            if ($wkByMinute.ContainsKey($tKey)) { $evTime = $wkByMinute[$tKey]; $matchedWk = $true }
                        }
                        if (-not $matchedWk -and $bestPath -match '(?<year>\d{4})(?<month>\d{2})(?<day>\d{2})-(?<hour>\d{2})(?<min>\d{2})') {
                            try {
                                $evTime = [datetime]::new(
                                    [int]$Matches['year'], [int]$Matches['month'], [int]$Matches['day'],
                                    [int]$Matches['hour'], [int]$Matches['min'], 0
                                )
                            } catch {}
                        }
                    }
                }
                if ($evTime -ge $lookbackCutoff) {
                    $thisPrio = if ($codePrio.ContainsKey($p1Code)) { $codePrio[$p1Code] } else { 1 }
                    if ($null -eq $bestLiveCand) {
                        $bestLiveCand = [PSCustomObject]@{
                            Timestamp = $evTime
                            Tier      = 3
                            Source    = "GPU LiveKernelEvent TDR (0x$p1Code)"
                            Details   = "LiveKernelEvent 0x$p1Code GPU Watchdog Timeout"
                            Item      = $liveEv
                        }
                        $bestLivePrio = $thisPrio
                    } else {
                        $deltaSec = ($evTime - $bestLiveCand.Timestamp).TotalSeconds
                        if ($deltaSec -gt 60 -or ([math]::Abs($deltaSec) -le 60 -and $thisPrio -gt $bestLivePrio)) {
                            $bestLiveCand = [PSCustomObject]@{
                                Timestamp = $evTime
                                Tier      = 3
                                Source    = "GPU LiveKernelEvent TDR (0x$p1Code)"
                                Details   = "LiveKernelEvent 0x$p1Code GPU Watchdog Timeout"
                                Item      = $liveEv
                            }
                            $bestLivePrio = $thisPrio
                        }
                    }
                }
            }
            if ($bestLiveCand) {
                $candidates.Add($bestLiveCand)
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

    # 11. Tier 3: Physical Network Adapter Link Drop / Port Exhaustion / Silent NCSI ARP Drop (Events 27, 32, 4266, 4042)
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
        $ncsiEv = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NCSI/Operational'; Id=4042; StartTime=$lookbackCutoff} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'SuspectArpProbeFailed|Capability:\s*None' } |
            Select-Object -First 1
        if ($ncsiEv) {
            $candidates.Add([PSCustomObject]@{
                Timestamp = $ncsiEv.TimeCreated
                Tier      = 3
                Source    = "Network ARP Probe / Capability Drop (NCSI Event 4042)"
                Details   = $ncsiEv.Message.Trim()
                Item      = $ncsiEv
            })
        }
    } catch {}

    if ($candidates.Count -gt 0) {
        $ranked = $candidates | ForEach-Object {
            $pri = if ($_.Source -match 'Network Adapter Link Drop|Network ARP Probe') {
                3
            } elseif ($_.Source -match 'Live Kernel Report \(Non-Fatal\)|Virtual Memory Exhaustion|Application Crash|PCI Bus Device Reset') {
                2
            } else {
                1
            }
            [PSCustomObject]@{
                Candidate = $_
                Priority  = $pri
            }
        }
        $latest = (
            $ranked |
                Sort-Object -Property @{ Expression = 'Priority'; Ascending = $true }, @{ Expression = { $_.Candidate.Timestamp }; Descending = $true } |
                Select-Object -First 1
        ).Candidate
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
                $aspmKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$($pcieStatus.SchemeGuid)\501a4d13-42af-4429-9fd1-a8218c268e20\ee12f906-d277-404b-b6da-e5fa1a576df5"
                $aspmWriteTime = Get-DcRegistryKeyLastWriteTime -RegistryPath $aspmKey
            }
            $changes.Add([PSCustomObject]@{
                Timestamp = $aspmWriteTime
                Category  = "PowerMitigation"
                Source    = "Power Scheme ($($pcieStatus.SchemeName))"
                Title     = "PCIe Link State Power Management (ASPM) Disabled (Off)"
                Version   = $null
                Details   = "PCIe ASPM ACSettingIndex=0 (Off) prevents L0s/L1 bus wake latency spikes that trigger TDR 4101 / 0x141 timeouts and 2.5GbE NIC DMA hangs."
            })
        }

        # 5b-2. NetAdapterCx Idle Power-Down Disabled on Ethernet Class Key
        $netClassKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
        if (Test-Path $netClassKey) {
            $netSubKeys = Get-ChildItem -Path $netClassKey -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' }
            foreach ($nsk in $netSubKeys) {
                $np = Get-ItemProperty -Path $nsk.PSPath -ErrorAction SilentlyContinue
                if ($np -and $np.'*IdleRestriction' -eq "1" -and $np.ULPMode -eq "0") {
                    $nskWriteTime = Get-DcRegistryKeyLastWriteTime -RegistryPath $nsk.PSPath
                    $changes.Add([PSCustomObject]@{
                        Timestamp = $nskWriteTime
                        Category  = "PowerMitigation"
                        Source    = "Registry ($($nsk.PSPath))"
                        Title     = "NetAdapterCx Idle Power-Down & ULP Disabled ($($np.DriverDesc))"
                        Version   = $null
                        Details   = "*IdleRestriction=1, ULPMode=0, ReduceSpeedOnPowerDown=$($np.ReduceSpeedOnPowerDown) prevents 5-second idle power-down TX/RX DMA hangs on $($np.DriverDesc)."
                    })
                    break
                }
            }
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
    <#
    .SYNOPSIS
        Evidence-only event summarizer. Reports what was observed, when, and from which source.
    .DESCRIPTION
        Deliberately makes NO causal claims and gives NO remediation advice. Temporal proximity is
        not causation, and a crash dump that names a module does not establish why that module failed.
        Output is ordered by time (newest first), never by a hard-coded "probability" score.
        Evidence the tool could not read is reported explicitly instead of being silently skipped.
    #>
    [CmdletBinding()]
    param(
        [object[]]$ParsedDumps = @(),
        [PSCustomObject]$Telemetry,
        [PSCustomObject]$GpuHealth,
        [object[]]$PnpIssues = @(),
        [PSCustomObject]$MotherboardHealth,
        [PSCustomObject]$DisplayHealth,
        [PSCustomObject]$KernelDriverHealth,
        [object[]]$NetworkHealth = @(),
        [object[]]$ZombieProcesses = @(),
        [string]$ScanMode = "LatestIncident",
        [int]$MaxLookbackDays = 30,
        [PSCustomObject]$IncidentAnchor,
        [object[]]$SteamGameSessions = @(),
        [string[]]$UnreadableSources = @(),
        [object[]]$EngineLogs = @(),
        [object[]]$SteamLogs = @()
    )

    $tel = $Telemetry
    $isElevatedTel = [bool]($tel -and $tel.PSObject.Properties['IsElevated'] -and $tel.IsElevated)
    $getEvents = {
        param([string]$Name)
        if ($tel -and $tel.PSObject.Properties[$Name] -and $tel.$Name) { return @($tel.$Name) }
        return @()
    }
    $fmt = { param($t) if ($t -is [datetime]) { $t.ToString('yyyy-MM-dd HH:mm:ss') } else { 'unknown time' } }
    $getGpuDriverNote = {
        param($IncidentTime, [string]$ModuleHint = '')
        if (-not $GpuHealth -or -not $GpuHealth.PSObject.Properties['Gpus'] -or -not $GpuHealth.Gpus) { return $null }
        $gCands = @($GpuHealth.Gpus | Where-Object { $_ -and -not ($_.PSObject.Properties['IsGeneric'] -and $_.IsGeneric) })
        if ($gCands.Count -eq 0) { $gCands = @($GpuHealth.Gpus | Where-Object { $_ }) }
        if ($gCands.Count -eq 0) { return $null }
        if ($ModuleHint) {
            $vh = if ($ModuleHint -match '(?i)amd|ati') { 'AMD' } elseif ($ModuleHint -match '(?i)nvlddm|nvwgf|nvoglv|nvd3d|nvidia') { 'NVIDIA' } elseif ($ModuleHint -match '(?i)igdkmd|igd|igfx|intel') { 'Intel' } else { '' }
            if ($vh) {
                $vm = @($gCands | Where-Object { $_.Vendor -ieq $vh })
                if ($vm.Count -gt 0) { $gCands = $vm }
            }
        }
        $selGpu = ($gCands | Sort-Object @{ Expression = {
            $s = 0
            if ($_.PSObject.Properties['IsHighBoostCard'] -and $_.IsHighBoostCard) { $s += 20 }
            if ($_.Name -match '(?i)\b(RX\s*\d|RTX\s*\d|GTX\s*\d|Radeon\s+PRO|Quadro|Arc\s+[AB]\d|XT\b|XTX\b|Ti\b)') { $s += 20 }
            if ($_.Name -match '(?i)^AMD Radeon\(TM\) Graphics$|^AMD Radeon Graphics$|Intel\(R\) UHD|Intel\(R\) HD Graphics|Intel\(R\) Iris') { $s -= 10 }
            $s
        }; Descending = $true } | Select-Object -First 1)
        if (-not $selGpu) { return $null }
        $lbl = if ($selGpu.PSObject.Properties['FriendlyDriverLabel'] -and $selGpu.FriendlyDriverLabel) {
            [string]$selGpu.FriendlyDriverLabel
        } elseif (Get-Command ConvertTo-DcFriendlyGpuVersion -ErrorAction SilentlyContinue) {
            (ConvertTo-DcFriendlyGpuVersion -Vendor ([string]$selGpu.Vendor) -WddmVersion ([string]$selGpu.DriverVersion) -MarketingVersion $(if ($selGpu.PSObject.Properties['MarketingVersion']) { [string]$selGpu.MarketingVersion } else { '' })).FriendlyDriverLabel
        } else {
            "$($selGpu.Vendor) GPU driver $($selGpu.DriverVersion)".Trim()
        }
        if ($IncidentTime -is [datetime] -and $selGpu.PSObject.Properties['DriverInstallDate'] -and $selGpu.DriverInstallDate -is [datetime]) {
            if (Get-Command Format-DcDriverInstallTiming -ErrorAction SilentlyContinue) {
                $tm = Format-DcDriverInstallTiming -IncidentTime $IncidentTime -InstallTime $selGpu.DriverInstallDate -DriverLabel $lbl
                if ($tm) {
                    return "$lbl (incident occurred $($tm.Phrase))"
                }
            }
            return "$lbl (installed $($selGpu.DriverInstallDate.ToString('yyyy-MM-dd HH:mm')))"
        }
        return $lbl
    }
    $observations = [System.Collections.Generic.List[PSCustomObject]]::new()

    $addObs = {
        param([string]$Id, [string]$Category, [string]$Kind, [string]$Title, [string]$Description,
              [object]$Timestamp, [string]$Component, [string]$Source)
        $observations.Add([PSCustomObject]@{
            Id                = $Id
            Category          = $Category
            Kind              = $Kind          # Crash | Event | Evidence
            Severity          = if ($Kind -eq 'Crash') { 'Critical' } elseif ($Kind -eq 'Evidence') { 'Info' } else { 'Warning' }
            PriorityScore     = 0
            Title             = $Title
            Description       = $Description
            Guidance          = ''
            Steps             = @()
            Actions           = @()
            Timestamp         = $Timestamp
            AffectedComponent = $Component
            Source            = $Source
        })
    }

    # ---- Kernel bugchecks (System log, Event 1001) ----
    $matchedDumpFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($bc in (& $getEvents 'KernelBugChecks')) {
        $dumpPathFromLog = if ($bc.Message -match 'A dump was saved in:\s*([^\r\n\.]+\.dmp)') { $Matches[1].Trim() } else { "" }
        $reportId = if ($bc.Message -match 'Report Id:\s*([a-fA-F0-9\-]+)') { $Matches[1].Trim() } else { "" }

        $p1 = ""
        if ($bc.Message -match '\((0x[0-9a-fA-F]+)') {
            $p1 = $Matches[1]
        }

        # Details: human explanation without raw hex strings
        $explanation = Get-DcBugCheckExplanation -CodeHex $bc.Code -Param1 $p1

        # Correlate with parsed dumps (never match a fatal BugCheck Event 1001 to a non-fatal LiveKernelReport)
        $matchedDump = $null
        $dumpFileName = if ($dumpPathFromLog) { Split-Path $dumpPathFromLog -Leaf } else { "" }
        if ($dumpFileName) {
            $matchedDump = @($ParsedDumps | Where-Object { $_ -and -not ($_.PSObject.Properties['IsLiveKernelReport'] -and $_.IsLiveKernelReport) -and $_.FileName -ieq $dumpFileName }) | Select-Object -First 1
        }
        if (-not $matchedDump -and $bc.TimeCreated) {
            $matchedDump = @($ParsedDumps | Where-Object { $_ -and $_.IsKernelDump -and -not ($_.PSObject.Properties['IsLiveKernelReport'] -and $_.IsLiveKernelReport) -and [Math]::Abs(($_.Timestamp - $bc.TimeCreated).TotalSeconds) -le 120 }) | Select-Object -First 1
        }

        if ($matchedDump) {
            [void]$matchedDumpFiles.Add($matchedDump.FileName)
        }

        # Dump location and local copy check
        $dumpLocationText = ""
        if ($matchedDump) {
            if ($dumpPathFromLog -and $matchedDump.FullName -ne $dumpPathFromLog) {
                $dumpLocationText = "$dumpPathFromLog (analyzed from workspace copy: $($matchedDump.FullName))"
            } else {
                $dumpLocationText = $matchedDump.FullName
            }
        } elseif ($dumpPathFromLog) {
            $dumpLocationText = $dumpPathFromLog
        } else {
            $dumpLocationText = "No dump file path recorded in event log"
        }

        $matchedHwLabel = if ($matchedDump -and $matchedDump.PSObject.Properties['HardwareId'] -and $matchedDump.HardwareId) {
            if ($matchedDump.PSObject.Properties['HardwareDeviceName'] -and $matchedDump.HardwareDeviceName) {
                "$($matchedDump.HardwareDeviceName) ($($matchedDump.HardwareId))"
            } else {
                $matchedDump.HardwareId
            }
        } else { $null }

        # Dump Diagnosis
        $diagnosisText = ""
        if ($matchedDump -and $matchedDump.CdbInspected) {
            $diagParts = [System.Collections.Generic.List[string]]::new()
            if ($matchedDump.FaultingIP) {
                $diagParts.Add("Faulting instruction/module: $($matchedDump.FaultingIP)")
            }
            if ($matchedHwLabel) {
                $diagParts.Add("Blamed hardware: $matchedHwLabel")
            }
            if ($matchedDump.ApiContext) {
                $diagParts.Add("Active stage: $($matchedDump.ApiContext)")
            }
            if ($matchedDump.FailureBucket) {
                $diagParts.Add("Failure bucket: $($matchedDump.FailureBucket)")
            }
            if ($matchedDump.ProbablyCausedBy) {
                $diagParts.Add("Probably caused by: $($matchedDump.ProbablyCausedBy)")
            }
            if ($matchedDump.BugcheckArgs -and $matchedDump.BugcheckArgs.Count -gt 0) {
                $diagParts.Add("Bugcheck args: $($matchedDump.BugcheckArgs -join ' ')")
            }
            if ($matchedDump.CallStack.Count -gt 0) {
                $topFrames = ($matchedDump.CallStack | Select-Object -First 4) -join ' -> '
                $diagParts.Add("Stack trace: $topFrames")
            }
            $diagnosisText = "Diagnosed via CDB: " + ($diagParts -join '; ') + "."
        } elseif ($dumpPathFromLog -and (Test-Path $dumpPathFromLog -ErrorAction SilentlyContinue)) {
            $watsonNote = if ($bc.PSObject.Properties['WatsonBucket'] -and $bc.WatsonBucket) { " Windows WER fault bucket: $($bc.WatsonBucket)." } else { "" }
            if ($isElevatedTel) {
                $diagnosisText = "Dump file exists at $dumpPathFromLog (install Windows SDK Debugging Tools / WinDbg to unwind kernel call stack symbols).$watsonNote"
            } else {
                $diagnosisText = "Dump file recorded at $dumpPathFromLog (decoding the full kernel call stack requires Administrator privileges).$watsonNote"
            }
        } elseif ($dumpPathFromLog -and ($dumpPathFromLog -match '(?i)C:\\WINDOWS\\Minidump')) {
            $watsonNote = if ($bc.PSObject.Properties['WatsonBucket'] -and $bc.WatsonBucket) { " Windows WER fault bucket: $($bc.WatsonBucket)." } else { "" }
            if ($isElevatedTel) {
                $diagnosisText = "Older minidump file ($dumpPathFromLog) is no longer present on disk; Windows Event Log stop code and parameters are shown.$watsonNote"
            } else {
                $diagnosisText = "Dump file recorded at $dumpPathFromLog (protected kernel dump folder requires Administrator to unwind call stack).$watsonNote"
            }
        } else {
            $watsonNote = if ($bc.PSObject.Properties['WatsonBucket'] -and $bc.WatsonBucket) { " Windows WER fault bucket: $($bc.WatsonBucket)." } else { "" }
            $diagnosisText = "Dump file was not found on disk or could not be accessed.$watsonNote"
        }

        # Key Information from Logs
        $keyInfoParts = [System.Collections.Generic.List[string]]::new()
        $keyInfoParts.Add("Stop Code: $($bc.Code) ($($bc.Meaning))")
        if ($matchedHwLabel) { $keyInfoParts.Add("Blamed Hardware: $matchedHwLabel") }
        if ($reportId) { $keyInfoParts.Add("Report ID: $reportId") }
        if ($bc.PSObject.Properties['WatsonBucket'] -and $bc.WatsonBucket) { $keyInfoParts.Add("Fault Bucket: $($bc.WatsonBucket)") }

        # Correlate nearby events. Event 1001 is logged AFTER the reboot, so anchor on the dump's own crash time when known.
        $anchorTime = if ($matchedDump -and $matchedDump.CrashTime) { [datetime]$matchedDump.CrashTime } else { $bc.TimeCreated }
        if ($matchedDump -and $matchedDump.CrashTime) {
            $keyInfoParts.Add("Crash time (from dump): $($anchorTime.ToString('yyyy-MM-dd HH:mm:ss'))")
            if ($matchedDump.Uptime) { $keyInfoParts.Add("Uptime at crash: $($matchedDump.Uptime)") }
        }
        $bcModHint = if ($matchedDump -and $matchedDump.DebuggerModuleName) { [string]$matchedDump.DebuggerModuleName } elseif ($matchedDump -and $matchedDump.FaultingIP) { [string]$matchedDump.FaultingIP } elseif ($bc.PSObject.Properties['WatsonBucket']) { [string]$bc.WatsonBucket } else { '' }
        if ($bc.Code -match '0x0*(116|119)\b' -or $bcModHint -match '(?i)amdkmd|nvlddm|igdkmd') {
            $gpuNote = & $getGpuDriverNote $anchorTime $bcModHint
            if ($gpuNote) { $keyInfoParts.Add("Active GPU Driver: $gpuNote") }
        }
        $preEvents = [System.Collections.Generic.List[string]]::new()
        $postEvents = [System.Collections.Generic.List[string]]::new()
        $nearList = @(
            @{ Label = 'Network link drop';   Events = @(& $getEvents 'NetworkDrops') },
            @{ Label = 'Display disconnect';  Events = @(& $getEvents 'DisplayHotplugEvents') }
        )
        foreach ($grp in $nearList) {
            foreach ($ev in $grp.Events) {
                if (-not $ev.TimeCreated) { continue }
                $delta = ($anchorTime - $ev.TimeCreated).TotalSeconds   # positive = event happened before the crash
                if (-not ($matchedDump -and $matchedDump.CrashTime) -and [math]::Abs($delta) -le 300) {
                    # Crash time unknown (dump unreadable): the anchor is the post-reboot log time, so before/after cannot be determined.
                    $postEvents.Add("$($grp.Label) at $($ev.TimeCreated.ToString('HH:mm:ss')) (logged around the reboot; exact crash time unknown, so it cannot be classed as before or after the crash)")
                } elseif ($delta -ge 0 -and $delta -le 300) {
                    $preEvents.Add("$($grp.Label) at $($ev.TimeCreated.ToString('HH:mm:ss')) ($([int]$delta)s before crash)")
                } elseif ($delta -lt 0 -and $delta -ge -180) {
                    $postEvents.Add("$($grp.Label) at $($ev.TimeCreated.ToString('HH:mm:ss')) ($([int](-$delta))s AFTER crash - likely a consequence of the crash/reboot)")
                }
            }
        }
        if ($preEvents.Count -gt 0) {
            $keyInfoParts.Add("Preceding events: " + ($preEvents -join ', '))
        }
        if ($postEvents.Count -gt 0) {
            $keyInfoParts.Add("Other nearby events: " + ($postEvents -join ', '))
        }
        $keyInfoText = $keyInfoParts -join ' | '

        $formattedDesc = "Timestamp:       $(& $fmt $bc.TimeCreated)`n" +
            "Type of Issue:   Kernel Crash (BSOD) - $($bc.Meaning)`n" +
            "Details:         $explanation`n" +
            "Key Information: $keyInfoText`n" +
            "Dump Location:   $dumpLocationText`n" +
            "Dump Diagnosis:  $diagnosisText"

        & $addObs 'KERNEL_BUGCHECK' 'System' 'Crash' "Kernel bugcheck (BSOD) $($bc.Code) - $($bc.Meaning)" $formattedDesc $bc.TimeCreated "Windows kernel" 'System event log (BugCheck, Event 1001)'
    }

    # ---- Crash dump files: separate fatal crash dumps from non-fatal LiveKernelReports ----
    $dumps = @($ParsedDumps | Where-Object {
        $_ -and $_.ExceptionCode -and
        -not ($_.PSObject.Properties['IsLiveKernelReport'] -and $_.IsLiveKernelReport) -and
        -not ($_.IsKernelDump -and $matchedDumpFiles.Contains($_.FileName))
    })
    foreach ($grp in ($dumps | Group-Object { "$($_.FileName -replace '\.\d+\.dmp$','')|$($_.ExceptionCode)|$($_.FaultingIP)" })) {
        $items = @($grp.Group | Sort-Object Timestamp -Descending)
        $d = $items[0]
        $span = if ($items.Count -gt 1) { "$($items.Count) dumps, $(& $fmt $items[-1].Timestamp) to $(& $fmt $d.Timestamp)" } else { "1 dump" }
        $where = if ($d.FaultingIP) { $d.FaultingIP } else { 'faulting module not resolved' }
        $assert = if ($d.Assertions -and $d.Assertions.Count -gt 0) { " Strings found in dump: $(@($d.Assertions) -join '; ')." } else { '' }
        $apiDesc = if ($d.ApiContext) { " Active stage: $($d.ApiContext)." } else { '' }
        $stackDesc = if ($d.CallStack.Count -gt 0) { " Call stack: $(($d.CallStack | Select-Object -First 3) -join ' -> ')." } else { '' }
        $kind = if ($d.IsKernelDump) { 'kernel dump' } else { 'process dump' }

        $desc = "Timestamp:       $(& $fmt $d.Timestamp)`n" +
            "Type of Issue:   Crash Dump ($kind)`n" +
            "Details:         Exception $($d.ExceptionCode) ($($d.ExceptionMeaning)) at $where. $span.$assert`n" +
            "Dump Location:   $($d.FullName)`n" +
            "Dump Diagnosis:  $($apiDesc.Trim()) $($stackDesc.Trim())"

        & $addObs 'CRASH_DUMP' 'Dump' 'Crash' "Crash dump ($kind): $($d.FileName)" $desc $d.Timestamp $d.FaultingIP "Dump file $($d.FullName)"
    }

    $liveDumps = @($ParsedDumps | Where-Object {
        $_ -and $_.ExceptionCode -and ($_.PSObject.Properties['IsLiveKernelReport'] -and $_.IsLiveKernelReport)
    })
    $tdrEvList = @(& $getEvents 'TdrEvents')
    foreach ($grp in ($liveDumps | Group-Object { "$($_.FileName -replace '-\d{8}-\d{4}.*','')|$($_.ExceptionCode)|$($_.FaultingIP)" })) {
        $items = @($grp.Group | Sort-Object Timestamp -Descending)
        $d = $items[0]
        $coveredByTdr = $d.IsGraphicsCrash -and (@($tdrEvList | Where-Object { $_.TimeCreated -and [Math]::Abs(($_.TimeCreated - $d.Timestamp).TotalSeconds) -le 120 }).Count -gt 0)
        if ($coveredByTdr) { continue }
        $span = if ($items.Count -gt 1) { "$($items.Count) live dumps, $(& $fmt $items[-1].Timestamp) to $(& $fmt $d.Timestamp)" } else { "1 live dump" }
        $where = if ($d.FaultingIP) { $d.FaultingIP } elseif ($d.FaultingModule) { $d.FaultingModule } else { 'module not resolved' }
        $bucketTxt = if ($d.FailureBucket) { " Failure bucket: $($d.FailureBucket)." } else { '' }
        $stackDesc = if ($d.CallStack -and $d.CallStack.Count -gt 0) { " Call stack: $(($d.CallStack | Select-Object -First 3) -join ' -> ')." } else { '' }

        $desc = "Timestamp:       $(& $fmt $d.Timestamp)`n" +
            "Type of Issue:   Non-Fatal Live Kernel Report (Windows did NOT crash or reboot)`n" +
            "Details:         $($d.ExceptionCode) ($($d.ExceptionMeaning)) blaming $where. $span.`n" +
            "Dump Location:   $($d.FullName)`n" +
            "Dump Diagnosis:  $($bucketTxt.Trim()) $($stackDesc.Trim())"

        & $addObs 'LIVE_KERNEL_DUMP' 'System' 'Event' "Non-fatal live kernel report: $($d.FileName) ($($d.ExceptionCode))" $desc $d.Timestamp $where "Live kernel dump $($d.FullName)"
    }

    # ---- GPU timeout events (TDR) ----
    foreach ($t in (& $getEvents 'TdrEvents')) {
        $hasDump = $t.PSObject.Properties['DumpPath'] -and $t.DumpPath
        
        # Correlate nearby crash dumps (+/- 120s)
        $nearDumps = @($dumps | Where-Object { [Math]::Abs(($_.Timestamp - $t.TimeCreated).TotalSeconds) -le 120 })
        
        # Correlate nearby engine logs (+/- 120s)
        $nearEngine = @($EngineLogs | Where-Object { [Math]::Abs(($_.Timestamp - $t.TimeCreated).TotalSeconds) -le 120 })
        
        # Correlate active process/workload if found nearby (WER RADAR / PowerShell)
        $nearWl = @()
        if ($tel -and $tel.PSObject.Properties['TdrWorkloads'] -and $tel.TdrWorkloads) {
            $nearWl = @($tel.TdrWorkloads | Where-Object { [Math]::Abs(($_.TdrTime - $t.TimeCreated).TotalSeconds) -le 120 -or [Math]::Abs(($_.TimeCreated - $t.TimeCreated).TotalSeconds) -le 120 })
        }
        
        # Correlate active Steam game sessions
        $nearSteam = @($SteamGameSessions | Where-Object { $_.StartTime -le $t.TimeCreated -and $_.EndTime -ge $t.TimeCreated })

        $nearWerApps = @(& $getEvents 'WerAppReports' | Where-Object { $_.Timestamp -and [Math]::Abs(($_.Timestamp - $t.TimeCreated).TotalSeconds) -le 120 -and $_.EventType -notmatch '(?i)LiveKernelEvent' })
        $nearAppCrashes = @(& $getEvents 'AppCrashes' | Where-Object { $_.TimeCreated -and [Math]::Abs(($_.TimeCreated - $t.TimeCreated).TotalSeconds) -le 120 })
        $nearDispHotplug = @(& $getEvents 'DisplayHotplugEvents' | Where-Object { $_.TimeCreated -and [Math]::Abs(($_.TimeCreated - $t.TimeCreated).TotalSeconds) -le 30 })
        $nearOom = @(& $getEvents 'MemoryExhaustion' | Where-Object {
            $_.TimeCreated -and (($t.TimeCreated - $_.TimeCreated).TotalSeconds -ge -30) -and (($t.TimeCreated - $_.TimeCreated).TotalSeconds -le 180)
        })

        # 1. Determine process context
        $procDesc = ""
        $associatedProc = $null
        $associatedApiStage = $null
        if ($nearDumps.Count -gt 0) {
            $d = $nearDumps[0]
            $procName = $d.FileName -replace '\.\d+\.dmp$',''
            $associatedProc = $procName
            $associatedApiStage = $d.ApiContext
            $overlayTag = if ($d.PSObject.Properties['IsOverlayFault'] -and $d.IsOverlayFault -and $d.OverlayName) { " [Third-party overlay hook: $($d.OverlayName)]" } else { "" }
            $procDesc = "Process '$procName' crashed at $(& $fmt $d.Timestamp) ($($d.ExceptionCode): $($d.ExceptionMeaning)) inside $($d.FaultingIP).$overlayTag"
            if ($d.ApiContext) {
                $procDesc += " Thread was executing: $($d.ApiContext)."
            }
            if ($d.CallStack.Count -gt 0) {
                $topFrames = ($d.CallStack | Select-Object -First 3) -join ' -> '
                $procDesc += " Stack trace: $topFrames."
            }
        } elseif ($nearEngine.Count -gt 0) {
            $el = $nearEngine[0]
            $procName = if ($el.GameName) { $el.GameName } elseif ($el.ExecutableName) { $el.ExecutableName } else { $el.Engine }
            $associatedProc = $procName
            $cmd = if ($el.CommandLine) { " (command: '$($el.CommandLine)')" } else { "" }
            $procDesc = "Application engine log '$($el.LogName)' active at $(& $fmt $el.Timestamp) for $procName$cmd."
            if ($el.PSObject.Properties['GpuErrorCode'] -and $el.GpuErrorCode) {
                $procDesc += " GPU error code: $($el.GpuErrorCode)."
            }
            if ($el.ErrorLines.Count -gt 0) {
                $procDesc += " Engine error recorded: '$($el.ErrorLines[0])'."
            }
        } elseif ($nearWl.Count -gt 0) {
            $w = $nearWl[0]
            $associatedProc = $w.ProcessName
            if ($w.CommandLine) { $procDesc = "Heavy GPU workload '$($w.ProcessName)' (command: `"$($w.CommandLine)`") active near timeout (identified via $($w.Source))." }
            else { $procDesc = "Heavy GPU workload '$($w.ProcessName)' active near timeout (identified via $($w.Source))." }
        } elseif ($nearSteam.Count -gt 0) {
            $s = $nearSteam[0]
            $sLabel = if ($s.PSObject.Properties['GameName'] -and $s.GameName) { "$($s.GameName) (AppID $($s.AppId))" } else { "Steam AppID $($s.AppId)" }
            $associatedProc = $sLabel
            $exitNote = if ($s.PSObject.Properties['ExitedAbnormally'] -and $s.ExitedAbnormally) { " Game process exited abnormally (exit code $($s.ExitCode))." } else { "" }
            $procDesc = "Steam game session active at timeout: $sLabel (running since $($s.StartTime.ToString('HH:mm:ss'))).$exitNote"
        } elseif ($nearWerApps.Count -gt 0) {
            $wa = $nearWerApps[0]
            $associatedProc = if ($wa.AppName) { $wa.AppName } else { $wa.FolderName }
            $modInfo = if ($wa.PSObject.Properties['IsOverlayFault'] -and $wa.IsOverlayFault -and $wa.OverlayName) { " inside overlay hook $($wa.OverlayName) ($($wa.FaultModule))" } elseif ($wa.PSObject.Properties['FaultModule'] -and $wa.FaultModule) { " inside $($wa.FaultModule)" } else { "" }
            $procDesc = "Application '$associatedProc' recorded a WER crash report at $(& $fmt $wa.Timestamp)$modInfo."
        } elseif ($nearAppCrashes.Count -gt 0) {
            $ac = $nearAppCrashes[0]
            $associatedProc = $ac.AppName
            $modInfo = if ($ac.PSObject.Properties['FaultModule'] -and $ac.FaultModule) { " in $($ac.FaultModule)" } else { "" }
            $procDesc = "Application Error 1000 logged for '$associatedProc'$modInfo at $(& $fmt $ac.TimeCreated)."
        } else {
            $procDesc = "No crashed app dump or active engine log was found within 2 minutes of timeout ($($t.TimeCreated.ToString('HH:mm:ss'))). Checked Unreal/Unity/idTech/Godot/Steam logs, Steam sessions, WER app crashes, and user-mode dumps."
        }

        if ($nearDispHotplug.Count -gt 0) {
            $dhList = @($nearDispHotplug | ForEach-Object { if ($_.PSObject.Properties['DeviceInstanceId'] -and $_.DeviceInstanceId) { $_.DeviceInstanceId } elseif ($_.Message) { $_.Message } else { "Display link event" } } | Select-Object -Unique)
            $procDesc += " Correlated monitor/display hotplug (Kernel-PnP 1010) within 30s: $($dhList -join '; ')."
        }
        if ($nearOom.Count -gt 0) {
            $oomTop = if ($nearOom[0].PSObject.Properties['TopConsumers'] -and $nearOom[0].TopConsumers) { " ($($nearOom[0].TopConsumers))" } else { "" }
            $procDesc += " Windows virtual memory exhaustion (Event 2004) occurred within 3 minutes prior$oomTop."
        }

        # 2. Determine shader / pipeline info
        $tdrDelayVal = if ($tel -and $tel.PSObject.Properties['GraphicsDriverSettings'] -and $tel.GraphicsDriverSettings -and $tel.GraphicsDriverSettings.TdrDelay) { $tel.GraphicsDriverSettings.TdrDelay } else { $null }
        $tdrWindowTxt = if ($tdrDelayVal) { "$tdrDelayVal-second configured TdrDelay" } else { "2-second default TdrDelay" }
        $shaderNote = ""
        if ($associatedApiStage) {
            $shaderNote = "Active graphics pipeline stage: $associatedApiStage (watchdog threshold: $tdrWindowTxt)."
        } elseif ($nearEngine.Count -gt 0 -and ($nearEngine[0].ShaderInfo -or $nearEngine[0].Breadcrumbs)) {
            $sParts = [System.Collections.Generic.List[string]]::new()
            if ($nearEngine[0].ShaderInfo) { $sParts.Add("Active shader from engine log: $($nearEngine[0].ShaderInfo)") }
            if ($nearEngine[0].Breadcrumbs) { $sParts.Add("DRED/GPU breadcrumbs: $($nearEngine[0].Breadcrumbs)") }
            $shaderNote = ($sParts -join '; ') + " (watchdog threshold: $tdrWindowTxt)."
        } else {
            $shaderNote = "Windows watchdog threshold is $tdrWindowTxt (triggers when a GPU queue does not respond in time). Kernel Event 1001 logs the reset itself rather than the individual shader instruction."
        }

        # 3. Dump status
        $watsonTxt = if ($t.PSObject.Properties['WatsonBucket'] -and $t.WatsonBucket) { " WER bucket: $($t.WatsonBucket)." } else { "" }
        $dumpDesc = if ($hasDump) {
            $comp = if ($t.PSObject.Properties['CompanionCodes'] -and $t.CompanionCodes -and $t.CompanionCodes.Count -gt 0) { " Additional companion live dumps written within 60s: $($t.CompanionCodes -join ', ') (vendor-defined)." } else { '' }
            $elevNote = if ($isElevatedTel) { "(Use WinDbg/CDB to inspect the live hardware ringbuffer dump if deeper triage is needed.)" } else { "(Reading live hardware ringbuffer dumps directly requires an Administrator shell)." }
            "Live dump saved at: $($t.DumpPath).$comp$watsonTxt $elevNote"
        } else {
            "No live dump file path recorded in this event.$watsonTxt"
        }

        # 4. Tailored Options
        $optionsDesc = ""
        if ($associatedApiStage -match 'Compute Pipeline|Graphics Pipeline|Shader Compilation') {
            $modName = if ($nearDumps.Count -gt 0 -and $nearDumps[0].FaultingModule) { $nearDumps[0].FaultingModule } else { "the graphics pipeline" }
            $optionsDesc = "(1) The fault occurred during pipeline compilation in $modName. If developing shaders, test with standalone compilers (DXC/glslangValidator) or enable API validation layers. (2) If this occurred in a game, clear the shader cache or verify game files rather than assuming a full GPU driver reinstall is required."
        } elseif ($associatedProc) {
            $optionsDesc = "(1) Inspect application, overlay, and engine logs for '$associatedProc' around $(& $fmt $t.TimeCreated) for hung draw calls, DRED device-removed errors, or third-party overlay conflicts. (2) For Unreal/DirectX games with GPU hangs, launch with '-gpucrashdebugging' to capture exact DRED draw breadcrumbs."
        } else {
            $optionsDesc = "(1) Check running overlays/recording software and Windows memory/sleep logs around $(& $fmt $t.TimeCreated). (2) If running 3D/compute workloads or dev builds, enable API validation or DRED breadcrumbs to catch any dispatch exceeding the $tdrWindowTxt watchdog."
        }

        $tdrGpuNote = & $getGpuDriverNote $t.TimeCreated ''
        $tdrGpuLine = if ($tdrGpuNote) { "Active Driver:   $tdrGpuNote`n" } else { "" }
        $fullDesc = "Timestamp:       $(& $fmt $t.TimeCreated)`n" +
            "Type of Issue:   GPU Driver Timeout / Engine Reset (LiveKernelEvent 0x$($t.Code.ToUpper()))`n" +
            $tdrGpuLine +
            "Details:         $($t.Meaning)`n" +
            "Process Context: $procDesc`n" +
            "Shader / Stage:  $shaderNote`n" +
            "Live Dump:       $dumpDesc`n" +
            "Next Options:    $optionsDesc"

        & $addObs 'GPU_TIMEOUT_EVENT' 'GPU' 'Event' "GPU driver timeout (LiveKernelEvent 0x$($t.Code.ToUpper()))" $fullDesc $t.TimeCreated 'Display driver' 'Windows Error Reporting (LiveKernelEvent)'
    }

    # ---- Unexpected restarts ----
    # Event 41 with a non-zero BugcheckCode describes the same restart as the bugcheck (Event 1001): fold it in.
    # Event 6008 adds nothing beyond a nearby Event 41: fold it in. Both still appear if nothing else covers them.
    $bcEvents = @(& $getEvents 'KernelBugChecks')
    $ev41 = @(& $getEvents 'AbruptReboots')
    foreach ($e in $ev41) {
        $covered = ($e.BugcheckCode -ne 0) -and (@($bcEvents | Where-Object { [Math]::Abs(($_.TimeCreated - $e.TimeCreated).TotalMinutes) -le 10 }).Count -gt 0)
        if ($covered) { continue }
        $title = if ($e.BugcheckCode -ne 0) { "Unexpected restart after a bugcheck (Kernel-Power Event 41)" } else { 'Unexpected restart (Kernel-Power Event 41)' }
        & $addObs 'KERNEL_POWER_41' 'System' 'Crash' $title "$($e.Message)" $e.TimeCreated 'System' 'System event log (Kernel-Power 41)'
    }
    foreach ($e in (& $getEvents 'UnexpectedShutdowns')) {
        $has41 = @($ev41 | Where-Object { [Math]::Abs(($_.TimeCreated - $e.TimeCreated).TotalMinutes) -le 10 }).Count -gt 0
        if ($has41) { continue }
        & $addObs 'EVENTLOG_6008' 'System' 'Crash' 'Unexpected shutdown (Event 6008)' 'The event log records that the previous shutdown was not clean. No other detail is recorded in this event.' $e.TimeCreated 'System' 'System event log (Event 6008)'
    }

    # ---- Hardware error reports ----
    foreach ($e in (& $getEvents 'PcieWheaErrors')) {
        & $addObs 'WHEA_PCIE' 'Hardware' 'Event' 'WHEA PCIe error report (Event 17)' "$($e.Message)" $e.TimeCreated 'PCI Express' 'WHEA-Logger'
    }
    foreach ($e in @((& $getEvents 'WheaErrors') | Where-Object { -not $_.IsPcieError })) {
        & $addObs 'WHEA_OTHER' 'Hardware' 'Event' "WHEA hardware error report (Event $($e.Id))" "$($e.Message)" $e.TimeCreated 'Hardware' 'WHEA-Logger'
    }

    # ---- Other logged events (grouped: count + first/last) ----
    $groupDefs = @(
        @{ Name = 'MemoryExhaustion';   Id = 'COMMIT_EXHAUSTION'; Cat = 'Memory';  Title = 'Windows reported low virtual memory (Event 2004)'; Src = 'Resource-Exhaustion-Detector' },
        @{ Name = 'AppHangs';           Id = 'APP_HANG';          Cat = 'Application'; Title = 'Application hang reports (Event 1002)'; Src = 'Application log' },
        @{ Name = 'PciDeviceResets';    Id = 'PCI_RESET';         Cat = 'Hardware'; Title = 'PCI device reset events'; Src = 'Microsoft-Windows-PCI' },
        @{ Name = 'NetworkDrops';       Id = 'NET_LINK_DROP';     Cat = 'Network';  Title = 'Network link-down events'; Src = 'System event log' },
        @{ Name = 'UdpPortExhaustions'; Id = 'UDP_PORT_4266';     Cat = 'Network';  Title = 'Ephemeral port exhaustion events (Event 4266)'; Src = 'System event log' },
        @{ Name = 'CpuThrottlingEvents';Id = 'CPU_THROTTLE';      Cat = 'Hardware'; Title = 'CPU throttling events'; Src = 'System event log' }
    )
    foreach ($gd in $groupDefs) {
        $ev = @((& $getEvents $gd.Name) | Where-Object { $_.TimeCreated })
        if ($ev.Count -eq 0) { continue }
        $sorted = @($ev | Sort-Object TimeCreated -Descending)
        $sample = if ($sorted[0].PSObject.Properties['Message'] -and $sorted[0].Message) { " Most recent: $($sorted[0].Message)" } elseif ($sorted[0].PSObject.Properties['Application']) { " Most recent: $($sorted[0].Application)" } else { '' }
        $extra = ""
        if ($gd.Id -eq 'NET_LINK_DROP') {
            $matchedSess = [System.Collections.Generic.List[string]]::new()
            foreach ($dropEv in $sorted) {
                $nearS = @($SteamGameSessions | Where-Object { $_.StartTime -le $dropEv.TimeCreated -and $_.EndTime -ge $dropEv.TimeCreated })
                foreach ($ms in $nearS) {
                    $lbl = if ($ms.PSObject.Properties['GameName'] -and $ms.GameName) { "$($ms.GameName) (AppID $($ms.AppId))" } else { "AppID $($ms.AppId)" }
                    if (-not $matchedSess.Contains($lbl)) { $matchedSess.Add($lbl) }
                }
            }
            if ($matchedSess.Count -gt 0) {
                $extra += " Active Steam session during drop: $($matchedSess -join ', ')."
            }
            $pwrNotes = [System.Collections.Generic.List[string]]::new()
            foreach ($nh in @($NetworkHealth)) {
                if ($nh -and $nh.PSObject.Properties['PowerSavingSummary'] -and $nh.PowerSavingSummary) {
                    $nLabel = if ($nh.PSObject.Properties['Name'] -and $nh.Name) { $nh.Name } else { "Adapter" }
                    $pwrNotes.Add("${nLabel}: $($nh.PowerSavingSummary)")
                }
            }
            if ($pwrNotes.Count -gt 0) {
                $extra += " Adapter power settings: $($pwrNotes -join '; ')."
            }
        } elseif ($gd.Id -eq 'UDP_PORT_4266') {
            if ($tel -and $tel.PSObject.Properties['TopUdpConsumers'] -and $tel.TopUdpConsumers) {
                $topU = @($tel.TopUdpConsumers | Select-Object -First 3 | ForEach-Object { "$($_.ProcessName) ($($_.EndpointCount) endpoints)" })
                if ($topU.Count -gt 0) {
                    $extra += " Top UDP consumers: $($topU -join ', ')."
                }
            }
        }
        & $addObs $gd.Id $gd.Cat 'Event' $gd.Title "$($ev.Count) event(s), $(& $fmt $sorted[-1].TimeCreated) to $(& $fmt $sorted[0].TimeCreated).$sample$extra" $sorted[0].TimeCreated '' $gd.Src
    }

    foreach ($ss in (& $getEvents 'StuckServices')) {
        $ssName = if ($ss.PSObject.Properties['Name'] -and $ss.Name) { [string]$ss.Name } else { "Background service" }
        $ssState = if ($ss.PSObject.Properties['State'] -and $ss.State) { [string]$ss.State } else { "Stuck" }
        $ssMsg = if ($ss.PSObject.Properties['Message'] -and $ss.Message) { [string]$ss.Message } else { "Service '$ssName' is stuck in '$ssState'." }
        & $addObs 'STUCK_BACKGROUND_SERVICE' 'System' 'Event' "Background service stuck: $ssName ($ssState)" $ssMsg (Get-Date) $ssName 'Service Control Manager'
    }

    foreach ($z in $ZombieProcesses) {
        & $addObs 'STEAM_NOT_RESPONDING' 'Application' 'Event' "steam.exe (PID $($z.PID)) is currently not responding or has no window" "Observed live at scan time. Started $($z.StartTime)." (Get-Date) 'steam.exe' 'Live process inspection'
    }

    # ---- Evidence the tool could not read (single consolidated item when kernel/TDR dumps are protected) ----
    $unreadList = @($UnreadableSources | Where-Object { $_ })
    if ($unreadList.Count -gt 0) {
        $folders = @($unreadList | ForEach-Object { ($_ -split ' - ')[0] } | Select-Object -Unique)
        $folderLabel = $folders -join ', '
        $refs = @((& $getEvents 'KernelBugChecks') | ForEach-Object { if ($_.Message -match 'A dump was saved in:\s*(\S+\.dmp)') { $Matches[1] } } | Select-Object -Unique)
        $refTxt = if ($refs.Count -gt 0) { " Dumps referenced in event log: $($refs -join ', ')." } else { '' }
        $elevDesc = "Protected kernel crash dump location(s) ($folderLabel) require Administrator privileges to open.$refTxt Standard-user analysis covered all Event Logs, WER reports, Steam logs, and engine logs instead."
        & $addObs 'EVIDENCE_UNREADABLE' 'Evidence' 'Evidence' "Protected kernel dump folder(s): $folderLabel (requires Administrator to decode)" $elevDesc $null '' 'DriverCheck access check'
    }

    # ---- Next Investigation Leads ----
    $leads = [System.Collections.Generic.List[PSCustomObject]]::new()
    $addLead = {
        param([string]$Lead, [string]$BasedOn, [string]$Strength)
        $leads.Add([PSCustomObject]@{ Lead = $Lead; BasedOn = $BasedOn; Strength = $Strength })
    }
    $moduleOwner = {
        param([string]$Module)
        foreach ($dir in @((Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'System32\drivers'))) {
            $f = Join-Path $dir $Module
            if (Test-Path -LiteralPath $f -ErrorAction SilentlyContinue) {
                $vi = (Get-Item -LiteralPath $f -ErrorAction SilentlyContinue).VersionInfo
                if ($vi -and $vi.CompanyName) { return "$($vi.CompanyName), file version $($vi.FileVersion)" }
            }
        }
        return $null
    }

    # (a) Modules named at the fault address in process dumps
    $byModule = @{}
    foreach ($d in $dumps) {
        if (-not $d.FaultingIP) { continue }
        $mod = ($d.FaultingIP -split '\+')[0]
        if ($mod -match '^0x') { continue }
        if (-not $byModule.ContainsKey($mod)) { $byModule[$mod] = [System.Collections.Generic.List[object]]::new() }
        $byModule[$mod].Add($d)
    }
    foreach ($mod in $byModule.Keys) {
        $ds = @($byModule[$mod])
        $procs = @($ds | ForEach-Object { $_.FileName -replace '\.\d+\.dmp$', '' } | Select-Object -Unique)
        $sameAddr = @($ds | Select-Object -ExpandProperty FaultingIP -Unique)
        $owner = & $moduleOwner $mod
        $ownerTxt = if ($owner) { " On this machine that file reports: $owner." } else { "" }
        if ($procs.Count -ge 2 -and $sameAddr.Count -eq 1) {
            & $addLead "The same instruction address ($($sameAddr[0])) appears in $($ds.Count) dumps from $($procs.Count) different programs ($($procs -join ', ')). That pattern points toward $mod itself.$ownerTxt Attach these dumps when reporting the issue to the vendor." "$($ds.Count) dumps naming $($sameAddr[0])" 'Direct'
        } elseif ($ds.Count -ge 2 -and $sameAddr.Count -eq 1 -and $procs.Count -eq 1) {
            & $addLead "$($procs[0]) crashed $($ds.Count) times at the identical address ($($sameAddr[0])). A repeatable crash at one address indicates a deterministic fault in that code path.$ownerTxt" "$($ds.Count) dumps with the same fault address" 'Direct'
        } else {
            & $addLead "$($procs -join ', ') faulted in $mod.$ownerTxt Review the call stack leading to $mod." "Fault address $($sameAddr -join ', ')" 'Direct'
        }
    }
    foreach ($d in ($dumps | Where-Object { $_.FaultingIP -and ($_.FaultingIP -split '\+')[0] -match '^0x' } | Select-Object -First 2)) {
        & $addLead "$($d.FileName): the fault address $($d.FaultingIP) was not resolved to a module. A debugger (WinDbg/cdb) with symbols can resolve it." "Dump $($d.FileName)" 'Incomplete'
    }

    # (a2) Non-fatal live kernel dumps (separate from process/BSOD crashes)
    foreach ($ld in ($liveDumps | Select-Object -First 4)) {
        $ldMod = if ($ld.DebuggerImageName) { $ld.DebuggerImageName } elseif ($ld.DebuggerModuleName) { $ld.DebuggerModuleName } elseif ($ld.FaultingModule) { $ld.FaultingModule } elseif ($ld.FaultingIP) { (($ld.FaultingIP -split '[!+\s\(]')[0]).Trim() } else { 'unknown driver' }
        $owner = & $moduleOwner $ldMod
        $ownerTxt = if ($owner) { " On this machine that file reports: $owner." } else { "" }
        $bktTxt = if ($ld.FailureBucket) { " (bucket: $($ld.FailureBucket))" } else { "" }
        & $addLead "Non-fatal live kernel report $($ld.FileName) ($($ld.ExceptionCode)): flagged $ldMod$bktTxt — Windows captured diagnostic state and recovered without rebooting.$ownerTxt" "Live kernel dump $($ld.FileName)" 'Direct'
    }

    # (b) Kernel bugchecks
    foreach ($bc in ((& $getEvents 'KernelBugChecks') | Select-Object -First 3)) {
        $dumpPath = if ($bc.Message -match 'A dump was saved in:\s*(\S+\.dmp)') { $Matches[1] } else { $null }
        $matchedDump = if ($dumpPath) { $ParsedDumps | Where-Object { $_ -and -not ($_.PSObject.Properties['IsLiveKernelReport'] -and $_.IsLiveKernelReport) -and $_.FileName -ieq (Split-Path $dumpPath -Leaf) } | Select-Object -First 1 } else { $null }
        if ($matchedDump -and $matchedDump.CdbInspected) {
            $diagLead = "Bugcheck $($bc.Code) ($($bc.Meaning)): Call stack identified $($matchedDump.FaultingIP)."
            if ($matchedDump.PSObject.Properties['HardwareId'] -and $matchedDump.HardwareId) {
                $hwL = if ($matchedDump.PSObject.Properties['HardwareDeviceName'] -and $matchedDump.HardwareDeviceName) { "$($matchedDump.HardwareDeviceName) ($($matchedDump.HardwareId))" } else { $matchedDump.HardwareId }
                $diagLead += " Blamed hardware: $hwL."
            }
            if ($matchedDump.ApiContext) { $diagLead += " Stage: $($matchedDump.ApiContext)." }
            if ($matchedDump.FailureBucket) { $diagLead += " Failure bucket: $($matchedDump.FailureBucket)." }
            if ($matchedDump.ProbablyCausedBy) { $diagLead += " Probably caused by: $($matchedDump.ProbablyCausedBy)." }
            if ($matchedDump.RawAnalysisPath) { $diagLead += " Raw cdb output: $($matchedDump.RawAnalysisPath)." }
            & $addLead $diagLead "Dump analysis of $($matchedDump.FileName)" 'Direct'
        } else {
            $where = if ($dumpPath) { "Dump saved at $dumpPath." } else { 'No dump file named in event log.' }
            $wb = if ($bc.PSObject.Properties['WatsonBucket'] -and $bc.WatsonBucket) { " WER fault bucket: $($bc.WatsonBucket)." } else { '' }
            $adminSuffix = if (-not $isElevatedTel) {
                " Optional: inspect with WinDbg/CDB from an Administrator shell if deeper kernel call-stack symbols are needed."
            } elseif ($dumpPath -and (Test-Path $dumpPath -ErrorAction SilentlyContinue)) {
                " Optional: install WinDbg/CDB if deeper kernel call-stack symbols are needed."
            } else {
                " Minidump file is no longer retained on disk; stop code and parameters come from Windows Event 1001."
            }
            & $addLead "Bugcheck $($bc.Code) ($($bc.Meaning)): $where$wb$adminSuffix" "Bugcheck at $(& $fmt $bc.TimeCreated)" 'Direct'
        }
    }

    # (b2) GPU driver timeout live dumps on disk
    $tdrDumps = @((& $getEvents 'TdrEvents') | Where-Object { $_.PSObject.Properties['DumpPath'] -and $_.DumpPath } | Sort-Object TimeCreated -Descending | Select-Object -First 3)
    foreach ($t in $tdrDumps) {
        $nearD = @($dumps | Where-Object { [Math]::Abs(($_.Timestamp - $t.TimeCreated).TotalSeconds) -le 120 })
        $contextLead = if ($nearD.Count -gt 0 -and $nearD[0].ApiContext) {
            " Correlated with crash of '$($nearD[0].FileName -replace '\.\d+\.dmp$','')' during $($nearD[0].ApiContext)."
        } else { "" }
        & $addLead "GPU driver timeout live dump from $(& $fmt $t.TimeCreated) saved at $($t.DumpPath).$contextLead Check app/overlay/engine logs first; enable API validation layers or GPU crash breadcrumbs (e.g. DRED / '-gpucrashdebugging') to isolate hung dispatches." "GPU watchdog live dump (LiveKernelEvent 0x$($t.Code.ToUpper()))" 'Direct'
    }

    # (c) Event 41 restarts that record no bugcheck
    foreach ($e in (@($ev41 | Where-Object { $_.BugcheckCode -eq 0 }) | Select-Object -First 3)) {
        $btn = if ($e.PowerButtonTimestamp) { " A power-button timestamp is recorded ($($e.PowerButtonTimestamp.ToString('yyyy-MM-dd HH:mm:ss')))." } else { '' }
        & $addLead "System rebooted without a clean shutdown at $(& $fmt $e.TimeCreated). No bugcheck stop code was generated, indicating an abrupt power interruption or freeze.$btn Check power supply, thermal levels, and events in the minutes prior to this timestamp." "Kernel-Power 41 with BugcheckCode 0" 'Direct'
    }

    # (d) Evidence gaps (single consolidated lead when protected kernel dump folders exist)
    $unreadLeadList = @($UnreadableSources | Where-Object { $_ })
    if ($unreadLeadList.Count -gt 0) {
        $folders = @($unreadLeadList | ForEach-Object { ($_ -split ' - ')[0] } | Select-Object -Unique) -join ', '
        & $addLead "Optional deep kernel stack decoding: protected dump folder(s) ($folders) require an Administrator shell and WinDbg/CDB." "Crash dump location found ($folders)" 'Direct'
    }

    $leadRank = { param($l) if ($l.BasedOn -like 'Bugcheck at*') { 0 } elseif ($l.BasedOn -like 'Crash dump location*' -or $l.BasedOn -like 'GPU watchdog*') { 1 } elseif ($l.BasedOn -like 'Kernel-Power 41*') { 2 } else { 3 } }
    $idx = 0
    $leads = @($leads | ForEach-Object { [PSCustomObject]@{ Item = $_; Rank = (& $leadRank $_); Idx = $idx++ } } | Sort-Object Rank, Idx | ForEach-Object { $_.Item })

    # ---- Order by crash relevance and timestamp ----
    # 0: Kernel BugChecks (BSOD)
    # 1: Process Crash Dumps
    # 2: GPU Driver Timeouts
    # 3: System Restarts (Kernel-Power 41 / Event 6008)
    # 4: Other logged events
    # 5: Evidence notes
    $groupOf = {
        param($o)
        if ($o.Id -eq 'KERNEL_BUGCHECK') { return 0 }
        if ($o.Id -eq 'CRASH_DUMP') { return 1 }
        if ($o.Id -in @('GPU_TIMEOUT_EVENT', 'LIVE_KERNEL_DUMP')) { return 2 }
        if ($o.Id -in @('KERNEL_POWER_41', 'EVENTLOG_6008')) { return 3 }
        if ($o.Kind -eq 'Evidence') { return 5 }
        return 4
    }
    $sorted = @($observations | Sort-Object @{ Expression = { & $groupOf $_ } }, @{ Expression = { if ($_.Timestamp -is [datetime]) { $_.Timestamp } else { [datetime]::MinValue } }; Descending = $true })

    # Headline = newest crash-class event
    $crashes = @($sorted | Where-Object { $_.Kind -eq 'Crash' })
    $primary = $null
    if ($crashes.Count -gt 0) {
        $informative = @($crashes | Where-Object { $_.Id -in @('KERNEL_BUGCHECK', 'CRASH_DUMP') -and $_.Timestamp -is [datetime] })
        if ($informative.Count -gt 0) {
            $primary = ($informative | Sort-Object Timestamp -Descending | Select-Object -First 1)
        } else {
            $primary = $crashes[0]
        }
    } elseif ($sorted.Count -gt 0) { $primary = $sorted[0] }

    if ($primary) {
        $secondary = @($sorted | Where-Object { $_ -ne $primary })
        $title = "MOST RECENT CRASH: $($primary.Title) at $(& $fmt $primary.Timestamp)"
        $desc = $primary.Description
        return [PSCustomObject]@{
            PrimaryFinding       = $primary
            SecondaryFindings    = $secondary
            Findings             = $sorted
            RecommendedActions   = @()
            Leads                = @($leads)
            RootCauseTitle       = $title
            RootCauseDescription = $desc
            RootCauseGuidance    = ''
            RootCauseSeverity    = $primary.Severity
        }
    }

    $none = [PSCustomObject]@{
        Id = 'NO_EVIDENCE'; Category = 'System'; Kind = 'Evidence'; Severity = 'Healthy'; PriorityScore = 0
        Title = 'NO CRASH EVIDENCE FOUND IN THE SOURCES THAT WERE READ'
        Description = "No crash dumps, bugchecks, GPU timeout events or unexpected restarts were found in the scanned window ($ScanMode, $MaxLookbackDays day lookback)."
        Guidance = ''; Steps = @(); Actions = @(); Timestamp = (Get-Date); AffectedComponent = 'System'; Source = 'All scanned sources'
    }
    return [PSCustomObject]@{
        PrimaryFinding = $none; SecondaryFindings = @(); Findings = @($none); RecommendedActions = @(); Leads = @($leads)
        RootCauseTitle = $none.Title; RootCauseDescription = $none.Description
        RootCauseGuidance = ''; RootCauseSeverity = 'Healthy'
    }
}

Set-Alias -Name Invoke-DcResolvedTimeoutAnalysis -Value Find-DcResolvedIncidentHistory

Export-ModuleMember -Function Get-DcFastStartupStatus, Get-DcSystemTelemetry, Get-DcEventXmlData, Get-DcWinEventsTargeted, Get-DcBugCheckMeaning, Get-DcBugCheckExplanation, Get-DcGraphicsDriverSettings, Get-DcPciePowerManagementStatus, Find-DcLatestIncident, Get-DcWerReportArchive, Get-DcRegistryKeyLastWriteTime, Get-DcSystemChangeHistory, Find-DcResolvedIncidentHistory, Resolve-DcDiagnosticFindings, Protect-DcTelemetryText -Alias Invoke-DcResolvedTimeoutAnalysis
