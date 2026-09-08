<#
.SYNOPSIS
    DriverCheck - System Telemetry & Event Log Correlator Module
.DESCRIPTION
    Audits Windows Fast Startup, Event Log telemetry (WHEA, GPU TDR 4101, BugChecks 1001,
    Kernel-Power 41, Unexpected Shutdowns 6008, Kernel-PnP 219, Storage I/O errors, Application Crashes 1000/1002).
#>

function Get-DcBugCheckMeaning {
    param([string]$CodeHex)

    switch -Regex ($CodeHex) {
        '0x0*116' { "VIDEO_TDR_ERROR (Display Driver Timeout & Recovery Failure)" }
        '0x0*119' { "VIDEO_SCHEDULER_INTERNAL_ERROR (DirectX Graphics Kernel Watchdog)" }
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

    return [PSCustomObject]@{
        TdrDelay    = $tdrDelay
        TdrLevel    = $tdrLevel
        TdrDdiDelay = $tdrDdiDelay
        HwSchMode   = $hwSchMode
        HAGSStatus  = $hagsStatus
    }
}

function Get-DcSystemTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddHours(-48)
    )

    $results = [PSCustomObject]@{
        CutoffTime             = $Cutoff
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
    }

    # Query System Events within time window
    $sysEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Cutoff} -ErrorAction SilentlyContinue

    if ($sysEvents) {
        foreach ($e in $sysEvents) {
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

            # 2. GPU Driver TDR Resets (Event 4101 or display driver stop)
            if ($e.Id -eq 4101 -or ($e.ProviderName -match 'Display|amdkmdag|nvlddmkm|igfx' -and $e.Message -match 'stopped responding')) {
                $results.TdrEvents.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
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
        }
    }

    # Query Virtual Memory / Commit Limit Exhaustion (Event 2004)
    $memEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Resource-Exhaustion-Detector'; Id=2004; StartTime=$Cutoff} -ErrorAction SilentlyContinue
    if (-not $memEvents) {
        $memEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Resource-Exhaustion-Detector/Operational'; Id=2004; StartTime=$Cutoff} -ErrorAction SilentlyContinue
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
    $appEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Application Error'; Id=1000; StartTime=$Cutoff} -ErrorAction SilentlyContinue
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
                Message         = $ae.Message.Trim()
            })
        }
    }

    $appHangs = Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Application Hang'; Id=1002; StartTime=$Cutoff} -ErrorAction SilentlyContinue
    if ($appHangs) {
        foreach ($ah in ($appHangs | Select-Object -First 5)) {
            $hangApp = "Unknown"
            if ($ah.Message -match 'The program\s*([^\r\n]+?)\s*version') { $hangApp = $Matches[1].Trim() }
            $results.AppHangs.Add([PSCustomObject]@{
                TimeCreated = $ah.TimeCreated
                Application = $hangApp
                Message     = $ah.Message.Trim()
            })
        }
    }

    return $results
}

Export-ModuleMember -Function Get-DcFastStartupStatus, Get-DcSystemTelemetry, Get-DcBugCheckMeaning, Get-DcGraphicsDriverSettings, Get-DcPciePowerManagementStatus
