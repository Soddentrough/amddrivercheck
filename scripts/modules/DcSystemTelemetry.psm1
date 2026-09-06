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

function Get-DcSystemTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddHours(-48)
    )

    $results = [PSCustomObject]@{
        CutoffTime            = $Cutoff
        FastStartup           = Get-DcFastStartupStatus
        WheaErrors            = [System.Collections.Generic.List[PSCustomObject]]::new()
        TdrEvents             = [System.Collections.Generic.List[PSCustomObject]]::new()
        KernelBugChecks       = [System.Collections.Generic.List[PSCustomObject]]::new()
        UnexpectedShutdowns   = [System.Collections.Generic.List[PSCustomObject]]::new()
        AbruptReboots         = [System.Collections.Generic.List[PSCustomObject]]::new()
        PnpDriverFailures     = [System.Collections.Generic.List[PSCustomObject]]::new()
        StorageErrors         = [System.Collections.Generic.List[PSCustomObject]]::new()
        AppCrashes            = [System.Collections.Generic.List[PSCustomObject]]::new()
        AppHangs              = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    # Query System Events within time window
    $sysEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$Cutoff} -ErrorAction SilentlyContinue

    if ($sysEvents) {
        foreach ($e in $sysEvents) {
            # 1. WHEA Hardware Errors
            if ($e.ProviderName -match 'WHEA-Logger') {
                $results.WheaErrors.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    Message      = $e.Message.Trim()
                })
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
                $results.AbruptReboots.Add([PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    Id           = $e.Id
                    Provider     = $e.ProviderName
                    Message      = "The system rebooted without cleanly shutting down first (Power drop, hardware hang, or instant reset)."
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

Export-ModuleMember -Function Get-DcFastStartupStatus, Get-DcSystemTelemetry, Get-DcBugCheckMeaning
