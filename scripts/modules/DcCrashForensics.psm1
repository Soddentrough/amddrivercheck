<#
.SYNOPSIS
    DriverCheck crash forensics: per-crash timelines, involved software components, and cross-crash patterns.
.DESCRIPTION
    Builds an evidence-only reconstruction of each kernel crash / unexpected reboot from:
      - the crash dump analysis (bugcheck, arguments, process, stack, faulting component)
      - the System and Application event logs (boot session, warnings/errors, power/PnP/device events)
    Nothing here guesses a root cause; every statement is derived from a log entry or dump field.
#>

$script:DcNotableMap = @{
    'Microsoft-Windows-Kernel-Power'              = @(41, 42, 107, 109, 187, 506, 507, 566, 577, 172)
    'Microsoft-Windows-Kernel-General'            = @(12, 13)
    'Microsoft-Windows-Kernel-Boot'               = @(20, 27)
    'EventLog'                                    = @(6005, 6006, 6008)
    'Microsoft-Windows-WER-SystemErrorReporting'  = @(1001)
    'Microsoft-Windows-Power-Troubleshooter'      = '*'
    'Microsoft-Windows-WHEA-Logger'               = '*'
    'Microsoft-Windows-PCI'                       = '*'
    'Microsoft-Windows-Kernel-PnP'                = @(219, 400, 410, 411, 1010)
    'Microsoft-Windows-NCSI'                      = @(4042)
    'Tcpip'                                       = @(4266)
    'e2fnexpress'                                 = '*'
    'Microsoft-Windows-NDIS'                      = '*'
    'Display'                                     = '*'
    'amdkmdag'                                    = '*'
    'amdwddmg'                                    = '*'
    'nvlddmkm'                                    = '*'
    'Microsoft-Windows-WindowsUpdateClient'       = @(19, 20, 43)
    'User32'                                      = @(1074)
    'Microsoft-Windows-Winlogon'                  = @(7001, 7002)
    'Microsoft-Windows-Kernel-Processor-Power'    = @(37)
    'MsiInstaller'                                = @(1033, 11708, 11722)
    'Microsoft-Windows-DriverFrameworks-UserMode' = '*'
    'Microsoft-Windows-UserPnp'                   = @(20001, 20003)
    'Service Control Manager'                     = @(7000, 7001, 7009, 7011, 7022, 7023, 7024, 7026, 7031, 7032, 7034)
}
$script:DcNoiseProviders = @('Microsoft-Windows-DistributedCOM', 'Schannel', 'Microsoft-Windows-CertificateServicesClient-CertEnroll')

function ConvertTo-DcEventLine {
    param($Event)
    $msg = ''
    try { $msg = [string]$Event.Message } catch {}
    if ($msg) {
        $msg = ($msg -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
        $msg = ($msg -replace '[\u200E\u200F]', '') -replace '\s+', ' '
        if ($msg.Length -gt 170) { $msg = $msg.Substring(0, 167) + '...' }
    }
    return $msg
}

function Test-DcNotableEvent {
    param($Event, [string]$Log)
    $p = [string]$Event.ProviderName
    $id = [int]$Event.Id
    $lvl = if ($null -ne $Event.Level) { [int]$Event.Level } else { 4 }

    if ($Log -eq 'Application') {
        if ($p -in 'Application Error', 'Application Hang', '.NET Runtime') { return $true }
        if ($p -eq 'Windows Error Reporting' -and $id -eq 1001) {
            $m = ''; try { $m = [string]$Event.Message } catch {}
            # Windows re-queues old BlueScreen/LiveKernelEvent reports at every boot (dozens of entries); those are handled by Get-DcLiveKernelReports.
            return [bool]($m -match 'Event Name:\s*(APPCRASH|AppHangB1|BEX|BEX64|CLR20r3|MoAppCrash|MoAppHang)')
        }
        return ($lvl -in 1, 2)
    }

    if ($p -in $script:DcNoiseProviders) { return $false }
    if ($lvl -in 1, 2, 3) { return $true }
    if ($script:DcNotableMap.ContainsKey($p)) {
        $ids = $script:DcNotableMap[$p]
        if ($ids -is [string]) { return $true }
        return ($id -in $ids)
    }
    return $false
}

function Get-DcEventsInRange {
    param([string]$Log, [datetime]$Start, [datetime]$End)
    try {
        return @(Get-WinEvent -FilterHashtable @{ LogName = $Log; StartTime = $Start; EndTime = $End } -ErrorAction Stop)
    } catch { return @() }
}

function Format-DcOffset {
    param([double]$Seconds)
    $sign = if ($Seconds -lt 0) { '-' } else { '+' }
    $s = [math]::Abs([int]$Seconds)
    if ($s -ge 3600) { return ('T{0}{1}h{2:00}m{3:00}s' -f $sign, [int][math]::Floor($s / 3600), [int][math]::Floor(($s % 3600) / 60), ($s % 60)) }
    if ($s -ge 60) { return ('T{0}{1}m{2:00}s' -f $sign, [int][math]::Floor($s / 60), ($s % 60)) }
    return ('T{0}{1}s' -f $sign, $s)
}

function Format-DcDuration {
    param([timespan]$Span)
    if ($Span.TotalHours -ge 1) { return ('{0}h{1:00}m' -f [int][math]::Floor($Span.TotalHours), $Span.Minutes) }
    if ($Span.TotalMinutes -ge 1) { return ('{0}m{1:00}s' -f [int][math]::Floor($Span.TotalMinutes), $Span.Seconds) }
    return ('{0}s' -f [int]$Span.TotalSeconds)
}

function Get-DcComponentInfo {
    param([string]$Name)
    if (-not $Name) { return $null }
    $n = ($Name -replace '[<>]', '' -replace '^Unloaded_', '').Trim()
    $base = $n -replace '\.(sys|dll|exe)$', ''
    $sys32 = Join-Path $env:windir 'System32'
    $cands = [System.Collections.Generic.List[string]]::new()
    if ($base -in 'nt', 'ntkrnlmp', 'ntoskrnl') {
        $cands.Add((Join-Path $sys32 'ntoskrnl.exe'))
    } else {
        foreach ($b in @($base, ($base -replace '_', '-'))) {
            $cands.Add((Join-Path $sys32 "drivers\$b.sys"))
            $cands.Add((Join-Path $sys32 "$b.dll"))
            $cands.Add((Join-Path $sys32 "$b.exe"))
            $cands.Add((Join-Path $sys32 "$b.sys"))
        }
    }
    foreach ($c in $cands) {
        if (Test-Path -LiteralPath $c -ErrorAction SilentlyContinue) {
            try {
                $vi = (Get-Item -LiteralPath $c).VersionInfo
                $company = [string]$vi.CompanyName
                return [PSCustomObject]@{
                    Name        = $base
                    Path        = ($c -replace [regex]::Escape($env:windir), '%WINDIR%')
                    Company     = $company
                    Description = [string]$vi.FileDescription
                    Version     = [string]$vi.ProductVersion
                    IsMicrosoft = [bool]($company -match 'Microsoft')
                    Found       = $true
                }
            } catch {}
        }
    }
    return [PSCustomObject]@{ Name = $base; Path = $null; Company = $null; Description = $null; Version = $null; IsMicrosoft = $false; Found = $false }
}

function Get-DcModulesFromStack {
    param([string[]]$Frames)
    $mods = [System.Collections.Generic.List[string]]::new()
    foreach ($f in @($Frames)) {
        if ($f -match '^<?(?:Unloaded_)?([A-Za-z0-9_\.\-]+?)(?:\.dll|\.sys|\.exe)?>?(?:!|\+)') {
            $m = $Matches[1]
            if ($m -notmatch '^0x' -and -not $mods.Contains($m)) { $mods.Add($m) }
        }
    }
    return @($mods)
}

function Get-DcLiveKernelReports {
    [CmdletBinding()]
    param([int]$Days = 14)
    # Non-fatal kernel "live dump" reports (GPU timeouts, driver watchdogs, NDIS events). Windows logs each one in the
    # Application log (WER 1001) and re-logs them at every boot, so de-duplicate by Report Id and take the real time from the file name.
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seen = @{}
    $events = @()
    try { $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Windows Error Reporting'; Id = 1001; StartTime = (Get-Date).AddDays(-$Days) } -ErrorAction Stop) } catch {}
    foreach ($e in $events) {
        $m = [string]$e.Message
        if ($m -notmatch 'Event Name:\s*LiveKernelEvent') { continue }
        $rid = if ($m -match 'Report Id:\s*(\S+)') { $Matches[1] } else { $null }
        if (-not $rid -or $seen.ContainsKey($rid)) { continue }
        $seen[$rid] = $true
        $code = if ($m -match 'P1:\s*(\S+)') { $Matches[1] } else { '?' }
        $file = ($m -split "`r?`n" | Where-Object { $_ -match '\.dmp' } | Select-Object -First 1)
        $when = $null; $kind = $null
        if ($file -and $file -match '([A-Za-z_]+)-(\d{8})-(\d{4})(?:-\d+)?\.dmp') {
            $kind = $Matches[1]
            try { $when = [datetime]::ParseExact("$($Matches[2])$($Matches[3])", 'yyyyMMddHHmm', [Globalization.CultureInfo]::InvariantCulture) } catch {}
        }
        if (-not $when) { continue }
        $desc = switch -Regex ($code.ToLower()) {
            '^141$'      { 'GPU engine timeout detected (VIDEO_ENGINE_TIMEOUT_DETECTED live dump)' }
            '^117$'      { 'GPU timeout / driver reset (VIDEO_TDR_TIMEOUT_DETECTED live dump)' }
            '^a1000001$' { 'AMD driver watchdog report' }
            '^a2000002$' { 'AMD user-mode driver report' }
            '^15e$'      { 'NDIS network driver live dump' }
            default      { "LiveKernelEvent 0x$code" }
        }
        $out.Add([PSCustomObject]@{ Time = $when; Code = $code; Kind = $kind; Description = $desc; File = (Split-Path $file -Leaf); ReportId = $rid })
    }
    return @($out | Sort-Object Time)
}

function Get-DcCrashList {
    param([int]$Days = 7)
    $since = (Get-Date).AddDays(-$Days)
    $crashes = [System.Collections.Generic.List[PSCustomObject]]::new()

    $bcEvents = @()
    try { $bcEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $since } -ErrorAction Stop) } catch {}
    foreach ($e in $bcEvents) {
        $msg = [string]$e.Message
        $code = $null
        $bcArgs = @()
        if ($msg -match 'bugcheck was:\s*(0x[0-9a-fA-F]+)(?:\s*\(([^)]+)\))?') {
            $code = $Matches[1]
            if ($Matches[2]) {
                $bcArgs = @($Matches[2] -split ',\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }
        }
        $dump = if ($msg -match 'dump was saved in:\s*(\S+\.dmp)') { $Matches[1] } else { $null }
        $crashes.Add([PSCustomObject]@{ Kind = 'Bugcheck (BSOD)'; LogTime = $e.TimeCreated; BugcheckCode = $code; BugcheckArgs = $bcArgs; DumpPath = $dump })
    }

    # Unexpected reboots with no bugcheck recorded (power loss / hard reset / hang)
    $e41 = @()
    try { $e41 = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $since } -ErrorAction Stop) } catch {}
    foreach ($e in $e41) {
        $bc = 0
        try { $bc = [uint32]$e.Properties[0].Value } catch {}
        $near = @($crashes | Where-Object { [math]::Abs(($_.LogTime - $e.TimeCreated).TotalSeconds) -le 180 })
        if ($bc -eq 0 -and $near.Count -eq 0) {
            $crashes.Add([PSCustomObject]@{ Kind = 'Unexpected reboot (no bugcheck recorded: power loss / hard reset / freeze)'; LogTime = $e.TimeCreated; BugcheckCode = $null; DumpPath = $null })
        }
    }
    return @($crashes | Sort-Object LogTime -Descending)
}

function Get-DcCrashForensics {
    [CmdletBinding()]
    param(
        $Dumps = @(),
        [int]$MaxDetailed = 3,
        [int]$LookbackDays = 7,
        [int]$PreWindowMinutes = 20,
        $Telemetry = $null,
        $Hardware = $null,
        $UnreadableSources = @(),
        [object[]]$EngineLogs = @(),
        [object[]]$SteamLogs = @(),
        [object[]]$SteamGameSessions = @()
    )

    $crashList = @(Get-DcCrashList -Days $LookbackDays)
    $bootStarts = @()
    try {
        $bootStarts = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-General'; Id = 12; StartTime = (Get-Date).AddDays(-($LookbackDays + 2)) } -ErrorAction Stop | Sort-Object TimeCreated | ForEach-Object { $_.TimeCreated })
    } catch {}

    $liveKernel = @(Get-DcLiveKernelReports -Days ([math]::Max($LookbackDays, 14)))
    $items = [System.Collections.Generic.List[PSCustomObject]]::new()
    $idx = 0
    foreach ($c in $crashList) {
        $idx++
        $osStart = $bootStarts | Where-Object { $_ -le $c.LogTime } | Select-Object -Last 1
        $prevBoot = if ($osStart) { $bootStarts | Where-Object { $_ -lt $osStart } | Select-Object -Last 1 } else { $null }

        $dumpName = if ($c.DumpPath) { Split-Path $c.DumpPath -Leaf } else { $null }
        $dump = if ($dumpName) { @($Dumps | Where-Object { $_ -and -not ($_.PSObject.Properties['IsLiveKernelReport'] -and $_.IsLiveKernelReport) -and $_.FileName -ieq $dumpName } | Select-Object -First 1)[0] } else { $null }
        $crashTime = $null
        $crashTimeSource = 'unknown'
        if ($dump -and $dump.CrashTime) { $crashTime = [datetime]$dump.CrashTime; $crashTimeSource = 'dump' }

        $item = [PSCustomObject]@{
            Index           = $idx
            Kind            = $c.Kind
            LogTime         = $c.LogTime
            BugcheckCode    = $c.BugcheckCode
            BugcheckArgs    = if ($c.PSObject.Properties['BugcheckArgs']) { @($c.BugcheckArgs) } else { @() }
            DumpPath        = $c.DumpPath
            Dump            = $dump
            CrashTime       = $crashTime
            CrashTimeSource = $crashTimeSource
            OsStart         = $osStart
            CrashedBootStart = $prevBoot
            PreEvents       = @()
            Timeline        = @()
            LastActivity    = $null
            Components      = @()
            BootTrigger     = $null
            BootType        = $null
            ProviderCounts  = @()
        }
        $items.Add($item)
    }

    # Detailed analysis for the most recent crashes only (event queries are the slow part)
    $detailCount = 0
    foreach ($item in $items) {
        if ($detailCount -ge $MaxDetailed) { break }
        $detailCount++

        $rangeStart = if ($item.CrashedBootStart) { $item.CrashedBootStart.AddMinutes(-3) } else { $item.LogTime.AddHours(-2) }
        $rangeEnd = if ($item.OsStart) { $item.OsStart.AddSeconds(90) } else { $item.LogTime.AddMinutes(2) }
        $sysEvents = Get-DcEventsInRange -Log 'System' -Start $rangeStart -End $rangeEnd
        $appEvents = Get-DcEventsInRange -Log 'Application' -Start $rangeStart -End $rangeEnd

        # Anchor: dump crash time if known, else the last System event logged before the reboot began.
        $lastBeforeReboot = $null
        if ($item.OsStart) {
            $lastBeforeReboot = $sysEvents | Where-Object { $_.TimeCreated -lt $item.OsStart.AddSeconds(-1) } | Sort-Object TimeCreated | Select-Object -Last 1
        }
        $anchor = if ($item.CrashTime) { $item.CrashTime } elseif ($lastBeforeReboot) { $lastBeforeReboot.TimeCreated } else { $item.LogTime }
        $item | Add-Member -NotePropertyName AnchorTime -NotePropertyValue $anchor -Force

        # Last logged activity at/before the crash
        $lastAct = $sysEvents | Where-Object { $_.TimeCreated -le $anchor.AddSeconds(1) } | Sort-Object TimeCreated | Select-Object -Last 1
        if ($lastAct) {
            $item.LastActivity = [PSCustomObject]@{
                Time    = $lastAct.TimeCreated
                Source  = $lastAct.ProviderName
                Id      = $lastAct.Id
                Message = (ConvertTo-DcEventLine $lastAct)
                SecondsBeforeCrash = [int]($anchor - $lastAct.TimeCreated).TotalSeconds
            }
        }

        # How the crashed boot began
        if ($item.CrashedBootStart) {
            $bs = $item.CrashedBootStart
            $around = @($sysEvents | Where-Object { $_.TimeCreated -ge $bs.AddMinutes(-3) -and $_.TimeCreated -le $bs.AddSeconds(90) })
            $bootEv = $around | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Boot' -and $_.Id -eq 27 } | Select-Object -First 1
            if ($bootEv -and ([string]$bootEv.Message) -match 'boot type was (0x[0-9a-fA-F]+)') {
                $t = $Matches[1]
                $item.BootType = switch ($t) { '0x0' { 'full boot (0x0)' } '0x1' { 'fast startup / hybrid boot (0x1)' } '0x2' { 'resume from hibernation (0x2)' } default { "boot type $t" } }
            }
            $k41 = $around | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41 } | Select-Object -First 1
            $u1074 = $sysEvents | Where-Object { $_.ProviderName -eq 'User32' -and $_.Id -eq 1074 -and $_.TimeCreated -ge $bs.AddMinutes(-4) -and $_.TimeCreated -le $bs } | Select-Object -Last 1
            $sd13 = $sysEvents | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-General' -and $_.Id -eq 13 -and $_.TimeCreated -ge $bs.AddMinutes(-4) -and $_.TimeCreated -le $bs } | Select-Object -Last 1
            $item.BootTrigger = if ($k41) { 'previous session ended unexpectedly (Kernel-Power 41 logged at start of this boot)' }
                                elseif ($u1074) { 'restart initiated by user/app: ' + (ConvertTo-DcEventLine $u1074) }
                                elseif ($sd13) { 'normal shutdown followed by start' }
                                else { 'no shutdown record found before this boot (cold start or log gap)' }
        }

        # Collect notable events
        $notable = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($e in $sysEvents) { if (Test-DcNotableEvent -Event $e -Log 'System') { $notable.Add([PSCustomObject]@{ Time = $e.TimeCreated; Log = 'System'; Level = $e.Level; Source = $e.ProviderName; Id = $e.Id; Message = (ConvertTo-DcEventLine $e) }) } }
        foreach ($e in $appEvents) { if (Test-DcNotableEvent -Event $e -Log 'Application') { $notable.Add([PSCustomObject]@{ Time = $e.TimeCreated; Log = 'Application'; Level = $e.Level; Source = $e.ProviderName; Id = $e.Id; Message = (ConvertTo-DcEventLine $e) }) } }
        foreach ($lk in $liveKernel) { if ($lk.Time -ge $rangeStart -and $lk.Time -le $rangeEnd) { $notable.Add([PSCustomObject]@{ Time = $lk.Time; Log = 'LiveKernelReport'; Level = 3; Source = 'LiveKernelReport'; Id = $lk.Code; Message = "$($lk.Description) [$($lk.File)] (time from file name, minute resolution)" }) } }
        $notable = @($notable | Sort-Object Time)
        $item | Add-Member -NotePropertyName LiveKernelDuringBoot -NotePropertyValue @($liveKernel | Where-Object { $_.Time -ge $rangeStart -and $_.Time -le $anchor.AddSeconds(2) }) -Force

        $preStart = $anchor.AddMinutes(-$PreWindowMinutes)
        # Boot-settling period: the first 150 s of a boot contain bookkeeping for the PREVIOUS crash (Kernel-Power 41, 6008, 1001, volmgr 162)
        # and normal device initialisation (e.g. NIC link negotiation). Those are not precursors of THIS crash.
        $settleEnd = if ($item.CrashedBootStart) { $item.CrashedBootStart.AddSeconds(150) } else { [datetime]::MinValue }
        $item | Add-Member -NotePropertyName BootSettleEnd -NotePropertyValue $settleEnd -Force
        $item.PreEvents = @($notable | Where-Object { $_.Time -ge $preStart -and $_.Time -gt $settleEnd -and $_.Time -le $anchor.AddSeconds(2) -and $_.Level -in 1, 2, 3 })
        $item | Add-Member -NotePropertyName BootStartupIssues -NotePropertyValue @($notable | Where-Object { $item.CrashedBootStart -and $_.Time -ge $item.CrashedBootStart -and $_.Time -le $settleEnd -and $_.Level -in 1, 2, 3 -and $_.Source -notin 'Microsoft-Windows-Kernel-Power', 'EventLog', 'Microsoft-Windows-WER-SystemErrorReporting', 'volmgr' }) -Force

        # Timeline selection: everything in pre-window and post-crash window; earlier in boot only warnings/errors + key milestones.
        $sel = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($n in $notable) {
            $isEarlyBoot = ($n.Time -lt $preStart) -and $item.CrashedBootStart -and ($n.Time -ge $item.CrashedBootStart.AddSeconds(-5)) -and ($n.Time -lt $anchor)
            $isInWindow = ($n.Time -ge $preStart -and $n.Time -le $anchor.AddMinutes(3))
            $isPostBoot = $item.OsStart -and ($n.Time -ge $item.OsStart.AddSeconds(-2) -and $n.Time -le $item.OsStart.AddSeconds(90))
            $milestone = ($n.Source -in 'Microsoft-Windows-Kernel-General', 'Microsoft-Windows-Kernel-Power', 'EventLog', 'Microsoft-Windows-WER-SystemErrorReporting', 'User32', 'Microsoft-Windows-WindowsUpdateClient', 'Microsoft-Windows-Winlogon')
            if ($isInWindow -or $isPostBoot) { $sel.Add($n) }
            elseif ($isEarlyBoot -and ($n.Level -in 1, 2, 3 -or $milestone)) { $sel.Add($n) }
        }
        # Collapse repeats (same source/id/message within 2 minutes)
        $collapsed = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($n in $sel) {
            $prev = if ($collapsed.Count -gt 0) { $collapsed[$collapsed.Count - 1] } else { $null }
            if ($prev -and $prev.Source -eq $n.Source -and $prev.Id -eq $n.Id -and $prev.Message -eq $n.Message -and ($n.Time - $prev.LastTime).TotalSeconds -le 120) {
                $prev.Count++
                $prev.LastTime = $n.Time
            } else {
                $collapsed.Add([PSCustomObject]@{ Time = $n.Time; LastTime = $n.Time; Count = 1; Log = $n.Log; Level = $n.Level; Source = $n.Source; Id = $n.Id; Message = $n.Message })
            }
        }
        $item.Timeline = @($collapsed)

        # Providers reporting warnings/errors in the pre-crash window
        $item.ProviderCounts = @($item.PreEvents | Group-Object Source | Sort-Object Count -Descending | ForEach-Object { [PSCustomObject]@{ Source = $_.Name; Count = $_.Count; Ids = (($_.Group | Select-Object -ExpandProperty Id -Unique) -join ',') } })

        # Components involved (from dump)
        $comp = [System.Collections.Generic.List[PSCustomObject]]::new()
        if ($item.Dump) {
            $names = [System.Collections.Generic.List[string]]::new()
            foreach ($m in @(Get-DcModulesFromStack -Frames @($item.Dump.CallStack))) { if (-not $names.Contains($m)) { $names.Add($m) } }
            foreach ($m in @($item.Dump.DebuggerModuleName, ($item.Dump.DebuggerImageName -replace '\.(sys|dll|exe)$', ''))) { if ($m -and -not $names.Contains($m)) { $names.Add($m) } }
            foreach ($nm in $names) {
                $info = Get-DcComponentInfo -Name $nm
                if ($info) {
                    $role = if ($nm -in @($item.Dump.DebuggerModuleName, ($item.Dump.DebuggerImageName -replace '\.(sys|dll|exe)$', ''))) { 'faulting/blamed by debugger' } else { 'on call stack' }
                    $info | Add-Member -NotePropertyName Role -NotePropertyValue $role -Force
                    $comp.Add($info)
                }
            }
        }
        $item.Components = @($comp)
    }

    # Non-fatal GPU timeouts, display link drops, and user-mode app/GPU crashes
    $gpuDisplayEvents = @(Get-DcNonFatalGpuAndDisplayEvents -Dumps $Dumps -LiveKernel $liveKernel -CrashList $items -LookbackDays $LookbackDays -MaxDetailed $MaxDetailed)

    # Cross-crash precursor analysis (crashes with a known crash time only)
    $patterns = Get-DcCrashPatterns -Items @($items | Where-Object { $_.CrashTime }) -LookbackDays $LookbackDays

    # Evidence-backed cause separation (Driver vs App/Overlay vs Shader/Workload vs OS/Hardware vs Unattributed)
    $attributions = @(Resolve-DcIncidentAttribution -Dumps $Dumps -Telemetry $Telemetry -Hardware $Hardware -ForensicsCrashes $items -EngineLogs $EngineLogs -SteamLogs $SteamLogs -SteamGameSessions $SteamGameSessions)

    $forensics = [PSCustomObject]@{
        Crashes              = @($items)
        Detailed             = [math]::Min($MaxDetailed, $items.Count)
        Patterns             = $patterns
        LiveKernelHistory    = $liveKernel
        GpuDisplayEvents     = $gpuDisplayEvents
        IncidentAttributions = @($attributions)
        PlainSummary         = $null
    }
    $forensics.PlainSummary = Get-DcPlainEnglishSummary -Forensics $forensics -Dumps $Dumps -Telemetry $Telemetry -Hardware $Hardware -UnreadableSources $UnreadableSources -Attributions $attributions
    return $forensics
}

function Get-DcStopCodePlainEnglish {
    param($Code, $Bucket, $ModuleName, $ImageName, $Args, $HardwareId = $null, $HardwareDeviceName = $null)

    $c = if ($Code) { $Code.ToLower().Trim() } else { '' }
    $b = if ($Bucket) { [string]$Bucket } else { '' }
    $m = if ($ModuleName) { [string]$ModuleName } elseif ($ImageName) { [string]$ImageName } else { '' }
    $a0 = if ($Args -and $Args.Count -gt 0) { [string]$Args[0] } else { '' }

    if ($c -match '0x0*1a\b') {
        if ($a0 -match '0x0*6000\b' -or $b -match 'MiStoreFaultComplete') {
            return 'Memory / Compressed-RAM Page Fault (0x1A, MiStoreFaultComplete): Windows caught corrupted or unreadable data while bringing compressed memory pages back in. Often points to RAM instability, a sleep/storage wake hiccup, or stale memory state.'
        }
        return 'Kernel Memory Management Error (0x1A): Windows detected a corrupted memory page, page table, or pool allocation.'
    }
    if ($c -match '0x0*4e\b') {
        return 'RAM Page-Tracking Corruption (0x4E, PFN_LIST_CORRUPT): Windows'' internal list tracking physical RAM pages became inconsistent (often a bad sleep transition, unstable RAM/XMP/EXPO timing, or driver bug).'
    }
    if ($c -match '0x0*9f\b') {
        if ($HardwareDeviceName -or $HardwareId) {
            $hwDesc = if ($HardwareDeviceName -and $HardwareId) { "$HardwareDeviceName ($HardwareId)" } elseif ($HardwareDeviceName) { "$HardwareDeviceName" } else { "$HardwareId" }
            $modSuffix = if ($m) { " via $m" } else { '' }
            return "Device Power-State Hang (0x9F blaming $hwDesc$modSuffix): The PCI/hardware device failed to complete a sleep, idle, or wake power transition in time and triggered a BugCheck reboot."
        }
        if ($m -match 'HDAudBus') {
            return 'Device Power-State Hang (0x9F blaming HDAudBus.sys): Windows waited too long for the High Definition Audio Bus Driver to finish an idle/sleep power transition and triggered a BugCheck reboot.'
        }
        if ($m) {
            return "Driver Power-State Hang (0x9F blaming $m): A driver did not complete a sleep/idle/wake power command in time."
        }
        return 'Driver Power-State Hang (0x9F): A device driver stalled during an idle, sleep, or wake power transition.'
    }
    if ($c -match '0x(?:10*)?0*7e\b') {
        if ($b -match 'ExAcquireResourceExclusiveLite' -or $m -match 'ntfs') {
            return 'Kernel System Thread Crash (0x1000007E, ExAcquireResourceExclusiveLite / NTFS): A Windows background thread tried to lock/access invalid memory while handling file-system work — typically a symptom of underlying RAM or pool corruption rather than an app bug.'
        }
        return 'Kernel System Thread Exception (0x7E / 0x1000007E): A background Windows kernel thread hit an unhandled RAM access or driver fault.'
    }
    if ($c -match '0x0*119\b') {
        $subHex = $a0
        if (-not $subHex -and $b -match '^0x0*119_([0-9a-fA-F]+)_') {
            $subHex = "0x$($Matches[1])"
        }
        $subDesc = if ($subHex -match '^0x0*1$') { '0x1: invalid fence' }
                   elseif ($subHex -match '^0x0*2$') { '0x2: failed command' }
                   elseif ($subHex -match '^0x0*3$') { '0x3: unable to schedule DMA buffer' }
                   elseif ($subHex -match '^0x0*5$') { '0x5: driver faulted system command' }
                   elseif ($subHex -match '^0x0*400$') { '0x400: invalid video memory operation' }
                   elseif ($subHex) { $subHex }
                   else { 'unknown' }
        $blk = if ($m -and $m -notin @('nt', 'ntkrnlmp', 'dxgmms2', 'watchdog')) { " blaming $m" } else { '' }
        return "Graphics Scheduler Crash (0x119$blk): Windows' DirectX graphics scheduler timed out waiting for a GPU command (subtype $subDesc)."
    }
    if ($c -match '0x0*15e\b') {
        $blk = if ($m) { " blaming $m" } elseif ($ImageName) { " blaming $ImageName" } else { '' }
        return "Non-Fatal NDIS Network Driver Live Dump (0x15E$blk): Windows recorded a network miniport buffer leak or stall without rebooting."
    }
    if ($c -match '0x0*116\b') {
        return 'Unrecoverable GPU Driver Hang (0x116): Your graphics card stopped responding and Windows'' automatic GPU driver reset failed, causing a full restart.'
    }
    if ($c -match '0x0*3b\b') {
        return 'System Service Memory Crash (0x3B): A privileged system routine hit an invalid memory access.'
    }
    if ($c -match '0x0*124\b') {
        return 'Hardware Error Alert (0x124 WHEA): CPU, motherboard bus, PCIe device, or memory hardware reported a fatal error.'
    }
    if ($c -match '0x0*133\b') {
        return 'Driver Interrupt Hang (0x133 DPC_WATCHDOG_VIOLATION): A driver held the CPU busy too long without yielding.'
    }
    if ($c) {
        return "Windows Kernel Crash ($c$(if ($m) { " in $m" }))"
    }
    return 'Unexpected Kernel Crash / Restart'
}

function Get-DcNonFatalGpuAndDisplayEvents {
    [CmdletBinding()]
    param(
        $Dumps = @(),
        $LiveKernel = @(),
        $CrashList = @(),
        [int]$LookbackDays = 7,
        [int]$MaxDetailed = 3
    )

    $since = (Get-Date).AddDays(-$LookbackDays)
    $raw = [System.Collections.Generic.List[PSCustomObject]]::new()

    # 1. System Display 4101 TDR recoveries
    try {
        $tdrs = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 4101; StartTime = $since } -ErrorAction Stop)
        foreach ($e in $tdrs) {
            $raw.Add([PSCustomObject]@{
                Category    = 'GPU Driver Timeout (TDR)'
                Severity    = 'Warning'
                Time        = $e.TimeCreated
                Code        = 'Event 4101'
                Source      = [string]$e.ProviderName
                Summary     = ConvertTo-DcEventLine $e
                Explanation = 'Windows detected the GPU stopped responding for ~2 seconds and reset the display driver without rebooting (may cause a brief black screen or frozen game).'
                WasCrashedOs = $false
                ActiveApps  = @()
                PrecedingEvents = @()
            })
        }
    } catch {}

    # 2. LiveKernelReports GPU / AMD Watchdog timeouts within LookbackDays
    foreach ($lk in @($LiveKernel)) {
        if ($lk.Time -ge $since -and ($lk.Code -match '^(141|117|193|a1000001|a2000002|1b8|1a8)$')) {
            $raw.Add([PSCustomObject]@{
                Category    = if ($lk.Code -match '^(141|117|193)$') { 'GPU Driver Timeout (TDR)' } else { 'AMD Driver Watchdog Report' }
                Severity    = 'Warning'
                Time        = $lk.Time
                Code        = "0x$($lk.Code)"
                Source      = "LiveKernelReport ($($lk.File))"
                Summary     = "$($lk.Description) [$($lk.File)]"
                Explanation = if ($lk.Code -match '^(141|117)$') { 'Non-fatal GPU timeout live-dump: the screen may freeze or flicker black for a few seconds while the GPU driver recovers.' } else { 'Non-fatal graphics driver diagnostic live report recorded by Windows/AMD Watchdog (did not crash the whole PC).' }
                WasCrashedOs = $false
                ActiveApps  = @()
                PrecedingEvents = @()
            })
        }
    }

    # 3. Monitor / Display link disconnects (Kernel-PnP 1010)
    try {
        $dispDrops = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-PnP'; Id = 1010; StartTime = $since } -ErrorAction Stop)
        foreach ($e in $dispDrops) {
            $nearCrash = @($CrashList | Where-Object { ($_.CrashTime -and [math]::Abs(($_.CrashTime - $e.TimeCreated).TotalSeconds) -le 120) -or [math]::Abs(($_.LogTime - $e.TimeCreated).TotalSeconds) -le 180 }).Count -gt 0
            $raw.Add([PSCustomObject]@{
                Category    = 'Display / Monitor Link Drop'
                Severity    = 'Info'
                Time        = $e.TimeCreated
                Code        = 'Kernel-PnP 1010'
                Source      = [string]$e.ProviderName
                Summary     = ConvertTo-DcEventLine $e
                Explanation = if ($nearCrash) { 'A display disconnected around the same time as a system crash or reboot.' } else { 'Display connection dropped/reconnected on DisplayPort/HDMI without crashing Windows (commonly happens on monitor sleep, cable wiggle, or input switch — only a concern if it happens while actively using the PC).' }
                WasCrashedOs = $false
                ActiveApps  = @()
                PrecedingEvents = @()
            })
        }
    } catch {}

    # 4. User-mode application / game GPU crashes from user-mode .dmp files
    foreach ($d in @($Dumps)) {
        if ($d -and $d.ExceptionCode -and -not $d.IsKernelDump -and $d.Timestamp -ge $since) {
            $procName = if ($d.FileName -match '^([^\.]+\.exe)') { $Matches[1] } else { $d.FileName }
            $mod = if ($d.FaultingIP -and $d.FaultingIP -ne 'Unknown') { $d.FaultingIP } elseif ($d.DebuggerImageName) { $d.DebuggerImageName } else { 'unknown module' }
            $isGpuMod = ($mod -match '(?i)amdvlk|atiumd|amdxn|nvlddm|nvwgf2|nvd3dum|igfx|d3d11|d3d12|dxgi|vulkan')
            $raw.Add([PSCustomObject]@{
                Category    = if ($isGpuMod) { 'App / Game Crash in GPU Driver DLL' } else { 'User-Mode Application Crash' }
                Severity    = 'Warning'
                Time        = $d.Timestamp
                Code        = if ($d.ExceptionCode) { $d.ExceptionCode } else { 'AppDump' }
                Source      = "$procName ($mod)"
                Summary     = "$procName crashed in $mod ($($d.ExceptionMeaning)) [dump: $($d.FileName)]"
                Explanation = 'Only that program closed — Windows itself did not crash or restart. User-mode graphics DLL crashes (e.g. amdvlk64.dll) point to that app/Vulkan code path or GPU driver version, separate from kernel BSODs.'
                WasCrashedOs = $false
                ActiveApps  = @($procName)
                PrecedingEvents = @()
            })
        }
    }

    # De-duplicate / group same category (or combined GPU Timeout + AMD Watchdog episodes) within 120s of each other
    $sorted = @($raw | Sort-Object Time -Descending)
    $grouped = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($ev in $sorted) {
        $evIsGpuTdr = ($ev.Category -match 'GPU Driver Timeout|AMD Driver Watchdog')
        $match = $null
        foreach ($g in $grouped) {
            $gIsGpuTdr = ($g.Category -match 'GPU Driver Timeout|AMD Driver Watchdog')
            $sameBucket = ($g.Category -eq $ev.Category) -or ($evIsGpuTdr -and $gIsGpuTdr)
            if ($sameBucket -and [math]::Abs(($g.Time - $ev.Time).TotalSeconds) -le 120) {
                $match = $g; break
            }
        }
        if ($match) {
            if ($ev.Category -eq 'GPU Driver Timeout (TDR)') { $match.Category = 'GPU Driver Timeout (TDR)' }
            if ($match.Summary -notmatch [regex]::Escape($ev.Code)) {
                $match.Summary += " + $($ev.Code)"
            }
        } else {
            $grouped.Add($ev)
        }
    }

    # For the newest few non-BSOD GPU timeouts / display drops, check what apps crashed/hung or notable events happened within +-3 minutes
    $enriched = 0
    foreach ($g in $grouped) {
        if ($enriched -ge $MaxDetailed) { break }
        if ($g.Category -match 'GPU Driver Timeout|AMD Driver Watchdog|Display / Monitor Link Drop') {
            $enriched++
            $appWin = Get-DcEventsInRange -Log 'Application' -Start ($g.Time.AddMinutes(-3)) -End ($g.Time.AddMinutes(1))
            $sysWin = Get-DcEventsInRange -Log 'System' -Start ($g.Time.AddMinutes(-3)) -End ($g.Time.AddMinutes(1))
            $apps = [System.Collections.Generic.List[string]]::new()
            foreach ($ae in $appWin) {
                if ($ae.ProviderName -in 'Application Error', 'Application Hang', 'Windows Error Reporting') {
                    $ln = ConvertTo-DcEventLine $ae
                    if ($ln -match '(?:Faulting application name|Program|AppName):\s*([^\s,]+)') {
                        $ap = $Matches[1].Trim()
                        if ($ap -and -not $apps.Contains($ap)) { $apps.Add($ap) }
                    } elseif ($ln -match 'P1:\s*([^\s,]+\.exe)') {
                        $ap = $Matches[1].Trim()
                        if ($ap -and -not $apps.Contains($ap)) { $apps.Add($ap) }
                    }
                }
            }
            if ($apps.Count -gt 0) { $g.ActiveApps = @($apps) }
            $pre = [System.Collections.Generic.List[string]]::new()
            foreach ($se in @($sysWin | Where-Object { $_.Level -in 1, 2, 3 } | Select-Object -First 4)) {
                $pre.Add("$($se.TimeCreated.ToString('HH:mm:ss')) $($se.ProviderName) $($se.Id): $(ConvertTo-DcEventLine $se)")
            }
            $g.PrecedingEvents = @($pre)
        }
    }

    return @($grouped)
}

function Format-DcDriverInstallTiming {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$IncidentTime,

        [Parameter(Mandatory = $true)]
        [datetime]$InstallTime,

        [Parameter(Mandatory = $true)]
        [string]$DriverLabel,

        [Parameter(Mandatory = $false)]
        [int]$MaxWindowDays = 30
    )

    $span = $IncidentTime - $InstallTime
    if ([Math]::Abs($span.TotalDays) -gt $MaxWindowDays) {
        return $null
    }

    $installStamp = $InstallTime.ToString('yyyy-MM-dd HH:mm')
    if ($span.TotalSeconds -ge 0) {
        $calDays = [int]($IncidentTime.Date - $InstallTime.Date).TotalDays
        if ($span.TotalMinutes -lt 60) {
            $mins = [Math]::Max(1, [int][Math]::Round($span.TotalMinutes))
            $phrase = "$mins minute$(if ($mins -ne 1) { 's' }) after $DriverLabel was installed ($installStamp)"
        } elseif ($calDays -eq 0 -or $span.TotalHours -lt 12) {
            $hrs = [Math]::Max(1, [int][Math]::Round($span.TotalHours))
            $phrase = "$hrs hour$(if ($hrs -ne 1) { 's' }) after $DriverLabel was installed ($installStamp)"
        } elseif ($calDays -eq 1) {
            $phrase = "the day after $DriverLabel was installed ($installStamp)"
        } else {
            $phrase = "$calDays days after $DriverLabel was installed ($installStamp)"
        }

        return [PSCustomObject]@{
            Relation     = 'AfterInstall'
            Phrase       = $phrase
            DeltaHours   = [math]::Round($span.TotalHours, 1)
            CalendarDays = $calDays
            InstallStamp = $installStamp
            DriverLabel  = $DriverLabel
        }
    }

    $beforeSpan = $InstallTime - $IncidentTime
    $calDaysBefore = [int]($InstallTime.Date - $IncidentTime.Date).TotalDays
    if ($beforeSpan.TotalMinutes -lt 60) {
        $mins = [Math]::Max(1, [int][Math]::Round($beforeSpan.TotalMinutes))
        $lead = "$mins minute$(if ($mins -ne 1) { 's' }) before"
    } elseif ($calDaysBefore -eq 0 -or $beforeSpan.TotalHours -lt 12) {
        $hrs = [Math]::Max(1, [int][Math]::Round($beforeSpan.TotalHours))
        $lead = "$hrs hour$(if ($hrs -ne 1) { 's' }) before"
    } elseif ($calDaysBefore -eq 1) {
        $lead = "the day before"
    } else {
        $lead = "$calDaysBefore days before"
    }

    return [PSCustomObject]@{
        Relation     = 'BeforeInstall'
        Phrase       = "$lead $DriverLabel was installed ($installStamp) (on the previous driver)"
        DeltaHours   = [math]::Round($span.TotalHours, 1)
        CalendarDays = -$calDaysBefore
        InstallStamp = $installStamp
        DriverLabel  = $DriverLabel
    }
}

function Select-DcRelevantGpu {
    param(
        $Hardware = $null,
        [string]$ModuleHint = '',
        [string]$DriverVersionHint = ''
    )

    if (-not $Hardware -or -not $Hardware.PSObject.Properties['Gpus'] -or -not $Hardware.Gpus) {
        return $null
    }

    $gpus = @($Hardware.Gpus | Where-Object { $_ })
    if ($gpus.Count -eq 0) { return $null }

    $active = @($gpus | Where-Object { -not ($_.PSObject.Properties['IsGeneric'] -and $_.IsGeneric) })
    if ($active.Count -eq 0) { $active = $gpus }

    $vendorHint = ''
    if ($ModuleHint) {
        if ($ModuleHint -match '(?i)amd|ati') { $vendorHint = 'AMD' }
        elseif ($ModuleHint -match '(?i)nvlddm|nvwgf|nvoglv|nvd3d|nvgpu|nvidia') { $vendorHint = 'NVIDIA' }
        elseif ($ModuleHint -match '(?i)igdkmd|igd1|igfx|igc|ze_intel|intel') { $vendorHint = 'Intel' }
    }

    $candidates = if ($vendorHint) {
        $vm = @($active | Where-Object { $_.Vendor -ieq $vendorHint })
        if ($vm.Count -gt 0) { $vm } else { $active }
    } else {
        $active
    }

    $scored = $candidates | ForEach-Object {
        $score = 0
        if ($DriverVersionHint -and $_.PSObject.Properties['DriverVersion'] -and $_.DriverVersion -eq $DriverVersionHint) { $score += 50 }
        if ($_.PSObject.Properties['IsHighBoostCard'] -and $_.IsHighBoostCard) { $score += 20 }
        if ($_.Name -match '(?i)\b(RX\s*\d|RTX\s*\d|GTX\s*\d|Radeon\s+PRO|Quadro|Arc\s+[AB]\d|XT\b|XTX\b|Ti\b)') { $score += 20 }
        if ($_.Name -match '(?i)^AMD Radeon\(TM\) Graphics$|^AMD Radeon Graphics$|Radeon Vega \d+ Graphics|Intel\(R\) UHD|Intel\(R\) HD Graphics|Intel\(R\) Iris') { $score -= 10 }
        if ($_.PSObject.Properties['DriverInstallDate'] -and $_.DriverInstallDate -is [datetime]) { $score += 2 }
        [PSCustomObject]@{ Gpu = $_; Score = $score }
    }

    $best = ($scored | Sort-Object Score -Descending | Select-Object -First 1).Gpu
    if (-not $best) { return $null }

    $friendlyLabel = if ($best.PSObject.Properties['FriendlyDriverLabel'] -and $best.FriendlyDriverLabel) {
        [string]$best.FriendlyDriverLabel
    } else { $null }
    $displayVer = if ($best.PSObject.Properties['DisplayVersion'] -and $best.DisplayVersion) {
        [string]$best.DisplayVersion
    } else { $null }

    if (-not $friendlyLabel -or -not $displayVer) {
        $wddm = if ($best.PSObject.Properties['DriverVersion'] -and $best.DriverVersion) { [string]$best.DriverVersion } else { '' }
        $mkt = if ($best.PSObject.Properties['MarketingVersion'] -and $best.MarketingVersion) { [string]$best.MarketingVersion } else { '' }
        $vend = if ($best.PSObject.Properties['Vendor'] -and $best.Vendor) { [string]$best.Vendor } else { '' }
        $isGen = [bool]($best.PSObject.Properties['IsGeneric'] -and $best.IsGeneric)
        if (Get-Command ConvertTo-DcFriendlyGpuVersion -ErrorAction SilentlyContinue) {
            $conv = ConvertTo-DcFriendlyGpuVersion -Vendor $vend -WddmVersion $wddm -MarketingVersion $mkt -IsGeneric $isGen
            if (-not $displayVer) { $displayVer = $conv.DisplayVersion }
            if (-not $friendlyLabel) { $friendlyLabel = $conv.FriendlyDriverLabel }
        } else {
            if (-not $displayVer) { $displayVer = if ($mkt -and $wddm) { "$mkt ($wddm)" } elseif ($wddm) { $wddm } else { 'Unknown' } }
            if (-not $friendlyLabel) { $friendlyLabel = if ($vend) { "$vend GPU driver $displayVer" } else { "GPU driver $displayVer" } }
        }
    }

    $instDt = $null
    if ($best.PSObject.Properties['DriverInstallDate'] -and $null -ne $best.DriverInstallDate) {
        if ($best.DriverInstallDate -is [datetimeoffset]) { $instDt = $best.DriverInstallDate.LocalDateTime }
        elseif ($best.DriverInstallDate -is [datetime]) { $instDt = $best.DriverInstallDate }
        else {
            $tmpDt = [datetime]::MinValue
            if ([datetime]::TryParse([string]$best.DriverInstallDate, [ref]$tmpDt)) { $instDt = $tmpDt }
        }
    }

    return [PSCustomObject]@{
        Name                = [string]$best.Name
        Vendor              = [string]$best.Vendor
        DriverVersion       = if ($best.PSObject.Properties['DriverVersion']) { [string]$best.DriverVersion } else { $null }
        DisplayVersion      = $displayVer
        FriendlyDriverLabel = $friendlyLabel
        DriverInstallDate   = $instDt
        RawGpu              = $best
    }
}

function Resolve-DcIncidentAttribution {
    [CmdletBinding()]
    param(
        $Dumps = @(),
        $Telemetry = $null,
        $Hardware = $null,
        $ForensicsCrashes = @(),
        $EngineLogs = @(),
        $SteamLogs = @(),
        $SteamGameSessions = @()
    )

    $overlayRegex = '(?i)^(NahimicOSD|A-Volute|SonicStudio|RTSSHooks|RTSSVkLayer|DiscordHook|GameOverlayRenderer|obs-vulkan|obs-graphics|Overwolf|OWClient|ReShade|SpecialK|MedalHook|MedalEncoder|nvspcap|bdcam|fraps|dxtory|playclaw|Action_x64)'
    $gpuUmdRegex = '(?i)^(amdvlk|amdxc|amdxn|amdxx|atidxx|amdhdl|atiumd|nvwgf2um|nvoglv|nvd3dum|nvgpucomp|igc|igd10|igd12|igfx|ze_intel)'
    $gpuKmdRegex = '(?i)^(amdkmdag|nvlddmkm|igdkmd|dxgmms2|dxgkrnl)'
    $inboxShellRegex = '(?i)^(ApplicationFrameHost|dwm|ShellExperienceHost|SearchHost|Explorer|StartMenuExperienceHost|SystemSettings)(\.exe)?$'
    $appEngineNonDriverRegex = '(?i)(UnityPlayer|UnrealEditor|UE4Game|UE5Game|GameAssembly|mono-2\.0|vcruntime|msvcp|ucrtbase|\.exe$)'

    $stripModBase = {
        param([string]$Mod)
        if (-not $Mod) { return "" }
        $s = $Mod.Trim() -replace '(?i)_unloaded$', '' -replace '^<Unloaded_', '' -replace '>$', ''
        return $s.Trim()
    }

    $parseFaultKey = {
        param([string]$FaultIp, [string]$ModuleName, [string]$OffsetStr)
        $mod = ""
        $offVal = [uint64]0
        if ($FaultIp -and $FaultIp -match '^\s*(<Unloaded_[^>]+>|[A-Za-z0-9_\.\-]+\.(?:dll|sys|exe))\s*\+\s*0x([0-9a-fA-F]+)') {
            $mod = $Matches[1].Trim()
            try { $offVal = [Convert]::ToUInt64($Matches[2], 16) } catch { $offVal = 0 }
        } elseif ($FaultIp -and $FaultIp -match 'in\s+(<Unloaded_[^>]+>|[A-Za-z0-9_\.\-]+\.(?:dll|sys|exe))(?:\+0x([0-9a-fA-F]+))?') {
            $mod = $Matches[1].Trim()
            if ($Matches[2]) { try { $offVal = [Convert]::ToUInt64($Matches[2], 16) } catch { $offVal = 0 } }
        }
        if (-not $mod -and $ModuleName) { $mod = $ModuleName.Trim() }
        if ($offVal -eq 0 -and $OffsetStr -and $OffsetStr -match '^(?:0x)?([0-9a-fA-F]+)$') {
            try { $offVal = [Convert]::ToUInt64($Matches[1], 16) } catch { $offVal = 0 }
        }
        if (-not $mod) { return "" }
        if ($offVal -gt 0) {
            return ("{0}+0x{1:x}" -f $mod.ToLowerInvariant(), $offVal)
        }
        return ""
    }

    $getProcName = {
        param($Obj)
        if (-not $Obj) { return "" }
        if ($Obj.PSObject.Properties['MainExecutable'] -and $Obj.MainExecutable) { return ([IO.Path]::GetFileName([string]$Obj.MainExecutable)).ToLowerInvariant() }
        if ($Obj.PSObject.Properties['AppName'] -and $Obj.AppName) { return ([IO.Path]::GetFileName([string]$Obj.AppName)).ToLowerInvariant() }
        if ($Obj.PSObject.Properties['FileName'] -and $Obj.FileName) {
            $clean = $Obj.FileName -replace '\.\d+\.dmp$', ''
            return ([IO.Path]::GetFileName($clean)).ToLowerInvariant()
        }
        return ""
    }

    $getTelArr = {
        param([string]$Prop)
        if ($Telemetry -and $Telemetry.PSObject.Properties[$Prop] -and $Telemetry.$Prop) { return @($Telemetry.$Prop) }
        return @()
    }

    $getGpuContext = {
        param([string]$ModuleHint, [string]$DriverVersionHint, $IncidentTime)
        $gpu = Select-DcRelevantGpu -Hardware $Hardware -ModuleHint $ModuleHint -DriverVersionHint $DriverVersionHint
        if (-not $gpu) { return $null }
        $timing = $null
        if ($gpu.DriverInstallDate -is [datetime] -and $IncidentTime -is [datetime]) {
            $timing = Format-DcDriverInstallTiming -IncidentTime $IncidentTime -InstallTime $gpu.DriverInstallDate -DriverLabel $gpu.FriendlyDriverLabel
        }
        return [PSCustomObject]@{
            Gpu    = $gpu
            Label  = $gpu.FriendlyDriverLabel
            Timing = $timing
        }
    }

    # Pre-compute cross-app GPU module+offset fault map (UMDs hitting identical non-zero FaultKey across 2+ distinct executables)
    $faultKeyProcs = @{}
    $registerFaultKey = {
        param([string]$Proc, [string]$Fk)
        if (-not $Proc -or -not $Fk) { return }
        $modPart = ($Fk -split '\+')[0]
        $base = & $stripModBase $modPart
        if ($base -notmatch $gpuUmdRegex) { return }
        $normFk = ("{0}+{1}" -f $base.ToLowerInvariant(), ($Fk -split '\+')[1])
        if (-not $faultKeyProcs.ContainsKey($normFk)) {
            $faultKeyProcs[$normFk] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        [void]$faultKeyProcs[$normFk].Add($Proc)
    }

    $userDumps = @($Dumps | Where-Object { $_ -and -not $_.IsKernelDump -and -not ($_.PSObject.Properties['IsLiveKernelReport'] -and $_.IsLiveKernelReport) })
    $werAppReports = @(& $getTelArr 'WerAppReports' | Where-Object { $_ -and $_.EventType -notmatch '(?i)LiveKernelEvent' })
    $appCrashes = @(& $getTelArr 'AppCrashes')
    $tdrEvents = @(& $getTelArr 'TdrEvents')
    $werKernelEvents = @(& $getTelArr 'WerKernelEvents')
    $tdrWorkloads = @(& $getTelArr 'TdrWorkloads')
    $oomEvents = @(& $getTelArr 'MemoryExhaustion')
    $sleepEvents = @(& $getTelArr 'SleepTransitions')
    $wheaAll = @(& $getTelArr 'PcieWheaErrors') + @(& $getTelArr 'WheaErrors')
    $dispHotplugs = @(& $getTelArr 'DisplayHotplugEvents')
    $kernelBugChecks = @(& $getTelArr 'KernelBugChecks')
    $abruptReboots = @(& $getTelArr 'AbruptReboots')

    foreach ($d in $userDumps) {
        $p = & $getProcName $d
        $m = if ($d.PSObject.Properties['FaultingModule'] -and $d.FaultingModule) { $d.FaultingModule } else { "" }
        $fk = & $parseFaultKey ([string]$d.FaultingIP) ([string]$m) ""
        & $registerFaultKey $p $fk
    }
    foreach ($w in $werAppReports) {
        $p = & $getProcName $w
        $m = if ($w.PSObject.Properties['FaultModule'] -and $w.FaultModule) { $w.FaultModule } else { $w.Parameter4 }
        $off = if ($w.PSObject.Properties['ExceptionOffset']) { $w.ExceptionOffset } else { "" }
        $fk = & $parseFaultKey "" ([string]$m) ([string]$off)
        & $registerFaultKey $p $fk
    }
    foreach ($ac in $appCrashes) {
        $p = & $getProcName $ac
        $m = if ($ac.PSObject.Properties['FaultingModule'] -and $ac.FaultingModule) { $ac.FaultingModule } elseif ($ac.PSObject.Properties['FaultModule'] -and $ac.FaultModule) { $ac.FaultModule } else { "" }
        $off = if ($ac.PSObject.Properties['FaultModuleOffset'] -and $ac.FaultModuleOffset) { $ac.FaultModuleOffset } elseif ($ac.PSObject.Properties['FaultOffset'] -and $ac.FaultOffset) { $ac.FaultOffset } else { "" }
        $fk = & $parseFaultKey "" ([string]$m) ([string]$off)
        & $registerFaultKey $p $fk
    }

    $crossAppGpuFaults = @{}
    foreach ($k in $faultKeyProcs.Keys) {
        if ($faultKeyProcs[$k].Count -ge 2) {
            $crossAppGpuFaults[$k] = @($faultKeyProcs[$k] | Sort-Object)
        }
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $absorbedDumps = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $absorbedWer = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $absorbedEngine = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $absorbedDisplayTimes = [System.Collections.Generic.List[datetime]]::new()
    $absorbedWheaTimes = [System.Collections.Generic.List[datetime]]::new()

    $addAttr = {
        param(
            [string]$Classification,
            [string]$LayerBadge,
            [string]$Confidence,
            [string]$BlamedComponent,
            [string]$FaultKey,
            [string[]]$Evidence,
            [string]$PlainVerdict,
            [bool]$IsGpuDriverFault,
            $Timestamp,
            [string]$SurfaceSymptom
        )
        $results.Add([PSCustomObject]@{
            Classification   = $Classification
            LayerBadge       = $LayerBadge
            Confidence       = $Confidence
            BlamedComponent  = $BlamedComponent
            FaultKey         = $FaultKey
            Evidence         = @($Evidence | Where-Object { $_ })
            PlainVerdict     = $PlainVerdict
            IsGpuDriverFault = $IsGpuDriverFault
            Timestamp        = $Timestamp
            SurfaceSymptom   = $SurfaceSymptom
        })
    }

    # ---- 1. GPU Timeout Episodes (TdrEvents) + standalone WerKernelEvents (e.g. 0x193) ----
    $tdrCandidates = [System.Collections.Generic.List[PSCustomObject]]::new()
    $gpuTdrCodeSet = @('141', '117', '193', 'a1000001', 'a2000002', '1b8', '1a8')
    foreach ($t in ($tdrEvents | Sort-Object TimeCreated -Descending)) {
        if ($t -and $t.TimeCreated) {
            $tCode = if ($t.PSObject.Properties['Code'] -and $t.Code) { (([string]$t.Code).Trim() -replace '^(?i)0x', '').ToLowerInvariant() } else { '' }
            if (-not $tCode) { $tCode = '4101' }
            $tdrCandidates.Add([PSCustomObject]@{ Source = 'TDR'; Item = $t; Time = [datetime]$t.TimeCreated; Code = $tCode; P2 = if ($t.PSObject.Properties['Parameter2']) { [string]$t.Parameter2 } else { '' }; Msg = [string]$t.Message; Comp = if ($t.PSObject.Properties['Component']) { [string]$t.Component } else { '' } })
        }
    }
    foreach ($wk in $werKernelEvents) {
        if (-not $wk -or -not $wk.TimeCreated) { continue }
        $wkFile = if ($wk.PSObject.Properties['DumpFile'] -and $wk.DumpFile) { [string]$wk.DumpFile } else { '' }
        $wkComp = if ($wk.PSObject.Properties['Component'] -and $wk.Component) { [string]$wk.Component } else { '' }
        $wkMsg = if ($wk.PSObject.Properties['Message'] -and $wk.Message) { [string]$wk.Message } else { $wkComp }
        $wkCode = if ($wk.PSObject.Properties['BugCheckOrCode'] -and $wk.BugCheckOrCode) { [string]$wk.BugCheckOrCode } elseif ($wk.PSObject.Properties['Code'] -and $wk.Code) { [string]$wk.Code } else { '' }
        $wkCode = ($wkCode.Trim() -replace '^(?i)0x', '').ToLowerInvariant()
        if (-not $wkCode) {
            if ($wkFile -match '(?i)^AMD_WATCHDOG' -or $wkComp -match '(?i)^AMD_WATCHDOG' -or $wkMsg -match '(?i)AMD_WATCHDOG') { $wkCode = 'a1000001' }
            elseif ($wkFile -match '(?i)^AMD_REPORT_UM' -or $wkComp -match '(?i)^AMD_REPORT_UM' -or $wkMsg -match '(?i)AMD_REPORT_UM') { $wkCode = 'a2000002' }
            elseif ($wkFile -match '(?i)^WATCHDOG' -or $wkComp -match '(?i)^WATCHDOG' -or $wkMsg -match '(?i)\bWATCHDOG-\d+') { $wkCode = '141' }
            elseif ($wkFile -match '(?i)DXGKRNL' -or $wkComp -match '(?i)ProcessDeadlockThread' -or $wkMsg -match '(?i)ProcessDeadlockThread|\b0x193\b') { $wkCode = '193' }
            elseif ($wkMsg -match '(?i)\b0x117\b') { $wkCode = '117' }
        }
        if ($wkCode -notin $gpuTdrCodeSet) { continue }
        $wkTime = [datetime]$wk.TimeCreated
        $already = @($tdrCandidates | Where-Object { [Math]::Abs(($_.Time - $wkTime).TotalSeconds) -le 120 }).Count -gt 0
        $nearBsod = @($kernelBugChecks | Where-Object { $_.TimeCreated -and [Math]::Abs(([datetime]$_.TimeCreated - $wkTime).TotalSeconds) -le 300 }).Count -gt 0
        if (-not $already -and -not $nearBsod) {
            $tdrCandidates.Add([PSCustomObject]@{
                Source = 'WerKernel'
                Item   = $wk
                Time   = $wkTime
                Code   = $wkCode
                P2     = if ($wk.PSObject.Properties['Parameter2']) { [string]$wk.Parameter2 } else { '' }
                Msg    = $wkMsg
                Comp   = $wkComp
            })
        }
    }

    foreach ($cand in ($tdrCandidates | Sort-Object Time -Descending)) {
        $tTime = $cand.Time
        $codeHex = if ($cand.Code) { "0x$($cand.Code.ToUpper() -replace '^0X', '')" } else { "TDR" }
        $sym = "GPU Driver Timeout (LiveKernelEvent $codeHex)"

        $nearDumps = @($userDumps | Where-Object { $_.Timestamp -and [Math]::Abs(($_.Timestamp - $tTime).TotalSeconds) -le 120 })
        $nearWer = @($werAppReports | Where-Object { $_.Timestamp -and [Math]::Abs(($_.Timestamp - $tTime).TotalSeconds) -le 120 })
        $nearAppCr = @($appCrashes | Where-Object { $_.TimeCreated -and [Math]::Abs(($_.TimeCreated - $tTime).TotalSeconds) -le 120 })
        $nearEngine = @($EngineLogs | Where-Object { $_.Timestamp -and [Math]::Abs(($_.Timestamp - $tTime).TotalSeconds) -le 120 })
        $nearSteamShad = @($SteamLogs | Where-Object { $_.PSObject.Properties['IsShaderError'] -and $_.IsShaderError -and $_.Timestamp -and [Math]::Abs(($_.Timestamp - $tTime).TotalSeconds) -le 120 })
        $nearWl = @($tdrWorkloads | Where-Object {
            ($_.PSObject.Properties['TdrTime'] -and $_.TdrTime -and [Math]::Abs(($_.TdrTime - $tTime).TotalSeconds) -le 120) -or
            ($_.PSObject.Properties['TimeCreated'] -and $_.TimeCreated -and [Math]::Abs(($_.TimeCreated - $tTime).TotalSeconds) -le 120)
        })
        $nearOom = @($oomEvents | Where-Object { $_.TimeCreated -and (($tTime - $_.TimeCreated).TotalSeconds -ge -30) -and (($tTime - $_.TimeCreated).TotalSeconds -le 180) })
        $nearSleep = @($sleepEvents | Where-Object { $_.TimeCreated -and [Math]::Abs(($_.TimeCreated - $tTime).TotalSeconds) -le 120 })
        $nearWhea = @($wheaAll | Where-Object { $_.TimeCreated -and [Math]::Abs(($_.TimeCreated - $tTime).TotalSeconds) -le 120 })
        $nearDisp = @($dispHotplugs | Where-Object { $_.TimeCreated -and [Math]::Abs(($_.TimeCreated - $tTime).TotalSeconds) -le 60 })
        foreach ($dh in $nearDisp) { $absorbedDisplayTimes.Add([datetime]$dh.TimeCreated) }

        # Priority 1: Check cross-app GPU UMD fault or Inbox Windows shell GPU UMD fault near TDR
        $crossMatch = $null
        $inboxGpuMatch = $null
        $overlayMatch = $null
        $appOwnFault = $null
        $shaderDumpMatch = $null

        foreach ($d in $nearDumps) {
            $proc = & $getProcName $d
            $mod = if ($d.PSObject.Properties['FaultingModule'] -and $d.FaultingModule) { $d.FaultingModule } else { "" }
            $modBase = & $stripModBase $mod
            $fk = & $parseFaultKey ([string]$d.FaultingIP) ([string]$mod) ""
            $normGpuFk = if ($fk -and $modBase -match $gpuUmdRegex) { ("{0}+{1}" -f $modBase.ToLowerInvariant(), ($fk -split '\+')[1]) } else { "" }

            if ($normGpuFk -and $crossAppGpuFaults.ContainsKey($normGpuFk)) {
                $crossMatch = [PSCustomObject]@{ Proc = $proc; Fk = $normGpuFk; Dump = $d }
            } elseif (($d.PSObject.Properties['IsOverlayFault'] -and $d.IsOverlayFault) -or $modBase -match $overlayRegex -or ($mod -match '^<Unloaded_|_unloaded$' -and $modBase -notmatch $gpuUmdRegex)) {
                $overlayMatch = [PSCustomObject]@{ Proc = $proc; Mod = $mod; Overlay = $(if ($d.OverlayName) { $d.OverlayName } else { $mod }); Fk = $fk; Dump = $d }
            } elseif ($proc -match $inboxShellRegex -and $modBase -match $gpuUmdRegex) {
                $inboxGpuMatch = [PSCustomObject]@{ Proc = $proc; Mod = $modBase; Fk = $fk; Dump = $d }
            } elseif (($d.PSObject.Properties['IsShaderCompiler'] -and $d.IsShaderCompiler) -or ($d.PSObject.Properties['ApiContext'] -and $d.ApiContext -match '(?i)Shader|Pipeline')) {
                $shaderDumpMatch = [PSCustomObject]@{ Proc = $proc; Mod = $mod; Fk = $fk; Api = $d.ApiContext; Dump = $d }
            } elseif ($modBase -and $modBase -notmatch $gpuUmdRegex -and ($modBase -match $appEngineNonDriverRegex -or ($proc -and $modBase -ieq $proc))) {
                $appOwnFault = [PSCustomObject]@{ Proc = $proc; Mod = $mod; Fk = $fk; Dump = $d }
            }
        }
        if (-not $overlayMatch -and -not $crossMatch) {
            foreach ($w in $nearWer) {
                $proc = & $getProcName $w
                $mod = if ($w.PSObject.Properties['FaultModule'] -and $w.FaultModule) { $w.FaultModule } else { $w.Parameter4 }
                $off = if ($w.PSObject.Properties['ExceptionOffset']) { $w.ExceptionOffset } else { "" }
                $modBase = & $stripModBase $mod
                $fk = & $parseFaultKey "" ([string]$mod) ([string]$off)
                $normGpuFk = if ($fk -and $modBase -match $gpuUmdRegex) { ("{0}+{1}" -f $modBase.ToLowerInvariant(), ($fk -split '\+')[1]) } else { "" }
                if ($normGpuFk -and $crossAppGpuFaults.ContainsKey($normGpuFk)) {
                    $crossMatch = [PSCustomObject]@{ Proc = $proc; Fk = $normGpuFk; Wer = $w }
                } elseif (($w.PSObject.Properties['IsOverlayFault'] -and $w.IsOverlayFault) -or $modBase -match $overlayRegex -or ($mod -match '^<Unloaded_|_unloaded$' -and $modBase -notmatch $gpuUmdRegex)) {
                    $overlayMatch = [PSCustomObject]@{ Proc = $proc; Mod = $mod; Overlay = $(if ($w.OverlayName) { $w.OverlayName } else { $mod }); Fk = $fk; Wer = $w }
                } elseif ($proc -match $inboxShellRegex -and $modBase -match $gpuUmdRegex) {
                    $inboxGpuMatch = [PSCustomObject]@{ Proc = $proc; Mod = $modBase; Fk = $fk; Wer = $w }
                } elseif ($modBase -and $modBase -notmatch $gpuUmdRegex -and ($modBase -match $appEngineNonDriverRegex -or ($proc -and $modBase -ieq $proc))) {
                    $appOwnFault = [PSCustomObject]@{ Proc = $proc; Mod = $mod; Fk = $fk; Wer = $w }
                }
            }
        }

        if ($overlayMatch) {
            foreach ($nd in $nearDumps) { [void]$absorbedDumps.Add($nd.FileName) }
            foreach ($nw in $nearWer) { if ($nw.ReportPath) { [void]$absorbedWer.Add($nw.ReportPath) } }
            $evList = @("TDR $codeHex at $($tTime.ToString('yyyy-MM-dd HH:mm:ss'))", "Overlay/hook fault: $($overlayMatch.Mod) in $($overlayMatch.Proc)")
            & $addAttr 'APP_OR_OVERLAY' 'Application / Overlay' 'Confirmed' $overlayMatch.Overlay $overlayMatch.Fk $evList `
                "Third-party overlay or injected hook ($($overlayMatch.Overlay)) faulted inside $($overlayMatch.Proc) right at the GPU timeout. Remove or disable this overlay rather than reinstalling GPU drivers." `
                $false $tTime $sym
            continue
        }

        if ($appOwnFault) {
            foreach ($nd in $nearDumps) { [void]$absorbedDumps.Add($nd.FileName) }
            foreach ($nw in $nearWer) { if ($nw.ReportPath) { [void]$absorbedWer.Add($nw.ReportPath) } }
            $evList = @("TDR $codeHex at $($tTime.ToString('yyyy-MM-dd HH:mm:ss'))", "App module fault: $($appOwnFault.Mod) in $($appOwnFault.Proc)")
            & $addAttr 'APP_OR_OVERLAY' 'Application' 'Confirmed' $appOwnFault.Proc $appOwnFault.Fk $evList `
                "Application '$($appOwnFault.Proc)' crashed in its own code module ($($appOwnFault.Mod)) around the GPU timeout. This is an application-level defect, not a GPU driver failure." `
                $false $tTime $sym
            continue
        }

        if ($crossMatch) {
            # Note: cross-app GPU driver fault also gets confirmed attribution; absorb nearDump to avoid duplicate card
            foreach ($nd in $nearDumps) { [void]$absorbedDumps.Add($nd.FileName) }
            foreach ($nw in $nearWer) { if ($nw.ReportPath) { [void]$absorbedWer.Add($nw.ReportPath) } }
            $apps = @($crossAppGpuFaults[$crossMatch.Fk]) -join ', '
            $drvHint = if ($crossMatch.Dump -and $crossMatch.Dump.PSObject.Properties['GpuDriverVersion']) { [string]$crossMatch.Dump.GpuDriverVersion } elseif ($crossMatch.Wer -and $crossMatch.Wer.PSObject.Properties['GpuDriverVersion']) { [string]$crossMatch.Wer.GpuDriverVersion } else { '' }
            $gCtx = & $getGpuContext $crossMatch.Fk $drvHint $tTime
            $evList = [System.Collections.Generic.List[string]]::new()
            $evList.Add("TDR $codeHex at $($tTime.ToString('yyyy-MM-dd HH:mm:ss'))")
            $evList.Add("Identical driver fault offset $($crossMatch.Fk) hit across 2+ unrelated apps ($apps)")
            if ($gCtx -and $gCtx.Label) { $evList.Add("Active GPU driver: $($gCtx.Label)") }
            if ($gCtx -and $gCtx.Timing) { $evList.Add("Driver install timing: $($gCtx.Timing.Phrase)") }
            $blamedComp = if ($gCtx -and $gCtx.Label) { "$($crossMatch.Fk) ($($gCtx.Label))" } else { $crossMatch.Fk }
            $timingClause = if ($gCtx -and $gCtx.Timing) { ", $($gCtx.Timing.Phrase)" } elseif ($gCtx -and $gCtx.Label) { " under $($gCtx.Label)" } else { "" }
            & $addAttr 'GPU_DRIVER' 'GPU Driver' 'Confirmed' $blamedComp $crossMatch.Fk $evList.ToArray() `
                "Two or more separate applications ($apps) crashed at the exact same GPU driver instruction ($($crossMatch.Fk))$timingClause, confirming a driver-level defect." `
                $true $tTime $sym
            continue
        }

        if ($inboxGpuMatch) {
            foreach ($nd in $nearDumps) { [void]$absorbedDumps.Add($nd.FileName) }
            foreach ($nw in $nearWer) { if ($nw.ReportPath) { [void]$absorbedWer.Add($nw.ReportPath) } }
            $drvHint = if ($inboxGpuMatch.Dump -and $inboxGpuMatch.Dump.PSObject.Properties['GpuDriverVersion']) { [string]$inboxGpuMatch.Dump.GpuDriverVersion } elseif ($inboxGpuMatch.Wer -and $inboxGpuMatch.Wer.PSObject.Properties['GpuDriverVersion']) { [string]$inboxGpuMatch.Wer.GpuDriverVersion } else { '' }
            $gCtx = & $getGpuContext $inboxGpuMatch.Mod $drvHint $tTime
            $evList = [System.Collections.Generic.List[string]]::new()
            $evList.Add("TDR $codeHex at $($tTime.ToString('yyyy-MM-dd HH:mm:ss'))")
            $evList.Add("Windows system shell '$($inboxGpuMatch.Proc)' faulted in $($inboxGpuMatch.Mod)")
            if ($gCtx -and $gCtx.Label) { $evList.Add("Active GPU driver: $($gCtx.Label)") }
            if ($gCtx -and $gCtx.Timing) { $evList.Add("Driver install timing: $($gCtx.Timing.Phrase)") }
            $blamedComp = if ($gCtx -and $gCtx.Label) { "$($inboxGpuMatch.Mod) ($($gCtx.Label))" } else { $inboxGpuMatch.Mod }
            $timingClause = if ($gCtx -and $gCtx.Timing) { " ($($gCtx.Timing.Phrase))" } elseif ($gCtx -and $gCtx.Label) { " under $($gCtx.Label)" } else { "" }
            & $addAttr 'GPU_DRIVER' 'GPU Driver' 'Likely' $blamedComp $inboxGpuMatch.Fk $evList.ToArray() `
                "Windows' built-in shell process ($($inboxGpuMatch.Proc)) faulted directly inside the GPU user-mode driver ($($inboxGpuMatch.Mod))$timingClause." `
                $true $tTime $sym
            continue
        }

        # Check OS / System Event (0x193 ProcessDeadlockThread P2=0x810, Event 2004 OOM, Sleep transitions)
        if ($cand.Code -ieq '193' -and ($cand.P2 -match '(?i)^0*810$' -or $cand.Msg -match '(?i)0x810|ProcessDeadlockThread' -or $cand.Comp -match '(?i)ProcessDeadlockThread')) {
            $evList = @("LiveKernelEvent 0x193 (P2=0x810 ProcessDeadlockThread) at $($tTime.ToString('yyyy-MM-dd HH:mm:ss'))")
            & $addAttr 'OS_OR_SYSTEM_EVENT' 'Windows / System Event' 'Confirmed' 'Windows CSGSS / ProcessDeadlockThread (0x193 P2=0x810)' '' $evList `
                "Windows recorded a kernel/graphics thread deadlock (0x193 P2=0x810 ProcessDeadlockThread) rather than a GPU shader hang. Check stuck services or OS deadlock triggers before blaming the GPU driver." `
                $false $tTime "Kernel Graphics Deadlock (0x193 P2=0x810)"
            continue
        }

        if ($nearOom.Count -gt 0) {
            $topCons = if ($nearOom[0].PSObject.Properties['TopConsumers'] -and $nearOom[0].TopConsumers) { " Top consumers: $($nearOom[0].TopConsumers)." } else { "" }
            $evList = @("Event 2004 (Resource-Exhaustion-Detector) at $($nearOom[0].TimeCreated.ToString('HH:mm:ss'))$topCons", "TDR $codeHex at $($tTime.ToString('HH:mm:ss'))")
            & $addAttr 'OS_OR_SYSTEM_EVENT' 'Windows / System Event' 'Likely' 'Windows Virtual Memory Exhaustion (Event 2004)' '' $evList `
                "Windows ran out of virtual commit memory (Event 2004)$topCons right before the GPU timeout. Memory pressure starved GPU allocations and triggered the timeout — close leaking apps or raise pagefile size." `
                $false $tTime $sym
            continue
        }

        if ($nearWhea.Count -gt 0) {
            foreach ($wh in $nearWhea) { $absorbedWheaTimes.Add([datetime]$wh.TimeCreated) }
            $evList = @("WHEA hardware/PCIe error (Event $($nearWhea[0].Id)) at $($nearWhea[0].TimeCreated.ToString('HH:mm:ss'))", "TDR $codeHex")
            & $addAttr 'DEVICE_OR_HARDWARE' 'Device / Hardware' 'Likely' 'WHEA PCIe / Hardware Error' '' $evList `
                "A hardware or PCIe bus error (WHEA) was logged within 2 minutes of the GPU timeout — inspect GPU seating, PCIe riser/power cables, and hardware stability." `
                $false $tTime $sym
            continue
        }

        # Shader / Workload evidence (DRED, shader error, shader compiler stage, compute benchmark TdrWorkload)
        $dredEng = @($nearEngine | Where-Object { $_.ShaderInfo -or $_.Breadcrumbs -or ($_.PSObject.Properties['GpuErrorCode'] -and $_.GpuErrorCode) })
        if ($shaderDumpMatch -or $dredEng.Count -gt 0 -or $nearSteamShad.Count -gt 0 -or $nearWl.Count -gt 0) {
            foreach ($nd in $nearDumps) { [void]$absorbedDumps.Add($nd.FileName) }
            foreach ($ne in $nearEngine) { if ($ne.FullName) { [void]$absorbedEngine.Add($ne.FullName) } }
            $evList = [System.Collections.Generic.List[string]]::new()
            $evList.Add("TDR $codeHex at $($tTime.ToString('yyyy-MM-dd HH:mm:ss'))")
            $blamed = ""
            if ($shaderDumpMatch) {
                $blamed = "$($shaderDumpMatch.Proc) ($($shaderDumpMatch.Api))"
                $evList.Add("Shader/pipeline compile stage: $($shaderDumpMatch.Api)")
            } elseif ($dredEng.Count -gt 0) {
                $el = $dredEng[0]
                $gName = if ($el.PSObject.Properties['GameName'] -and $el.GameName) { $el.GameName } elseif ($el.ExecutableName) { $el.ExecutableName } else { $el.Engine }
                $blamed = if ($el.PSObject.Properties['GpuErrorCode'] -and $el.GpuErrorCode) { "$gName ($($el.GpuErrorCode))" } else { "$gName shader/DRED fault" }
                if ($el.ShaderInfo) { $evList.Add("Shader: $($el.ShaderInfo)") }
                if ($el.Breadcrumbs) { $evList.Add("Breadcrumbs: $($el.Breadcrumbs)") }
            } elseif ($nearWl.Count -gt 0) {
                $w = $nearWl[0]
                $blamed = "$($w.ProcessName) (compute/GPU workload)"
                $evList.Add("Active GPU workload: $($w.ProcessName)$(if ($w.CommandLine) { " ($($w.CommandLine))" })")
            } else {
                $blamed = "Steam Shader Pipeline Error"
                $evList.Add("Steam shader_log reported shader error near timeout")
            }
            & $addAttr 'SHADER_OR_WORKLOAD' 'Shader / Workload' 'Likely' $blamed $(if ($shaderDumpMatch) { $shaderDumpMatch.Fk } else { '' }) $evList.ToArray() `
                "A specific shader, D3D12/Vulkan draw call (DRED), or heavy compute dispatch ($blamed) exceeded the 2-second watchdog threshold. This is workload/shader-specific rather than a broken driver installation." `
                $false $tTime $sym
            continue
        }

        if ($nearSleep.Count -gt 0) {
            $evList = @("Sleep/wake transition at $($nearSleep[0].TimeCreated.ToString('HH:mm:ss'))", "TDR $codeHex")
            & $addAttr 'OS_OR_SYSTEM_EVENT' 'Windows / System Event' 'Suspected' 'Windows Sleep / Power Transition' '' $evList `
                "The GPU timeout occurred right around a Windows sleep or wake transition." `
                $false $tTime $sym
            continue
        }

        $checkedParts = @("Event Logs", "WER Archives", "Engine/DRED Logs", "Steam Sessions", "WHEA", "Event 2004 OOM")
        $dispNote = if ($nearDisp.Count -gt 0) { " Monitor link reconnected at timeout (downstream consequence)." } else { "" }
        $gCtx = & $getGpuContext $cand.Comp "" $tTime
        $unattrEv = [System.Collections.Generic.List[string]]::new()
        $unattrEv.Add("TDR $codeHex at $($tTime.ToString('yyyy-MM-dd HH:mm:ss'))")
        $unattrEv.Add("Checked & cleared: $($checkedParts -join ', ')")
        if ($gCtx -and $gCtx.Label) {
            $tSuffix = if ($gCtx.Timing) { " (occurred $($gCtx.Timing.Phrase))" } else { "" }
            $unattrEv.Add("Active GPU driver: $($gCtx.Label)$tSuffix")
        }
        $timingVerdictNote = if ($gCtx -and $gCtx.Timing) { " This occurred $($gCtx.Timing.Phrase)." } elseif ($gCtx -and $gCtx.Label) { " Active driver: $($gCtx.Label)." } else { "" }
        & $addAttr 'UNATTRIBUTED' 'Unattributed' 'Unattributed' 'Unidentified GPU Queue Stall' '' $unattrEv.ToArray() `
            "Windows detected a 2-second GPU queue stall ($codeHex), but no single app dump, shader error, OOM, or cross-app driver signature proved the exact trigger.$timingVerdictNote$dispNote" `
            $false $tTime $sym
    }

    # ---- 2. Unabsorbed User-Mode Crash Dumps & WER App Reports ----
    foreach ($d in ($userDumps | Sort-Object Timestamp -Descending)) {
        if ($absorbedDumps.Contains($d.FileName)) { continue }
        $proc = & $getProcName $d
        $mod = if ($d.PSObject.Properties['FaultingModule'] -and $d.FaultingModule) { $d.FaultingModule } else { "" }
        $modBase = & $stripModBase $mod
        $fk = & $parseFaultKey ([string]$d.FaultingIP) ([string]$mod) ""
        $normGpuFk = if ($fk -and $modBase -match $gpuUmdRegex) { ("{0}+{1}" -f $modBase.ToLowerInvariant(), ($fk -split '\+')[1]) } else { "" }

        if ($normGpuFk -and $crossAppGpuFaults.ContainsKey($normGpuFk)) {
            $apps = @($crossAppGpuFaults[$normGpuFk]) -join ', '
            if (-not (@($results | Where-Object { $_.Classification -eq 'GPU_DRIVER' -and $_.FaultKey -ieq $normGpuFk }).Count -gt 0)) {
                $drvHint = if ($d.PSObject.Properties['GpuDriverVersion']) { [string]$d.GpuDriverVersion } else { '' }
                $gCtx = & $getGpuContext $modBase $drvHint $d.Timestamp
                $isBeforeCurrent = ($gCtx -and $gCtx.Timing -and $gCtx.Timing.Relation -eq 'BeforeInstall')
                $evList = [System.Collections.Generic.List[string]]::new()
                $evList.Add("Cross-app GPU driver fault in $($d.FileName): $fk")
                $evList.Add("Identical address across apps: $apps")
                if ($gCtx -and $gCtx.Label) {
                    $drvPrefix = if ($isBeforeCurrent) { "Current GPU driver" } else { "Active GPU driver" }
                    $evList.Add("${drvPrefix}: $($gCtx.Label)")
                }
                if ($gCtx -and $gCtx.Timing) { $evList.Add("Driver install timing: $($gCtx.Timing.Phrase)") }
                $blamedComp = if ($isBeforeCurrent) {
                    if ($drvHint -and (-not $gCtx.Gpu.DriverVersion -or $drvHint -ne $gCtx.Gpu.DriverVersion)) { "$normGpuFk ($drvHint)" } else { "$normGpuFk (previous driver)" }
                } elseif ($gCtx -and $gCtx.Label) {
                    "$normGpuFk ($($gCtx.Label))"
                } else {
                    $normGpuFk
                }
                $timingClause = if ($gCtx -and $gCtx.Timing) { ", $($gCtx.Timing.Phrase)" } elseif ($gCtx -and $gCtx.Label) { " under $($gCtx.Label)" } else { "" }
                & $addAttr 'GPU_DRIVER' 'GPU Driver' 'Confirmed' $blamedComp $normGpuFk $evList.ToArray() `
                    "Multiple separate applications ($apps) faulted at the exact same GPU driver instruction ($normGpuFk)$timingClause, confirming a GPU driver bug." `
                    $true $d.Timestamp "App Crash ($apps)"
            }
            continue
        }
        if (($d.PSObject.Properties['IsOverlayFault'] -and $d.IsOverlayFault) -or $modBase -match $overlayRegex -or ($mod -match '^<Unloaded_|_unloaded$' -and $modBase -notmatch $gpuUmdRegex)) {
            $ov = if ($d.PSObject.Properties['OverlayName'] -and $d.OverlayName) { $d.OverlayName } else { $mod }
            $evList = @("Dump $($d.FileName) faulted at $(if ($fk) { $fk } else { $mod })")
            & $addAttr 'APP_OR_OVERLAY' 'Application / Overlay' 'Confirmed' $ov $fk $evList `
                "Third-party overlay or injected hook ($ov) crashed inside $proc (at $fk). Disable or update the overlay." `
                $false $d.Timestamp "App Crash ($proc)"
            continue
        }
        if ($proc -match $inboxShellRegex -and $modBase -match $gpuUmdRegex) {
            $drvHint = if ($d.PSObject.Properties['GpuDriverVersion']) { [string]$d.GpuDriverVersion } else { '' }
            $gCtx = & $getGpuContext $modBase $drvHint $d.Timestamp
            $evList = [System.Collections.Generic.List[string]]::new()
            $evList.Add("Inbox Windows process '$proc' faulted in '$modBase' ($($d.FileName))")
            if ($gCtx -and $gCtx.Label) { $evList.Add("Active GPU driver: $($gCtx.Label)") }
            if ($gCtx -and $gCtx.Timing) { $evList.Add("Driver install timing: $($gCtx.Timing.Phrase)") }
            $blamedComp = if ($gCtx -and $gCtx.Label) { "$modBase ($($gCtx.Label))" } else { $modBase }
            $timingClause = if ($gCtx -and $gCtx.Timing) { " ($($gCtx.Timing.Phrase))" } elseif ($gCtx -and $gCtx.Label) { " under $($gCtx.Label)" } else { "" }
            & $addAttr 'GPU_DRIVER' 'GPU Driver' 'Likely' $blamedComp $fk $evList.ToArray() `
                "Windows system shell process '$proc' crashed inside the vendor GPU driver DLL ($modBase)$timingClause." `
                $true $d.Timestamp "Windows Shell Crash ($proc)"
            continue
        }
        if (($d.PSObject.Properties['IsShaderCompiler'] -and $d.IsShaderCompiler) -or ($d.PSObject.Properties['ApiContext'] -and $d.ApiContext -match '(?i)Shader|Pipeline')) {
            $evList = @("Dump $($d.FileName) at $($d.ApiContext): $fk")
            & $addAttr 'SHADER_OR_WORKLOAD' 'Shader / Workload' 'Likely' "$proc ($($d.ApiContext))" $fk $evList `
                "Single-application shader/pipeline crash in $proc ($($d.ApiContext)). Clear shader cache or report to the app/game developer." `
                $false $d.Timestamp "App Shader Crash ($proc)"
            continue
        }
        if ($modBase -and $modBase -match $gpuUmdRegex) {
            $evList = @("Single-app dump $($d.FileName) in $modBase ($fk); no matching fault offset in any other application")
            & $addAttr 'UNATTRIBUTED' 'Unattributed' 'Unattributed' "$proc in $modBase" $fk $evList `
                "Only '$proc' faulted inside $modBase$(if ($fk) { " at $fk" }), with no cross-app replication or shader log proof — cannot separate app bad-data from a driver bug yet." `
                $false $d.Timestamp "App Crash ($proc)"
            continue
        }
        if ($modBase) {
            $appModLabel = if ($proc -and $modBase -ine $proc) { "$proc ($modBase)" } else { $modBase }
            $evList = @("Dump $($d.FileName) faulted inside $modBase ($fk)")
            & $addAttr 'APP_OR_OVERLAY' 'Application' 'Confirmed' $appModLabel $fk $evList `
                "Application '$proc' crashed inside its own/third-party module '$modBase' (unrelated to the GPU driver)." `
                $false $d.Timestamp "App Crash ($proc)"
        }
    }

    foreach ($w in $werAppReports) {
        if ($w.ReportPath -and $absorbedWer.Contains($w.ReportPath)) { continue }
        $proc = & $getProcName $w
        $nearDupDump = @($userDumps | Where-Object { $dp = & $getProcName $_; $dp -ieq $proc -and $_.Timestamp -and $w.Timestamp -and [Math]::Abs(($_.Timestamp - $w.Timestamp).TotalSeconds) -le 90 }).Count -gt 0
        if ($nearDupDump) { continue }
        $mod = if ($w.PSObject.Properties['FaultModule'] -and $w.FaultModule) { $w.FaultModule } else { $w.Parameter4 }
        $off = if ($w.PSObject.Properties['ExceptionOffset']) { $w.ExceptionOffset } else { "" }
        $modBase = & $stripModBase $mod
        $fk = & $parseFaultKey "" ([string]$mod) ([string]$off)
        $normGpuFk = if ($fk -and $modBase -match $gpuUmdRegex) { ("{0}+{1}" -f $modBase.ToLowerInvariant(), ($fk -split '\+')[1]) } else { "" }

        if ($normGpuFk -and $crossAppGpuFaults.ContainsKey($normGpuFk)) {
            $apps = @($crossAppGpuFaults[$normGpuFk]) -join ', '
            if (-not (@($results | Where-Object { $_.Classification -eq 'GPU_DRIVER' -and $_.FaultKey -ieq $normGpuFk }).Count -gt 0)) {
                $drvHint = if ($w.PSObject.Properties['GpuDriverVersion']) { [string]$w.GpuDriverVersion } else { '' }
                $gCtx = & $getGpuContext $modBase $drvHint $w.Timestamp
                $evList = [System.Collections.Generic.List[string]]::new()
                $evList.Add("WER reports across $apps at $normGpuFk")
                if ($gCtx -and $gCtx.Label) { $evList.Add("Active GPU driver: $($gCtx.Label)") }
                if ($gCtx -and $gCtx.Timing) { $evList.Add("Driver install timing: $($gCtx.Timing.Phrase)") }
                $blamedComp = if ($gCtx -and $gCtx.Label) { "$normGpuFk ($($gCtx.Label))" } else { $normGpuFk }
                $timingClause = if ($gCtx -and $gCtx.Timing) { ", $($gCtx.Timing.Phrase)" } elseif ($gCtx -and $gCtx.Label) { " under $($gCtx.Label)" } else { "" }
                & $addAttr 'GPU_DRIVER' 'GPU Driver' 'Confirmed' $blamedComp $normGpuFk $evList.ToArray() `
                    "Multiple separate applications ($apps) faulted at the exact same GPU driver offset ($normGpuFk)$timingClause." `
                    $true $w.Timestamp "WER App Crash ($apps)"
            }
            continue
        }
        if (($w.PSObject.Properties['IsOverlayFault'] -and $w.IsOverlayFault) -or $modBase -match $overlayRegex -or ($mod -match '^<Unloaded_|_unloaded$' -and $modBase -notmatch $gpuUmdRegex)) {
            $ov = if ($w.PSObject.Properties['OverlayName'] -and $w.OverlayName) { $w.OverlayName } else { $mod }
            & $addAttr 'APP_OR_OVERLAY' 'Application / Overlay' 'Confirmed' $ov $fk @("WER $($w.FolderName): FaultModule=$mod") `
                "Third-party overlay or hook ($ov) crashed inside '$proc' without involving the GPU driver." `
                $false $w.Timestamp "WER App Crash ($proc)"
            continue
        }
        if ($proc -match $inboxShellRegex -and $modBase -match $gpuUmdRegex) {
            $drvHint = if ($w.PSObject.Properties['GpuDriverVersion']) { [string]$w.GpuDriverVersion } else { '' }
            $gCtx = & $getGpuContext $modBase $drvHint $w.Timestamp
            $evList = [System.Collections.Generic.List[string]]::new()
            $evList.Add("WER: $proc faulted in $modBase")
            if ($gCtx -and $gCtx.Label) { $evList.Add("Active GPU driver: $($gCtx.Label)") }
            if ($gCtx -and $gCtx.Timing) { $evList.Add("Driver install timing: $($gCtx.Timing.Phrase)") }
            $blamedComp = if ($gCtx -and $gCtx.Label) { "$modBase ($($gCtx.Label))" } else { $modBase }
            $timingClause = if ($gCtx -and $gCtx.Timing) { " ($($gCtx.Timing.Phrase))" } elseif ($gCtx -and $gCtx.Label) { " under $($gCtx.Label)" } else { "" }
            & $addAttr 'GPU_DRIVER' 'GPU Driver' 'Likely' $blamedComp $fk $evList.ToArray() `
                "Windows shell '$proc' crashed inside GPU driver module $modBase$timingClause." `
                $true $w.Timestamp "WER Shell Crash ($proc)"
        }
    }

    # ---- 3. Standalone DRED / Engine Shader Errors without a nearby TDR ----
    foreach ($el in $EngineLogs) {
        if ($el.FullName -and $absorbedEngine.Contains($el.FullName)) { continue }
        $hasDred = ($el.PSObject.Properties['GpuErrorCode'] -and $el.GpuErrorCode) -or ($el.PSObject.Properties['Breadcrumbs'] -and $el.Breadcrumbs) -or ($el.PSObject.Properties['ShaderInfo'] -and $el.ShaderInfo)
        if (-not $hasDred) { continue }
        $nearTdr = @($tdrCandidates | Where-Object { $el.Timestamp -and [Math]::Abs(($_.Time - $el.Timestamp).TotalSeconds) -le 120 }).Count -gt 0
        if ($nearTdr) { continue }
        $gName = if ($el.PSObject.Properties['GameName'] -and $el.GameName) { $el.GameName } elseif ($el.ExecutableName) { $el.ExecutableName } else { $el.Engine }
        $detail = if ($el.GpuErrorCode) { $el.GpuErrorCode } elseif ($el.ShaderInfo) { $el.ShaderInfo } else { "DRED Breadcrumbs" }
        & $addAttr 'SHADER_OR_WORKLOAD' 'Shader / Workload' 'Confirmed' "$gName ($detail)" '' @("Engine log $($el.LogName): $detail$(if ($el.Breadcrumbs) { " - $($el.Breadcrumbs)" })") `
            "Engine log for '$gName' captured a GPU workload/shader error ($detail) directly in its own diagnostics." `
            $false $el.Timestamp "Engine GPU Error ($gName)"
    }

    # ---- 4. Kernel BSODs ----
    foreach ($bc in $kernelBugChecks) {
        $matchedC = @($ForensicsCrashes | Where-Object { $_.Kind -match 'Bugcheck' -and $_.BugcheckCode -ieq $bc.Code -and [Math]::Abs(($_.LogTime - $bc.TimeCreated).TotalSeconds) -le 120 } | Select-Object -First 1)
        $anchor = if ($matchedC.Count -gt 0 -and $matchedC[0].CrashTime) { [datetime]$matchedC[0].CrashTime } else { [datetime]$bc.TimeCreated }
        $dumpObj = if ($matchedC.Count -gt 0) { $matchedC[0].Dump } else { $null }
        if (-not $dumpObj -and $Dumps) {
            $dumpObj = @($Dumps | Where-Object {
                $_ -and $_.IsKernelDump -and -not ($_.PSObject.Properties['IsLiveKernelReport'] -and $_.IsLiveKernelReport) -and
                $_.ExceptionCode -ieq $bc.Code -and (
                    ($_.CrashTime -and [Math]::Abs(([datetime]$_.CrashTime - [datetime]$bc.TimeCreated).TotalSeconds) -le 600) -or
                    ($_.Timestamp -and [Math]::Abs(([datetime]$_.Timestamp - [datetime]$bc.TimeCreated).TotalSeconds) -le 180)
                )
            } | Select-Object -First 1)[0]
            if ($dumpObj -and $dumpObj.CrashTime) { $anchor = [datetime]$dumpObj.CrashTime }
        }
        $blamedMod = if ($dumpObj -and $dumpObj.DebuggerModuleName) { [string]$dumpObj.DebuggerModuleName } elseif ($dumpObj -and $dumpObj.FaultingModule) { [string]$dumpObj.FaultingModule } else { "" }
        $bucket = if ($bc.PSObject.Properties['WatsonBucket'] -and $bc.WatsonBucket) { [string]$bc.WatsonBucket } elseif ($dumpObj -and $dumpObj.FailureBucket) { [string]$dumpObj.FailureBucket } else { "" }

        $nearOom = @($oomEvents | Where-Object { $_.TimeCreated -and (($anchor - $_.TimeCreated).TotalSeconds -ge -30) -and (($anchor - $_.TimeCreated).TotalSeconds -le 180) })
        $nearSleep = @($sleepEvents | Where-Object { $_.TimeCreated -and [Math]::Abs(($_.TimeCreated - $anchor).TotalSeconds) -le 120 })
        $nearWhea = @($wheaAll | Where-Object { $_.TimeCreated -and [Math]::Abs(($_.TimeCreated - $anchor).TotalSeconds) -le 120 })

        if ($bc.Code -match '0x0*124\b' -or $nearWhea.Count -gt 0) {
            foreach ($wh in $nearWhea) { $absorbedWheaTimes.Add([datetime]$wh.TimeCreated) }
            & $addAttr 'DEVICE_OR_HARDWARE' 'Device / Hardware' 'Confirmed' "Hardware / WHEA Stop $($bc.Code)" $bucket @("Kernel BugCheck $($bc.Code)", "WHEA hardware error correlation") `
                "Windows hit a hardware/machine-check BugCheck ($($bc.Code)), indicating a CPU, PCIe, or motherboard hardware error rather than a software driver timeout." `
                $false $anchor "BSOD $($bc.Code)"
        } elseif ($bc.Code -match '0x0*(116|119)\b' -and $nearOom.Count -eq 0 -and $nearWhea.Count -eq 0 -and $nearSleep.Count -eq 0 -and ($blamedMod -match $gpuKmdRegex -or -not $blamedMod)) {
            $modOrBucketHint = if ($blamedMod) { $blamedMod } else { $bucket }
            $drvHint = if ($dumpObj -and $dumpObj.PSObject.Properties['GpuDriverVersion']) { [string]$dumpObj.GpuDriverVersion } else { '' }
            $gCtx = & $getGpuContext $modOrBucketHint $drvHint $anchor
            $isBeforeCurrent = ($gCtx -and $gCtx.Timing -and $gCtx.Timing.Relation -eq 'BeforeInstall')
            $kmdLabel = if ($isBeforeCurrent) {
                if ($blamedMod -and $drvHint -and (-not $gCtx.Gpu.DriverVersion -or $drvHint -ne $gCtx.Gpu.DriverVersion)) {
                    "$blamedMod ($drvHint)"
                } elseif ($blamedMod) {
                    "$blamedMod (previous GPU driver)"
                } else {
                    "Previous GPU Kernel Driver ($($bc.Code))"
                }
            } elseif ($blamedMod -and $gCtx -and $gCtx.Label) {
                "$blamedMod ($($gCtx.Label))"
            } elseif ($gCtx -and $gCtx.Label) {
                "$($gCtx.Label) ($($bc.Code))"
            } elseif ($blamedMod) {
                $blamedMod
            } else {
                "GPU Kernel Driver ($($bc.Code))"
            }
            $bsodEv = [System.Collections.Generic.List[string]]::new()
            $bsodEv.Add("Kernel BugCheck $($bc.Code)$(if ($blamedMod) { " blaming $blamedMod" })")
            if ($gCtx -and $gCtx.Label) {
                $drvPrefix = if ($isBeforeCurrent) { "Current GPU driver" } else { "Active GPU driver" }
                $bsodEv.Add("${drvPrefix}: $($gCtx.Label)")
            }
            if ($gCtx -and $gCtx.Timing) { $bsodEv.Add("Driver install timing: $($gCtx.Timing.Phrase)") }
            $bsodEv.Add("No OOM/WHEA/sleep precursors")
            $inModTxt = if ($blamedMod) { "in $blamedMod" } else { "in the GPU kernel driver" }
            $verdict = if ($gCtx -and $gCtx.Timing) {
                "Kernel graphics stop code ($($bc.Code)) triggered $inModTxt, $($gCtx.Timing.Phrase), without OOM, WHEA, or sleep precursors."
            } elseif ($gCtx -and $gCtx.Label) {
                "Kernel graphics stop code ($($bc.Code)) triggered $inModTxt under $($gCtx.Label) without OOM, WHEA, or sleep precursors."
            } else {
                "Kernel graphics stop code ($($bc.Code)) triggered $(if ($blamedMod) { "in $blamedMod " })without OOM, WHEA, or sleep precursors."
            }
            & $addAttr 'GPU_DRIVER' 'GPU Driver' 'Likely' $kmdLabel $bucket $bsodEv.ToArray() `
                $verdict `
                $true $anchor "BSOD $($bc.Code)"
        } elseif ($bc.Code -match '0x0*9f\b' -and $dumpObj -and (($dumpObj.PSObject.Properties['HardwareId'] -and $dumpObj.HardwareId) -or ($dumpObj.PSObject.Properties['HardwareDeviceName'] -and $dumpObj.HardwareDeviceName))) {
            $hwDisp = if ($dumpObj.PSObject.Properties['HardwareDeviceName'] -and $dumpObj.HardwareDeviceName -and $dumpObj.PSObject.Properties['HardwareId'] -and $dumpObj.HardwareId) {
                "$($dumpObj.HardwareDeviceName) ($($dumpObj.HardwareId))"
            } elseif ($dumpObj.PSObject.Properties['HardwareDeviceName'] -and $dumpObj.HardwareDeviceName) {
                "$($dumpObj.HardwareDeviceName)"
            } else {
                "$($dumpObj.HardwareId)"
            }
            $hwComp = if ($blamedMod) { "$hwDisp ($blamedMod)" } else { $hwDisp }
            $ev9f = [System.Collections.Generic.List[string]]::new()
            $ev9f.Add("Kernel BugCheck $($bc.Code)$(if ($blamedMod) { " in $blamedMod" })")
            if ($dumpObj.PSObject.Properties['HardwareId'] -and $dumpObj.HardwareId) { $ev9f.Add("Hardware ID: $($dumpObj.HardwareId)") }
            if ($bucket) { $ev9f.Add("Bucket: $bucket") }
            & $addAttr 'DEVICE_OR_HARDWARE' 'Device / Driver Power' 'Confirmed' $hwComp $bucket $ev9f.ToArray() `
                "PCI/PnP hardware device $hwComp failed to complete a Windows power/sleep transition ($($bc.Code)) — unrelated to the GPU driver." `
                $false $anchor "BSOD $($bc.Code)"
        } elseif ($bc.Code -match '0x(?:10*)?0*(9f|1a|4e|7e|3b|50|d1|133)\b' -or $nearOom.Count -gt 0 -or $nearSleep.Count -gt 0) {
            $comp = if ($blamedMod) { "$($bc.Code) ($blamedMod)" } else { "Windows Kernel ($($bc.Code))" }
            & $addAttr 'OS_OR_SYSTEM_EVENT' 'Windows / System Event' 'Likely' $comp $bucket @("Kernel BugCheck $($bc.Code)$(if ($blamedMod) { ", module: $blamedMod" })$(if ($bucket) { ", bucket: $bucket" })") `
                "Kernel crash $($bc.Code) happened in OS/power/memory management$(if ($blamedMod) { " ($blamedMod)" }) — separate from a GPU driver TDR." `
                $false $anchor "BSOD $($bc.Code)"
        } else {
            & $addAttr 'UNATTRIBUTED' 'Unattributed' 'Unattributed' $(if ($bucket) { $bucket } else { "Kernel BugCheck $($bc.Code)" }) $bucket @("Kernel BugCheck $($bc.Code) (stack not decoded)") `
                "Windows recorded BugCheck $($bc.Code), but protected dump symbols are needed to confirm the faulting kernel driver." `
                $false $anchor "BSOD $($bc.Code)"
        }
    }

    # ---- 4b. Unabsorbed Non-GPU LiveKernelReport Dumps (e.g. NDIS 0x15E) ----
    $nonGpuLiveDumps = @($Dumps | Where-Object {
        $_ -and ($_.PSObject.Properties['IsLiveKernelReport'] -and $_.IsLiveKernelReport) -and
        -not $_.IsGraphicsCrash -and -not $absorbedDumps.Contains($_.FileName)
    })
    foreach ($ld in ($nonGpuLiveDumps | Sort-Object Timestamp -Descending)) {
        $ldMod = if ($ld.PSObject.Properties['DebuggerImageName'] -and $ld.DebuggerImageName) {
            [string]$ld.DebuggerImageName
        } elseif ($ld.PSObject.Properties['DebuggerModuleName'] -and $ld.DebuggerModuleName) {
            [string]$ld.DebuggerModuleName
        } elseif ($ld.PSObject.Properties['FaultingModule'] -and $ld.FaultingModule) {
            [string]$ld.FaultingModule
        } else {
            [string]$ld.FileName
        }
        $ldCode = if ($ld.ExceptionCode) { [string]$ld.ExceptionCode } else { 'LiveDump' }
        $ldBucket = if ($ld.PSObject.Properties['FailureBucket'] -and $ld.FailureBucket) { [string]$ld.FailureBucket } else { '' }
        $ldEv = [System.Collections.Generic.List[string]]::new()
        $ldEv.Add("LiveKernelReport $($ld.FileName) ($ldCode)")
        if ($ldBucket) { $ldEv.Add("Failure bucket: $ldBucket") }
        $compInfo = Get-DcComponentInfo -Name $ldMod
        if ($compInfo -and $compInfo.Found -and $compInfo.Company) {
            $ldEv.Add("Driver vendor: $($compInfo.Company) v$($compInfo.Version)")
        }
        & $addAttr 'DEVICE_OR_HARDWARE' 'Device / Driver (Non-Fatal)' 'Confirmed' "$ldMod (Non-Fatal Live Dump)" $ldBucket $ldEv.ToArray() `
            "Non-fatal Windows live kernel report ($ldCode) flagged $ldMod — Windows captured diagnostic state and recovered without rebooting the PC." `
            $false $ld.Timestamp "Live Dump ($ldCode)"
    }

    # ---- 5. Abrupt Power Restarts & Standalone Display Link Drops & WHEA ----
    foreach ($rb in $abruptReboots) {
        if ($rb.BugcheckCode -ne 0) { continue }
        $hasBc = @($kernelBugChecks | Where-Object { $_.TimeCreated -and $rb.TimeCreated -and [Math]::Abs(($_.TimeCreated - $rb.TimeCreated).TotalMinutes) -le 10 }).Count -gt 0
        if ($hasBc) { continue }
        & $addAttr 'DEVICE_OR_HARDWARE' 'Device / Hardware' 'Suspected' 'Power Delivery / Unlogged Hard Reset (Event 41)' '' @("Kernel-Power Event 41 (BugcheckCode=0) at $($rb.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))") `
            "PC lost power or froze completely before Windows could write a crash dump or stop code." `
            $false $rb.TimeCreated "Sudden Power Reset (Event 41)"
    }

    $emittedDisp = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($dh in ($dispHotplugs | Sort-Object TimeCreated -Descending)) {
        if (-not $dh.TimeCreated) { continue }
        $tDh = [datetime]$dh.TimeCreated
        $absTdr = @($absorbedDisplayTimes | Where-Object { [Math]::Abs(($_ - $tDh).TotalSeconds) -le 60 }).Count -gt 0
        $nearBc = @($kernelBugChecks | Where-Object { $_.TimeCreated -and [Math]::Abs(([datetime]$_.TimeCreated - $tDh).TotalSeconds) -le 180 }).Count -gt 0
        $nearRb = @($abruptReboots | Where-Object { $_.TimeCreated -and [Math]::Abs(([datetime]$_.TimeCreated - $tDh).TotalSeconds) -le 180 }).Count -gt 0
        if ($absTdr -or $nearBc -or $nearRb) { continue }
        $devId = if ($dh.PSObject.Properties['DeviceInstanceId'] -and $dh.DeviceInstanceId) { $dh.DeviceInstanceId } else { "Display link" }
        $dupDisp = @($emittedDisp | Where-Object { $_.DevId -ieq $devId -and [Math]::Abs(($_.Time - $tDh).TotalSeconds) -le 60 }).Count -gt 0
        if ($dupDisp) { continue }
        $emittedDisp.Add([PSCustomObject]@{ DevId = $devId; Time = $tDh })
        & $addAttr 'DEVICE_OR_HARDWARE' 'Device / Hardware' 'Confirmed' "Display / Cable Link ($devId)" '' @("Kernel-PnP Event 1010 ($devId) with zero concurrent TDR or BugCheck") `
            "Standalone monitor disconnect/reconnect ($devId) on DisplayPort/HDMI without any GPU driver reset or OS crash — typically monitor standby, input switching, or cable contact." `
            $false $tDh "Display Link Drop (Event 1010)"
    }

    foreach ($wh in $wheaAll) {
        if (-not $wh.TimeCreated) { continue }
        $tWh = [datetime]$wh.TimeCreated
        if (@($absorbedWheaTimes | Where-Object { [Math]::Abs(($_ - $tWh).TotalSeconds) -le 120 }).Count -gt 0) { continue }
        & $addAttr 'DEVICE_OR_HARDWARE' 'Device / Hardware' 'Confirmed' "WHEA Hardware Error (Event $($wh.Id))" '' @("WHEA-Logger Event $($wh.Id) at $($tWh.ToString('yyyy-MM-dd HH:mm:ss'))") `
            "Hardware/PCIe error correction alert reported by WHEA-Logger." `
            $false $tWh "WHEA Hardware Event $($wh.Id)"
    }

    return @($results | Sort-Object @{ Expression = { if ($_.Timestamp -is [datetime]) { $_.Timestamp } else { [datetime]::MinValue } }; Descending = $true })
}

function Get-DcPlainEnglishSummary {
    [CmdletBinding()]
    param(
        $Forensics,
        $Dumps = @(),
        $Telemetry = $null,
        $Hardware = $null,
        $UnreadableSources = @(),
        $Attributions = @()
    )

    $crashes = @($Forensics.Crashes)
    $bsods = @($crashes | Where-Object { $_.Kind -match 'Bugcheck' })
    $restarts = @($crashes | Where-Object { $_.Kind -notmatch 'Bugcheck' })
    $gpuDisp = @($Forensics.GpuDisplayEvents)
    $gpuTdrs = @($gpuDisp | Where-Object { $_.Category -match 'GPU Driver Timeout|AMD Driver Watchdog' })
    $dispDrops = @($gpuDisp | Where-Object { $_.Category -eq 'Display / Monitor Link Drop' })
    $appCrashes = @($gpuDisp | Where-Object { $_.Category -match 'Application Crash|App / Game Crash' })
    $lkAll = @($Forensics.LiveKernelHistory)
    $lkGpuAll = @($lkAll | Where-Object { $_.Code -match '^(141|117|193|a1000001|a2000002)$' })
    $attrList = if (@($Attributions).Count -gt 0) { @($Attributions) } elseif ($Forensics -and $Forensics.PSObject.Properties['IncidentAttributions'] -and $Forensics.IncidentAttributions) { @($Forensics.IncidentAttributions) } else { @() }

    $translated = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($c in ($bsods | Select-Object -First 6)) {
        $d = $c.Dump
        $plain = if ($d) {
            $dHwId = if ($d.PSObject.Properties['HardwareId']) { $d.HardwareId } else { $null }
            $dHwName = if ($d.PSObject.Properties['HardwareDeviceName']) { $d.HardwareDeviceName } else { $null }
            Get-DcStopCodePlainEnglish -Code $c.BugcheckCode -Bucket $d.FailureBucket -ModuleName $d.DebuggerModuleName -ImageName $d.DebuggerImageName -Args $d.BugcheckArgs -HardwareId $dHwId -HardwareDeviceName $dHwName
        } else {
            $cArgs = if ($c.PSObject.Properties['BugcheckArgs']) { $c.BugcheckArgs } else { @() }
            Get-DcStopCodePlainEnglish -Code $c.BugcheckCode -Args $cArgs
        }
        $whenTxt = if ($c.CrashTime) { $c.CrashTime.ToString('yyyy-MM-dd HH:mm') } else { $c.LogTime.ToString('yyyy-MM-dd HH:mm') + ' (log time)' }
        $procTxt = if ($d -and $d.AnalysisDetail -and $d.AnalysisDetail.ProcessName -and $d.AnalysisDetail.ProcessName -notmatch 'wrong\.symbols|^System$') { " while $($d.AnalysisDetail.ProcessName) was active." } else { '' }
        $plainTrim = $plain.TrimEnd('.')
        $plainFinal = if ($procTxt) { "$plainTrim$procTxt" } else { $plain }
        $translated.Add([PSCustomObject]@{
            Kind = 'BSOD'
            When = $whenTxt
            Code = if ($c.BugcheckCode) { $c.BugcheckCode } else { 'Unknown' }
            PlainText = $plainFinal
        })
    }

    $headline = if ($bsods.Count -gt 0 -and $restarts.Count -gt 0) {
        "Your PC hit $($bsods.Count) Windows crash(es) (BSOD) and $($restarts.Count) sudden restart(s) without a crash screen in the last week."
    } elseif ($bsods.Count -gt 0) {
        "Your PC hit $($bsods.Count) Windows system crash(es) (Blue Screen / forced reboot) in the last week."
    } elseif ($restarts.Count -gt 0) {
        "Your PC restarted unexpectedly $($restarts.Count) time(s) without recording a Windows crash screen (sudden power cut or complete hang)."
    } elseif ($gpuTdrs.Count -gt 0) {
        "Windows did not crash, but your graphics driver timed out and recovered $($gpuTdrs.Count) time(s) recently (brief black screen / freeze)."
    } elseif ($dispDrops.Count -gt 0) {
        "No OS crashes or GPU driver timeouts were found in this window — only $($dispDrops.Count) monitor display link disconnect(s)."
    } else {
        "No Windows crashes, sudden restarts, or GPU driver timeouts were recorded in the inspected window."
    }

    $facts = [System.Collections.Generic.List[string]]::new()
    $rulesOut = [System.Collections.Generic.List[string]]::new()
    $nextChecks = [System.Collections.Generic.List[string]]::new()

    if ($bsods.Count -gt 0) {
        $analyzed = @($bsods | Where-Object { $_.Dump -and $_.Dump.CdbInspected -and $_.Dump.DebuggerModuleName -ne 'wrong.symbols' })
        $codes = @($bsods | Where-Object { $_.BugcheckCode } | ForEach-Object { $_.BugcheckCode } | Select-Object -Unique)
        $facts.Add("$($bsods.Count) Windows BugCheck crash(es) recorded ($($codes -join ', ')); $($analyzed.Count) dump(s) decoded with Windows debugger symbols.")
    }
    if ($restarts.Count -gt 0) {
        $facts.Add("$($restarts.Count) sudden power-loss / hard-hang restart(s) (Kernel-Power Event 41 with BugcheckCode 0 — Windows lost power or froze before writing a dump).")
    }
    if ($gpuTdrs.Count -gt 0 -or $lkGpuAll.Count -gt 0) {
        $recentGpu = $gpuTdrs.Count
        $histGpu = $lkGpuAll.Count
        $lastGpu = if ($gpuTdrs.Count -gt 0) { $gpuTdrs[0].Time.ToString('yyyy-MM-dd HH:mm') } elseif ($lkGpuAll.Count -gt 0) { ($lkGpuAll | Select-Object -Last 1).Time.ToString('yyyy-MM-dd HH:mm') } else { '' }
        $facts.Add("Non-fatal GPU driver timeouts/watchdog reports: $recentGpu in the last 7 days, $histGpu total in Windows WER history (latest: $lastGpu).")
    }
    if ($dispDrops.Count -gt 0) {
        $facts.Add("$($dispDrops.Count) monitor/display link drop(s) (Kernel-PnP 1010). On its own this is just DisplayPort/HDMI disconnecting (e.g. monitor sleep), not a PC crash.")
    }
    if ($appCrashes.Count -gt 0) {
        $facts.Add("$($appCrashes.Count) user-mode app crash dump(s) -- only those individual programs closed; they did not reboot Windows.")
    }

    $primaryGpu = Select-DcRelevantGpu -Hardware $Hardware
    $gpuIncidentTimes = [System.Collections.Generic.List[datetime]]::new()
    foreach ($b in $bsods) {
        if ($b.BugcheckCode -match '0x0*(116|119)\b') {
            $bt = if ($b.CrashTime -is [datetime]) { [datetime]$b.CrashTime } elseif ($b.LogTime -is [datetime]) { [datetime]$b.LogTime } else { $null }
            if ($bt) { $gpuIncidentTimes.Add($bt) }
        }
    }
    foreach ($gt in $gpuTdrs) {
        if ($gt.Time -is [datetime]) { $gpuIncidentTimes.Add([datetime]$gt.Time) }
    }
    foreach ($at in $attrList) {
        if ($at.IsGpuDriverFault -and $at.Timestamp -is [datetime]) {
            $dup = @($gpuIncidentTimes | Where-Object { [Math]::Abs(($_ - [datetime]$at.Timestamp).TotalSeconds) -le 120 }).Count -gt 0
            if (-not $dup) { $gpuIncidentTimes.Add([datetime]$at.Timestamp) }
        }
    }
    $gpuAfterInstall = @()
    $gpuBeforeInstall = @()
    if ($primaryGpu) {
        if ($primaryGpu.DriverInstallDate -is [datetime] -and $gpuIncidentTimes.Count -gt 0) {
            $instTime = [datetime]$primaryGpu.DriverInstallDate
            $gpuAfterInstall = @($gpuIncidentTimes | Where-Object { $_ -ge $instTime } | Sort-Object)
            $gpuBeforeInstall = @($gpuIncidentTimes | Where-Object { $_ -lt $instTime } | Sort-Object)
            $postTiming = if ($gpuAfterInstall.Count -gt 0) {
                Format-DcDriverInstallTiming -IncidentTime $gpuAfterInstall[0] -InstallTime $instTime -DriverLabel $primaryGpu.FriendlyDriverLabel
            } else { $null }
            $preTiming = if ($gpuBeforeInstall.Count -gt 0) {
                Format-DcDriverInstallTiming -IncidentTime $gpuBeforeInstall[0] -InstallTime $instTime -DriverLabel $primaryGpu.FriendlyDriverLabel
            } else { $null }

            if ($postTiming -and $gpuBeforeInstall.Count -eq 0) {
                $lead = if ($gpuAfterInstall.Count -eq 1) { "the recorded GPU incident occurred" } else { "all $($gpuAfterInstall.Count) recorded GPU incidents started" }
                $facts.Add("GPU driver install timing: $lead $($postTiming.Phrase).")
            } elseif ($postTiming -and $gpuBeforeInstall.Count -gt 0) {
                $facts.Add("GPU driver install timing: $($primaryGpu.FriendlyDriverLabel) was installed on $($instTime.ToString('yyyy-MM-dd HH:mm')); GPU incidents occurred both before ($($gpuBeforeInstall[0].ToString('yyyy-MM-dd HH:mm')), on the previous driver) and $($postTiming.Phrase).")
            } elseif ($preTiming -and $gpuAfterInstall.Count -eq 0) {
                $facts.Add("GPU driver install timing: $($primaryGpu.FriendlyDriverLabel) was installed on $($instTime.ToString('yyyy-MM-dd HH:mm')) after the earlier GPU incident(s); 0 GPU crashes or timeouts have occurred since that update.")
            } else {
                $facts.Add("Active GPU driver: $($primaryGpu.FriendlyDriverLabel) (installed $($instTime.ToString('yyyy-MM-dd HH:mm'))).")
            }
        } elseif ($gpuIncidentTimes.Count -gt 0) {
            $facts.Add("Active GPU driver: $($primaryGpu.FriendlyDriverLabel).")
        }
    }

    $idleNoWarningNote = $null
    $pat = $Forensics.Patterns
    if ($pat -and $pat.CrashCount -ge 1 -and $pat.NoPrecursorCrashes -gt 0) {
        $idleNoWarningNote = "$($pat.NoPrecursorCrashes) of $($pat.CrashCount) crashes had ZERO warnings or errors logged in the 30 minutes beforehand. That rules out a noisy software error or logged thermal/disk warning building up beforehand — instead, each failure happened suddenly (consistent with RAM/memory-controller corruption, a sudden sleep/idle power-state fault like HDAudBus.sys, or a sudden hardware/storage wake hiccup)."
        $facts.Add("Clean log history before crashes: $($pat.NoPrecursorCrashes)/$($pat.CrashCount) decoded crashes had 0 warnings/errors in the 30 minutes prior.")
    }

    if ($Telemetry -and $Telemetry.PostCrashNetworkEventsCount -gt 0) {
        $rulesOut.Add("Network link events right after a crash are caused BY Windows restarting its Ethernet adapter on boot — they did not trigger the crash.")
    } elseif ($crashes.Count -gt 0) {
        $postNet = @($crashes | ForEach-Object { @($_.Timeline | Where-Object { $_.Time -gt $_.AnchorTime -and $_.Source -match 'e2fnexpress|NCSI|NDIS' }) } | Select-Object -First 1)
        if ($postNet.Count -gt 0) {
            $rulesOut.Add("Network disconnect events logged seconds after a crash happened DURING the reboot — they are normal startup behavior, not the cause of the crashes.")
        }
    }

    if ($Hardware) {
        if ($Hardware.PhysicalDisks -and $Hardware.PhysicalDisks.Disks.Count -gt 0) {
            $unhealthy = @($Hardware.PhysicalDisks.Disks | Where-Object { $_.HealthStatus -ne 'Healthy' -or $_.ReadErrorsUncorrected -gt 0 -or $_.WriteErrorsUncorrected -gt 0 })
            if ($unhealthy.Count -eq 0 -and @($Hardware.PhysicalDisks.Findings).Count -eq 0) {
                $rulesOut.Add("SSD / storage SMART health checks look clean (all drives report Healthy with 0 uncorrected read/write errors and no storage controller errors in System logs).")
            }
        }
        if ($null -ne $Hardware.WheaEvents -and @($Hardware.WheaEvents).Count -eq 0) {
            $rulesOut.Add("Zero WHEA hardware error records in the last 30 days (no logged CPU machine-check or PCIe AER error alerts).")
        }
    }
    if ($appCrashes.Count -gt 0 -and $bsods.Count -gt 0) {
        $hasMemBsod = @($bsods | Where-Object { $_.BugcheckCode -match '0x0*(1a|4e|7e|1000007e|3b)' }).Count -gt 0
        if ($hasMemBsod) {
            $rulesOut.Add("User-mode Vulkan/shader app crashes (such as amdvlk64.dll) only crash that program — clearing a game shader cache will NOT fix kernel 0x1A / 0x4E / 0x9F BSODs.")
        }
    }

    # Build Next Checks strictly from attributed causes (never recommend DDU unless GPU driver fault is evidenced)
    $appOverlayAttrs = @($attrList | Where-Object { $_.Classification -eq 'APP_OR_OVERLAY' })
    $overlayAttrs = @($appOverlayAttrs | Where-Object { $_.LayerBadge -eq 'Application / Overlay' -or $_.PlainVerdict -match '(?i)overlay|injected hook' })
    $appOnlyAttrs = @($appOverlayAttrs | Where-Object { -not ($_.LayerBadge -eq 'Application / Overlay' -or $_.PlainVerdict -match '(?i)overlay|injected hook') })
    if ($overlayAttrs.Count -gt 0) {
        $ovComps = (@($overlayAttrs | ForEach-Object { $_.BlamedComponent } | Select-Object -Unique) -join ', ')
        $nextChecks.Add("Disable or update the third-party overlay/hook ($ovComps): evidence points directly to this injected component rather than the GPU driver.")
    }
    if ($appOnlyAttrs.Count -gt 0) {
        $appComps = (@($appOnlyAttrs | ForEach-Object { $_.BlamedComponent } | Select-Object -Unique) -join ', ')
        $nextChecks.Add("Investigate or update the crashing application ($appComps): the fault occurred in user-space application/runtime code rather than the GPU driver.")
    }
    $shaderAttrs = @($attrList | Where-Object { $_.Classification -eq 'SHADER_OR_WORKLOAD' })
    if ($shaderAttrs.Count -gt 0) {
        $comps = (@($shaderAttrs | ForEach-Object { $_.BlamedComponent } | Select-Object -Unique) -join ', ')
        $nextChecks.Add("Clear the game/app shader cache or verify game files ($comps); if testing your own app or Unreal game, launch with DRED / '-gpucrashdebugging' to capture the specific offending shader/draw call.")
    }
    $osOomAttrs = @($attrList | Where-Object { $_.Classification -eq 'OS_OR_SYSTEM_EVENT' -and ($_.BlamedComponent -match '2004|Memory|Exhaustion|0x193') })
    if ($osOomAttrs.Count -gt 0) {
        $nextChecks.Add("Check Windows memory & background services (Event 2004 virtual commit exhaustion / 0x193 thread deadlock): inspect top memory-consuming processes or increase pagefile size rather than reinstalling display drivers.")
    }

    $isElevated = [bool]($Telemetry -and $Telemetry.PSObject.Properties['IsElevated'] -and $Telemetry.IsElevated)
    $uninspectedPresentDumps = @($bsods | Where-Object { $_.Dump -and -not $_.Dump.CdbInspected })
    $undecodedBsods = @($bsods | Where-Object { -not $_.Dump -or -not $_.Dump.CdbInspected })
    if (-not $isElevated -and ((@($UnreadableSources).Count -gt 0 -and $bsods.Count -gt 0) -or $undecodedBsods.Count -gt 0)) {
        $nextChecks.Add("Optional for kernel BSOD call stacks: Windows' protected C:\WINDOWS\Minidump folder requires an Administrator shell (and WinDbg/CDB) to unwind kernel crash stacks.")
    } elseif ($isElevated -and $uninspectedPresentDumps.Count -gt 0) {
        $nextChecks.Add("Optional for kernel BSOD call stacks: install Windows SDK Debugging Tools (cdb.exe) or WinDbg so DriverCheck can unwind symbols from $($uninspectedPresentDumps.Count) minidump file(s).")
    }
    $hasMem = @($bsods | Where-Object { $_.BugcheckCode -match '0x0*(1a|4e|50|d1|3b|7e|1000007e)' }).Count -gt 0
    if ($hasMem) {
        $expoTxt = if ($Hardware -and $Hardware.Memory -and $Hardware.Memory.ConfiguredClockSpeed -ge 5600) { " (your RAM is at $($Hardware.Memory.ConfiguredClockSpeed) MT/s)" } else { "" }
        $nextChecks.Add("Test system memory (RAM) stability: Windows hit multiple memory/page-corruption BSODs (0x1A / 0x4E / 0x1000007E)$expoTxt. Run Windows Memory Diagnostic (mdsched.exe) or TestMem5/OCCT memory test; if it errors at current speed, temporarily test at JEDEC base speed (or update motherboard BIOS for AGESA/memory stability).")
    }
    $powerHangBsods = @($bsods | Where-Object { $_.BugcheckCode -match '0x0*9f' -or ($_.Dump -and $_.Dump.DebuggerModuleName -match 'HDAudBus') })
    if ($powerHangBsods.Count -gt 0) {
        $powerTargets = [System.Collections.Generic.List[string]]::new()
        $hasHdAud = $false
        $hasPciHw = $false
        foreach ($pb in $powerHangBsods) {
            if ($pb.Dump) {
                $d = $pb.Dump
                if ($d.DebuggerModuleName -match 'HDAudBus' -or $d.FailureBucket -match 'HDAudBus') {
                    $hasHdAud = $true
                    if (-not $powerTargets.Contains('HDAudBus.sys')) { $powerTargets.Add('HDAudBus.sys') }
                }
                if ($d.PSObject.Properties['HardwareDeviceName'] -and $d.HardwareDeviceName) {
                    $hasPciHw = $true
                    $hwLbl = if ($d.DebuggerModuleName) { "$($d.HardwareDeviceName) via $($d.DebuggerModuleName)" } else { "$($d.HardwareDeviceName)" }
                    if (-not $powerTargets.Contains($hwLbl)) { $powerTargets.Add($hwLbl) }
                } elseif ($d.PSObject.Properties['HardwareId'] -and $d.HardwareId) {
                    $hasPciHw = $true
                    if (-not $powerTargets.Contains($d.HardwareId)) { $powerTargets.Add($d.HardwareId) }
                } elseif ($d.DebuggerModuleName -and $d.DebuggerModuleName -notmatch 'HDAudBus') {
                    if (-not $powerTargets.Contains($d.DebuggerModuleName)) { $powerTargets.Add($d.DebuggerModuleName) }
                }
            }
        }
        $powerTag = if ($powerTargets.Count -gt 0) { "0x9F: $($powerTargets -join ', ')" } else { "0x9F DRIVER_POWER_STATE_FAILURE" }
        if ($hasPciHw -and $hasHdAud) {
            $nextChecks.Add("Check device/power-state stability ($powerTag): update the blamed network/Wi-Fi and Realtek/HD Audio drivers plus Motherboard Chipset drivers from your vendor, and test turning OFF PCIe Link State Power Management (ASPM) and Windows Fast Startup (and disable unused HDMI/DisplayPort audio devices in Device Manager).")
        } elseif ($hasPciHw) {
            $nextChecks.Add("Check PCI device power-state stability ($powerTag): update the blamed device driver and Motherboard Chipset drivers from your vendor, and test turning OFF PCIe Link State Power Management (ASPM) and Windows Fast Startup.")
        } else {
            $nextChecks.Add("Check audio/power-state stability ($powerTag + idle pattern): update Motherboard Chipset & Realtek/HD Audio drivers from your motherboard vendor, and test turning OFF Windows Fast Startup or PCIe Link State Power Management (and disable unused HDMI/DisplayPort audio devices in Device Manager).")
        }
    }
    if ($restarts.Count -gt 0 -and $bsods.Count -eq 0) {
        $nextChecks.Add("Check power delivery & PSU cables because the PC restarted cleanly without a crash dump (reseat 24-pin ATX / 8-pin EPS / GPU power connectors, check wall outlet/UPS, and inspect motherboard BIOS Event Log if available).")
    }
    $confirmedGpuDriverAttrs = @($attrList | Where-Object { $_.IsGpuDriverFault })
    if ($confirmedGpuDriverAttrs.Count -gt 0) {
        $gpuMention = if ($primaryGpu -and $primaryGpu.FriendlyDriverLabel) { $primaryGpu.FriendlyDriverLabel } else { "the GPU driver" }
        $cleanDrvParts = [System.Collections.Generic.List[string]]::new()
        foreach ($ga in $confirmedGpuDriverAttrs) {
            $c = [string]$ga.BlamedComponent
            if (-not $c) { continue }
            if ($gpuMention -and $gpuMention -ne 'the GPU driver') {
                $escGpu = [regex]::Escape($gpuMention)
                $c = ($c -replace "\s*\($escGpu\)", '').Trim()
                if ($c -ieq $gpuMention -and $ga.SurfaceSymptom) { $c = [string]$ga.SurfaceSymptom }
                elseif ($c -match "^$escGpu\s*\((.+)\)$") { $c = $Matches[1].Trim() }
            }
            if ($c -and -not $cleanDrvParts.Contains($c)) { $cleanDrvParts.Add($c) }
        }
        $drvDetails = if ($cleanDrvParts.Count -gt 0) { $cleanDrvParts -join ', ' } else { (@($confirmedGpuDriverAttrs | ForEach-Object { $_.BlamedComponent } | Select-Object -Unique) -join ', ') }
        if ($gpuAfterInstall.Count -gt 0 -and $gpuBeforeInstall.Count -eq 0 -and $primaryGpu -and $primaryGpu.DriverInstallDate -is [datetime]) {
            $instTiming = Format-DcDriverInstallTiming -IncidentTime $gpuAfterInstall[0] -InstallTime $primaryGpu.DriverInstallDate -DriverLabel $gpuMention
            $afterPhrase = if ($instTiming) { $instTiming.Phrase } else { "after $gpuMention was installed" }
            $nextChecks.Add("Roll back or cleanly reinstall the GPU driver (AMD Cleanup Utility / DDU in Safe Mode): GPU-driver faults ($drvDetails) started $afterPhrase -- testing the previous WHQL version is a strong check.")
        } else {
            $nextChecks.Add("Refresh the GPU driver cleanly (AMD Cleanup Utility / DDU in Safe Mode, then reinstall a WHQL driver): cross-app / system evidence directly implicates $gpuMention ($drvDetails).")
        }
    }
    if ($nextChecks.Count -eq 0 -and $dispDrops.Count -gt 0) {
        $nextChecks.Add("If your screen went black while actively gaming/working, try a certified DisplayPort/HDMI cable or another GPU port; if it only logged while idle, it's just normal monitor sleep.")
    }

    return [PSCustomObject]@{
        Headline            = $headline
        Counts              = [PSCustomObject]@{
            Bsods          = $bsods.Count
            SuddenRestarts = $restarts.Count
            GpuTimeouts    = $gpuTdrs.Count
            GpuHistory14d  = $lkGpuAll.Count
            DisplayDrops   = $dispDrops.Count
            AppGpuCrashes  = $appCrashes.Count
        }
        TranslatedIncidents = @($translated)
        Attributions        = @($attrList)
        IdleNoWarningNote   = $idleNoWarningNote
        ConfirmedFacts      = @($facts)
        WhatThisRulesOut    = @($rulesOut)
        SensibleNextChecks  = @($nextChecks)
    }
}

function Format-DcPlainSummaryReport {
    [CmdletBinding()]
    param($PlainSummary)

    $L = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not $PlainSummary) { return @($L) }
    $add = { param($t, $c = 'Gray') $L.Add([PSCustomObject]@{ Text = $t; Color = $c }) }

    & $add ''
    & $add '========================================================================' 'Cyan'
    & $add '  WHAT HAPPENED (PLAIN-ENGLISH SUMMARY FOR HUMANS)' 'Cyan'
    & $add '========================================================================' 'Cyan'
    $headColor = if ($PlainSummary.Counts.Bsods -gt 0 -or $PlainSummary.Counts.SuddenRestarts -gt 0) { 'Red' } elseif ($PlainSummary.Counts.GpuTimeouts -gt 0) { 'Yellow' } else { 'Green' }
    & $add ("  {0}" -f $PlainSummary.Headline) $headColor
    & $add ''
    & $add ('  Breakdown (scan period): BSODs: {0} | Sudden Power Restarts: {1} | GPU Driver Timeouts: {2} (14d history: {3}) | Monitor Drops: {4} | App Crashes: {5}' -f `
        $PlainSummary.Counts.Bsods, $PlainSummary.Counts.SuddenRestarts, $PlainSummary.Counts.GpuTimeouts, $PlainSummary.Counts.GpuHistory14d, $PlainSummary.Counts.DisplayDrops, $PlainSummary.Counts.AppGpuCrashes) 'White'

    if ($PlainSummary.PSObject.Properties['Attributions'] -and @($PlainSummary.Attributions).Count -gt 0) {
        & $add ''
        & $add '  CAUSE SEPARATION (DRIVER vs. APP vs. SHADER vs. WINDOWS / HARDWARE):' 'Cyan'
        foreach ($at in ($PlainSummary.Attributions | Select-Object -First 10)) {
            $when = if ($at.Timestamp -is [datetime]) { $at.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { 'unknown time' }
            $col = if ($at.IsGpuDriverFault) { 'Red' } elseif ($at.Classification -in @('APP_OR_OVERLAY', 'SHADER_OR_WORKLOAD', 'OS_OR_SYSTEM_EVENT')) { 'Yellow' } else { 'Gray' }
            & $add ("   * [{0}] [{1}] {2} -> {3}: {4}" -f $when, $at.LayerBadge, $at.SurfaceSymptom, $at.BlamedComponent, $at.PlainVerdict) $col
        }
    }

    if (@($PlainSummary.TranslatedIncidents).Count -gt 0) {
        & $add ''
        & $add '  CRASHES EXPLAINED IN PLAIN ENGLISH:' 'Yellow'
        foreach ($ti in $PlainSummary.TranslatedIncidents) {
            & $add ("   * [{0}] {1}" -f $ti.When, $ti.PlainText) 'Gray'
        }
    }

    if ($PlainSummary.IdleNoWarningNote) {
        & $add ''
        & $add '  WHY WERE THERE NO WARNINGS BEFORE THE CRASH?' 'White'
        & $add ("   {0}" -f $PlainSummary.IdleNoWarningNote) 'Gray'
    }

    if (@($PlainSummary.ConfirmedFacts).Count -gt 0) {
        & $add ''
        & $add '  CONFIRMED FACTS:' 'White'
        foreach ($f in $PlainSummary.ConfirmedFacts) { & $add ("   + {0}" -f $f) 'Gray' }
    }

    if (@($PlainSummary.WhatThisRulesOut).Count -gt 0) {
        & $add ''
        & $add '  WHAT THIS RULES OUT (SAVE YOURSELF THE BUSYWORK):' 'Green'
        foreach ($r in $PlainSummary.WhatThisRulesOut) { & $add ("   - {0}" -f $r) 'Gray' }
    }

    if (@($PlainSummary.SensibleNextChecks).Count -gt 0) {
        & $add ''
        & $add '  SENSIBLE NEXT CHECKS (ORDERED BY EVIDENCE):' 'Cyan'
        $i = 1
        foreach ($s in $PlainSummary.SensibleNextChecks) {
            & $add ("   {0}. {1}" -f $i, $s) 'White'
            $i++
        }
    }
    return @($L)
}

function Get-DcCrashPatterns {
    param($Items, [int]$LookbackDays = 7, [int]$WindowMinutes = 30)

    $result = [PSCustomObject]@{ CrashCount = @($Items).Count; Precursors = @(); NoPrecursorCrashes = 0; Notes = @() }
    $items = @($Items)
    if ($items.Count -lt 2) { $result.Notes = @('Fewer than two crashes with a known crash time; no cross-crash comparison possible.'); return $result }

    $since = (Get-Date).AddDays(-$LookbackDays)
    $baselineEvents = [System.Collections.Generic.List[object]]::new()
    try { foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2, 3; StartTime = $since } -ErrorAction Stop)) { $baselineEvents.Add($e) } } catch {}
    try { foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = @($script:DcNotableMap.Keys); StartTime = $since } -ErrorAction Stop)) { $baselineEvents.Add($e) } } catch {}

    $notable = @($baselineEvents | Where-Object { Test-DcNotableEvent -Event $_ -Log 'System' } | Sort-Object TimeCreated -Unique)
    # exclude structural boot/shutdown bookkeeping from precursor statistics
    $skipSources = @('Microsoft-Windows-Kernel-General', 'EventLog', 'Microsoft-Windows-WER-SystemErrorReporting', 'Microsoft-Windows-Kernel-Boot')
    $stat = @($notable | Where-Object { $_.ProviderName -notin $skipSources -and -not ($_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -in 41, 109, 577, 172) })

    $totalWindows = [math]::Max(1, ($LookbackDays * 24 * 60) / $WindowMinutes)
    $byKey = @{}
    foreach ($it in $items) {
        $ws = $it.CrashTime.AddMinutes(-$WindowMinutes)
        if ($it.CrashedBootStart -and $ws -lt $it.CrashedBootStart.AddSeconds(150)) { $ws = $it.CrashedBootStart.AddSeconds(150) }   # skip boot-settling noise
        $keysThisCrash = @($stat | Where-Object { $_.TimeCreated -ge $ws -and $_.TimeCreated -le $it.CrashTime.AddSeconds(1) } | ForEach-Object { "$($_.ProviderName)|$($_.Id)" } | Select-Object -Unique)
        foreach ($k in $keysThisCrash) { if (-not $byKey.ContainsKey($k)) { $byKey[$k] = 0 }; $byKey[$k]++ }
        if ($keysThisCrash.Count -eq 0) { $result.NoPrecursorCrashes++ }
    }

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($k in $byKey.Keys) {
        $cnt = $byKey[$k]
        if ($cnt -lt 2) { continue }
        $parts = $k -split '\|'
        $total = @($stat | Where-Object { $_.ProviderName -eq $parts[0] -and "$($_.Id)" -eq $parts[1] }).Count
        $sample = $stat | Where-Object { $_.ProviderName -eq $parts[0] -and "$($_.Id)" -eq $parts[1] } | Select-Object -First 1
        $expected = [math]::Round(($total / $totalWindows) * $items.Count, 2)   # expected # of crash windows containing it if events were spread evenly
        $rows.Add([PSCustomObject]@{
            Source = $parts[0]; Id = $parts[1]; CrashesPreceded = $cnt; OfCrashes = $items.Count
            TotalInPeriod = $total; ExpectedByChance = [math]::Min($expected, $items.Count)
            Sample = (ConvertTo-DcEventLine $sample)
        })
    }
    $result.Precursors = @($rows | Sort-Object @{ e = 'CrashesPreceded'; Descending = $true }, @{ e = 'TotalInPeriod'; Descending = $false })
    return $result
}

function Format-DcCrashForensicsReport {
    [CmdletBinding()]
    param($Forensics)

    $L = [System.Collections.Generic.List[PSCustomObject]]::new()
    $add = { param($t, $c = 'Gray') $L.Add([PSCustomObject]@{ Text = $t; Color = $c }) }

    & $add '' 
    & $add '========================================================================' 'Cyan'
    & $add '  CRASH FORENSICS - TIMELINE & INVOLVED COMPONENTS (evidence only)' 'Cyan'
    & $add '========================================================================' 'Cyan'

    $crashes = @($Forensics.Crashes)
    if ($crashes.Count -eq 0) {
        & $add '  No bugcheck or unexpected-reboot events found in the lookback period.' 'Green'
    } else {
        # Summary table
        & $add ''
        & $add '  SUMMARY OF CRASHES (newest first)' 'White'
        & $add ('  {0,-19} {1,-14} {2,-20} {3,-22} {4}' -f 'Crash time', 'Stop code', 'Uptime at crash', 'Process / component', 'Boot began') 'DarkGray'
        foreach ($c in $crashes) {
            $ct = if ($c.CrashTime) { $c.CrashTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '~' + $c.LogTime.ToString('MM-dd HH:mm') + ' (log)' }
            $up = if ($c.Dump -and $c.Dump.Uptime) { $c.Dump.Uptime -replace '^0 days ', '' -replace '\.\d+$', '' } else { '?' }
            $comp = if ($c.Dump) { $pn = if ($c.Dump.AnalysisDetail) { $c.Dump.AnalysisDetail.ProcessName } else { $null }; if ($pn -match 'wrong\.symbols') { $pn = $null }; $mn = if ($c.Dump.DebuggerModuleName) { $c.Dump.DebuggerModuleName } else { '-' }; "$pn / $mn" } else { 'dump not analysed' }
            $code = if ($c.BugcheckCode) { $c.BugcheckCode } else { 'none' }
            $trig = 'n/a (not detailed)'
            if ($c.PSObject.Properties['BootTrigger'] -and $c.BootTrigger) { $trig = if ($c.BootTrigger -match '^previous session') { 'after previous crash' } elseif ($c.BootTrigger -match '^restart initiated') { 'after user/app restart' } elseif ($c.BootTrigger -match '^normal') { 'normal restart' } else { 'unknown' } }
            & $add ('  {0,-19} {1,-14} {2,-20} {3,-22} {4}' -f $ct, $code, $up, $comp, $trig) 'Gray'
        }
    }

    $n = 0
    foreach ($c in $crashes) {
        if (-not $c.PSObject.Properties['AnchorTime']) { continue }
        $n++
        $anchor = $c.AnchorTime
        & $add ''
        & $add "------------------------------------------------------------------------" 'DarkGray'
        & $add ("  CRASH #{0}: {1}" -f $n, $c.Kind) 'Yellow'
        & $add "------------------------------------------------------------------------" 'DarkGray'

        if ($c.CrashTime) {
            $upTxt = if ($c.CrashedBootStart) { ' | uptime ' + (Format-DcDuration ($c.CrashTime - $c.CrashedBootStart)) + ' (boot began ' + $c.CrashedBootStart.ToString('MM-dd HH:mm:ss') + ')' } else { '' }
            & $add ("  When:        {0}  [from dump]{1}" -f $c.CrashTime.ToString('yyyy-MM-dd HH:mm:ss'), $upTxt) 'White'
        } else {
            $span = if ($c.OsStart) { " between $($anchor.ToString('HH:mm:ss')) (last logged event) and $($c.OsStart.ToString('HH:mm:ss')) (reboot)" } else { '' }
            & $add ("  When:        exact time unknown (dump not readable){0}" -f $span) 'White'
        }
        if ($c.BootType) { & $add ("  Boot type:   {0}" -f $c.BootType) 'Gray' }
        if ($c.BootTrigger) { & $add ("  Boot began:  {0}" -f $c.BootTrigger) 'Gray' }

        $d = $c.Dump
        if ($d -and $d.CdbInspected) {
            $ad = $d.AnalysisDetail
            $bcName = if ($ad -and $ad.BugcheckName) { $ad.BugcheckName } else { "$($d.ExceptionCode) ($($d.ExceptionMeaning))" }
            & $add ("  Stop code:   {0}  -> {1}" -f $c.BugcheckCode, $bcName) 'Red'
            if ($ad -and $ad.Description) { & $add ("  Meaning:     {0}" -f $ad.Description) 'Gray' }
            if ($ad -and $ad.ArgList) {
                foreach ($a in $ad.ArgList) { & $add ("  Arg{0}:        {1}{2}" -f $a.Index, $a.Value, $(if ($a.Description) { "  - $($a.Description)" } else { '' })) 'DarkGray' }
            }
            $pn = if ($ad) { $ad.ProcessName } else { $null }
            if ($pn -and $pn -notmatch 'wrong\.symbols') { & $add ("  Process:     {0} was the current process when the crash occurred" -f $pn) 'White' }
            if ($d.FailureBucket) { & $add ("  Bucket:      {0}" -f $d.FailureBucket) 'White' }
            if ($d.DebuggerSymbolName) { & $add ("  Fault at:    {0}" -f $d.DebuggerSymbolName) 'White' }
            if ($d.ProbablyCausedBy -and $d.ProbablyCausedBy -match '^Undetermined') { & $add ("  Note:        {0}" -f $d.ProbablyCausedBy) 'Yellow' }
            if ($d.CallStack -and $d.CallStack.Count -gt 0) {
                & $add '  Call stack:' 'DarkGray'
                foreach ($fr in ($d.CallStack | Select-Object -First 10)) { & $add ("     {0}" -f $fr) 'Gray' }
            }
            if ($d.ApiContext) { & $add ("  Stage:       {0}" -f $d.ApiContext) 'Magenta' }
            if ($d.RawAnalysisPath) { & $add ("  Raw debugger output: {0}" -f ($d.RawAnalysisPath -replace '\\scripts\\modules\\\.\.\\\.\.', '')) 'DarkGray' }
        } elseif ($c.BugcheckCode) {
            & $add ("  Stop code:   {0}  (dump not analysed - run from an Administrator PowerShell with WinDbg installed)" -f $c.BugcheckCode) 'Yellow'
        }

        if ($c.Components.Count -gt 0) {
            & $add '' 
            & $add '  SOFTWARE COMPONENTS INVOLVED (from dump):' 'White'
            foreach ($co in $c.Components) {
                $who = if (-not $co.Found) { 'file not found on this system' } else { "$($co.Description) | $($co.Company) | v$($co.Version)" + $(if (-not $co.IsMicrosoft) { '  [THIRD-PARTY]' } else { '' }) }
                $col = if ($co.Found -and -not $co.IsMicrosoft) { 'Yellow' } else { 'Gray' }
                & $add ("     {0,-14} {1,-28} {2}" -f $co.Name, "($($co.Role))", $who) $col
            }
        }

        & $add ''
        & $add ("  TIMELINE (T = crash/last-activity time {0}; notable System+Application events only):" -f $anchor.ToString('HH:mm:ss')) 'White'
        $crossedCrash = $false
        foreach ($t in $c.Timeline) {
            if (-not $crossedCrash -and $t.Time -gt $anchor.AddSeconds(2)) {
                & $add '     ---------------- CRASH (no log entries can be written while the system is down) ----------------' 'Red'
                $crossedCrash = $true
            }
            $lvl = switch ([int]$t.Level) { 1 { 'CRIT' } 2 { 'ERR ' } 3 { 'WARN' } default { 'info' } }
            $col = switch ([int]$t.Level) { 1 { 'Red' } 2 { 'Red' } 3 { 'Yellow' } default { 'Gray' } }
            $cnt = if ($t.Count -gt 1) { " (x$($t.Count))" } else { '' }
            $off = Format-DcOffset (($t.Time - $anchor).TotalSeconds)
            $phase = if ($t.Time -gt $anchor.AddSeconds(2)) { 'POST ' } elseif ($c.CrashedBootStart -and $t.Time -le $c.CrashedBootStart.AddSeconds(150)) { 'BOOT ' } elseif ($t.Time -ge $anchor.AddMinutes(-20)) { 'PRE  ' } else { 'RUN  ' }
            & $add ("     {0}  {1,-11} {2} {3} {4} {5}: {6}{7}" -f $t.Time.ToString('HH:mm:ss'), $off, $phase, $lvl, $t.Source, $t.Id, $t.Message, $cnt) $col
        }
        if (-not $crossedCrash) { & $add '     ---------------- CRASH (no log entries can be written while the system is down) ----------------' 'Red' }

        & $add ''
        & $add '  FACTS FROM THE LOGS:' 'White'
        if ($c.LastActivity) {
            & $add ("   - Last System-log entry before the crash: {0} ({1}s before) - {2} {3}: {4}" -f $c.LastActivity.Time.ToString('HH:mm:ss'), $c.LastActivity.SecondsBeforeCrash, $c.LastActivity.Source, $c.LastActivity.Id, $c.LastActivity.Message) 'Gray'
        }
        if (@($c.BootStartupIssues).Count -gt 0) {
            & $add ("   - During the first 2.5 minutes of the crashed boot (startup), {0} warning/error event(s) were logged by: {1}" -f @($c.BootStartupIssues).Count, ((@($c.BootStartupIssues) | Group-Object Source | ForEach-Object { "$($_.Name) [ids $((@($_.Group) | Select-Object -ExpandProperty Id -Unique) -join ',')]" }) -join '; ')) 'Gray'
        }
        if ($c.PreEvents.Count -eq 0) {
            & $add ("   - No warnings or errors were logged in the {0} minutes before the crash (excluding boot startup); the system gave no logged warning." -f 20) 'Gray'
        } else {
            & $add ("   - {0} warning/error event(s) in the 20 minutes before the crash, from: {1}" -f $c.PreEvents.Count, (($c.ProviderCounts | ForEach-Object { "$($_.Source) [ids $($_.Ids)] x$($_.Count)" }) -join '; ')) 'Yellow'
        }
        if ($c.PSObject.Properties['LiveKernelDuringBoot']) {
            if (@($c.LiveKernelDuringBoot).Count -eq 0) { & $add '   - No non-fatal kernel live-dump reports (GPU timeouts, AMD/NDIS watchdogs) were recorded during the crashed boot session.' 'Gray' }
            else { & $add ("   - {0} non-fatal kernel live-dump report(s) during the crashed boot session: {1}" -f @($c.LiveKernelDuringBoot).Count, ((@($c.LiveKernelDuringBoot) | Select-Object -First 5 | ForEach-Object { "$($_.Time.ToString('MM-dd HH:mm')) $($_.Description)" }) -join '; ')) 'Yellow' }
        }
        $post = @($c.Timeline | Where-Object { $_.Time -gt $anchor.AddSeconds(2) -and $_.Source -match 'Network|NDIS|e2fnexpress|NCSI' })
        if ($post.Count -gt 0) {
            & $add ("   - Network events logged AFTER the crash (during reboot): {0} - these are consequences of the reboot, not precursors." -f (($post | Select-Object -First 3 | ForEach-Object { "$($_.Time.ToString('HH:mm:ss')) $($_.Source) $($_.Id)" }) -join ', ')) 'Gray'
        }
    }

    # Patterns
    $p = $Forensics.Patterns
    & $add ''
    & $add '------------------------------------------------------------------------' 'DarkGray'
    & $add '  CROSS-CRASH PATTERNS (statistics from the logs, not conclusions)' 'Yellow'
    & $add '------------------------------------------------------------------------' 'DarkGray'
    foreach ($note in @($p.Notes)) { & $add "   $note" 'Gray' }
    if ($p.CrashCount -ge 2) {
        & $add ("   - {0} of {1} crashes had NO warning/error/hardware/power event logged in the 30 minutes before them." -f $p.NoPrecursorCrashes, $p.CrashCount) 'White'
        if (@($p.Precursors).Count -eq 0) {
            & $add '   - No event type appeared in the 30 minutes before two or more crashes.' 'Gray'
        } else {
            & $add '   - Events seen in the 30 minutes before multiple crashes (with how often they occur overall):' 'White'
            foreach ($r in $p.Precursors) {
                & $add ("       {0} id {1}: before {2}/{3} crashes | {4} occurrences in period (~{5} crash-windows expected by chance) | {6}" -f $r.Source, $r.Id, $r.CrashesPreceded, $r.OfCrashes, $r.TotalInPeriod, $r.ExpectedByChance, $r.Sample) 'Gray'
            }
        }
        $uptimes = @($Forensics.Crashes | Where-Object { $_.CrashTime -and $_.CrashedBootStart } | ForEach-Object { [int](($_.CrashTime - $_.CrashedBootStart).TotalMinutes) })
        if ($uptimes.Count -gt 0) { & $add ("   - Uptime at crash (minutes): {0}" -f ($uptimes -join ', ')) 'Gray' }
        $procs = @($Forensics.Crashes | Where-Object { $_.Dump -and $_.Dump.AnalysisDetail -and $_.Dump.AnalysisDetail.ProcessName -and $_.Dump.AnalysisDetail.ProcessName -notmatch 'wrong\.symbols' } | ForEach-Object { $_.Dump.AnalysisDetail.ProcessName })
        if ($procs.Count -gt 0) { & $add ("   - Current process at crash: {0}" -f ($procs -join ', ')) 'Gray' }
    }
    $gpuDisp = @($Forensics.GpuDisplayEvents)
    if ($gpuDisp.Count -gt 0) {
        & $add ''
        & $add '------------------------------------------------------------------------' 'DarkGray'
        & $add '  NON-FATAL GPU TIMEOUTS, DISPLAY DROPS & USER-MODE APP CRASHES' 'Yellow'
        & $add '------------------------------------------------------------------------' 'DarkGray'
        foreach ($ge in ($gpuDisp | Select-Object -First 12)) {
            $col = if ($ge.Severity -eq 'Warning') { 'Yellow' } else { 'Gray' }
            & $add ("   * [{0}] {1} ({2}) - {3}" -f $ge.Time.ToString('yyyy-MM-dd HH:mm:ss'), $ge.Category, $ge.Code, $ge.Summary) $col
            & $add ("     What this means: {0}" -f $ge.Explanation) 'DarkGray'
            if (@($ge.ActiveApps).Count -gt 0) {
                & $add ("     Apps reporting errors/hangs around this time: {0}" -f ($ge.ActiveApps -join ', ')) 'White'
            }
            if (@($ge.PrecedingEvents).Count -gt 0) {
                foreach ($pe in $ge.PrecedingEvents) {
                    & $add ("     Nearby log: {0}" -f $pe) 'DarkGray'
                }
            }
        }
    }

    if (@($Forensics.LiveKernelHistory).Count -gt 0) {
        & $add '   - Non-fatal kernel live-dump report history (de-duplicated; real times from file names):' 'White'
        foreach ($g in (@($Forensics.LiveKernelHistory) | Group-Object { $_.Time.ToString('yyyy-MM-dd') } | Sort-Object Name)) {
            & $add ("       {0}: {1}" -f $g.Name, ((@($g.Group) | Group-Object Description | ForEach-Object { "$($_.Name) x$($_.Count) (last $((@($_.Group) | Select-Object -Last 1).Time.ToString('HH:mm')))" }) -join '; ')) 'Gray'
        }
    }
    return @($L)
}

Export-ModuleMember -Function Get-DcLiveKernelReports, Get-DcCrashForensics, Resolve-DcIncidentAttribution, Format-DcDriverInstallTiming, Format-DcCrashForensicsReport, Format-DcPlainSummaryReport, Get-DcPlainEnglishSummary, Get-DcNonFatalGpuAndDisplayEvents, Get-DcCrashList, Get-DcComponentInfo
