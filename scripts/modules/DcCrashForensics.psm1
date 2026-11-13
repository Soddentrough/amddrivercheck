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
        $UnreadableSources = @()
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
        $dump = if ($dumpName) { @($Dumps | Where-Object { $_.FileName -ieq $dumpName } | Select-Object -First 1)[0] } else { $null }
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

    $forensics = [PSCustomObject]@{
        Crashes           = @($items)
        Detailed          = [math]::Min($MaxDetailed, $items.Count)
        Patterns          = $patterns
        LiveKernelHistory = $liveKernel
        GpuDisplayEvents  = $gpuDisplayEvents
        PlainSummary      = $null
    }
    $forensics.PlainSummary = Get-DcPlainEnglishSummary -Forensics $forensics -Dumps $Dumps -Telemetry $Telemetry -Hardware $Hardware -UnreadableSources $UnreadableSources
    return $forensics
}

function Get-DcStopCodePlainEnglish {
    param($Code, $Bucket, $ModuleName, $ImageName, $Args)

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
        return 'Graphics Scheduler Crash (0x119, dxgmms2): Windows'' DirectX graphics scheduler timed out waiting for a GPU command (subtype ' + $(if ($a0) { $a0 } else { 'unknown' }) + ').'
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

function Get-DcPlainEnglishSummary {
    [CmdletBinding()]
    param(
        $Forensics,
        $Dumps = @(),
        $Telemetry = $null,
        $Hardware = $null,
        $UnreadableSources = @()
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

    $translated = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($c in ($bsods | Select-Object -First 6)) {
        $d = $c.Dump
        $plain = if ($d) {
            Get-DcStopCodePlainEnglish -Code $c.BugcheckCode -Bucket $d.FailureBucket -ModuleName $d.DebuggerModuleName -ImageName $d.DebuggerImageName -Args $d.BugcheckArgs
        } else {
            $cArgs = if ($c.PSObject.Properties['BugcheckArgs']) { $c.BugcheckArgs } else { @() }
            Get-DcStopCodePlainEnglish -Code $c.BugcheckCode -Args $cArgs
        }
        $whenTxt = if ($c.CrashTime) { $c.CrashTime.ToString('yyyy-MM-dd HH:mm') } else { $c.LogTime.ToString('yyyy-MM-dd HH:mm') + ' (log time)' }
        $procTxt = if ($d -and $d.AnalysisDetail -and $d.AnalysisDetail.ProcessName -and $d.AnalysisDetail.ProcessName -notmatch 'wrong\.symbols') { " while $($d.AnalysisDetail.ProcessName) was active" } else { '' }
        $translated.Add([PSCustomObject]@{
            Kind = 'BSOD'
            When = $whenTxt
            Code = if ($c.BugcheckCode) { $c.BugcheckCode } else { 'Unknown' }
            PlainText = "$plain$procTxt"
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
        $facts.Add("$($appCrashes.Count) user-mode app crash dump(s) — only those individual programs closed; they did not reboot Windows.")
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

    # Build Next Checks strictly from what was actually seen
    if (@($UnreadableSources).Count -gt 0) {
        $nextChecks.Add("Run DriverCheck as Administrator (with WinDbg installed) so Windows' protected C:\WINDOWS\Minidump crash files can be decoded.")
    }
    $hasMem = @($bsods | Where-Object { $_.BugcheckCode -match '0x0*(1a|4e|50|d1|3b|7e|1000007e)' }).Count -gt 0
    if ($hasMem) {
        $expoTxt = if ($Hardware -and $Hardware.Memory -and $Hardware.Memory.ConfiguredClockSpeed -ge 5600) { " (your RAM is at $($Hardware.Memory.ConfiguredClockSpeed) MT/s)" } else { "" }
        $nextChecks.Add("Test system memory (RAM) stability: Windows hit multiple memory/page-corruption BSODs (0x1A / 0x4E / 0x1000007E)$expoTxt. Run Windows Memory Diagnostic (mdsched.exe) or TestMem5/OCCT memory test; if it errors at current speed, temporarily test at JEDEC base speed (or update motherboard BIOS for AGESA/memory stability).")
    }
    $hasPowerHang = @($bsods | Where-Object { $_.BugcheckCode -match '0x0*9f' -or ($_.Dump -and $_.Dump.DebuggerModuleName -match 'HDAudBus') }).Count -gt 0
    if ($hasPowerHang) {
        $nextChecks.Add("Check audio/power-state stability (0x9F HDAudBus.sys + idle pattern): update Motherboard Chipset & Realtek/HD Audio drivers from your motherboard vendor, and test turning OFF Windows Fast Startup or PCIe Link State Power Management (and disable unused HDMI/DisplayPort audio devices in Device Manager).")
    }
    if ($restarts.Count -gt 0 -and $bsods.Count -eq 0) {
        $nextChecks.Add("Check power delivery & PSU cables because the PC restarted cleanly without a crash dump (reseat 24-pin ATX / 8-pin EPS / GPU power connectors, check wall outlet/UPS, and inspect motherboard BIOS Event Log if available).")
    }
    if ($gpuTdrs.Count -gt 0 -or @($bsods | Where-Object { $_.BugcheckCode -match '0x0*(116|119)' }).Count -gt 0) {
        $nextChecks.Add("Refresh the GPU driver cleanly (AMD Cleanup Utility / DDU in Safe Mode, then reinstall WHQL driver) because recent GPU timeout/scheduler events (0x119 / 0x141 / 0x117) were recorded.")
    }
    if ($nextChecks.Count -eq 0 -and $dispDrops.Count -gt 0) {
        $nextChecks.Add("If your screen went black while actively gaming/working, try a certified DisplayPort/HDMI cable or another GPU port; if it only logged while idle, it's just normal monitor sleep.")
    }

    return [PSCustomObject]@{
        Headline          = $headline
        Counts            = [PSCustomObject]@{
            Bsods          = $bsods.Count
            SuddenRestarts = $restarts.Count
            GpuTimeouts    = $gpuTdrs.Count
            GpuHistory14d  = $lkGpuAll.Count
            DisplayDrops   = $dispDrops.Count
            AppGpuCrashes  = $appCrashes.Count
        }
        TranslatedIncidents = @($translated)
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

Export-ModuleMember -Function Get-DcLiveKernelReports, Get-DcCrashForensics, Format-DcCrashForensicsReport, Format-DcPlainSummaryReport, Get-DcPlainEnglishSummary, Get-DcNonFatalGpuAndDisplayEvents, Get-DcCrashList, Get-DcComponentInfo
