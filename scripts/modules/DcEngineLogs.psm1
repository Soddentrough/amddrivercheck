<#
.SYNOPSIS
    DriverCheck - Game Engine & Platform Log Inspector Module
.DESCRIPTION
    Analyzes game engine logs (Unreal, Unity, idTech, Source 2, Godot) and Steam
    telemetry logs, suppressing clean exit patterns and capturing real crash markers.
#>

function Protect-DcLogText {
    param([string]$Text)
    if (-not $Text) { return $Text }

    # Redact SteamID3 ([U:1:xxxxxx]) to preserve user privacy
    $sanitized = $Text -replace '\[U:\d+:\d+\]', '[U:1:REDACTED]'

    # Redact user profile directory paths (<Drive>:\Users\<username> -> %USERPROFILE%)
    if ($env:USERPROFILE) {
        $sanitized = $sanitized.Replace($env:USERPROFILE, "%USERPROFILE%")
    }
    $sanitized = $sanitized -replace '(?i)[a-zA-Z]:\\Users\\[^\\"\r\n]+(?=\\)', '%USERPROFILE%'
    $sanitized = $sanitized -replace '(?i)[a-zA-Z]:\\Users\\[^\\"\r\n\s]+', '%USERPROFILE%'
    $sanitized = $sanitized -replace '(?i)User:\s*[^\r\n\.\s]+\\[^\r\n\.\s]+', 'User: [REDACTED]'

    return $sanitized
}

function Read-DcSharedLogLines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [int]$Tail = 0,

        [Parameter(Mandatory = $false)]
        [int]$MaxBytes = 524288
    )

    if (-not $Path -or -not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return @() }
    $fs = $null
    $sr = $null
    try {
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        $skipFirstPartial = $false
        if ($Tail -gt 0 -and $MaxBytes -gt 0 -and $fs.Length -gt $MaxBytes) {
            [void]$fs.Seek(-$MaxBytes, [System.IO.SeekOrigin]::End)
            $skipFirstPartial = $true
        }
        $sr = [System.IO.StreamReader]::new($fs, [System.Text.Encoding]::UTF8, $true)
        if ($skipFirstPartial -and -not $sr.EndOfStream) {
            [void]$sr.ReadLine()
        }
        $all = [System.Collections.Generic.List[string]]::new()
        while (-not $sr.EndOfStream) {
            $ln = $sr.ReadLine()
            if ($null -ne $ln) { $all.Add($ln) }
        }
        if ($Tail -gt 0 -and $all.Count -gt $Tail) {
            return @($all.GetRange($all.Count - $Tail, $Tail))
        }
        return @($all)
    } catch {
        return @()
    } finally {
        if ($sr) { $sr.Dispose() }
        elseif ($fs) { $fs.Dispose() }
    }
}

function Get-DcSteamPath {
    $steamPath = $null
    $regVal = Get-ItemProperty -Path "HKCU:\Software\Valve\Steam" -Name "SteamPath" -ErrorAction SilentlyContinue
    if ($regVal -and $regVal.SteamPath) {
        $steamPath = $regVal.SteamPath.Replace('/', '\')
    } else {
        $regVal32 = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam" -Name "InstallPath" -ErrorAction SilentlyContinue
        if ($regVal32 -and $regVal32.InstallPath) { $steamPath = $regVal32.InstallPath }
    }
    if (-not $steamPath -and (Test-Path "C:\Program Files (x86)\Steam")) {
        $steamPath = "C:\Program Files (x86)\Steam"
    }
    return $steamPath
}

function Get-DcSteamAppNameMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$SteamPath
    )

    $resolved = if ($SteamPath) { $SteamPath } else { Get-DcSteamPath }
    $map = @{}
    if (-not $resolved -or -not (Test-Path -LiteralPath $resolved -ErrorAction SilentlyContinue)) {
        return $map
    }

    $steamAppsDirs = [System.Collections.Generic.List[string]]::new()
    $primaryApps = Join-Path $resolved "steamapps"
    if (Test-Path -LiteralPath $primaryApps -ErrorAction SilentlyContinue) {
        $steamAppsDirs.Add($primaryApps)
    }

    $libVdf = Join-Path $primaryApps "libraryfolders.vdf"
    if (Test-Path -LiteralPath $libVdf -ErrorAction SilentlyContinue) {
        $vdfLines = Read-DcSharedLogLines -Path $libVdf -MaxBytes 131072
        foreach ($vl in $vdfLines) {
            if ($vl -match '"path"\s+"([^"]+)"') {
                $libRoot = $Matches[1].Replace('\\', '\')
                $sa = Join-Path $libRoot "steamapps"
                if ((Test-Path -LiteralPath $sa -ErrorAction SilentlyContinue) -and -not $steamAppsDirs.Contains($sa)) {
                    $steamAppsDirs.Add($sa)
                }
            }
        }
    }

    foreach ($saDir in $steamAppsDirs) {
        $manifests = Get-ChildItem -LiteralPath $saDir -Filter "appmanifest_*.acf" -File -ErrorAction SilentlyContinue
        foreach ($mf in $manifests) {
            $lines = Read-DcSharedLogLines -Path $mf.FullName -MaxBytes 65536
            $appId = $null
            $name = $null
            $installDir = $null
            foreach ($ln in $lines) {
                if (-not $appId -and $ln -match '"appid"\s+"(\d+)"') { $appId = $Matches[1] }
                elseif (-not $name -and $ln -match '"name"\s+"([^"]+)"') { $name = $Matches[1] }
                elseif (-not $installDir -and $ln -match '"installdir"\s+"([^"]+)"') { $installDir = $Matches[1] }
                if ($appId -and $name -and $installDir) { break }
            }
            if ($appId -and $name -and -not $map.ContainsKey($appId)) {
                $map[$appId] = [PSCustomObject]@{
                    AppId      = $appId
                    Name       = $name
                    InstallDir = $installDir
                }
            }
        }
    }

    return $map
}

function Get-DcSteamLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddHours(-48),

        [Parameter(Mandatory = $false)]
        [datetime]$EndTime = (Get-Date)
    )

    $steamPath = Get-DcSteamPath
    if (-not $steamPath) { return @() }

    $logFiles = @(
        (Join-Path $steamPath "logs\gameoverlay_ui.txt"),
        (Join-Path $steamPath "logs\gameoverlay_ui.previous.txt"),
        (Join-Path $steamPath "logs\gameoverlay_renderer.txt"),
        (Join-Path $steamPath "logs\webhelper.txt"),
        (Join-Path $steamPath "logs\webhelper_gpu.txt"),
        (Join-Path $steamPath "logs\shader_log.txt"),
        (Join-Path $steamPath "logs\connection_log.txt")
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($lp in $logFiles) {
        if (Test-Path $lp) {
            $item = Get-Item $lp
            if ($item.LastWriteTime -ge $Cutoff -and $item.LastWriteTime -le $EndTime) {
                $lines = Read-DcSharedLogLines -Path $lp -Tail 300
                if ($lines) {
                    $errors = [System.Collections.Generic.List[string]]::new()
                    $isShaderOrGpuLog = ($item.Name -match '(?i)shader_log|webhelper_gpu')
                    foreach ($line in $lines) {
                        # Exclude benign normal hook teardown on clean game exit
                        if ($line -match '(?i)GameOverlayRenderer\.dll detaching|Detaching input hook') {
                            continue
                        }
                        if ($isShaderOrGpuLog) {
                            if ($line -match '(?i)failed\s+to\s+compile|corrupt\s+pipeline|VK_ERROR_DEVICE_LOST|DXGI_ERROR|GPU\s+process\s+exited\s+unexpectedly|ContextResult::kTransientFailure|kFatalFailure|ERROR:\s*fossilize') {
                                $errors.Add((Protect-DcLogText $line.Trim()))
                            }
                        } elseif ($line -match '(?i)stalled|fatal assert|exitonfatalassert|cross-thread pipe|pipes\.cpp|The game hasn''t rendered a frame|possibly crashed/killed game|OnSystemPowerStateSuspend|BMainLoop appears to have stalled|OnNetworkDeviceStateChange|failed talking to cm|Connectivity test.*failed|Reset cReconnectAttempts') {
                            $errors.Add((Protect-DcLogText $line.Trim()))
                        }
                    }

                    if ($errors.Count -gt 0) {
                        $results.Add([PSCustomObject]@{
                            LogName       = $item.Name
                            FullName      = (Protect-DcLogText $item.FullName)
                            Timestamp     = $item.LastWriteTime
                            ErrorLines    = @($errors)
                            IsPipeError   = ($errors | Where-Object { $_ -match '(?i)pipes\.cpp|cross-thread pipe|ExitOnFatalAssert' }).Count -gt 0
                            IsShaderError = ($item.Name -ieq 'shader_log.txt') -or (($errors | Where-Object { $_ -match '(?i)shader|fossilize|VK_ERROR_DEVICE_LOST|DXGI_ERROR|GPU process exited' }).Count -gt 0)
                        })
                    }
                }
            }
        }
    }

    return $results
}

function Get-DcSteamGameSessions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddDays(-14),

        [Parameter(Mandatory = $false)]
        [datetime]$EndTime = (Get-Date),

        [Parameter(Mandatory = $false)]
        [string]$SteamPath
    )

    $resolvedSteamPath = if ($SteamPath) { $SteamPath } else { Get-DcSteamPath }
    if (-not $resolvedSteamPath) { return @() }

    $appMap = Get-DcSteamAppNameMap -SteamPath $resolvedSteamPath
    $resolveName = {
        param([string]$aid)
        if ($aid -and $appMap.ContainsKey($aid)) { return $appMap[$aid].Name }
        return $null
    }

    $sessions = [System.Collections.Generic.List[PSCustomObject]]::new()
    $inv = [System.Globalization.CultureInfo]::InvariantCulture

    # 1. Parse gameprocess_log.txt (+ .previous.txt) for ALL game launches + exit codes
    foreach ($gpName in @('gameprocess_log.txt', 'gameprocess_log.previous.txt')) {
        $gpPath = Join-Path $resolvedSteamPath "logs\$gpName"
        if (-not (Test-Path -LiteralPath $gpPath -ErrorAction SilentlyContinue)) { continue }
        $gpItem = Get-Item -LiteralPath $gpPath -ErrorAction SilentlyContinue
        if ($gpItem -and $gpItem.LastWriteTime -lt $Cutoff) { continue }

        $lines = Read-DcSharedLogLines -Path $gpPath -Tail 3000
        if (-not $lines) { continue }

        $openGp = @{}
        $lastTs = $null
        foreach ($line in $lines) {
            if ($line -match '^\[(?<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\].*?(?:AppID\s+(?<appid>\d+)\s+adding\s+PID\s+(?<pid>\d+)|Adding\s+process\s+(?<pid>\d+)\s+for\s+game\s*ID\s+(?<appid>\d+))') {
                $appId = $Matches['appid']
                if ($appId -eq '1') { continue }
                $ts = [datetime]::MinValue
                if ([datetime]::TryParseExact($Matches['ts'], 'yyyy-MM-dd HH:mm:ss', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$ts)) {
                    $lastTs = $ts
                    if (-not $openGp.ContainsKey($appId)) {
                        $openGp[$appId] = [PSCustomObject]@{ Start = $ts; ExitCode = $null; LastPidEnd = $null }
                    }
                }
            } elseif ($line -match '^\[(?<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\].*?AppID\s+(?<appid>\d+)\s+no\s+longer\s+tracking\s+PID\s+(?<pid>\d+),\s+exit\s+code\s+(?<exit>-?\d+)') {
                $appId = $Matches['appid']
                if ($appId -eq '1') { continue }
                $exitVal = [int64]$Matches['exit']
                $ts = [datetime]::MinValue
                if ([datetime]::TryParseExact($Matches['ts'], 'yyyy-MM-dd HH:mm:ss', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$ts)) {
                    $lastTs = $ts
                    if ($openGp.ContainsKey($appId)) {
                        $openGp[$appId].ExitCode = $exitVal
                        $openGp[$appId].LastPidEnd = $ts
                    }
                }
            } elseif ($line -match '^\[(?<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\].*?(?:Remove\s+(?<appid>\d+)\s+from\s+running\s+list|Removing\s+process\s+\d+\s+for\s+game\s*ID\s+(?<appid>\d+))') {
                $appId = $Matches['appid']
                if ($appId -eq '1') { continue }
                $ts = [datetime]::MinValue
                if ([datetime]::TryParseExact($Matches['ts'], 'yyyy-MM-dd HH:mm:ss', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$ts)) {
                    $lastTs = $ts
                    if ($openGp.ContainsKey($appId)) {
                        $entry = $openGp[$appId]
                        $openGp.Remove($appId)
                        $startTs = $entry.Start
                        $ec = $entry.ExitCode
                        if ($ts -ge $Cutoff -and $startTs -le $EndTime -and $ts -ge $startTs) {
                            $sessions.Add([PSCustomObject]@{
                                AppId            = $appId
                                GameName         = (& $resolveName $appId)
                                StartTime        = $startTs
                                EndTime          = $ts
                                IsActive         = $false
                                DurationMinutes  = [math]::Round(($ts - $startTs).TotalMinutes, 1)
                                ExitCode         = $ec
                                ExitedAbnormally = ($null -ne $ec -and $ec -ne 0)
                                SourceLog        = $gpName
                            })
                        }
                    }
                }
            }
        }

        foreach ($remAppId in @($openGp.Keys)) {
            $entry = $openGp[$remAppId]
            $startTs = $entry.Start
            $ec = $entry.ExitCode
            if ($null -ne $entry.LastPidEnd) {
                $endTs = $entry.LastPidEnd
                if ($endTs -ge $Cutoff -and $startTs -le $EndTime -and $endTs -ge $startTs) {
                    $sessions.Add([PSCustomObject]@{
                        AppId            = $remAppId
                        GameName         = (& $resolveName $remAppId)
                        StartTime        = $startTs
                        EndTime          = $endTs
                        IsActive         = $false
                        DurationMinutes  = [math]::Round(($endTs - $startTs).TotalMinutes, 1)
                        ExitCode         = $ec
                        ExitedAbnormally = ($null -ne $ec -and $ec -ne 0)
                        SourceLog        = $gpName
                    })
                }
            } elseif ($gpName -eq 'gameprocess_log.txt') {
                $nowTs = if ($EndTime -lt (Get-Date)) { $EndTime } else { Get-Date }
                if ($nowTs -ge $Cutoff -and $startTs -le $EndTime -and $nowTs -ge $startTs) {
                    $sessions.Add([PSCustomObject]@{
                        AppId            = $remAppId
                        GameName         = (& $resolveName $remAppId)
                        StartTime        = $startTs
                        EndTime          = $nowTs
                        IsActive         = $true
                        DurationMinutes  = [math]::Round(($nowTs - $startTs).TotalMinutes, 1)
                        ExitCode         = $null
                        ExitedAbnormally = $false
                        SourceLog        = $gpName
                    })
                }
            }
        }
    }

    # 2. Parse streaming_log.txt as additional/fallback source
    $streamingLog = Join-Path $resolvedSteamPath "logs\streaming_log.txt"
    if (Test-Path $streamingLog) {
        $lines = Read-DcSharedLogLines -Path $streamingLog -Tail 2500
        if ($lines) {
            $openSessions = @{}
            foreach ($line in $lines) {
                if ($line -match '^\[(?<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\].*?(?:Game Recording - would start recording game|Game Recording - game started \[gameid=|Adding process \d+ for gameID)\s*(?<appid>\d+)') {
                    $appId = $Matches['appid']
                    if ($appId -eq '1') { continue }
                    $ts = [datetime]::MinValue
                    if ([datetime]::TryParseExact($Matches['ts'], 'yyyy-MM-dd HH:mm:ss', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$ts)) {
                        if (-not $openSessions.ContainsKey($appId)) {
                            $openSessions[$appId] = $ts
                        }
                    }
                } elseif ($line -match '^\[(?<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\].*?Game Recording - game stopped \[gameid=(?<appid>\d+)\]') {
                    $appId = $Matches['appid']
                    if ($appId -eq '1') { continue }
                    $ts = [datetime]::MinValue
                    if ([datetime]::TryParseExact($Matches['ts'], 'yyyy-MM-dd HH:mm:ss', $inv, [System.Globalization.DateTimeStyles]::None, [ref]$ts)) {
                        if ($openSessions.ContainsKey($appId)) {
                            $startTs = $openSessions[$appId]
                            $openSessions.Remove($appId)
                            if ($ts -ge $Cutoff -and $startTs -le $EndTime -and $ts -ge $startTs) {
                                $dup = @($sessions | Where-Object { $_.AppId -eq $appId -and [math]::Abs(($_.StartTime - $startTs).TotalSeconds) -le 90 })
                                if ($dup.Count -eq 0) {
                                    $sessions.Add([PSCustomObject]@{
                                        AppId            = $appId
                                        GameName         = (& $resolveName $appId)
                                        StartTime        = $startTs
                                        EndTime          = $ts
                                        IsActive         = $false
                                        DurationMinutes  = [math]::Round(($ts - $startTs).TotalMinutes, 1)
                                        ExitCode         = $null
                                        ExitedAbnormally = $false
                                        SourceLog        = "streaming_log.txt"
                                    })
                                }
                            }
                        }
                    }
                }
            }

            foreach ($activeAppId in @($openSessions.Keys)) {
                $startTs = $openSessions[$activeAppId]
                $nowTs = if ($EndTime -lt (Get-Date)) { $EndTime } else { Get-Date }
                if ($nowTs -ge $Cutoff -and $startTs -le $EndTime -and $nowTs -ge $startTs) {
                    $dup = @($sessions | Where-Object { $_.AppId -eq $activeAppId -and [math]::Abs(($_.StartTime - $startTs).TotalSeconds) -le 90 })
                    if ($dup.Count -eq 0) {
                        $sessions.Add([PSCustomObject]@{
                            AppId            = $activeAppId
                            GameName         = (& $resolveName $activeAppId)
                            StartTime        = $startTs
                            EndTime          = $nowTs
                            IsActive         = $true
                            DurationMinutes  = [math]::Round(($nowTs - $startTs).TotalMinutes, 1)
                            ExitCode         = $null
                            ExitedAbnormally = $false
                            SourceLog        = "streaming_log.txt"
                        })
                    }
                }
            }
        }
    }

    return @($sessions | Sort-Object StartTime -Descending)
}

function Get-DcShaderAndBreadcrumbs {
    param([string[]]$Lines)

    $shader = $null
    $breadcrumbs = $null
    $gpuErrCode = $null

    foreach ($l in $Lines) {
        if (-not $shader -and $l -match '(?i)(?:Compiling\s+shader|Shader\s+compilation\s+failed|Shader|Material|Pipeline|Dispatch)[\s:]+([^\r\n]{3,120}\.(?:usf|hlsl|spv|cso|glsl)|[a-zA-Z0-9_\-\.\/\\]+)') {
            $matched = $Matches[1].Trim()
            if ($matched -and $matched -notmatch '(?i)^(error|failed|true|false|warning|none|null|the|this|an|a)$') {
                $shader = $matched
            }
        }
        if (-not $breadcrumbs -and $l -match '(?i)(?:AutoBreadcrumbs|DRED|Last\s+completed\s+breadcrumb|Breadcrumb[s]?|Last\s+Breadcrumb|GPU\s+Marker|Active\s+pass|RenderPass|PageFaultVA)[\s:=]+([^\r\n]{3,140})') {
            $breadcrumbs = $Matches[1].Trim()
        }
        if (-not $gpuErrCode -and $l -match '(?i)(0x887A00\d\d|DXGI_ERROR_[A-Z0-9_]+|VK_ERROR_DEVICE_LOST)') {
            $gpuErrCode = $Matches[1].Trim()
        }
    }

    return [PSCustomObject]@{
        ShaderInfo   = $shader
        Breadcrumbs  = $breadcrumbs
        GpuErrorCode = $gpuErrCode
    }
}

function Get-DcEngineLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddHours(-48),

        [Parameter(Mandatory = $false)]
        [datetime]$EndTime = (Get-Date)
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # 1. Unreal Engine Saved Logs & CrashContext (%LOCALAPPDATA%\*\Saved\Logs\*.log and %LOCALAPPDATA%\*\Saved\Crashes\*)
    if (Test-Path $env:LOCALAPPDATA) {
        $ueLogDirs = Get-ChildItem "$env:LOCALAPPDATA" -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName "Saved\Logs" } |
            Where-Object { Test-Path $_ }

        foreach ($dir in $ueLogDirs) {
            $inferredGame = Split-Path (Split-Path $dir -Parent) -Leaf
            $logs = Get-ChildItem -Path $dir -Filter "*.log" -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Cutoff -and $_.LastWriteTime -le $EndTime }
            foreach ($log in $logs) {
                $lines = Read-DcSharedLogLines -Path $log.FullName -Tail 250
                $critLines = $lines | Where-Object {
                    $_ -match '(?i)Fatal error|CrashReportClient|Assertion failed|GPU Crash dump Triggered|DXGI_ERROR|D3D12.*Hung|DeviceRemovedReason|DRED|AutoBreadcrumbs|Out of memory'
                } | ForEach-Object { Protect-DcLogText $_ }
                if ($critLines) {
                    $sb = Get-DcShaderAndBreadcrumbs -Lines $lines
                    $results.Add([PSCustomObject]@{
                        Engine         = "Unreal Engine"
                        LogName        = $log.Name
                        FullName       = (Protect-DcLogText $log.FullName)
                        Timestamp      = $log.LastWriteTime
                        ErrorLines     = @($critLines)
                        GameName       = $inferredGame
                        ExecutableName = $null
                        CommandLine    = $null
                        ShaderInfo     = $sb.ShaderInfo
                        Breadcrumbs    = $sb.Breadcrumbs
                        GpuErrorCode   = $sb.GpuErrorCode
                    })
                }
            }
        }

        # Unreal Saved Crashes (CrashContext.runtime-xml)
        $ueCrashDirs = Get-ChildItem "$env:LOCALAPPDATA" -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName "Saved\Crashes" } |
            Where-Object { Test-Path $_ }

        foreach ($cdir in $ueCrashDirs) {
            $xmlFiles = Get-ChildItem -Path $cdir -Filter "CrashContext.runtime-xml" -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Cutoff -and $_.LastWriteTime -le $EndTime }
            foreach ($xf in $xmlFiles) {
                try {
                    $rawLines = Read-DcSharedLogLines -Path $xf.FullName -MaxBytes 524288
                    if (-not $rawLines -or $rawLines.Count -eq 0) { continue }
                    $rawText = $rawLines -join "`n"
                    $gameName = if ($rawText -match '<GameName>(.*?)</GameName>') { $Matches[1].Trim() } else { $null }
                    $exeName = if ($rawText -match '<ExecutableName>(.*?)</ExecutableName>') { $Matches[1].Trim() } else { $null }
                    $errMsg = if ($rawText -match '<ErrorMessage>(.*?)</ErrorMessage>') { $Matches[1].Trim() } else { $null }
                    $cmdLine = if ($rawText -match '<CommandLine>(.*?)</CommandLine>') { $Matches[1].Trim() } else { $null }
                    $rhiName = if ($rawText -match '<RHI\.RHIName>(.*?)</RHI\.RHIName>') { $Matches[1].Trim() } else { $null }

                    $errLines = [System.Collections.Generic.List[string]]::new()
                    if ($errMsg) { $errLines.Add((Protect-DcLogText $errMsg)) }
                    if ($rhiName) { $errLines.Add("RHI Subsystem: $rhiName") }

                    $sb = Get-DcShaderAndBreadcrumbs -Lines $rawLines

                    $results.Add([PSCustomObject]@{
                        Engine         = "Unreal Engine (CrashContext)"
                        LogName        = $xf.Name
                        FullName       = (Protect-DcLogText $xf.FullName)
                        Timestamp      = $xf.LastWriteTime
                        ErrorLines     = @($errLines)
                        GameName       = $gameName
                        ExecutableName = $exeName
                        CommandLine    = (Protect-DcLogText $cmdLine)
                        ShaderInfo     = $sb.ShaderInfo
                        Breadcrumbs    = $sb.Breadcrumbs
                        GpuErrorCode   = $sb.GpuErrorCode
                    })
                } catch {}
            }
        }
    }

    # 2. Unity Engine Player Logs (%USERPROFILE%\AppData\LocalLow\*\*\Player.log)
    $localLow = Join-Path $env:USERPROFILE "AppData\LocalLow"
    if (Test-Path $localLow) {
        $unityLogs = Get-ChildItem -Path $localLow -Recurse -Include "Player.log", "Player-prev.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Cutoff -and $_.LastWriteTime -le $EndTime }
        foreach ($ulog in $unityLogs) {
            $lines = Read-DcSharedLogLines -Path $ulog.FullName -Tail 250
            $critLines = $lines | Where-Object {
                $_ -match '(?i)Crash!!!|Fatal Error|d3d11: failed to create|d3d12: failed to|D3D12 device removed|Vulkan: out of device memory|VK_ERROR_DEVICE_LOST|DXGI_ERROR|NullReferenceException|StackOverflowException'
            } | ForEach-Object { Protect-DcLogText $_ }
            if ($critLines) {
                $sb = Get-DcShaderAndBreadcrumbs -Lines $lines
                $results.Add([PSCustomObject]@{
                    Engine         = "Unity"
                    LogName        = $ulog.Name
                    FullName       = (Protect-DcLogText $ulog.FullName)
                    Timestamp      = $ulog.LastWriteTime
                    ErrorLines     = @($critLines)
                    GameName       = (Split-Path $ulog.DirectoryName -Leaf)
                    ExecutableName = $null
                    CommandLine    = $null
                    ShaderInfo     = $sb.ShaderInfo
                    Breadcrumbs    = $sb.Breadcrumbs
                    GpuErrorCode   = $sb.GpuErrorCode
                })
            }
        }
    }

    # 3. idTech Engine Console Logs (%USERPROFILE%\Saved Games\*\base\*.log)
    $savedGames = Join-Path $env:USERPROFILE "Saved Games"
    if (Test-Path $savedGames) {
        $idLogs = Get-ChildItem -Path $savedGames -Recurse -Filter "qconsole.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Cutoff -and $_.LastWriteTime -le $EndTime }
        foreach ($il in $idLogs) {
            $lines = Read-DcSharedLogLines -Path $il.FullName -Tail 250
            $critLines = $lines | Where-Object {
                $_ -match '(?i)Failed to allocate.*material|buffer allocation failure|catchup timeout expired|FATAL ERROR|VK_ERROR_DEVICE_LOST|DXGI_ERROR'
            } | ForEach-Object { Protect-DcLogText $_ }
            if ($critLines) {
                $sb = Get-DcShaderAndBreadcrumbs -Lines $lines
                $results.Add([PSCustomObject]@{
                    Engine         = "idTech"
                    LogName        = $il.Name
                    FullName       = (Protect-DcLogText $il.FullName)
                    Timestamp      = $il.LastWriteTime
                    ErrorLines     = @($critLines)
                    GameName       = (Split-Path (Split-Path $il.DirectoryName -Parent) -Leaf)
                    ExecutableName = $null
                    CommandLine    = $null
                    ShaderInfo     = $sb.ShaderInfo
                    Breadcrumbs    = $sb.Breadcrumbs
                    GpuErrorCode   = $sb.GpuErrorCode
                })
            }
        }
    }

    # 4. Godot Engine Logs (%APPDATA%\Godot\app_userdata\*\logs\godot.log)
    $godotDir = Join-Path $env:APPDATA "Godot\app_userdata"
    if (Test-Path $godotDir) {
        $godotLogs = Get-ChildItem -Path $godotDir -Recurse -Filter "godot.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Cutoff -and $_.LastWriteTime -le $EndTime }
        foreach ($gl in $godotLogs) {
            $lines = Read-DcSharedLogLines -Path $gl.FullName -Tail 200
            $critLines = $lines | Where-Object { $_ -match '(?i)ERROR:|CRITICAL:|FATAL:' } | ForEach-Object { Protect-DcLogText $_ }
            if ($critLines) {
                $sb = Get-DcShaderAndBreadcrumbs -Lines $lines
                $results.Add([PSCustomObject]@{
                    Engine         = "Godot"
                    LogName        = $gl.Name
                    FullName       = (Protect-DcLogText $gl.FullName)
                    Timestamp      = $gl.LastWriteTime
                    ErrorLines     = @($critLines)
                    GameName       = (Split-Path (Split-Path $gl.DirectoryName -Parent) -Leaf)
                    ExecutableName = $null
                    CommandLine    = $null
                    ShaderInfo     = $sb.ShaderInfo
                    Breadcrumbs    = $sb.Breadcrumbs
                    GpuErrorCode   = $sb.GpuErrorCode
                })
            }
        }
    }

    # 5. Pearl Abyss / BlackSpace Engine Logs (%LOCALAPPDATA%\Pearl Abyss\log\*.log)
    $paLogDir = Join-Path $env:LOCALAPPDATA "Pearl Abyss\log"
    if (Test-Path $paLogDir) {
        $paLogs = Get-ChildItem -Path $paLogDir -Filter "*.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Cutoff -and $_.LastWriteTime -le $EndTime }
        foreach ($pl in $paLogs) {
            $lines = Read-DcSharedLogLines -Path $pl.FullName -Tail 200
            $critLines = $lines | Where-Object { $_ -match '(?i)\[ERROR\]|\[FATAL\]|DATA_ERROR|Crash|Exception|DXGI_ERROR|VK_ERROR' } | ForEach-Object { Protect-DcLogText $_ }
            if ($critLines) {
                $sb = Get-DcShaderAndBreadcrumbs -Lines $lines
                $results.Add([PSCustomObject]@{
                    Engine         = "BlackSpace Engine (Pearl Abyss)"
                    LogName        = $pl.Name
                    FullName       = (Protect-DcLogText $pl.FullName)
                    Timestamp      = $pl.LastWriteTime
                    ErrorLines     = @($critLines)
                    GameName       = "Pearl Abyss"
                    ExecutableName = $null
                    CommandLine    = $null
                    ShaderInfo     = $sb.ShaderInfo
                    Breadcrumbs    = $sb.Breadcrumbs
                    GpuErrorCode   = $sb.GpuErrorCode
                })
            }
        }
    }

    # 6. CD Projekt Red / REDengine (Cyberpunk 2077 / Witcher 3)
    $cdprDir = Join-Path $env:LOCALAPPDATA "CD Projekt Red"
    if (Test-Path $cdprDir) {
        $cdprLogs = Get-ChildItem -Path $cdprDir -Recurse -Include "stacktrace.txt", "*.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Cutoff -and $_.LastWriteTime -le $EndTime }
        foreach ($cpl in $cdprLogs) {
            $lines = Read-DcSharedLogLines -Path $cpl.FullName -Tail 200
            $critLines = $lines | Where-Object { $_ -match '(?i)Error Reason:|Expression:|Message:|Crash|Unhandled exception|GPU Crash|DXGI_ERROR' } | ForEach-Object { Protect-DcLogText $_ }
            if ($critLines) {
                $sb = Get-DcShaderAndBreadcrumbs -Lines $lines
                $results.Add([PSCustomObject]@{
                    Engine         = "REDengine (CD Projekt Red)"
                    LogName        = $cpl.Name
                    FullName       = (Protect-DcLogText $cpl.FullName)
                    Timestamp      = $cpl.LastWriteTime
                    ErrorLines     = @($critLines)
                    GameName       = (Split-Path $cpl.DirectoryName -Leaf)
                    ExecutableName = $null
                    CommandLine    = $null
                    ShaderInfo     = $sb.ShaderInfo
                    Breadcrumbs    = $sb.Breadcrumbs
                    GpuErrorCode   = $sb.GpuErrorCode
                })
            }
        }
    }

    # 7. Bethesda / Creation Engine (Starfield / Fallout)
    $docsGames = Join-Path $env:USERPROFILE "Documents\My Games"
    if (Test-Path $docsGames) {
        $bethLogs = Get-ChildItem -Path $docsGames -Recurse -Include "*.log", "CrashLog*.txt" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Cutoff -and $_.LastWriteTime -le $EndTime }
        foreach ($bl in $bethLogs) {
            $lines = Read-DcSharedLogLines -Path $bl.FullName -Tail 200
            $critLines = $lines | Where-Object { $_ -match '(?i)FATAL|CRASH|EXCEPTION|Error|Device Removed|DXGI_ERROR' } | ForEach-Object { Protect-DcLogText $_ }
            if ($critLines) {
                $sb = Get-DcShaderAndBreadcrumbs -Lines $lines
                $results.Add([PSCustomObject]@{
                    Engine         = "Creation Engine (Bethesda)"
                    LogName        = $bl.Name
                    FullName       = (Protect-DcLogText $bl.FullName)
                    Timestamp      = $bl.LastWriteTime
                    ErrorLines     = @($critLines)
                    GameName       = (Split-Path $bl.DirectoryName -Leaf)
                    ExecutableName = $null
                    CommandLine    = $null
                    ShaderInfo     = $sb.ShaderInfo
                    Breadcrumbs    = $sb.Breadcrumbs
                    GpuErrorCode   = $sb.GpuErrorCode
                })
            }
        }
    }

    # 8. Capcom RE Engine
    $capcomDir = Join-Path $env:LOCALAPPDATA "CAPCOM"
    if (Test-Path $capcomDir) {
        $capcomLogs = Get-ChildItem -Path $capcomDir -Recurse -Filter "*.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Cutoff -and $_.LastWriteTime -le $EndTime }
        foreach ($ccl in $capcomLogs) {
            $lines = Read-DcSharedLogLines -Path $ccl.FullName -Tail 200
            $critLines = $lines | Where-Object { $_ -match '(?i)Fatal|Error|Exception|Crash|DXGI_ERROR' } | ForEach-Object { Protect-DcLogText $_ }
            if ($critLines) {
                $sb = Get-DcShaderAndBreadcrumbs -Lines $lines
                $results.Add([PSCustomObject]@{
                    Engine         = "RE Engine (Capcom)"
                    LogName        = $ccl.Name
                    FullName       = (Protect-DcLogText $ccl.FullName)
                    Timestamp      = $ccl.LastWriteTime
                    ErrorLines     = @($critLines)
                    GameName       = (Split-Path $ccl.DirectoryName -Leaf)
                    ExecutableName = $null
                    CommandLine    = $null
                    ShaderInfo     = $sb.ShaderInfo
                    Breadcrumbs    = $sb.Breadcrumbs
                    GpuErrorCode   = $sb.GpuErrorCode
                })
            }
        }
    }

    return $results
}

Set-Alias -Name Extract-DcShaderAndBreadcrumbs -Value Get-DcShaderAndBreadcrumbs

Export-ModuleMember -Function Get-DcSteamPath, Get-DcSteamLogs, Get-DcSteamGameSessions, Get-DcEngineLogs, Protect-DcLogText, Get-DcShaderAndBreadcrumbs, Read-DcSharedLogLines, Get-DcSteamAppNameMap -Alias Extract-DcShaderAndBreadcrumbs
