<#
.SYNOPSIS
    DriverCheck - Game Engine & Platform Log Inspector Module
.DESCRIPTION
    Analyzes game engine logs (Unreal, Unity, idTech, Source 2, Godot) and Steam
    telemetry logs, suppressing clean exit patterns and capturing real crash markers.
#>

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

function Get-DcSteamLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddHours(-48)
    )

    $steamPath = Get-DcSteamPath
    if (-not $steamPath) { return @() }

    $logFiles = @(
        (Join-Path $steamPath "logs\gameoverlay_ui.txt"),
        (Join-Path $steamPath "logs\gameoverlay_ui.previous.txt"),
        (Join-Path $steamPath "logs\gameoverlay_renderer.txt"),
        (Join-Path $steamPath "logs\webhelper.txt"),
        (Join-Path $steamPath "logs\connection_log.txt")
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($lp in $logFiles) {
        if (Test-Path $lp) {
            $item = Get-Item $lp
            if ($item.LastWriteTime -ge $Cutoff) {
                # Read tail of log
                $lines = Get-Content $lp -Tail 300 -ErrorAction SilentlyContinue
                if ($lines) {
                    $errors = [System.Collections.Generic.List[string]]::new()
                    foreach ($line in $lines) {
                        # Exclude benign normal hook teardown on clean game exit
                        if ($line -match '(?i)GameOverlayRenderer\.dll detaching|Detaching input hook') {
                            continue
                        }
                        # Match actual crash and stall patterns
                        if ($line -match '(?i)stalled|fatal assert|exitonfatalassert|cross-thread pipe|pipes\.cpp|The game hasn''t rendered a frame|possibly crashed/killed game|OnSystemPowerStateSuspend|BMainLoop appears to have stalled') {
                            $errors.Add($line.Trim())
                        }
                    }

                    if ($errors.Count -gt 0) {
                        $results.Add([PSCustomObject]@{
                            LogName     = $item.Name
                            FullName    = $item.FullName
                            Timestamp   = $item.LastWriteTime
                            ErrorLines  = @($errors)
                            IsPipeError = ($errors | Where-Object { $_ -match '(?i)pipes\.cpp|cross-thread pipe|ExitOnFatalAssert' }).Count -gt 0
                        })
                    }
                }
            }
        }
    }

    return $results
}

function Get-DcEngineLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddHours(-48)
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # 1. Unreal Engine Saved Logs (%LOCALAPPDATA%\*\Saved\Logs\*.log)
    if (Test-Path $env:LOCALAPPDATA) {
        $ueLogDirs = Get-ChildItem "$env:LOCALAPPDATA" -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName "Saved\Logs" } |
            Where-Object { Test-Path $_ }

        foreach ($dir in $ueLogDirs) {
            $logs = Get-ChildItem -Path $dir -Filter "*.log" -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Cutoff }
            foreach ($log in $logs) {
                $lines = Get-Content $log.FullName -Tail 250 -ErrorAction SilentlyContinue
                $critLines = $lines | Where-Object {
                    $_ -match '(?i)Fatal error|CrashReportClient|Assertion failed|GPU Crash dump Triggered|DXGI_ERROR|D3D12.*Hung|DeviceRemovedReason|Out of memory'
                }
                if ($critLines) {
                    $results.Add([PSCustomObject]@{
                        Engine      = "Unreal Engine"
                        LogName     = $log.Name
                        FullName    = $log.FullName
                        Timestamp   = $log.LastWriteTime
                        ErrorLines  = @($critLines)
                    })
                }
            }
        }
    }

    # 2. Unity Engine Player Logs (%USERPROFILE%\AppData\LocalLow\*\*\Player.log)
    $localLow = Join-Path $env:USERPROFILE "AppData\LocalLow"
    if (Test-Path $localLow) {
        $unityLogs = Get-ChildItem -Path $localLow -Recurse -Include "Player.log", "Player-prev.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Cutoff }
        foreach ($ulog in $unityLogs) {
            $lines = Get-Content $ulog.FullName -Tail 250 -ErrorAction SilentlyContinue
            $critLines = $lines | Where-Object {
                $_ -match '(?i)Crash!!!|Fatal Error|d3d11: failed to create|d3d12: failed to|D3D12 device removed|Vulkan: out of device memory|NullReferenceException|StackOverflowException'
            }
            if ($critLines) {
                $results.Add([PSCustomObject]@{
                    Engine      = "Unity"
                    LogName     = $ulog.Name
                    FullName    = $ulog.FullName
                    Timestamp   = $ulog.LastWriteTime
                    ErrorLines  = @($critLines)
                })
            }
        }
    }

    # 3. idTech Engine Console Logs (%USERPROFILE%\Saved Games\*\base\*.log)
    $savedGames = Join-Path $env:USERPROFILE "Saved Games"
    if (Test-Path $savedGames) {
        $idLogs = Get-ChildItem -Path $savedGames -Recurse -Filter "qconsole.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Cutoff }
        foreach ($il in $idLogs) {
            $lines = Get-Content $il.FullName -Tail 250 -ErrorAction SilentlyContinue
            $critLines = $lines | Where-Object {
                $_ -match '(?i)Failed to allocate.*material|buffer allocation failure|catchup timeout expired|FATAL ERROR'
            }
            if ($critLines) {
                $results.Add([PSCustomObject]@{
                    Engine      = "idTech"
                    LogName     = $il.Name
                    FullName    = $il.FullName
                    Timestamp   = $il.LastWriteTime
                    ErrorLines  = @($critLines)
                })
            }
        }
    }

    # 4. Godot Engine Logs (%APPDATA%\Godot\app_userdata\*\logs\godot.log)
    $godotDir = Join-Path $env:APPDATA "Godot\app_userdata"
    if (Test-Path $godotDir) {
        $godotLogs = Get-ChildItem -Path $godotDir -Recurse -Filter "godot.log" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Cutoff }
        foreach ($gl in $godotLogs) {
            $lines = Get-Content $gl.FullName -Tail 200 -ErrorAction SilentlyContinue
            $critLines = $lines | Where-Object { $_ -match '(?i)ERROR:|CRITICAL:|FATAL:' }
            if ($critLines) {
                $results.Add([PSCustomObject]@{
                    Engine      = "Godot"
                    LogName     = $gl.Name
                    FullName    = $gl.FullName
                    Timestamp   = $gl.LastWriteTime
                    ErrorLines  = @($critLines)
                })
            }
        }
    }

    return $results
}

Export-ModuleMember -Function Get-DcSteamPath, Get-DcSteamLogs, Get-DcEngineLogs
