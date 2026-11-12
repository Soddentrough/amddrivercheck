<#
.SYNOPSIS
    DriverCheck - Crash Dump & Minidump Inspector Module
.DESCRIPTION
    Parses Windows minidump (MDMP) binary streams across x86 and x64 processes.
    Discovers crash dumps from Windows BSOD (C:\Windows\Minidump), User-Mode WER,
    Steam, Unreal Engine, and Unity.
#>

function Get-DcDumpDirectories {
    [CmdletBinding()]
    param()

    $dirs = [System.Collections.Generic.List[string]]::new()

    # 0. Current working directory / workspace (for manually copied dumps)
    if ($PWD -and (Test-Path -LiteralPath $PWD)) {
        $dirs.Add((Get-Item -LiteralPath $PWD).FullName)
    }

    # 1. Windows Kernel BSOD Minidumps & LiveKernelReports (Non-BSOD GPU TDR Watchdog Dumps)
    $winMinidump = Join-Path $env:SystemRoot "Minidump"
    try { if (Test-Path $winMinidump -ErrorAction SilentlyContinue) { $dirs.Add($winMinidump) } } catch {}

    $liveWatchdog = Join-Path $env:SystemRoot "LiveKernelReports\WATCHDOG"
    try { if (Test-Path $liveWatchdog -ErrorAction SilentlyContinue) { $dirs.Add($liveWatchdog) } } catch {}
    $liveKernelReports = Join-Path $env:SystemRoot "LiveKernelReports"
    try {
        if (Test-Path $liveKernelReports -ErrorAction SilentlyContinue) {
            $dirs.Add($liveKernelReports)
            $lkrSubDirs = Get-ChildItem -Path $liveKernelReports -Directory -ErrorAction SilentlyContinue
            foreach ($sd in $lkrSubDirs) { $dirs.Add($sd.FullName) }
        }
    } catch {}

    # 2. Windows User-Mode WER Crash Dumps
    $werDumps = Join-Path $env:LOCALAPPDATA "CrashDumps"
    if (Test-Path $werDumps -ErrorAction SilentlyContinue) { $dirs.Add($werDumps) }

    # 3. Steam Minidumps (Dynamic SteamPath lookup with fallback)
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
    if ($steamPath) {
        $steamDumpDir = Join-Path $steamPath "dumps"
        if (Test-Path $steamDumpDir) { $dirs.Add($steamDumpDir) }
    }

    # 4. Unreal Engine Crash Dumps (Auto-discover in %LOCALAPPDATA%\*\Saved\Crashes)
    if (Test-Path $env:LOCALAPPDATA) {
        $ueDirs = Get-ChildItem "$env:LOCALAPPDATA" -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName "Saved\Crashes" } |
            Where-Object { Test-Path $_ -ErrorAction SilentlyContinue }
        foreach ($d in $ueDirs) { $dirs.Add($d) }
    }

    # 5. Unity Crash Dumps (%LOCALAPPDATA%\Temp\*\Crashes)
    $tempDir = Join-Path $env:LOCALAPPDATA "Temp"
    if (Test-Path $tempDir) {
        $unityDirs = Get-ChildItem $tempDir -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName "Crashes" } |
            Where-Object { Test-Path $_ -ErrorAction SilentlyContinue }
        foreach ($d in $unityDirs) { $dirs.Add($d) }
    }

    # 6. Specific Popular Game AppData Dump Directories
    $knownGameDirs = @(
        "$env:LOCALAPPDATA\Pearl Abyss\DumpCache",
        "$env:LOCALAPPDATA\BeamNG.drive",
        "$env:LOCALAPPDATA\Maine\Saved\Crashes",
        "$env:LOCALAPPDATA\CD Projekt Red\Cyberpunk 2077\Crashes",
        "$env:LOCALAPPDATA\Cyberpunk 2077\Crashes",
        (Join-Path $env:USERPROFILE "Documents\My Games\Starfield\CrashDumps"),
        "$env:LOCALAPPDATA\Starfield",
        "$env:LOCALAPPDATA\CAPCOM",
        (Join-Path $env:USERPROFILE "Documents\Battlefield 2042\CrashDumps")
    )
    foreach ($kd in $knownGameDirs) {
        if (Test-Path $kd -ErrorAction SilentlyContinue) { $dirs.Add($kd) }
    }

    return $dirs | Select-Object -Unique
}

function Get-DcCrashDumps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddHours(-48),

        [Parameter(Mandatory = $false)]
        [datetime]$EndTime = (Get-Date),

        [Parameter(Mandatory = $false)]
        [switch]$LatestOnly,

        [Parameter(Mandatory = $false)]
        [string[]]$CustomDirectories
    )

    $searchDirs = if ($CustomDirectories) { $CustomDirectories } else { Get-DcDumpDirectories }
    $foundFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

    foreach ($dir in $searchDirs) {
        if (Test-Path $dir) {
            $files = Get-ChildItem -Path $dir -Recurse -Include "*.dmp", "__sentry-event" -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Cutoff -and $_.LastWriteTime -le $EndTime }
            if ($files) {
                foreach ($f in $files) { $foundFiles.Add($f) }
            }
        }
    }

    # Also check C:\Windows\MEMORY.DMP if modified within window
    $memDump = Join-Path $env:SystemRoot "MEMORY.DMP"
    if (Test-Path $memDump) {
        $mf = Get-Item $memDump -ErrorAction SilentlyContinue
        if ($mf -and $mf.LastWriteTime -ge $Cutoff -and $mf.LastWriteTime -le $EndTime) {
            $foundFiles.Add($mf)
        }
    }

    $sorted = $foundFiles | Sort-Object LastWriteTime -Descending
    if ($LatestOnly -and $sorted) {
        return @($sorted | Select-Object -First 1)
    }
    return @($sorted)
}

function Get-DcLatestDumpFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$LookbackDays = 30,

        [Parameter(Mandatory = $false)]
        [string[]]$CustomDirectories
    )

    $cutoff = (Get-Date).AddDays(-$LookbackDays)
    $dumps = Get-DcCrashDumps -Cutoff $cutoff -CustomDirectories $CustomDirectories
    if ($dumps -and $dumps.Count -gt 0) {
        return ($dumps | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
    }
    return $null
}

function Get-DcExceptionMeaning {
    param([string]$CodeHex)

    switch ($CodeHex.ToUpper()) {
        "0xC0000005" { "STATUS_ACCESS_VIOLATION" }
        "0xC0000409" { "STATUS_STACK_BUFFER_OVERRUN (fast-fail)" }
        "0x80000003" { "STATUS_BREAKPOINT" }
        "0xC000001D" { "STATUS_ILLEGAL_INSTRUCTION" }
        "0xC00000FD" { "STATUS_STACK_OVERFLOW" }
        "0x887A0006" { "DXGI_ERROR_DEVICE_HUNG" }
        "0x887A0005" { "DXGI_ERROR_DEVICE_REMOVED" }
        "0x887A0001" { "DXGI_ERROR_INVALID_CALL" }
        "0x887A002B" { "DXGI_ERROR_DRIVER_INTERNAL_ERROR" }
        "0xE06D7363" { "C++ exception (0xE06D7363)" }
        "0x00000093" { "INVALID_KERNEL_HANDLE" }
        "0x00000141" { "LiveKernelEvent 0x141 (VIDEO_ENGINE_TDR_TIMEOUT)" }
        "0x00000117" { "LiveKernelEvent 0x117 (VIDEO_TDR_TIMEOUT_DETECTED)" }
        "0x00000193" { "LiveKernelEvent 0x193 (VIDEO_DXGKRNL_LIVEDUMP)" }
        "0xA1000001" { "LiveKernelEvent 0xA1000001 (AMD_WATCHDOG)" }
        "0x000001B8" { "LiveKernelEvent 0x1B8 (VIDEO_DXGKRNL_BLACK_SCREEN_LIVEDUMP)" }
        "0x000001A8" { "LiveKernelEvent 0x1A8 (VIDEO_DXGKRNL_SYSMM_FATAL_ERROR)" }
        "0x00000000" { "exit code 0 recorded by crash handler" }
        "ASSERTION"  { "Assertion recorded" }
        "SENTRY_FATAL" { "Sentry Native Crashpad Fatal Crash Event" }
        default      { "Unhandled Exception" }
    }
}

$script:CachedCdbPath = $null

function Find-DcCdbPath {
    if ($script:CachedCdbPath -and (Test-Path -LiteralPath $script:CachedCdbPath)) {
        return $script:CachedCdbPath
    }
    try {
        $appx = Get-AppxPackage -Name *WinDbg* -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($appx -and $appx.InstallLocation) {
            $c = Join-Path $appx.InstallLocation "amd64\cdb.exe"
            if (Test-Path -LiteralPath $c) {
                $script:CachedCdbPath = $c
                return $c
            }
        }
    } catch {}

    $staticCandidates = @(
        "C:\Program Files\WindowsApps\Microsoft.WinDbg_1.2611.4001.0_x64__8wekyb3d8bbwe\amd64\cdb.exe",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
        "C:\Program Files\Debugging Tools for Windows (x64)\cdb.exe"
    )
    foreach ($cand in $staticCandidates) {
        if (Test-Path -LiteralPath $cand) {
            $script:CachedCdbPath = $cand
            return $cand
        }
    }

    try {
        $cmd = Get-Command cdb.exe -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source)) {
            $script:CachedCdbPath = $cmd.Source
            return $cmd.Source
        }
    } catch {}

    return $null
}

function Invoke-DcDumpStackTrace {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DumpPath,
        [string]$CdbPath = $null,
        [int]$TimeoutSeconds = 8
    )

    $resolvedCdb = if ($CdbPath) { $CdbPath } else { Find-DcCdbPath }
    if (-not $resolvedCdb -or -not (Test-Path -LiteralPath $resolvedCdb)) {
        return [PSCustomObject]@{
            CallStack    = @()
            ApiContext   = $null
            CdbInspected = $false
        }
    }

    $isKernel = ($DumpPath -match '(?i)SystemRoot|Windows\\(Minidump|LiveKernelReports)|MEMORY\.DMP|WATCHDOG|\d{6}-\d{5}-\d{2}\.dmp')

    $symArg = ""
    $localSym = Join-Path $PSScriptRoot "..\..\symcache"
    if (Test-Path $localSym) {
        $symArg = "-y `"cache*$localSym`""
    }

    $cdbArgs = if ($isKernel) {
        if ($symArg) { "-z `"$DumpPath`" $symArg -c `".bugcheck; k 25; q`"" } else { "-z `"$DumpPath`" -c `".bugcheck; k 25; q`"" }
    } else {
        if ($symArg) { "-z `"$DumpPath`" $symArg -c `".ecxr; k 25; q`"" } else { "-z `"$DumpPath`" -c `".ecxr; k 25; q`"" }
    }

    $frames = [System.Collections.Generic.List[string]]::new()
    $apiContext = $null
    $kernelBugcheck = $null
    $kernelBugcheckArgs = @()

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $resolvedCdb
        $psi.Arguments = $cdbArgs
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        $out = $proc.StandardOutput.ReadToEnd()
        $proc.WaitForExit($TimeoutSeconds * 1000)

        $lines = $out -split '\r?\n'
        $inStack = $false
        foreach ($l in $lines) {
            if ($l -match 'Bugcheck code\s+([0-9a-fA-F]+)') {
                $kernelBugcheck = "0x$($Matches[1])"
            }
            if ($l -match 'Arguments\s+([0-9a-fA-F`\s]+)') {
                $kernelBugcheckArgs = @($Matches[1].Trim() -split '\s+' | ForEach-Object { "0x$($_ -replace '`','')" })
            }
            if ($l -match '^\s*Child-SP|\s*RetAddr\s+:\s+Args|#\s+Child-SP') {
                $inStack = $true
                continue
            }
            if ($inStack) {
                if ($l -match '^(?:[0-9a-fA-F]+\s+)?([0-9a-fA-F`]+)\s+([0-9a-fA-F`]+)\s+(.+)$') {
                    $frame = $Matches[3].Trim()
                    $frames.Add($frame)
                } elseif ($l -match '^quit:' -or ($frames.Count -gt 0 -and $l -match '^\s*$')) {
                    $inStack = $false
                }
            }
        }
    } catch {}

    $allFramesText = $frames -join "`n"
    if ($allFramesText -match '(?i)CreateComputePipelines') {
        $apiContext = "Vulkan Compute Pipeline Creation / Shader Compilation (vkCreateComputePipelines)"
    } elseif ($allFramesText -match '(?i)CreateGraphicsPipelines') {
        $apiContext = "Vulkan Graphics Pipeline Creation / Shader Compilation (vkCreateGraphicsPipelines)"
    } elseif ($allFramesText -match '(?i)CreateComputePipelineState') {
        $apiContext = "Direct3D 12 Compute Pipeline Creation / Shader Compilation (CreateComputePipelineState)"
    } elseif ($allFramesText -match '(?i)CreateGraphicsPipelineState') {
        $apiContext = "Direct3D 12 Graphics Pipeline Creation / Shader Compilation (CreateGraphicsPipelineState)"
    } elseif ($allFramesText -match '(?i)vkQueueSubmit') {
        $apiContext = "Vulkan Queue Submission / GPU Work Execution (vkQueueSubmit)"
    } elseif ($allFramesText -match '(?i)ExecuteCommandLists') {
        $apiContext = "Direct3D 12 Command List Execution (ExecuteCommandLists)"
    } elseif ($allFramesText -match '(?i)vkCmdDispatch|ID3D12GraphicsCommandList::Dispatch') {
        $apiContext = "Compute Shader Dispatch Execution"
    } elseif ($allFramesText -match '(?i)vkCmdDraw|DrawIndexedInstanced|DrawInstanced') {
        $apiContext = "Geometry Draw Call Dispatch"
    } elseif ($allFramesText -match '(?i)VidSchiResetEngine|VidSchiSendToExecutionQueue|KeBugCheckEx|watchdog!WdLogSingleEntry|dxgmms2') {
        if ($allFramesText -match 'amdkmdag') {
            $apiContext = "AMD Kernel Display Driver (amdkmdag.sys) GPU Scheduler Timeout / Reset"
        } elseif ($allFramesText -match 'nvlddmkm') {
            $apiContext = "NVIDIA Kernel Display Driver (nvlddmkm.sys) GPU Scheduler Timeout / Reset"
        } else {
            $apiContext = "DirectX Graphics Kernel Scheduler Watchdog Timeout (dxgkrnl / dxgmms2)"
        }
    }

    return [PSCustomObject]@{
        CallStack        = @($frames)
        ApiContext       = $apiContext
        BugcheckCode     = $kernelBugcheck
        BugcheckArgs     = @($kernelBugcheckArgs)
        CdbInspected     = ($frames.Count -gt 0 -or $null -ne $kernelBugcheck)
    }
}

function Read-DcMinidump {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) { return $null }

    $fileInfo = Get-Item $Path
    $cleanFullName = $fileInfo.FullName
    if ($env:USERPROFILE) {
        $cleanFullName = $cleanFullName.Replace($env:USERPROFILE, "%USERPROFILE%")
    }
    $cleanFullName = $cleanFullName -replace '(?i)[a-zA-Z]:\\Users\\[^\\]+', '%USERPROFILE%'

    $result = [PSCustomObject]@{
        FileName              = $fileInfo.Name
        FullName              = $cleanFullName
        Timestamp             = $fileInfo.LastWriteTime
        SizeMb                = [math]::Round($fileInfo.Length / 1MB, 2)
        Architecture          = "Unknown"
        ExceptionCode         = $null
        ExceptionMeaning      = $null
        FaultingModule        = $null
        FaultingIP            = $null
        IsGraphicsCrash       = $false
        IsShaderCompiler      = $false
        IsRogueKernelDriver   = $false
        ThreadCount           = 0
        Modules               = @()
        DriverModuleVersions  = @{}
        GpuDriverVersion      = $null
        MainExecutable        = $null
        MainExecutableVersion = $null
        Assertions            = @()
        IsKernelDump          = ($fileInfo.DirectoryName -match '(?i)SystemRoot|Windows\\(Minidump|LiveKernelReports)' -or $fileInfo.Name -match '(?i)MEMORY\.DMP|WATCHDOG|^\d{6}-\d{5}-\d{2}\.dmp$')
        CallStack             = @()
        ApiContext            = $null
        CdbInspected          = $false
    }

    if ($fileInfo.Name -match '__sentry-event') {
        try {
            $sBytes = [System.IO.File]::ReadAllBytes($Path)
            $sText = [System.Text.Encoding]::ASCII.GetString($sBytes)
            $result.Architecture = "64-bit (x64)"
            $result.ExceptionCode = "SENTRY_FATAL"
            $result.ExceptionMeaning = "Sentry Native Crashpad Fatal Crash Event"
            if ($sText -match 'app_name\?([a-zA-Z0-9_\-\.]+)') { $result.FaultingModule = $Matches[1] }
            $asserts = [System.Collections.Generic.List[string]]::new()
            if ($sText -match 'release\?([a-zA-Z0-9_\-\.@]+)') { $asserts.Add("Release: $($Matches[1])") }
            if ($sText -match 'BuildKey\?([a-zA-Z0-9_\-]+)') { $asserts.Add("Build: $($Matches[1])") }
            $result.Assertions = @($asserts)
        } catch {}
        return $result
    }

    if ($fileInfo.Name -notmatch '\.dmp$') { return $result }

    $fs = $null
    $br = $null
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $br = New-Object System.IO.BinaryReader($fs)

        $sig = $br.ReadUInt32() # 'MDMP' = 0x504D444D
        if ($sig -ne 0x504D444D) {
            # Check for Windows Kernel Dump signature ('PAGE' = 0x45474150 / PAGEDU64) or generic kernel dump
            if ($sig -eq 0x45474150 -or $fileInfo.Name -match '(?i)\.dmp$') {
                $result.IsKernelDump = $true
                $result.Architecture = "64-bit (x64)"
                try {
                    $stackInfo = Invoke-DcDumpStackTrace -DumpPath $Path
                    if ($stackInfo -and $stackInfo.CdbInspected) {
                        $result.CallStack = @($stackInfo.CallStack)
                        $result.ApiContext = $stackInfo.ApiContext
                        $result.CdbInspected = $true
                        if ($stackInfo.BugcheckCode) {
                            $result.ExceptionCode = $stackInfo.BugcheckCode
                            $result.ExceptionMeaning = Get-DcBugCheckMeaning $stackInfo.BugcheckCode
                            $result.BugcheckArgs = $stackInfo.BugcheckArgs
                        }
                        if ($stackInfo.CallStack.Count -gt 0) {
                            $result.FaultingIP = $stackInfo.CallStack[0]
                        }
                        if ($result.ExceptionCode -in @('0x00000119', '0x00000116', '0x00000141', '0x00000117')) {
                            $result.IsGraphicsCrash = $true
                        }
                    }
                } catch {}
            }
            return $result
        }

        $ver = $br.ReadUInt32()
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

        # 1. SystemInfoStream (Type 7) -> Determine x86 vs x64
        $sysInfoStream = $streams | Where-Object { $_.Type -eq 7 } | Select-Object -First 1
        $arch = "AMD64"
        if ($sysInfoStream) {
            $fs.Position = $sysInfoStream.Rva
            $cpuArch = $br.ReadUInt16()
            switch ($cpuArch) {
                0 { $arch = "x86"; $result.Architecture = "32-bit (x86)" }
                9 { $arch = "AMD64"; $result.Architecture = "64-bit (x64)" }
                default { $result.Architecture = "Arch $cpuArch" }
            }
        }

        # 2. Module List (Type 4)
        $mods = [System.Collections.Generic.List[PSCustomObject]]::new()
        $modStream = $streams | Where-Object { $_.Type -eq 4 } | Select-Object -First 1
        if ($modStream) {
            $fs.Position = $modStream.Rva
            $numMods = $br.ReadUInt32()
            for ($m = 0; $m -lt $numMods; $m++) {
                $base = $br.ReadUInt64()
                $msize = $br.ReadUInt32()
                $chk = $br.ReadUInt32()
                $tds = $br.ReadUInt32()
                $nameRva = $br.ReadUInt32()
                $verInfo = $br.ReadBytes(52)
                $cvRva = $br.ReadUInt32()
                $cvSize = $br.ReadUInt32()
                $miscRva = $br.ReadUInt32()
                $miscSize = $br.ReadUInt32()
                $br.ReadBytes(16) | Out-Null

                $modVer = $null
                if ($verInfo -and $verInfo.Length -ge 16) {
                    $fileVerMS = [System.BitConverter]::ToUInt32($verInfo, 8)
                    $fileVerLS = [System.BitConverter]::ToUInt32($verInfo, 12)
                    if ($fileVerMS -ne 0 -or $fileVerLS -ne 0) {
                        $vMaj = ($fileVerMS -shr 16) -band 0xFFFF
                        $vMin = $fileVerMS -band 0xFFFF
                        $vBld = ($fileVerLS -shr 16) -band 0xFFFF
                        $vRev = $fileVerLS -band 0xFFFF
                        $modVer = "$vMaj.$vMin.$vBld.$vRev"
                    }
                }

                $linkDate = $null
                if ($tds -gt 0 -and $tds -lt [uint32]::MaxValue) {
                    try {
                        $linkDate = [DateTimeOffset]::FromUnixTimeSeconds([int64]$tds).LocalDateTime
                    } catch {}
                }

                $mods.Add([PSCustomObject]@{
                    Base      = $base
                    Size      = $msize
                    NameRva   = $nameRva
                    Name      = ""
                    ShortName = ""
                    Version   = $modVer
                    LinkDate  = $linkDate
                })
            }
            $trackedDriverMods = @('amdkmdag.sys', 'amdxc64.dll', 'amdhdl64.dll', 'atidxx64.dll', 'nvlddmkm.sys', 'nvwgf2umx.dll', 'igdkmd64.sys', 'inpoutx64.sys', 'winring0x64.sys', 'ene.sys')
            for ($m = 0; $m -lt $mods.Count; $m++) {
                if ($mods[$m].NameRva -gt 0 -and $mods[$m].NameRva -lt $fs.Length) {
                    $fs.Position = $mods[$m].NameRva
                    $len = $br.ReadUInt32()
                    if ($len -gt 0 -and $len -lt 2048) {
                        $nameBytes = $br.ReadBytes($len)
                        $fullModName = ([System.Text.Encoding]::Unicode.GetString($nameBytes).TrimEnd([char]0))
                        $shortName = [System.IO.Path]::GetFileName($fullModName)
                        $cleanModName = $fullModName
                        if ($env:USERPROFILE) {
                            $cleanModName = $cleanModName.Replace($env:USERPROFILE, "%USERPROFILE%")
                        }
                        $cleanModName = $cleanModName -replace '(?i)[a-zA-Z]:\\Users\\[^\\]+', '%USERPROFILE%'
                        $mods[$m].Name = $cleanModName
                        $mods[$m].ShortName = $shortName

                        if ($m -eq 0 -or ($shortName -match '\.exe$' -and -not $result.MainExecutable)) {
                            $result.MainExecutable = $shortName
                            $result.MainExecutableVersion = $mods[$m].Version
                        }

                        if ($shortName -and ($trackedDriverMods -contains $shortName.ToLower())) {
                            if ($mods[$m].Version) {
                                $result.DriverModuleVersions[$shortName.ToLower()] = $mods[$m].Version
                            } elseif ($mods[$m].LinkDate) {
                                $result.DriverModuleVersions[$shortName.ToLower()] = "LinkDate:$($mods[$m].LinkDate.ToString('yyyy-MM-dd'))"
                            }
                        }
                    }
                }
            }
            $result.Modules = $mods

            # Set primary GPU driver version summary if present in loaded modules
            foreach ($gpuModKey in @('amdkmdag.sys', 'amdxc64.dll', 'amdhdl64.dll', 'atidxx64.dll', 'nvlddmkm.sys', 'nvwgf2umx.dll', 'igdkmd64.sys')) {
                if ($result.DriverModuleVersions.ContainsKey($gpuModKey) -and $result.DriverModuleVersions[$gpuModKey] -notmatch '^LinkDate:') {
                    $result.GpuDriverVersion = $result.DriverModuleVersions[$gpuModKey]
                    break
                }
            }
        }

        function Resolve-DumpAddress([UInt64]$addr, $moduleList) {
            foreach ($m in $moduleList) {
                if ($addr -ge $m.Base -and $addr -lt ($m.Base + $m.Size)) {
                    $off = $addr - $m.Base
                    $short = [System.IO.Path]::GetFileName($m.Name)
                    return ('{0}+0x{1:X}' -f $short, $off)
                }
            }
            return ('0x{0:X16}' -f $addr)
        }

        # 3. Exception Stream (Type 6)
        $excStream = $streams | Where-Object { $_.Type -eq 6 } | Select-Object -First 1
        if ($excStream) {
            $fs.Position = $excStream.Rva
            $threadId = $br.ReadUInt32()
            $align = $br.ReadUInt32()
            $excCode = $br.ReadUInt32()
            $excFlags = $br.ReadUInt32()
            $excRecord = $br.ReadUInt64()
            $excAddr = $br.ReadUInt64()

            $codeHex = "0x{0:X8}" -f $excCode
            $result.ExceptionCode = $codeHex
            $result.ExceptionMeaning = Get-DcExceptionMeaning $codeHex
            $result.FaultingIP = Resolve-DumpAddress $excAddr $mods
            $result.FaultingModule = if ($result.FaultingIP -match '^([^\+]+)\+') { $Matches[1] } else { "Unknown" }

            $isShaderCompiler = ($result.FaultingModule -match '(?i)amdxc|amdxx|nvwgf2|oo2core')
            $isGfxDriver = ($result.FaultingModule -match '(?i)amdkmdag|nvlddmkm|igdkmd|dxgi|d3d12|d3d11|vulkan|atidxx')
            $isRogueKernel = ($result.FaultingModule -match '(?i)inpoutx64|inpout32|winring0|ene\.sys|asromgdrv|asrdrv|gdrv' -or $result.ExceptionCode -eq '0x00000093')
            $result.IsShaderCompiler = $isShaderCompiler
            $result.IsRogueKernelDriver = $isRogueKernel
            $result.IsGraphicsCrash = ($isShaderCompiler -or $isGfxDriver -or ($result.ExceptionCode -match '0x887A000[156]'))
        }

        # Handle LiveKernelReports Watchdog Dumps (GPU TDR / DXGKRNL Live Dumps without user exception stream)
        if (-not $result.ExceptionCode -and ($fileInfo.DirectoryName -match '(?i)LiveKernelReports' -or $fileInfo.Name -match '(?i)WATCHDOG')) {
            $result.IsKernelDump = $true
            $result.IsGraphicsCrash = $true
            $hasDxgkrnlMod = ($result.Modules | Where-Object { $_.Name -match '(?i)dxgkrnl\.sys|watchdog\.sys' } | Select-Object -First 1)
            $gfxMod = $result.Modules | Where-Object { $_.Name -match '(?i)amdkmdag|nvlddmkm|igdkmd' } | Select-Object -First 1

            # Determine specific LiveKernelEvent code from filename/path or loaded modules
            if ($fileInfo.FullName -match '(?i)(?:^|[^0-9a-f])0*193(?:[^0-9a-f]|$)|VIDEO_DXGKRNL_LIVEDUMP|ProcessDeadlockThread' -or ($hasDxgkrnlMod -and -not $gfxMod)) {
                $result.ExceptionCode = "0x00000193"
            } elseif ($fileInfo.FullName -match '(?i)(?:^|[^0-9a-f])0*117(?:[^0-9a-f]|$)') {
                $result.ExceptionCode = "0x00000117"
            } elseif ($fileInfo.FullName -match '(?i)a1000001') {
                $result.ExceptionCode = "0xA1000001"
            } elseif ($fileInfo.FullName -match '(?i)(?:^|[^0-9a-f])0*1b8(?:[^0-9a-f]|$)') {
                $result.ExceptionCode = "0x000001B8"
            } elseif ($fileInfo.FullName -match '(?i)(?:^|[^0-9a-f])0*1a8(?:[^0-9a-f]|$)') {
                $result.ExceptionCode = "0x000001A8"
            } else {
                $result.ExceptionCode = "0x00000141"
            }
            $result.ExceptionMeaning = Get-DcExceptionMeaning $result.ExceptionCode

            if (-not $result.FaultingModule) {
                if ($gfxMod) {
                    $result.FaultingModule = [System.IO.Path]::GetFileName($gfxMod.Name)
                } elseif ($hasDxgkrnlMod) {
                    $result.FaultingModule = [System.IO.Path]::GetFileName($hasDxgkrnlMod.Name)
                } else {
                    $result.FaultingModule = "dxgkrnl.sys"
                }
            }
            if (-not $result.FaultingIP) {
                $result.FaultingIP = if ($result.ExceptionCode -eq "0x00000193") {
                    if ($gfxMod) { "dxgkrnl.sys / $($result.FaultingModule) (Kernel Watchdog)" } else { "dxgkrnl.sys (DirectX Graphics Kernel Watchdog)" }
                } else {
                    "$($result.FaultingModule) (Kernel Watchdog Live Dump)"
                }
            }
        }

        # 4. Thread List (Type 3)
        $threadStream = $streams | Where-Object { $_.Type -eq 3 } | Select-Object -First 1
        if ($threadStream) {
            $fs.Position = $threadStream.Rva
            $result.ThreadCount = $br.ReadUInt32()
        }

        # 5. Comment Stream (Type 10 = CommentStreamA, Type 11 = CommentStreamW)
        $commentStreamA = $streams | Where-Object { $_.Type -eq 10 } | Select-Object -First 1
        if ($commentStreamA -and $commentStreamA.Size -gt 0) {
            $fs.Position = $commentStreamA.Rva
            $cBytes = $br.ReadBytes([math]::Min($commentStreamA.Size, 4096))
            $cText = [System.Text.Encoding]::ASCII.GetString($cBytes).TrimEnd([char]0, "`r", "`n")
            if ($cText) {
                if (-not $result.Assertions) { $result.Assertions = @() }
                $result.Assertions += $cText
            }
        }
        $commentStreamW = $streams | Where-Object { $_.Type -eq 11 } | Select-Object -First 1
        if ($commentStreamW -and $commentStreamW.Size -gt 0) {
            $fs.Position = $commentStreamW.Rva
            $cBytes = $br.ReadBytes([math]::Min($commentStreamW.Size, 4096))
            $cText = [System.Text.Encoding]::Unicode.GetString($cBytes).TrimEnd([char]0, "`r", "`n")
            if ($cText) {
                if (-not $result.Assertions) { $result.Assertions = @() }
                $result.Assertions += $cText
            }
        }
    } catch {
        # Graceful degradation
    } finally {
        if ($br) { $br.Close() }
        if ($fs) { $fs.Close() }
    }

    # 6. Bounded, safe scan for text assertions (Max 2 MB scan)
    try {
        if ($fileInfo.Length -gt 0) {
            $scanLimit = [math]::Min($fileInfo.Length, 2MB)
            $buffer = New-Object byte[] $scanLimit
            $readStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $bytesRead = $readStream.Read($buffer, 0, $scanLimit)
            $readStream.Close()

            if ($bytesRead -gt 0) {
                $ascii = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                if ($result.ExceptionCode -eq "0x00000141") {
                    if ($ascii -match '(?i)VIDEO_DXGKRNL_LIVEDUMP|ProcessDeadlockThread') {
                        $result.ExceptionCode = "0x00000193"
                        $result.ExceptionMeaning = Get-DcExceptionMeaning "0x00000193"
                        $result.FaultingIP = if ($result.FaultingModule -and $result.FaultingModule -ne "dxgkrnl.sys") {
                            "dxgkrnl.sys / $($result.FaultingModule) (Kernel Watchdog)"
                        } else {
                            "dxgkrnl.sys (DirectX Graphics Kernel Watchdog)"
                        }
                    } elseif ($ascii -match '(?i)VIDEO_TDR_TIMEOUT_DETECTED') {
                        $result.ExceptionCode = "0x00000117"
                        $result.ExceptionMeaning = Get-DcExceptionMeaning "0x00000117"
                    } elseif ($ascii -match '(?i)AMD_WATCHDOG|a1000001') {
                        $result.ExceptionCode = "0xA1000001"
                        $result.ExceptionMeaning = Get-DcExceptionMeaning "0xA1000001"
                    } elseif ($ascii -match '(?i)VIDEO_DXGKRNL_BLACK_SCREEN_LIVEDUMP') {
                        $result.ExceptionCode = "0x000001B8"
                        $result.ExceptionMeaning = Get-DcExceptionMeaning "0x000001B8"
                    } elseif ($ascii -match '(?i)VIDEO_DXGKRNL_SYSMM_FATAL_ERROR') {
                        $result.ExceptionCode = "0x000001A8"
                        $result.ExceptionMeaning = Get-DcExceptionMeaning "0x000001A8"
                    }
                }
                $matches = [regex]::Matches($ascii, '(?i)Assert(ion)?\([^\r\n]{5,180}\)|Fatal error:?\s+[^\r\n]{5,180}|DXGI_ERROR_[A-Z_]+|DeviceRemovedReason:?\s+[^\r\n]{5,120}|VK_ERROR_[A-Z_]+|D3D12 device removed|ProcessDeadlockThread') |
                    Select-Object -ExpandProperty Value -Unique |
                    Select-Object -First 6
                if ($matches) {
                    $combined = [System.Collections.Generic.List[string]]::new()
                    if ($result.Assertions) { foreach ($a in $result.Assertions) { $combined.Add($a) } }
                    foreach ($m in $matches) {
                        $alreadyContained = $false
                        foreach ($c in $combined) {
                            if ($c.Contains($m)) { $alreadyContained = $true; break }
                        }
                        if (-not $alreadyContained) { $combined.Add($m) }
                    }
                    $result.Assertions = @($combined)
                }
            }
        }
    } catch {}

    # 7. Post-process assertions & external watchdog signatures
    if (-not $result.ExceptionCode -and $result.Assertions.Count -gt 0) {
        $result.ExceptionCode = "ASSERTION"
        $result.ExceptionMeaning = "Fatal Application Assertion / Process Watchdog"
    }

    if ($result.ExceptionCode -eq "0x00000000" -and ($result.Assertions -match '(?i)cross-thread pipe|pipes\.cpp|watchdog|stall')) {
        $result.ExceptionMeaning = "STATUS_SUCCESS (Steam Watchdog Stalled Cross-Thread Pipe Kill)"
    }

    if ($result.FaultingModule -eq "Unknown" -and $fileInfo.Name -match '^crash_([a-zA-Z0-9_\-\.]+?)\.exe') {
        $result.FaultingModule = "$($Matches[1]).exe"
    }

    # Redact user profile directory paths from assertion messages
    if ($result.Assertions) {
        $result.Assertions = @($result.Assertions | ForEach-Object {
            $s = $_
            if ($env:USERPROFILE) { $s = $s.Replace($env:USERPROFILE, "%USERPROFILE%") }
            $s -replace '(?i)[a-zA-Z]:\\Users\\[^\\]+', '%USERPROFILE%'
        })
    }

    # 8. Automated Call Stack & API Stage Inspection via CDB (if available)
    if ($fileInfo.Name -match '\.dmp$') {
        try {
            $stackInfo = Invoke-DcDumpStackTrace -DumpPath $Path
            if ($stackInfo -and $stackInfo.CdbInspected) {
                $result.CallStack = @($stackInfo.CallStack)
                $result.ApiContext = $stackInfo.ApiContext
                $result.CdbInspected = $true
                if (-not $result.ExceptionCode -and $stackInfo.BugcheckCode) {
                    $result.ExceptionCode = $stackInfo.BugcheckCode
                    $result.ExceptionMeaning = Get-DcBugCheckMeaning $stackInfo.BugcheckCode
                    $result.IsKernelDump = $true
                    if (-not $result.FaultingIP -and $stackInfo.CallStack.Count -gt 0) {
                        $result.FaultingIP = $stackInfo.CallStack[0]
                    }
                    if ($result.ExceptionCode -in @('0x00000119', '0x00000116', '0x00000141', '0x00000117')) {
                        $result.IsGraphicsCrash = $true
                    }
                }
            }
        } catch {}
    }

    return $result
}

Export-ModuleMember -Function Get-DcDumpDirectories, Get-DcCrashDumps, Get-DcLatestDumpFile, Read-DcMinidump, Get-DcExceptionMeaning, Find-DcCdbPath, Invoke-DcDumpStackTrace
