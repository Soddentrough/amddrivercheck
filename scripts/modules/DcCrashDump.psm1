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

    # 1. Windows Kernel BSOD Minidumps
    $winMinidump = Join-Path $env:SystemRoot "Minidump"
    if (Test-Path $winMinidump) { $dirs.Add($winMinidump) }

    # 2. Windows User-Mode WER Crash Dumps
    $werDumps = Join-Path $env:LOCALAPPDATA "CrashDumps"
    if (Test-Path $werDumps) { $dirs.Add($werDumps) }

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
            Where-Object { Test-Path $_ }
        foreach ($d in $ueDirs) { $dirs.Add($d) }
    }

    # 5. Unity Crash Dumps (%LOCALAPPDATA%\Temp\*\Crashes)
    $tempDir = Join-Path $env:LOCALAPPDATA "Temp"
    if (Test-Path $tempDir) {
        $unityDirs = Get-ChildItem $tempDir -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName "Crashes" } |
            Where-Object { Test-Path $_ }
        foreach ($d in $unityDirs) { $dirs.Add($d) }
    }

    # 6. Specific Popular Game AppData Dump Directories
    $knownGameDirs = @(
        "$env:LOCALAPPDATA\Pearl Abyss\DumpCache",
        "$env:LOCALAPPDATA\BeamNG.drive",
        "$env:LOCALAPPDATA\Maine\Saved\Crashes",
        "$env:LOCALAPPDATA\Cyberpunk 2077\Crashes"
    )
    foreach ($kd in $knownGameDirs) {
        if (Test-Path $kd) { $dirs.Add($kd) }
    }

    return $dirs | Select-Object -Unique
}

function Get-DcCrashDumps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [datetime]$Cutoff = (Get-Date).AddHours(-48),

        [Parameter(Mandatory = $false)]
        [string[]]$CustomDirectories
    )

    $searchDirs = if ($CustomDirectories) { $CustomDirectories } else { Get-DcDumpDirectories }
    $foundFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

    foreach ($dir in $searchDirs) {
        if (Test-Path $dir) {
            $files = Get-ChildItem -Path $dir -Recurse -Include "*.dmp", "__sentry-event" -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Cutoff }
            if ($files) {
                foreach ($f in $files) { $foundFiles.Add($f) }
            }
        }
    }

    # Also check C:\Windows\MEMORY.DMP if modified within window
    $memDump = Join-Path $env:SystemRoot "MEMORY.DMP"
    if (Test-Path $memDump) {
        $mf = Get-Item $memDump -ErrorAction SilentlyContinue
        if ($mf -and $mf.LastWriteTime -ge $Cutoff) {
            $foundFiles.Add($mf)
        }
    }

    return $foundFiles | Sort-Object LastWriteTime -Descending
}

function Get-DcExceptionMeaning {
    param([string]$CodeHex)

    switch ($CodeHex.ToUpper()) {
        "0xC0000005" { "STATUS_ACCESS_VIOLATION (Memory Access Violation / Null Pointer / Native Bug)" }
        "0xC0000409" { "STATUS_STACK_BUFFER_OVERRUN (Fast Fail / Stack Guard Security Check)" }
        "0x80000003" { "STATUS_BREAKPOINT (Hardcoded Assertion or Debug Breakpoint Hit)" }
        "0xC000001D" { "STATUS_ILLEGAL_INSTRUCTION (Unsupported CPU Instruction / AVX/SSE Mismatch)" }
        "0xC00000FD" { "STATUS_STACK_OVERFLOW (Infinite Recursion or Exhausted Call Stack)" }
        "0x887A0006" { "DXGI_ERROR_DEVICE_HUNG (GPU TDR Timeout / Shader Hang)" }
        "0x887A0005" { "DXGI_ERROR_DEVICE_REMOVED (GPU Hardware Reset / Driver Crash)" }
        "0x887A0001" { "DXGI_ERROR_INVALID_CALL (Graphics API Misuse by Engine)" }
        "0x887A002B" { "DXGI_ERROR_DRIVER_INTERNAL_ERROR (Display Driver Internal Bug)" }
        "0xE06D7363" { "STATUS_CPP_EXCEPTION (Uncaught C++ Exception)" }
        "0x00000000" { "STATUS_SUCCESS (External Watchdog Termination / Process Hang)" }
        default      { "Unhandled Exception" }
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
    $result = [PSCustomObject]@{
        FileName        = $fileInfo.Name
        FullName        = $fileInfo.FullName
        Timestamp       = $fileInfo.LastWriteTime
        SizeMb          = [math]::Round($fileInfo.Length / 1MB, 2)
        Architecture    = "Unknown"
        ExceptionCode   = $null
        ExceptionMeaning= $null
        FaultingModule  = $null
        FaultingIP      = $null
        IsGraphicsCrash = $false
        IsShaderCompiler= $false
        ThreadCount     = 0
        Modules         = @()
        Assertions      = @()
        IsKernelDump    = ($fileInfo.DirectoryName -match '(?i)SystemRoot|Windows\\Minidump' -or $fileInfo.Name -match '(?i)MEMORY\.DMP')
    }

    if ($fileInfo.Name -notmatch '\.dmp$') { return $result }

    $fs = $null
    $br = $null
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $br = New-Object System.IO.BinaryReader($fs)

        $sig = $br.ReadUInt32() # 'MDMP' = 0x504D444D
        if ($sig -ne 0x504D444D) {
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
                $mods.Add([PSCustomObject]@{ Base = $base; Size = $msize; NameRva = $nameRva; Name = "" })
            }
            for ($m = 0; $m -lt $mods.Count; $m++) {
                if ($mods[$m].NameRva -gt 0 -and $mods[$m].NameRva -lt $fs.Length) {
                    $fs.Position = $mods[$m].NameRva
                    $len = $br.ReadUInt32()
                    if ($len -gt 0 -and $len -lt 2048) {
                        $nameBytes = $br.ReadBytes($len)
                        $mods[$m].Name = ([System.Text.Encoding]::Unicode.GetString($nameBytes).TrimEnd([char]0))
                    }
                }
            }
            $result.Modules = $mods
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
            $result.IsShaderCompiler = $isShaderCompiler
            $result.IsGraphicsCrash = ($isShaderCompiler -or $isGfxDriver -or ($result.ExceptionCode -match '0x887A000[156]'))
        }

        # 4. Thread List (Type 3)
        $threadStream = $streams | Where-Object { $_.Type -eq 3 } | Select-Object -First 1
        if ($threadStream) {
            $fs.Position = $threadStream.Rva
            $result.ThreadCount = $br.ReadUInt32()
        }
    } catch {
        # Graceful degradation
    } finally {
        if ($br) { $br.Close() }
        if ($fs) { $fs.Close() }
    }

    # 5. Bounded, safe scan for text assertions (Max 2 MB scan)
    try {
        if ($fileInfo.Length -gt 0) {
            $scanLimit = [math]::Min($fileInfo.Length, 2MB)
            $buffer = New-Object byte[] $scanLimit
            $readStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $bytesRead = $readStream.Read($buffer, 0, $scanLimit)
            $readStream.Close()

            if ($bytesRead -gt 0) {
                $ascii = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                $matches = [regex]::Matches($ascii, '(?i)Assert(ion)?\([^\r\n]{5,180}\)|Fatal error:?\s+[^\r\n]{5,180}|DXGI_ERROR_[A-Z_]+|DeviceRemovedReason:?\s+[^\r\n]{5,120}|VK_ERROR_[A-Z_]+|D3D12 device removed') |
                    Select-Object -ExpandProperty Value -Unique |
                    Select-Object -First 6
                if ($matches) {
                    $result.Assertions = @($matches)
                }
            }
        }
    } catch {}

    return $result
}

Export-ModuleMember -Function Get-DcDumpDirectories, Get-DcCrashDumps, Read-DcMinidump, Get-DcExceptionMeaning
