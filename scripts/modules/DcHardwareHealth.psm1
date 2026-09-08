<#
.SYNOPSIS
    DriverCheck - Hardware Health & GPU Driver Alignment Module
.DESCRIPTION
    Audits PnP device health (missing drivers Code 28, error Code 43),
    evaluates GPU drivers, detects dual-GPU driver mismatch / Windows Update downgrades,
    audits Bluetooth controllers, and inspects network adapter stability.
#>

function Get-DcPnpHealth {
    [CmdletBinding()]
    param()

    $badDevices = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -ne "OK" }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($badDevices) {
        foreach ($bd in $badDevices) {
            $explanation = switch ($bd.ConfigManagerErrorCode) {
                28 { "Missing Driver (Code 28: Device has no driver installed. Check motherboard chipset or manufacturer driver packages)." }
                43 { "Device Failure (Code 43: Windows stopped this device because it reported problems / hardware reset / crash)." }
                10 { "Cannot Start (Code 10: Device failed firmware or resource initialization)." }
                14 { "Reboot Required (Code 14: This device cannot work properly until you restart your computer)." }
                22 { "Disabled (Code 22: This device is disabled in Device Manager)." }
                default { "Problem status: $($bd.Problem) (Code $($bd.ConfigManagerErrorCode))" }
            }

            $results.Add([PSCustomObject]@{
                FriendlyName = $bd.FriendlyName
                InstanceId   = $bd.InstanceId
                Status       = $bd.Status
                ErrorCode    = $bd.ConfigManagerErrorCode
                Problem      = $bd.Problem
                Explanation  = $explanation
            })
        }
    }

    return $results
}

function Get-DcGpuDriverHealth {
    [CmdletBinding()]
    param()

    $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
    $signedDrivers = @(Get-CimInstance Win32_PnPSignedDriver -Filter "DeviceClass = 'DISPLAY'" -ErrorAction SilentlyContinue)

    $gpuList = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($vc in $gpus) {
        $sd = $signedDrivers | Where-Object { $_.DeviceID -eq $vc.PNPDeviceID -or $_.DeviceName -eq $vc.Name } | Select-Object -First 1
        $ver = if ($sd -and $sd.DriverVersion) { $sd.DriverVersion } else { $vc.DriverVersion }
        $rawDate = if ($sd -and $sd.DriverDate) { $sd.DriverDate } else { $vc.DriverDate }
        $prov = if ($sd -and $sd.DriverProviderName) { $sd.DriverProviderName } else { $vc.AdapterCompatibility }

        $isGeneric = ($prov -match '(?i)Microsoft' -or $vc.Name -match '(?i)Microsoft Basic Display Adapter')
        $isAMD = ($prov -match '(?i)Advanced Micro Devices|AMD' -or $vc.Name -match '(?i)Radeon')
        $isNvidia = ($prov -match '(?i)NVIDIA' -or $vc.Name -match '(?i)GeForce|RTX|GTX')
        $isIntel = ($prov -match '(?i)Intel' -or $vc.Name -match '(?i)Arc|Iris|UHD|HD Graphics')

        # Detect AMD Software Install Type (Driver Only vs Adrenalin Full Install) and Crash Defender
        $amdInstallType = $null
        $crashDefenderActive = $false
        if ($isAMD) {
            $progFiles = if ($env:ProgramFiles) { $env:ProgramFiles } else { "C:\Program Files" }
            $hasRadeonGui = (Test-Path "$progFiles\AMD\CNext\CNext\RadeonSoftware.exe") -or
                            (Get-Service -Name "AMDRSServ" -ErrorAction SilentlyContinue)
            $amdInstallType = if ($hasRadeonGui) { "Full (Adrenalin GUI)" } else { "Driver Only" }

            $fendrSvc = Get-Service -Name "AMDFendrSR" -ErrorAction SilentlyContinue
            if ($fendrSvc -and $fendrSvc.Status -eq "Running") {
                $crashDefenderActive = $true
            }
        }

        $isHighBoost = ($vc.Name -match '(?i)7900\s*(XTX|XT|GRE)|7800\s*XT|6950\s*XT|6900\s*XT|RTX\s*4090|RTX\s*4080')

        $gpuList.Add([PSCustomObject]@{
            Name                = $vc.Name
            PNPDeviceID         = $vc.PNPDeviceID
            DriverVersion       = $ver
            DriverDate          = $rawDate
            Provider            = $prov
            Status              = $vc.Status
            IsGeneric           = $isGeneric
            Vendor              = if ($isAMD) { "AMD" } elseif ($isNvidia) { "NVIDIA" } elseif ($isIntel) { "Intel" } else { "Other" }
            AmdInstallType      = $amdInstallType
            CrashDefenderActive = $crashDefenderActive
            IsHighBoostCard     = $isHighBoost
        })
    }

    # Detect Dual-GPU Configuration & Potential Version Desync
    $dualGpuConflict = $false
    $dualGpuDetails = $null
    if ($gpuList.Count -ge 2) {
        $amdGpus = $gpuList | Where-Object { $_.Vendor -eq "AMD" }
        if ($amdGpus.Count -ge 2) {
            $versions = $amdGpus.DriverVersion | Select-Object -Unique
            if ($versions.Count -gt 1) {
                $dualGpuConflict = $true
                $dualGpuDetails = "Dual AMD GPU driver version mismatch: Discrete GPU and Integrated GPU are running different driver versions ($($versions -join ' vs ')). This causes shared service (atieclxx.exe) crashes and 0x9F sleep hangs."
            }
        }
    }

    # Query Windows Update Driver Policies
    $dsReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -ErrorAction SilentlyContinue
    $searchOrderConfig = if ($dsReg) { $dsReg.SearchOrderConfig } else { $null }

    $wuReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
    $excludeWUDrivers = if ($wuReg) { $wuReg.ExcludeWUDriversInQualityUpdate } else { $null }

    return [PSCustomObject]@{
        Gpus               = @($gpuList)
        DualGpuConflict    = $dualGpuConflict
        DualGpuDetails     = $dualGpuDetails
        SearchOrderConfig  = $searchOrderConfig
        ExcludeWUDrivers   = $excludeWUDrivers
        IsWUDriverBlocked  = ($searchOrderConfig -eq 0 -and $excludeWUDrivers -eq 1)
    }
}

function Get-DcBluetoothHealth {
    [CmdletBinding()]
    param()

    $btDevices = Get-PnpDevice -Class Bluetooth -PresentOnly -ErrorAction SilentlyContinue
    $radios = $btDevices | Where-Object { $_.FriendlyName -match '(?i)Adapter|Radio|Bluetooth Device' -and $_.FriendlyName -notmatch 'LE Generic|Enumerator' }
    $controllers = $btDevices | Where-Object { $_.FriendlyName -match '(?i)Controller|DualSense|Xbox|Stadia|VR|Sense' }
    $audio = $btDevices | Where-Object { $_.FriendlyName -match '(?i)Buds|Headphones|Headset|AirPods|WH-|WF-' }

    $problemBt = $btDevices | Where-Object { $_.Status -ne "OK" }

    return [PSCustomObject]@{
        Radios        = @($radios)
        Controllers   = @($controllers)
        AudioDevices  = @($audio)
        ProblemCount  = if ($problemBt) { $problemBt.Count } else { 0 }
        ProblemList   = if ($problemBt) { @($problemBt) } else { @() }
    }
}

function Get-DcNetworkHealth {
    [CmdletBinding()]
    param()

    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($a in $adapters) {
        $speedDuplex = Get-NetAdapterAdvancedProperty -Name $a.Name -DisplayName "Speed & Duplex" -ErrorAction SilentlyContinue
        $sdVal = if ($speedDuplex) { $speedDuplex.DisplayValue } else { "N/A" }

        $vlan = Get-NetAdapterAdvancedProperty -Name $a.Name -DisplayName "Packet Priority & VLAN" -ErrorAction SilentlyContinue
        $vlanVal = if ($vlan) { $vlan.DisplayValue } else { "N/A" }

        $isIntel25G = ($a.InterfaceDescription -match '(?i)I225|I226|Intel.*Ethernet')

        $results.Add([PSCustomObject]@{
            Name                 = $a.Name
            InterfaceDescription = $a.InterfaceDescription
            Status               = $a.Status
            LinkSpeed            = $a.LinkSpeed
            SpeedDuplex          = $sdVal
            PriorityVLAN         = $vlanVal
            IsIntel25G           = $isIntel25G
        })
    }

    return $results
}

function Get-DcDisplayDiagnostics {
    [CmdletBinding()]
    param()

    $results = [PSCustomObject]@{
        Displays                = [System.Collections.Generic.List[PSCustomObject]]::new()
        HighRiskTimingsDetected = $false
        RiskSummary             = $null
        Guidance                = $null
    }

    # Query WMI Monitor info
    $wmiMonitors = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue)
    $wmiConns = @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -ErrorAction SilentlyContinue)
    $activeGpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)

    # Query Registry EDID entries
    $regDisplays = @(Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -eq "Device Parameters" })

    $displayList = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($reg in $regDisplays) {
        $edidBytes = (Get-ItemProperty -Path $reg.PSPath -Name "EDID" -ErrorAction SilentlyContinue).EDID
        if (-not $edidBytes -or $edidBytes.Length -lt 128) { continue }

        $pathParts = $reg.PSPath -split '\\'
        $monId = if ($pathParts.Length -ge 3) { $pathParts[-2] } else { "Unknown" }

        # Match WMI monitor for user-friendly name
        $friendlyName = $null
        $matchedWmi = $wmiMonitors | Where-Object { $reg.PSPath -match [regex]::Escape($_.InstanceName) } | Select-Object -First 1
        if ($matchedWmi -and $matchedWmi.UserFriendlyName) {
            $friendlyName = -join ($matchedWmi.UserFriendlyName | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ })
        }

        # Connection technology
        $connType = "Unknown"
        $isDisplayPort = $false
        $matchedConn = $wmiConns | Where-Object { $reg.PSPath -match [regex]::Escape($_.InstanceName) } | Select-Object -First 1
        if ($matchedConn) {
            switch ($matchedConn.VideoOutputTechnology) {
                10 { $connType = "DisplayPort"; $isDisplayPort = $true }
                11 { $connType = "DisplayPort (External)"; $isDisplayPort = $true }
                12 { $connType = "Embedded DisplayPort (eDP)"; $isDisplayPort = $true }
                5  { $connType = "HDMI" }
                4  { $connType = "DVI" }
                0  { $connType = "VGA" }
                default { $connType = "Output Tech ($($matchedConn.VideoOutputTechnology))" }
            }
        }

        # Parse Detailed Timing Descriptors (Base block: 54, 72, 90, 108)
        $dtdOffsets = [System.Collections.Generic.List[int]]::new()
        foreach ($offset in 54, 72, 90, 108) { $dtdOffsets.Add($offset) }

        # Check Extension Blocks (CEA-861 / DisplayID)
        $numExtensions = [int]$edidBytes[126]
        if ($numExtensions -gt 0 -and $edidBytes.Length -ge (128 * ($numExtensions + 1))) {
            for ($ext = 1; $ext -le $numExtensions; $ext++) {
                $extBase = $ext * 128
                $tag = [int]$edidBytes[$extBase]
                if ($tag -eq 0x02) {
                    $dtdStart = [int]$edidBytes[$extBase + 2]
                    if ($dtdStart -ge 4 -and $dtdStart -lt 120) {
                        for ($o = ($extBase + $dtdStart); $o -le ($extBase + 128 - 18); $o += 18) {
                            $dtdOffsets.Add($o)
                        }
                    }
                }
            }
        }

        $timings = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($offset in $dtdOffsets) {
            if ($offset + 17 -ge $edidBytes.Length) { continue }

            $pClockLower = [int]$edidBytes[$offset]
            $pClockUpper = [int]$edidBytes[$offset + 1]

            if ($pClockLower -eq 0 -and $pClockUpper -eq 0) {
                $tag = [int]$edidBytes[$offset + 3]
                if ($tag -eq 0xFC -and -not $friendlyName) {
                    $nameBytes = $edidBytes[($offset + 5)..($offset + 17)]
                    $friendlyName = (-join ($nameBytes | Where-Object { $_ -ge 32 -and $_ -le 126 } | ForEach-Object { [char]$_ })).Trim()
                }
                continue
            }

            $pixelClockHz = (($pClockUpper -shl 8) -bor $pClockLower) * 10000
            $pixelClockMHz = [math]::Round($pixelClockHz / 1000000, 2)

            $hActive = (([int]$edidBytes[$offset + 4] -band 0xF0) -shl 4) -bor [int]$edidBytes[$offset + 2]
            $hBlank  = (([int]$edidBytes[$offset + 4] -band 0x0F) -shl 8) -bor [int]$edidBytes[$offset + 3]
            $hTotal  = $hActive + $hBlank

            $vActive = (([int]$edidBytes[$offset + 7] -band 0xF0) -shl 4) -bor [int]$edidBytes[$offset + 5]
            $vBlank  = (([int]$edidBytes[$offset + 7] -band 0x0F) -shl 8) -bor [int]$edidBytes[$offset + 6]
            $vTotal  = $vActive + $vBlank

            if ($hTotal -gt 0 -and $vTotal -gt 0) {
                $refreshRate = [math]::Round($pixelClockHz / ($hTotal * $vTotal), 1)

                $timings.Add([PSCustomObject]@{
                    HActive       = $hActive
                    VActive       = $vActive
                    HBlank        = $hBlank
                    VBlank        = $vBlank
                    HTotal        = $hTotal
                    VTotal        = $vTotal
                    PixelClockMHz = $pixelClockMHz
                    RefreshRate   = $refreshRate
                })
            }
        }

        $currentRes = "Unknown"
        $currentRefresh = 0
        if ($activeGpus) {
            $g = $activeGpus[0]
            if ($g.CurrentHorizontalResolution -and $g.CurrentVerticalResolution) {
                $currentRes = "$($g.CurrentHorizontalResolution)x$($g.CurrentVerticalResolution)"
                $currentRefresh = $g.CurrentRefreshRate
            }
        }

        $dispName = if ($friendlyName) { $friendlyName } else { $monId }

        # Check for High-Risk Overclocked Timing on DisplayPort
        # Signature: 1440p+ with >144Hz refresh rate, and PixelClock >= 585 MHz OR VTotal >= 1500 lines
        $hasRisk = $false
        $riskTiming = $null
        foreach ($t in $timings) {
            if ($t.HActive -ge 2560 -and $t.VActive -ge 1440 -and $t.RefreshRate -gt 144) {
                if ($t.PixelClockMHz -ge 585 -or $t.VTotal -ge 1500) {
                    $hasRisk = $true
                    $riskTiming = $t
                    break
                }
            }
        }

        $isKnownIssueModel = ($dispName -match '(?i)Optix.*G27|MAG27|G24C')

        $displayObj = [PSCustomObject]@{
            Name               = $dispName
            MonitorId          = $monId
            Connection         = $connType
            IsDisplayPort      = $isDisplayPort
            ActiveResolution   = $currentRes
            ActiveRefreshRate  = $currentRefresh
            Timings            = @($timings)
            HasTimingRisk      = ($hasRisk -or ($isKnownIssueModel -and $currentRefresh -gt 144))
            RiskTiming         = $riskTiming
            IsKnownIssueModel  = $isKnownIssueModel
        }

        $displayList.Add($displayObj)

        if ($displayObj.HasTimingRisk -and -not $results.HighRiskTimingsDetected) {
            $results.HighRiskTimingsDetected = $true
            $timingStr = if ($riskTiming) { "$($riskTiming.HActive)x$($riskTiming.VActive) @ $($riskTiming.RefreshRate)Hz (Pixel Clock: $($riskTiming.PixelClockMHz) MHz, V-Total: $($riskTiming.VTotal) lines)" } else { "Active Refresh: $($currentRefresh)Hz" }
            $results.RiskSummary = "Display '$dispName' ($connType) is running a high-refresh factory overclock ($timingStr). On DisplayPort 1.2a without DSC, bloated factory blanking operates budget monitor scalers at their electrical and thermal limits, causing periodic phase desync, Hot-Plug Detect (HPD) link drops, and 2-3s blackouts without triggering GPU driver TDRs."
            $results.Guidance = "1. Lower refresh rate to native 144 Hz in Windows Display Settings.`n2. Use AMD Software (Custom Resolutions) or Custom Resolution Utility (CRU) to enforce VESA CVT-RB (Reduced Blanking) timing (target V-Total ~1463 lines, Pixel Clock ~573 MHz).`n3. In CRU, delete the 165Hz extension profile to permanently prevent Windows or graphics drivers from reverting."
        }
    }

    $results.Displays = @($displayList)
    return $results
}

function Get-DcProblematicKernelDrivers {
    [CmdletBinding()]
    param()

    $results = [PSCustomObject]@{
        RogueDriversDetected = $false
        Drivers              = [System.Collections.Generic.List[PSCustomObject]]::new()
        RiskSummary          = $null
        Guidance             = $null
    }

    $knownRogue = @(
        @{
            ServiceName = "inpoutx64"
            FileName    = "inpoutx64.sys"
            Vendor      = "Highresolution Enterprises (InpOutx64)"
            Software    = "SignalRGB / OpenRGB / Legacy RGB Tools"
            RiskReason  = "Direct I/O port driver. Under anti-cheat (Easy Anti-Cheat, BattlEye) or Memory Integrity, throws INVALID_KERNEL_HANDLE (0x93), causes video freezes with audio continuing, and crashes games."
            FixCommand  = "sc config inpoutx64 start= disabled"
        },
        @{
            ServiceName = "inpout32"
            FileName    = "inpout32.sys"
            Vendor      = "Highresolution Enterprises (InpOut32)"
            Software    = "Legacy 32-bit RGB / Hardware Utilities"
            RiskReason  = "Direct I/O port driver. Triggers anti-cheat blocks, DPC latency spikes, and system freezes."
            FixCommand  = "sc config inpout32 start= disabled"
        },
        @{
            ServiceName = "WinRing0x64"
            FileName    = "WinRing0x64.sys"
            Vendor      = "OpenLibSys (WinRing0)"
            Software    = "EVGA Precision X / OpenRGB / Custom Fan Tools"
            RiskReason  = "Known vulnerable kernel driver (CVE-2020-14979). Blocked by Windows Memory Integrity and modern game anti-cheats."
            FixCommand  = "sc config WinRing0x64 start= disabled"
        },
        @{
            ServiceName = "ene"
            FileName    = "ene.sys"
            Vendor      = "ENE Technology"
            Software    = "ENE RGB / Kingston Fury CTRL / MSI Mystic Light"
            RiskReason  = "Legacy DRAM RGB driver. Causes high DPC latency, thread deadlocks, and random game stutter/freezes."
            FixCommand  = "sc config ene start= disabled"
        },
        @{
            ServiceName = "AsrOmgDrv"
            FileName    = "AsrOmgDrv.sys"
            Vendor      = "ASRock"
            Software    = "ASRock Polychrome RGB / A-Tuning"
            RiskReason  = "Legacy motherboard driver. Causes kernel handle exhaustion and random game crashes."
            FixCommand  = "sc config AsrOmgDrv start= disabled"
        },
        @{
            ServiceName = "gdrv"
            FileName    = "gdrv.sys"
            Vendor      = "GIGABYTE"
            Software    = "GIGABYTE App Center / RGB Fusion"
            RiskReason  = "Known unstable kernel driver with memory safety defects and anti-cheat incompatibility."
            FixCommand  = "sc config gdrv start= disabled"
        }
    )

    $driversDir = Join-Path $env:SystemRoot "System32\drivers"

    foreach ($entry in $knownRogue) {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($entry.ServiceName)"
        $serviceReg = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        $filePath = Join-Path $driversDir $entry.FileName

        $isInstalled = ($null -ne $serviceReg -or (Test-Path $filePath))
        if ($isInstalled) {
            $startType = if ($serviceReg) { $serviceReg.Start } else { $null }
            $startDesc = switch ($startType) {
                0 { "Boot" }
                1 { "System" }
                2 { "Automatic" }
                3 { "Manual" }
                4 { "Disabled" }
                default { "Unknown" }
            }

            $isActiveOrAuto = ($startType -in @(0, 1, 2, 3) -or (-not $serviceReg -and (Test-Path $filePath)))

            $driverObj = [PSCustomObject]@{
                ServiceName = $entry.ServiceName
                FileName    = $entry.FileName
                Vendor      = $entry.Vendor
                Software    = $entry.Software
                StartType   = $startDesc
                IsDisabled  = ($startType -eq 4)
                IsActive    = $isActiveOrAuto
                FileExists  = (Test-Path $filePath)
                RiskReason  = $entry.RiskReason
                FixCommand  = $entry.FixCommand
            }

            $results.Drivers.Add($driverObj)

            if ($driverObj.IsActive -and -not $driverObj.IsDisabled) {
                $results.RogueDriversDetected = $true
            }
        }
    }

    if ($results.RogueDriversDetected) {
        $activeNames = ($results.Drivers | Where-Object { $_.IsActive -and -not $_.IsDisabled } | ForEach-Object { "$($_.FileName) ($($_.ServiceName))" }) -join ", "
        $results.RiskSummary = "Detected rogue/problematic legacy kernel I/O driver(s) configured to load on boot: $activeNames. These legacy drivers (commonly left behind by RGB or hardware monitoring software) bypass Windows driver safety abstractions. Modern game anti-cheat engines (Easy Anti-Cheat, BattlEye, Vanguard) and Windows Memory Integrity frequently block their handles, causing INVALID_KERNEL_HANDLE (0x93) BSODs, game lockups where audio continues playing, or unexplained freezes."
        $results.Guidance = "Disable the problematic driver service(s) by running '.\scripts\Disable-RogueKernelDrivers.ps1' or 'sc config <service> start= disabled' in an Administrator terminal. Modern RGB suites (like SignalRGB) continue to work normally without these legacy kernel drivers."
    }

    return $results
}

function Get-DcMotherboardAndChipsetHealth {
    [CmdletBinding()]
    param()

    # 1. BaseBoard / Motherboard Info
    $bb = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -First 1
    $mbManufacturer = if ($bb -and $bb.Manufacturer) { $bb.Manufacturer.Trim() } else { "Unknown" }
    $mbProduct = if ($bb -and $bb.Product) { $bb.Product.Trim() } else { "Unknown" }
    $mbVersion = if ($bb -and $bb.Version) { $bb.Version.Trim() } else { "" }

    # 2. BIOS Info
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1
    $biosVendor = if ($bios -and $bios.Manufacturer) { $bios.Manufacturer.Trim() } else { "Unknown" }
    $biosVersion = if ($bios -and $bios.SMBIOSBIOSVersion) { $bios.SMBIOSBIOSVersion.Trim() } else { "Unknown" }

    $biosDateStr = $null
    $biosAgeDays = $null
    $biosAgeYears = $null
    $isBiosOutdated = $false

    if ($bios -and $bios.ReleaseDate) {
        try {
            $parsedDate = [datetime]$bios.ReleaseDate
            $biosDateStr = $parsedDate.ToString("yyyy-MM-dd")
            $diff = (Get-Date) - $parsedDate
            $biosAgeDays = [math]::Round($diff.TotalDays)
            $biosAgeYears = [math]::Round($biosAgeDays / 365.25, 1)
            # Flag if BIOS is > 3 years old (>1095 days)
            if ($biosAgeDays -gt 1095) {
                $isBiosOutdated = $true
            }
        } catch {
            $biosDateStr = "$($bios.ReleaseDate)"
        }
    }

    # 3. Detect Platform CPU Vendor to know which Chipset drivers to look for
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $cpuName = if ($cpu -and $cpu.Name) { $cpu.Name.Trim() } else { "" }
    $isAmdCpu = ($cpuName -match '(?i)AMD|Ryzen|Threadripper|EPYC' -or $mbProduct -match '(?i)B450|B550|X470|X570|A520|A620|B650|B850|X670|X870|TRX40|WRX80|WRX90')
    $isIntelCpu = ($cpuName -match '(?i)Intel|Core\(TM\)|Xeon' -or $mbProduct -match '(?i)Z490|Z590|Z690|Z790|Z890|B460|B560|B660|B760|B860|H610|H670|H770')

    # 4. Query Installed Chipset Software from Registry (Uninstall keys)
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $installedApps = @(Get-ItemProperty $uninstallPaths -ErrorAction SilentlyContinue)

    $chipsetSoftware = $null
    $chipsetVersion = $null
    $chipsetInstallDate = $null

    $amdChipset = $installedApps | Where-Object { $_.DisplayName -match '(?i)AMD Chipset Software' } | Select-Object -First 1
    $intelChipset = $installedApps | Where-Object { $_.DisplayName -match '(?i)Intel(\(R\))? Chipset Device Software' } | Select-Object -First 1

    if ($amdChipset) {
        $chipsetSoftware = $amdChipset.DisplayName
        $chipsetVersion = $amdChipset.DisplayVersion
        $chipsetInstallDate = $amdChipset.InstallDate
    } elseif ($intelChipset) {
        $chipsetSoftware = $intelChipset.DisplayName
        $chipsetVersion = $intelChipset.DisplayVersion
        $chipsetInstallDate = $intelChipset.InstallDate
    }

    # 5. Audit Core Platform Controller Drivers (PnP)
    $allDrivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue)
    $allPnp = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue)

    $controllerAudit = [System.Collections.Generic.List[PSCustomObject]]::new()
    $missingChipsetControllers = [System.Collections.Generic.List[string]]::new()

    if ($isAmdCpu) {
        # Check AMD GPIO Controller
        $gpio = $allPnp | Where-Object { $_.FriendlyName -match '(?i)AMD GPIO' -or $_.InstanceId -match '(?i)AMDI0030|AMDI0031|AMD0030' } | Select-Object -First 1
        $gpioDrv = if ($gpio) { $allDrivers | Where-Object { $_.DeviceID -eq $gpio.InstanceId } | Select-Object -First 1 } else { $null }
        $controllerAudit.Add([PSCustomObject]@{
            Controller = "AMD GPIO Controller"
            Present    = ($null -ne $gpio)
            Status     = if ($gpio) { $gpio.Status } else { "Not Present" }
            DriverVer  = if ($gpioDrv) { $gpioDrv.DriverVersion } else { "N/A" }
            Provider   = if ($gpioDrv) { $gpioDrv.DriverProviderName } else { "N/A" }
        })
        if (-not $gpio -or ($gpio -and $gpio.Status -ne "OK")) {
            $missingChipsetControllers.Add("AMD GPIO Controller")
        }

        # Check AMD I2C Controller
        $i2c = $allPnp | Where-Object { $_.FriendlyName -match '(?i)AMD I2C' -or $_.InstanceId -match '(?i)AMDI0010|AMDI0011' } | Select-Object -First 1
        $i2cDrv = if ($i2c) { $allDrivers | Where-Object { $_.DeviceID -eq $i2c.InstanceId } | Select-Object -First 1 } else { $null }
        if ($i2c) {
            $controllerAudit.Add([PSCustomObject]@{
                Controller = "AMD I2C Controller"
                Present    = $true
                Status     = $i2c.Status
                DriverVer  = if ($i2cDrv) { $i2cDrv.DriverVersion } else { "N/A" }
                Provider   = if ($i2cDrv) { $i2cDrv.DriverProviderName } else { "N/A" }
            })
            if ($i2c.Status -ne "OK") {
                $missingChipsetControllers.Add("AMD I2C Controller ($($i2c.Status))")
            }
        }

        # Check AMD PCI Device Driver (amdfendr / amdpcidev)
        $pciDev = $allPnp | Where-Object { $_.FriendlyName -match '(?i)AMD PCI' -or $_.InstanceId -match '(?i)VEN_1022&DEV_148A|VEN_1022&DEV_149A' } | Select-Object -First 1
        $pciDevDrv = if ($pciDev) { $allDrivers | Where-Object { $_.DeviceID -eq $pciDev.InstanceId } | Select-Object -First 1 } else { $null }
        if ($pciDev) {
            $controllerAudit.Add([PSCustomObject]@{
                Controller = "AMD PCI Device Driver"
                Present    = $true
                Status     = $pciDev.Status
                DriverVer  = if ($pciDevDrv) { $pciDevDrv.DriverVersion } else { "N/A" }
                Provider   = if ($pciDevDrv) { $pciDevDrv.DriverProviderName } else { "N/A" }
            })
            if ($pciDev.Status -ne "OK") {
                $missingChipsetControllers.Add("AMD PCI Device Driver ($($pciDev.Status))")
            }
        }

        # Check AMD PSP (Platform Security Processor)
        $psp = $allPnp | Where-Object { $_.FriendlyName -match '(?i)AMD PSP|Platform Security Processor' -or $_.InstanceId -match '(?i)VEN_1022&DEV_1486|VEN_1022&DEV_15DF|VEN_1022&DEV_1649' } | Select-Object -First 1
        $pspDrv = if ($psp) { $allDrivers | Where-Object { $_.DeviceID -eq $psp.InstanceId } | Select-Object -First 1 } else { $null }
        if ($psp) {
            $controllerAudit.Add([PSCustomObject]@{
                Controller = "AMD PSP Device"
                Present    = $true
                Status     = $psp.Status
                DriverVer  = if ($pspDrv) { $pspDrv.DriverVersion } else { "N/A" }
                Provider   = if ($pspDrv) { $pspDrv.DriverProviderName } else { "N/A" }
            })
            if ($psp.Status -ne "OK") {
                $missingChipsetControllers.Add("AMD PSP Device ($($psp.Status))")
            }
        }

        # Check AMD 3D V-Cache Optimizer (if X3D CPU)
        if ($cpuName -match '(?i)X3D') {
            $vcacheSvc = Get-Service -Name "amd3dvcache" -ErrorAction SilentlyContinue
            $controllerAudit.Add([PSCustomObject]@{
                Controller = "AMD 3D V-Cache Optimizer"
                Present    = ($null -ne $vcacheSvc)
                Status     = if ($vcacheSvc) { $vcacheSvc.Status.ToString() } else { "Not Installed" }
                DriverVer  = "Service"
                Provider   = "AMD"
            })
            if (-not $vcacheSvc -or $vcacheSvc.Status -ne "Running") {
                $missingChipsetControllers.Add("AMD 3D V-Cache Optimizer Service (Not running for X3D CPU)")
            }
        }
    } elseif ($isIntelCpu) {
        # Check Intel Management Engine (MEI)
        $mei = $allPnp | Where-Object { $_.FriendlyName -match '(?i)Intel.*Management Engine|Intel.*MEI' -or $_.InstanceId -match '(?i)VEN_8086&DEV_' } | Select-Object -First 1
        $meiDrv = if ($mei) { $allDrivers | Where-Object { $_.DeviceID -eq $mei.InstanceId } | Select-Object -First 1 } else { $null }
        if ($mei) {
            $controllerAudit.Add([PSCustomObject]@{
                Controller = "Intel Management Engine (MEI)"
                Present    = $true
                Status     = $mei.Status
                DriverVer  = if ($meiDrv) { $meiDrv.DriverVersion } else { "N/A" }
                Provider   = if ($meiDrv) { $meiDrv.DriverProviderName } else { "N/A" }
            })
            if ($mei.Status -ne "OK") {
                $missingChipsetControllers.Add("Intel Management Engine ($($mei.Status))")
            }
        }
    }

    # Summary Health Assessment
    $isHealthy = ($missingChipsetControllers.Count -eq 0)
    $summary = if ($chipsetSoftware) {
        "$chipsetSoftware v$chipsetVersion"
    } elseif ($isAmdCpu) {
        "AMD Platform (Generic / Unregistered Chipset Package)"
    } elseif ($isIntelCpu) {
        "Intel Platform (Generic / Unregistered Chipset Package)"
    } else {
        "Standard Platform"
    }

    return [PSCustomObject]@{
        MotherboardManufacturer = $mbManufacturer
        MotherboardProduct      = $mbProduct
        MotherboardVersion      = $mbVersion
        BiosVendor              = $biosVendor
        BiosVersion             = $biosVersion
        BiosReleaseDate         = $biosDateStr
        BiosAgeDays             = $biosAgeDays
        BiosAgeYears            = $biosAgeYears
        IsBiosOutdated          = $isBiosOutdated
        CpuName                 = $cpuName
        IsAmdCpu                = $isAmdCpu
        IsIntelCpu              = $isIntelCpu
        ChipsetSoftware         = $chipsetSoftware
        ChipsetVersion          = $chipsetVersion
        ChipsetInstallDate      = $chipsetInstallDate
        ChipsetControllers      = @($controllerAudit)
        MissingControllers      = @($missingChipsetControllers)
        IsHealthy               = $isHealthy
        Summary                 = $summary
    }
}

Export-ModuleMember -Function Get-DcPnpHealth, Get-DcGpuDriverHealth, Get-DcBluetoothHealth, Get-DcNetworkHealth, Get-DcDisplayDiagnostics, Get-DcProblematicKernelDrivers, Get-DcMotherboardAndChipsetHealth
