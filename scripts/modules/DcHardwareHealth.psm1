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

        $gpuList.Add([PSCustomObject]@{
            Name          = $vc.Name
            PNPDeviceID   = $vc.PNPDeviceID
            DriverVersion = $ver
            DriverDate    = $rawDate
            Provider      = $prov
            Status        = $vc.Status
            IsGeneric     = $isGeneric
            Vendor        = if ($isAMD) { "AMD" } elseif ($isNvidia) { "NVIDIA" } elseif ($isIntel) { "Intel" } else { "Other" }
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

Export-ModuleMember -Function Get-DcPnpHealth, Get-DcGpuDriverHealth, Get-DcBluetoothHealth, Get-DcNetworkHealth, Get-DcDisplayDiagnostics
