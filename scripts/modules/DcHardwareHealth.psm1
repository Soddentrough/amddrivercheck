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

Export-ModuleMember -Function Get-DcPnpHealth, Get-DcGpuDriverHealth, Get-DcBluetoothHealth, Get-DcNetworkHealth
