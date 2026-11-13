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

            $sanitizedFriendlyName = if ($bd.FriendlyName) {
                $bd.FriendlyName -replace "^.+?'s\s+", "" -replace "^.+?の\s*", ""
            } else {
                $bd.FriendlyName
            }

            $results.Add([PSCustomObject]@{
                FriendlyName = $sanitizedFriendlyName
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

function Get-DcRebarStatus {
    [CmdletBinding()]
    param()

    $rebarStatus = [PSCustomObject]@{
        IsSupported = $false
        IsEnabled   = $false
        BarSizeMb   = 0
        Details     = "Not Audited"
    }

    try {
        if (-not ('DcNativeRegResourceReader' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DcNativeRegResourceReader {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegOpenKeyEx(IntPtr hKey, string subKey, int options, int sam, out IntPtr phkResult);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegQueryValueEx(IntPtr hKey, string lpValueName, IntPtr lpReserved, out int lpType, byte[] lpData, ref int lpcbData);
    [DllImport("advapi32.dll")]
    private static extern int RegCloseKey(IntPtr hKey);

    public static byte[] ReadResourceMap(string subKey, string valName) {
        IntPtr hk;
        if (RegOpenKeyEx((IntPtr)unchecked((int)0x80000002), subKey, 0, 0x20019, out hk) != 0) return null;
        try {
            int type = 0, size = 0;
            RegQueryValueEx(hk, valName, IntPtr.Zero, out type, null, ref size);
            if (size <= 0) return null;
            byte[] buf = new byte[size];
            if (RegQueryValueEx(hk, valName, IntPtr.Zero, out type, buf, ref size) != 0) return null;
            return buf;
        } finally {
            RegCloseKey(hk);
        }
    }
}
'@ -ErrorAction SilentlyContinue
        }

        $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
        $maxBarBytes = [int64]0

        # 1. Primary: Inspect kernel PnP CM_RESOURCE_LIST (includes 64-bit CmResourceTypeMemoryLarge BARs >= 4 GB)
        foreach ($gpu in $gpus) {
            $gpuId = $gpu.PNPDeviceID
            if (-not $gpuId -or $gpuId -notmatch '^PCI\\') { continue }
            try {
                $pdoProp = Get-PnpDeviceProperty -InstanceId $gpuId -KeyName 'DEVPKEY_Device_PDOName' -ErrorAction SilentlyContinue
                if ($pdoProp -and $pdoProp.Data) {
                    $rawBytes = [DcNativeRegResourceReader]::ReadResourceMap("HARDWARE\RESOURCEMAP\PnP Manager\PnpManager", "$($pdoProp.Data).Translated")
                    if ($rawBytes -and $rawBytes.Length -ge 40) {
                        $descCount = [BitConverter]::ToInt32($rawBytes, 16)
                        $offset = 20
                        for ($i = 0; $i -lt $descCount; $i++) {
                            if (($offset + 20) -gt $rawBytes.Length) { break }
                            $resType = $rawBytes[$offset]
                            $resFlags = [BitConverter]::ToUInt16($rawBytes, $offset + 2)
                            $rawLen = [int64][BitConverter]::ToUInt32($rawBytes, $offset + 12)
                            $barBytes = [int64]0
                            if ($resType -eq 3) {
                                # CmResourceTypeMemory (32-bit length)
                                $barBytes = $rawLen
                            } elseif ($resType -eq 7) {
                                # CmResourceTypeMemoryLarge (40/48/64-bit shifted length)
                                if ($resFlags -band 0x0200) { $barBytes = ($rawLen -shl 8) }
                                elseif ($resFlags -band 0x0400) { $barBytes = ($rawLen -shl 16) }
                                elseif ($resFlags -band 0x0800) { $barBytes = ($rawLen -shl 32) }
                            }
                            if ($barBytes -gt $maxBarBytes) {
                                $maxBarBytes = $barBytes
                            }
                            $offset += 20
                        }
                    }
                }
            } catch {}
        }

        # 2. Fallback: WMI Win32_PnPAllocatedResource -> Win32_DeviceMemoryAddress joined by StartingAddress
        if ($maxBarBytes -eq 0) {
            $memAddrs = @(Get-CimInstance Win32_DeviceMemoryAddress -ErrorAction SilentlyContinue)
            $pnpRes = @(Get-CimInstance Win32_PnPAllocatedResource -ErrorAction SilentlyContinue)
            foreach ($gpu in $gpus) {
                $gpuId = $gpu.PNPDeviceID
                if (-not $gpuId) { continue }
                $matchedRes = $pnpRes | Where-Object { $_.Dependent.DeviceID -eq $gpuId -and $null -ne $_.Antecedent.StartingAddress }
                foreach ($res in $matchedRes) {
                    $addr = $memAddrs | Where-Object { $_.StartingAddress -eq $res.Antecedent.StartingAddress } | Select-Object -First 1
                    if ($addr -and $null -ne $addr.StartingAddress -and $null -ne $addr.EndingAddress) {
                        $start = [Convert]::ToInt64($addr.StartingAddress, 10)
                        $end = [Convert]::ToInt64($addr.EndingAddress, 10)
                        $size = $end - $start + 1
                        if ($size -gt $maxBarBytes) {
                            $maxBarBytes = $size
                        }
                    }
                }
            }
        }

        $maxBarMb = [math]::Round($maxBarBytes / 1MB)
        if ($maxBarBytes -ge 536870912) { # >= 512 MB indicates 64-bit Resizable BAR is expanded (> standard 256MB)
            $rebarStatus.IsEnabled = $true
            $rebarStatus.IsSupported = $true
            $rebarStatus.BarSizeMb = $maxBarMb
            $rebarStatus.Details = "Enabled (BAR Aperture: ${maxBarMb} MB)"
        } elseif ($maxBarBytes -gt 0) {
            $rebarStatus.IsEnabled = $false
            $rebarStatus.IsSupported = $true
            $rebarStatus.BarSizeMb = $maxBarMb
            $rebarStatus.Details = "Disabled in BIOS / 256MB Legacy Aperture (Current: ${maxBarMb} MB)"
        } else {
            $rebarStatus.Details = "Memory aperture could not be resolved"
        }
    } catch {
        $rebarStatus.Details = "Query exception: $($_.Exception.Message)"
    }

    return $rebarStatus
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

        $isHighBoost = ($vc.Name -match '(?i)9070\s*(XT)?|7900\s*(XTX|XT|GRE)|7800\s*XT|6950\s*XT|6900\s*XT|RTX\s*50[89]0|RTX\s*4090|RTX\s*4080')

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

    # Detect Dual-GPU Configuration, Potential Version Desync, and Hybrid Multi-GPU Setups
    $dualGpuConflict = $false
    $dualGpuDetails = $null
    $hybridMultiGpu = $false
    $hybridMultiGpuDetails = $null

    $activeGpus = @($gpuList | Where-Object { -not $_.IsGeneric })
    if ($activeGpus.Count -ge 2) {
        $hybridMultiGpu = $true
        $gpuSummaryNames = ($activeGpus | ForEach-Object { "$($_.Name) ($($_.Vendor) v$($_.DriverVersion))" }) -join ' + '
        $vendors = @($activeGpus.Vendor | Select-Object -Unique)
        if ($vendors.Count -gt 1) {
            $hybridMultiGpuDetails = "Hybrid cross-vendor multi-GPU configuration active: $gpuSummaryNames. Cross-vendor iGPU + dGPU setups can experience DXGI adapter enumeration or HAGS / DWM presentation deadlocks (LiveKernelEvent 0x193 / 0x141) in D3D12 titles."
        } else {
            $hybridMultiGpuDetails = "Multi-GPU configuration active: $gpuSummaryNames."
        }
    }

    if ($gpuList.Count -ge 2) {
        $amdGpus = @($gpuList | Where-Object { $_.Vendor -eq "AMD" })
        if ($amdGpus.Count -ge 2) {
            $versions = @($amdGpus.DriverVersion | Select-Object -Unique)
            if ($versions.Count -gt 1) {
                $dualGpuConflict = $true
                $dualGpuDetails = "Discrete GPU and integrated GPU report different driver versions ($($versions -join ' vs '))."
            }
        }
    }

    # Detect Conflicting / Ghost GPU Drivers (e.g. leftover NVIDIA service on AMD system or AMD service on NVIDIA)
    $ghostGpuDrivers = [System.Collections.Generic.List[string]]::new()
    $hasDiscreteAmd = @($gpuList | Where-Object { $_.Vendor -eq "AMD" -and -not $_.IsGeneric }).Count -gt 0
    $hasDiscreteNvidia = @($gpuList | Where-Object { $_.Vendor -eq "NVIDIA" -and -not $_.IsGeneric }).Count -gt 0

    if ($hasDiscreteAmd) {
        $nvKmd = Get-Service -Name "nvlddmkm" -ErrorAction SilentlyContinue
        if ($nvKmd -and $nvKmd.StartType -ne 'Disabled') {
            $ghostGpuDrivers.Add("NVIDIA Display Driver service (nvlddmkm) is present/active on an AMD GPU system")
        }
    }
    if ($hasDiscreteNvidia) {
        $amdKmd = Get-Service -Name "amdkmdag" -ErrorAction SilentlyContinue
        if ($amdKmd -and $amdKmd.StartType -ne 'Disabled') {
            $ghostGpuDrivers.Add("AMD Display Driver service (amdkmdag) is present/active on an NVIDIA GPU system")
        }
    }

    # Query Windows Update Driver Policies
    $dsReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -ErrorAction SilentlyContinue
    $searchOrderConfig = if ($dsReg) { $dsReg.SearchOrderConfig } else { $null }

    $wuReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
    $excludeWUDrivers = if ($wuReg) { $wuReg.ExcludeWUDriversInQualityUpdate } else { $null }

    $ulpsActive = $false
    try {
        $classKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
        if (Test-Path $classKey) {
            $subkeys = Get-ChildItem -Path $classKey -ErrorAction SilentlyContinue
            foreach ($sk in $subkeys) {
                $p = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
                if ($p -and ($p.DriverDesc -match '(?i)Radeon|AMD' -or $null -ne $p.EnableUlps) -and $p.EnableUlps -eq 1) {
                    $ulpsActive = $true
                    break
                }
            }
        }
    } catch {}

    return [PSCustomObject]@{
        Gpus                  = @($gpuList)
        DualGpuConflict       = $dualGpuConflict
        DualGpuDetails        = $dualGpuDetails
        HybridMultiGpu        = $hybridMultiGpu
        HybridMultiGpuDetails = $hybridMultiGpuDetails
        SearchOrderConfig     = $searchOrderConfig
        ExcludeWUDrivers      = $excludeWUDrivers
        IsWUDriverBlocked     = ($searchOrderConfig -eq 0 -and $excludeWUDrivers -eq 1)
        IsUlpsEnabled         = $ulpsActive
        RebarStatus           = (Get-DcRebarStatus)
        GhostGpuDrivers       = @($ghostGpuDrivers)
        HasGhostDrivers       = ($ghostGpuDrivers.Count -gt 0)
    }
}

function Get-DcBluetoothHealth {
    [CmdletBinding()]
    param()

    $btDevices = Get-PnpDevice -Class Bluetooth -PresentOnly -ErrorAction SilentlyContinue
    $radios = $btDevices | Where-Object { $_.FriendlyName -match '(?i)Adapter|Radio|Bluetooth Device' -and $_.FriendlyName -notmatch 'LE Generic|Enumerator' }
    $controllers = $btDevices | Where-Object { $_.FriendlyName -match '(?i)Controller|DualSense|Xbox|Stadia|VR|Sense' }
    $audio = $btDevices | Where-Object { $_.FriendlyName -match '(?i)Buds|Headphones|Headset|AirPods|WH-|WF-' }

    # Sanitize possessive personal names (e.g. "John's AirPods" -> "AirPods") to protect user identity
    function Anonymize-BtDevice($dev) {
        if (-not $dev) { return $dev }
        $sanitizedName = $dev.FriendlyName -replace "^.+?'s\s+", "" -replace "^.+?の\s*", ""
        return [PSCustomObject]@{
            FriendlyName = $sanitizedName
            Status       = $dev.Status
            InstanceId   = $dev.InstanceId
        }
    }

    $sanitizedControllers = @($controllers | ForEach-Object { Anonymize-BtDevice $_ })
    $sanitizedAudio = @($audio | ForEach-Object { Anonymize-BtDevice $_ })

    $problemBt = $btDevices | Where-Object { $_.Status -ne "OK" }
    $sanitizedProblemBt = if ($problemBt) { @($problemBt | ForEach-Object { Anonymize-BtDevice $_ }) } else { @() }

    return [PSCustomObject]@{
        Radios        = @($radios)
        Controllers   = $sanitizedControllers
        AudioDevices  = $sanitizedAudio
        ProblemCount  = $sanitizedProblemBt.Count
        ProblemList   = $sanitizedProblemBt
    }
}

function Get-DcNetworkHealth {
    [CmdletBinding()]
    param()

    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $udpDynamicV4 = & netsh int ipv4 show dynamicport udp 2>$null
    $tcpDynamicV4 = & netsh int ipv4 show dynamicport tcp 2>$null
    $udpStart = $null; $udpNum = $null
    $tcpStart = $null; $tcpNum = $null

    if ($udpDynamicV4) {
        foreach ($line in $udpDynamicV4) {
            if ($line -match 'Start Port\s*:\s*(\d+)') { $udpStart = [int]$Matches[1] }
            if ($line -match 'Number of Ports\s*:\s*(\d+)') { $udpNum = [int]$Matches[1] }
        }
    }
    if ($tcpDynamicV4) {
        foreach ($line in $tcpDynamicV4) {
            if ($line -match 'Start Port\s*:\s*(\d+)') { $tcpStart = [int]$Matches[1] }
            if ($line -match 'Number of Ports\s*:\s*(\d+)') { $tcpNum = [int]$Matches[1] }
        }
    }

    $isUdpConstrained = ($udpNum -and $udpNum -lt 30000 -and $tcpNum -ge 30000)
    $udpRangeStr = if ($udpStart -and $udpNum) { "$udpStart-$($udpStart + $udpNum - 1) ($udpNum ports)" } else { "Default" }
    $tcpRangeStr = if ($tcpStart -and $tcpNum) { "$tcpStart-$($tcpStart + $tcpNum - 1) ($tcpNum ports)" } else { "Default" }

    foreach ($a in $adapters) {
        $speedDuplex = Get-NetAdapterAdvancedProperty -Name $a.Name -DisplayName "Speed & Duplex" -ErrorAction SilentlyContinue
        $sdVal = if ($speedDuplex) { $speedDuplex.DisplayValue } else { "N/A" }

        $vlan = Get-NetAdapterAdvancedProperty -Name $a.Name -DisplayName "Packet Priority & VLAN" -ErrorAction SilentlyContinue
        $vlanVal = if ($vlan) { $vlan.DisplayValue } else { "N/A" }

        $isIntel25G = ($a.InterfaceDescription -match '(?i)I225|I226|Intel.*Ethernet')
        $isRealtek25G = ($a.InterfaceDescription -match '(?i)Realtek.*2\.5G|RTL8125')

        $idleRestriction = $null
        $idleTimeoutMs = $null
        $enableD3ColdInS0 = $null
        $ltrEnabled = $null
        $pmArpOffload = $null
        $pmNsOffload = $null
        $ulpMode = $null
        $reduceSpeedOnPowerDown = $null
        $modernStandbyWoL = $null
        $eeeVal = $null
        $flowControlVal = $null
        $rawSpeedDuplex = $null
        $driverClassKeyPath = $null

        try {
            $netClassBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
            if (Test-Path $netClassBase) {
                $classSubKeys = Get-ChildItem -Path $netClassBase -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' }
                foreach ($csk in $classSubKeys) {
                    $props = Get-ItemProperty -Path $csk.PSPath -ErrorAction SilentlyContinue
                    if ($props -and (($a.InterfaceGuid -and $props.NetCfgInstanceId -eq $a.InterfaceGuid) -or ($props.DriverDesc -eq $a.InterfaceDescription))) {
                        $driverClassKeyPath = $csk.PSPath
                        $idleRestriction = $props.'*IdleRestriction'
                        $idleTimeoutMs = $props.IdleTimeoutMs
                        $enableD3ColdInS0 = $props.EnableD3ColdInS0
                        $ltrEnabled = $props.LatencyToleranceReporting
                        $pmArpOffload = $props.'*PMARPOffload'
                        $pmNsOffload = $props.'*PMNSOffload'
                        $ulpMode = $props.ULPMode
                        $reduceSpeedOnPowerDown = $props.ReduceSpeedOnPowerDown
                        $modernStandbyWoL = $props.'*ModernStandbyWoLMagicPacket'
                        $eeeVal = $props.'*EEE'
                        $flowControlVal = $props.'*FlowControl'
                        $rawSpeedDuplex = $props.'*SpeedDuplex'
                        break
                    }
                }
            }
        } catch {}

        $hasPowerSavingRisk = $false
        if ($isIntel25G -or $isRealtek25G) {
            $idleTimeoutActive = ($null -ne $idleTimeoutMs -and "$idleTimeoutMs" -ne "0")
            $d3ColdActive = ($null -eq $enableD3ColdInS0 -or "$enableD3ColdInS0" -ne "0")
            if ($idleRestriction -eq "0" -or $idleTimeoutActive -or ($isIntel25G -and $d3ColdActive) -or $ulpMode -eq "1" -or $reduceSpeedOnPowerDown -eq "1" -or $eeeVal -eq "1" -or $pmArpOffload -eq "1" -or $pmNsOffload -eq "1") {
                $hasPowerSavingRisk = $true
            }
        }
        $hasForced25GSpeed = $false
        if ($isIntel25G -or $isRealtek25G) {
            if ($rawSpeedDuplex -eq "2500" -or $sdVal -match '(?i)2\.5\s*Gbps') {
                $hasForced25GSpeed = $true
            }
        }

        $pwrParts = [System.Collections.Generic.List[string]]::new()
        if ($null -ne $idleTimeoutMs) {
            $pwrParts.Add("IdleTimeoutMs=$idleTimeoutMs" + $(if ("$idleTimeoutMs" -ne "0") { " (WDF S0-Idle Active)" } else { " (S0-Idle Disabled)" }))
        }
        if ($null -ne $enableD3ColdInS0) { $pwrParts.Add("EnableD3ColdInS0=$enableD3ColdInS0") }
        if ($null -ne $ltrEnabled) { $pwrParts.Add("LTR=$ltrEnabled") }
        if ($null -ne $idleRestriction) {
            $pwrParts.Add("IdleRestriction=$idleRestriction")
        }
        if ($null -ne $pmArpOffload) { $pwrParts.Add("PMARPOffload=$pmArpOffload") }
        if ($null -ne $pmNsOffload) { $pwrParts.Add("PMNSOffload=$pmNsOffload") }
        if ($null -ne $ulpMode) { $pwrParts.Add("ULPMode=$ulpMode") }
        if ($null -ne $reduceSpeedOnPowerDown) { $pwrParts.Add("ReduceSpeedOnPowerDown=$reduceSpeedOnPowerDown") }
        if ($null -ne $eeeVal) { $pwrParts.Add("EEE=$eeeVal") }
        if ($null -ne $flowControlVal) { $pwrParts.Add("FlowControl=$flowControlVal") }
        $powerSavingSummary = if ($pwrParts.Count -gt 0) { $pwrParts -join ", " } else { "Default" }

        $results.Add([PSCustomObject]@{
            Name                        = $a.Name
            InterfaceDescription        = $a.InterfaceDescription
            Status                      = $a.Status
            LinkSpeed                   = $a.LinkSpeed
            SpeedDuplex                 = $sdVal
            RawSpeedDuplex              = $rawSpeedDuplex
            PriorityVLAN                = $vlanVal
            IsIntel25G                  = $isIntel25G
            DriverClassKeyPath          = $driverClassKeyPath
            IdleRestriction             = $idleRestriction
            IdleTimeoutMs               = $idleTimeoutMs
            EnableD3ColdInS0            = $enableD3ColdInS0
            LatencyToleranceReporting   = $ltrEnabled
            PMARPOffload                = $pmArpOffload
            PMNSOffload                 = $pmNsOffload
            ULPMode                     = $ulpMode
            ReduceSpeedOnPowerDown      = $reduceSpeedOnPowerDown
            ModernStandbyWoLMagicPacket = $modernStandbyWoL
            EEE                         = $eeeVal
            FlowControl                 = $flowControlVal
            HasPowerSavingRisk          = $hasPowerSavingRisk
            HasForced25GSpeed           = $hasForced25GSpeed
            PowerSavingSummary          = $powerSavingSummary
            UdpPortRange                = $udpRangeStr
            TcpPortRange                = $tcpRangeStr
            IsUdpConstrained            = $isUdpConstrained
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
        $detailedTimings = [System.Collections.Generic.List[PSCustomObject]]::new()
        $riskReasons = [System.Collections.Generic.List[string]]::new()

        foreach ($t in $timings) {
            $vBlankLines = ($t.VTotal - $t.VActive)
            $isModeHighRisk = ($t.PixelClockMHz -gt 580 -or $vBlankLines -gt 1500)
            $detailedTimings.Add([PSCustomObject]@{
                Mode          = "$($t.HActive)x$($t.VActive)@$($t.RefreshRate)Hz"
                PixelClockMHz = $t.PixelClockMHz
                VBlankLines   = $vBlankLines
                IsHighRisk    = $isModeHighRisk
            })
            if ($t.HActive -ge 2560 -and $t.VActive -ge 1440 -and $t.RefreshRate -gt 144) {
                if ($t.PixelClockMHz -ge 585 -or $t.VTotal -ge 1500) {
                    $hasRisk = $true
                    if (-not $riskTiming) { $riskTiming = $t }
                }
            }
        }

        $isKnownIssueModel = ($dispName -match '(?i)Optix.*G27|MAG27|G24C')
        $hasTimingRiskFinal = ($hasRisk -or ($isKnownIssueModel -and $currentRefresh -gt 144))

        if ($hasTimingRiskFinal) {
            if ($riskTiming) {
                $riskReasons.Add("High-refresh overclock timing $($riskTiming.HActive)x$($riskTiming.VActive)@$($riskTiming.RefreshRate)Hz (Pixel Clock: $($riskTiming.PixelClockMHz) MHz, V-Total: $($riskTiming.VTotal) lines) approaches DisplayPort 1.2a / budget scaler saturation limits.")
            }
            if ($isKnownIssueModel -and $currentRefresh -gt 144) {
                $riskReasons.Add("Known MSI Optix/MAG high-refresh DisplayPort blanking profile detected at $($currentRefresh)Hz.")
            }
        }

        $displayObj = [PSCustomObject]@{
            Name               = $dispName
            MonitorId          = $monId
            Connection         = $connType
            IsDisplayPort      = $isDisplayPort
            ActiveResolution   = $currentRes
            ActiveRefreshRate  = $currentRefresh
            Timings            = @($timings)
            DetailedTimings    = @($detailedTimings)
            HasTimingRisk      = $hasTimingRiskFinal
            RiskTiming         = $riskTiming
            RiskReasons        = @($riskReasons)
            IsKnownIssueModel  = $isKnownIssueModel
        }

        $displayList.Add($displayObj)

        if ($displayObj.HasTimingRisk -and -not $results.HighRiskTimingsDetected) {
            $results.HighRiskTimingsDetected = $true
            $timingStr = if ($riskTiming) { "$($riskTiming.HActive)x$($riskTiming.VActive) @ $($riskTiming.RefreshRate)Hz (Pixel Clock: $($riskTiming.PixelClockMHz) MHz, V-Total: $($riskTiming.VTotal) lines)" } else { "Active Refresh: $($currentRefresh)Hz" }
            $results.RiskSummary = "Display '$dispName' ($connType) is running a high-refresh factory overclock ($timingStr). On DisplayPort 1.2a without DSC, bloated factory blanking operates budget monitor scalers at their electrical and thermal limits, causing periodic phase desync, Hot-Plug Detect (HPD) link drops, and 2-3s blackouts without triggering GPU driver TDRs."
            $results.Guidance = $null
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
            RiskReason  = "Legacy direct I/O port driver."
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
        $results.RiskSummary = "Legacy kernel I/O driver(s) configured to load on boot: $activeNames."
        $results.Guidance = $null
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

function Get-DcMemoryHealth {
    [CmdletBinding()]
    param()

    $sticks = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue)
    $memResults = [PSCustomObject]@{
        TotalCapacityGb      = 0
        ModuleCount          = 0
        ConfiguredClockSpeed = 0
        MaxSpeed             = 0
        IsRunningBaseJedec   = $false
        Modules              = [System.Collections.Generic.List[PSCustomObject]]::new()
        Summary              = "No physical memory modules detected"
    }

    if ($sticks.Count -gt 0) {
        $totalBytes = [int64]0
        $maxSpeed = 0
        $configuredSpeed = 0

        foreach ($s in $sticks) {
            $capBytes = if ($s.Capacity) { [Convert]::ToInt64($s.Capacity, 10) } else { 0 }
            $totalBytes += $capBytes
            $spd = if ($s.Speed) { [int]$s.Speed } else { 0 }
            $cfg = if ($s.ConfiguredClockSpeed) { [int]$s.ConfiguredClockSpeed } else { 0 }
            if ($spd -gt $maxSpeed) { $maxSpeed = $spd }
            if ($cfg -gt $configuredSpeed) { $configuredSpeed = $cfg }

            $memResults.Modules.Add([PSCustomObject]@{
                BankLabel       = $s.BankLabel
                DeviceLocator   = $s.DeviceLocator
                CapacityGb      = [math]::Round($capBytes / 1GB, 1)
                Manufacturer    = if ($s.Manufacturer) { $s.Manufacturer.Trim() } else { "Unknown" }
                PartNumber      = if ($s.PartNumber) { $s.PartNumber.Trim() } else { "Unknown" }
                Speed           = $spd
                ConfiguredSpeed = $cfg
            })
        }

        $totalGb = [math]::Round($totalBytes / 1GB)
        $memResults.TotalCapacityGb = $totalGb
        $memResults.ModuleCount = $sticks.Count
        $memResults.ConfiguredClockSpeed = $configuredSpeed
        $memResults.MaxSpeed = $maxSpeed

        if ($maxSpeed -gt 0 -and $configuredSpeed -gt 0 -and $configuredSpeed -lt $maxSpeed) {
            $memResults.IsRunningBaseJedec = $true
        }

        $memResults.Summary = "${totalGb} GB ($($sticks.Count) module(s) @ ${configuredSpeed} MT/s)"
    }

    return $memResults
}

function Get-DcStorageHealth {
    [CmdletBinding()]
    param()

    $disks = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction SilentlyContinue)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($d in $disks) {
        $totalGb = if ($d.Size) { [math]::Round([Convert]::ToInt64($d.Size, 10) / 1GB, 1) } else { 0 }
        $freeGb = if ($d.FreeSpace) { [math]::Round([Convert]::ToInt64($d.FreeSpace, 10) / 1GB, 1) } else { 0 }
        $pctFree = if ($totalGb -gt 0) { [math]::Round(($freeGb / $totalGb) * 100, 1) } else { 0 }
        $isLowSpace = ($freeGb -lt 10)

        $results.Add([PSCustomObject]@{
            DeviceID    = $d.DeviceID
            VolumeName  = if ($d.VolumeName) { $d.VolumeName } else { "Local Disk" }
            TotalGb     = $totalGb
            FreeGb      = $freeGb
            PercentFree = $pctFree
            IsLowSpace  = $isLowSpace
        })
    }

    return $results
}

function Get-DcPhysicalDiskHealth {
    [CmdletBinding()]
    param([int]$EventDays = 30)

    $result = [PSCustomObject]@{
        Disks        = [System.Collections.Generic.List[PSCustomObject]]::new()
        StorageEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
        Findings     = [System.Collections.Generic.List[string]]::new()
        Notes        = [System.Collections.Generic.List[string]]::new()
    }

    $physical = @()
    try { $physical = @(Get-PhysicalDisk -ErrorAction Stop) } catch { $result.Notes.Add("Get-PhysicalDisk unavailable: $($_.Exception.Message)") }

    foreach ($pd in $physical) {
        $rel = $null
        try { $rel = $pd | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}

        $sizeGb = if ($pd.Size) { [math]::Round([double]$pd.Size / 1GB, 0) } else { 0 }
        $disk = [PSCustomObject]@{
            FriendlyName          = $pd.FriendlyName
            MediaType             = [string]$pd.MediaType
            BusType               = [string]$pd.BusType
            SizeGb                = $sizeGb
            HealthStatus          = [string]$pd.HealthStatus
            OperationalStatus     = (@($pd.OperationalStatus) -join ', ')
            Wear                  = if ($rel) { $rel.Wear } else { $null }
            TemperatureC          = if ($rel) { $rel.Temperature } else { $null }
            TemperatureMaxC       = if ($rel) { $rel.TemperatureMax } else { $null }
            PowerOnHours          = if ($rel) { $rel.PowerOnHours } else { $null }
            ReadErrorsTotal       = if ($rel) { $rel.ReadErrorsTotal } else { $null }
            ReadErrorsUncorrected = if ($rel) { $rel.ReadErrorsUncorrected } else { $null }
            WriteErrorsTotal      = if ($rel) { $rel.WriteErrorsTotal } else { $null }
            WriteErrorsUncorrected = if ($rel) { $rel.WriteErrorsUncorrected } else { $null }
            ReliabilityAvailable  = ($null -ne $rel)
        }
        $result.Disks.Add($disk)

        $name = "$($pd.FriendlyName) ($sizeGb GB $($disk.BusType))"
        if ($disk.HealthStatus -and $disk.HealthStatus -ne 'Healthy') { $result.Findings.Add("$name reports HealthStatus '$($disk.HealthStatus)' (Operational: $($disk.OperationalStatus)).") }
        if ($null -ne $disk.Wear -and $disk.Wear -ge 80) { $result.Findings.Add("$name wear is $($disk.Wear)% (SSD nearing end of life).") }
        if ($null -ne $disk.TemperatureC -and $disk.TemperatureC -ge 70) { $result.Findings.Add("$name temperature is $($disk.TemperatureC) C (max recorded: $($disk.TemperatureMaxC) C).") }
        if ($disk.ReadErrorsUncorrected -gt 0 -or $disk.WriteErrorsUncorrected -gt 0) { $result.Findings.Add("$name has uncorrected I/O errors (read: $($disk.ReadErrorsUncorrected), write: $($disk.WriteErrorsUncorrected)).") }
        if (-not $disk.ReliabilityAvailable) { $result.Notes.Add("$($pd.FriendlyName): SMART/reliability counters not available (may require Administrator or driver support).") }
    }

    # Storage-related errors from the System log (disk, filesystem, NVMe/SATA controller)
    try {
        $since = (Get-Date).AddDays(-$EventDays)
        $wanted = @{
            'disk'     = @(7, 11, 15, 51, 52, 153)
            'Ntfs'     = @(55, 137)
            'stornvme' = @(129, 130)
            'storahci' = @(129)
            'volmgr'   = @(46, 161)
        }
        $evts = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = @($wanted.Keys); StartTime = $since } -ErrorAction SilentlyContinue)
        foreach ($e in $evts) {
            if ($wanted[$e.ProviderName] -and ($wanted[$e.ProviderName] -contains $e.Id)) {
                $msg = if ($e.Message) { ($e.Message -split "`r?`n")[0] } else { "" }
                if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
                $result.StorageEvents.Add([PSCustomObject]@{ TimeCreated = $e.TimeCreated; Provider = $e.ProviderName; Id = $e.Id; Message = $msg })
            }
        }
        if ($result.StorageEvents.Count -gt 0) {
            $grp = $result.StorageEvents | Group-Object Provider, Id | Sort-Object Count -Descending
            $summary = ($grp | Select-Object -First 4 | ForEach-Object { "$($_.Name -replace ', ',' event ') x$($_.Count)" }) -join '; '
            $result.Findings.Add("$($result.StorageEvents.Count) storage/filesystem error event(s) in the last $EventDays days: $summary.")
        }
    } catch {}

    return $result
}

function Get-DcWheaEvents {
    [CmdletBinding()]
    param([int]$Days = 30)

    $events = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $since = (Get-Date).AddDays(-$Days)
        foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $since } -ErrorAction SilentlyContinue)) {
            $msg = if ($e.Message) { ($e.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' ' } else { "" }
            if ($msg.Length -gt 220) { $msg = $msg.Substring(0, 220) }
            $events.Add([PSCustomObject]@{ TimeCreated = $e.TimeCreated; Id = $e.Id; Level = $e.LevelDisplayName; Message = $msg })
        }
    } catch {}
    return $events
}
Export-ModuleMember -Function Get-DcPnpHealth, Get-DcGpuDriverHealth, Get-DcRebarStatus, Get-DcMemoryHealth, Get-DcStorageHealth, Get-DcPhysicalDiskHealth, Get-DcWheaEvents, Get-DcBluetoothHealth, Get-DcNetworkHealth, Get-DcDisplayDiagnostics, Get-DcProblematicKernelDrivers, Get-DcMotherboardAndChipsetHealth
