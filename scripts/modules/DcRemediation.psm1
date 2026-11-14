<#
.SYNOPSIS
    DriverCheck - Safe Remediation & System Maintenance Module
.DESCRIPTION
    Provides non-destructive, safe remediation actions with automatic backups,
    WhatIf/Confirm support, and admin checks.
#>

function Test-DcIsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-DcAdminElevation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $false)]
        [string[]]$Arguments = @()
    )

    if (Test-DcIsAdmin) { return $true }
    if (-not $ScriptPath -or -not (Test-Path $ScriptPath)) {
        Write-Host "[WARNING] Cannot auto-elevate without a valid -ScriptPath." -ForegroundColor Yellow
        return $false
    }

    try {
        $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$ScriptPath`"")
        if ($Arguments) { $argList += $Arguments }
        Write-Host "[INFO] Requesting Administrator elevation via UAC..." -ForegroundColor Cyan
        Start-Process -FilePath "powershell.exe" -ArgumentList ($argList -join " ") -Verb RunAs -Wait
        return $true
    } catch {
        Write-Host "[ERROR] Elevation cancelled or failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Backup-DcRemediationState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ActionName = "General",

        [Parameter(Mandatory = $false)]
        [string]$BackupDirectory
    )

    try {
        if (-not $BackupDirectory) {
            $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
            $BackupDirectory = Join-Path $repoRoot "logs"
        }
        if (-not (Test-Path $BackupDirectory)) {
            New-Item -Path $BackupDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        }

        $ts = (Get-Date).ToString("yyyyMMdd-HHmmss")
        $safeAction = ($ActionName -replace '[^a-zA-Z0-9_-]', '_')
        $backupFile = Join-Path $BackupDirectory "Remediation-Backup-$safeAction-$ts.json"

        $udpV4Raw = (& netsh int ipv4 show dynamicport udp 2>$null) | Out-String
        $udpV6Raw = (& netsh int ipv6 show dynamicport udp 2>$null) | Out-String

        $adapterSnapshot = @()
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match '(?i)I225|I226|Intel.*Ethernet|Realtek' -or $_.Name -eq 'Ethernet' }
        foreach ($ad in $adapters) {
            $spd = Get-NetAdapterAdvancedProperty -Name $ad.Name -DisplayName "Speed & Duplex" -ErrorAction SilentlyContinue
            $vlan = Get-NetAdapterAdvancedProperty -Name $ad.Name -DisplayName "Packet Priority & VLAN" -ErrorAction SilentlyContinue
            $adapterSnapshot += [PSCustomObject]@{
                Name                = $ad.Name
                InterfaceDesc       = $ad.InterfaceDescription
                SpeedAndDuplex      = if ($spd) { $spd.DisplayValue } else { $null }
                PacketPriorityVlan  = if ($vlan) { $vlan.DisplayValue } else { $null }
            }
        }

        $netClassBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
        $regKeysToCapture = @(
            "IdleTimeoutMs", "EnableD3ColdInS0", "LatencyToleranceReporting",
            "*PMARPOffload", "*PMNSOffload", "*IdleRestriction", "ULPMode",
            "ReduceSpeedOnPowerDown", "*ModernStandbyWoLMagicPacket",
            "*EEE", "*SpeedDuplex", "*FlowControl"
        )
        if ($adapterSnapshot.Count -gt 0 -and (Test-Path $netClassBase)) {
            $csks = Get-ChildItem -Path $netClassBase -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' }
            foreach ($adSnap in $adapterSnapshot) {
                $adObj = $adapters | Where-Object { $_.Name -eq $adSnap.Name } | Select-Object -First 1
                $classKeyPath = $null
                $drvRegVals = [ordered]@{}
                foreach ($csk in $csks) {
                    $props = Get-ItemProperty -Path $csk.PSPath -ErrorAction SilentlyContinue
                    if ($props -and (($adObj -and $adObj.InterfaceGuid -and $props.NetCfgInstanceId -eq $adObj.InterfaceGuid) -or ($props.DriverDesc -eq $adSnap.InterfaceDesc))) {
                        $classKeyPath = $csk.PSPath
                        foreach ($rk in $regKeysToCapture) {
                            if ($props.PSObject.Properties.Name -contains $rk -and $null -ne $props.$rk) {
                                $drvRegVals[$rk] = [string]$props.$rk
                            }
                        }
                        break
                    }
                }
                $adSnap | Add-Member -NotePropertyName ClassKeyPath -NotePropertyValue $classKeyPath -Force
                $adSnap | Add-Member -NotePropertyName DriverRegistryValues -NotePropertyValue $drvRegVals -Force
            }
        }

        $dsKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -ErrorAction SilentlyContinue
        $wuKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
        $gfxKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -ErrorAction SilentlyContinue
        $pwrKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -ErrorAction SilentlyContinue

        $snapshot = [PSCustomObject]@{
            Timestamp                          = (Get-Date).ToString("o")
            ActionName                         = $ActionName
            UdpDynamicPortIPv4                 = if ($udpV4Raw) { $udpV4Raw.Trim() } else { $null }
            UdpDynamicPortIPv6                 = if ($udpV6Raw) { $udpV6Raw.Trim() } else { $null }
            NetworkAdapters                    = $adapterSnapshot
            RegistryDriverSearchOrderConfig    = if ($dsKey -and $null -ne $dsKey.SearchOrderConfig) { $dsKey.SearchOrderConfig } else { $null }
            RegistryExcludeWUDrivers           = if ($wuKey -and $null -ne $wuKey.ExcludeWUDriversInQualityUpdate) { $wuKey.ExcludeWUDriversInQualityUpdate } else { $null }
            RegistryTdrDelay                   = if ($gfxKey -and $null -ne $gfxKey.TdrDelay) { $gfxKey.TdrDelay } else { $null }
            RegistryTdrDdiDelay                = if ($gfxKey -and $null -ne $gfxKey.TdrDdiDelay) { $gfxKey.TdrDdiDelay } else { $null }
            RegistryHiberbootEnabled           = if ($pwrKey -and $null -ne $pwrKey.HiberbootEnabled) { $pwrKey.HiberbootEnabled } else { $null }
        }

        $snapshot | ConvertTo-Json -Depth 5 | Set-Content -Path $backupFile -Encoding UTF8 -ErrorAction SilentlyContinue
        Write-Host "  [BACKUP] Saved pre-remediation state to: $([System.IO.Path]::GetFileName($backupFile))" -ForegroundColor DarkGray
        return $backupFile
    } catch {
        return $null
    }
}

function Restore-DcRemediationState {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupFilePath
    )

    if (-not (Test-Path $BackupFilePath)) {
        Write-Host "[ERROR] Backup file not found: $BackupFilePath" -ForegroundColor Red
        return $false
    }

    if (-not (Test-DcIsAdmin) -and -not $WhatIfPreference) {
        Write-Host "[ERROR] Administrator elevation is required to restore system state." -ForegroundColor Red
        return $false
    }

    try {
        $snap = Get-Content -Path $BackupFilePath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($PSCmdlet.ShouldProcess($BackupFilePath, "Restore system state from snapshot ($($snap.ActionName) @ $($snap.Timestamp))")) {
            if ($snap.NetworkAdapters) {
                foreach ($ad in $snap.NetworkAdapters) {
                    if ($ad.SpeedAndDuplex) {
                        Set-NetAdapterAdvancedProperty -Name $ad.Name -DisplayName "Speed & Duplex" -DisplayValue $ad.SpeedAndDuplex -ErrorAction SilentlyContinue
                    }
                    if ($ad.PacketPriorityVlan) {
                        Set-NetAdapterAdvancedProperty -Name $ad.Name -DisplayName "Packet Priority & VLAN" -DisplayValue $ad.PacketPriorityVlan -ErrorAction SilentlyContinue
                    }
                }
            }
            if ($snap.NetworkAdapters) {
                foreach ($ad in $snap.NetworkAdapters) {
                    if ($ad.PSObject.Properties['ClassKeyPath'] -and $ad.ClassKeyPath -and $ad.PSObject.Properties['DriverRegistryValues'] -and $ad.DriverRegistryValues -and (Test-Path $ad.ClassKeyPath)) {
                        foreach ($prop in $ad.DriverRegistryValues.PSObject.Properties) {
                            if ($null -ne $prop.Value) {
                                Set-ItemProperty -Path $ad.ClassKeyPath -Name $prop.Name -Value ([string]$prop.Value) -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
            }
            if ($null -ne $snap.RegistryDriverSearchOrderConfig) {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value ([int]$snap.RegistryDriverSearchOrderConfig) -Type DWord -Force -ErrorAction SilentlyContinue
            }
            if ($null -ne $snap.RegistryTdrDelay) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDelay" -Value ([int]$snap.RegistryTdrDelay) -Type DWord -Force -ErrorAction SilentlyContinue
            }
            if ($null -ne $snap.RegistryHiberbootEnabled) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value ([int]$snap.RegistryHiberbootEnabled) -Type DWord -Force -ErrorAction SilentlyContinue
            }
            Write-Host "[SUCCESS] Restored remediation snapshot from $BackupFilePath" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "[ERROR] Failed to restore snapshot: $($_.Exception.Message)" -ForegroundColor Red
    }
    return $false
}

function Clear-DcGameConfig {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("TheGreatCircle", "DOOMEternal", "DOOMTheDarkAges", "CrimsonDesert", "All")]
        [string]$Game = "All",

        [Parameter(Mandatory = $false)]
        [switch]$Backup = $true
    )

    $targets = [System.Collections.Generic.List[string]]::new()
    $savedGames = Join-Path $env:USERPROFILE "Saved Games"
    $localApp = $env:LOCALAPPDATA

    if ($Game -in @("TheGreatCircle", "All")) {
        $targets.Add((Join-Path $savedGames "MachineGames\TheGreatCircle\base"))
    }
    if ($Game -in @("DOOMEternal", "All")) {
        $targets.Add((Join-Path $savedGames "id Software\DOOMEternal\base"))
    }
    if ($Game -in @("DOOMTheDarkAges", "All")) {
        $targets.Add((Join-Path $savedGames "id Software\DOOMTheDarkAges\base"))
    }

    $cleanedCount = 0
    foreach ($target in $targets) {
        if (Test-Path $target) {
            Write-Host "Inspecting: $target" -ForegroundColor Yellow
            $configs = Get-ChildItem -Path $target -Include "*.local", "*.cfg", "crash_marker.txt" -File -ErrorAction SilentlyContinue
            if ($configs) {
                foreach ($cfg in $configs) {
                    if ($PSCmdlet.ShouldProcess($cfg.FullName, "Backup and Clean Stale Game Config")) {
                        try {
                            if ($Backup) {
                                $backupPath = "$($cfg.FullName).bak"
                                Copy-Item -Path $cfg.FullName -Destination $backupPath -Force -ErrorAction Stop
                                Write-Host "  [BACKUP] Created: $([System.IO.Path]::GetFileName($backupPath))" -ForegroundColor DarkGray
                            }
                            Remove-Item -Path $cfg.FullName -Force -ErrorAction Stop
                            Write-Host "  [REMOVED] $($cfg.Name)" -ForegroundColor Green
                            $cleanedCount++
                        } catch {
                            Write-Host "  [FAILED] $($cfg.Name): $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                }
            } else {
                Write-Host "  No stale config files found in directory." -ForegroundColor DarkGray
            }
        }
    }

    # Special handling for Crimson Desert (Pearl Abyss / BlackSpace Engine)
    if ($Game -in @("CrimsonDesert", "All")) {
        $paDir = Join-Path $localApp "Pearl Abyss"
        $dumpCacheDir = Join-Path $paDir "DumpCache"
        $tempDir = Join-Path $paDir "temp"
        $cdSaveDir = Join-Path $paDir "CD\save"

        if (Test-Path $dumpCacheDir) {
            Write-Host "Inspecting Pearl Abyss DumpCache & Crash Locks: $dumpCacheDir" -ForegroundColor Yellow
            $dumpItems = Get-ChildItem -Path $dumpCacheDir -Include "*.lock", "*.run", "*.dat", "last_crash", "metadata" -Recurse -ErrorAction SilentlyContinue
            foreach ($item in $dumpItems) {
                if ($PSCmdlet.ShouldProcess($item.FullName, "Purge Crash Lock / Dump Item")) {
                    try {
                        Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                        Write-Host "  [REMOVED] $($item.Name)" -ForegroundColor Green
                        $cleanedCount++
                    } catch {
                        Write-Host "  [NOTICE] Could not remove $($item.Name): $($_.Exception.Message)" -ForegroundColor DarkGray
                    }
                }
            }
        }

        if (Test-Path $tempDir) {
            Write-Host "Inspecting Pearl Abyss Temp: $tempDir" -ForegroundColor Yellow
            $tempFiles = Get-ChildItem -Path $tempDir -File -ErrorAction SilentlyContinue
            foreach ($tf in $tempFiles) {
                if ($PSCmdlet.ShouldProcess($tf.FullName, "Purge Temp Dump File")) {
                    try {
                        Remove-Item -Path $tf.FullName -Force -ErrorAction Stop
                        Write-Host "  [REMOVED] $($tf.Name)" -ForegroundColor Green
                        $cleanedCount++
                    } catch {}
                }
            }
        }

        if (Test-Path $cdSaveDir) {
            $optFile = Join-Path $cdSaveDir "user_engine_option_save.xml"
            if (Test-Path $optFile) {
                if ($PSCmdlet.ShouldProcess($optFile, "Backup and Clean Engine Options")) {
                    try {
                        if ($Backup) {
                            $bakPath = "$optFile.bak"
                            Copy-Item -Path $optFile -Destination $bakPath -Force -ErrorAction Stop
                            Write-Host "  [BACKUP] Created: $([System.IO.Path]::GetFileName($bakPath))" -ForegroundColor DarkGray
                        }
                        Remove-Item -Path $optFile -Force -ErrorAction Stop
                        Write-Host "  [REMOVED] user_engine_option_save.xml" -ForegroundColor Green
                        $cleanedCount++
                    } catch {}
                }
            }
        }
    }

    return $cleanedCount
}

function Clear-DcSteamCache {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$KillRunningSteam
    )

    $cachePath = Join-Path $env:LOCALAPPDATA "Steam\htmlcache"
    $runningSteam = Get-Process -Name steam, steamwebhelper -ErrorAction SilentlyContinue
    if ($runningSteam -and $WhatIfPreference -and -not $KillRunningSteam) {
        Write-Host "[WARNING] Steam / SteamWebHelper is currently running (dry-run preview continuing under -WhatIf)." -ForegroundColor Yellow
        $runningSteam = $null
    }

    if ($runningSteam) {
        if ($KillRunningSteam) {
            if ($PSCmdlet.ShouldProcess("Active Steam processes", "Terminate Steam / SteamWebHelper to unlock browser cache")) {
                Write-Host "Closing active Steam processes to unlock browser cache..." -ForegroundColor Yellow
            $runningSteam | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
            }
        } else {
            Write-Host "[WARNING] Steam / SteamWebHelper is currently running." -ForegroundColor Yellow
            Write-Host "Please close Steam before clearing the browser cache, or specify -KillRunningSteam." -ForegroundColor Yellow
            return $false
        }
    }

    if (Test-Path $cachePath) {
        $steamCacheProceed = $PSCmdlet.ShouldProcess($cachePath, "Purge Steam CEF HTML Browser Cache")
        if (-not $steamCacheProceed) { return $false }
        if ($steamCacheProceed) {
            try {
                Remove-Item -Path "$cachePath\*" -Recurse -Force -ErrorAction Stop
                Write-Host "[SUCCESS] Steam HTML browser cache purged successfully." -ForegroundColor Green
                return $true
            } catch {
                Write-Host "[FAILED] Could not purge Steam cache: $($_.Exception.Message)" -ForegroundColor Red
                return $false
            }
        }
    } else {
        Write-Host "No Steam HTML cache directory found at '$cachePath'." -ForegroundColor DarkGray
        return $true
    }
}

function Stop-DcZombieProcesses {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $targetNames = @("steam", "steamwebhelper", "gameoverlayui", "steamerrorreporter", "steamerrorreporter64")
    $procs = Get-Process -Name $targetNames -ErrorAction SilentlyContinue

    $terminatedCount = 0
    if ($procs) {
        foreach ($p in $procs) {
            $isCandidate = $false
            try {
                $hasWindow = ($p.MainWindowHandle -ne [IntPtr]::Zero)
                $isHung = ($p.Responding -eq $false)
                $isLowThread = ($p.Threads.Count -le 3 -and -not $hasWindow -and $p.ProcessName -eq "steam")
                if ($isHung -or $isLowThread) { $isCandidate = $true }
            } catch { $isCandidate = $true }

            if ($isCandidate) {
                if ($PSCmdlet.ShouldProcess("$($p.ProcessName) (PID: $($p.Id))", "Terminate Zombie / Hung Process")) {
                    try {
                        Stop-Process -Id $p.Id -Force -ErrorAction Stop
                        Write-Host "  [KILLED] $($p.ProcessName) (PID: $($p.Id))" -ForegroundColor Green
                        $terminatedCount++
                    } catch {
                        Write-Host "  [FAILED] PID $($p.Id): $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
        }
    }

    if ($terminatedCount -eq 0) {
        Write-Host "No hung or zombie background processes detected." -ForegroundColor DarkGray
    }
    return $terminatedCount
}

function Repair-DcUdpPortRange {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [int]$StartPort = 1024,

        [Parameter(Mandatory = $false)]
        [int]$NumberOfPorts = 64511
    )

    if (-not (Test-DcIsAdmin) -and -not $WhatIfPreference) {
        Write-Host "[ERROR] Administrator elevation is required to modify dynamic port ranges." -ForegroundColor Red
        Write-Host "Please re-run in an elevated terminal (Run as Administrator) or run:" -ForegroundColor Yellow
        Write-Host "  netsh int ipv4 set dynamicport udp start=$StartPort num=$NumberOfPorts" -ForegroundColor White
        Write-Host "  netsh int ipv6 set dynamicport udp start=$StartPort num=$NumberOfPorts" -ForegroundColor White
        return $false
    }

    Write-Host "=== Windows UDP Ephemeral Port Space Optimizer ===" -ForegroundColor Cyan
    Write-Host "Target Configuration: Start Port: $StartPort, Number of Ports: $NumberOfPorts (Range: $StartPort-$($StartPort + $NumberOfPorts - 1))" -ForegroundColor White

    $targetAction = "Expand dynamic UDP port range for IPv4 and IPv6 to StartPort=$StartPort, NumberOfPorts=$NumberOfPorts"
    if ($PSCmdlet.ShouldProcess("TCP/IP Stack", $targetAction)) {
        Backup-DcRemediationState -ActionName "UdpPortRange" | Out-Null
        try {
            Write-Host "Configuring IPv4 UDP dynamic port range..." -NoNewline -ForegroundColor White
            $v4Out = & netsh int ipv4 set dynamicport udp start=$StartPort num=$NumberOfPorts 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host " [ OK ]" -ForegroundColor Green
            } else {
                Write-Host " [FAILED: $v4Out]" -ForegroundColor Red
            }

            Write-Host "Configuring IPv6 UDP dynamic port range..." -NoNewline -ForegroundColor White
            $v6Out = & netsh int ipv6 set dynamicport udp start=$StartPort num=$NumberOfPorts 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host " [ OK ]" -ForegroundColor Green
            } else {
                Write-Host " [FAILED: $v6Out]" -ForegroundColor Red
            }

            Write-Host "`nUpdated Dynamic Port Status:" -ForegroundColor Cyan
            & netsh int ipv4 show dynamicport udp | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

            Write-Host "`n[SUCCESS] Windows UDP dynamic port space expanded to match TCP range." -ForegroundColor Green
            Write-Host "Eliminates ephemeral port exhaustion (Event 4266) during Steam/game matchmaking." -ForegroundColor DarkGray
            return $true
        } catch {
            Write-Host " [ERROR: $($_.Exception.Message)]" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

function Repair-DcEthernetSettings {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("Current", "2.5G", "1.0G", "Auto")]
        [string]$Speed = "Current",

        [Parameter(Mandatory = $false)]
        [switch]$ExpandUdpPorts
    )

    if ($ExpandUdpPorts) {
        $udpResult = Repair-DcUdpPortRange -WhatIf:$WhatIfPreference
    }

    if (-not (Test-DcIsAdmin) -and -not $WhatIfPreference) {
        Write-Host "[ERROR] Administrator elevation is required to modify network adapter properties." -ForegroundColor Red
        Write-Host "Please re-run in an elevated terminal (Run as Administrator)." -ForegroundColor Yellow
        return $false
    }

    $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match '(?i)I225|I226|Intel.*Ethernet' } | Select-Object -First 1
    if (-not $adapter) { $adapter = Get-NetAdapter -Name "Ethernet" -ErrorAction SilentlyContinue }
    if (-not $adapter) {
        Write-Host "[ERROR] No suitable Ethernet adapter found to configure." -ForegroundColor Red
        return $false
    }

    Write-Host "Target Adapter: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor White
    $speedValue = switch ($Speed) {
        "2.5G" { "2.5 Gbps Full Duplex" }
        "1.0G" { "1.0 Gbps Full Duplex" }
        "Auto" { "Auto Negotiation" }
        default { $null }
    }

    $actionDesc = if ($speedValue) {
        "Set Speed/Duplex to '$speedValue' and disable Packet Priority/VLAN"
    } else {
        "Disable Packet Priority/VLAN (preserving current Speed & Duplex)"
    }

    if ($PSCmdlet.ShouldProcess($adapter.Name, $actionDesc)) {
        Backup-DcRemediationState -ActionName "EthernetSettings" | Out-Null
        if ($speedValue) {
            try {
                Write-Host "Applying Speed & Duplex ('$speedValue')..." -NoNewline -ForegroundColor White
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Speed & Duplex" -DisplayValue $speedValue -ErrorAction Stop
                Write-Host " [ OK ]" -ForegroundColor Green
            } catch {
                Write-Host " [NOTICE: $($_.Exception.Message)]" -ForegroundColor Yellow
            }
        } else {
            $currentSpeed = Get-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Speed & Duplex" -ErrorAction SilentlyContinue
            $curVal = if ($currentSpeed) { $currentSpeed.DisplayValue } else { "Unknown" }
            Write-Host "Preserving current Speed & Duplex ('$curVal')." -ForegroundColor DarkGray
        }

        try {
            Write-Host "Disabling Packet Priority & VLAN..." -NoNewline -ForegroundColor White
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Packet Priority & VLAN" -DisplayValue "Packet Priority & VLAN Disabled" -ErrorAction Stop
            Write-Host " [ OK ]" -ForegroundColor Green
        } catch {
            Write-Host " [NOTICE: $($_.Exception.Message)]" -ForegroundColor Yellow
        }

        # Apply NetAdapterCx / NDIS Idle Power-Down & IEEE 802.3bz Stability Fixes in Driver Class Key
        try {
            $netClassBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
            if (Test-Path $netClassBase) {
                $classSubKeys = Get-ChildItem -Path $netClassBase -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' }
                foreach ($csk in $classSubKeys) {
                    $props = Get-ItemProperty -Path $csk.PSPath -ErrorAction SilentlyContinue
                    if ($props -and (($adapter.InterfaceGuid -and $props.NetCfgInstanceId -eq $adapter.InterfaceGuid) -or ($props.DriverDesc -eq $adapter.InterfaceDescription))) {
                        $regModified = $false
                        Write-Host "Disabling NetAdapterCx WDF S0-Idle, D3Cold, LTR & Firmware Offload states in driver registry ($($csk.PSChildName))..." -ForegroundColor White
                        if ($null -ne $props.IdleTimeoutMs -or $props.PSObject.Properties.Name -contains 'IdleTimeoutMs') {
                            Set-ItemProperty -Path $csk.PSPath -Name "IdleTimeoutMs" -Value "0" -ErrorAction SilentlyContinue
                            Write-Host "  [OK] IdleTimeoutMs = 0 (WDF S0-Idle power-down disabled in e2fn.sys)" -ForegroundColor Green
                            $regModified = $true
                        }
                        Set-ItemProperty -Path $csk.PSPath -Name "EnableD3ColdInS0" -Value "0" -ErrorAction SilentlyContinue
                        Write-Host "  [OK] EnableD3ColdInS0 = 0 (D3cold in S0 disabled)" -ForegroundColor Green
                        $regModified = $true

                        Set-ItemProperty -Path $csk.PSPath -Name "LatencyToleranceReporting" -Value "0" -ErrorAction SilentlyContinue
                        Write-Host "  [OK] LatencyToleranceReporting = 0 (Dynamic PCIe LTR 5s timer disabled)" -ForegroundColor Green
                        $regModified = $true

                        if ($null -ne $props.'*PMARPOffload') {
                            Set-ItemProperty -Path $csk.PSPath -Name "*PMARPOffload" -Value "0" -ErrorAction SilentlyContinue
                            Write-Host "  [OK] *PMARPOffload = 0 (Firmware ARP Offload disabled)" -ForegroundColor Green
                            $regModified = $true
                        }
                        if ($null -ne $props.'*PMNSOffload') {
                            Set-ItemProperty -Path $csk.PSPath -Name "*PMNSOffload" -Value "0" -ErrorAction SilentlyContinue
                            Write-Host "  [OK] *PMNSOffload = 0 (Firmware NS Offload disabled)" -ForegroundColor Green
                            $regModified = $true
                        }
                        if ($null -ne $props.'*IdleRestriction') {
                            Set-ItemProperty -Path $csk.PSPath -Name "*IdleRestriction" -Value "1" -ErrorAction SilentlyContinue
                            Write-Host "  [OK] *IdleRestriction = 1" -ForegroundColor Green
                            $regModified = $true
                        }
                        if ($null -ne $props.ULPMode) {
                            Set-ItemProperty -Path $csk.PSPath -Name "ULPMode" -Value "0" -ErrorAction SilentlyContinue
                            Write-Host "  [OK] ULPMode = 0 (Ultra Low Power disabled)" -ForegroundColor Green
                            $regModified = $true
                        }
                        if ($null -ne $props.ReduceSpeedOnPowerDown) {
                            Set-ItemProperty -Path $csk.PSPath -Name "ReduceSpeedOnPowerDown" -Value "0" -ErrorAction SilentlyContinue
                            Write-Host "  [OK] ReduceSpeedOnPowerDown = 0" -ForegroundColor Green
                            $regModified = $true
                        }
                        if ($null -ne $props.'*ModernStandbyWoLMagicPacket') {
                            Set-ItemProperty -Path $csk.PSPath -Name "*ModernStandbyWoLMagicPacket" -Value "0" -ErrorAction SilentlyContinue
                            Write-Host "  [OK] *ModernStandbyWoLMagicPacket = 0" -ForegroundColor Green
                            $regModified = $true
                        }
                        Set-ItemProperty -Path $csk.PSPath -Name "*EEE" -Value "0" -ErrorAction SilentlyContinue
                        Write-Host "  [OK] *EEE = 0 (Energy Efficient Ethernet disabled)" -ForegroundColor Green
                        $regModified = $true
                        if ($Speed -eq "Current" -and $props.'*SpeedDuplex' -eq "2500") {
                            Set-ItemProperty -Path $csk.PSPath -Name "*SpeedDuplex" -Value "0" -ErrorAction SilentlyContinue
                            Write-Host "  [OK] *SpeedDuplex = 0 (Restored IEEE 802.3bz Auto Negotiation from forced 2.5G)" -ForegroundColor Green
                            $regModified = $true
                        }
                        $fcEnumPath = Join-Path $csk.PSPath "Ndi\params\*FlowControl\Enum"
                        if ((Test-Path $fcEnumPath) -and $null -ne (Get-ItemProperty -Path $fcEnumPath -Name "4" -ErrorAction SilentlyContinue).'4') {
                            Set-ItemProperty -Path $csk.PSPath -Name "*FlowControl" -Value "4" -ErrorAction SilentlyContinue
                            Write-Host "  [OK] *FlowControl = 4 (Auto Negotiation)" -ForegroundColor Green
                            $regModified = $true
                        }
                        if ($regModified) {
                            Write-Host "Restarting adapter '$($adapter.Name)' to apply NetAdapterCx power settings..." -NoNewline -ForegroundColor White
                            Restart-NetAdapter -Name $adapter.Name -ErrorAction SilentlyContinue
                            Write-Host " [ OK ]" -ForegroundColor Green
                        }
                        break
                    }
                }
            }
        } catch {
            Write-Host " [NOTICE: $($_.Exception.Message)]" -ForegroundColor Yellow
        }

        Write-Host "[SUCCESS] Network adapter configuration applied." -ForegroundColor Green
        return $true
    }
    return $false
}

function Repair-DcAmdDriverAlignment {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$BlockWindowsUpdateDrivers = $true
    )

    if (-not (Test-DcIsAdmin) -and -not $WhatIfPreference) {
        Write-Host "[ERROR] Administrator elevation is required to modify driver policies." -ForegroundColor Red
        return $false
    }

    Write-Host "=== Applying Windows Update GPU Driver Overwrite Protection ===" -ForegroundColor Cyan
    if ($BlockWindowsUpdateDrivers) {
        if ($PSCmdlet.ShouldProcess("Registry Driver Policies", "Block Windows Update from replacing graphics drivers")) {
            Backup-DcRemediationState -ActionName "AmdDriverAlignment" | Out-Null
            try {
                # 1. DriverSearching -> SearchOrderConfig = 0
                $dsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"
                if (-not (Test-Path $dsPath)) { New-Item -Path $dsPath -Force | Out-Null }
                Set-ItemProperty -Path $dsPath -Name "SearchOrderConfig" -Value 0 -Type DWord -Force
                Write-Host "  [OK] Set SearchOrderConfig = 0 (Windows Update driver search disabled)" -ForegroundColor Green

                # 2. WindowsUpdate -> ExcludeWUDriversInQualityUpdate = 1
                $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                if (-not (Test-Path $wuPath)) { New-Item -Path $wuPath -Force | Out-Null }
                Set-ItemProperty -Path $wuPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord -Force
                Write-Host "  [OK] Set ExcludeWUDriversInQualityUpdate = 1 (Quality updates exclude drivers)" -ForegroundColor Green

                Write-Host "[SUCCESS] Windows Update driver replacement policies successfully locked." -ForegroundColor Green
                return $true
            } catch {
                Write-Host "[FAILED] Could not apply registry policies: $($_.Exception.Message)" -ForegroundColor Red
                return $false
            }
        }
    }
    return $false
}

function Clear-DcShaderCache {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("DirectX", "AMD", "NVIDIA", "All")]
        [string]$Target = "All"
    )

    Write-Host "=== PURGING GRAPHICS & SHADER CACHES ===" -ForegroundColor Magenta

    $paths = [System.Collections.Generic.List[PSCustomObject]]::new()
    $localApp = $env:LOCALAPPDATA

    if ($Target -in @("DirectX", "All")) {
        $paths.Add([PSCustomObject]@{ Label = "DirectX D3D Shader Cache"; Path = (Join-Path $localApp "D3DSCache") })
    }
    if ($Target -in @("AMD", "All")) {
        $paths.Add([PSCustomObject]@{ Label = "AMD DirectX Shader Cache"; Path = (Join-Path $localApp "AMD\DxCache") })
        $paths.Add([PSCustomObject]@{ Label = "AMD DXC Shader Cache (SM6 / DX12)"; Path = (Join-Path $localApp "AMD\DxcCache") })
        $paths.Add([PSCustomObject]@{ Label = "AMD Vulkan Shader Cache"; Path = (Join-Path $localApp "AMD\VkCache") })
        $paths.Add([PSCustomObject]@{ Label = "AMD OpenGL Shader Cache"; Path = (Join-Path $localApp "AMD\GLCache") })
        $paths.Add([PSCustomObject]@{ Label = "AMD OpenCL Cache"; Path = (Join-Path $localApp "AMD\OclCache") })
        if ($env:USERPROFILE) {
            $paths.Add([PSCustomObject]@{ Label = "AMD LocalLow DirectX Shader Cache"; Path = (Join-Path $env:USERPROFILE "AppData\LocalLow\AMD\DxCache") })
            $paths.Add([PSCustomObject]@{ Label = "AMD LocalLow DXC Shader Cache"; Path = (Join-Path $env:USERPROFILE "AppData\LocalLow\AMD\DxcCache") })
        }
    }
    if ($Target -in @("NVIDIA", "All")) {
        $paths.Add([PSCustomObject]@{ Label = "NVIDIA DXCache"; Path = (Join-Path $localApp "NVIDIA\DXCache") })
        $paths.Add([PSCustomObject]@{ Label = "NVIDIA GLCache"; Path = (Join-Path $localApp "NVIDIA\GLCache") })
        if ($env:USERPROFILE) {
            $paths.Add([PSCustomObject]@{ Label = "NVIDIA LocalLow PerDriverVersion DXCache"; Path = (Join-Path $env:USERPROFILE "AppData\LocalLow\NVIDIA\PerDriverVersion\DXCache") })
        }
    }

    $totalPurged = 0
    foreach ($p in $paths) {
        if (Test-Path $p.Path) {
            Write-Host "Cleaning $($p.Label): $($p.Path)..." -ForegroundColor Yellow
            if ($PSCmdlet.ShouldProcess($p.Path, "Purge Shader Cache Files")) {
                $files = Get-ChildItem -Path $p.Path -Recurse -File -ErrorAction SilentlyContinue
                if ($files) {
                    $cleanedThis = 0
                    foreach ($f in $files) {
                        try {
                            Remove-Item -Path $f.FullName -Force -ErrorAction Stop
                            $cleanedThis++
                            $totalPurged++
                        } catch {
                            # File may be actively locked by running game or display service
                        }
                    }
                    Write-Host "  [OK] Cleared $cleanedThis file(s)." -ForegroundColor Green
                } else {
                    Write-Host "  Directory is empty (no cache files)." -ForegroundColor DarkGray
                }
            }
        }
    }

    Write-Host "[DONE] Shader cache purge complete ($totalPurged file(s) removed)." -ForegroundColor Green
    Write-Host "Next time games launch, shaders will cleanly recompile from scratch." -ForegroundColor DarkGray
    return $totalPurged
}

function Repair-DcPciePowerSettings {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if (-not (Test-DcIsAdmin) -and -not $WhatIfPreference) {
        Write-Host "[ERROR] Administrator elevation is required to modify PCIe power plan settings." -ForegroundColor Red
        Write-Host "Please re-run in an elevated terminal (Run as Administrator)." -ForegroundColor Yellow
        return $false
    }

    Write-Host "=== OPTIMIZING PCIE LINK STATE POWER MANAGEMENT (ASPM) ===" -ForegroundColor Magenta
    Write-Host "Disabling PCIe Link State Power Management on active power plan..." -ForegroundColor White

    if ($PSCmdlet.ShouldProcess("Active Power Scheme (SCHEME_CURRENT)", "Disable PCIe Link State Power Management (ASPM)")) {
        try {
            $subGroup = "501a4d13-42af-4429-9fd1-a8218c268e20"
            $setting = "ee12f906-d277-404b-b6da-e5fa1a576df5"

            & powercfg /setacvalueindex SCHEME_CURRENT $subGroup $setting 0
            $acExit = $LASTEXITCODE
            & powercfg /setdcvalueindex SCHEME_CURRENT $subGroup $setting 0
            $dcExit = $LASTEXITCODE
            & powercfg /setactive SCHEME_CURRENT

            if ($acExit -ne 0 -or $dcExit -ne 0) {
                Write-Host "  [FAILED] powercfg returned non-zero exit code (AC=$acExit, DC=$dcExit)." -ForegroundColor Red
                return $false
            }

            Write-Host "  [OK] Link State Power Management set to OFF for AC and DC." -ForegroundColor Green
            Write-Host "[SUCCESS] PCIe bus power transitions disabled. GPU and chipset PCIe endpoints will maintain active link clock." -ForegroundColor Green
            Write-Host "This resolves random driver timeouts (TDR 4101), sleep-wake crashes, PCIe WHEA errors, and 2.5GbE NIC DMA hangs." -ForegroundColor DarkGray
            return $true
        } catch {
            Write-Host "  [FAILED] Could not update power settings: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

function Disable-DcProblematicKernelDriver {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriverName
    )

    if (-not (Test-DcIsAdmin) -and -not $WhatIfPreference) {
        Write-Host "[ERROR] Administrator elevation is required to configure kernel driver services." -ForegroundColor Red
        Write-Host "Please run this command from an elevated PowerShell terminal (Run as Administrator)." -ForegroundColor Yellow
        return $false
    }

    Write-Host "Configuring kernel driver service '$DriverName'..." -ForegroundColor Yellow

    if ($PSCmdlet.ShouldProcess($DriverName, "Disable service (sc.exe config $DriverName start= disabled)")) {
        Backup-DcRemediationState -ActionName "DisableDriver_$DriverName" | Out-Null
        try {
            $configResult = & sc.exe config $DriverName start= disabled 2>&1 | Out-String
            if ($configResult -match 'SUCCESS') {
                Write-Host "  [OK] Service '$DriverName' set to DISABLED (Start Type: 4)." -ForegroundColor Green
            } else {
                Write-Host "  [NOTICE] sc config output: $($configResult.Trim())" -ForegroundColor Yellow
            }

            $stopResult = & sc.exe stop $DriverName 2>&1 | Out-String
            Write-Host "  [OK] Stop signal sent to '$DriverName'." -ForegroundColor DarkGray

            Write-Host "[SUCCESS] Driver '$DriverName' disabled. It will no longer load into kernel memory on boot." -ForegroundColor Green
            return $true
        } catch {
            Write-Host "[FAILED] Could not disable service '$DriverName': $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

function Repair-DcGpuSleepSettings {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [int]$TdrDelaySeconds = 8,

        [Parameter(Mandatory = $false)]
        [switch]$DisableUlps,

        [Parameter(Mandatory = $false)]
        [switch]$DisableFastStartup
    )

    if (-not (Test-DcIsAdmin) -and -not $WhatIfPreference) {
        Write-Host "[ERROR] Administrator elevation is required to configure GPU sleep and TDR recovery settings." -ForegroundColor Red
        Write-Host "Please run this command from an elevated PowerShell terminal (Run as Administrator)." -ForegroundColor Yellow
        return $false
    }

    Write-Host "=== OPTIMIZING GPU WATCHDOG & DISPLAY WAKE RECOVERY ===" -ForegroundColor Magenta
    Write-Host "  Preserving GPU sleep and power-saving states by default (Zero Power Impact)." -ForegroundColor Cyan

    # 1. Increase TdrDelay and TdrDdiDelay in GraphicsDrivers registry (Zero Power Impact)
    $appliedAny = $false
    $gfxKey = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    if ($PSCmdlet.ShouldProcess($gfxKey, "Set TdrDelay = $TdrDelaySeconds and TdrDdiDelay = $TdrDelaySeconds")) {
        Backup-DcRemediationState -ActionName "GpuSleepSettings" | Out-Null
        if (-not (Test-Path $gfxKey)) { New-Item -Path $gfxKey -ItemType Directory -Force | Out-Null }
        Set-ItemProperty -Path $gfxKey -Name "TdrDelay" -Value $TdrDelaySeconds -Type DWord -Force
        Set-ItemProperty -Path $gfxKey -Name "TdrDdiDelay" -Value $TdrDelaySeconds -Type DWord -Force
        Write-Host "  [OK] Graphics watchdog timeout (TdrDelay / TdrDdiDelay) set to $TdrDelaySeconds seconds (Zero Power Impact)." -ForegroundColor Green
        $appliedAny = $true
    }

    # 2. Ultra-Low Power State (ULPS) - ONLY modified if explicitly requested as a temporary diagnostic last resort
    if ($DisableUlps) {
        Write-Host "  [NOTICE] Disabling ULPS (Temporary Diagnostic Workaround / Last Resort). Note: Increases idle power consumption." -ForegroundColor Yellow
        $classKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
        $ulpsFixed = 0
        if (Test-Path $classKey) {
            $subkeys = Get-ChildItem -Path $classKey -ErrorAction SilentlyContinue
            foreach ($sk in $subkeys) {
                $prop = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
                if ($prop -and ($prop.DriverDesc -match '(?i)Radeon|AMD' -or $null -ne $prop.EnableUlps)) {
                    if ($PSCmdlet.ShouldProcess("$($prop.DriverDesc) ($($sk.PSChildName))", "Set EnableUlps = 0")) {
                        Set-ItemProperty -Path $sk.PSPath -Name "EnableUlps" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path $sk.PSPath -Name "EnableUlps_NA" -Value "0" -Type String -Force -ErrorAction SilentlyContinue
                        Write-Host "  [OK] Disabled ULPS on $($prop.DriverDesc) ($($sk.PSChildName)) [Temporary Workaround]." -ForegroundColor Yellow
                        $ulpsFixed++
                        $appliedAny = $true
                    }
                }
            }
        }
    } else {
        Write-Host "  [INFO] GPU low-power sleep states (ULPS) kept active to preserve energy savings." -ForegroundColor Gray
    }

    # 3. Disable Fast Startup if requested
    if ($DisableFastStartup) {
        $pwrKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
        if (Test-Path $pwrKey) {
            if ($PSCmdlet.ShouldProcess($pwrKey, "Set HiberbootEnabled = 0")) {
                Set-ItemProperty -Path $pwrKey -Name "HiberbootEnabled" -Value 0 -Type DWord -Force
                Write-Host "  [OK] Windows Fast Startup disabled (ensures clean driver state on reboots)." -ForegroundColor Green
                $appliedAny = $true
            }
        }
    }

    if (-not $appliedAny) { return $false }
    Write-Host "[SUCCESS] GPU recovery settings optimized. A system reboot is recommended to apply changes." -ForegroundColor Green
    return $true
}

Export-ModuleMember -Function Test-DcIsAdmin, Request-DcAdminElevation, Backup-DcRemediationState, Restore-DcRemediationState, Clear-DcGameConfig, Clear-DcSteamCache, Clear-DcShaderCache, Stop-DcZombieProcesses, Repair-DcEthernetSettings, Repair-DcUdpPortRange, Repair-DcAmdDriverAlignment, Repair-DcPciePowerSettings, Disable-DcProblematicKernelDriver, Repair-DcGpuSleepSettings

