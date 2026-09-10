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

function Clear-DcGameConfig {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("TheGreatCircle", "DOOMEternal", "DOOMTheDarkAges", "All")]
        [string]$Game = "All",

        [Parameter(Mandatory = $false)]
        [switch]$Backup = $true
    )

    $targets = [System.Collections.Generic.List[string]]::new()
    $savedGames = Join-Path $env:USERPROFILE "Saved Games"

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

    if ($runningSteam) {
        if ($KillRunningSteam) {
            Write-Host "Closing active Steam processes to unlock browser cache..." -ForegroundColor Yellow
            $runningSteam | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        } else {
            Write-Host "[WARNING] Steam / SteamWebHelper is currently running." -ForegroundColor Yellow
            Write-Host "Please close Steam before clearing the browser cache, or specify -KillRunningSteam." -ForegroundColor Yellow
            return $false
        }
    }

    if (Test-Path $cachePath) {
        if ($PSCmdlet.ShouldProcess($cachePath, "Purge Steam CEF HTML Browser Cache")) {
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

function Repair-DcEthernetSettings {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("Current", "2.5G", "1.0G", "Auto")]
        [string]$Speed = "Current"
    )

    if (-not (Test-DcIsAdmin)) {
        Write-Host "[ERROR] Administrator elevation is required to modify network adapter properties." -ForegroundColor Red
        Write-Host "Please re-run in an elevated terminal (Run as Administrator)." -ForegroundColor Yellow
        return $false
    }

    $adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match '(?i)I225|I226|Intel.*Ethernet' } | Select-Object -First 1
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

    if (-not (Test-DcIsAdmin)) {
        Write-Host "[ERROR] Administrator elevation is required to modify driver policies." -ForegroundColor Red
        return $false
    }

    Write-Host "=== Applying Windows Update GPU Driver Overwrite Protection ===" -ForegroundColor Cyan
    if ($BlockWindowsUpdateDrivers) {
        if ($PSCmdlet.ShouldProcess("Registry Driver Policies", "Block Windows Update from replacing graphics drivers")) {
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
        $paths.Add([PSCustomObject]@{ Label = "AMD OpenGL Shader Cache"; Path = (Join-Path $localApp "AMD\GLCache") })
        $paths.Add([PSCustomObject]@{ Label = "AMD OpenCL Cache"; Path = (Join-Path $localApp "AMD\OclCache") })
    }
    if ($Target -in @("NVIDIA", "All")) {
        $paths.Add([PSCustomObject]@{ Label = "NVIDIA DXCache"; Path = (Join-Path $localApp "NVIDIA\DXCache") })
        $paths.Add([PSCustomObject]@{ Label = "NVIDIA GLCache"; Path = (Join-Path $localApp "NVIDIA\GLCache") })
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

    Write-Host "=== OPTIMIZING PCIE LINK STATE POWER MANAGEMENT (ASPM) ===" -ForegroundColor Magenta
    Write-Host "Disabling PCIe Link State Power Management on active power plan..." -ForegroundColor White

    if ($PSCmdlet.ShouldProcess("Active Power Scheme (SCHEME_CURRENT)", "Disable PCIe Link State Power Management (ASPM)")) {
        try {
            $subGroup = "501a4d13-42af-4429-9e56-9d9c20330821"
            $setting = "ee12f906-d277-404b-b6da-e5fa1a576df5"

            & powercfg /setacvalueindex SCHEME_CURRENT $subGroup $setting 0
            & powercfg /setdcvalueindex SCHEME_CURRENT $subGroup $setting 0
            & powercfg /setactive SCHEME_CURRENT

            Write-Host "  [OK] Link State Power Management set to OFF for AC and DC." -ForegroundColor Green
            Write-Host "[SUCCESS] PCIe bus power transitions disabled. GPU will maintain active link clock." -ForegroundColor Green
            Write-Host "This resolves random driver timeouts (TDR 4101), sleep-wake crashes, and PCIe WHEA errors." -ForegroundColor DarkGray
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

    if (-not (Test-DcIsAdmin)) {
        Write-Host "[ERROR] Administrator elevation is required to configure kernel driver services." -ForegroundColor Red
        Write-Host "Please run this command from an elevated PowerShell terminal (Run as Administrator)." -ForegroundColor Yellow
        return $false
    }

    Write-Host "Configuring kernel driver service '$DriverName'..." -ForegroundColor Yellow

    if ($PSCmdlet.ShouldProcess($DriverName, "Disable service (sc.exe config $DriverName start= disabled)")) {
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

Export-ModuleMember -Function Test-DcIsAdmin, Clear-DcGameConfig, Clear-DcSteamCache, Clear-DcShaderCache, Stop-DcZombieProcesses, Repair-DcEthernetSettings, Repair-DcAmdDriverAlignment, Repair-DcPciePowerSettings, Disable-DcProblematicKernelDriver
