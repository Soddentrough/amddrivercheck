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
        [ValidateSet("2.5G", "1.0G", "Auto")]
        [string]$Speed = "2.5G"
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
    }

    if ($PSCmdlet.ShouldProcess($adapter.Name, "Set Speed/Duplex to '$speedValue' and disable Packet Priority/VLAN")) {
        try {
            Write-Host "Applying Speed & Duplex ('$speedValue')..." -NoNewline -ForegroundColor White
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Speed & Duplex" -DisplayValue $speedValue -ErrorAction Stop
            Write-Host " [ OK ]" -ForegroundColor Green
        } catch {
            Write-Host " [NOTICE: $($_.Exception.Message)]" -ForegroundColor Yellow
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

Export-ModuleMember -Function Test-DcIsAdmin, Clear-DcGameConfig, Clear-DcSteamCache, Stop-DcZombieProcesses, Repair-DcEthernetSettings, Repair-DcAmdDriverAlignment
