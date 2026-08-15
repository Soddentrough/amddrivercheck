<#
.SYNOPSIS
    GPU & System Driver Diagnostic, Age Tracker & Crash Dump Analysis Tool
.DESCRIPTION
    Checks active display devices and their currently loaded driver versions/providers.
    Queries active Network Adapters and Storage Controllers for driver age and health.
    Scans system event logs for network adapter disconnects (Intel I225-V e2fnexpress), GPU TDR timeouts (LiveKernelEvent 141), and Kernel-Power reboots (Event 41).
    Scans for recent Steam crash dumps, Windows user-mode crash dumps, and game telemetry caches (Pearl Abyss, BeamNG).
    Checks registry keys related to Windows Update driver searches and custom TdrDelay values.
    Detects potential driver downgrade conflicts and offers automated fixes.
.PARAMETER ApplyFix
    Switch parameter to apply fixes (installing driver, removing custom TdrDelay, or updating registry policies) if issues are detected.
    Must be run as Administrator. Prompts for confirmation before applying any changes.
.EXAMPLE
    .\Get-GPUDriverDiagnostics.ps1
    Runs the tool in read-only diagnostic mode (safe).
.EXAMPLE
    .\Get-GPUDriverDiagnostics.ps1 -ApplyFix
    Prompts to apply fixes (requires Administrator elevation).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$ApplyFix
)

# Set Output Encoding to UTF-8 to support consistent terminal rendering
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Function to write colored log messages
function Write-Log {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Success", "Warning", "Error", "Header", "Muted")]
        [string]$Type = "Info",
        [Parameter(Mandatory = $false)]
        [switch]$NoNewLine
    )

    $color = "White"
    $prefix = ""
    switch ($Type) {
        "Info"    { $color = "Cyan"; $prefix = "[INFO] " }
        "Success" { $color = "Green"; $prefix = "[ OK ] " }
        "Warning" { $color = "Yellow"; $prefix = "[WARN] " }
        "Error"   { $color = "Red"; $prefix = "[ERR ] " }
        "Header"  { $color = "Magenta"; $prefix = "=== " }
        "Muted"   { $color = "DarkGray"; $prefix = "    " }
    }

    if ($NoNewLine) {
        Write-Host "$prefix$Message" -ForegroundColor $color -NoNewline
    } else {
        Write-Host "$prefix$Message" -ForegroundColor $color
    }
}

# Helper to check if running as Admin
function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Helper to safely parse dotted version strings for comparison
function Get-SafeVersion {
    param([string]$versionStr)
    if ($versionStr -match '^\d+(\.\d+){1,3}$') {
        try {
            return [version]$versionStr
        } catch {
            return $null
        }
    }
    return $null
}

# Helper to calculate human-readable Driver Age
function Get-DriverAge {
    param([PSObject]$rawDate)
    if ($null -eq $rawDate) { return "Unknown" }
    
    $parsedDate = $null
    if ($rawDate -is [DateTime]) {
        $parsedDate = $rawDate
    } elseif ($rawDate -match '^(\d{4})-(\d{2})-(\d{2})') {
        try { $parsedDate = [DateTime]::Parse($Matches[0]) } catch {}
    } elseif ($rawDate -match '^(\d{4})(\d{2})(\d{2})') {
        try { $parsedDate = [DateTime]::Parse("$($Matches[1])-$($Matches[2])-$($Matches[3])") } catch {}
    }

    if ($null -eq $parsedDate) { return "Unknown" }

    $days = ((Get-Date) - $parsedDate).Days
    if ($days -lt 0) { return "0 days" }
    if ($days -lt 30) { return "$days days" }
    if ($days -lt 365) {
        $months = [math]::Round($days / 30.4, 1)
        return "$months mos ($days d)"
    }
    $years = [math]::Round($days / 365.25, 1)
    return "$years yrs ($days d)"
}

# Helper to search C:\AMD for extracted compatible drivers
function Find-CompatibleExtractedDriver {
    param([string]$pnpDeviceID)
    $devId = $null
    if ($pnpDeviceID -match 'DEV_([0-9A-Fa-f]{4})') {
        $devId = $Matches[1]
    }
    if ($null -eq $devId -or -not (Test-Path "C:\AMD")) {
        return $null
    }
    
    $infFiles = Get-ChildItem -Path "C:\AMD" -Filter "*.inf" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $infFiles) {
        $content = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue
        if ($content -match "DEV_$devId" -and $content -match "display") {
            $version = "Unknown"
            $driverVerLine = $content | Where-Object { $_ -match 'DriverVer\s*=' } | Select-Object -First 1
            if ($driverVerLine -and $driverVerLine -match 'DriverVer\s*=\s*[^,]+,\s*(.+)$') {
                $version = $Matches[1].Trim()
            }
            return [PSCustomObject]@{
                InfPath     = $file.FullName
                FolderPath  = $file.DirectoryName
                Version     = $version
            }
        }
    }
    return $null
}

# Helper to draw a formatted table
function Format-CustomTable {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Data,
        [Parameter(Mandatory=$true)]
        [array]$Columns
    )
    if ($Data.Count -eq 0) {
        Write-Host "  No records found." -ForegroundColor DarkGray
        return
    }
    
    # Calculate column widths
    $widths = @{}
    foreach ($col in $Columns) {
        $maxVal = $col.Length
        foreach ($row in $Data) {
            $val = ""
            if ($row.$col) {
                $val = [string]($row.$col)
            }
            if ($val.Length -gt $maxVal) {
                $maxVal = $val.Length
            }
        }
        $widths[$col] = $maxVal + 2 # Add padding
    }
    
    # Draw top border
    $topLine = "+"
    for ($i = 0; $i -lt $Columns.Count; $i++) {
        $col = $Columns[$i]
        $topLine += "-" * $widths[$col]
        if ($i -lt $Columns.Count - 1) { $topLine += "+" }
    }
    $topLine += "+"
    Write-Host "  $topLine" -ForegroundColor DarkGray
    
    # Draw headers
    for ($i = 0; $i -lt $Columns.Count; $i++) {
        $col = $Columns[$i]
        $headerText = " " + $col
        $headerText = $headerText.PadRight($widths[$col])
        Write-Host "  " -NoNewline -ForegroundColor DarkGray
        Write-Host "|" -NoNewline -ForegroundColor DarkGray
        Write-Host $headerText -NoNewline -ForegroundColor Cyan
        if ($i -eq $Columns.Count - 1) {
            Write-Host "|" -ForegroundColor DarkGray
        }
    }
    
    # Draw separator line
    $sepLine = "+"
    for ($i = 0; $i -lt $Columns.Count; $i++) {
        $col = $Columns[$i]
        $sepLine += "-" * $widths[$col]
        if ($i -lt $Columns.Count - 1) { $sepLine += "+" }
    }
    $sepLine += "+"
    Write-Host "  $sepLine" -ForegroundColor DarkGray
    
    # Draw rows
    foreach ($row in $Data) {
        for ($i = 0; $i -lt $Columns.Count; $i++) {
            $col = $Columns[$i]
            $val = ""
            if ($row.$col) {
                $val = [string]($row.$col)
            }
            $cellText = " " + $val
            $cellText = $cellText.PadRight($widths[$col])
            
            Write-Host "  " -NoNewline -ForegroundColor DarkGray
            Write-Host "|" -NoNewline -ForegroundColor DarkGray
            
            # Color coding cells
            $color = "White"
            if ($col -eq "Active" -and $val -eq "YES") {
                $color = "Green"
            } elseif ($col -eq "Active" -and $val -eq "NO") {
                $color = "DarkGray"
            } elseif ($col -eq "Provider" -and $val -match "Advanced Micro Devices") {
                $color = "Red"
            } elseif ($col -eq "Provider" -and $val -match "NVIDIA") {
                $color = "Green"
            } elseif ($col -eq "Provider" -and $val -match "Intel") {
                $color = "Blue"
            } elseif ($col -eq "Class" -and $val -eq "Display") {
                $color = "Magenta"
            } elseif ($col -eq "Class" -and $val -eq "Net") {
                $color = "Cyan"
            } elseif ($col -eq "DriverAge" -and $val -match "yrs") {
                $color = "Yellow"
            }
            
            Write-Host $cellText -NoNewline -ForegroundColor $color
            if ($i -eq $Columns.Count - 1) {
                Write-Host "|" -ForegroundColor DarkGray
            }
        }
    }
    
    # Draw bottom border
    $bottomLine = "+"
    for ($i = 0; $i -lt $Columns.Count; $i++) {
        $col = $Columns[$i]
        $bottomLine += "-" * $widths[$col]
        if ($i -lt $Columns.Count - 1) { $bottomLine += "+" }
    }
    $bottomLine += "+"
    Write-Host "  $bottomLine" -ForegroundColor DarkGray
}

# Display Title Card using ASCII
Write-Host ""
Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor Magenta
Write-Host "  |       GPU & System Driver Diagnostics, Age Tracker & Health Check       |" -ForegroundColor Magenta
Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor Magenta
Write-Host ""

$isAdmin = Test-IsAdmin
if ($isAdmin) {
    Write-Log "Running in ELEVATED mode (Administrator)" -Type Success
} else {
    Write-Log "Running in USER mode (Read-Only Diagnostics)" -Type Info
}
Write-Host ""

# ---------------------------------------------------------
# STEP 1: System Hardware Driver Inventory & Age Table
# ---------------------------------------------------------
Write-Log "Building System Hardware Driver Inventory & Age Summary..." -Type Header

$signedDriversAll = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue
$systemDriverInventory = [System.Collections.Generic.List[PSObject]]::new()

# 1. Display Devices
$videoControllers = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
$activeGPUs = [System.Collections.Generic.List[PSObject]]::new()

foreach ($vc in $videoControllers) {
    $sd = $signedDriversAll | Where-Object { $_.DeviceClass -eq 'DISPLAY' -and ($_.DeviceID -eq $vc.PNPDeviceID -or $_.DeviceName -eq $vc.Name) } | Select-Object -First 1
    $ver = if ($sd -and $sd.DriverVersion) { $sd.DriverVersion } else { $vc.DriverVersion }
    $rawDate = if ($sd -and $sd.DriverDate) { $sd.DriverDate } else { $vc.DriverDate }
    
    $formattedDate = "Unknown"
    if ($rawDate) {
        if ($rawDate -is [DateTime]) {
            $formattedDate = $rawDate.ToString("yyyy-MM-dd")
        } elseif ($rawDate -match '^(\d{4})(\d{2})(\d{2})') {
            $formattedDate = "$($Matches[1])-$($Matches[2])-$($Matches[3])"
        } else {
            $formattedDate = $rawDate.ToString()
        }
    }
    
    $prov = if ($sd -and $sd.DriverProviderName) { $sd.DriverProviderName } else { "Unknown" }
    $infName = if ($sd -and $sd.InfName) { $sd.InfName } else { "Unknown" }
    $signer = if ($sd -and $sd.Signer) { $sd.Signer } else { "Unknown" }
    
    $gpuObj = [PSCustomObject]@{
        Name          = $vc.Name
        Status        = $vc.Status
        PNPDeviceID   = $vc.PNPDeviceID
        DriverVersion = $ver
        DriverDate    = $formattedDate
        Provider      = $prov
        InfName       = $infName
        Signer        = $signer
    }
    $activeGPUs.Add($gpuObj)

    $systemDriverInventory.Add([PSCustomObject]@{
        Class         = "Display"
        DeviceName    = $vc.Name
        Provider      = $prov
        DriverVersion = $ver
        ReleaseDate   = $formattedDate
        DriverAge     = Get-DriverAge -rawDate $formattedDate
    })
}

# 2. Network Adapters
$netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
foreach ($net in $netAdapters) {
    $sd = $signedDriversAll | Where-Object { $_.DeviceClass -eq 'NET' -and ($_.DeviceName -eq $net.InterfaceDescription -or $_.Description -eq $net.InterfaceDescription) } | Select-Object -First 1
    $ver = if ($sd) { $sd.DriverVersion } else { "Unknown" }
    $rawDate = if ($sd) { $sd.DriverDate } else { $null }
    
    $formattedDate = "Unknown"
    if ($rawDate) {
        if ($rawDate -is [DateTime]) { $formattedDate = $rawDate.ToString("yyyy-MM-dd") }
        elseif ($rawDate -match '^(\d{4})(\d{2})(\d{2})') { $formattedDate = "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
    }
    $prov = if ($sd -and $sd.DriverProviderName) { $sd.DriverProviderName } else { "Unknown" }
    
    $systemDriverInventory.Add([PSCustomObject]@{
        Class         = "Net"
        DeviceName    = $net.InterfaceDescription
        Provider      = $prov
        DriverVersion = $ver
        ReleaseDate   = $formattedDate
        DriverAge     = Get-DriverAge -rawDate $formattedDate
    })
}

# Render Driver Inventory Table
Format-CustomTable -Data $systemDriverInventory -Columns @("Class", "DeviceName", "Provider", "DriverVersion", "ReleaseDate", "DriverAge")
Write-Host ""

# Print GPU Specific Details
foreach ($gpu in $activeGPUs) {
    Write-Host "  GPU Device: " -NoNewline -ForegroundColor White
    Write-Host $gpu.Name -ForegroundColor Cyan
    Write-Host "    +- Active Driver Ver: " -NoNewline -ForegroundColor DarkGray
    Write-Host $gpu.DriverVersion -ForegroundColor White
    Write-Host "    +- Release Date:     " -NoNewline -ForegroundColor DarkGray
    Write-Host $gpu.DriverDate -ForegroundColor White
    Write-Host "    +- Provider:          " -NoNewline -ForegroundColor DarkGray
    if ($gpu.Provider -match "Microsoft") {
        Write-Host $gpu.Provider -ForegroundColor Yellow -NoNewline
        Write-Host " (Warning: Generic/Basic Windows driver)" -ForegroundColor Yellow
    } else {
        Write-Host $gpu.Provider -ForegroundColor White
    }
    Write-Host "    +- INF File Name:     " -NoNewline -ForegroundColor DarkGray
    Write-Host $gpu.InfName -ForegroundColor White
    Write-Host "    +- Digital Signer:    " -NoNewline -ForegroundColor DarkGray
    Write-Host $gpu.Signer -ForegroundColor White
    Write-Host "    +- Status:            " -NoNewline -ForegroundColor DarkGray
    if ($gpu.Status -eq "OK") {
        Write-Host $gpu.Status -ForegroundColor Green
    } else {
        Write-Host $gpu.Status -ForegroundColor Red
    }
    Write-Host ""
}

# ---------------------------------------------------------
# STEP 2: Enumerate Staged Drivers in Driver Store
# ---------------------------------------------------------
Write-Log "Scanning Windows Driver Store for display driver packages..." -Type Header

$stagedDisplayDrivers = [System.Collections.Generic.List[PSObject]]::new()
$pnpDriversRaw = pnputil /enum-drivers /format csv 2>$null

if ($pnpDriversRaw) {
    $pnpDrivers = $pnpDriversRaw | ConvertFrom-Csv
    $displayDrivers = $pnpDrivers | Where-Object { 
        $_.ClassGuid -eq '{4d36e968-e325-11ce-bfc1-08002be10318}' -or $_.ClassName -eq 'Display'
    }

    foreach ($drv in $displayDrivers) {
        $date = "Unknown"
        $version = "Unknown"
        if ($drv.DriverVersion -match '^([^\s]+)\s+(.+)$') {
            $rawDate = $Matches[1]
            $version = $Matches[2]
            if ($rawDate -match '^(\d{2})/(\d{2})/(\d{4})$') {
                $date = "$($Matches[3])-$($Matches[1])-$($Matches[2])"
            } else {
                $date = $rawDate
            }
        } else {
            $version = $drv.DriverVersion
        }

        $isActive = "NO"
        foreach ($gpu in $activeGPUs) {
            if ($gpu.InfName -eq $drv.DriverName) {
                $isActive = "YES"
                break
            }
            if ($gpu.InfName -eq "Unknown" -and $gpu.DriverVersion -eq $version -and $gpu.Provider -match $drv.ProviderName) {
                $isActive = "YES"
                break
            }
        }

        $stagedDisplayDrivers.Add([PSCustomObject]@{
            "InfFile"      = $drv.DriverName
            "OriginalName" = $drv.OriginalName
            "Provider"     = $drv.ProviderName
            "Version"      = $version
            "ReleaseDate"  = $date
            "Active"       = $isActive
        })
    }
}

Format-CustomTable -Data $stagedDisplayDrivers -Columns @("InfFile", "OriginalName", "Provider", "Version", "ReleaseDate", "Active")
Write-Host ""

# ---------------------------------------------------------
# STEP 3: Inspect Windows Update Settings & Event Log Health
# ---------------------------------------------------------
Write-Log "Checking Windows Update policies, TDR settings & scanning System Health..." -Type Header

# Check SearchOrderConfig
$searchOrderConfig = $null
$searchOrderPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"
if (Test-Path $searchOrderPath) {
    $searchOrderConfig = (Get-ItemProperty -Path $searchOrderPath -Name "SearchOrderConfig" -ErrorAction SilentlyContinue).SearchOrderConfig
}

# Check ExcludeWUDriversInQualityUpdate
$excludeWUDrivers = $null
$wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if (Test-Path $wuPolicyPath) {
    $excludeWUDrivers = (Get-ItemProperty -Path $wuPolicyPath -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue).ExcludeWUDriversInQualityUpdate
}

# Check GraphicsDrivers TdrDelay / TdrDdiDelay
$tdrDelay = $null
$tdrDdiDelay = $null
$gfxPath = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
if (Test-Path $gfxPath) {
    $tdrProps = Get-ItemProperty -Path $gfxPath -ErrorAction SilentlyContinue
    if ($tdrProps.PSObject.Properties['TdrDelay']) { $tdrDelay = $tdrProps.TdrDelay }
    if ($tdrProps.PSObject.Properties['TdrDdiDelay']) { $tdrDdiDelay = $tdrProps.TdrDdiDelay }
}

Write-Host "  1. Driver Searching Setting (SearchOrderConfig):" -ForegroundColor White
if ($null -eq $searchOrderConfig) {
    Write-Log "Setting is missing/Default (Windows determines driver searches)." -Type Info
} elseif ($searchOrderConfig -eq 0) {
    Write-Log "Disabled (0) - Windows Update will NOT search for drivers." -Type Info
} else {
    Write-Log "Enabled ($searchOrderConfig) - Windows Update searches for drivers automatically." -Type Info
}

Write-Host "  2. Driver Exclusion Policy (ExcludeWUDriversInQualityUpdate):" -ForegroundColor White
if ($null -eq $excludeWUDrivers) {
    Write-Log "Policy is not set (Drivers are included in Windows updates)." -Type Info
} elseif ($excludeWUDrivers -eq 1) {
    Write-Log "Enabled (1) - Drivers are excluded from Quality Updates." -Type Info
} else {
    Write-Log "Disabled (0) - Drivers are included in Quality Updates." -Type Info
}

Write-Host "  3. Windows GPU Timeout Setting (TdrDelay):" -ForegroundColor White
if ($null -eq $tdrDelay) {
    Write-Log "Default (2 seconds) - Normal Windows soft-recovery behavior." -Type Success
} else {
    Write-Log "Custom TdrDelay = $tdrDelay sec (Warning: High TdrDelay can turn soft TDR resets into 8-second black screen reboots)." -Type Warning
}

# Scan System Log for GPU TDR events and Kernel-Power reboots in past 7 days
$tdrEventsCount = 0
$rebootEventsCount = 0
$netDisconnectCount = 0
try {
    $startDate = (Get-Date).AddDays(-7)
    $sysLog = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$startDate} -ErrorAction SilentlyContinue
    if ($sysLog) {
        foreach ($evt in $sysLog) {
            if ($evt.ProviderName -match 'e2fnexpress|e1dexpress|rt640x64|Netwtw' -and ($evt.Id -eq 27 -or $evt.Message -match 'disconnected')) {
                $netDisconnectCount++
            }
            if ($evt.ProviderName -match 'amdkmdag|Display|Graphics' -or $evt.Id -eq 4101 -or $evt.Message -match 'LiveKernelEvent') {
                $tdrEventsCount++
            }
            if ($evt.Id -eq 41 -and $evt.ProviderName -match 'Kernel-Power') {
                $rebootEventsCount++
            }
        }
    }
} catch {}

if ($netDisconnectCount -gt 0) {
    Write-Log "Detected $netDisconnectCount Network Adapter link disconnection event(s) in past 7 days." -Type Warning
} else {
    Write-Log "No recent network adapter disconnect events in System Log." -Type Success
}

if ($tdrEventsCount -gt 0) {
    Write-Log "Detected $tdrEventsCount GPU Driver TDR reset / timeout event(s) in past 7 days." -Type Warning
}

if ($rebootEventsCount -gt 0) {
    Write-Log "Detected $rebootEventsCount Kernel-Power unexpected reboot event(s) (Event 41) in past 7 days." -Type Warning
}
Write-Host ""

# ---------------------------------------------------------
# STEP 4: Scan for Recent Steam, App & Game Crash Dumps
# ---------------------------------------------------------
Write-Log "Scanning system for recent Steam & Game crash minidumps..." -Type Header

$recentDumps = [System.Collections.Generic.List[PSObject]]::new()
$dumpSearchPaths = @(
    "C:\Program Files (x86)\Steam\dumps",
    "$env:LOCALAPPDATA\CrashDumps",
    "$env:LOCALAPPDATA\Pearl Abyss\DumpCache",
    "$env:LOCALAPPDATA\BeamNG.drive"
)

$cutoff7Days = (Get-Date).AddDays(-7)
foreach ($path in $dumpSearchPaths) {
    if (Test-Path $path) {
        $files = Get-ChildItem -Path $path -Recurse -Include "*.dmp", "*.wer", "__sentry-event" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoff7Days }
        foreach ($f in $files) {
            $sizeMb = [math]::Round($f.Length / 1MB, 2)
            $recentDumps.Add([PSCustomObject]@{
                FileName     = $f.Name
                LastModified = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                SizeMB       = $sizeMb
                Location     = $f.DirectoryName
            })
        }
    }
}

if ($recentDumps.Count -gt 0) {
    Write-Log "Found $($recentDumps.Count) recent crash dump file(s) in the past 7 days:" -Type Warning
    Format-CustomTable -Data $recentDumps -Columns @("FileName", "LastModified", "SizeMB", "Location")
} else {
    Write-Log "No recent crash dump files found in Steam or AppData locations." -Type Success
}
Write-Host ""

# ---------------------------------------------------------
# STEP 5: Diagnosis & Recommendations
# ---------------------------------------------------------
Write-Log "Analyzing System Driver Health & Generating Recommendations..." -Type Header

$hasActiveDriverIssue = $false
$mismatchedGPUs = [System.Collections.Generic.List[PSObject]]::new()
$issuesList = [System.Collections.Generic.List[string]]::new()
$fixesList = [System.Collections.Generic.List[string]]::new()

# Check GPU Microsoft Basic Display Adapter
foreach ($gpu in $activeGPUs) {
    if ($gpu.Provider -match "Microsoft") {
        $hasActiveDriverIssue = $true
    }
}

# Check GPU Staged Downgrades
foreach ($gpu in $activeGPUs) {
    $gpuVer = Get-SafeVersion -versionStr $gpu.DriverVersion
    if ($null -ne $gpuVer) {
        $devId = $null
        if ($gpu.PNPDeviceID -match 'DEV_([0-9A-Fa-f]{4})') {
            $devId = $Matches[1]
        }

        $sameProviderDrivers = $stagedDisplayDrivers | Where-Object { 
            (($_.Provider -match $gpu.Provider) -or ($gpu.Provider -match $_.Provider)) -and
            ($null -eq $devId -or (Select-String -Path "$env:SystemRoot\INF\$($_.InfFile)" -Pattern "DEV_$devId" -Quiet))
        }
        
        $newerStaged = $null
        foreach ($spd in $sameProviderDrivers) {
            $spdVer = Get-SafeVersion -versionStr $spd.Version
            if ($null -ne $spdVer -and $spdVer -gt $gpuVer) {
                $currNewerVer = $null
                if ($newerStaged) {
                    $currNewerVer = Get-SafeVersion -versionStr $newerStaged.Version
                }
                if ($null -eq $newerStaged -or ($currNewerVer -and $spdVer -gt $currNewerVer)) {
                    $newerStaged = $spd
                }
            }
        }
        
        if ($null -ne $newerStaged) {
            $hasActiveDriverIssue = $true
            $mismatchedGPUs.Add([PSCustomObject]@{
                GPUName        = $gpu.Name
                CurrentVersion = $gpu.DriverVersion
                NewerVersion   = $newerStaged.Version
                ReleaseDate    = $newerStaged.ReleaseDate
                InfFile        = $newerStaged.InfFile
            })
        }
    }
}

if ($hasActiveDriverIssue) {
    foreach ($gpu in $activeGPUs) {
        if ($gpu.Provider -match "Microsoft") {
            $issuesList.Add("GPU '$($gpu.Name)' is using generic Microsoft Basic Display Adapter. Performance degraded.")
            $extracted = Find-CompatibleExtractedDriver -pnpDeviceID $gpu.PNPDeviceID
            if ($null -ne $extracted) {
                $fixesList.Add("A compatible driver (ver $($extracted.Version)) was found extracted locally. Install via Device Manager: $($extracted.FolderPath)")
            } else {
                $fixesList.Add("Download and install manufacturer driver from AMD/NVIDIA/Intel.")
            }
        }
    }
    
    foreach ($mismatched in $mismatchedGPUs) {
        $issuesList.Add("For GPU '$($mismatched.GPUName)', newer staged driver ($($mismatched.NewerVersion)) exists, but older ($($mismatched.CurrentVersion)) is active.")
        $gpuObj = $activeGPUs | Where-Object { $_.Name -eq $mismatched.GPUName } | Select-Object -First 1
        $extracted = if ($gpuObj) { Find-CompatibleExtractedDriver -pnpDeviceID $gpuObj.PNPDeviceID } else { $null }
        if ($null -ne $extracted) {
            $fixesList.Add("Update '$($mismatched.GPUName)' to staged $($mismatched.NewerVersion) via Device Manager or run with -ApplyFix.")
        } else {
            $fixesList.Add("Update '$($mismatched.GPUName)' to staged driver $($mismatched.NewerVersion) with -ApplyFix.")
        }
    }

    if ($searchOrderConfig -ne 0 -or $excludeWUDrivers -ne 1) {
        $issuesList.Add("Windows Update driver searching is enabled, causing driver overwrites.")
        $fixesList.Add("Disable automatic Windows Update driver search/installation.")
    }
}

# TDR Delay Warning
if ($null -ne $tdrDelay -and $tdrDelay -gt 2) {
    $issuesList.Add("Custom TdrDelay = $tdrDelay seconds is active. High TdrDelay holds GPU hangs for $tdrDelay s, causing 8-second black screens and triggering full system reboots.")
    $fixesList.Add("Remove custom TdrDelay and TdrDdiDelay registry keys to restore 2-second soft recovery mode.")
}

# Network Adapter Issue Diagnostics
if ($netDisconnectCount -gt 0) {
    $issuesList.Add("Detected $netDisconnectCount Ethernet link disconnection event(s) in system logs (Intel I225-V / e2fnexpress).")
    $fixesList.Add("Disable 'Allow computer to turn off this device to save power' & 'Energy Efficient Ethernet (EEE)' in Device Manager for Intel I225-V.")
}

# Display Recommendations
if ($issuesList.Count -gt 0) {
    Write-Log "Issues / Warnings Detected:" -Type Warning
    foreach ($issue in $issuesList) {
        Write-Host "  [!] $issue" -ForegroundColor Yellow
    }
    Write-Host ""
    
    Write-Log "Recommendations & Action Items:" -Type Info
    foreach ($fix in $fixesList) {
        Write-Host "  * $fix" -ForegroundColor White
    }
    Write-Host ""
    if (-not $ApplyFix -and ($hasActiveDriverIssue -or ($null -ne $tdrDelay -and $tdrDelay -gt 2))) {
        Write-Host "  To apply driver/registry fixes automatically, run as Administrator with:" -ForegroundColor Gray
        Write-Host "    Powershell.exe -ExecutionPolicy Bypass -File .\Get-GPUDriverDiagnostics.ps1 -ApplyFix" -ForegroundColor Cyan
    }
} else {
    Write-Log "No active GPU driver downgrades or critical system driver failures were detected." -Type Success
    Write-Log "Active drivers match staged packages and Windows Update driver block policy is active." -Type Info
}
Write-Host ""

# ---------------------------------------------------------
# STEP 6: Apply Fixes (If requested)
# ---------------------------------------------------------
if ($ApplyFix) {
    Write-Log "Switch '-ApplyFix' specified. Processing modifications..." -Type Header
    
    if (-not $isAdmin) {
        Write-Log "Administrator elevation is required to modify policies or install drivers." -Type Error
        exit 1
    }

    # Fix 1: Revert custom TdrDelay
    if ($null -ne $tdrDelay -and $tdrDelay -gt 2) {
        Write-Host ""
        Write-Log "Remove custom TdrDelay = $tdrDelay registry keys to restore 2-second soft recovery mode:" -Type Info
        $confirmTdr = Read-Host "Remove custom TdrDelay and TdrDdiDelay registry keys? (y/n)"
        if ($confirmTdr -eq "y" -or $confirmTdr -eq "yes") {
            try {
                Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDelay", "TdrDdiDelay" -ErrorAction SilentlyContinue
                Write-Log "Removed custom TdrDelay and TdrDdiDelay registry keys successfully." -Type Success
            } catch {
                Write-Log "Failed to remove TdrDelay registry keys: $_" -Type Error
            }
        }
    }

    # Fix 2: Update Mismatched Drivers
    if ($mismatchedGPUs.Count -gt 0) {
        foreach ($mismatched in $mismatchedGPUs) {
            Write-Host ""
            Write-Log "DETECTED DOWNGRADE: GPU '$($mismatched.GPUName)' active $($mismatched.CurrentVersion), staged $($mismatched.NewerVersion)." -Type Warning
            $confirm = Read-Host "Reinstall/force-update this device to its staged driver? (y/n)"
            if ($confirm -eq "y" -or $confirm -eq "yes") {
                Write-Log "Updating driver using pnputil..." -Type Info
                $infPath = Join-Path $env:SystemRoot "INF\$($mismatched.InfFile)"
                $res = pnputil /add-driver $infPath /install 2>&1
                Write-Host $res
                Write-Log "Driver installation completed." -Type Success
            }
        }
    }

    # Fix 3: Windows Update Block Registry Policy
    if ($searchOrderConfig -ne 0 -or $excludeWUDrivers -ne 1) {
        Write-Host ""
        Write-Log "Prevent Windows Update from replacing display drivers:" -Type Info
        $confirmReg = Read-Host "Apply registry changes to block Windows Update driver search? (y/n)"
        if ($confirmReg -eq "y" -or $confirmReg -eq "yes") {
            try {
                $dsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"
                if (-not (Test-Path $dsPath)) { New-Item -Path $dsPath -Force | Out-Null }
                Set-ItemProperty -Path $dsPath -Name "SearchOrderConfig" -Value 0 -Type DWord -Force
                Write-Log "Set SearchOrderConfig = 0" -Type Success

                $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                if (-not (Test-Path $wuPath)) { New-Item -Path $wuPath -Force | Out-Null }
                Set-ItemProperty -Path $wuPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord -Force
                Write-Log "Set ExcludeWUDriversInQualityUpdate = 1" -Type Success
            } catch {
                Write-Log "Failed to apply registry changes: $_" -Type Error
            }
        }
    }
}
Write-Host ""
