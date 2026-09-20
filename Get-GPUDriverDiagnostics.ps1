<#
.SYNOPSIS
    GPU Driver Diagnostic & Downgrade Prevention Tool
.DESCRIPTION
    Checks active display devices and their currently loaded driver versions/providers.
    Queries the Windows Driver Store via pnputil for staged display drivers.
    Checks registry keys related to Windows Update driver searches.
    Detects potential downgrade conflicts (e.g. from Windows Update).
    Optionally applies fixes (reinstalling staged drivers or disabling update overwrites) if problems exist.
.PARAMETER ApplyFix
    Switch parameter to apply fixes (installing driver or registry settings) if issues are detected.
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

# Display Title Card using ASCII
Write-Host ""
Write-Host "  +------------------------------------------------------------------------+" -ForegroundColor Magenta
Write-Host "  |             GPU Driver Diagnostics & Downgrade Prevention              |" -ForegroundColor Magenta
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
# STEP 1: Query Active Graphics Controllers
# ---------------------------------------------------------
Write-Log "Querying active GPU Hardware and loaded drivers..." -Type Header

$videoControllers = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
$signedDrivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DeviceClass -eq 'DISPLAY' }

$activeGPUs = [System.Collections.Generic.List[PSObject]]::new()

foreach ($vc in $videoControllers) {
    # Match the video controller to its signed driver properties
    $sd = $signedDrivers | Where-Object { $_.DeviceID -eq $vc.PNPDeviceID }
    if ($null -eq $sd) {
        # Fallback match by Name
        $sd = $signedDrivers | Where-Object { $_.DeviceName -eq $vc.Name }
    }

    # Extract version details
    $driverVersion = $vc.DriverVersion
    if ($sd -and $sd.DriverVersion) {
        $driverVersion = $sd.DriverVersion
    }

    $driverDate = $vc.DriverDate
    if ($sd -and $sd.DriverDate) {
        $driverDate = $sd.DriverDate
    }

    $provider = "Unknown"
    if ($sd -and $sd.DriverProviderName) {
        $provider = $sd.DriverProviderName
    }

    $infName = "Unknown"
    if ($sd -and $sd.InfName) {
        $infName = $sd.InfName
    }

    $signer = "Unknown"
    if ($sd -and $sd.Signer) {
        $signer = $sd.Signer
    }

    # Parse Driver Date
    $formattedDate = "Unknown"
    if ($driverDate) {
        if ($driverDate -is [DateTime]) {
            $formattedDate = $driverDate.ToString("yyyy-MM-dd")
        } else {
            # Sometimes date comes back as CIM datetime string: yyyymmdd......
            if ($driverDate -match '^(\d{4})(\d{2})(\d{2})') {
                $formattedDate = "$($Matches[1])-$($Matches[2])-$($Matches[3])"
            } else {
                $formattedDate = $driverDate.ToString()
            }
        }
    }

    $gpuObj = [PSCustomObject]@{
        Name          = $vc.Name
        Status        = $vc.Status
        PNPDeviceID   = $vc.PNPDeviceID
        DriverVersion = $driverVersion
        DriverDate    = $formattedDate
        Provider      = $provider
        InfName       = $infName
        Signer        = $signer
    }
    $activeGPUs.Add($gpuObj)
}

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

# Run pnputil to fetch staged drivers
$stagedDisplayDrivers = [System.Collections.Generic.List[PSObject]]::new()
$pnpDriversRaw = pnputil /enum-drivers /format csv 2>$null

if ($pnpDriversRaw) {
    $pnpDrivers = $pnpDriversRaw | ConvertFrom-Csv
    
    # Filter for Display Class Guid: {4d36e968-e325-11ce-bfc1-08002be10318} or ClassName 'Display'
    $displayDrivers = $pnpDrivers | Where-Object { 
        $_.ClassGuid -eq '{4d36e968-e325-11ce-bfc1-08002be10318}' -or
        $_.ClassName -eq 'Display'
    }

    foreach ($drv in $displayDrivers) {
        # Parse driver version and date from the field
        # e.g. "06/28/2026 32.0.31021.5001"
        $date = "Unknown"
        $version = "Unknown"
        if ($drv.DriverVersion -match '^([^\s]+)\s+(.+)$') {
            # Convert MM/DD/YYYY to YYYY-MM-DD for standard presentation
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

        # Check if this staged driver is currently active on any GPU
        $isActive = "NO"
        foreach ($gpu in $activeGPUs) {
            if ($gpu.InfName -eq $drv.DriverName) {
                $isActive = "YES"
                break
            }
            # Fallback if WMI's InfName is missing/empty: match by version and provider
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
                $color = "Red" # AMD
            } elseif ($col -eq "Provider" -and $val -match "NVIDIA") {
                $color = "Green" # NVIDIA (using standard green)
            } elseif ($col -eq "Provider" -and $val -match "Intel") {
                $color = "Blue" # Intel (blue)
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

Format-CustomTable -Data $stagedDisplayDrivers -Columns @("InfFile", "OriginalName", "Provider", "Version", "ReleaseDate", "Active")
Write-Host ""

# ---------------------------------------------------------
# STEP 3: Inspect Windows Update Settings
# ---------------------------------------------------------
Write-Log "Checking Windows Update & Driver Search policies..." -Type Header

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

# Display status
Write-Host "  1. Driver Searching Setting (SearchOrderConfig):" -ForegroundColor White
if ($null -eq $searchOrderConfig) {
    Write-Log "Setting is missing/Default (Windows determines driver searches)." -Type Info
} elseif ($searchOrderConfig -eq 0) {
    Write-Log "Disabled (0) - Windows Update will NOT search for drivers." -Type Info
} elseif ($searchOrderConfig -eq 1) {
    Write-Log "Enabled (1) - Windows Update searches for drivers automatically." -Type Info
} else {
    Write-Log "Custom ($searchOrderConfig) - Windows Update is configured to search." -Type Info
}

Write-Host "  2. Driver Exclusion Policy (ExcludeWUDriversInQualityUpdate):" -ForegroundColor White
if ($null -eq $excludeWUDrivers) {
    Write-Log "Policy is not set (Drivers are included in Windows updates)." -Type Info
} elseif ($excludeWUDrivers -eq 1) {
    Write-Log "Enabled (1) - Drivers are excluded from Quality Updates." -Type Info
} else {
    Write-Log "Disabled (0) - Drivers are included in Quality Updates." -Type Info
}
Write-Host ""

# ---------------------------------------------------------
# STEP 4: Diagnosis & Recommendations
# ---------------------------------------------------------
Write-Log "Analyzing Driver Health & Generating Recommendations..." -Type Header

$hasActiveDriverIssue = $false
$mismatchedGPUs = [System.Collections.Generic.List[PSObject]]::new()

# Check for Microsoft Basic Display Adapter
foreach ($gpu in $activeGPUs) {
    if ($gpu.Provider -match "Microsoft") {
        $hasActiveDriverIssue = $true
    }
}

# Check for staged newer versions than active versions
foreach ($gpu in $activeGPUs) {
    $gpuVer = Get-SafeVersion -versionStr $gpu.DriverVersion
    if ($null -ne $gpuVer) {
        # Find drivers from same provider in the staged list that support this device ID
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

$issuesList = [System.Collections.Generic.List[string]]::new()
$fixesList = [System.Collections.Generic.List[string]]::new()

if ($hasActiveDriverIssue) {
    # Flag the actual driver issues
    foreach ($gpu in $activeGPUs) {
        if ($gpu.Provider -match "Microsoft") {
            $issuesList.Add("GPU '$($gpu.Name)' is currently using the generic Microsoft Basic Display Adapter driver. Performance is heavily degraded.")
            # Check for extracted driver in C:\AMD
            $extracted = Find-CompatibleExtractedDriver -pnpDeviceID $gpu.PNPDeviceID
            if ($null -ne $extracted) {
                $fixesList.Add("A compatible driver (version $($extracted.Version)) was found extracted locally. Manually install it via Device Manager by pointing it to: $($extracted.FolderPath)")
            } else {
                $fixesList.Add("Download and install the official manufacturer driver from AMD, NVIDIA, or Intel websites.")
            }
        }
    }
    
    foreach ($mismatched in $mismatchedGPUs) {
        $issuesList.Add("For GPU '$($mismatched.GPUName)', a newer driver version ($($mismatched.NewerVersion) dated $($mismatched.ReleaseDate) in $($mismatched.InfFile)) is staged in your system store, but the older version ($($mismatched.CurrentVersion)) is active. This indicates a driver downgrade has occurred.")
        # Check for extracted driver in C:\AMD
        $gpuObj = $activeGPUs | Where-Object { $_.Name -eq $mismatched.GPUName } | Select-Object -First 1
        $extracted = $null
        if ($gpuObj) {
            $extracted = Find-CompatibleExtractedDriver -pnpDeviceID $gpuObj.PNPDeviceID
        }
        
        if ($null -ne $extracted) {
            $fixesList.Add("Update GPU '$($mismatched.GPUName)' to its staged version $($mismatched.NewerVersion) via Device Manager (point to the extracted files at: $($extracted.FolderPath)) or by running this script with the -ApplyFix switch.")
        } else {
            $fixesList.Add("Update GPU '$($mismatched.GPUName)' to its staged driver version $($mismatched.NewerVersion) using Device Manager or by running this script with the -ApplyFix switch.")
        }
    }
    
    # Since there is an active problem, check if Windows Update configuration is a contributing factor
    if ($searchOrderConfig -ne 0 -or $excludeWUDrivers -ne 1) {
        $issuesList.Add("Windows Update is allowed to query and install driver updates, which is the root cause of these driver downgrades/overwrites.")
        $fixesList.Add("Disable automatic Windows Update driver search/installation to prevent this downgrade from recurring.")
    }
}

# Display Recommendations
if ($issuesList.Count -gt 0) {
    Write-Log "Issues Detected:" -Type Warning
    foreach ($issue in $issuesList) {
        Write-Host "  [!] $issue" -ForegroundColor Yellow
    }
    Write-Host ""
    
    Write-Log "Recommendations & Action Items:" -Type Info
    foreach ($fix in $fixesList) {
        Write-Host "  * $fix" -ForegroundColor White
    }
    
    Write-Host ""
    if (-not $ApplyFix) {
        Write-Host "  To apply fixes (such as updating driver to staged version or disabling driver updates), run as Administrator with:" -ForegroundColor Gray
        Write-Host "    Powershell.exe -ExecutionPolicy Bypass -File .\Get-GPUDriverDiagnostics.ps1 -ApplyFix" -ForegroundColor Cyan
    }
} else {
    Write-Log "No active GPU driver problems (such as generic adapters or downgrades) were detected on this system." -Type Success
    Write-Log "Your active drivers match or exceed all staged drivers in the store. No modifications are needed." -Type Info
}
Write-Host ""

# ---------------------------------------------------------
# STEP 5: Apply Fixes (If requested)
# ---------------------------------------------------------
if ($ApplyFix) {
    Write-Log "Switch '-ApplyFix' specified. Processing modifications..." -Type Header
    
    if (-not $isAdmin) {
        Write-Log "Administrator elevation is required to modify registry policies or install drivers. Please run PowerShell as Administrator." -Type Error
        exit 1
    }

    if (-not $hasActiveDriverIssue) {
        Write-Log "No active GPU driver problems (downgrades or generic adapters) were detected. No fixes need to be applied." -Type Success
        return
    }

    # 1. Direct Driver Update Fix
    if ($mismatchedGPUs.Count -gt 0) {
        foreach ($mismatched in $mismatchedGPUs) {
            Write-Host ""
            Write-Log "DETECTED DOWNGRADE: GPU '$($mismatched.GPUName)' is active on $($mismatched.CurrentVersion) but version $($mismatched.NewerVersion) is staged." -Type Warning
            Write-Host "  Proposed Action: Force reinstall/update the GPU to the newer staged driver: $($mismatched.InfFile) ($($mismatched.NewerVersion))" -ForegroundColor Cyan
            
            $confirm = Read-Host "Are you sure you want to reinstall/force-update this device to its staged driver? (y/n)"
            if ($confirm -eq "y" -or $confirm -eq "yes") {
                Write-Log "Updating driver using pnputil..." -Type Info
                $infPath = Join-Path $env:SystemRoot "INF\$($mismatched.InfFile)"
                
                # Run pnputil to install the driver
                $res = pnputil /add-driver $infPath /install 2>&1
                Write-Host $res
                Write-Log "Driver installation command completed." -Type Success
            } else {
                Write-Log "Skipped driver reinstallation for '$($mismatched.GPUName)'." -Type Info
            }
        }
    }

    # 2. Windows Update Block Fix
    if ($searchOrderConfig -ne 0 -or $excludeWUDrivers -ne 1) {
        Write-Host ""
        Write-Log "PREVENTATIVE ACTION: Prevent Windows Update from automatically replacing display drivers." -Type Info
        Write-Host "Proposed Registry Changes:" -ForegroundColor Cyan
        if ($searchOrderConfig -ne 0) {
            Write-Host "  - Set SearchOrderConfig to 0 in HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -ForegroundColor White
        }
        if ($excludeWUDrivers -ne 1) {
            Write-Host "  - Set ExcludeWUDriversInQualityUpdate to 1 in HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ForegroundColor White
        }
        Write-Host ""
        
        Write-Log "Note: You only need to apply this fix if Windows Update keeps repeatedly downgrading your driver." -Type Info
        $confirmReg = Read-Host "Do you want to apply these registry changes to block Windows Update driver search? (y/n)"
        if ($confirmReg -eq "y" -or $confirmReg -eq "yes") {
            try {
                # Update DriverSearching
                $dsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"
                if (-not (Test-Path $dsPath)) {
                    New-Item -Path $dsPath -Force | Out-Null
                }
                Set-ItemProperty -Path $dsPath -Name "SearchOrderConfig" -Value 0 -Type DWord -Force
                Write-Log "Set SearchOrderConfig = 0 (Driver searching disabled via WU)" -Type Success

                # Update WindowsUpdate Policy
                $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                if (-not (Test-Path $wuPath)) {
                    New-Item -Path $wuPath -Force | Out-Null
                }
                Set-ItemProperty -Path $wuPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord -Force
                Write-Log "Set ExcludeWUDriversInQualityUpdate = 1 (Drivers excluded from updates)" -Type Success

                Write-Log "Registry optimizations applied successfully! Please restart to apply policies fully." -Type Success
            }
            catch {
                Write-Log "Failed to apply registry changes. Error: $_" -Type Error
            }
        } else {
            Write-Log "Skipped registry modifications. No registry changes were made." -Type Info
        }
    }
}
Write-Host ""
