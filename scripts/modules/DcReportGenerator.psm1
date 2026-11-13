<#
.SYNOPSIS
    DriverCheck - HTML & Diagnostic Bundle Report Generator Module
.DESCRIPTION
    Generates high-fidelity, self-contained, dark-mode HTML reports and support bundle ZIPs
    for sharing on technical forums, Discord, or developer support tickets.
#>

function Export-DcHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ReportData,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath
    )

    if (-not $OutputPath) {
        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $OutputPath = Join-Path $PWD "CrashReport_$timestamp.html"
    }

    $statusClass = if ($ReportData.RootCauseSeverity -eq "Critical") { "badge-critical" } elseif ($ReportData.RootCauseSeverity -eq "Warning") { "badge-warning" } else { "badge-healthy" }
    $statusText = if ($ReportData.RootCauseSeverity -eq "Critical") { "CRITICAL ISSUES DETECTED" } elseif ($ReportData.RootCauseSeverity -eq "Warning") { "POTENTIAL ISSUES FOUND" } else { "SYSTEM HEALTHY" }
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }

    # Build Dump HTML
    $dumpRows = [System.Collections.Generic.List[string]]::new()
    if ($ReportData.Dumps.Count -gt 0) {
        foreach ($d in $ReportData.Dumps) {
            $excBadge = if ($d.ExceptionCode) { "<span class='badge-code'>" + (& $enc $d.ExceptionCode) + "</span>" } else { "<span class='badge-neutral'>N/A</span>" }
            $modBadge = if ($d.FaultingIP) { "<span class='badge-module'>" + (& $enc $d.FaultingIP) + "</span>" } else { "<span class='badge-neutral'>Unknown</span>" }
            $assertHtml = ""
            if ($d.Assertions.Count -gt 0) {
                $assertHtml = "<div class='assert-box'>" + (($d.Assertions | ForEach-Object { "<div><code>" + (& $enc $_) + "</code></div>" }) -join "") + "</div>"
            }

            $drvBadgeHtml = if ($d.GpuDriverVersion) { "<div><strong>Loaded GPU Driver:</strong> <span class='badge-module'>v" + (& $enc $d.GpuDriverVersion) + "</span></div>" } else { "" }
            $apiContextHtml = if ($d.ApiContext) { "<div><strong>Graphics API Stage:</strong> <span class='badge-module' style='background: rgba(192, 132, 252, 0.2); color: var(--magenta);'>" + (& $enc $d.ApiContext) + "</span></div>" } else { "" }
            $stackHtml = ""
            if ($d.CallStack -and $d.CallStack.Count -gt 0) {
                $stackLines = ($d.CallStack | Select-Object -First 15 | ForEach-Object { & $enc $_ }) -join "<br>"
                $stackHtml = "<details style='margin-top: 8px;'><summary style='cursor: pointer; color: var(--cyan); font-size: 0.85rem;'>Call Stack ($($d.CallStack.Count) frames)</summary><div class='code-block' style='font-size: 0.8rem; max-height: 200px; overflow-y: auto;'>$stackLines</div></details>"
            }

            $card = "<div class='card-item'>" +
                "<div class='card-header-row'>" +
                    "<span class='file-name'>" + (& $enc $d.FileName) + "</span>" +
                    "<span class='timestamp'>$($d.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')) | $($d.SizeMb) MB | " + (& $enc $d.Architecture) + "</span>" +
                "</div>" +
                "<div class='card-body-row'>" +
                    "<div><strong>Exception:</strong> $excBadge " + (& $enc $d.ExceptionMeaning) + "</div>" +
                    "<div><strong>Faulting Module:</strong> $modBadge</div>" +
                    $apiContextHtml +
                    $drvBadgeHtml +
                    $assertHtml +
                    $stackHtml +
                "</div>" +
            "</div>"
            $dumpRows.Add($card)
        }
    } else {
        $dumpRows.Add("<div class='empty-state'>No crash dump files recorded in monitored directories within the scan window.</div>")
    }

    # Build Engine Logs HTML
    $logRows = [System.Collections.Generic.List[string]]::new()
    if ($ReportData.EngineLogs.Count -gt 0 -or $ReportData.SteamLogs.Count -gt 0) {
        foreach ($el in $ReportData.EngineLogs) {
            $errSnippet = ($el.ErrorLines | Select-Object -First 5 | ForEach-Object { "<div><code>" + (& $enc $_) + "</code></div>" }) -join ""
            $card = "<div class='card-item'>" +
                "<div class='card-header-row'>" +
                    "<span class='file-name'>[" + (& $enc $el.Engine) + "] " + (& $enc $el.LogName) + "</span>" +
                    "<span class='timestamp'>$($el.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</span>" +
                "</div>" +
                "<div class='code-block'>$errSnippet</div>" +
            "</div>"
            $logRows.Add($card)
        }
        foreach ($sl in $ReportData.SteamLogs) {
            $errSnippet = ($sl.ErrorLines | Select-Object -First 5 | ForEach-Object { "<div><code>" + (& $enc $_) + "</code></div>" }) -join ""
            $card = "<div class='card-item'>" +
                "<div class='card-header-row'>" +
                    "<span class='file-name'>[Steam Telemetry] " + (& $enc $sl.LogName) + "</span>" +
                    "<span class='timestamp'>$($sl.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</span>" +
                "</div>" +
                "<div class='code-block'>$errSnippet</div>" +
            "</div>"
            $logRows.Add($card)
        }
    } else {
        $logRows.Add("<div class='empty-state'>No application or game engine log errors recorded in this timeframe.</div>")
    }

    # Build System Telemetry HTML
    $telemRows = [System.Collections.Generic.List[string]]::new()
    $telem = $ReportData.SystemTelemetry
    $hasTelemIssue = $false
    if ($telem) {
        if ($telem.FastStartup.FastStartupEnabled) {
            $hasTelemIssue = $true
            $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x26A1; Power Configuration:</strong> Windows Fast Startup is enabled (configuration state only).</div>")
        }
        if ($telem.PciePowerManagement -and $telem.PciePowerManagement.IsEnabled) {
            $hasTelemIssue = $true
            $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x26A1; PCIe Power Configuration:</strong> PCI Express Link State Power Management is <strong>ENABLED ($($telem.PciePowerManagement.ACSettingName))</strong> in plan '$($telem.PciePowerManagement.SchemeName)'.</div>")
        }
        if ($telem.GraphicsDriverSettings) {
            $gfx = $telem.GraphicsDriverSettings
            $tdrInfo = if ($gfx.TdrDelay) { "TdrDelay: $($gfx.TdrDelay)s" } else { "TdrDelay: Default (2s)" }
            $hagsInfo = "HAGS: $($gfx.HAGSStatus)"
            $mpoInfo = if ($gfx.PSObject.Properties['IsMpoDisabled'] -and $gfx.IsMpoDisabled) { "DWM MPO: Disabled (OverlayTestMode=5)" } else { "DWM MPO: Active (Default)" }
            $telemRows.Add("<div class='alert-card' style='background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3);'><strong>&#x1F3AE; Graphics Driver Subsystem:</strong> $hagsInfo | $tdrInfo | $mpoInfo</div>")
        }
        foreach ($pcie in $telem.PcieWheaErrors) {
            $hasTelemIssue = $true
            $telemRows.Add("<div class='alert-card alert-critical'><strong>&#x26A0; PCIe Bus / Riser Error (WHEA Event 17) [$($pcie.TimeCreated)]:</strong> PCI Express Root Port link error detected! Verify GPU PCIe slot seating, disable PCIe power management (ASPM), or bypass PCIe riser cables.</div>")
        }
        foreach ($whea in ($telem.WheaErrors | Where-Object { -not $_.IsPcieError })) {
            $hasTelemIssue = $true
            $telemRows.Add("<div class='alert-card alert-critical'><strong>&#x26A0; WHEA Hardware Error [$($whea.TimeCreated)]:</strong> $($whea.Message)</div>")
        }
        foreach ($mem in $telem.MemoryExhaustion) {
            $hasTelemIssue = $true
            $telemRows.Add("<div class='alert-card alert-critical'><strong>&#x1F4BE; Out-of-Memory / Commit Limit Exhaustion (Event 2004) [$($mem.TimeCreated)]:</strong> Windows diagnosed low virtual memory. Ensure Paging File (Pagefile) is enabled and set to System-Managed.</div>")
        }
        foreach ($tdr in $telem.TdrEvents) {
            $hasTelemIssue = $true
            $telemRows.Add("<div class='alert-card alert-critical'><strong>&#x1F5A5; GPU Display Driver TDR Reset [$($tdr.TimeCreated)]:</strong> $($tdr.Message)</div>")
        }
        if ($telem.PSObject.Properties['TdrWorkloads'] -and $telem.TdrWorkloads -and $telem.TdrWorkloads.Count -gt 0) {
            foreach ($tw in ($telem.TdrWorkloads | Select-Object -First 3)) {
                $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x2699; Pre-TDR GPU Compute / Benchmark Workload [$($tw.TimeCreated)]:</strong> $($tw.Message)</div>")
            }
        }
        if ($telem.PSObject.Properties['DisplayHotplugEvents'] -and $telem.DisplayHotplugEvents -and $telem.DisplayHotplugEvents.Count -gt 0) {
            foreach ($dhp in ($telem.DisplayHotplugEvents | Select-Object -First 3)) {
                $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x1F5A5; Display Hotplug / Surprise-Removal (Event 1010) [$($dhp.TimeCreated)]:</strong> $($dhp.Message)</div>")
            }
        }
        foreach ($bsod in $telem.KernelBugChecks) {
            $hasTelemIssue = $true
            $telemRows.Add("<div class='alert-card alert-critical'><strong>&#x1F480; Kernel BugCheck BSOD [$($bsod.TimeCreated)]:</strong> $($bsod.Code) - $($bsod.Meaning)</div>")
        }
        foreach ($reb in $telem.AbruptReboots) {
            $hasTelemIssue = $true
            $rebDetail = if ($reb.BugcheckCode -eq 0) { "Instant Power Cut / PSU Trip / Freeze (BugcheckCode: 0 - No BSOD dump recorded)" } else { "Dirty reboot following BugCheck 0x{0:X}" -f $reb.BugcheckCode }
            $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x1F50C; Kernel-Power Event 41 [$($reb.TimeCreated)]:</strong> $rebDetail</div>")
        }
        if ($telem.NetworkDrops -and $telem.NetworkDrops.Count -gt 0) {
            $hasTelemIssue = $true
            foreach ($nd in ($telem.NetworkDrops | Select-Object -First 5)) {
                $telemRows.Add("<div class='alert-card alert-critical'><strong>&#x1F310; Network Link Drop / NCSI Issue [$($nd.TimeCreated)]:</strong> $($nd.Message)</div>")
            }
        }
        if ($telem.PciDeviceResets -and $telem.PciDeviceResets.Count -gt 0) {
            $hasTelemIssue = $true
            foreach ($pr in ($telem.PciDeviceResets | Select-Object -First 3)) {
                $telemRows.Add("<div class='alert-card alert-critical'><strong>&#x26A1; PCI Bus Hardware Reset [$($pr.TimeCreated)]:</strong> $($pr.Message)</div>")
            }
        }
        if ($telem.UdpPortExhaustions -and $telem.UdpPortExhaustions.Count -gt 0) {
            $hasTelemIssue = $true
            foreach ($upe in ($telem.UdpPortExhaustions | Select-Object -First 3)) {
                $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x1F50C; UDP Dynamic Port Exhaustion (Event 4266) [$($upe.TimeCreated)]:</strong> $($upe.Message)</div>")
            }
        }
        if ($telem.WlanFailovers -and $telem.WlanFailovers.Count -gt 0) {
            $hasTelemIssue = $true
            foreach ($wf in ($telem.WlanFailovers | Select-Object -First 3)) {
                $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x1F4F6; WLAN AutoConfig Failover [$($wf.TimeCreated)]:</strong> $($wf.Message)</div>")
            }
        }
        if ($telem.SleepTransitions -and $telem.SleepTransitions.Count -gt 0) {
            foreach ($st in ($telem.SleepTransitions | Select-Object -First 3)) {
                $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x1F319; Sleep/Wake Transition [$($st.WakeTime)]:</strong> $($st.Message)</div>")
            }
        }
        if ($telem.CpuThrottlingEvents -and $telem.CpuThrottlingEvents.Count -gt 0) {
            $hasTelemIssue = $true
            foreach ($ct in ($telem.CpuThrottlingEvents | Select-Object -First 3)) {
                $telemRows.Add("<div class='alert-card alert-critical'><strong>&#x1F525; CPU Thermal / VRM Firmware Throttling (Event 37) [$($ct.TimeCreated)]:</strong> $($ct.Message)</div>")
            }
        }
        foreach ($us in $telem.UnexpectedShutdowns) {
            $hasTelemIssue = $true
            $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x1F50C; Unexpected Shutdown (Event 6008) [$($us.TimeCreated)]:</strong> Previous system shutdown was unexpected.</div>")
        }
    }
    if (-not $hasTelemIssue) {
        $telemRows.Add("<div class='empty-state'>&#x2705; No WHEA errors, GPU TDR resets, network drops, or hardware errors found in event telemetry.</div>")
    }

    # Build Hardware HTML
    $hw = $ReportData.HardwareHealth

    # Build Motherboard & Chipset HTML
    $mbRows = [System.Collections.Generic.List[string]]::new()
    if ($hw -and $hw.Motherboard) {
        $mb = $hw.Motherboard
        $mbBadge = if ($mb.IsHealthy) { "<span class='badge-healthy'>HEALTHY</span>" } else { "<span class='badge-warning'>ITEMS NOTED</span>" }
        $biosAgeNotice = if ($mb.BiosAgeYears) { " ($($mb.BiosAgeYears) yrs old)" } else { "" }
        $biosBadge = if ($mb.IsBiosOutdated) { "<span class='badge-warning'>AGING ($($mb.BiosAgeYears) YRS)</span>" } else { "<span class='badge-healthy'>OK</span>" }

        $missingHtml = ""
        if ($mb.MissingControllers.Count -gt 0) {
            $missingList = ($mb.MissingControllers | ForEach-Object { "<li>$_</li>" }) -join ""
            $missingHtml = "<div class='alert-card alert-warning' style='margin-top: 8px;'><strong>&#x26A0; Missing Platform Controllers:</strong><ul style='margin-left: 20px; margin-top: 4px;'>$missingList</ul></div>"
        }

        $mbCard = "<div class='card-item'>" +
            "<div class='card-header-row'>" +
                "<span class='file-name'>&#x1F4DF; $($mb.MotherboardManufacturer) $($mb.MotherboardProduct)</span>" +
                "$mbBadge" +
            "</div>" +
            "<div><strong>BIOS Version:</strong> $($mb.BiosVersion) (Released: $($mb.BiosReleaseDate)$biosAgeNotice) $biosBadge</div>" +
            "<div><strong>Platform & Chipset:</strong> $($mb.Summary)</div>" +
            $missingHtml +
        "</div>"
        $mbRows.Add($mbCard)
    }

    $gpuRows = [System.Collections.Generic.List[string]]::new()
    if ($hw -and $hw.Gpus) {
        foreach ($g in $hw.Gpus) {
            $gpuBadge = if ($g.IsGeneric) { "<span class='badge-critical'>GENERIC ADAPTER</span>" } else { "<span class='badge-healthy'>ACTIVE</span>" }
            $installInfo = if ($g.AmdInstallType) { "<br><span style='font-size: 0.8rem; color: var(--text-muted);'>Type: $($g.AmdInstallType)</span>" } else { "" }
            $gpuRows.Add("<tr><td><strong>$($g.Name)</strong>$installInfo</td><td>$($g.Vendor)</td><td>$($g.DriverVersion)</td><td>$($g.DriverDate)</td><td>$gpuBadge</td></tr>")
        }
    }

    $pnpRows = [System.Collections.Generic.List[string]]::new()
    if ($hw -and $hw.PnpIssues.Count -gt 0) {
        foreach ($p in $hw.PnpIssues) {
            $pnpRows.Add("<div class='alert-card alert-critical'><strong>&#x274C; [$($p.Status)] $($p.FriendlyName):</strong> $($p.Explanation) (Instance: $($p.InstanceId))</div>")
        }
    } else {
        $pnpRows.Add("<div class='empty-state'>&#x2705; All present Plug-and-Play devices are reporting 100% HEALTHY (Status: OK).</div>")
    }

    # Build Display HTML
    $displayRows = [System.Collections.Generic.List[string]]::new()
    if ($hw -and $hw.Displays -and $hw.Displays.Count -gt 0) {
        foreach ($disp in $hw.Displays) {
            $dispStatusBadge = if ($disp.HasTimingRisk) { "<span class='badge-critical'>TIMING RISK</span>" } else { "<span class='badge-healthy'>OK</span>" }
            $timingDetails = ""
            $detailItems = if ($disp.DetailedTimings -and $disp.DetailedTimings.Count -gt 0) {
                $disp.DetailedTimings
            } elseif ($disp.Timings -and $disp.Timings.Count -gt 0) {
                @($disp.Timings | ForEach-Object {
                    [PSCustomObject]@{
                        Mode          = "$($_.HActive)x$($_.VActive)@$($_.RefreshRate)Hz"
                        PixelClockMHz = $_.PixelClockMHz
                        VBlankLines   = ($_.VTotal - $_.VActive)
                        IsHighRisk    = ($_.PixelClockMHz -gt 580 -or ($_.VTotal - $_.VActive) -gt 1500)
                    }
                })
            } else { @() }
            if ($detailItems.Count -gt 0) {
                $dtStrings = @()
                foreach ($dt in $detailItems) {
                    $dtBadge = if ($dt.IsHighRisk) { "<span class='badge-critical'>$($dt.Mode) ($($dt.PixelClockMHz) MHz)</span>" } else { "$($dt.Mode) ($($dt.PixelClockMHz) MHz)" }
                    $dtStrings += $dtBadge
                }
                $timingDetails = "<div style='font-size: 0.85rem; color: var(--text-muted); margin-top: 4px;'>EDID Timings: " + ($dtStrings -join " | ") + "</div>"
            }
            $alertBox = ""
            if ($disp.HasTimingRisk) {
                $reasons = if ($disp.RiskReasons) { $disp.RiskReasons -join ' | ' } else { "High pixel clock / bloated vertical blanking exceeds budget scaler thresholds." }
                $alertBox = "<div class='alert-card alert-critical' style='margin-top: 8px;'><strong>&#x26A0; EDID timing heuristic matched (not an observed fault):</strong> $reasons</div>"
            }
            $displayRows.Add("<div class='card-item'><div class='card-header-row'><span class='file-name'>&#x1F5A5; $($disp.Name)</span>$dispStatusBadge</div><div>Connection: <strong>$($disp.Connection)</strong> | Active Mode: <strong>$($disp.ActiveResolution) @ $($disp.ActiveRefreshRate) Hz</strong></div>$timingDetails$alertBox</div>")
        }
    } else {
        $displayRows.Add("<div class='empty-state'>&#x2705; Connected displays report standard compliant timings.</div>")
    }

    # Build Rogue Drivers HTML
    $driverRows = [System.Collections.Generic.List[string]]::new()
    if ($hw -and $hw.KernelDrivers -and $hw.KernelDrivers.Count -gt 0) {
        foreach ($kd in $hw.KernelDrivers) {
            $badge = if ($kd.IsDisabled) { "<span class='badge-healthy'>DISABLED</span>" } elseif ($kd.IsActive) { "<span class='badge-warning'>AUTO-START</span>" } else { "<span class='badge-warning'>PRESENT</span>" }
            $alert = if ($kd.IsActive -and -not $kd.IsDisabled) {
                "<div class='alert-card alert-critical' style='margin-top: 8px;'><strong>&#x26A0; Legacy driver present:</strong> $($kd.RiskReason)</div>"
            } else { "" }
            $driverRows.Add("<div class='card-item'><div class='card-header-row'><span class='file-name'>&#x26A0; $($kd.FileName) (Service: $($kd.ServiceName))</span>$badge</div><div>Software: <strong>$($kd.Software)</strong> | Vendor: $($kd.Vendor) | Start Type: <strong>$($kd.StartType)</strong></div>$alert</div>")
        }
    } else {
        $driverRows.Add("<div class='empty-state'>&#x2705; No problematic third-party kernel I/O drivers (inpoutx64/WinRing0/ENE) detected.</div>")
    }

    # Build Network HTML
    $networkRows = [System.Collections.Generic.List[string]]::new()
    if ($hw -and $hw.NetworkAdapters -and $hw.NetworkAdapters.Count -gt 0) {
        foreach ($net in $hw.NetworkAdapters) {
            $statusBadge = if ($net.Status -eq "Up") { "<span class='badge-healthy'>UP</span>" } else { "<span class='badge-neutral'>$($net.Status)</span>" }
            $intelNotice = ""
            if ($net.IsIntel25G -and $net.PriorityVLAN -match 'Enabled') {
                $intelNotice = "<div class='alert-card alert-warning' style='margin-top: 6px; font-size: 0.85rem;'><strong>Config:</strong> Packet Priority &amp; VLAN is enabled on $($net.Name).</div>"
            }
            $udpNotice = ""
            if ($net.IsUdpConstrained) {
                $udpNotice = "<div class='alert-card alert-warning' style='margin-top: 6px; font-size: 0.85rem;'><strong>&#x26A0; UDP Dynamic Port Space Constrained:</strong> UDP ephemeral ports are restricted to $($net.UdpPortRange) (vs TCP $($net.TcpPortRange)). Rapid socket bursts during Steam/game matchmaking can exhaust ports and cause connection timeouts. Run <code>Repair-EthernetSettings.ps1 -ExpandUdpPorts</code> as Admin.</div>"
            }
            $portInfo = if ($net.UdpPortRange) { " | UDP Ports: <strong>$($net.UdpPortRange)</strong>" } else { "" }
            $networkRows.Add("<div class='card-item'><div class='card-header-row'><span class='file-name'>&#x1F310; $($net.Name) - $($net.InterfaceDescription)</span>$statusBadge</div><div style='font-size: 0.9rem;'>Link Speed: <strong>$($net.LinkSpeed)</strong> | Speed/Duplex: <strong>$($net.SpeedDuplex)</strong> | VLAN/Priority: <strong>$($net.PriorityVLAN)</strong>$portInfo</div>$intelNotice$udpNotice</div>")
        }
    } else {
        $networkRows.Add("<div class='empty-state'>&#x2705; Network adapters reporting normal status.</div>")
    }

    $cpuVal = if ($hw -and $hw.Motherboard -and $hw.Motherboard.CpuName) { $hw.Motherboard.CpuName } else { "Standard CPU" }
    $ramVal = if ($hw -and $hw.Memory -and $hw.Memory.Summary) { $hw.Memory.Summary } else { "Audited via System" }
    $gpuVal = if ($hw -and $hw.Gpus -and $hw.Gpus.Count -gt 0) { "$($hw.Gpus[0].Name) (v$($hw.Gpus[0].DriverVersion))" } else { "Standard Display Adapter" }
    $rebarVal = if ($hw -and $hw.RebarStatus -and $hw.RebarStatus.Details) { $hw.RebarStatus.Details } else { "N/A" }
    $mbVal = if ($hw -and $hw.Motherboard) { "$($hw.Motherboard.MotherboardManufacturer) $($hw.Motherboard.MotherboardProduct)" } else { "Standard Motherboard" }
    $biosVal = if ($hw -and $hw.Motherboard -and $hw.Motherboard.BiosVersion) { " | BIOS: $($hw.Motherboard.BiosVersion)" } else { "" }

    $fastStartupStatusStr = if ($telem -and $telem.FastStartup.FastStartupEnabled) { 'Enabled (Risk)' } else { 'Disabled (Clean)' }
    $pcieAspmStr = if ($telem -and $telem.PciePowerManagement) { $telem.PciePowerManagement.ACSettingName } else { 'Unknown' }
    $mbSummaryStr = if ($hw -and $hw.Motherboard) {
        "$($hw.Motherboard.MotherboardManufacturer) $($hw.Motherboard.MotherboardProduct) (BIOS: $($hw.Motherboard.BiosVersion) - $($hw.Motherboard.BiosReleaseDate))"
    } else { 'Unknown' }
    $chipsetSummaryStr = if ($hw -and $hw.Motherboard) {
        $mb = $hw.Motherboard
        $statusNotice = if ($mb.IsHealthy) { "Healthy" } else { "Missing: " + ($mb.MissingControllers -join ', ') }
        "$($mb.Summary) [$statusNotice]"
    } else { 'Unknown' }
    $gpuNamesStr = if ($hw -and $hw.Gpus -and $hw.Gpus.Count -gt 0) {
        ($hw.Gpus | ForEach-Object {
            $instTag = if ($_.AmdInstallType) { ", $($_.AmdInstallType)" } else { "" }
            "$($_.Name) (v$($_.DriverVersion)$instTag)"
        }) -join ' | '
    } else { 'None' }
    $multiGpuNoticeHtml = ""
    if ($hw -and $hw.DualGpuConflict -and $hw.DualGpuDetails) {
        $multiGpuNoticeHtml = "<div class='alert-card alert-critical' style='margin-top: 8px;'><strong>&#x26A0; Dual-GPU Driver Mismatch:</strong> $($hw.DualGpuDetails)</div>"
    } elseif ($hw -and $hw.HybridMultiGpu -and $hw.HybridMultiGpuDetails) {
        $multiGpuNoticeHtml = "<div class='alert-card alert-warning' style='margin-top: 8px;'><strong>&#x2139; Multi-GPU Configuration:</strong> $($hw.HybridMultiGpuDetails)</div>"
    }
    $pnpCountStr = if ($hw -and $hw.PnpIssues) { $hw.PnpIssues.Count } else { 0 }
    $dispSummaryStr = if ($hw -and $hw.Displays) {
        ($hw.Displays | ForEach-Object {
            $riskNotice = if ($_.HasTimingRisk) { " [HAZARD: Scaler/EDID Timing Risk]" } else { "" }
            "$($_.Name) ($($_.ActiveResolution)@$($_.ActiveRefreshRate)Hz)$riskNotice"
        }) -join '; '
    } else { 'None' }
    $rogueDriversStr = if ($hw -and $hw.KernelDrivers -and $hw.KernelDrivers.Count -gt 0) {
        $activeKd = @($hw.KernelDrivers | Where-Object { $_.IsActive -and -not $_.IsDisabled })
        if ($activeKd.Count -gt 0) { ($activeKd.FileName -join ', ') + " [HAZARD: Auto-Start]" } else { "None Active (Clean)" }
    } else { 'None (Clean)' }

    $ulpsStr = if (($hw -and $hw.IsUlpsEnabled) -or ($telem -and $telem.GraphicsDriverSettings -and $telem.GraphicsDriverSettings.IsUlpsEnabled)) { "Enabled (Power Saving Active)" } else { "Disabled" }
    $hagsStr = if ($telem -and $telem.GraphicsDriverSettings -and $telem.GraphicsDriverSettings.HAGSStatus) { $telem.GraphicsDriverSettings.HAGSStatus } else { "Default" }
    $tdrDelayStr = if ($telem -and $telem.GraphicsDriverSettings -and $telem.GraphicsDriverSettings.TdrDelay) { "$($telem.GraphicsDriverSettings.TdrDelay)s" } else { "2s (Windows Default)" }
    $scanRangeDiscord = if ($ReportData.ScanMode -eq "InvestigateResolved") {
        "Historical Resolution Analysis (Past $($ReportData.IncidentAnchor.LookbackDays) Days)"
    } elseif ($ReportData.ScanMode -eq "LatestIncident" -and $ReportData.IncidentAnchor) {
        "Latest Incident (Anchored: $($ReportData.IncidentAnchor.Timestamp.ToString('yyyy-MM-dd HH:mm')) - $($ReportData.IncidentAnchor.AgeDescription))"
    } elseif ($ReportData.ScanMode -eq "LatestIncidentClean") {
        "Latest Incident (Past $($ReportData.IncidentAnchor.LookbackDays) Days - Clean)"
    } elseif ($ReportData.ScanMode -eq "AllIncidents") {
        "Full Incident History (Past $($ReportData.HoursScanned) Hours)"
    } else {
        "Past $($ReportData.HoursScanned) Hours"
    }

    $resolvedRows = [System.Collections.Generic.List[string]]::new()
    $resolvedDiscordSection = ""
    if ($ReportData.PSObject.Properties['ResolvedHistory'] -and $ReportData.ResolvedHistory -and $ReportData.ResolvedHistory.HasResolvedEpisodes -and $ReportData.ResolvedHistory.PrimaryResolvedEpisode) {
        $ep = $ReportData.ResolvedHistory.PrimaryResolvedEpisode
        $histDrv = if ($ep.HistoricalDriverVersion) { "v$($ep.HistoricalDriverVersion)" } else { "Unrecorded" }
        $currDrv = if ($ep.CurrentDriverVersion) { "v$($ep.CurrentDriverVersion)" } else { "Unknown" }

        $factorRows = [System.Collections.Generic.List[string]]::new()
        $discordFactorLines = [System.Collections.Generic.List[string]]::new()
        if ($ep.ResolutionFactors -and $ep.ResolutionFactors.Count -gt 0) {
            foreach ($rf in ($ep.ResolutionFactors | Select-Object -First 6)) {
                $confBadge = switch ($rf.Confidence) {
                    "High"   { "<span class='badge-healthy'>HIGH</span>" }
                    "Medium" { "<span class='badge-warning'>MEDIUM</span>" }
                    default  { "<span class='badge-neutral'>CONTEXTUAL</span>" }
                }
                $tsDisplay = if ($rf.Timestamp) { $rf.Timestamp.ToString('yyyy-MM-dd HH:mm') } else { "Active State" }
                $factorRows.Add("<tr><td>$confBadge</td><td><code>$tsDisplay</code><br><span style='font-size:0.8rem;color:var(--text-muted);'>$($rf.DeltaFromLast)</span></td><td><strong>$($rf.Title)</strong><br><span style='font-size:0.85rem;color:var(--text-muted);'>$($rf.Details)</span></td><td>$($rf.Source)</td></tr>")
                $discordFactorLines.Add("  * [$($rf.Confidence)] $($rf.Title) ($($rf.DeltaFromLast)) - $($rf.Source)")
            }
        }

        $factorTableHtml = if ($factorRows.Count -gt 0) {
            "<table><thead><tr><th>Confidence</th><th>Timestamp / Delta</th><th>What Changed to Resolve It</th><th>Evidence Source</th></tr></thead><tbody>" + ($factorRows -join "`n") + "</tbody></table>"
        } else {
            "<div class='empty-state'>No explicit driver or registry change timestamped in the post-incident window.</div>"
        }

        $resolvedCard = "<div class='card-item'>" +
            "<div class='card-header-row'>" +
                "<span class='file-name'>&#x1F50D; Historical Episode ($($ep.StartTime.ToString('yyyy-MM-dd HH:mm')) .. $($ep.EndTime.ToString('yyyy-MM-dd HH:mm')))</span>" +
                "<span class='badge-healthy'>RESOLVED ($($ep.QuietDaysSinceEnd) DAYS CRASH-FREE)</span>" +
            "</div>" +
            "<div><strong>Incident Count:</strong> $($ep.IncidentCount) | <strong>Historical Cause:</strong> $($ep.HistoricalRootCause)</div>" +
            "<div><strong>Driver Version Diff:</strong> <code>$histDrv</code> (at crash) &rarr; <code>$currDrv</code> (current)</div>" +
            "<div style='margin-top: 10px;'><strong>Ranked Resolution Correlations:</strong>$factorTableHtml</div>" +
        "</div>"
        $resolvedRows.Add($resolvedCard)

        $resolvedDiscordSection = "`n`n[Historical Timeout Resolution]`n" +
            "Episode:     $($ep.StartTime.ToString('yyyy-MM-dd')) .. $($ep.EndTime.ToString('yyyy-MM-dd')) ($($ep.IncidentCount) incidents, $($ep.QuietDaysSinceEnd) days crash-free)`n" +
            "Past Cause:  $($ep.HistoricalRootCause)`n" +
            "Driver Diff: $histDrv -> $currDrv`n" +
            "What Changed:`n" + ($discordFactorLines -join "`n")
    }

    $multiGpuDiscordLine = if ($hw -and $hw.DualGpuConflict -and $hw.DualGpuDetails) {
        "Multi-GPU:      CONFLICT - $($hw.DualGpuDetails)`n"
    } elseif ($hw -and $hw.HybridMultiGpu -and $hw.HybridMultiGpuDetails) {
        "Multi-GPU:      $($hw.HybridMultiGpuDetails)`n"
    } else { "" }

    $formatGuidanceHtml = {
        param([string]$RawGuidance, [object[]]$Steps = $null, [object[]]$Actions = $null)
        $stepItems = [System.Collections.Generic.List[string]]::new()
        if ($Steps -and $Steps.Count -gt 0) {
            foreach ($st in $Steps) {
                if (-not [string]::IsNullOrWhiteSpace($st)) { $stepItems.Add($st.Trim()) }
            }
        } elseif (-not [string]::IsNullOrWhiteSpace($RawGuidance)) {
            $splitParts = @($RawGuidance -split '(?:\r?\n\s*(?:\*|\d+\.)\s*)|(?:\s+\*\s+)|(?:^\s*(?:\*|\d+\.)\s*)' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            foreach ($sp in $splitParts) {
                $stepItems.Add($sp.Trim())
            }
        }
        if ($stepItems.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($RawGuidance)) {
            $stepItems.Add($RawGuidance.Trim())
        }

        $htmlLines = [System.Collections.Generic.List[string]]::new()
        $htmlLines.Add("<ul class='guidance-list'>")
        foreach ($item in $stepItems) {
            $escaped = [System.Net.WebUtility]::HtmlEncode($item)
            $escaped = $escaped -replace '^([^:]{3,52}):\s+', '<strong>$1:</strong> '
            $escaped = $escaped -replace '^\((Recommended[^)]*)\)\s*', '<span class="badge-healthy" style="font-size:0.75rem;padding:2px 8px;border-radius:999px;margin-right:6px;">$1</span>'
            $escaped = $escaped -replace "(&#39;|')(\.\\[^']+?)(&#39;|')", "<code class='badge-code'>`$2</code>"
            $htmlLines.Add("<li>$escaped</li>")
        }
        $htmlLines.Add("</ul>")

        if ($Actions -and $Actions.Count -gt 0) {
            $pills = [System.Collections.Generic.List[string]]::new()
            foreach ($act in $Actions) {
                $admTag = if ($act.RequiresAdmin) { " (Admin)" } else { "" }
                $lbl = [System.Net.WebUtility]::HtmlEncode("$($act.Label)$admTag")
                $sw  = [System.Net.WebUtility]::HtmlEncode($act.SwitchHint)
                $fullCmd = ".\Analyze-LatestCrash.ps1 $($act.SwitchHint)"
                $fullCmdAttr = [System.Net.WebUtility]::HtmlEncode($fullCmd)
                $pills.Add("<button type='button' class='action-pill' data-cmd='$fullCmdAttr' onclick='copyCliFix(this)' title='Click to copy command: $fullCmdAttr (or select in DriverCheck terminal menu)'>&#9889; $lbl <code>$sw</code> <span class='copy-hint'>[Copy Fix Cmd]</span></button>")
            }
            $htmlLines.Add("<div class='action-pill-row'><span class='action-pill-label'>Quick Fixes (click to copy command, or select in terminal):</span> " + ($pills -join " ") + "</div>")
        }
        return ($htmlLines -join "`n")
    }

    $primarySteps = if ($ReportData.PSObject.Properties['Findings'] -and $ReportData.Findings -and $ReportData.Findings.Count -gt 0 -and $ReportData.Findings[0].PSObject.Properties['Steps'] -and ($ReportData.RootCauseGuidance -eq $ReportData.Findings[0].Guidance)) { $ReportData.Findings[0].Steps } else { $null }
    $primaryActions = if ($ReportData.PSObject.Properties['Findings'] -and $ReportData.Findings -and $ReportData.Findings.Count -gt 0 -and $ReportData.Findings[0].PSObject.Properties['Actions']) { $ReportData.Findings[0].Actions } else { $null }
    $primaryGuidanceHtml = & $formatGuidanceHtml $ReportData.RootCauseGuidance $primarySteps $primaryActions

    $secondaryFindingsHtml = ""
    $secondaryDiscordSection = ""
    if ($ReportData.PSObject.Properties['SecondaryFindings'] -and $ReportData.SecondaryFindings -and $ReportData.SecondaryFindings.Count -gt 0) {
        $secCards = [System.Collections.Generic.List[string]]::new()
        $secDiscordLines = [System.Collections.Generic.List[string]]::new()
        $secCards.Add("<div style='margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border);'><strong style='color: var(--yellow); font-size: 1.0rem;'>Other recorded events ($($ReportData.SecondaryFindings.Count)):</strong>")
        $idx = 2
        foreach ($sf in $ReportData.SecondaryFindings) {
            $sfBadge = if ($sf.Severity -eq "Critical") { "<span class='badge-critical'>CRITICAL</span>" } elseif ($sf.Severity -eq "Warning") { "<span class='badge-warning'>WARNING</span>" } else { "<span class='badge-neutral'>$($sf.Severity)</span>" }
            $sfSteps = if ($sf.PSObject.Properties['Steps']) { $sf.Steps } else { $null }
            $sfActs  = if ($sf.PSObject.Properties['Actions']) { $sf.Actions } else { $null }
            $sfGuidanceFormatted = & $formatGuidanceHtml $sf.Guidance $sfSteps $sfActs
            $evSecIdx = [array]::IndexOf(@($ReportData.Findings), $sf)
            $secCards.Add("<div class='card-item' id='ev-$evSecIdx' style='margin-top: 10px;'><div class='card-header-row'><span class='file-name'>[$idx] " + (& $enc $sf.Title) + "</span>$sfBadge</div><div style='font-size: 0.9rem; margin-bottom: 8px; white-space: pre-wrap;'>" + (& $enc $sf.Description) + "</div><div style='font-size:0.8rem;color:var(--text-muted);'>Source: " + (& $enc $sf.Source) + "</div></div>")
            $secDiscordLines.Add("  * $($sf.Title) :: $($sf.Description) (Source: $($sf.Source))")
            $idx++
        }
        $secCards.Add("</div>")
        $secondaryFindingsHtml = $secCards -join "`n"
        $secondaryDiscordSection = "`n`n[Other Recorded Events]`n" + ($secDiscordLines -join "`n")
    }

    $discordText = "=== DriverCheck Diagnostic Summary ===`n" +
        "Status:         $($ReportData.RootCauseTitle)`n" +
        "Severity:       $($ReportData.RootCauseSeverity)`n" +
        "Timestamp:      $((Get-Date).ToString('yyyy-MM-dd HH:mm'))`n" +
        "Scan Range:     $scanRangeDiscord`n`n" +
        "[Summary]`n$($ReportData.RootCauseDescription)" +
        $secondaryDiscordSection +
        $resolvedDiscordSection + "`n`n" +
        "[Hardware & Platform]`n" +
        "CPU:            $cpuVal`n" +
        "RAM:            $ramVal`n" +
        "Motherboard:    $mbSummaryStr`n" +
        "Chipset:        $chipsetSummaryStr`n" +
        "GPUs:           $gpuNamesStr`n" +
        $multiGpuDiscordLine +
        "Resizable BAR:  $rebarVal`n" +
        "Displays:       $dispSummaryStr`n" +
        "PCIe ASPM:      $pcieAspmStr`n" +
        "HAGS / TdrDelay: $hagsStr | TdrDelay: $tdrDelayStr`n" +
        "ULPS (Power):   $ulpsStr`n" +
        "Fast Startup:   $fastStartupStatusStr`n" +
        "Kernel Drivers: $rogueDriversStr`n" +
        "PnP Issues:     $pnpCountStr`n" +
        "Crash Dumps:    $($ReportData.Dumps.Count)"

    # Assemble HTML
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add("<!DOCTYPE html>")
    $parts.Add("<html lang='en'>")
    $parts.Add("<head>")
    $parts.Add("    <meta charset='UTF-8'>")
    $parts.Add("    <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    $parts.Add("    <title>DriverCheck Diagnostic Report - $($ReportData.RootCauseTitle)</title>")
    $cssBlock = @'
    <style>
        :root {
            --bg: #070b14;
            --bg-accent: radial-gradient(ellipse 85% 45% at 50% -12%, rgba(56, 189, 248, 0.14), transparent 70%);
            --surface: rgba(15, 23, 42, 0.88);
            --surface-solid: #0f172a;
            --surface-2: #162033;
            --surface-hover: #1e293b;
            --nav-bg: rgba(7, 11, 20, 0.84);
            --code-bg: #050811;
            --border: rgba(148, 163, 184, 0.16);
            --border-strong: rgba(148, 163, 184, 0.30);
            --text: #f1f5f9;
            --text-muted: #94a3b8;
            --cyan: #38bdf8;
            --indigo: #818cf8;
            --magenta: #c084fc;
            --green: #34d399;
            --yellow: #fbbf24;
            --red: #f87171;
            --shadow: 0 14px 36px -10px rgba(0, 0, 0, 0.55);
        }
        [data-theme="light"] {
            --bg: #f1f5f9;
            --bg-accent: radial-gradient(ellipse 85% 45% at 50% -12%, rgba(14, 165, 233, 0.12), transparent 70%);
            --surface: rgba(255, 255, 255, 0.94);
            --surface-solid: #ffffff;
            --surface-2: #f8fafc;
            --surface-hover: #e2e8f0;
            --nav-bg: rgba(248, 250, 252, 0.88);
            --code-bg: #f1f5f9;
            --border: rgba(15, 23, 42, 0.10);
            --border-strong: rgba(15, 23, 42, 0.22);
            --text: #0f172a;
            --text-muted: #475569;
            --cyan: #0284c7;
            --indigo: #4f46e5;
            --magenta: #9333ea;
            --green: #059669;
            --yellow: #d97706;
            --red: #dc2626;
            --shadow: 0 10px 30px -10px rgba(15, 23, 42, 0.10);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body {
            font-family: 'Inter', 'Segoe UI Variable', 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            background: var(--bg);
            background-image: var(--bg-accent);
            background-attachment: fixed;
            color: var(--text);
            line-height: 1.55;
            padding: 20px 20px 56px 20px;
            font-variant-numeric: tabular-nums;
        }
        .container { max-width: 1180px; margin: 0 auto; }

        /* Header */
        .header {
            display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap;
            background: var(--surface); border: 1px solid var(--border); border-radius: 16px;
            padding: 20px 24px; margin-bottom: 14px; box-shadow: var(--shadow);
        }
        .brand-row { display: flex; align-items: center; gap: 12px; }
        .brand-icon {
            width: 40px; height: 40px; border-radius: 11px; display: grid; place-items: center;
            background: linear-gradient(135deg, rgba(56,189,248,0.22), rgba(129,140,248,0.22));
            border: 1px solid rgba(56,189,248,0.35); color: var(--cyan); flex-shrink: 0;
        }
        .header-title h1 { font-size: 1.45rem; font-weight: 700; letter-spacing: -0.02em; color: var(--text); }
        .header-title p { color: var(--text-muted); font-size: 0.84rem; margin-top: 2px; }
        .header-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

        .btn {
            display: inline-flex; align-items: center; gap: 6px; padding: 7px 13px; border-radius: 9px;
            font-size: 0.82rem; font-weight: 600; font-family: inherit; cursor: pointer;
            background: var(--surface-2); color: var(--text); border: 1px solid var(--border);
            transition: all 0.15s ease;
        }
        .btn:hover { background: var(--surface-hover); border-color: var(--border-strong); transform: translateY(-1px); }
        .btn-primary { background: rgba(56,189,248,0.14); border-color: rgba(56,189,248,0.35); color: var(--cyan); }
        .btn-primary:hover { background: rgba(56,189,248,0.24); border-color: var(--cyan); }

        .badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 9999px; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
        .badge-healthy { background: rgba(52, 211, 153, 0.14); color: var(--green); border: 1px solid rgba(52, 211, 153, 0.35); padding: 3px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 700; }
        .badge-warning { background: rgba(251, 191, 36, 0.14); color: var(--yellow); border: 1px solid rgba(251, 191, 36, 0.35); padding: 3px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 700; }
        .badge-critical { background: rgba(248, 113, 113, 0.14); color: var(--red); border: 1px solid rgba(248, 113, 113, 0.35); padding: 3px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 700; }
        .badge-code { background: rgba(192, 132, 252, 0.16); color: var(--magenta); border: 1px solid rgba(192,132,252,0.28); padding: 2px 7px; border-radius: 6px; font-family: 'Cascadia Code', Consolas, monospace; font-size: 0.8rem; font-weight: 600; }
        .badge-module { background: rgba(56, 189, 248, 0.14); color: var(--cyan); border: 1px solid rgba(56,189,248,0.25); padding: 2px 7px; border-radius: 6px; font-family: 'Cascadia Code', Consolas, monospace; font-size: 0.8rem; font-weight: 600; }
        .badge-neutral { background: var(--surface-2); color: var(--text-muted); border: 1px solid var(--border); padding: 2px 8px; border-radius: 6px; font-size: 0.78rem; font-weight: 600; }
        .badge-thirdparty { background: rgba(251, 191, 36, 0.18); color: var(--yellow); border: 1px solid rgba(251,191,36,0.4); padding: 1px 7px; border-radius: 999px; font-size: 0.7rem; font-weight: 700; margin-left: 4px; }

        /* Sticky nav & search */
        .sticky-bar {
            position: sticky; top: 10px; z-index: 40;
            display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;
            background: var(--nav-bg); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
            border: 1px solid var(--border-strong); border-radius: 14px;
            padding: 10px 14px; margin-bottom: 18px; box-shadow: var(--shadow);
        }
        .nav-tabs { display: flex; flex-wrap: wrap; gap: 6px; }
        .nav-tab {
            background: transparent; color: var(--text-muted); border: 1px solid transparent;
            border-radius: 9px; padding: 6px 12px; font-size: 0.82rem; font-weight: 600; cursor: pointer;
            font-family: inherit; transition: all 0.14s ease; display: inline-flex; align-items: center; gap: 6px;
        }
        .nav-tab:hover { color: var(--text); background: var(--surface-hover); }
        .nav-tab.active { color: var(--cyan); background: rgba(56, 189, 248, 0.14); border-color: rgba(56, 189, 248, 0.35); }
        .nav-pill { font-size: 0.72rem; background: var(--surface-2); padding: 1px 6px; border-radius: 999px; color: var(--text-muted); border: 1px solid var(--border); }
        .nav-tab.active .nav-pill { color: var(--cyan); border-color: rgba(56,189,248,0.35); }

        .search-wrap { position: relative; flex: 1 1 280px; max-width: 380px; display: flex; align-items: center; gap: 8px; }
        .filter-input {
            width: 100%; background: var(--code-bg); border: 1px solid var(--border); border-radius: 9px;
            color: var(--text); padding: 8px 34px 8px 12px; font-size: 0.85rem; outline: none; font-family: inherit;
            transition: border-color 0.15s ease;
        }
        .filter-input:focus { border-color: var(--cyan); }
        .search-clear {
            position: absolute; right: 8px; background: none; border: none; color: var(--text-muted);
            cursor: pointer; font-size: 1rem; line-height: 1; padding: 4px; display: none;
        }
        .search-meta { font-size: 0.75rem; color: var(--cyan); white-space: nowrap; font-weight: 600; }

        /* KPI Strip */
        .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 18px; }
        .kpi-card {
            background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
            padding: 16px 18px; cursor: pointer; text-decoration: none; color: inherit; display: block;
            position: relative; overflow: hidden; transition: transform 0.15s ease, border-color 0.15s ease, background 0.15s ease;
        }
        .kpi-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--border-strong); }
        .kpi-card.kpi-red::before { background: var(--red); }
        .kpi-card.kpi-amber::before { background: var(--yellow); }
        .kpi-card.kpi-cyan::before { background: var(--cyan); }
        .kpi-card.kpi-green::before { background: var(--green); }
        .kpi-card:hover { transform: translateY(-2px); border-color: var(--border-strong); background: var(--surface-hover); }
        .kpi-label { font-size: 0.76rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); display: flex; justify-content: space-between; align-items: center; }
        .kpi-num { font-size: 2.1rem; font-weight: 800; line-height: 1.15; margin: 6px 0 4px 0; color: var(--text); letter-spacing: -0.02em; }
        .kpi-sub { font-size: 0.8rem; color: var(--text-muted); }

        /* Hero Bento */
        .hero-card {
            background: var(--surface); border: 1px solid var(--border); border-radius: 16px;
            padding: 22px 24px; margin-bottom: 18px; box-shadow: var(--shadow);
        }
        .hero-headline {
            font-size: 1.18rem; font-weight: 700; color: var(--text); padding: 14px 18px;
            border-radius: 12px; background: var(--surface-2); border-left: 4px solid var(--cyan); margin-bottom: 16px;
        }
        .hero-headline.sev-crit { border-left-color: var(--red); }
        .hero-headline.sev-warn { border-left-color: var(--yellow); }
        .hero-headline.sev-ok { border-left-color: var(--green); }

        .bento-grid { display: grid; grid-template-columns: 1.15fr 1fr; gap: 18px; }
        @media (max-width: 860px) { .bento-grid { grid-template-columns: 1fr; } }
        .bento-panel { background: var(--surface-2); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; }
        .panel-title { font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--cyan); margin-bottom: 10px; }
        .panel-title.ok { color: var(--green); }
        .panel-title.warn { color: var(--yellow); }

        .plain-list { list-style: none; display: flex; flex-direction: column; gap: 9px; }
        .plain-list li { font-size: 0.9rem; line-height: 1.5; padding: 9px 11px; border-radius: 9px; background: var(--surface); border: 1px solid var(--border); }
        .step-num {
            display: inline-grid; place-items: center; width: 20px; height: 20px; border-radius: 999px;
            background: rgba(56,189,248,0.18); color: var(--cyan); font-size: 0.75rem; font-weight: 700; margin-right: 7px;
        }
        .callout-warn {
            margin-top: 12px; padding: 12px 14px; border-radius: 10px;
            background: rgba(251, 191, 36, 0.10); border: 1px solid rgba(251, 191, 36, 0.30); font-size: 0.88rem;
        }
        .callout-ok {
            margin-top: 10px; padding: 10px 12px; border-radius: 10px;
            background: rgba(52, 211, 153, 0.10); border: 1px solid rgba(52, 211, 153, 0.25); font-size: 0.86rem;
        }

        /* Spec Strip */
        .spec-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(195px, 1fr)); gap: 10px; margin-bottom: 20px; }
        .spec-card { background: var(--surface); border: 1px solid var(--border); border-radius: 11px; padding: 11px 14px; }
        .spec-label { font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.05em; }
        .spec-value { font-size: 0.88rem; font-weight: 600; color: var(--text); margin-top: 3px; word-break: break-word; }

        /* Section Containers */
        .view-section { margin-bottom: 26px; }
        .view-section.is-hidden { display: none; }
        .section-heading {
            display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;
            margin: 8px 0 12px 0; padding-bottom: 8px; border-bottom: 1px solid var(--border);
        }
        .section-heading h2 { font-size: 1.12rem; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 8px; }
        .section-sub { font-size: 0.8rem; color: var(--text-muted); }

        .card-item { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; margin-bottom: 12px; }
        .card-header-row { display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; font-size: 0.95rem; }
        .file-name { font-weight: 700; color: var(--text); }
        .timestamp { color: var(--text-muted); font-size: 0.82rem; font-family: 'Cascadia Code', Consolas, monospace; }
        .code-block { background: var(--code-bg); border: 1px solid var(--border); padding: 11px 14px; border-radius: 8px; font-family: 'Cascadia Code', Consolas, monospace; font-size: 0.82rem; color: var(--text); overflow-x: auto; margin-top: 8px; white-space: pre-wrap; }
        .empty-state { background: var(--surface); border: 1px dashed var(--border-strong); border-radius: 10px; padding: 14px 16px; color: var(--green); font-size: 0.9rem; font-weight: 500; }
        .alert-card { padding: 11px 14px; border-radius: 10px; margin-bottom: 8px; font-size: 0.88rem; }
        .alert-critical { background: rgba(248, 113, 113, 0.12); border: 1px solid rgba(248, 113, 113, 0.32); }
        .alert-warning { background: rgba(251, 191, 36, 0.11); border: 1px solid rgba(251, 191, 36, 0.30); }

        /* Forensics Phase Timeline Table */
        .tl-controls { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin: 10px 0 8px 0; }
        .forensic-tl { width: 100%; border-collapse: collapse; font-size: 0.82rem; margin-top: 6px; }
        .forensic-tl th { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); padding: 7px 8px; border-bottom: 1px solid var(--border-strong); }
        .forensic-tl td { padding: 7px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
        .forensic-tl tr.is-noise { opacity: 0.72; }
        .forensic-tl.hide-noise tr.is-noise { display: none; }
        .crash-divider td {
            background: rgba(248, 113, 113, 0.14); color: var(--red); font-weight: 700; text-align: center;
            border-top: 1px solid rgba(248,113,113,0.45); border-bottom: 1px solid rgba(248,113,113,0.45);
            letter-spacing: 0.03em; font-size: 0.78rem; padding: 8px;
        }
        .phase-pill { display: inline-block; padding: 1px 7px; border-radius: 5px; font-size: 0.7rem; font-weight: 700; font-family: monospace; }
        .ph-pre { background: rgba(251, 191, 36, 0.2); color: var(--yellow); }
        .ph-boot { background: rgba(148, 163, 184, 0.16); color: var(--text-muted); }
        .ph-post { background: rgba(56, 189, 248, 0.15); color: var(--cyan); }
        .ph-run { background: rgba(129, 140, 248, 0.16); color: var(--indigo); }

        .lvl-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 5px; vertical-align: middle; }
        .lvl-1, .lvl-2 { background: var(--red); }
        .lvl-3 { background: var(--yellow); }
        .lvl-4 { background: var(--text-muted); }

        /* Standard tables & accordions */
        table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.88rem; }
        th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); }
        th { color: var(--cyan); font-weight: 700; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }
        tbody tr:hover { background: var(--surface-hover); }

        details.acc { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 12px; overflow: hidden; }
        details.acc > summary {
            list-style: none; cursor: pointer; padding: 13px 18px; font-weight: 700; font-size: 0.94rem;
            display: flex; justify-content: space-between; align-items: center; color: var(--text);
            background: var(--surface-2); user-select: none;
        }
        details.acc > summary::-webkit-details-marker { display: none; }
        details.acc > summary:hover { background: var(--surface-hover); }
        details.acc[open] > summary { border-bottom: 1px solid var(--border); }
        .acc-body { padding: 14px 18px; }

        /* Timeline chips & rail */
        .tl-filters { display: flex; flex-wrap: wrap; gap: 7px; margin-bottom: 12px; }
        .tl-chip { background: var(--surface-2); color: var(--text-muted); border: 1px solid var(--border); border-radius: 999px; padding: 5px 13px; font-size: 0.8rem; font-weight: 600; cursor: pointer; font-family: inherit; }
        .tl-chip.active, .tl-chip:hover { color: var(--cyan); border-color: var(--cyan); background: rgba(56,189,248,0.12); }
        .tl { position: relative; margin-left: 6px; padding-left: 6px; border-left: 2px solid var(--border); }
        .tl-day { font-size: 0.75rem; font-weight: 700; color: var(--text-muted); margin: 12px 0 6px 14px; text-transform: uppercase; letter-spacing: 0.05em; }
        .tl-item { position: relative; display: flex; align-items: baseline; gap: 10px; text-decoration: none; color: var(--text); padding: 6px 10px 6px 18px; border-radius: 8px; font-size: 0.88rem; }
        .tl-item:hover { background: var(--surface-hover); }
        .tl-time { font-family: 'Cascadia Code', Consolas, monospace; font-size: 0.79rem; color: var(--text-muted); min-width: 64px; }
        .tl-dot { position: absolute; left: -9px; top: 12px; width: 11px; height: 11px; border-radius: 50%; background: var(--red); border: 2px solid var(--bg); }
        .tl-warn .tl-dot { background: var(--yellow); }
        .tl-tag { display: inline-block; font-size: 0.68rem; font-weight: 700; text-transform: uppercase; padding: 1px 8px; border-radius: 999px; margin-right: 6px; border: 1px solid var(--border); }
        .tl-tag-sys { color: var(--red); border-color: rgba(248,113,113,0.4); background: rgba(248,113,113,0.1); }
        .tl-tag-app { color: var(--yellow); border-color: rgba(251,191,36,0.4); background: rgba(251,191,36,0.1); }
        .tl-tag-drv { color: var(--cyan); border-color: rgba(56,189,248,0.4); background: rgba(56,189,248,0.1); }
        .tl-tag-other { color: var(--text-muted); }

        .hw-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(460px, 1fr)); gap: 14px; }
        @media (max-width: 600px) { .hw-grid { grid-template-columns: 1fr; } }

        .guidance-list { margin: 6px 0 4px 18px; }
        .guidance-list li { margin-bottom: 7px; font-size: 0.9rem; }
        .action-pill-row { margin-top: 12px; padding-top: 10px; border-top: 1px dashed var(--border-strong); display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
        .action-pill-label { font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: var(--green); }
        .action-pill {
            display: inline-flex; align-items: center; gap: 6px; background: rgba(52,211,153,0.12);
            border: 1px solid rgba(52,211,153,0.35); color: var(--green); padding: 6px 12px;
            border-radius: 8px; font-size: 0.8rem; font-weight: 600; cursor: pointer; font-family: inherit;
        }
        .action-pill:hover { background: rgba(52,211,153,0.22); }

        .discord-copy-box { margin-top: 22px; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; }
        .discord-copy-box textarea { width: 100%; height: 130px; background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px; color: var(--text-muted); padding: 11px; font-family: 'Cascadia Code', Consolas, monospace; font-size: 0.82rem; margin-top: 8px; resize: vertical; }
        footer { margin-top: 28px; border-top: 1px solid var(--border); padding-top: 16px; text-align: center; color: var(--text-muted); font-size: 0.8rem; }
        .toast {
            position: fixed; bottom: 24px; right: 24px; background: var(--surface-solid); color: var(--cyan);
            border: 1px solid var(--cyan); padding: 10px 16px; border-radius: 10px; font-size: 0.85rem; font-weight: 600;
            box-shadow: var(--shadow); opacity: 0; transform: translateY(10px); pointer-events: none; transition: all 0.2s ease; z-index: 90;
        }
        .toast.show { opacity: 1; transform: translateY(0); }
        .card-item:target, .hero-headline:target { outline: 2px solid var(--cyan); outline-offset: 3px; }
        @media print {
            body { background: #fff; color: #000; padding: 0; }
            .sticky-bar, .header-actions, .tl-controls, .action-pill-row, .toast { display: none !important; }
            .view-section.is-hidden { display: block !important; }
            .card-item, .hero-card, details.acc { break-inside: avoid; box-shadow: none; }
        }
    </style>
'@
    $parts.Add($cssBlock)
    $parts.Add("</head>")
    $parts.Add("<body>")
    $parts.Add("    <div class='container'>")

    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $mbHeaderInfo = if ($hw -and $hw.Motherboard) { "System: $($hw.Motherboard.MotherboardManufacturer) $($hw.Motherboard.MotherboardProduct)" } else { "" }
    $scanInfo = if ($ReportData.ScanMode -eq "InvestigateResolved") {
        "Historical Resolution Analysis (Past $($ReportData.IncidentAnchor.LookbackDays) Days)"
    } elseif ($ReportData.ScanMode -eq "LatestIncident" -and $ReportData.IncidentAnchor) {
        "Latest Incident (Anchored: $($ReportData.IncidentAnchor.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')) - $($ReportData.IncidentAnchor.AgeDescription))"
    } elseif ($ReportData.ScanMode -eq "LatestIncidentClean") {
        "Latest Incident (Past $($ReportData.IncidentAnchor.LookbackDays) days: Clean)"
    } elseif ($ReportData.ScanMode -eq "AllIncidents") {
        "Full Incident History (Past $($ReportData.HoursScanned) Hours)"
    } else {
        "Scan Window: Past $($ReportData.HoursScanned) Hours"
    }

    $parts.Add("        <header class='header'>")
    $parts.Add("            <div class='brand-row'>")
    $parts.Add("                <div class='brand-icon'><svg width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/><path d='m9 12 2 2 4-4'/></svg></div>")
    $parts.Add("                <div class='header-title'>")
    $parts.Add("                    <h1>DriverCheck Diagnostic Report</h1>")
    $parts.Add("                    <p>$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) &middot; " + (& $enc $scanInfo) + $(if ($mbHeaderInfo) { " &middot; " + (& $enc $mbHeaderInfo) } else { "" }) + "</p>")
    $parts.Add("                </div>")
    $parts.Add("            </div>")
    $parts.Add("            <div class='header-actions'>")
    $parts.Add("                <span class='badge $statusClass'>$statusText</span>")
    $parts.Add("                <button type='button' class='btn' onclick='toggleTheme()' id='themeBtn'>Light Mode</button>")
    $parts.Add("                <button type='button' class='btn btn-primary' onclick='copyDiscordSummary()'>Copy Summary</button>")
    $parts.Add("                <button type='button' class='btn' onclick='window.print()'>Print / PDF</button>")
    $parts.Add("            </div>")
    $parts.Add("        </header>")

    # Derive unified counts & sections
    $allEv = if ($ReportData.PSObject.Properties['Findings'] -and $ReportData.Findings) { @($ReportData.Findings) } else { @() }
    $catOf = {
        param($f)
        if ($f.Id -in @('KERNEL_BUGCHECK', 'KERNEL_POWER_41', 'EVENTLOG_6008')) { return 'sys' }
        if ($f.Id -eq 'CRASH_DUMP') { if ($f.Title -match 'kernel dump') { return 'sys' } else { return 'app' } }
        if ($f.Id -eq 'GPU_TIMEOUT_EVENT') { return 'drv' }
        return 'other'
    }
    $catLabel = @{ sys = 'System crash'; app = 'Application crash'; drv = 'Driver timeout'; other = 'Other event' }
    $fmtT = { param($t) if ($t -is [datetime]) { $t.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' } }
    $latestOf = {
        param($items)
        $x = @($items | Where-Object { $_.Timestamp -is [datetime] } | Sort-Object Timestamp -Descending | Select-Object -First 1)
        if ($x.Count -gt 0) { & $fmtT $x[0].Timestamp } else { 'n/a' }
    }

    $sysItems = @($allEv | Where-Object { (& $catOf $_) -eq 'sys' })
    $bcItems  = @($sysItems | Where-Object { $_.Id -eq 'KERNEL_BUGCHECK' })
    $rsItems  = @($sysItems | Where-Object { $_.Id -in @('KERNEL_POWER_41', 'EVENTLOG_6008') })
    $drvItems = @($allEv | Where-Object { $_.Id -eq 'GPU_TIMEOUT_EVENT' })
    $appDumps = @($ReportData.Dumps | Where-Object { $_ -and $_.ExceptionCode -and -not $_.IsKernelDump })
    $gapItems = @($allEv | Where-Object { $_.Id -eq 'EVIDENCE_UNREADABLE' })

    $cf = if ($ReportData.PSObject.Properties['CrashForensics']) { $ReportData.CrashForensics } else { $null }
    $ps = if ($cf -and $cf.PSObject.Properties['PlainSummary']) { $cf.PlainSummary } else { $null }

    $bsodKpi     = if ($ps -and $ps.Counts) { $ps.Counts.Bsods } else { $bcItems.Count }
    $restartKpi  = if ($ps -and $ps.Counts) { $ps.Counts.SuddenRestarts } else { $rsItems.Count }
    $gpuKpi      = if ($ps -and $ps.Counts) { $ps.Counts.GpuTimeouts } else { $drvItems.Count }
    $gpu14Kpi    = if ($ps -and $ps.Counts) { $ps.Counts.GpuHistory14d } else { 0 }
    $dispKpi     = if ($ps -and $ps.Counts) { $ps.Counts.DisplayDrops } else { 0 }
    $appKpi      = if ($ps -and $ps.Counts) { $ps.Counts.AppGpuCrashes } else { $appDumps.Count }
    $forensicCnt = if ($cf) { @($cf.Crashes).Count } else { 0 }
    $gpuDispCnt  = if ($cf) { @($cf.GpuDisplayEvents).Count } else { 0 }
    $dumpsLogsCnt = @($ReportData.Dumps).Count + @($ReportData.EngineLogs).Count + @($ReportData.SteamLogs).Count

    # Sticky Toolbar & View Switcher
    $parts.Add("        <nav class='sticky-bar'>")
    $parts.Add("            <div class='nav-tabs'>")
    $parts.Add("                <button type='button' class='nav-tab active' data-view='all' onclick='switchView(&quot;all&quot;, this)'>All Sections</button>")
    $parts.Add("                <button type='button' class='nav-tab' data-view='overview' onclick='switchView(&quot;overview&quot;, this)'>What Happened</button>")
    $parts.Add("                <button type='button' class='nav-tab' data-view='forensics' onclick='switchView(&quot;forensics&quot;, this)'>Timelines &amp; Forensics <span class='nav-pill'>$forensicCnt</span></button>")
    $parts.Add("                <button type='button' class='nav-tab' data-view='gpu-apps' onclick='switchView(&quot;gpu-apps&quot;, this)'>GPU &amp; App Events <span class='nav-pill'>$gpuDispCnt</span></button>")
    $parts.Add("                <button type='button' class='nav-tab' data-view='hardware' onclick='switchView(&quot;hardware&quot;, this)'>Hardware &amp; Storage</button>")
    $parts.Add("                <button type='button' class='nav-tab' data-view='logs' onclick='switchView(&quot;logs&quot;, this)'>Dumps &amp; Logs <span class='nav-pill'>$dumpsLogsCnt</span></button>")
    $parts.Add("            </div>")
    $parts.Add("            <div class='search-wrap'>")
    $parts.Add("                <input type='text' class='filter-input' id='reportFilter' placeholder='Search crashes, drivers, modules, or timestamps...' oninput='filterReport()'>")
    $parts.Add("                <button type='button' class='search-clear' id='searchClear' onclick='clearSearch()' title='Clear search'>&times;</button>")
    $parts.Add("                <span class='search-meta' id='filterCount'></span>")
    $parts.Add("            </div>")
    $parts.Add("        </nav>")

    # KPI Hero Strip
    $bsodCls    = if ($bsodKpi -gt 0) { 'kpi-red' } else { 'kpi-green' }
    $rebCls     = if ($restartKpi -gt 0) { 'kpi-red' } else { 'kpi-green' }
    $gpuCls     = if ($gpuKpi -gt 0) { 'kpi-amber' } else { 'kpi-cyan' }
    $dispAppTot = $dispKpi + $appKpi
    $dispCls    = if ($dispAppTot -gt 0) { 'kpi-amber' } else { 'kpi-cyan' }

    $parts.Add("        <section class='kpi-grid'>")
    $parts.Add("            <a class='kpi-card $bsodCls' href='#sec-forensics' onclick='switchView(&quot;all&quot;)'><div class='kpi-label'><span>Windows Crashes (BSOD)</span></div><div class='kpi-num'>$bsodKpi</div><div class='kpi-sub'>$(if ($bsodKpi -gt 0) { 'Forced OS stop / BugCheck' } elseif ($gapItems.Count -gt 0) { 'See dump access notice below' } else { 'None recorded' })</div></a>")
    $parts.Add("            <a class='kpi-card $rebCls' href='#sec-forensics' onclick='switchView(&quot;all&quot;)'><div class='kpi-label'><span>Sudden Restarts</span></div><div class='kpi-num'>$restartKpi</div><div class='kpi-sub'>$(if ($restartKpi -gt 0) { 'Power loss or hang without dump' } else { 'No unexpected power-loss resets' })</div></a>")
    $parts.Add("            <a class='kpi-card $gpuCls' href='#sec-gpu-apps' onclick='switchView(&quot;all&quot;)'><div class='kpi-label'><span>GPU Driver Timeouts</span></div><div class='kpi-num'>$gpuKpi</div><div class='kpi-sub'>Brief freeze / reset (14d history: $gpu14Kpi)</div></a>")
    $parts.Add("            <a class='kpi-card $dispCls' href='#sec-gpu-apps' onclick='switchView(&quot;all&quot;)'><div class='kpi-label'><span>Display Drops &amp; App Crashes</span></div><div class='kpi-num'>$dispAppTot</div><div class='kpi-sub'>Monitor drops: $dispKpi &middot; App dumps: $appKpi</div></a>")
    $parts.Add("        </section>")

    # OVERVIEW SECTION
    $parts.Add("        <div class='view-section' data-section='overview' id='sec-overview'>")
    $sevHero = if ($ReportData.RootCauseSeverity -eq 'Critical') { 'sev-crit' } elseif ($ReportData.RootCauseSeverity -eq 'Warning') { 'sev-warn' } else { 'sev-ok' }

    if ($ps) {
        $parts.Add("            <section class='hero-card' id='what-happened'>")
        $parts.Add("                <div class='hero-headline $sevHero'>" + (& $enc $ps.Headline) + "</div>")
        $parts.Add("                <div class='bento-grid'>")
        $parts.Add("                    <div class='bento-panel'>")
        $parts.Add("                        <div class='panel-title'>What Each Crash Means</div>")
        if (@($ps.TranslatedIncidents).Count -gt 0) {
            $parts.Add("                        <ul class='plain-list'>")
            foreach ($ti in $ps.TranslatedIncidents) {
                $parts.Add("                            <li><span class='timestamp'>" + (& $enc $ti.When) + "</span> <span class='badge-code'>" + (& $enc $ti.Code) + "</span><div style='margin-top:4px;'>" + (& $enc $ti.PlainText) + "</div></li>")
            }
            $parts.Add("                        </ul>")
        } else {
            $parts.Add("                        <div class='empty-state'>No OS crash stop codes were recorded in this window.</div>")
        }
        if ($ps.IdleNoWarningNote) {
            $parts.Add("                        <div class='callout-warn'><strong>Why were there no warnings beforehand?</strong><br>" + (& $enc $ps.IdleNoWarningNote) + "</div>")
        }
        if (@($ps.ConfirmedFacts).Count -gt 0) {
            $parts.Add("                        <div style='margin-top:14px;'><div class='panel-title'>Confirmed Facts</div><ul class='guidance-list'>")
            foreach ($cfFact in $ps.ConfirmedFacts) { $parts.Add("                            <li>" + (& $enc $cfFact) + "</li>") }
            $parts.Add("                        </ul></div>")
        }
        $parts.Add("                    </div>")
        $parts.Add("                    <div class='bento-panel'>")
        if (@($ps.WhatThisRulesOut).Count -gt 0) {
            $parts.Add("                        <div class='panel-title ok'>What This Rules Out</div>")
            foreach ($ro in $ps.WhatThisRulesOut) {
                $parts.Add("                        <div class='callout-ok'>" + (& $enc $ro) + "</div>")
            }
        }
        if (@($ps.SensibleNextChecks).Count -gt 0) {
            $parts.Add("                        <div class='panel-title' style='margin-top:14px;'>Sensible Next Checks (By Evidence)</div>")
            $parts.Add("                        <ul class='plain-list'>")
            $stepN = 1
            foreach ($nc in $ps.SensibleNextChecks) {
                $parts.Add("                            <li><span class='step-num'>$stepN</span>" + (& $enc $nc) + "</li>")
                $stepN++
            }
            $parts.Add("                        </ul>")
        }
        $parts.Add("                    </div>")
        $parts.Add("                </div>")
        $parts.Add("            </section>")
    }

    # Spec Ribbon
    $parts.Add("            <div class='spec-grid'>")
    $parts.Add("                <div class='spec-card'><div class='spec-label'>Processor</div><div class='spec-value'>" + (& $enc $cpuVal) + "</div></div>")
    $parts.Add("                <div class='spec-card'><div class='spec-label'>System Memory</div><div class='spec-value'>" + (& $enc $ramVal) + "</div></div>")
    $parts.Add("                <div class='spec-card'><div class='spec-label'>Graphics Hardware</div><div class='spec-value'>" + (& $enc $gpuVal) + "</div></div>")
    $parts.Add("                <div class='spec-card'><div class='spec-label'>Resizable BAR / SAM</div><div class='spec-value'>" + (& $enc $rebarVal) + "</div></div>")
    $parts.Add("                <div class='spec-card'><div class='spec-label'>Motherboard &amp; BIOS</div><div class='spec-value'>" + (& $enc "$mbVal$biosVal") + "</div></div>")
    $parts.Add("            </div>")

    # Timeline Card
    $tlItems = @($allEv | Where-Object { $_.Timestamp -is [datetime] -and ($_.Kind -eq 'Crash' -or $_.Severity -in @('Critical', 'Warning')) } | Sort-Object Timestamp -Descending)
    $parts.Add("            <section class='card-item' id='timeline'>")
    $parts.Add("                <div class='section-heading'><h2>Incident &amp; Event Timeline</h2><span class='section-sub'>Click an item to jump to its details</span></div>")
    $parts.Add("                <div class='tl-filters'>")
    $parts.Add("                    <button type='button' class='tl-chip active' data-cat='all' onclick='filterTimeline(this.getAttribute(&quot;data-cat&quot;))'>All</button>")
    $parts.Add("                    <button type='button' class='tl-chip' data-cat='sys' onclick='filterTimeline(this.getAttribute(&quot;data-cat&quot;))'>System crashes</button>")
    $parts.Add("                    <button type='button' class='tl-chip' data-cat='app' onclick='filterTimeline(this.getAttribute(&quot;data-cat&quot;))'>Application crashes</button>")
    $parts.Add("                    <button type='button' class='tl-chip' data-cat='drv' onclick='filterTimeline(this.getAttribute(&quot;data-cat&quot;))'>Driver timeouts</button>")
    $parts.Add("                    <button type='button' class='tl-chip' data-cat='other' onclick='filterTimeline(this.getAttribute(&quot;data-cat&quot;))'>Other events</button>")
    $parts.Add("                </div>")
    if ($tlItems.Count -eq 0) {
        $parts.Add("                <div class='empty-state'>No timestamped crash or warning events were recorded in the sources that were read.</div>")
    } else {
        $parts.Add("                <div class='tl'>")
        $lastDay = $null
        foreach ($f in $tlItems) {
            $day = $f.Timestamp.ToString('yyyy-MM-dd (ddd)')
            if ($day -ne $lastDay) {
                $parts.Add("                    <div class='tl-day' data-day='1'>$day</div>")
                $lastDay = $day
            }
            $cat = & $catOf $f
            $sevCls = if ($f.Severity -eq 'Critical') { 'tl-crit' } else { 'tl-warn' }
            $evi = [array]::IndexOf($allEv, $f)
            $parts.Add("                    <a class='tl-item $sevCls' data-cat='$cat' href='#ev-$evi' onclick='switchView(&quot;all&quot;)'><span class='tl-time'>$($f.Timestamp.ToString('HH:mm:ss'))</span><span class='tl-dot'></span><span class='tl-body'><span class='tl-tag tl-tag-$cat'>$($catLabel[$cat])</span> " + (& $enc $f.Title) + "</span></a>")
        }
        $parts.Add("                </div>")
    }
    $parts.Add("            </section>")

    # Raw Event Summary Accordion (keeps Overview sleek while keeping full Event details accessible)
    $primIdx = if ($ReportData.PSObject.Properties['PrimaryFinding'] -and $ReportData.PrimaryFinding) { [array]::IndexOf($allEv, $ReportData.PrimaryFinding) } else { -1 }
    $primIdAttr = if ($primIdx -ge 0) { " id='ev-$primIdx'" } else { '' }
    $parts.Add("            <details class='acc' open>")
    $parts.Add("                <summary><span>Detailed Event Summary &amp; Log Findings ($($allEv.Count) item(s))</span><span class='badge-neutral'>Click to collapse</span></summary>")
    $parts.Add("                <div class='acc-body'>")
    $parts.Add("                    <div class='hero-headline $sevHero'$primIdAttr>" + (& $enc $ReportData.RootCauseTitle) + "</div>")
    $parts.Add("                    <div style='font-size:0.92rem; line-height:1.55; white-space:pre-wrap; margin-bottom:12px;'>" + (& $enc $ReportData.RootCauseDescription) + "</div>")
    if ($secondaryFindingsHtml) { $parts.Add($secondaryFindingsHtml) }
    if ($ReportData.PSObject.Properties['Leads'] -and $ReportData.Leads -and @($ReportData.Leads).Count -gt 0) {
        $parts.Add("                    <div style='margin-top:16px;padding-top:12px;border-top:1px solid var(--border);'><strong style='color:var(--green);'>Additional Investigation Leads:</strong>")
        foreach ($ld in @($ReportData.Leads)) {
            $parts.Add("                    <div class='card-item' style='margin-top:8px;padding:12px 14px;'><div>" + (& $enc $ld.Lead) + "</div><div style='font-size:0.8rem;color:var(--text-muted);margin-top:4px;'>Based on: " + (& $enc $ld.BasedOn) + "</div></div>")
        }
        $parts.Add("                    </div>")
    }
    $parts.Add("                </div>")
    $parts.Add("            </details>")

    if ($resolvedRows.Count -gt 0) {
        $parts.Add("            <div class='section-heading'><h2>Past Crash History &amp; What Changed</h2></div>")
        $parts.Add(($resolvedRows -join "`n"))
    }
    $parts.Add("        </div>") # end overview

    # FORENSICS SECTION
    $parts.Add("        <div class='view-section' data-section='forensics' id='sec-forensics'>")
    $parts.Add("            <div class='section-heading'><h2>Crash Forensics &amp; Event Timelines</h2><span class='section-sub'>Evidence-only per-crash reconstruction around T = crash time</span></div>")
    if ($cf -and @($cf.Crashes).Count -gt 0) {
        foreach ($cr in @($cf.Crashes)) {
            if (-not $cr.PSObject.Properties['AnchorTime']) { continue }
            $ctStr = if ($cr.CrashTime) { $cr.CrashTime.ToString('yyyy-MM-dd HH:mm:ss') } else { "~" + $cr.LogTime.ToString('yyyy-MM-dd HH:mm:ss') + " (log)" }
            $bcStr = if ($cr.BugcheckCode) { $cr.BugcheckCode } else { "No bugcheck" }
            $parts.Add("            <div class='card-item'>")
            $parts.Add("                <div class='card-header-row'><span><span class='file-name'>Crash #$($cr.Index): " + (& $enc $cr.Kind) + "</span> <span class='badge-code'>" + (& $enc $bcStr) + "</span></span><span class='timestamp'>" + (& $enc $ctStr) + "</span></div>")
            if ($cr.BootTrigger -or $cr.BootType) {
                $parts.Add("                <div style='font-size:0.84rem;color:var(--text-muted);margin-bottom:6px;'>Boot: " + (& $enc "$($cr.BootType) &middot; $($cr.BootTrigger)") + "</div>")
            }
            if ($cr.Dump -and $cr.Dump.CdbInspected) {
                $procInfo = if ($cr.Dump.AnalysisDetail -and $cr.Dump.AnalysisDetail.ProcessName -and $cr.Dump.AnalysisDetail.ProcessName -notmatch 'wrong\.symbols') { " <span class='badge-neutral'>Process: " + (& $enc $cr.Dump.AnalysisDetail.ProcessName) + "</span>" } else { "" }
                $parts.Add("                <div style='font-size:0.86rem;margin-bottom:8px;display:flex;flex-wrap:wrap;gap:6px;align-items:center;'><span>Bucket:</span> <span class='badge-module'>" + (& $enc $cr.Dump.FailureBucket) + "</span> <span>Fault at:</span> <span class='badge-code'>" + (& $enc $cr.Dump.DebuggerSymbolName) + "</span>$procInfo</div>")
            }
            if (@($cr.Components).Count -gt 0) {
                $compPills = (@($cr.Components) | ForEach-Object {
                    $tp = if (-not $_.IsMicrosoft -and $_.Found) { "<span class='badge-thirdparty'>THIRD-PARTY</span>" } else { "" }
                    "<span class='badge-neutral'>" + (& $enc "$($_.Name) ($($_.Role))") + "$tp</span>"
                }) -join " "
                $parts.Add("                <div style='margin-bottom:10px;display:flex;flex-wrap:wrap;gap:6px;align-items:center;'><strong style='font-size:0.82rem;color:var(--text-muted);'>Components:</strong> $compPills</div>")
            }
            if (@($cr.Timeline).Count -gt 0) {
                $tlId = "ft-$($cr.Index)"
                $parts.Add("                <div class='tl-controls'><strong style='font-size:0.82rem;color:var(--cyan);'>Event Timeline ($($cr.Timeline.Count) grouped entries)</strong><button type='button' class='btn' style='padding:4px 10px;font-size:0.76rem;' onclick='toggleNoise(&quot;$tlId&quot;, this)'>Hide boot &amp; post-reboot noise</button></div>")
                $parts.Add("                <table class='forensic-tl' id='$tlId'><thead><tr><th>Time</th><th>Offset</th><th>Phase</th><th>Severity</th><th>Source / ID</th><th>Message</th></tr></thead><tbody>")
                $crossed = $false
                $anchor = $cr.AnchorTime
                foreach ($t in $cr.Timeline) {
                    if (-not $crossed -and $t.Time -gt $anchor.AddSeconds(2)) {
                        $parts.Add("                    <tr class='crash-divider'><td colspan='6'>CRASH / HANG POINT (Windows cannot write logs while down)</td></tr>")
                        $crossed = $true
                    }
                    $isPost = ($t.Time -gt $anchor.AddSeconds(2))
                    $isBoot = ($cr.CrashedBootStart -and $t.Time -le $cr.CrashedBootStart.AddSeconds(150))
                    $isPre  = ($t.Time -ge $anchor.AddMinutes(-20))
                    $phLbl = if ($isPost) { 'POST' } elseif ($isBoot) { 'BOOT' } elseif ($isPre) { 'PRE' } else { 'RUN' }
                    $phCls = if ($isPost) { 'ph-post' } elseif ($isBoot) { 'ph-boot' } elseif ($isPre) { 'ph-pre' } else { 'ph-run' }
                    $rowCls = if ($isBoot -or $isPost) { ' class="is-noise"' } else { '' }
                    $secDiff = [int]($t.Time - $anchor).TotalSeconds
                    $sign = if ($secDiff -lt 0) { '-' } else { '+' }
                    $absS = [math]::Abs($secDiff)
                    $offStr = if ($absS -ge 3600) { 'T{0}{1}h{2:00}m' -f $sign, [int][math]::Floor($absS/3600), [int][math]::Floor(($absS%3600)/60) } elseif ($absS -ge 60) { 'T{0}{1}m{2:00}s' -f $sign, [int][math]::Floor($absS/60), ($absS%60) } else { 'T{0}{1}s' -f $sign, $absS }
                    $lvlN = [int]$t.Level
                    $lvlTxt = switch ($lvlN) { 1 { 'CRIT' } 2 { 'ERR' } 3 { 'WARN' } default { 'info' } }
                    $cntTxt = if ($t.Count -gt 1) { " <span class='badge-neutral'>x$($t.Count)</span>" } else { "" }
                    $parts.Add("                    <tr$rowCls><td class='timestamp'>$($t.Time.ToString('HH:mm:ss'))</td><td class='timestamp'>$offStr</td><td><span class='phase-pill $phCls'>$phLbl</span></td><td><span class='lvl-dot lvl-$lvlN'></span>$lvlTxt</td><td><strong>" + (& $enc $t.Source) + "</strong> $($t.Id)</td><td>" + (& $enc $t.Message) + "$cntTxt</td></tr>")
                }
                if (-not $crossed) {
                    $parts.Add("                    <tr class='crash-divider'><td colspan='6'>CRASH / HANG POINT (Windows cannot write logs while down)</td></tr>")
                }
                $parts.Add("                </tbody></table>")
            }
            $preMsg = if ($cr.PreEvents.Count -eq 0) { "0 warning/error events logged in the 20 minutes before this crash (excluding startup)." } else { "$($cr.PreEvents.Count) warning/error event(s) in the 20 minutes prior." }
            $parts.Add("                <div style='margin-top:8px;font-size:0.82rem;color:var(--text-muted);'><strong>Pre-crash summary:</strong> " + (& $enc $preMsg) + "</div>")
            $parts.Add("            </div>")
        }
    } else {
        $parts.Add("            <div class='empty-state'>No OS BugCheck or Kernel-Power 41 restarts recorded in the forensics lookback window.</div>")
    }
    $parts.Add("        </div>") # end forensics

    # GPU & APP EVENTS SECTION
    $parts.Add("        <div class='view-section' data-section='gpu-apps' id='sec-gpu-apps'>")
    $parts.Add("            <div class='section-heading'><h2>Non-Fatal GPU Timeouts, Display Drops &amp; App Crashes</h2><span class='section-sub'>Events that froze/reset a display or closed a program without crashing Windows</span></div>")
    if ($cf -and @($cf.GpuDisplayEvents).Count -gt 0) {
        $parts.Add("            <div class='card-item'><table><thead><tr><th>Time</th><th>Category</th><th>Code</th><th>Summary &amp; Plain-English Context</th></tr></thead><tbody>")
        foreach ($ge in (@($cf.GpuDisplayEvents) | Select-Object -First 20)) {
            $appStr = if (@($ge.ActiveApps).Count -gt 0) { " | Active/Faulting apps: " + ($ge.ActiveApps -join ", ") } else { "" }
            $catBadge = if ($ge.Category -match 'Timeout') { 'badge-warning' } elseif ($ge.Category -match 'App') { 'badge-code' } else { 'badge-neutral' }
            $parts.Add("                <tr><td class='timestamp'>$($ge.Time.ToString('yyyy-MM-dd HH:mm:ss'))</td><td><span class='$catBadge'>" + (& $enc $ge.Category) + "</span></td><td><span class='badge-code'>" + (& $enc $ge.Code) + "</span></td><td><div>" + (& $enc ($ge.Summary + $appStr)) + "</div><div style='font-size:0.8rem;color:var(--text-muted);margin-top:3px;'>" + (& $enc $ge.Explanation) + "</div></td></tr>")
        }
        $parts.Add("            </tbody></table></div>")
    } else {
        $parts.Add("            <div class='empty-state'>No non-fatal GPU timeouts, display drops, or user-mode GPU crash dumps in the current window.</div>")
    }
    if ($cf -and @($cf.LiveKernelHistory).Count -gt 0) {
        $parts.Add("            <details class='acc'><summary><span>Full Non-Fatal LiveKernelReport History (14+ Days &mdash; $($cf.LiveKernelHistory.Count) reports)</span><span class='badge-neutral'>Expand</span></summary><div class='acc-body'><table><thead><tr><th>Date</th><th>Summary of Non-Fatal Kernel Reports</th></tr></thead><tbody>")
        foreach ($g in (@($cf.LiveKernelHistory) | Group-Object { $_.Time.ToString('yyyy-MM-dd') } | Sort-Object Name -Descending)) {
            $rowDesc = ((@($g.Group) | Group-Object Description | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join "; ")
            $parts.Add("                <tr><td class='timestamp'>$($g.Name)</td><td>" + (& $enc $rowDesc) + "</td></tr>")
        }
        $parts.Add("            </tbody></table></div></details>")
    }
    $parts.Add("        </div>") # end gpu-apps

    # HARDWARE & STORAGE SECTION
    $parts.Add("        <div class='view-section' data-section='hardware' id='sec-hardware'>")
    $parts.Add("            <div class='section-heading'><h2>Hardware, Storage SMART Health &amp; WHEA</h2><span class='section-sub'>Platform health, displays, storage reliability, and network adapters</span></div>")
    $parts.Add("            <div class='hw-grid'>")
    if ($hw -and $hw.PSObject.Properties['PhysicalDisks'] -and $hw.PhysicalDisks) {
        $pdObj = $hw.PhysicalDisks
        $parts.Add("                <div class='card-item'><strong>Physical Storage Health (SMART &amp; Reliability Counters)</strong>")
        if (@($pdObj.Disks).Count -gt 0) {
            $parts.Add("                <table><thead><tr><th>Drive</th><th>Size</th><th>Bus</th><th>Health</th><th>Wear / Temp</th><th>R/W Errors</th></tr></thead><tbody>")
            foreach ($pd in @($pdObj.Disks)) {
                $wearS = if ($null -ne $pd.Wear) { "$($pd.Wear)%" } else { "n/a" }
                $tempS = if ($null -ne $pd.TemperatureC) { "$($pd.TemperatureC) C" } else { "n/a" }
                $errS  = if ($pd.ReliabilityAvailable) { "$($pd.ReadErrorsUncorrected) / $($pd.WriteErrorsUncorrected)" } else { "n/a" }
                $hlthB = if ($pd.HealthStatus -eq 'Healthy') { "<span class='badge-healthy'>Healthy</span>" } else { "<span class='badge-critical'>" + (& $enc $pd.HealthStatus) + "</span>" }
                $parts.Add("                    <tr><td>" + (& $enc $pd.FriendlyName) + "</td><td>$($pd.SizeGb) GB</td><td>" + (& $enc $pd.BusType) + "</td><td>$hlthB</td><td>$wearS / $tempS</td><td>$errS</td></tr>")
            }
            $parts.Add("                </tbody></table>")
        }
        foreach ($pf in @($pdObj.Findings)) { $parts.Add("                <div class='alert-card alert-critical' style='margin-top:8px;'>" + (& $enc $pf) + "</div>") }
        foreach ($pn in @($pdObj.Notes)) { $parts.Add("                <div style='font-size:0.82rem;color:var(--text-muted);margin-top:6px;'>" + (& $enc $pn) + "</div>") }
        $parts.Add("                </div>")
    }
    $wheaList = if ($hw -and $hw.PSObject.Properties['WheaEvents'] -and $hw.WheaEvents) { @($hw.WheaEvents) } else { @() }
    $parts.Add("                <div class='card-item'><strong>WHEA Hardware Error Log (Last 30 Days)</strong>")
    if ($wheaList.Count -eq 0) {
        $parts.Add("                <div class='empty-state' style='margin-top:10px;'>0 WHEA hardware error events (CPU, memory, PCIe) logged in the last 30 days.</div>")
    } else {
        foreach ($we in ($wheaList | Select-Object -First 10)) {
            $wTs = if ($we.TimeCreated -is [datetime]) { $we.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { 'unknown' }
            $parts.Add("                <div class='alert-card alert-critical' style='margin-top:8px;'>[$wTs] Event $($we.Id) ($($we.Level)): " + (& $enc $we.Message) + "</div>")
        }
    }
    $parts.Add("                </div>")
    $parts.Add("            </div>")

    $parts.Add("            <div class='card-item'><strong>Active Graphics Hardware</strong><table><thead><tr><th>Device Name</th><th>Vendor</th><th>Driver Version</th><th>Driver Date</th><th>Status</th></tr></thead><tbody>" + ($gpuRows -join "`n") + "</tbody></table>$multiGpuNoticeHtml</div>")
    if ($mbRows.Count -gt 0) { $parts.Add("            <div style='margin-top:10px;'>" + ($mbRows -join "`n") + "</div>") }
    $parts.Add("            <div class='hw-grid' style='margin-top:10px;'>")
    $parts.Add("                <div>" + ($displayRows -join "`n") + "</div>")
    $parts.Add("                <div>" + ($networkRows -join "`n") + "</div>")
    $parts.Add("            </div>")
    $parts.Add("            <div class='hw-grid' style='margin-top:10px;'>")
    $parts.Add("                <div>" + ($driverRows -join "`n") + "</div>")
    $parts.Add("                <div>" + ($pnpRows -join "`n") + "</div>")
    $parts.Add("            </div>")
    $parts.Add("        </div>") # end hardware

    # RAW DUMPS & LOGS SECTION
    $parts.Add("        <div class='view-section' data-section='logs' id='sec-logs'>")
    $parts.Add("            <div class='section-heading'><h2>Raw Crash Dumps, Application Logs &amp; System Events</h2><span class='section-sub'>Detailed technical artifacts for debugging</span></div>")
    $parts.Add("            <details class='acc' open><summary><span>1. Inspected Crash Dumps ($($ReportData.Dumps.Count))</span><span class='badge-neutral'>Toggle</span></summary><div class='acc-body'>" + ($dumpRows -join "`n") + "</div></details>")
    $parts.Add("            <details class='acc'><summary><span>2. Game &amp; Steam Logs ($($ReportData.EngineLogs.Count + $ReportData.SteamLogs.Count))</span><span class='badge-neutral'>Toggle</span></summary><div class='acc-body'>" + ($logRows -join "`n") + "</div></details>")
    $parts.Add("            <details class='acc'><summary><span>3. Windows System &amp; Event Log Telemetry</span><span class='badge-neutral'>Toggle</span></summary><div class='acc-body'>" + ($telemRows -join "`n") + "</div></details>")
    $parts.Add("        </div>") # end logs

    # Share box & Toast
    $parts.Add("        <div class='discord-copy-box'>")
    $parts.Add("            <div style='display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;'><strong>Share Summary for Discord / Reddit / Tech Support</strong><button type='button' class='btn btn-primary' onclick='copyDiscordSummary()'>Copy to Clipboard</button></div>")
    $parts.Add("            <textarea id='discordSummaryBox' readonly onclick='this.select()'>$discordText</textarea>")
    $parts.Add("        </div>")
    $parts.Add("        <footer>DriverCheck Diagnostic Suite v4.5.0 &middot; Evidence-Based Crash &amp; Driver Analysis</footer>")
    $parts.Add("    </div>")
    $parts.Add("    <div class='toast' id='toast'></div>")

    $jsBlock = @'
    <script>
    function showToast(msg) {
        var el = document.getElementById('toast');
        if (!el) return;
        el.textContent = msg;
        el.classList.add('show');
        clearTimeout(window._toastTimer);
        window._toastTimer = setTimeout(function() { el.classList.remove('show'); }, 2200);
    }
    function toggleTheme() {
        var html = document.documentElement;
        var next = html.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        if (next === 'light') html.setAttribute('data-theme', 'light');
        else html.removeAttribute('data-theme');
        var btn = document.getElementById('themeBtn');
        if (btn) btn.textContent = next === 'light' ? 'Dark Mode' : 'Light Mode';
    }
    function switchView(view, btn) {
        document.querySelectorAll('.nav-tab').forEach(function(t) {
            t.classList.toggle('active', t.getAttribute('data-view') === view);
        });
        document.querySelectorAll('.view-section').forEach(function(sec) {
            var s = sec.getAttribute('data-section');
            sec.classList.toggle('is-hidden', view !== 'all' && s !== view);
        });
    }
    function filterReport() {
        var inp = document.getElementById('reportFilter');
        var clr = document.getElementById('searchClear');
        var cnt = document.getElementById('filterCount');
        var q = (inp.value || '').trim().toLowerCase();
        if (clr) clr.style.display = q ? 'block' : 'none';
        if (q) switchView('all');
        var matched = 0;
        var items = document.querySelectorAll('.card-item, .alert-card, .acc .card-item, tbody tr');
        items.forEach(function(el) {
            if (el.classList.contains('crash-divider')) return;
            var hit = !q || el.textContent.toLowerCase().indexOf(q) !== -1;
            el.style.display = hit ? '' : 'none';
            if (hit && q) matched++;
        });
        if (q) {
            document.querySelectorAll('details.acc').forEach(function(d) { d.open = true; });
            if (cnt) cnt.textContent = matched + ' match' + (matched === 1 ? '' : 'es');
        } else if (cnt) {
            cnt.textContent = '';
        }
    }
    function clearSearch() {
        var inp = document.getElementById('reportFilter');
        if (inp) { inp.value = ''; filterReport(); inp.focus(); }
    }
    function filterTimeline(cat) {
        document.querySelectorAll('.tl-chip').forEach(function(c) {
            c.classList.toggle('active', c.getAttribute('data-cat') === cat);
        });
        document.querySelectorAll('.tl-item').forEach(function(el) {
            el.style.display = (cat === 'all' || el.getAttribute('data-cat') === cat) ? '' : 'none';
        });
        document.querySelectorAll('.tl-day').forEach(function(d) {
            var n = d.nextElementSibling, any = false;
            while (n && !n.classList.contains('tl-day')) {
                if (n.style.display !== 'none') any = true;
                n = n.nextElementSibling;
            }
            d.style.display = any ? '' : 'none';
        });
    }
    function toggleNoise(tableId, btn) {
        var tbl = document.getElementById(tableId);
        if (!tbl) return;
        var hiding = tbl.classList.toggle('hide-noise');
        btn.textContent = hiding ? 'Show boot & post-reboot entries' : 'Hide boot & post-reboot noise';
    }
    function copyText(txt, toastMsg) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(txt);
        } else {
            var ta = document.createElement('textarea');
            ta.value = txt; document.body.appendChild(ta); ta.select();
            document.execCommand('copy'); document.body.removeChild(ta);
        }
        showToast(toastMsg || 'Copied to clipboard');
    }
    function copyDiscordSummary() {
        var box = document.getElementById('discordSummaryBox');
        if (box) copyText(box.value, 'Diagnostic summary copied to clipboard!');
    }
    function copyCliFix(btn) {
        var cmd = btn.getAttribute('data-cmd') || '';
        copyText(cmd, 'Fix command copied: ' + cmd);
        var hint = btn.querySelector('.copy-hint');
        if (hint) {
            var orig = hint.textContent;
            hint.textContent = '[Copied!]';
            setTimeout(function() { hint.textContent = orig; }, 2000);
        }
    }
    </script>
'@
    $parts.Add($jsBlock)
    $parts.Add("</body>")
    $parts.Add("</html>")

    $fullHtml = $parts -join "`r`n"

    # Global Privacy Pass: Redact user directory paths, Windows User identifiers, and SteamID identifiers
    if ($env:USERPROFILE) {
        $fullHtml = $fullHtml.Replace($env:USERPROFILE, "%USERPROFILE%")
    }
    $fullHtml = $fullHtml -replace '(?i)[a-zA-Z]:\\Users\\[^\\"<>\r\n]+(?=\\)', '%USERPROFILE%'
    $fullHtml = $fullHtml -replace '(?i)[a-zA-Z]:\\Users\\[^\\"<>\r\n\s]+', '%USERPROFILE%'
    $fullHtml = $fullHtml -replace '(?i)User:\s*[^\r\n"<>\\]+\\[^\r\n"<>\.]+', 'User: [REDACTED]'
    $fullHtml = $fullHtml -replace '\[U:\d+:\d+\]', '[U:1:REDACTED]'

    [System.IO.File]::WriteAllText($OutputPath, $fullHtml, [System.Text.Encoding]::UTF8)
    return $OutputPath
}

function Export-DcSupportBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ReportData,

        [Parameter(Mandatory = $false)]
        [string]$ZipPath
    )

    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $tempDir = Join-Path $env:TEMP "DriverCheckBundle_$timestamp"
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

    if (-not $ZipPath) {
        $ZipPath = Join-Path $PWD "DriverCheck_SupportBundle_$timestamp.zip"
    }

    try {
        # 1. Generate HTML Report inside bundle
        $htmlPath = Join-Path $tempDir "CrashReport.html"
        Export-DcHtmlReport -ReportData $ReportData -OutputPath $htmlPath | Out-Null

        # 2. Copy sanitized small logs if present
        $logsDir = Join-Path $tempDir "Logs"
        New-Item -Path $logsDir -ItemType Directory -Force | Out-Null

        foreach ($el in $ReportData.EngineLogs) {
            $localLogPath = $el.FullName
            if ($localLogPath -and $env:USERPROFILE) {
                $localLogPath = $localLogPath.Replace("%USERPROFILE%", $env:USERPROFILE)
            }
            if ($localLogPath -and (Test-Path $localLogPath)) {
                $dest = Join-Path $logsDir "$($el.Engine)_$($el.LogName)"
                $tailLines = Get-Content $localLogPath -Tail 500 -ErrorAction SilentlyContinue
                if ($tailLines) {
                    $sanitized = $tailLines | ForEach-Object {
                        if (Get-Command Protect-DcLogText -ErrorAction SilentlyContinue) {
                            Protect-DcLogText $_
                        } else {
                            $s = $_ -replace '\[U:\d+:\d+\]', '[U:1:REDACTED]'
                            if ($env:USERPROFILE) { $s = $s.Replace($env:USERPROFILE, "%USERPROFILE%") }
                            $s = $s -replace '(?i)[a-zA-Z]:\\Users\\[^\\]+', '%USERPROFILE%'
                            $s -replace '(?i)User:\s*[^\r\n"\\]+\\[^\r\n"\.]+', 'User: [REDACTED]'
                        }
                    }
                    Set-Content -Path $dest -Value $sanitized -Encoding UTF8
                }
            }
        }

        # 2b. Include Crash Forensics text report and recent redacted cdb outputs if available
        if ($ReportData.PSObject.Properties['CrashForensics'] -and $ReportData.CrashForensics) {
            try {
                $cfLines = [System.Collections.Generic.List[string]]::new()
                if ($ReportData.CrashForensics.PlainSummary -and (Get-Command Format-DcPlainSummaryReport -ErrorAction SilentlyContinue)) {
                    foreach ($pl in @(Format-DcPlainSummaryReport -PlainSummary $ReportData.CrashForensics.PlainSummary)) { $cfLines.Add($pl.Text) }
                }
                if (Get-Command Format-DcCrashForensicsReport -ErrorAction SilentlyContinue) {
                    foreach ($fl in @(Format-DcCrashForensicsReport -Forensics $ReportData.CrashForensics)) { $cfLines.Add($fl.Text) }
                }
                if ($cfLines.Count -gt 0) {
                    $cfText = $cfLines -join "`r`n"
                    if ($env:USERPROFILE) { $cfText = $cfText.Replace($env:USERPROFILE, "%USERPROFILE%") }
                    $cfText = $cfText -replace '(?i)[a-zA-Z]:\\Users\\[^\\\r\n]+', '%USERPROFILE%'
                    Set-Content -Path (Join-Path $tempDir "CrashForensics.txt") -Value $cfText -Encoding UTF8
                }
            } catch {}
        }

        $cdbOutFiles = [System.Collections.Generic.List[string]]::new()
        foreach ($d in @($ReportData.Dumps)) {
            if ($d -and $d.PSObject.Properties['RawAnalysisPath'] -and $d.RawAnalysisPath -and (Test-Path -LiteralPath $d.RawAnalysisPath -ErrorAction SilentlyContinue)) {
                $cdbOutFiles.Add($d.RawAnalysisPath)
            }
        }
        if ($cdbOutFiles.Count -gt 0) {
            $cdbDir = Join-Path $logsDir "dump-analysis"
            New-Item -Path $cdbDir -ItemType Directory -Force | Out-Null
            foreach ($cfPath in ($cdbOutFiles | Select-Object -Unique | Select-Object -First 6)) {
                try {
                    $rawTxt = Get-Content -LiteralPath $cfPath -Raw -ErrorAction SilentlyContinue
                    if ($rawTxt) {
                        if ($env:USERPROFILE) { $rawTxt = $rawTxt.Replace($env:USERPROFILE, "%USERPROFILE%") }
                        $rawTxt = $rawTxt -replace '(?i)[a-zA-Z]:\\Users\\[^\\\r\n]+', '%USERPROFILE%'
                        Set-Content -Path (Join-Path $cdbDir (Split-Path $cfPath -Leaf)) -Value $rawTxt -Encoding UTF8
                    }
                } catch {}
            }
        }

        # 3. Create ZIP
        if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
        Compress-Archive -Path "$tempDir\*" -DestinationPath $ZipPath -Force

        Write-Host "[SUCCESS] Support bundle exported: $ZipPath" -ForegroundColor Green
        return $ZipPath
    } finally {
        if (Test-Path $tempDir) {
            Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Export-ModuleMember -Function Export-DcHtmlReport, Export-DcSupportBundle
