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

    # Build Dump HTML
    $dumpRows = [System.Collections.Generic.List[string]]::new()
    if ($ReportData.Dumps.Count -gt 0) {
        foreach ($d in $ReportData.Dumps) {
            $excBadge = if ($d.ExceptionCode) { "<span class='badge-code'>$($d.ExceptionCode)</span>" } else { "<span class='badge-neutral'>N/A</span>" }
            $modBadge = if ($d.FaultingIP) { "<span class='badge-module'>$($d.FaultingIP)</span>" } else { "<span class='badge-neutral'>Unknown</span>" }
            $assertHtml = ""
            if ($d.Assertions.Count -gt 0) {
                $assertHtml = "<div class='assert-box'>" + ($d.Assertions | ForEach-Object { "<div><code>$_</code></div>" } | Out-String) + "</div>"
            }

            $drvBadgeHtml = if ($d.GpuDriverVersion) { "<div><strong>Loaded GPU Driver:</strong> <span class='badge-module'>v$($d.GpuDriverVersion)</span></div>" } else { "" }

            $card = "<div class='card-item'>" +
                "<div class='card-header-row'>" +
                    "<span class='file-name'>&#x1F4C4; $($d.FileName)</span>" +
                    "<span class='timestamp'>$($d.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')) | $($d.SizeMb) MB | $($d.Architecture)</span>" +
                "</div>" +
                "<div class='card-body-row'>" +
                    "<div><strong>Exception:</strong> $excBadge $($d.ExceptionMeaning)</div>" +
                    "<div><strong>Faulting Module:</strong> $modBadge</div>" +
                    $drvBadgeHtml +
                    $assertHtml +
                "</div>" +
            "</div>"
            $dumpRows.Add($card)
        }
    } else {
        $dumpRows.Add("<div class='empty-state'>&#x2705; No crash dump files recorded in monitored directories within the scan window.</div>")
    }

    # Build Engine Logs HTML
    $logRows = [System.Collections.Generic.List[string]]::new()
    if ($ReportData.EngineLogs.Count -gt 0 -or $ReportData.SteamLogs.Count -gt 0) {
        foreach ($el in $ReportData.EngineLogs) {
            $errSnippet = ($el.ErrorLines | Select-Object -First 5 | ForEach-Object { "<div><code>$_</code></div>" }) -join ""
            $card = "<div class='card-item'>" +
                "<div class='card-header-row'>" +
                    "<span class='file-name'>&#x1F3AE; [$($el.Engine)] $($el.LogName)</span>" +
                    "<span class='timestamp'>$($el.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</span>" +
                "</div>" +
                "<div class='code-block'>$errSnippet</div>" +
            "</div>"
            $logRows.Add($card)
        }
        foreach ($sl in $ReportData.SteamLogs) {
            $errSnippet = ($sl.ErrorLines | Select-Object -First 5 | ForEach-Object { "<div><code>$_</code></div>" }) -join ""
            $card = "<div class='card-item'>" +
                "<div class='card-header-row'>" +
                    "<span class='file-name'>&#x2699; [Steam Telemetry] $($sl.LogName)</span>" +
                    "<span class='timestamp'>$($sl.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</span>" +
                "</div>" +
                "<div class='code-block'>$errSnippet</div>" +
            "</div>"
            $logRows.Add($card)
        }
    } else {
        $logRows.Add("<div class='empty-state'>&#x2705; No application or game engine log errors recorded in this timeframe.</div>")
    }

    # Build System Telemetry HTML
    $telemRows = [System.Collections.Generic.List[string]]::new()
    $telem = $ReportData.SystemTelemetry
    $hasTelemIssue = $false
    if ($telem) {
        if ($telem.FastStartup.FastStartupEnabled) {
            $hasTelemIssue = $true
            $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x26A1; Power Configuration:</strong> Windows Fast Startup is ENABLED. Fast Startup saves hybrid kernel session states across shutdowns, frequently causing 0x9F power transition crashes on dual-GPU or updated systems.</div>")
        }
        if ($telem.PciePowerManagement -and $telem.PciePowerManagement.IsEnabled) {
            $hasTelemIssue = $true
            $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x26A1; PCIe Power Configuration:</strong> PCI Express Link State Power Management is <strong>ENABLED ($($telem.PciePowerManagement.ACSettingName))</strong> in plan '$($telem.PciePowerManagement.SchemeName)'. Low-power L0s/L1 bus states during idle or video load cause driver timeouts (TDR 4101) and sleep-wake crashes on PCIe 4.0/5.0 GPUs. Recommendation: Set to <strong>Off</strong>.</div>")
        }
        if ($telem.GraphicsDriverSettings) {
            $gfx = $telem.GraphicsDriverSettings
            $tdrInfo = if ($gfx.TdrDelay) { "TdrDelay: $($gfx.TdrDelay)s" } else { "TdrDelay: Default (2s)" }
            $hagsInfo = "HAGS: $($gfx.HAGSStatus)"
            $telemRows.Add("<div class='alert-card' style='background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3);'><strong>&#x1F3AE; Graphics Driver Subsystem:</strong> $hagsInfo | $tdrInfo</div>")
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
        $mbBadge = if ($mb.IsHealthy) { "<span class='badge-healthy'>HEALTHY</span>" } else { "<span class='badge-warning'>ACTION RECOMMENDED</span>" }
        $biosAgeNotice = if ($mb.BiosAgeYears) { " ($($mb.BiosAgeYears) yrs old)" } else { "" }
        $biosBadge = if ($mb.IsBiosOutdated) { "<span class='badge-warning'>AGING ($($mb.BiosAgeYears) YRS)</span>" } else { "<span class='badge-healthy'>OK</span>" }

        $missingHtml = ""
        if ($mb.MissingControllers.Count -gt 0) {
            $missingList = ($mb.MissingControllers | ForEach-Object { "<li>$_</li>" }) -join ""
            $missingHtml = "<div class='alert-card alert-warning' style='margin-top: 8px;'><strong>&#x26A0; Missing Platform Controllers:</strong><ul style='margin-left: 20px; margin-top: 4px;'>$missingList</ul><span style='font-size: 0.85rem;'>Recommendation: Download and install the latest official chipset driver package from your motherboard support page or AMD.com / Intel.com.</span></div>"
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
                $alertBox = "<div class='alert-card alert-critical' style='margin-top: 8px;'><strong>&#x26A0; DisplayPort Scaler Saturation Hazard:</strong> $reasons<br><span style='font-size: 0.85rem;'>Recommendation: Lower refresh rate to 144Hz or configure CVT-RB in Custom Resolution Utility (CRU) to reduce pixel clock below 580 MHz.</span></div>"
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
            $badge = if ($kd.IsDisabled) { "<span class='badge-healthy'>DISABLED</span>" } elseif ($kd.IsActive) { "<span class='badge-critical'>HAZARD (AUTO-START)</span>" } else { "<span class='badge-warning'>PRESENT</span>" }
            $alert = if ($kd.IsActive -and -not $kd.IsDisabled) {
                "<div class='alert-card alert-critical' style='margin-top: 8px;'><strong>&#x26A0; Conflict Hazard:</strong> $($kd.RiskReason)<br><span style='font-size: 0.85rem;'>Fix: Run <code>.\scripts\Disable-RogueKernelDrivers.ps1</code> or <code>$($kd.FixCommand)</code></span></div>"
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
                $intelNotice = "<div class='alert-card alert-warning' style='margin-top: 6px; font-size: 0.85rem;'><strong>&#x26A0; Intel 2.5G Stability Notice:</strong> Packet Priority & VLAN is enabled on $($net.Name). This is known to cause ARP probe timeouts and socket stalls. Run <code>Repair-EthernetSettings.ps1</code> to disable VLAN tagging.</div>"
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
        $secCards.Add("<div style='margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border);'><strong style='color: var(--yellow); font-size: 1.0rem;'>Other Issues Found ($($ReportData.SecondaryFindings.Count)):</strong>")
        $idx = 2
        foreach ($sf in $ReportData.SecondaryFindings) {
            $sfBadge = if ($sf.Severity -eq "Critical") { "<span class='badge-critical'>CRITICAL</span>" } elseif ($sf.Severity -eq "Warning") { "<span class='badge-warning'>WARNING</span>" } else { "<span class='badge-neutral'>$($sf.Severity)</span>" }
            $sfSteps = if ($sf.PSObject.Properties['Steps']) { $sf.Steps } else { $null }
            $sfActs  = if ($sf.PSObject.Properties['Actions']) { $sf.Actions } else { $null }
            $sfGuidanceFormatted = & $formatGuidanceHtml $sf.Guidance $sfSteps $sfActs
            $secCards.Add("<div class='card-item' style='margin-top: 10px; background: rgba(15, 23, 42, 0.7);'><div class='card-header-row'><span class='file-name'>[$idx] $($sf.Title)</span>$sfBadge</div><div style='font-size: 0.92rem; margin-bottom: 8px;'>$($sf.Description)</div><div class='guidance-box' style='margin-top: 6px; padding: 10px 14px;'><strong>Recommended Fix:</strong>$sfGuidanceFormatted</div></div>")
            $secDiscordLines.Add("  [$idx] [$($sf.Severity)] $($sf.Title) -> $($sf.Guidance)")
            $idx++
        }
        $secCards.Add("</div>")
        $secondaryFindingsHtml = $secCards -join "`n"
        $secondaryDiscordSection = "`n`n[Concurrent / Secondary Findings]`n" + ($secDiscordLines -join "`n")
    }

    $discordText = "=== DriverCheck Diagnostic Summary ===`n" +
        "Status:         $($ReportData.RootCauseTitle)`n" +
        "Severity:       $($ReportData.RootCauseSeverity)`n" +
        "Timestamp:      $((Get-Date).ToString('yyyy-MM-dd HH:mm'))`n" +
        "Scan Range:     $scanRangeDiscord`n`n" +
        "[Summary]`n$($ReportData.RootCauseGuidance)" +
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
    $parts.Add("    <style>")
    $parts.Add("        :root { --bg: #090d16; --surface: #131b2e; --surface-hover: #1a253f; --border: #233052; --text: #e2e8f0; --text-muted: #94a3b8; --cyan: #38bdf8; --magenta: #c084fc; --green: #4ade80; --yellow: #facc15; --red: #f87171; }")
    $parts.Add("        * { box-sizing: border-box; margin: 0; padding: 0; }")
    $parts.Add("        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg); color: var(--text); line-height: 1.6; padding: 24px; }")
    $parts.Add("        .container { max-width: 1040px; margin: 0 auto; }")
    $parts.Add("        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }")
    $parts.Add("        .header-title h1 { font-size: 1.75rem; color: var(--cyan); font-weight: 700; letter-spacing: -0.5px; }")
    $parts.Add("        .header-title p { color: var(--text-muted); font-size: 0.9rem; }")
    $parts.Add("        .badge { display: inline-block; padding: 6px 14px; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }")
    $parts.Add("        .badge-healthy { background: rgba(74, 222, 128, 0.15); color: var(--green); border: 1px solid rgba(74, 222, 128, 0.3); }")
    $parts.Add("        .badge-warning { background: rgba(250, 204, 21, 0.15); color: var(--yellow); border: 1px solid rgba(250, 204, 21, 0.3); }")
    $parts.Add("        .badge-critical { background: rgba(248, 113, 113, 0.15); color: var(--red); border: 1px solid rgba(248, 113, 113, 0.3); }")
    $parts.Add("        .badge-code { background: rgba(192, 132, 252, 0.2); color: var(--magenta); padding: 2px 6px; border-radius: 4px; font-family: monospace; }")
    $parts.Add("        .badge-module { background: rgba(56, 189, 248, 0.15); color: var(--cyan); padding: 2px 6px; border-radius: 4px; font-family: monospace; }")
    $parts.Add("        .badge-neutral { background: var(--surface); color: var(--text-muted); padding: 2px 6px; border-radius: 4px; }")
    $parts.Add("        .executive-card { background: linear-gradient(135deg, rgba(35, 48, 82, 0.5) 0%, rgba(19, 27, 46, 0.8) 100%); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3); }")
    $parts.Add("        .executive-card h2 { font-size: 1.3rem; margin-bottom: 8px; color: var(--cyan); }")
    $parts.Add("        .executive-card .root-cause { font-size: 1.15rem; font-weight: 600; color: #fff; margin-bottom: 12px; }")
    $parts.Add("        .guidance-box { background: rgba(0, 0, 0, 0.3); border-left: 4px solid var(--green); padding: 14px 18px; margin-top: 12px; border-radius: 0 8px 8px 0; font-size: 0.95rem; }
        .guidance-list { margin: 8px 0 4px 20px; padding: 0; list-style-type: disc; }
        .guidance-list li { margin-bottom: 8px; line-height: 1.55; color: #e2e8f0; }
        .guidance-list li:last-child { margin-bottom: 0; }
        .guidance-list li strong { color: var(--green); }
        .action-pill-row { margin-top: 12px; padding-top: 10px; border-top: 1px dashed rgba(74, 222, 128, 0.25); display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
        .action-pill-label { font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--green); margin-right: 4px; }
        .action-pill { display: inline-flex; align-items: center; gap: 6px; background: rgba(74, 222, 128, 0.12); border: 1px solid rgba(74, 222, 128, 0.35); color: #bbf7d0; padding: 6px 12px; border-radius: 6px; font-size: 0.82rem; font-weight: 600; cursor: pointer; font-family: inherit; transition: all 0.15s ease; }
        .action-pill:hover { background: rgba(74, 222, 128, 0.25); border-color: var(--green); transform: translateY(-1px); }
        .action-pill .copy-hint { font-size: 0.72rem; color: var(--green); opacity: 0.85; margin-left: 2px; }
        .action-pill code { background: rgba(0, 0, 0, 0.4); color: var(--cyan); padding: 1px 5px; border-radius: 4px; font-family: monospace; font-size: 0.78rem; }")
    $parts.Add("        .section-title { font-size: 1.15rem; margin: 24px 0 12px 0; color: var(--magenta); display: flex; align-items: center; gap: 8px; }")
    $parts.Add("        .card-item { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; margin-bottom: 12px; }")
    $parts.Add("        .card-header-row { display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 0.95rem; }")
    $parts.Add("        .file-name { font-weight: 600; color: var(--yellow); }")
    $parts.Add("        .timestamp { color: var(--text-muted); font-size: 0.85rem; font-family: monospace; }")
    $parts.Add("        .code-block { background: #050811; padding: 10px 14px; border-radius: 6px; font-family: Consolas, Monaco, monospace; font-size: 0.85rem; color: #cbd5e1; overflow-x: auto; margin-top: 6px; }")
    $parts.Add("        .empty-state { background: var(--surface); border: 1px dashed var(--border); border-radius: 8px; padding: 14px 18px; color: var(--green); font-size: 0.95rem; }")
    $parts.Add("        .alert-card { padding: 12px 16px; border-radius: 8px; margin-bottom: 10px; font-size: 0.95rem; }")
    $parts.Add("        .alert-critical { background: rgba(248, 113, 113, 0.15); border: 1px solid rgba(248, 113, 113, 0.4); color: #fecaca; }")
    $parts.Add("        .alert-warning { background: rgba(250, 204, 21, 0.15); border: 1px solid rgba(250, 204, 21, 0.4); color: #fef08a; }")
    $parts.Add("        table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.9rem; }")
    $parts.Add("        th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); }")
    $parts.Add("        th { color: var(--cyan); font-weight: 600; }")
    $parts.Add("        tr:hover { background: var(--surface-hover); }")
    $parts.Add("        .discord-copy-box { margin-top: 32px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }")
    $parts.Add("        .discord-copy-box textarea { width: 100%; height: 120px; background: #050811; border: 1px solid var(--border); border-radius: 6px; color: #94a3b8; padding: 10px; font-family: monospace; font-size: 0.85rem; margin-top: 8px; resize: vertical; }")
    $parts.Add("        footer { margin-top: 40px; border-top: 1px solid var(--border); padding-top: 16px; text-align: center; color: var(--text-muted); font-size: 0.85rem; }")
    $parts.Add("        .spec-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; margin-bottom: 24px; }")
    $parts.Add("        .spec-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }")
    $parts.Add("        .spec-label { font-size: 0.75rem; text-transform: uppercase; color: var(--cyan); font-weight: 600; letter-spacing: 0.5px; }")
    $parts.Add("        .spec-value { font-size: 0.92rem; font-weight: 600; color: #fff; margin-top: 3px; word-break: break-word; }")
    $parts.Add("        .filter-input { width: 100%; box-sizing: border-box; background: #050811; border: 1px solid var(--border); border-radius: 8px; color: #fff; padding: 12px 16px; margin: 16px 0; font-size: 0.95rem; outline: none; }")
    $parts.Add("        .filter-input:focus { border-color: var(--cyan); }")
    $parts.Add("    </style>")
    $parts.Add("</head>")
    $parts.Add("<body>")
    $parts.Add("    <div class='container'>")
    $parts.Add("        <header class='header'>")
    $parts.Add("            <div class='header-title'>")
    $parts.Add("                <h1>DriverCheck Diagnostic Suite</h1>")
    $mbHeaderInfo = if ($hw -and $hw.Motherboard) { " | System: $($hw.Motherboard.MotherboardManufacturer) $($hw.Motherboard.MotherboardProduct)" } else { "" }
    $scanInfo = if ($ReportData.ScanMode -eq "InvestigateResolved") {
        "Mode: Historical Resolution Analysis (Past $($ReportData.IncidentAnchor.LookbackDays) Days)"
    } elseif ($ReportData.ScanMode -eq "LatestIncident" -and $ReportData.IncidentAnchor) {
        "Mode: Latest Incident (Anchored: $($ReportData.IncidentAnchor.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')) - $($ReportData.IncidentAnchor.AgeDescription))"
    } elseif ($ReportData.ScanMode -eq "LatestIncidentClean") {
        "Mode: Latest Incident (Scanned past $($ReportData.IncidentAnchor.LookbackDays) days: Clean - No crashes recorded)"
    } elseif ($ReportData.ScanMode -eq "AllIncidents") {
        "Mode: Full Incident History (Past $($ReportData.HoursScanned) Hours)"
    } else {
        "Scan Window: Past $($ReportData.HoursScanned) Hours"
    }
    $parts.Add("                <p>Generated on $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) | $scanInfo$mbHeaderInfo</p>")
    $parts.Add("            </div>")
    $parts.Add("            <span class='badge $statusClass'>$statusText</span>")
    $parts.Add("        </header>")

    $parts.Add("        <div class='spec-grid'>")
    $parts.Add("            <div class='spec-card'><div class='spec-label'>Processor</div><div class='spec-value'>$cpuVal</div></div>")
    $parts.Add("            <div class='spec-card'><div class='spec-label'>System Memory</div><div class='spec-value'>$ramVal</div></div>")
    $parts.Add("            <div class='spec-card'><div class='spec-label'>Graphics Hardware</div><div class='spec-value'>$gpuVal</div></div>")
    $parts.Add("            <div class='spec-card'><div class='spec-label'>Resizable BAR / SAM</div><div class='spec-value'>$rebarVal</div></div>")
    $parts.Add("            <div class='spec-card'><div class='spec-label'>Motherboard & Firmware</div><div class='spec-value'>$mbVal$biosVal</div></div>")
    $parts.Add("        </div>")
    $parts.Add("        <input type='text' class='filter-input' id='reportFilter' placeholder='Search report, events, drivers, exception codes, and error logs...' onkeyup='filterReport()'>")
    $parts.Add("        <section class='executive-card'>")
    $parts.Add("            <h2>Crash Check Summary & How to Fix It</h2>")
    $parts.Add("            <div class='root-cause'>Main Issue: $($ReportData.RootCauseTitle)</div>")
    $parts.Add("            <p>$($ReportData.RootCauseDescription)</p>")
    $parts.Add("            <div class='guidance-box'>")
    $parts.Add("                <strong>How to Fix:</strong>")
    $parts.Add("                $primaryGuidanceHtml")
    $parts.Add("            </div>")
    if ($secondaryFindingsHtml) {
        $parts.Add($secondaryFindingsHtml)
    }
    $parts.Add("        </section>")
    if ($resolvedRows.Count -gt 0) {
        $parts.Add("        <h3 class='section-title'>Past Crash History & What Fixed It</h3>")
        $parts.Add(($resolvedRows -join "`n"))
    }
    $parts.Add("        <h3 class='section-title'>1. Crash Dumps</h3>")
    $parts.Add(($dumpRows -join "`n"))
    $parts.Add("        <h3 class='section-title'>2. Game & Steam Logs</h3>")
    $parts.Add(($logRows -join "`n"))
    $parts.Add("        <h3 class='section-title'>3. Windows System & Event Logs</h3>")
    $parts.Add(($telemRows -join "`n"))
    $parts.Add("        <h3 class='section-title'>4. Hardware & Driver Status</h3>")
    if ($mbRows.Count -gt 0) {
        $parts.Add("        <div style='margin-bottom: 12px;'>")
        $parts.Add("            <strong>Motherboard, BIOS & Platform Chipset Drivers:</strong>")
        $parts.Add(($mbRows -join "`n"))
        $parts.Add("        </div>")
    }
    $parts.Add("        <div class='card-item'>")
    $parts.Add("            <strong>Active Graphics Hardware:</strong>")
    $parts.Add("            <table>")
    $parts.Add("                <thead>")
    $parts.Add("                    <tr><th>Device Name</th><th>Vendor</th><th>Driver Version</th><th>Driver Date</th><th>Status</th></tr>")
    $parts.Add("                </thead>")
    $parts.Add("                <tbody>")
    $parts.Add(($gpuRows -join "`n"))
    $parts.Add("                </tbody>")
    $parts.Add("            </table>")
    if ($multiGpuNoticeHtml) {
        $parts.Add("            $multiGpuNoticeHtml")
    }
    $parts.Add("        </div>")
    $parts.Add("        <div style='margin-top: 12px;'>")
    $parts.Add("            <strong>Connected Displays & Monitor EDID Timings:</strong>")
    $parts.Add(($displayRows -join "`n"))
    $parts.Add("        </div>")
    $parts.Add("        <div style='margin-top: 12px;'>")
    $parts.Add("            <strong>Legacy & Third-Party Kernel I/O Driver Security Audit:</strong>")
    $parts.Add(($driverRows -join "`n"))
    $parts.Add("        </div>")
    $parts.Add("        <div style='margin-top: 12px;'>")
    $parts.Add("            <strong>Plug and Play Device Health:</strong>")
    $parts.Add(($pnpRows -join "`n"))
    $parts.Add("        </div>")
    $parts.Add("        <div style='margin-top: 12px;'>")
    $parts.Add("            <strong>Network Adapters & Link Stability:</strong>")
    $parts.Add(($networkRows -join "`n"))
    $parts.Add("        </div>")
    $parts.Add("        <div class='discord-copy-box'>")
    $parts.Add("            <strong>Copy Summary for Discord / Reddit / Technical Support</strong>")
    $parts.Add("            <textarea readonly onclick='this.select()'>$discordText</textarea>")
    $parts.Add("        </div>")
    $parts.Add("        <footer>")
    $parts.Add("            DriverCheck Diagnostic Suite v4.5.0 | Evidence-Based Crash Analysis Engine")
    $parts.Add("        </footer>")
    $parts.Add("    </div>")
    $parts.Add("    <script>")
    $parts.Add("    function filterReport() {")
    $parts.Add("        var q = document.getElementById('reportFilter').value.toLowerCase();")
    $parts.Add("        var items = document.querySelectorAll('.card-item, .alert-card, tbody tr');")
    $parts.Add("        items.forEach(function(el) {")
    $parts.Add("            var txt = el.textContent.toLowerCase();")
    $parts.Add("            el.style.display = txt.indexOf(q) !== -1 ? '' : 'none';")
    $parts.Add("        });")
    $parts.Add("    }")
    $parts.Add("    function copyCliFix(btn) {
        var cmd = btn.getAttribute('data-cmd') || '';
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(cmd);
        } else {
            var ta = document.createElement('textarea');
            ta.value = cmd;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        }
        var hint = btn.querySelector('.copy-hint');
        if (hint) {
            var orig = hint.textContent;
            hint.textContent = '[Copied to Clipboard!]';
            hint.style.color = '#fff';
            setTimeout(function() { hint.textContent = orig; hint.style.color = ''; }, 2000);
        }
    }
    </script>")
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
