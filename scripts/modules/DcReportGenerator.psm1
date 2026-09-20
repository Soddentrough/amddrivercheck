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

            $card = "<div class='card-item'>" +
                "<div class='card-header-row'>" +
                    "<span class='file-name'>&#x1F4C4; $($d.FileName)</span>" +
                    "<span class='timestamp'>$($d.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')) | $($d.SizeMb) MB | $($d.Architecture)</span>" +
                "</div>" +
                "<div class='card-body-row'>" +
                    "<div><strong>Exception:</strong> $excBadge $($d.ExceptionMeaning)</div>" +
                    "<div><strong>Faulting Module:</strong> $modBadge</div>" +
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
        foreach ($us in $telem.UnexpectedShutdowns) {
            $hasTelemIssue = $true
            $telemRows.Add("<div class='alert-card alert-warning'><strong>&#x1F50C; Unexpected Shutdown (Event 6008) [$($us.TimeCreated)]:</strong> Previous system shutdown was unexpected.</div>")
        }
    }
    if (-not $hasTelemIssue) {
        $telemRows.Add("<div class='empty-state'>&#x2705; No WHEA errors, GPU TDR resets, or BSOD bugchecks found in event telemetry.</div>")
    }

    # Build Hardware HTML
    $hw = $ReportData.HardwareHealth
    $gpuRows = [System.Collections.Generic.List[string]]::new()
    if ($hw -and $hw.Gpus) {
        foreach ($g in $hw.Gpus) {
            $gpuBadge = if ($g.IsGeneric) { "<span class='badge-critical'>GENERIC ADAPTER</span>" } else { "<span class='badge-healthy'>ACTIVE</span>" }
            $gpuRows.Add("<tr><td><strong>$($g.Name)</strong></td><td>$($g.Vendor)</td><td>$($g.DriverVersion)</td><td>$($g.DriverDate)</td><td>$gpuBadge</td></tr>")
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
            if ($disp.DetailedTimings -and $disp.DetailedTimings.Count -gt 0) {
                $dtStrings = @()
                foreach ($dt in $disp.DetailedTimings) {
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

    $fastStartupStatusStr = if ($telem -and $telem.FastStartup.FastStartupEnabled) { 'Enabled (Risk)' } else { 'Disabled (Clean)' }
    $gpuNamesStr = if ($hw -and $hw.Gpus) { ($hw.Gpus.Name -join ' | ') } else { 'None' }
    $pnpCountStr = if ($hw -and $hw.PnpIssues) { $hw.PnpIssues.Count } else { 0 }
    $dispSummaryStr = if ($hw -and $hw.Displays) {
        ($hw.Displays | ForEach-Object {
            $riskNotice = if ($_.HasTimingRisk) { " [HAZARD: Scaler/EDID Timing Risk]" } else { "" }
            "$($_.Name) ($($_.ActiveResolution)@$($_.ActiveRefreshRate)Hz)$riskNotice"
        }) -join '; '
    } else { 'None' }

    $discordText = "=== DriverCheck Diagnostic Summary ===`n" +
        "Status:     $($ReportData.RootCauseTitle)`n" +
        "Severity:   $($ReportData.RootCauseSeverity)`n" +
        "Timestamp:  $((Get-Date).ToString('yyyy-MM-dd HH:mm'))`n" +
        "Scan Range: Past $($ReportData.HoursScanned) Hours`n`n" +
        "[Summary]`n$($ReportData.RootCauseGuidance)`n`n" +
        "[Hardware]`n" +
        "GPUs: $gpuNamesStr`n" +
        "Displays: $dispSummaryStr`n" +
        "Fast Startup: $fastStartupStatusStr`n" +
        "PnP Issues: $pnpCountStr`n" +
        "Crash Dumps: $($ReportData.Dumps.Count)"

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
    $parts.Add("        .guidance-box { background: rgba(0, 0, 0, 0.3); border-left: 4px solid var(--green); padding: 12px 16px; margin-top: 12px; border-radius: 0 6px 6px 0; font-size: 0.95rem; }")
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
    $parts.Add("    </style>")
    $parts.Add("</head>")
    $parts.Add("<body>")
    $parts.Add("    <div class='container'>")
    $parts.Add("        <header class='header'>")
    $parts.Add("            <div class='header-title'>")
    $parts.Add("                <h1>DriverCheck Diagnostic Suite</h1>")
    $parts.Add("                <p>Generated on $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) | Scan Window: Past $($ReportData.HoursScanned) Hours</p>")
    $parts.Add("            </div>")
    $parts.Add("            <span class='badge $statusClass'>$statusText</span>")
    $parts.Add("        </header>")
    $parts.Add("        <section class='executive-card'>")
    $parts.Add("            <h2>Executive Root Cause & Actionable Guidance</h2>")
    $parts.Add("            <div class='root-cause'>$($ReportData.RootCauseTitle)</div>")
    $parts.Add("            <p>$($ReportData.RootCauseDescription)</p>")
    $parts.Add("            <div class='guidance-box'>")
    $parts.Add("                <strong>Recommended Next Steps:</strong><br>")
    $parts.Add("                $($ReportData.RootCauseGuidance)")
    $parts.Add("            </div>")
    $parts.Add("        </section>")
    $parts.Add("        <h3 class='section-title'>[TIER 1] Crash Dumps & Exceptions (Primary Ground Truth)</h3>")
    $parts.Add(($dumpRows -join "`n"))
    $parts.Add("        <h3 class='section-title'>[TIER 2] Game & Platform Logs (Secondary Evidence)</h3>")
    $parts.Add(($logRows -join "`n"))
    $parts.Add("        <h3 class='section-title'>[TIER 3] System Logs & Telemetry (Tertiary Telemetry)</h3>")
    $parts.Add(($telemRows -join "`n"))
    $parts.Add("        <h3 class='section-title'>[TIER 4] Hardware & Driver Health (Contextual Audit)</h3>")
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
    $parts.Add("        </div>")
    $parts.Add("        <div style='margin-top: 12px;'>")
    $parts.Add("            <strong>Connected Displays & Monitor EDID Timings:</strong>")
    $parts.Add(($displayRows -join "`n"))
    $parts.Add("        </div>")
    $parts.Add("        <div style='margin-top: 12px;'>")
    $parts.Add("            <strong>Plug and Play Device Health:</strong>")
    $parts.Add(($pnpRows -join "`n"))
    $parts.Add("        </div>")
    $parts.Add("        <div class='discord-copy-box'>")
    $parts.Add("            <strong>Copy Summary for Discord / Reddit / Technical Support</strong>")
    $parts.Add("            <textarea readonly onclick='this.select()'>$discordText</textarea>")
    $parts.Add("        </div>")
    $parts.Add("        <footer>")
    $parts.Add("            DriverCheck Diagnostic Suite v4.1.0 | Evidence-Based Crash Analysis Engine")
    $parts.Add("        </footer>")
    $parts.Add("    </div>")
    $parts.Add("</body>")
    $parts.Add("</html>")

    $fullHtml = $parts -join "`r`n"
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

        # 2. Copy relevant small logs if present
        $logsDir = Join-Path $tempDir "Logs"
        New-Item -Path $logsDir -ItemType Directory -Force | Out-Null

        foreach ($el in $ReportData.EngineLogs) {
            if (Test-Path $el.FullName) {
                $dest = Join-Path $logsDir "$($el.Engine)_$($el.LogName)"
                Get-Content $el.FullName -Tail 500 | Set-Content -Path $dest -Encoding UTF8
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
