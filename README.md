# DriverCheck — Game & PC Crash Troubleshooter (`drivercheck`)

> **Windows PC & game crash diagnostics.** Find the cause of game crashes, GPU driver timeouts (TDR 4101 / 0x141), black screens, network drops, and unexpected reboots, and apply targeted fixes directly from the terminal.

---

## Quick Start

### Option 1: Interactive Menu (`Run-Diagnostics.bat`)
1. Download and extract the latest release package.
2. Double-click **`Run-Diagnostics.bat`**.
3. Press **`[1]`** (**Crash check and Report**).
4. An **HTML Report** (`CrashReport_<timestamp>.html`) will open in your browser, and the terminal will display an interactive menu of any recommended fixes you can apply immediately.

```text
========================================================================
  DriverCheck - Game & PC Crash Troubleshooter (v4.5.0)
========================================================================

  [1] Crash check and Report (Recommended)
  [2] Check full crash history
  [3] Create support ZIP (for Discord / tech support)
  [4] Check motherboard, chipset, and device drivers
  [5] Check monitor and refresh rate settings
  [6] Check GPU driver status and version
  [7] Stop Windows Update from overwriting GPU drivers
  [8] Check power and sleep settings
  [9] Check network connection and drops
  [M] Fixes and cleanup tools
  [0] Exit
========================================================================
```

Selecting Option **`[1]`** scans backward up to 30 days to locate the most recent crash or driver timeout, correlates Windows event logs around that timestamp, opens the HTML report, and lets you run recommended fixes directly from the terminal. Option **`[2]`** scans all incidents across the past 30 days.

### Option 2: PowerShell Command Line
Run directly from PowerShell (no administrator privileges required for scanning):

```powershell
# Default: Crash check and HTML report (with interactive fix prompt)
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -ExportHtml -OpenReport

# Investigate Resolved Historical Timeouts (Clusters past episodes & correlates what fixed them)
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -InvestigateResolved -ExportHtml -OpenReport

# Full Incident History Scan (Past 30 Days)
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -AllIncidents -ExportHtml

# Create Support Bundle ZIP (Report + Sanitized Logs for Reddit/Discord)
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -ExportZip

# JSON Export for automated pipelines or CI
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -ExportJson -Quiet
```

---

## What `drivercheck` Checks & Reports On

`drivercheck` checks crash dumps, game logs, Windows event logs, and hardware configuration:

| Diagnostic Area | Checks Performed |
| :--- | :--- |
| **Windows Driver Overwrites** | • Checks Windows Update driver searching policy (`SearchOrderConfig`).<br>• Checks Windows Quality Update driver exclusion policies (`ExcludeWUDriversInQualityUpdate`) to see if Windows Update is replacing GPU drivers with older OEM versions. |
| **Mismatched & Desynced Drivers** | • Detects **Dual-GPU driver version mismatch** between discrete AMD Radeon GPUs and integrated CPU graphics (a common cause of `atieclxx.exe` crashes and `0x9F` sleep hangs).<br>• Detects generic display adapter fallbacks (Microsoft Basic Display Adapter).<br>• Identifies AMD Software installation type (Driver Only vs Adrenalin Full) and active AMD Crash Defender services. |
| **Recent Windows Updates & Hotfixes** | • Queries Windows Update Agent history (filtering out daily Defender definition updates) for recently installed Windows Quality Updates and driver packages.<br>• Checks installed Windows Hotfixes (`Win32_QuickFixEngineering`) to correlate new crashes or resolved issues with recent updates. |
| **Historical Timeout Resolution Tracking (`-InvestigateResolved`)** | • Reconstructs historical timeout/crash episodes (`[T_first .. T_last]`) across up to 365 days using Event Logs, `WER\ReportArchive`, `LiveKernelReports`, and minidump `VS_FIXEDFILEINFO` module versions.<br>• Correlates the last incident (`T_last`) against timestamped GPU/chipset driver installs (`Kernel-PnP`, `setupapi.dev.log`, `DriverStore\FileRepository`), BIOS updates, Windows Quality Updates, and registry/power settings (`TdrDelay`, PCIe ASPM, Fast Startup, ULPS, disabled kernel drivers) to show what changed when past timeouts stopped. |
| **Windows Event Logs (Crashes & Timeouts)** | • **GPU Driver Resets**: Display driver timeouts (Event `4101` / `0x141` / `0x117` / `0xA1000001` / `VIDEO_TDR_ERROR` / `0x193`).<br>• **PCIe Bus & Riser Errors**: `WHEA-Logger` PCIe Root Port link communication faults (Event `17`).<br>• **Kernel BugChecks**: System BSOD crash codes (`WER-SystemErrorReporting` Event `1001`).<br>• **Unexpected Shutdowns & Power Cuts**: Kernel-Power Event `41` and Event `6008`.<br>• **Virtual Memory Exhaustion**: Windows commit limit / pagefile exhaustion (`Resource-Exhaustion-Detector` Event `2004`).<br>• **Network Drops & Port Exhaustion**: NCSI connectivity drops (Event `4042`), PCI bus device resets (Event `1`), TCP/IP UDP ephemeral port exhaustion (Event `4266`), and Wi-Fi failovers. |
| **Application & Binary Crash Dumps** | • Binary minidump parser (`MDMP`) across Windows Kernel BSODs (`C:\Windows\Minidump`), GPU watchdog live dumps (`C:\Windows\LiveKernelReports`), User-Mode WER dumps (`%LOCALAPPDATA%\CrashDumps`), Steam dumps (`Steam\dumps`), Unreal Engine (`Saved\Crashes`), and Unity.<br>• Extracts Exception Codes (`0xC0000005`, `0x887A0006`, `0xC0000409`, `0x00000000`), faulting module addresses, `VS_FIXEDFILEINFO` loaded driver/module versions, and assertion strings.<br>• Detects stuck background processes (such as headless `steam.exe` blocking relaunch). |
| **Motherboard, BIOS & Chipset Drivers** | • Checks motherboard manufacturer, model, and BIOS release date (flags firmware >3 years old).<br>• Checks AMD Chipset Software / Intel Chipset Device Software versions.<br>• Verifies platform controller status (AMD GPIO, I2C, PCI Device Driver, PSP, 3D V-Cache / Intel MEI).<br>• Scans Plug and Play (PnP) devices for missing drivers (Code 28) and device errors (Code 43). |
| **Display EDID Timings & Scaler Bandwidth** | • Parses binary EDID Detailed Timing Descriptors (DTDs) across HDMI and DisplayPort.<br>• Calculates pixel clocks (MHz) and vertical blanking lines to flag factory overclocks (such as 1440p 165Hz with vertical blanking >1500 lines) that exceed DisplayPort 1.2a scaler bandwidth and cause brief black screens without TDR events. |
| **Legacy Kernel I/O Driver Check** | • Scans for legacy direct port I/O drivers (`inpoutx64.sys`, `WinRing0x64.sys`, `ene.sys`, `AsrOmgDrv.sys`, `gdrv.sys`) installed by RGB or hardware monitoring utilities.<br>• Identifies conflicts with anti-cheat software (Easy Anti-Cheat, BattlEye, Vanguard) and Windows Memory Integrity that cause `INVALID_KERNEL_HANDLE (0x93)` BSODs or freezes. |
| **Power & PCIe ASPM Link States** | • Checks Windows **Fast Startup** (`HiberbootEnabled`), which can cause `0x9F` sleep/wake crashes.<br>• Checks **PCIe Link State Power Management (ASPM)** across active power plans, identifying low-power link states that can trigger GPU driver timeouts (TDR 4101) during idle or bursty loads. |

---

## Common Symptoms & What They Point To

| Symptom | Typical Causes Checked |
| :--- | :--- |
| **GPU Driver Timeout (TDR 4101 / 0x141 / 0x193)** | PCIe ASPM wake latency, corrupted shader caches, short `TdrDelay` on wake, or dual-GPU driver mismatch. |
| **Black Screen for 2–3s (No crash dump)** | DisplayPort 1.2a scaler bandwidth limit / high EDID vertical blanking (>1500 lines). |
| **Game Freezes with Audio Still Playing** | Anti-cheat conflict with legacy RGB/fan kernel I/O drivers (`inpoutx64.sys`, `WinRing0`, `ene.sys`, `0x93`). |
| **Game Closes to Desktop Without Error** | Steam watchdog cross-thread pipe stall (`pipes.cpp`), engine assertions, or Ethernet link drops. |
| **PC Instantly Reboots or Powers Off** | Kernel-Power Event 41 (BugcheckCode 0), PSU transient power trips, or Fast Startup state issues. |
| **Out-of-Memory / D3D Device Lost** | Windows commit limit exhaustion (Event 2004) or disabled/undersized pagefile. |
| **BSOD 0x9F DRIVER_POWER_STATE_FAILURE** | Dual-GPU driver mismatch (AMD iGPU vs dGPU) or sleep/wake power transition failure with Fast Startup. |

---

## Diagnostic Report & Interactive Fixes

Running `drivercheck` provides:

1. **Crash Check Summary & How to Fix It**:
   Primary and secondary findings ranked by evidence, with numbered steps and an interactive terminal prompt to apply recommended fixes immediately.
2. **Detailed Evidence Breakdown**:
   Exception codes (`0xC0000005`, `0x887A0006`, `0x141`, `0x193`), faulting modules, assertion strings, and correlated Windows event logs.
3. **Hardware & Driver Status**:
   Motherboard BIOS age, chipset driver versions, EDID monitor timings, PCIe power settings, network adapter health, and active GPU configuration.
4. **Support Summary Export**:
   A pre-formatted summary block at the bottom of the HTML report that can be copied for **Discord** or **Reddit**, plus clickable buttons to copy individual fix commands.

---

## Sharing Results for Troubleshooting

To share your diagnostic results:

1. **Clipboard Summary**: Scroll to the bottom of the HTML report and click the **"Copy Summary for Discord / Reddit / Technical Support"** box.
2. **Support ZIP**: Select Option **`[3]`** in `Run-Diagnostics.bat` (or run `-ExportZip`). This creates `DriverCheck_SupportBundle_<timestamp>.zip` containing the HTML report and sanitized log excerpts.

### Privacy & Redaction
* **100% Local**: No data is sent over the network.
* **Automatic Redaction**: Reports, JSON exports, and support bundles redact:
  * Windows usernames and user profile paths (`C:\Users\<username>` → `%USERPROFILE%`)
  * Wi-Fi network SSIDs (`[Redacted Wi-Fi Network]`)
  * Steam Account IDs (`[U:1:REDACTED]`)
  * Possessive names on Bluetooth audio devices

---

## Standalone Scripts (`scripts/`)

Each script in `scripts/` can also be run individually:

| Script | Area | Description |
| :--- | :--- | :--- |
| **`Inspect-CrashDumps.ps1`** | Crash Dumps | Binary inspector for BSOD, LiveKernelReports, WER, Steam, Unreal, and Unity minidumps. |
| **`Inspect-GameLogs.ps1`** | Logs | Scans Unreal, Unity, idTech, Source 2, and Godot logs for errors and assertions. |
| **`Inspect-SteamLogs.ps1`** | Logs | Analyzes Steam IPC pipes, browser cache errors, and connection drops. |
| **`Get-PnpDeviceDiagnostics.ps1`** | Hardware | Checks devices for missing drivers (Code 28) and errors (Code 43). |
| **`Get-MotherboardAndChipsetDiagnostics.ps1`** | Hardware | Checks motherboard model, BIOS version/date, and chipset drivers (AMD/Intel). |
| **`Get-GPUDriverDiagnostics.ps1`** | GPU | Checks GPU driver status/version and Windows Update driver overwrite settings. |
| **`Get-DisplayDiagnostics.ps1`** | Display | Checks connected monitors, EDID timings, and DisplayPort bandwidth limits. |
| **`Get-PowerAndSleepDiagnostics.ps1`** | Power | Checks Windows Fast Startup, unexpected shutdowns (6008), and sleep/wake history. |
| **`Get-BluetoothDiagnostics.ps1`** | Peripherals | Checks Bluetooth radios, controllers, and connection resets. |
| **`Get-NetworkDiagnostics.ps1`** | Network | Checks network adapter speed, duplex settings, PCI resets, and link drops. |
| **`Get-WindowsUpdateHistory.ps1`** | System | Lists recently installed Windows Quality Updates and driver updates. |
| **`Clean-ShaderCache.ps1`** | Fix / Cleanup | Clears DirectX, AMD (`DxCache`/`DxcCache`/`VkCache`), and NVIDIA shader caches. |
| **`Clean-GameConfig.ps1`** | Fix / Cleanup | Clears stuck game crash locks and shader caches (creates `.bak` backups first). |
| **`Clean-SteamCache.ps1`** | Fix / Cleanup | Clears the Steam browser cache (`%LOCALAPPDATA%\Steam\htmlcache`). |
| **`Repair-EthernetSettings.ps1`** | Fix / Cleanup | Disables Packet Priority & VLAN on Intel/Realtek adapters while keeping link speed, and expands UDP ports. |
| **`Repair-PciePowerSettings.ps1`** | Fix / Cleanup | Turns off PCIe Link State Power Management (ASPM) on the active power plan. |
| **`Repair-GpuSleepSettings.ps1`** | Fix / Cleanup | Sets GPU watchdog timeout (`TdrDelay = 8s`) for 4K / HDMI 2.1 display wake stability. |
| **`Disable-RogueKernelDrivers.ps1`** | Fix / Cleanup | Disables conflicting legacy kernel I/O drivers (`inpoutx64`, `winring0`, etc.). |

---

## Safety & Backups

All diagnostic scans are **read-only**. When you choose to run a fix, the following safeguards apply:

* **Automatic Backups**: Registry, power plan, network adapter, and service state changes are backed up to `%LOCALAPPDATA%\DriverCheck\Backups` before changes are applied (and can be restored with `Restore-DcRemediationState`). Game configuration cleanup (`Clean-GameConfig.ps1`) creates `.bak` file copies in the same folder.
* **Preserved Link Speed & Power Efficiency**: `Repair-EthernetSettings.ps1` preserves your active negotiated Ethernet link speed by default, and `Repair-GpuSleepSettings.ps1` extends `TdrDelay` to 8 seconds without disabling GPU sleep states.
* **Non-Destructive Driver Disabling**: `Disable-RogueKernelDrivers.ps1` sets legacy driver services to `disabled` via Service Control Manager (`sc.exe`) without deleting files.

---

## System Requirements

* **Operating System:** Windows 10 or Windows 11 (64-bit or 32-bit).
* **PowerShell:** Windows PowerShell 5.1 (included with Windows) or PowerShell 7+.
* **Permissions:** Standard user permissions are sufficient for all scans, reports, and cache cleanup. Administrator permissions are only needed when applying system-level fixes (such as network adapter settings, UDP port range expansion, or Windows Update driver policies).
