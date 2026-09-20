# Automated Game & System Crash Diagnostic Suite (`drivercheck`)

> **Evidence-based Windows PC gaming diagnostics.** Pinpoint the exact root cause of game crashes, GPU driver timeouts (TDR 4101), black screens, and sudden reboots in 30 seconds — without guessing, wiping configs, or blindly reinstalling Windows.

---

## ⚡ Quick Start (30 Seconds)

### Option 1: Interactive Launcher (Recommended for Gamers)
1. Download and extract the latest release package.
2. Double-click **`Run-Diagnostics.bat`**.
3. Press **`[1]`** (Full Crash Diagnostics + Open HTML Report).
4. A dark-mode **HTML Report** (`CrashReport_<timestamp>.html`) will generate and automatically open in your default browser.

```text
========================================================================
  AUTOMATED GAME & SYSTEM CRASH DIAGNOSTIC SUITE (v4.4.0)
  Evidence-Based Engine (Crash Dumps, Logs, Telemetry, Hardware)
========================================================================

  [1] Full Crash Diagnostics + Open HTML Report (Recommended)
  [2] Quick Scan (Past 24 Hours)
  [3] Deep Scan (Past 7 Days)
  [4] Export Support Bundle (HTML Report + ZIP for Discord/Support)
  [5] Motherboard, Chipset Drivers & PnP Hardware Health Audit
  [6] Display, EDID Timings & DP Scaler Saturation Audit
  [7] GPU Driver Health & Downgrade Prevention Audit
  [8] Apply GPU Downgrade Protection (Lock Windows Update Drivers)
  [9] Power, Fast Startup & Sleep Transition Audit
  [10] Maintenance & Cache Cleaning Tools
  [0] Exit
========================================================================
```

### Option 2: PowerShell CLI (Power Users & Tech Support)
Run directly from PowerShell (no administrator privileges required for scanning):

```powershell
# Standard 48-Hour Diagnostic Scan & Open HTML Report
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -ExportHtml -OpenReport

# Deep Scan (Past 7 Days)
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -DeepScan -ExportHtml

# Create Support Bundle ZIP (Report + Sanitized Logs for Reddit/Discord)
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -ExportZip

# JSON Export for automated pipelines or CI
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -ExportJson -Quiet
```

---

## 🎯 What Symptoms Does This Diagnose?

| Symptom | Detected Root Causes & Diagnostic Check |
| :--- | :--- |
| **GPU Driver Timeout (TDR 4101 / 0x141)** | PCIe ASPM bus wake latency, shader compiler crash loops, short TdrDelay, or dual-GPU driver desync. |
| **Black Screen for 2–3s (No crash dump)** | DisplayPort 1.2a scaler saturation / bloated EDID factory vertical blanking (>1500 lines) exceeding monitor scaler limits. |
| **Game Freezes with Audio Still Playing** | Anti-cheat collision with legacy RGB/fan kernel I/O drivers (`inpoutx64.sys`, `WinRing0`, `ene.sys`, `0x93`). |
| **Silent Game Crash to Desktop** | Steam watchdog cross-thread pipe kill (`pipes.cpp`), engine unhandled assertions, or Intel 2.5GbE ARP link drops. |
| **PC Instantly Reboots or Powers Off** | Kernel-Power Event 41 (BugcheckCode 0), PSU transient spike trips, or Fast Startup hybrid session corruption. |
| **Out-of-Memory / D3D Device Lost** | Windows commit limit exhaustion (Event 2004) or missing/disabled System-Managed Pagefile. |
| **BSOD 0x9F DRIVER_POWER_STATE_FAILURE** | Dual-GPU driver desync (AMD iGPU vs dGPU) or sleep/wake power transition failure with Fast Startup. |
| **Micro-Stuttering & Input Lag Spikes** | Background Windows Quality Updates, Bluetooth RF interference, or uninitialized motherboard chipset controllers. |

---

## 📊 What You Get: Diagnostic Report

Running `drivercheck` generates a self-contained, responsive HTML report featuring:

1. **Executive Root Cause & Actionable Guidance**:
   Direct, evidence-backed conclusion with step-by-step resolution instructions (no vague "reinstall Windows" suggestions).
2. **Tiered Evidence Breakdown**:
   Exact exception codes (`0xC0000005`, `0x887A0006`), faulting DLLs, binary assertion strings, and correlated Windows event logs.
3. **Hardware & Configuration Audit**:
   Motherboard BIOS age (>3 yrs flagged), AMD/Intel platform chipset driver health, EDID monitor timings, PCIe power states, and active GPU configuration.
4. **1-Click Community Tech Support Export**:
   Pre-formatted markdown block ready to copy and paste directly to **Reddit** (r/AMDHelp, r/techsupport) or **Discord**.

---

## 💬 Sharing for Community Tech Support

When asking for help online, you never need to screenshot multiple windows:

1. **Clipboard Summary**: Scroll to the bottom of your HTML report and click the **"Copy Summary for Discord / Reddit"** box.
2. **Support Bundle ZIP**: Select Option **`[4]`** in `Run-Diagnostics.bat` (or run `-ExportZip`). This creates a small `DriverCheck_SupportBundle_<timestamp>.zip` containing your HTML report and engine log excerpts.

### 🔒 Privacy Guarantee
* **100% Offline & Local**: No data is ever sent to external servers or telemetry endpoints.
* **Automated PII Redaction**: Diagnostic reports, JSON exports, and support bundles automatically redact personal identifiers:
  * Windows usernames and user profile paths (`C:\Users\<username>` → `%USERPROFILE%`)
  * Personal Wi-Fi network SSIDs (`[Redacted Wi-Fi Network]`)
  * Steam Account IDs (`[U:1:REDACTED]`)
  * Personal possessive names on Bluetooth audio devices

---

## 🏛️ How It Works: The 4-Tier Diagnostic Hierarchy

`drivercheck` strictly prioritizes concrete binary crash artifacts over generalized system logs:

1. **Tier 1: Crash Dumps & Binary Thread Inspector (Primary Ground Truth)**
   * Inspects binary minidump streams (`MDMP`) across Windows Kernel BSODs (`C:\Windows\Minidump`), Windows Error Reporting (`%LOCALAPPDATA%\CrashDumps`), Steam dumps, Unreal Engine (`Saved\Crashes`), and Unity dumps.
   * Architecture-aware parsing across **64-bit (x64)** and **32-bit (x86)** processes.
   * Extracts exact Exception Codes (`0xC0000005`, `0x887A0006`, `0xC0000409`, `0x80000003`, `0xC000001D`, `0x00000000`), faulting module addresses, and in-binary assertion callouts.
   * Audits live processes for **zombie / deadlocked background processes** (e.g. headless `steam.exe` instances blocking relaunch mutexes).

2. **Tier 2: Application & Game Engine Logs (Secondary Evidence)**
   * Discovers and analyzes engine logs across **Unreal Engine**, **Unity** (`Player.log`), **idTech** (`qconsole.log`), **Source 2**, and **Godot**.
   * Inspects Steam Overlay, CEF WebHelper, and IPC pipe logs (`gameoverlay_ui.txt`, `webhelper.txt`, `connection_log.txt`) while intelligently suppressing clean game exit teardown events (`GameOverlayRenderer.dll detaching`).

3. **Tier 3: System Logs & Hardware Telemetry (Tertiary Telemetry)**
   * Correlates Windows Event Logs timestamp-aligned to crash incidents:
     * `WHEA-Logger` CPU, bus, and PCIe hardware errors (detects PCIe 4.0/5.0 riser cable packet loss / WHEA Event `17`).
     * GPU driver TDR timeouts (Event `4101` / `0x141` / `VIDEO_TDR_ERROR`).
     * Virtual memory / commit limit exhaustion (`Resource-Exhaustion-Detector` Event `2004`).
     * Kernel BugChecks (`WER-SystemErrorReporting` BSOD codes).
     * Unexpected shutdowns (Event `6008`) and dirty reboots / instant power trips (Kernel-Power Event `41`).
     * Driver load failures (Kernel-PnP Event `219`) and storage/NVMe timeouts (`stornvme`, `disk`).
   * Audits Windows **Fast Startup** configuration (`HiberbootEnabled`), which frequently causes recurring `0x9F` driver power state crashes.
   * Audits **PCIe Link State Power Management (ASPM)** settings across active power plans (`SUB_PCIEXPRESS`), identifying low-power bus transition latency spikes that trigger GPU driver timeouts (TDR 4101 / 0x141) during idle or video playback.

4. **Tier 4: System Hardware & Configuration (Contextual Audit)**
   * Audits **Motherboard, BIOS Firmware & Platform Chipset Drivers** (Manufacturer, Model, BIOS release date, AMD Chipset Software / Intel Chipset Device Software version, and core controllers: AMD GPIO, I2C, PCI, PSP, and 3D V-Cache Optimizer).
   * Audits **Plug and Play (PnP) Hardware Health** across all system devices for missing drivers (Code 28 `CM_PROB_FAILED_INSTALL`), failed devices (Code 43), and uninitialized chipset devices.
   * Audits **Rogue & Legacy Kernel I/O Drivers** (`inpoutx64.sys`, `WinRing0x64.sys`, `ene.sys`, `AsrOmgDrv.sys`, `gdrv.sys`) left by RGB or fan tools, diagnosing collisions with anti-cheat software (Easy Anti-Cheat, BattlEye, Vanguard) and Windows Memory Integrity that cause `INVALID_KERNEL_HANDLE (0x93)` BSODs or video freeze lockups.
   * Audits active graphics hardware (`Win32_VideoController`), detects **Dual-GPU driver version conflicts** (e.g. AMD Ryzen integrated graphics vs. discrete Radeon graphics), AMD Software installation type (Driver Only vs Adrenalin Full Install), and checks Windows Update driver overwrite policies (`SearchOrderConfig`, `ExcludeWUDriversInQualityUpdate`).
   * Audits **Connected Displays & EDID Detailed Timings** via WMI and Registry, detecting aggressive factory overclocks (e.g. 1440p 165Hz with bloated vertical blanking >1500 lines or pixel clock >585 MHz) saturating DisplayPort 1.2a budget scalers and causing periodic 2-3s blackouts without generating Windows TDRs or crash dumps.
   * Audits graphics subsystem configuration (TdrDelay, TdrLevel, Hardware-Accelerated GPU Scheduling).
   * Audits Bluetooth gaming controllers (DualSense, Xbox, VR, Stadia) and network adapter stability.

---

## 🛠️ Modular Tools (`scripts/`)

Every tool in the `scripts/` directory can be executed independently as an isolated, standalone diagnostic:

| Script | Category | Description |
| :--- | :--- | :--- |
| **`Inspect-CrashDumps.ps1`** | Crash Dumps | Direct binary inspector for BSOD, WER, Steam, Unreal, and Unity minidumps. |
| **`Inspect-GameLogs.ps1`** | Logs | Scans Unreal, Unity, idTech, Source 2, and Godot logs for fatal errors and asserts. |
| **`Inspect-SteamLogs.ps1`** | Logs | Analyzes Steam IPC pipes, CEF browser errors, and sleep/wake crashes. |
| **`Get-PnpDeviceDiagnostics.ps1`** | Hardware | Scans all active hardware for missing drivers (Code 28) and device errors (Code 43). |
| **`Get-MotherboardAndChipsetDiagnostics.ps1`** | Hardware | Audits motherboard model, BIOS version/date, and platform chipset drivers (AMD/Intel). |
| **`Get-GPUDriverDiagnostics.ps1`** | GPU | Audits display adapters, detects driver downgrades, and locks Windows Update driver policies. |
| **`Get-DisplayDiagnostics.ps1`** | Display | Audits connected displays, EDID detailed timings, and DP 1.2a scaler saturation hazards. |
| **`Get-PowerAndSleepDiagnostics.ps1`** | Power | Audits Windows Fast Startup, unexpected shutdowns (6008), and sleep/wake transitions. |
| **`Get-BluetoothDiagnostics.ps1`** | Peripherals | Audits Bluetooth radios, gaming controllers, and connection reset errors. |
| **`Get-NetworkDiagnostics.ps1`** | Network | Audits network adapter link speed, duplex negotiation, and link flapping events. |
| **`Get-WindowsUpdateHistory.ps1`** | System | Audits recently installed Windows Quality Updates and driver packages. |
| **`Clean-ShaderCache.ps1`** | Remediation | Purges DirectX, AMD, and NVIDIA shader caches to resolve shader compile crash loops. |
| **`Clean-GameConfig.ps1`** | Remediation | Purges stale game configs and shader caches (**creates automatic `.bak` backups**). |
| **`Clean-SteamCache.ps1`** | Remediation | Purges the Steam CEF HTML browser cache (`%LOCALAPPDATA%\Steam\htmlcache`). |
| **`Repair-EthernetSettings.ps1`** | Remediation | Applies stability settings to Intel/Realtek Ethernet adapters (disables VLAN/Priority). |
| **`Repair-PciePowerSettings.ps1`** | Remediation | Disables PCIe Link State Power Management (ASPM) on active power scheme to eliminate TDRs. |
| **`Repair-GpuSleepSettings.ps1`** | Remediation | Optimizes GPU watchdog timeout (TdrDelay = 8s) for 4K/high-refresh display wake stability. |
| **`Disable-RogueKernelDrivers.ps1`** | Remediation | Scans for and disables problematic kernel I/O drivers (`inpoutx64`, `winring0`, etc.). |

---

## 🛡️ Safe Remediation & Non-Destructive Principles

Diagnostic scans are **100% read-only**. Optional remediation tools adhere to strict safety guardrails:

* **Automatic Backups**: Before modifying or deleting any configuration (`.cfg`, `.local`, `user_engine_option_save.xml`), `Clean-GameConfig.ps1` generates an exact `.bak` copy in the same folder. Your keybindings, sensitivities, and custom settings are never lost.
* **GPU Downgrade Protection**: `Get-GPUDriverDiagnostics.ps1 -ApplyFix` sets standard Windows registry policies (`SearchOrderConfig = 0`, `ExcludeWUDriversInQualityUpdate = 1`) to prevent Windows Update from silently overwriting official graphics drivers with outdated OEM builds.
* **Zero Power-Impact Defaults**: `Repair-GpuSleepSettings.ps1` resolves display wake TDRs by increasing watchdog tolerance (TdrDelay = 8s) rather than disabling GPU sleep states, preserving full idle power efficiency.
* **Non-Destructive Kernel Driver Disabling**: `Disable-RogueKernelDrivers.ps1` configures driver autostart services to `disabled` via Windows Service Control Manager (`sc.exe`) without deleting system files, immediately resolving anti-cheat conflicts and BugCheck 0x93.

---

## 📋 System Requirements

* **Operating System:** Windows 10 or Windows 11 (64-bit or 32-bit).
* **PowerShell:** Windows PowerShell 5.1 (pre-installed on Windows) or PowerShell Core (7.x+).
* **Privileges:** Standard user privileges are sufficient for all diagnostic scans and HTML report generation. Administrator privileges are only required when explicitly applying system policy changes (e.g. locking Windows Update driver policies or reconfiguring Ethernet adapter properties).
