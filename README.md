# Automated Game & System Crash Diagnostic Suite (`drivercheck`)

`drivercheck` is an evidence-based diagnostic toolkit and distributable diagnostic engine designed to identify the exact root cause of Windows PC gaming crashes, Blue Screens of Death (BSOD), and driver hangs.

It strictly adheres to a **4-Tier Diagnostic Hierarchy**, prioritizing binary crash artifacts over generalized system logs to provide accurate root-cause determinations without speculative guesses or unnecessary system modifications.

---

## 🏛️ The 4-Tier Diagnostic Hierarchy

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

## 🚀 How to Run

### 1. Interactive Launcher (Recommended for Gamers)
Simply double-click **`Run-Diagnostics.bat`** in the project folder. It launches an interactive menu:

```text
========================================================================
  AUTOMATED GAME & SYSTEM CRASH DIAGNOSTIC SUITE (v4.3.0)
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
```

Selecting Option **`[1]`** automatically executes the full 4-tier scan and generates a responsive, dark-mode **HTML Report** (`CrashReport_<timestamp>.html`), automatically opening it in your default web browser.

---

### 2. PowerShell CLI (Power Users & Tech Support)

Run the unified engine directly via PowerShell:

```powershell
# Standard 48-Hour Diagnostic Scan with HTML Report
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -ExportHtml -OpenReport

# Deep Scan (Past 7 Days)
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -DeepScan -ExportHtml

# Create Support Bundle ZIP (HTML report + logs for Discord/Reddit)
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -ExportZip

# JSON Export for automated pipelines or scripting
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1 -ExportJson -Quiet
```

---

## 🛠️ Modular Tools (`scripts/`)

Each tool in the `scripts/` directory can also be executed individually as an isolated, standalone diagnostic:

| Script | Description |
| :--- | :--- |
| **`Inspect-CrashDumps.ps1`** | Direct binary inspector for BSOD, WER, Steam, Unreal, and Unity minidumps. |
| **`Inspect-GameLogs.ps1`** | Scans Unreal, Unity, idTech, Source 2, and Godot logs for fatal errors and asserts. |
| **`Inspect-SteamLogs.ps1`** | Analyzes Steam IPC pipes, CEF browser errors, and sleep/wake crashes. |
| **`Get-PnpDeviceDiagnostics.ps1`** | Scans all active hardware for missing drivers (Code 28) and device errors (Code 43). |
| **`Get-MotherboardAndChipsetDiagnostics.ps1`** | Audits motherboard model, BIOS version/date, and platform chipset drivers (AMD/Intel). |
| **`Get-GPUDriverDiagnostics.ps1`** | Audits display adapters, detects driver downgrades, and locks Windows Update driver policies. |
| **`Get-PowerAndSleepDiagnostics.ps1`** | Audits Windows Fast Startup, unexpected shutdowns (6008), and sleep/wake transitions. |
| **`Get-DisplayDiagnostics.ps1`** | Audits connected displays, EDID detailed timings, and DP 1.2a scaler saturation hazards. |
| **`Get-BluetoothDiagnostics.ps1`** | Audits Bluetooth radios, gaming controllers, and connection reset errors. |
| **`Get-NetworkDiagnostics.ps1`** | Audits network adapter link speed, duplex negotiation, and link flapping events. |
| **`Get-WindowsUpdateHistory.ps1`** | Audits recently installed Windows Quality Updates and driver packages. |
| **`Clean-ShaderCache.ps1`** | Purges DirectX, AMD, and NVIDIA shader caches to resolve shader compile crash loops. |
| **`Clean-GameConfig.ps1`** | Purges stale game configs and shader caches (**creates automatic `.bak` backups**). |
| **`Clean-SteamCache.ps1`** | Purges the Steam CEF HTML browser cache (`%LOCALAPPDATA%\Steam\htmlcache`). |
| **`Repair-EthernetSettings.ps1`** | Applies stability settings to Intel/Realtek Ethernet adapters (disables VLAN/Priority). |
| **`Repair-PciePowerSettings.ps1`** | Disables PCIe Link State Power Management (ASPM) on the active power scheme to eliminate TDRs. |
| **`Disable-RogueKernelDrivers.ps1`** | Scans for and disables problematic kernel I/O drivers (`inpoutx64`, `winring0`, etc.). |

---

## 🛡️ Safe Remediation

Remediation features are strictly separated from read-only scans:
* **Safe Configuration Cleaner:** Before deleting any `.cfg` or `.local` files, `Clean-GameConfig.ps1` creates an exact `.bak` copy in the same directory, ensuring custom keybinds and sensitivities are never lost.
* **Downgrade Protection:** `Get-GPUDriverDiagnostics.ps1 -ApplyFix` sets registry policies (`SearchOrderConfig = 0`, `ExcludeWUDriversInQualityUpdate = 1`) to permanently prevent Windows Update from silently replacing your official graphics drivers with older OEM builds.
* **PCIe Power Stability:** `Repair-PciePowerSettings.ps1` runs `powercfg` to disable Link State Power Management on AC and DC for `SCHEME_CURRENT`, eliminating bus wake latency spikes that cause TDRs.
* **Kernel Driver Neutralization:** `Disable-RogueKernelDrivers.ps1` safely disables legacy RGB/fan kernel services via `sc config <name> start= disabled` and terminates running instances without deleting files, immediately resolving anti-cheat conflicts and BugCheck 0x93.

---

## 📋 System Requirements
* **Operating System:** Windows 10 or Windows 11 (64-bit or 32-bit).
* **PowerShell:** Windows PowerShell 5.1 or PowerShell Core (7.x+).
* **Privileges:** Administrator privileges are only required when modifying network properties or writing system registry policies; all diagnostic scans run smoothly under standard user privileges.
