# Automated Game & System Crash Diagnostic Suite (`drivercheck`)

`drivercheck` is a zero-prompt, **100% read-only** PowerShell and batch diagnostic suite for Windows gaming PCs.

It runs an automatic post-crash analysis across system telemetry, Windows Event logs, Steam crash dumps, minidump binary exception streams, and game logs to identify the exact root cause of game crashes and provide evidence-based guidance on what to check—preventing users from blindly blaming GPU drivers.

---

## 🚀 How to Run

Simply double-click **`Run-Diagnostics.bat`** or run:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\Analyze-LatestCrash.ps1
```

The tool runs completely automatically without any menus or modifying commands, analyzes the past 48 hours of crash telemetry, and outputs a structured diagnostic report.

---

## 🔍 What the Tool Analyzes

1. **Graphics Hardware & Driver Stack**
   * Enumerates active GPUs (AMD, NVIDIA, Intel), driver versions, release dates, and detects dual-GPU driver branch conflicts (e.g. Discrete GPU vs. CPU Integrated Graphics).

2. **Windows Updates & Background Activity**
   * Audits recently installed Windows Quality Updates and Microsoft Defender signature updates (`KB2267602`) that coincide with crash timestamps.

3. **Network Connectivity & Link Drops**
   * Inspects all active network adapters (Ethernet, Wi-Fi) for link drops, auto-negotiation retraining events, and Steam network device state bounces (`OnNetworkDeviceStateChange`).

4. **System Logs & LiveKernel Telemetry**
   * Correlates GPU driver TDR timeouts (`LiveKernelEvent 141` / `VIDEO_ENGINE_TIMEOUT_DETECTED`), user-mode driver crashes (`AMD_REPORT_UM`), and dirty shutdowns (`Kernel-Power 41`).

5. **Deep Crash Dump & Binary Minidump Inspector**
   * Scans Steam dumps, `%LOCALAPPDATA%\CrashDumps`, Unreal Engine crash folders, and Sentry logs.
   * Parses binary minidump streams to extract exact Exception Codes (`0xC0000005`, `0x887A0006`, `0x00000000`), Steam IPC assertion callstacks (`pipes.cpp`, `steamengine.cpp`), and active Vulkan hook layers.

6. **Game Engine Console & Log Analysis**
   * Inspects game logs (e.g. idTech `qconsole.log`, Unreal Engine `cef3.log`) for vertex buffer pool limits, streaming timeouts, and clean vs. abrupt exits.

7. **Executive Root Cause Summary & Actionable Guidance**
   * Tells the user in plain English **what actually caused the crash** (e.g., *Network Drop -> Steam IPC Pipe Kill*, *GPU TDR / Display Driver Reset*, *Background Defender Update Lock*, *In-Engine Buffer Exhaustion*).
   * Provides concrete, actionable recommendations on what settings or hardware to look at.
