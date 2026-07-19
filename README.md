# GPU Driver Diagnostics & Downgrade Prevention Tool

A Windows utility designed to diagnose display adapter driver health, detect automatic version downgrades, and resolve system crashes (such as **DRIVER_POWER_STATE_FAILURE / BugCheck 0x9F**) on dual-GPU configurations—especially systems running both an AMD Ryzen CPU with integrated graphics and a discrete AMD Radeon graphics card.

---

## The Problem

On Windows systems with dual graphics processors (e.g., AMD Ryzen Integrated Graphics + AMD Radeon Discrete GPU), Windows Update will often silently overwrite or downgrade the driver of the integrated GPU to an older OEM-approved branch in the background. 

Because AMD drivers share background system services (like `atieclxx.exe` and `amducsi.sys`), this version mismatch conflicts during power transitions (such as system sleep, hibernation, restart, or shutdown), causing a 5-minute timeout hang that results in a Blue Screen of Death (BSOD) `0x0000009F`.

---

## Features

* **Dual-GPU Alignment Scan:** Queries active display adapters and cross-references them against the Windows Driver Store to find driver version mismatches.
* **Smart Device ID Checking:** Maps device Hardware IDs (`DEV_xxxx`) to staged INF files to prevent false-positive warnings across different GPU architectures.
* **Windows Update Prevention:** Offers to apply registry exclusions (`ExcludeWUDriversInQualityUpdate = 1` and `SearchOrderConfig = 0`) to permanently block Windows Update from replacing your official GPU drivers.
* **Local Package Scan (`C:\AMD`):** Recursively searches your local `C:\AMD` directory for extracted driver folders. If a mismatch or generic driver is found, the tool points you to the exact local directory to perform a manual update using Device Manager.

---

## How to Run

### Option 1: Double-Click Launcher (Recommended)
1. Right-click the **[Run-Diagnostics.bat](file:///c:/Users/naoki/Development/drivercheck/Run-Diagnostics.bat)** file in the root directory.
2. Select **Run as Administrator**.
3. The launcher will automatically request elevation, bypass PowerShell execution policies, and run the script in interactive mode.

### Option 2: PowerShell (Manual)
1. Open PowerShell as Administrator.
2. Navigate to the project directory:
   ```powershell
   Set-Location -Path "C:\Users\naoki\Development\drivercheck"
   ```
3. Run the script in safe diagnostic mode (read-only):
   ```powershell
   Powershell.exe -ExecutionPolicy Bypass -File .\Get-GPUDriverDiagnostics.ps1
   ```
4. Run the script in interactive fix mode (applies registry fixes and stages drivers):
   ```powershell
   Powershell.exe -ExecutionPolicy Bypass -File .\Get-GPUDriverDiagnostics.ps1 -ApplyFix
   ```

---

## Verifying Success

When your system is successfully aligned and protected, running the diagnostics script will report:

```text
=== Checking Windows Update & Driver Search policies...
  1. Driver Searching Setting (SearchOrderConfig):
[INFO] Disabled (0) - Windows Update will NOT search for drivers.
  2. Driver Exclusion Policy (ExcludeWUDriversInQualityUpdate):
[INFO] Enabled (1) - Drivers are excluded from Quality Updates.

=== Analyzing Driver Health & Generating Recommendations...
[ OK ] No active GPU driver problems (such as generic adapters or downgrades) were detected on this system.
```
