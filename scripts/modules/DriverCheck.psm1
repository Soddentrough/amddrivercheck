<#
.SYNOPSIS
    DriverCheck Unified PowerShell Root Module
.DESCRIPTION
    Loads all DriverCheck diagnostic, telemetry, crash dump, hardware health, remediation,
    and report generation sub-modules in deterministic dependency order.
#>

$subModules = @(
    "DcCrashDump.psm1",
    "DcEngineLogs.psm1",
    "DcSystemTelemetry.psm1",
    "DcHardwareHealth.psm1",
    "DcRemediation.psm1",
    "DcReportGenerator.psm1"
)

foreach ($modFile in $subModules) {
    $modPath = Join-Path $PSScriptRoot $modFile
    if (Test-Path $modPath) {
        Import-Module $modPath -Global -Force -ErrorAction SilentlyContinue
    }
}
