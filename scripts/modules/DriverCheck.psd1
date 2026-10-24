@{
    RootModule        = 'DriverCheck.psm1'
    ModuleVersion     = '4.5.0'
    GUID              = '8f4c2e91-7a5b-4d3e-9c12-6b8a0e5d1f34'
    Author            = 'DriverCheck Contributors'
    CompanyName       = 'DriverCheck'
    Copyright         = '(c) DriverCheck Contributors. All rights reserved.'
    Description       = 'Unified Windows System, GPU, Network, and Game Crash Diagnostic Engine'
    PowerShellVersion = '5.1'
    NestedModules     = @(
        'DcCrashDump.psm1',
        'DcEngineLogs.psm1',
        'DcSystemTelemetry.psm1',
        'DcHardwareHealth.psm1',
        'DcRemediation.psm1',
        'DcReportGenerator.psm1'
    )
    FunctionsToExport = '*'
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = '*'
}
