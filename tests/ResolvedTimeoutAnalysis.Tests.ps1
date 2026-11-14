$repoRoot = Split-Path -Parent $PSScriptRoot
$modulesDir = Join-Path $repoRoot "scripts\modules"
Import-Module (Join-Path $modulesDir "DriverCheck.psm1") -Force

$pesterMod = Get-Module Pester
if (-not $pesterMod) {
    $pesterMod = Import-Module Pester -PassThru -ErrorAction SilentlyContinue
}
if ($pesterMod -and $pesterMod.Version.Major -lt 5) {
    function Should {
        param(
            [Parameter(ValueFromPipeline = $true)]
            $ActualValue,
            [switch]$Not,
            [switch]$BeNullOrEmpty,
            [switch]$Be,
            [switch]$Match,
            [switch]$BeLessThan,
            [switch]$BeGreaterThan,
            [switch]$BeGreaterOrEqual,
            [switch]$Contain,
            [Parameter(Position = 0)]
            $ExpectedValue
        )
        begin {
            $items = [System.Collections.Generic.List[object]]::new()
        }
        process {
            $items.Add($ActualValue)
        }
        end {
            $val = if ($items.Count -eq 0) { $null } elseif ($items.Count -eq 1) { $items[0] } else { $items.ToArray() }
            if ($BeNullOrEmpty) {
                $isEmpty = ($null -eq $val) -or ($val -is [string] -and $val.Length -eq 0) -or ($val -is [System.Collections.ICollection] -and $val.Count -eq 0)
                if ($Not -and $isEmpty) { throw "Expected value not to be null or empty, but it was null/empty." }
                if (-not $Not -and -not $isEmpty) { throw "Expected null or empty, but got '$val'." }
                return
            }
            if ($Be) {
                if ($Not) {
                    if ($val -eq $ExpectedValue) { throw "Expected '$val' not to be '$ExpectedValue'." }
                } else {
                    if ($val -ne $ExpectedValue) { throw "Expected '$ExpectedValue', but got '$val'." }
                }
                return
            }
            if ($Match) {
                if ($Not) {
                    if ([string]$val -match $ExpectedValue) { throw "Expected '$val' not to match '$ExpectedValue'." }
                } else {
                    if ([string]$val -notmatch $ExpectedValue) { throw "Expected '$val' to match '$ExpectedValue'." }
                }
                return
            }
            if ($BeLessThan) {
                if (-not ($val -lt $ExpectedValue)) { throw "Expected '$val' to be less than '$ExpectedValue'." }
                return
            }
            if ($BeGreaterThan) {
                if (-not ($val -gt $ExpectedValue)) { throw "Expected '$val' to be greater than '$ExpectedValue'." }
                return
            }
            if ($BeGreaterOrEqual) {
                if (-not ($val -ge $ExpectedValue)) { throw "Expected '$val' to be >= '$ExpectedValue'." }
                return
            }
            if ($Contain) {
                if (@($val) -notcontains $ExpectedValue) { throw "Expected collection to contain '$ExpectedValue'." }
                return
            }
        }
    }
}

Describe "DcCrashDump - Minidump VS_FIXEDFILEINFO & LiveKernelReports" {
    It "Decodes VS_FIXEDFILEINFO module versions, LinkDate, and GPU driver versions from binary MDMP stream" {
        $tempDump = Join-Path $PSScriptRoot ("test_mdmp_" + [guid]::NewGuid().ToString("N") + ".dmp")
        try {
            $ms = New-Object System.IO.MemoryStream
            $bw = New-Object System.IO.BinaryWriter($ms)

            # MDMP Header (32 bytes)
            $bw.Write([UInt32]0x504D444D) # 'MDMP'
            $bw.Write([UInt32]0x0000A793) # Version
            $bw.Write([UInt32]2)          # NumberOfStreams (SystemInfo=7, ModuleList=4)
            $bw.Write([UInt32]32)         # StreamDirectoryRva
            $bw.Write([UInt32]0)          # CheckSum
            $bw.Write([UInt32]0)          # TimeDateStamp
            $bw.Write([UInt64]0)          # Flags

            # Stream Directory at offset 32 (2 streams * 12 bytes = 24 bytes -> ends at 56)
            # Stream 0: SystemInfoStream (Type 7) at RVA 64, Size 56
            $bw.Write([UInt32]7)
            $bw.Write([UInt32]56)
            $bw.Write([UInt32]64)
            # Stream 1: ModuleListStream (Type 4) at RVA 120, Size 4 + 2*108 = 220
            $bw.Write([UInt32]4)
            $bw.Write([UInt32]220)
            $bw.Write([UInt32]120)

            # Pad to 64
            $bw.Write([byte[]]::new(8))

            # SystemInfoStream at offset 64 (56 bytes)
            $bw.Write([UInt16]9) # ProcessorArchitecture = 9 (AMD64)
            $bw.Write([byte[]]::new(54))

            # ModuleListStream at offset 120
            $bw.Write([UInt32]2) # 2 modules: game.exe and amdkmdag.sys

            # Module 0: C:\Games\TestGame.exe (Version 1.2.3.4) -> Name at RVA 340
            $bw.Write([uint64]"0x140000000") # BaseOfImage
            $bw.Write([uint32]"0x01000000")  # SizeOfImage
            $bw.Write([UInt32]0)           # CheckSum
            $bw.Write([UInt32]1700000000)  # TimeDateStamp
            $bw.Write([UInt32]340)         # ModuleNameRva
            # VS_FIXEDFILEINFO (52 bytes)
            $bw.Write([uint32]"0xFEEF04BD")  # dwSignature
            $bw.Write([uint32]"0x00010000")  # dwStrucVersion
            $bw.Write([uint32]"0x00010002")  # dwFileVersionMS (1.2)
            $bw.Write([uint32]"0x00030004")  # dwFileVersionLS (3.4)
            $bw.Write([byte[]]::new(36))   # Rest of VS_FIXEDFILEINFO
            $bw.Write([byte[]]::new(32))   # CvRecord, MiscRecord, Reserved0, Reserved1

            # Module 1: C:\Windows\System32\drivers\amdkmdag.sys (Version 31.0.24033.1003) -> Name at RVA 400
            $bw.Write([uint64]"0xFFFFF80010000000") # BaseOfImage
            $bw.Write([uint32]"0x05000000")         # SizeOfImage
            $bw.Write([UInt32]0)                  # CheckSum
            $bw.Write([UInt32]1710000000)         # TimeDateStamp
            $bw.Write([UInt32]400)                # ModuleNameRva
            # VS_FIXEDFILEINFO (52 bytes)
            $bw.Write([uint32]"0xFEEF04BD")         # dwSignature
            $bw.Write([uint32]"0x00010000")         # dwStrucVersion
            $bw.Write([UInt32]((31 -shl 16) -bor 0))         # dwFileVersionMS (31.0)
            $bw.Write([UInt32]((24033 -shl 16) -bor 1003))   # dwFileVersionLS (24033.1003)
            $bw.Write([byte[]]::new(36))
            $bw.Write([byte[]]::new(32))

            # Offset is now 120 + 4 + 216 = 340
            $mod0Name = [System.Text.Encoding]::Unicode.GetBytes("C:\Games\TestGame.exe")
            $bw.Write([UInt32]$mod0Name.Length)
            $bw.Write($mod0Name)
            # Pad from current position to 400
            $padLen = 400 - [int]$ms.Position
            if ($padLen -gt 0) { $bw.Write([byte[]]::new($padLen)) }

            $mod1Name = [System.Text.Encoding]::Unicode.GetBytes("C:\Windows\System32\drivers\amdkmdag.sys")
            $bw.Write([UInt32]$mod1Name.Length)
            $bw.Write($mod1Name)

            [System.IO.File]::WriteAllBytes($tempDump, $ms.ToArray())
            $bw.Close()
            $ms.Close()

            $parsed = Read-DcMinidump -Path $tempDump
            $parsed | Should -Not -BeNullOrEmpty
            $parsed.Architecture | Should -Be "64-bit (x64)"
            $parsed.MainExecutable | Should -Be "TestGame.exe"
            $parsed.MainExecutableVersion | Should -Be "1.2.3.4"
            $parsed.GpuDriverVersion | Should -Be "31.0.24033.1003"
            $parsed.DriverModuleVersions["amdkmdag.sys"] | Should -Be "31.0.24033.1003"
            $parsed.Modules[1].LinkDate | Should -Not -BeNullOrEmpty
        } finally {
            if (Test-Path $tempDump) { Remove-Item $tempDump -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe "DcSystemTelemetry - WER ReportArchive Parser" {
    It "Parses Report.wer FILETIME EventTime, LiveKernelEvent 141 signature, and LoadedModules" {
        $tempDir = Join-Path $PSScriptRoot ("wer_test_" + [guid]::NewGuid().ToString("N"))
        $reportFolder = Join-Path $tempDir "Kernel_141_1a2b3c4d"
        New-Item -Path $reportFolder -ItemType Directory -Force | Out-Null
        $werFile = Join-Path $reportFolder "Report.wer"

        try {
            $targetTime = (Get-Date).AddDays(-45)
            $fileTime = $targetTime.ToFileTime()
            $werContent = @(
                "Version=1",
                "EventType=LiveKernelEvent",
                "EventTime=$fileTime",
                "FriendlyEventName=Hardware error",
                "NsAppName=Windows",
                "Sig[0].Name=Code",
                "Sig[0].Value=141",
                "Sig[1].Name=Parameter 1",
                "Sig[1].Value=ffffda8b12345010",
                "Sig[3].Name=Faulting Module",
                "Sig[3].Value=amdkmdag.sys",
                "LoadedModule[0]=amdkmdag.sys"
            )
            Set-Content -Path $werFile -Value $werContent -Encoding UTF8

            $reports = @(Get-DcWerReportArchive -Cutoff (Get-Date).AddDays(-90) -EndTime (Get-Date) -CustomArchivePaths @($tempDir))
            $reports.Count | Should -Be 1
            $reports[0].EventType | Should -Be "LiveKernelEvent"
            $reports[0].BugCheckOrCode | Should -Be "141"
            $reports[0].IsTdrOrGpu | Should -Be $true
            $reports[0].Parameter4 | Should -Be "amdkmdag.sys"
            ([math]::Abs(($reports[0].Timestamp - $targetTime).TotalSeconds)) | Should -BeLessThan 5
        } finally {
            if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe "DcSystemTelemetry - SetupAPI & DriverStore Change History" {
    It "Extracts historical GPU and Chipset driver installations from setupapi.dev.log and DriverStore FileRepository" {
        $tempRoot = Join-Path $PSScriptRoot ("chg_test_" + [guid]::NewGuid().ToString("N"))
        $fakeStore = Join-Path $tempRoot "FileRepository"
        $fakePkg = Join-Path $fakeStore "u0401234.inf_amd64_abcdef123456"
        New-Item -Path $fakePkg -ItemType Directory -Force | Out-Null

        $setupLog = Join-Path $tempRoot "setupapi.dev.log"
        $infFile = Join-Path $fakePkg "u0401234.inf"

        try {
            $installDate = (Get-Date).AddDays(-25)
            $tsStr = $installDate.ToString("yyyy/MM/dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
            $logText = @(
                ">>>  [Device Install (Hardware initiated) - PCI\VEN_1002&DEV_744C]",
                ">>>  Section start $tsStr",
                "     dvi: {Install Device - PCI\VEN_1002&DEV_744C}",
                "     dvi:      DriverVer = 08/15/2026, 32.0.11037.4004",
                "<<<  Section end $tsStr",
                "<<<  [Exit status: SUCCESS]"
            )
            Set-Content -Path $setupLog -Value $logText -Encoding UTF8

            $infText = @(
                "[Version]",
                "Signature=`"`$WINDOWS NT`$`"",
                "Class=Display",
                "DriverVer=08/15/2026, 32.0.11037.4004"
            )
            Set-Content -Path $infFile -Value $infText -Encoding UTF8

            $changes = Get-DcSystemChangeHistory -Cutoff (Get-Date).AddDays(-60) -SetupApiLogPath $setupLog -DriverStorePath $fakeStore
            $setupMatch = $changes | Where-Object { $_.Source -eq "setupapi.dev.log" } | Select-Object -First 1
            $storeMatch = $changes | Where-Object { $_.Source -match "DriverStore FileRepository" } | Select-Object -First 1

            $setupMatch | Should -Not -BeNullOrEmpty
            $setupMatch.Category | Should -Be "GpuDriverUpdate"
            $setupMatch.Version | Should -Be "32.0.11037.4004"

            $storeMatch | Should -Not -BeNullOrEmpty
            $storeMatch.Category | Should -Be "GpuDriverUpdate"
            $storeMatch.Version | Should -Be "32.0.11037.4004"
        } finally {
            if (Test-Path $tempRoot) { Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe "DcSystemTelemetry - Episode Clustering & Resolution Correlation Engine" {
    It "Clusters historical TDR timeouts into a resolved episode and ranks the resolving GPU driver update and ASPM fix" {
        $now = Get-Date
        $t1 = $now.AddDays(-65)
        $t2 = $now.AddDays(-62)
        $t3 = $now.AddDays(-60) # T_last = 60 days ago

        $incidents = @(
            [PSCustomObject]@{
                Timestamp        = $t1
                Category         = "GpuTdrTimeout"
                Code             = "4101"
                Source           = "Display"
                Application      = "Cyberpunk2077.exe"
                FaultingModule   = "amdkmdag.sys"
                GpuDriverVersion = "31.0.22011.1001"
                Details          = "Display driver amdkmdag stopped responding"
            },
            [PSCustomObject]@{
                Timestamp        = $t2
                Category         = "GpuTdrTimeout"
                Code             = "141"
                Source           = "LiveKernelEvent"
                Application      = "Cyberpunk2077.exe"
                FaultingModule   = "amdkmdag.sys"
                GpuDriverVersion = "31.0.22011.1001"
                Details          = "LiveKernelEvent 0x141"
            },
            [PSCustomObject]@{
                Timestamp        = $t3
                Category         = "GpuTdrTimeout"
                Code             = "141"
                Source           = "LiveKernelEvent"
                Application      = "Cyberpunk2077.exe"
                FaultingModule   = "amdkmdag.sys"
                GpuDriverVersion = "31.0.22011.1001"
                Details          = "LiveKernelEvent 0x141"
            }
        )

        # System change 3 hours after T_last: GPU driver updated + PCIe ASPM disabled
        $changes = @(
            [PSCustomObject]@{
                Timestamp = $t3.AddHours(3)
                Category  = "GpuDriverUpdate"
                Source    = "setupapi.dev.log"
                Title     = "SetupAPI Display Driver Install (v32.0.11037.4004)"
                Version   = "32.0.11037.4004"
                Details   = "Updated AMD display driver to 32.0.11037.4004"
            },
            [PSCustomObject]@{
                Timestamp = $t3.AddHours(4)
                Category  = "PowerMitigation"
                Source    = "Power Scheme (Balanced)"
                Title     = "PCIe Link State Power Management (ASPM) Disabled (Off)"
                Version   = $null
                Details   = "PCIe ASPM set to Off"
            },
            [PSCustomObject]@{
                Timestamp = $now.AddDays(-120) # Prior change before episode -> should be ignored
                Category  = "WindowsUpdate"
                Source    = "Win32_QuickFixEngineering"
                Title     = "Old Windows Update (KB5000001)"
                Version   = "KB5000001"
                Details   = "Old update"
            }
        )

        $analysis = Find-DcResolvedIncidentHistory -LookbackDays 180 -HistoricalIncidents $incidents -ChangeHistory $changes -CurrentGpuDriverVersion "32.0.11037.4004"

        $analysis.HasHistoricalIncidents | Should -Be $true
        $analysis.HasResolvedEpisodes | Should -Be $true
        $analysis.Episodes.Count | Should -Be 1

        $ep = $analysis.PrimaryResolvedEpisode
        $ep | Should -Not -BeNullOrEmpty
        $ep.IsResolved | Should -Be $true
        $ep.IncidentCount | Should -Be 3
        $ep.HistoricalDriverVersion | Should -Be "31.0.22011.1001"
        $ep.CurrentDriverVersion | Should -Be "32.0.11037.4004"
        $ep.QuietDaysSinceEnd | Should -BeGreaterThan 55

        # Top resolution factors should be High confidence and exclude the 120-day-old update
        $highConf = @($ep.ResolutionFactors | Where-Object { $_.Confidence -eq "High" })
        $highConf.Count | Should -BeGreaterOrEqual 2
        ($ep.ResolutionFactors | Where-Object { $_.Version -eq "KB5000001" }) | Should -BeNullOrEmpty
    }

    It "Separates an older resolved episode from a recent active episode and surfaces the resolved episode" {
        $now = Get-Date
        $incidents = @(
            # Episode 1: 90-88 days ago (Resolved)
            [PSCustomObject]@{
                Timestamp        = $now.AddDays(-90)
                Category         = "GpuTdrTimeout"
                Code             = "141"
                Source           = "LiveKernelEvent"
                Application      = "Starfield.exe"
                FaultingModule   = "amdkmdag.sys"
                GpuDriverVersion = "31.0.14001.1000"
                Details          = "LiveKernelEvent 0x141"
            },
            [PSCustomObject]@{
                Timestamp        = $now.AddDays(-88)
                Category         = "GpuTdrTimeout"
                Code             = "141"
                Source           = "LiveKernelEvent"
                Application      = "Starfield.exe"
                FaultingModule   = "amdkmdag.sys"
                GpuDriverVersion = "31.0.14001.1000"
                Details          = "LiveKernelEvent 0x141"
            },
            # Episode 2: 1 day ago (Unresolved / Active)
            [PSCustomObject]@{
                Timestamp        = $now.AddDays(-1)
                Category         = "AppCrash"
                Code             = "0xC0000005"
                Source           = "Application Error"
                Application      = "OtherApp.exe"
                FaultingModule   = "OtherApp.exe"
                GpuDriverVersion = $null
                Details          = "Access violation"
            }
        )

        $changes = @(
            [PSCustomObject]@{
                Timestamp = $now.AddDays(-88).AddHours(2)
                Category  = "GpuDriverUpdate"
                Source    = "setupapi.dev.log"
                Title     = "SetupAPI Display Driver Install (v32.0.11037.4004)"
                Version   = "32.0.11037.4004"
                Details   = "Updated AMD display driver"
            }
        )

        $analysis = Invoke-DcResolvedTimeoutAnalysis -LookbackDays 180 -HistoricalIncidents $incidents -ChangeHistory $changes -CurrentGpuDriverVersion "32.0.11037.4004"
        $analysis.Episodes.Count | Should -Be 2
        $analysis.HasResolvedEpisodes | Should -Be $true
        $analysis.PrimaryResolvedEpisode | Should -Not -BeNullOrEmpty
        $analysis.PrimaryResolvedEpisode.IncidentCount | Should -Be 2
        $analysis.PrimaryResolvedEpisode.HistoricalDriverVersion | Should -Be "31.0.14001.1000"
    }
}

Describe "DcSystemTelemetry - Multi-Line WER LiveKernelEvent 1001 & EndTime Enforcement" {
    It "Extracts .dmp/.wer paths and embedded YYYYMMDD-HHMM timestamps across multi-line Attached files blocks and enforces EndTime" {
        $global:dcTestNow = Get-Date
        $cutoff = $global:dcTestNow.AddDays(-30)
        $endTime = $global:dcTestNow.AddDays(-5)

        # Event 1: Embedded timestamp 10 days ago (within [Cutoff, EndTime])
        $validDumpDate = $global:dcTestNow.AddDays(-10)
        $validDateTag = $validDumpDate.ToString("yyyyMMdd-HHmm")
        $global:dcTestMsgValid = @"
Fault bucket , type 0
Event Name: LiveKernelEvent
Response: Not available
Cab Id: 0

Problem signature:
P1: 141
P2: ffffda8b12345010
P3: fffff80012345678
P4: 0
P5: 1234

Attached files:
\\?\C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-4101-$validDateTag-01.dmp
\\?\C:\ProgramData\Microsoft\Windows\WER\Temp\WER-12345.sysdata.xml
\\?\C:\ProgramData\Microsoft\Windows\WER\ReportArchive\Kernel_141_abc\Report.wer

These files may be available here:
\\?\C:\ProgramData\Microsoft\Windows\WER\ReportArchive\Kernel_141_abc
"@

        # Event 2: Embedded timestamp 1 day ago (after EndTime -> must be filtered out)
        $lateDumpDate = $global:dcTestNow.AddDays(-1)
        $lateDateTag = $lateDumpDate.ToString("yyyyMMdd-HHmm")
        $global:dcTestMsgLate = @"
Fault bucket , type 0
Event Name: LiveKernelEvent
Problem signature:
P1: 117
Attached files:
\\?\C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-$lateDateTag-01.dmp

These files may be available here:
"@

        Mock -ModuleName DcSystemTelemetry Get-CimInstance { return @() }
        Mock -ModuleName DcSystemTelemetry Get-WinEvent {
            $fh = if ($FilterHashtable -is [array]) { $FilterHashtable[0] } else { $FilterHashtable }
            if ($fh -and $fh['ProviderName'] -eq 'Windows Error Reporting' -and ($fh['Id'] -contains 1001)) {
                return @(
                    [PSCustomObject]@{
                        Id           = 1001
                        ProviderName = 'Windows Error Reporting'
                        TimeCreated  = $global:dcTestNow.AddDays(-9)
                        Message      = $global:dcTestMsgValid
                    },
                    [PSCustomObject]@{
                        Id           = 1001
                        ProviderName = 'Windows Error Reporting'
                        TimeCreated  = $global:dcTestNow.AddDays(-1)
                        Message      = $global:dcTestMsgLate
                    }
                )
            }
            return @()
        }

        $telem = Get-DcSystemTelemetry -Cutoff $cutoff -EndTime $endTime
        $telem.TdrEvents.Count | Should -Be 1
        $telem.TdrEvents[0].Code | Should -Be "141"
        $telem.TdrEvents[0].DumpPath | Should -Match "WATCHDOG-4101-$validDateTag-01\.dmp"
        $telem.TdrEvents[0].TimeCreated.ToString("yyyyMMdd-HHmm") | Should -Be $validDateTag
    }

    It "Parses LiveKernelEvent 193 (VIDEO_DXGKRNL_LIVEDUMP) with P2: 810 ProcessDeadlockThread in Get-DcSystemTelemetry and Get-DcWerReportArchive" {
        $now = Get-Date
        $cutoff = $now.AddDays(-15)
        $endTime = $now
        $global:dcTestDumpDate193 = $now.AddDays(-2)
        $dateTag = $global:dcTestDumpDate193.ToString("yyyyMMdd-HHmm")

        $global:dcTestMsg193 = @"
Fault bucket , type 0
Event Name: LiveKernelEvent
Response: Not available
Cab Id: 0

Problem signature:
P1: 193
P2: 810
P3: ffffb60f12345678
P4: 0

Attached files:
\\?\C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-$dateTag-01.dmp
"@

        Mock -ModuleName DcSystemTelemetry Get-CimInstance { return @() }
        Mock -ModuleName DcSystemTelemetry Get-WinEvent {
            $fh = if ($FilterHashtable -is [array]) { $FilterHashtable[0] } else { $FilterHashtable }
            if ($fh -and $fh['ProviderName'] -eq 'Windows Error Reporting' -and ($fh['Id'] -contains 1001)) {
                return @(
                    [PSCustomObject]@{
                        Id           = 1001
                        ProviderName = 'Windows Error Reporting'
                        TimeCreated  = $global:dcTestDumpDate193
                        Message      = $global:dcTestMsg193
                    }
                )
            }
            return @()
        }

        $telem = Get-DcSystemTelemetry -Cutoff $cutoff -EndTime $endTime
        $telem.TdrEvents.Count | Should -Be 1
        $telem.TdrEvents[0].Code | Should -Be "193"
        $telem.TdrEvents[0].Meaning | Should -Match "0x193.*VIDEO_DXGKRNL_LIVEDUMP.*ProcessDeadlockThread"

        # Also verify Get-DcWerReportArchive with Kernel_193
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wer_193_" + [guid]::NewGuid().ToString("N"))
        $reportFolder = Join-Path $tempDir "Kernel_193_deadbeef"
        New-Item -Path $reportFolder -ItemType Directory -Force | Out-Null
        $werFile = Join-Path $reportFolder "Report.wer"
        try {
            $ft = $global:dcTestDumpDate193.ToFileTime()
            $werContent = @(
                "Version=1",
                "EventType=LiveKernelEvent",
                "EventTime=$ft",
                "FriendlyEventName=Hardware error",
                "NsAppName=Windows",
                "Sig[0].Name=Code",
                "Sig[0].Value=193",
                "Sig[1].Name=Parameter 1",
                "Sig[1].Value=810",
                "Sig[3].Name=Faulting Module",
                "Sig[3].Value=dxgkrnl.sys"
            )
            Set-Content -Path $werFile -Value $werContent -Encoding UTF8

            $reports = @(Get-DcWerReportArchive -Cutoff $cutoff -EndTime $endTime -CustomArchivePaths @($tempDir))
            $reports.Count | Should -Be 1
            $reports[0].BugCheckOrCode | Should -Be "193"
            $reports[0].IsTdrOrGpu | Should -Be $true
        } finally {
            if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe "DcCrashDump - WATCHDOG Live Dump Decoding & FaultingIP Population" {
    It "Populates FaultingIP and decodes 0x00000141 and 0x00000193 on simulated WATCHDOG live dumps without ExceptionStream" {
        $tempRootDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wd_test_" + [guid]::NewGuid().ToString("N"))
        $tempWatchdogDir = Join-Path $tempRootDir "LiveKernelReports\WATCHDOG"
        New-Item -Path $tempWatchdogDir -ItemType Directory -Force | Out-Null
        $wd141 = Join-Path $tempWatchdogDir "WATCHDOG-4101-20261020-1200.dmp"
        $wd193 = Join-Path $tempWatchdogDir "WATCHDOG-193-20261020-1205.dmp"
        $wdBuf193 = Join-Path $tempWatchdogDir "WATCHDOG-20261020-1210.dmp"

        try {
            # Build minimal MDMP with SystemInfoStream (Type 7) + ModuleListStream (Type 4) containing amdkmdag.sys, no ExceptionStream
            $ms = New-Object System.IO.MemoryStream
            $bw = New-Object System.IO.BinaryWriter($ms)
            $bw.Write([uint32]"0x504D444D") # 'MDMP'
            $bw.Write([uint32]"0x0000A793")
            $bw.Write([UInt32]2)          # 2 streams
            $bw.Write([UInt32]32)         # StreamDirectoryRva
            $bw.Write([UInt32]0)
            $bw.Write([UInt32]0)
            $bw.Write([UInt64]0)

            # Stream 0: SystemInfo (Type 7) at RVA 64, Size 56
            $bw.Write([UInt32]7)
            $bw.Write([UInt32]56)
            $bw.Write([UInt32]64)
            # Stream 1: ModuleList (Type 4) at RVA 120, Size 112 (1 module)
            $bw.Write([UInt32]4)
            $bw.Write([UInt32]112)
            $bw.Write([UInt32]120)
            $bw.Write([byte[]]::new(8))

            # SystemInfo at 64
            $bw.Write([UInt16]9) # AMD64
            $bw.Write([byte[]]::new(54))

            # ModuleList at 120 (1 module: amdkmdag.sys at RVA 240)
            $bw.Write([UInt32]1)
            $bw.Write([uint64]"0xFFFFF80010000000")
            $bw.Write([uint32]"0x05000000")
            $bw.Write([UInt32]0)
            $bw.Write([UInt32]1710000000)
            $bw.Write([UInt32]240)
            $bw.Write([uint32]"0xFEEF04BD")
            $bw.Write([uint32]"0x00010000")
            $bw.Write([UInt32]((32 -shl 16) -bor 0))
            $bw.Write([UInt32]((13031 -shl 16) -bor 2001))
            $bw.Write([byte[]]::new(36))
            $bw.Write([byte[]]::new(32))

            $pad = 240 - [int]$ms.Position
            if ($pad -gt 0) { $bw.Write([byte[]]::new($pad)) }
            $modName = [System.Text.Encoding]::Unicode.GetBytes("C:\Windows\System32\drivers\amdkmdag.sys")
            $bw.Write([UInt32]$modName.Length)
            $bw.Write($modName)

            $bytes = $ms.ToArray()
            $bw.Close()
            $ms.Close()

            [System.IO.File]::WriteAllBytes($wd141, $bytes)
            [System.IO.File]::WriteAllBytes($wd193, $bytes)

            # Also create a generic WATCHDOG-YYYYMMDD-HHMM.dmp containing ProcessDeadlockThread in its binary buffer
            $sigBytes = [System.Text.Encoding]::ASCII.GetBytes(" dxgkrnl!ProcessDeadlockThread VIDEO_DXGKRNL_LIVEDUMP ")
            $bufBytes = New-Object byte[] ($bytes.Length + $sigBytes.Length)
            [System.Array]::Copy($bytes, 0, $bufBytes, 0, $bytes.Length)
            [System.Array]::Copy($sigBytes, 0, $bufBytes, $bytes.Length, $sigBytes.Length)
            [System.IO.File]::WriteAllBytes($wdBuf193, $bufBytes)

            $p141 = Read-DcMinidump -Path $wd141
            $p141.ExceptionCode | Should -Be "0x00000141"
            $p141.ExceptionMeaning | Should -Match "VIDEO_ENGINE_TDR_TIMEOUT"
            $p141.FaultingModule | Should -Be "amdkmdag.sys"
            $p141.FaultingIP | Should -Not -BeNullOrEmpty
            $p141.IsKernelDump | Should -Be $true
            $p141.IsGraphicsCrash | Should -Be $true

            $p193 = Read-DcMinidump -Path $wd193
            $p193.ExceptionCode | Should -Be "0x00000193"
            $p193.ExceptionMeaning | Should -Match "VIDEO_DXGKRNL_LIVEDUMP"
            $p193.FaultingIP | Should -Match "dxgkrnl\.sys"
            $p193.IsKernelDump | Should -Be $true

            $pBuf193 = Read-DcMinidump -Path $wdBuf193
            $pBuf193.ExceptionCode | Should -Be "0x00000193"
            $pBuf193.ExceptionMeaning | Should -Match "VIDEO_DXGKRNL_LIVEDUMP"
            $pBuf193.FaultingIP | Should -Match "dxgkrnl\.sys / amdkmdag\.sys"
            $pBuf193.Assertions | Should -Contain "ProcessDeadlockThread"
        } finally {
            if (Test-Path $tempRootDir) { Remove-Item $tempRootDir -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe "DcRemediation - Clear-DcShaderCache AMD DxcCache & VkCache Coverage" {
    It "Purges files in AMD\DxcCache, AMD\VkCache, and AMD\DxCache when invoked" {
        $fakeLocalApp = Join-Path ([System.IO.Path]::GetTempPath()) ("shader_test_" + [guid]::NewGuid().ToString("N"))
        $dxcDir = Join-Path $fakeLocalApp "AMD\DxcCache"
        $vkDir = Join-Path $fakeLocalApp "AMD\VkCache"
        $dxDir = Join-Path $fakeLocalApp "AMD\DxCache"
        New-Item -Path $dxcDir -ItemType Directory -Force | Out-Null
        New-Item -Path $vkDir -ItemType Directory -Force | Out-Null
        New-Item -Path $dxDir -ItemType Directory -Force | Out-Null

        $f1 = Join-Path $dxcDir "sm6_shader.bin"
        $f2 = Join-Path $vkDir "vk_pipeline.bin"
        $f3 = Join-Path $dxDir "dx_pso.bin"
        Set-Content -Path $f1 -Value "dummy"
        Set-Content -Path $f2 -Value "dummy"
        Set-Content -Path $f3 -Value "dummy"

        $oldLocalApp = $env:LOCALAPPDATA
        $oldUserProf = $env:USERPROFILE
        try {
            $env:LOCALAPPDATA = $fakeLocalApp
            $env:USERPROFILE = $fakeLocalApp
            # Verify -WhatIf leaves files intact
            $whatIfCount = Clear-DcShaderCache -Target AMD -WhatIf
            (Test-Path $f1) | Should -Be $true
            (Test-Path $f2) | Should -Be $true

            # Verify actual purge removes DxcCache, VkCache, and DxCache files
            $purged = Clear-DcShaderCache -Target AMD -Confirm:$false
            $purged | Should -Be 3
            (Test-Path $f1) | Should -Be $false
            (Test-Path $f2) | Should -Be $false
            (Test-Path $f3) | Should -Be $false
        } finally {
            $env:LOCALAPPDATA = $oldLocalApp
            $env:USERPROFILE = $oldUserProf
            if (Test-Path $fakeLocalApp) { Remove-Item $fakeLocalApp -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe "Privacy & PII Redaction - JSON-Escaped Paths, Non-C Drives & Reliability Monitor User Strings" {
    It "Completely redacts JSON-escaped paths (C:\\Users\\SecretUser\\AppData), non-C drive paths (D:\Users\SecretUser\Games), and Win32_ReliabilityRecords User: DESKTOP-PC\SecretUser strings" {
        $rawRelMsg = "Windows Installer reconfigured the product. Product Name: AMD Chipset Software. User: DESKTOP-PC\SecretUser."
        $sanitizedRel = Protect-DcTelemetryText $rawRelMsg
        $sanitizedRel | Should -Not -Match "SecretUser"
        $sanitizedRel | Should -Not -Match "DESKTOP-PC"
        $sanitizedRel | Should -Match "User: \[REDACTED\]"

        $rawDrivePath = "Faulting application path: D:\Users\SecretUser\Games\SomeGame\game.exe"
        $sanitizedDrive = Protect-DcTelemetryText $rawDrivePath
        $sanitizedDrive | Should -Not -Match "SecretUser"
        $sanitizedDrive | Should -Match "%USERPROFILE%\\Games\\SomeGame\\game\.exe"

        $rawSpaceDrivePath = "Faulting application path: D:\Users\Jane Doe\Games\SomeGame\game.exe"
        $sanitizedSpaceDrive = Protect-DcTelemetryText $rawSpaceDrivePath
        $sanitizedSpaceDrive | Should -Not -Match "Jane Doe"
        $sanitizedSpaceDrive | Should -Match "%USERPROFILE%\\Games\\SomeGame\\game\.exe"

        $rawEngineLine = "LogInit: User: GAMING-RIG\SecretUser loaded from E:\Users\SecretUser\AppData\Local\Game\Saved"
        $sanitizedEngine = Protect-DcLogText $rawEngineLine
        $sanitizedEngine | Should -Not -Match "SecretUser"
        $sanitizedEngine | Should -Not -Match "GAMING-RIG"
        $sanitizedEngine | Should -Match "User: \[REDACTED\]"
        $sanitizedEngine | Should -Match "%USERPROFILE%\\AppData"

        # Simulate ConvertTo-Json escaped backslash output and post-ConvertTo-Json redaction
        $payload = [PSCustomObject]@{
            EscapedPath = "C:\Users\SecretUser\AppData\Local\CrashDumps\game.dmp"
            AltDrive    = "D:\Users\SecretUser\Games\Starfield\Starfield.exe"
            RelRecord   = "Installation completed successfully. User: DESKTOP-PC\SecretUser."
        }
        $jsonText = $payload | ConvertTo-Json -Depth 4
        $jsonText = $jsonText -replace '(?i)[a-zA-Z]:\\\\Users\\\\[^\\"\r\n]+', '%USERPROFILE%'
        $jsonText = $jsonText -replace '(?i)[a-zA-Z]:\\Users\\[^\\"\r\n]+', '%USERPROFILE%'
        $jsonText = $jsonText -replace '(?i)User:\s*[^\r\n"\\]+\\\\[^\r\n"\.]+', 'User: [REDACTED]'
        $jsonText = $jsonText -replace '(?i)User:\s*[^\r\n"\\]+\\[^\r\n"\.]+', 'User: [REDACTED]'

        $jsonText | Should -Not -Match "SecretUser"
        $jsonText | Should -Not -Match "DESKTOP-PC"
        $jsonText | Should -Match "%USERPROFILE%\\\\AppData"
        $jsonText | Should -Match "%USERPROFILE%\\\\Games"
        $jsonText | Should -Match "User: \[REDACTED\]"
    }
}

Describe "DcSystemTelemetry - Multi-Finding Diagnostic Rule Engine (Resolve-DcDiagnosticFindings)" {
    It "Independently surfaces both PCI NIC Reset/Disconnects and Shader Runtime Crash without masking" {
        $now = Get-Date
        $dumpObj = [PSCustomObject]@{
            FileName         = "ApplicationFrameHost.exe.19428.dmp"
            Timestamp        = $now.AddHours(-22)
            MainExecutable   = "ApplicationFrameHost.exe"
            ExceptionCode    = "0xC0000005"
            ExceptionMeaning = "Access Violation"
            FaultingModule   = "amdxx64.dll"
            FaultingIP       = "0x7ffa12345678 (in amdxx64.dll)"
            IsShaderCompiler = $true
            IsKernelDump     = $false
            IsGraphicsCrash  = $true
        }

        $telemObj = [PSCustomObject]@{
            KernelBugChecks    = @()
            AbruptReboots      = @()
            WheaErrors         = @()
            PcieWheaErrors     = @()
            TdrEvents          = @()
            StorageErrors      = @()
            MemoryExhaustion   = @()
            SleepTransitions   = @()
            PnpDriverFailures  = @()
            AppCrashes         = @()
            AppHangs           = @()
            PciDeviceResets    = @(
                [PSCustomObject]@{
                    TimeCreated  = $now.AddHours(-2)
                    Id           = 1
                    FriendlyName = "PCI_DEV_15F3 (Intel(R) Ethernet Controller (3) I225-V)"
                    DeviceLabel  = "PCI_DEV_15F3 (Intel(R) Ethernet Controller (3) I225-V)"
                    Pdo          = "PCI_DEV_15F3"
                    Message      = "PCI Express Bus Device Reset (Type 2)"
                }
            )
            NetworkDrops       = @(
                [PSCustomObject]@{
                    TimeCreated   = $now.AddHours(-2)
                    Id            = 27
                    Provider      = "e2fnexpress"
                    InterfaceName = "e2fnexpress"
                    Reason        = "Hardware Link Disconnect"
                    Message       = "Intel(R) Ethernet Controller (3) I225-V Network link is disconnected."
                }
            )
            WlanFailovers      = @()
            UdpPortExhaustions = @(
                [PSCustomObject]@{
                    TimeCreated = $now.AddHours(-1)
                    Id          = 4266
                    Provider    = "Tcpip"
                    Message     = "A request to allocate an ephemeral port number from the global UDP port space has failed."
                }
            )
        }

        $result = Resolve-DcDiagnosticFindings -ParsedDumps @($dumpObj) -Telemetry $telemObj
        $result | Should -Not -BeNullOrEmpty
        $result.Findings.Count | Should -BeGreaterOrEqual 3

        $ruleIds = @($result.Findings | ForEach-Object { $_.Id })
        $ruleIds | Should -Contain "CRASH_DUMP"
        $ruleIds | Should -Contain "PCI_RESET"
        $ruleIds | Should -Contain "NET_LINK_DROP"
        $ruleIds | Should -Contain "UDP_PORT_4266"

        $result.PrimaryFinding | Should -Not -BeNullOrEmpty
        $result.SecondaryFindings.Count | Should -BeGreaterOrEqual 2
    }
}

Describe "DcSystemTelemetry - Get-DcEventXmlData & Get-DcWinEventsTargeted" {
    It "Extracts structured XML EventData key-value properties from an EventLogRecord" {
        $fakeRecord = New-Object PSObject
        $fakeRecord | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
            return @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-PCI" />
    <EventID>1</EventID>
  </System>
  <EventData>
    <Data Name="ResetType">2</Data>
    <Data Name="VendorId">0x8086</Data>
    <Data Name="DeviceId">0x15F3</Data>
  </EventData>
</Event>
"@
        }

        $xmlProps = Get-DcEventXmlData -EventRecord $fakeRecord
        $xmlProps["ResetType"] | Should -Be "2"
        $xmlProps["VendorId"] | Should -Be "0x8086"
        $xmlProps["DeviceId"] | Should -Be "0x15F3"
    }

    It "Batches large Event ID lists into chunks of <= 12 IDs in Get-DcWinEventsTargeted" {
        $global:dcTestBatchCount = 0
        Mock -ModuleName DcSystemTelemetry Get-WinEvent {
            $fh = if ($FilterHashtable -is [array]) { $FilterHashtable[0] } else { $FilterHashtable }
            if ($fh -and $fh.ContainsKey('Id')) {
                $global:dcTestBatchCount++
                if ($fh['Id'].Count -gt 12) {
                    throw "Batch size exceeded 12: $($fh['Id'].Count)"
                }
            }
            return @()
        }

        $ids = 1..25
        $res = Get-DcWinEventsTargeted -LogName "System" -Ids $ids -StartTime (Get-Date).AddHours(-1) -EndTime (Get-Date)
        $global:dcTestBatchCount | Should -Be 3
    }
}

Describe "DcRemediation - Non-Admin WhatIf Dry-Run Support" {
    It "Allows Repair-DcUdpPortRange -WhatIf and Repair-DcAmdDriverAlignment -WhatIf without failing on admin checks" {
        $udpWhatIf = Repair-DcUdpPortRange -WhatIf
        $udpWhatIf | Should -Be $false

        $amdWhatIf = Repair-DcAmdDriverAlignment -WhatIf
        $amdWhatIf | Should -Be $false
    }

    It "Populates structured Steps, Actions, and RecommendedActions on findings and formats HTML guidance as a clean list" {
        $now = Get-Date
        $telemetry = [PSCustomObject]@{
            KernelBugChecks      = @()
            PcieWheaErrors       = @()
            WheaErrors           = @()
            MemoryExhaustion     = @()
            TdrEvents            = @([PSCustomObject]@{ TimeCreated = $now.AddMinutes(-5); Code = "141"; Meaning = "VIDEO_ENGINE_TIMEOUT_DETECTED" })
            SleepTransitions     = @()
            PciePowerManagement  = [PSCustomObject]@{ IsEnabled = $false; ACSettingName = "Off"; SchemeName = "Balanced" }
            PciDeviceResets      = @([PSCustomObject]@{ TimeCreated = $now.AddMinutes(-4); Pdo = "PCI_0"; DeviceLabel = "Intel I225-V"; FriendlyName = "Intel(R) Ethernet Controller (3) I225-V"; Message = "Started -> Uninitialized" })
            NetworkDrops         = @([PSCustomObject]@{ TimeCreated = $now.AddMinutes(-4); InterfaceName = "Ethernet"; Message = "Link disconnected" })
            WlanFailovers        = @()
            UdpPortExhaustions   = @()
            AppHangs             = @()
            AbruptReboots        = @()
            UnexpectedShutdowns  = @()
            FastStartup          = [PSCustomObject]@{ FastStartupEnabled = $false }
        }

        $res = Resolve-DcDiagnosticFindings -ParsedDumps @() -Telemetry $telemetry -ScanMode "LatestIncident" -MaxLookbackDays 30
        $res.PrimaryFinding.Id | Should -Be "GPU_TIMEOUT_EVENT"
        $resIds = @($res.Findings | ForEach-Object { $_.Id })
        $resIds | Should -Contain "GPU_TIMEOUT_EVENT"
        $resIds | Should -Contain "PCI_RESET"
        $resIds | Should -Contain "NET_LINK_DROP"
    }
}

Describe "Gaming NIC Silent DMA Hang, Steam Session Correlation & PCIe ASPM GUID Fixes" {
    It "Queries valid Windows SUB_PCIEXPRESS Subgroup GUID (501a4d13-42af-4429-9fd1-a8218c268e20) in Get-DcPciePowerManagementStatus" {
        $pcie = Get-DcPciePowerManagementStatus
        $pcie | Should -Not -BeNullOrEmpty
        $pcie.ACSettingIndex | Should -Not -BeNullOrEmpty
        $pcie.SchemeGuid | Should -Not -BeNullOrEmpty
    }

    It "Extracts Steam gameplay sessions from streaming_log.txt and correlates mid-game NCSI 4042 Silent DMA Hangs" {
        $tempSteam = Join-Path $PSScriptRoot ("steam_test_" + [guid]::NewGuid().ToString("N"))
        $logsDir = Join-Path $tempSteam "logs"
        New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
        $streamingLog = Join-Path $logsDir "streaming_log.txt"

        try {
            $now = Get-Date
            $gameStart = $now.AddMinutes(-45)
            $ncsiDropTime = $now.AddMinutes(-30) # 15 minutes into game
            $gameEnd = $now.AddMinutes(-10)

            $startStr = $gameStart.ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
            $endStr = $gameEnd.ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)

            $logLines = @(
                "[$startStr][100.123] Game Recording - would start recording game 990080, but recording for this game is disabled",
                "[$startStr][100.456] Adding process 12345 for gameID 990080",
                "[$endStr][2200.789] Game Recording - game stopped [gameid=990080]",
                "[$endStr][2200.900] Removing process 12345 for gameID 990080"
            )
            Set-Content -Path $streamingLog -Value $logLines -Encoding UTF8

            $sessions = @(Get-DcSteamGameSessions -Cutoff $now.AddHours(-2) -EndTime $now -SteamPath $tempSteam)
            $sessions.Count | Should -Be 1
            $sessions[0].AppId | Should -Be "990080"
            $sessions[0].IsActive | Should -Be $false
            $sessions[0].DurationMinutes | Should -BeGreaterThan 30

            $telemObj = [PSCustomObject]@{
                CutoffTime          = $now.AddHours(-2)
                EndTime             = $now
                KernelBugChecks     = @()
                AbruptReboots       = @()
                UnexpectedShutdowns = @()
                WheaErrors          = @()
                PcieWheaErrors      = @()
                TdrEvents           = @()
                StorageErrors       = @()
                MemoryExhaustion    = @()
                SleepTransitions    = @()
                PnpDriverFailures   = @()
                AppCrashes          = @()
                AppHangs            = @()
                PciDeviceResets     = @()
                WlanFailovers       = @()
                PciePowerManagement = [PSCustomObject]@{ IsEnabled = $true; ACSettingName = "Moderate power savings"; SchemeName = "Balanced" }
                FastStartup         = [PSCustomObject]@{ FastStartupEnabled = $false }
                NetworkDrops        = @(
                    [PSCustomObject]@{
                        TimeCreated     = $ncsiDropTime
                        Id              = 4042
                        Provider        = "NCSI"
                        InterfaceName   = "Ethernet (Intel(R) Ethernet Controller (3) I225-V)"
                        Reason          = "SuspectArpProbeFailed"
                        IsSilentDmaHang = $true
                        Message         = "Network Internet capability dropped to None (Reason: SuspectArpProbeFailed - Silent TX/RX DMA Hang without physical link disconnect)"
                    }
                )
                UdpPortExhaustions  = @(
                    [PSCustomObject]@{
                        TimeCreated = $ncsiDropTime.AddMinutes(2)
                        Id          = 4266
                        Provider    = "Tcpip"
                        Message     = "Ephemeral port exhaustion"
                    }
                )
                TopUdpConsumers     = @(
                    [PSCustomObject]@{
                        ProcessName   = "qbittorrent.exe"
                        PID           = 9999
                        EndpointCount = 42
                    }
                )
                StuckServices       = @(
                    [PSCustomObject]@{
                        Name        = "BcastDVRUserService_72e2c"
                        DisplayName = "GameDVR and Broadcast User Service"
                        State       = "Stop Pending"
                        ProcessId   = 8888
                        Message     = "Service 'BcastDVRUserService_72e2c' is stuck in 'Stop Pending' (PID: 8888)."
                    }
                )
            }

            $netHealthMock = @(
                [PSCustomObject]@{
                    Name               = "Ethernet"
                    HasPowerSavingRisk = $true
                    HasForced25GSpeed  = $true
                    PowerSavingSummary = "IdleRestriction=0 (5s Idle Power-Down Active), ULPMode=1"
                    SpeedDuplex        = "2.5 Gbps Full Duplex"
                    IsUdpConstrained   = $true
                    UdpPortRange       = "49152-65535 (16384 ports)"
                    TcpPortRange       = "1024-65535 (64511 ports)"
                }
            )

            $res = Resolve-DcDiagnosticFindings -ParsedDumps @() -Telemetry $telemObj -NetworkHealth $netHealthMock -SteamGameSessions $sessions
            $netFinding = $res.Findings | Where-Object { $_.Id -eq "NET_LINK_DROP" } | Select-Object -First 1
            $netFinding | Should -Not -BeNullOrEmpty
            $netFinding.Description | Should -Match "990080"
            $netFinding.Description | Should -Match "IdleRestriction=0"

            $udpFinding = $res.Findings | Where-Object { $_.Id -eq "UDP_PORT_4266" } | Select-Object -First 1
            $udpFinding | Should -Not -BeNullOrEmpty
            $udpFinding.Description | Should -Match "qbittorrent\.exe"

            $stuckFinding = $res.Findings | Where-Object { $_.Id -eq "STUCK_BACKGROUND_SERVICE" } | Select-Object -First 1
            $stuckFinding | Should -Not -BeNullOrEmpty
            $stuckFinding.Title | Should -Match "BcastDVRUserService"
        } finally {
            if (Test-Path $tempSteam) { Remove-Item $tempSteam -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe "Desktop & Compute TDR Coalescing, WerKernel Exact Timestamps & Display Hotplug Correlation" {
    It "Coalesces companion 0x141 + 0xA1000001 + 0xA2000002 LiveKernelEvents, upgrades to WerKernel Event 1002 second-level timestamps, and correlates Display Hotplug Event 1010 and PowerShell 400 GPU workloads" {
        $now = Get-Date
        $cutoff = $now.AddHours(-24)
        $endTime = $now
        $exactTdrTime = [datetime]::new($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0).AddHours(-2).AddSeconds(50)
        $minTag = $exactTdrTime.ToString("yyyyMMdd-HHmm")

        $global:dcTestExactTdrTime = $exactTdrTime
        $global:dcTestMinTag = $minTag

        $global:dcMsgA2 = @"
Fault bucket , type 0
Event Name: LiveKernelEvent
Problem signature:
P1: a2000002
P2: 11

Attached files:
\\?\C:\ProgramData\Microsoft\Windows\WER\Temp\WER.a2.dmp
\\?\C:\Windows\LiveKernelReports\AMD_REPORT_UM-$minTag.dmp
"@
        $global:dcMsgA1 = @"
Fault bucket , type 0
Event Name: LiveKernelEvent
Problem signature:
P1: a1000001
P2: 1

Attached files:
\\?\C:\Windows\LiveKernelReports\AMD_WATCHDOG-$minTag.dmp
"@
        $global:dcMsg141 = @"
Fault bucket , type 0
Event Name: LiveKernelEvent
Problem signature:
P1: 141
P2: ffffe00a80045050
P3: fffff8056d65d650

Attached files:
\\?\C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-$minTag.dmp
"@
        $global:dcMsgRadar = @"
Fault bucket , type 0
Event Name: RADAR_PRE_LEAK_64
Problem signature:
P1: gpubench.exe
P2: 0.0.0.0
"@

        Mock -ModuleName DcSystemTelemetry Get-CimInstance { return @() }
        Mock -ModuleName DcSystemTelemetry Get-WinEvent {
            $fh = if ($FilterHashtable -is [array]) { $FilterHashtable[0] } else { $FilterHashtable }
            if ($fh -and $fh['LogName'] -eq 'Microsoft-Windows-WerKernel/Operational') {
                return @(
                    [PSCustomObject]@{
                        Id           = 1002
                        ProviderName = 'Microsoft-Windows-WerKernel'
                        TimeCreated  = $global:dcTestExactTdrTime
                        Message      = "Live dump file C:\WINDOWS\LiveKernelReports\WATCHDOG\WATCHDOG-$($global:dcTestMinTag).dmp created."
                    }
                )
            }
            if ($fh -and $fh['ProviderName'] -eq 'Windows Error Reporting' -and ($fh['Id'] -contains 1001)) {
                return @(
                    [PSCustomObject]@{
                        Id           = 1001
                        ProviderName = 'Windows Error Reporting'
                        TimeCreated  = $global:dcTestExactTdrTime.AddMinutes(5)
                        Message      = $global:dcMsgA2
                    },
                    [PSCustomObject]@{
                        Id           = 1001
                        ProviderName = 'Windows Error Reporting'
                        TimeCreated  = $global:dcTestExactTdrTime.AddMinutes(5)
                        Message      = $global:dcMsgA1
                    },
                    [PSCustomObject]@{
                        Id           = 1001
                        ProviderName = 'Windows Error Reporting'
                        TimeCreated  = $global:dcTestExactTdrTime.AddMinutes(5)
                        Message      = $global:dcMsg141
                    },
                    [PSCustomObject]@{
                        Id           = 1001
                        ProviderName = 'Windows Error Reporting'
                        TimeCreated  = $global:dcTestExactTdrTime.AddSeconds(-20)
                        Message      = $global:dcMsgRadar
                    }
                )
            }
            if ($fh -and $fh['LogName'] -eq 'Microsoft-Windows-Kernel-PnP/Device Management') {
                return @(
                    [PSCustomObject]@{
                        Id           = 1010
                        ProviderName = 'Microsoft-Windows-Kernel-PnP'
                        TimeCreated  = $global:dcTestExactTdrTime.AddSeconds(1)
                        Message      = "Device instance ID: DISPLAY\GSM5CE8\5&2ef38343&4&UID268"
                    }
                )
            }
            if ($fh -and $fh['LogName'] -eq 'Windows PowerShell') {
                return @(
                    [PSCustomObject]@{
                        Id           = 400
                        ProviderName = 'PowerShell'
                        TimeCreated  = $global:dcTestExactTdrTime.AddSeconds(-35)
                        Message      = "Engine state is changed from None to Available.`r`nDetails:`r`n`tHostApplication=powershell.exe -Command .\build\gpubench.exe -b RayScheduling --dump-isa"
                    }
                )
            }
            return @()
        }

        $telem = Get-DcSystemTelemetry -Cutoff $cutoff -EndTime $endTime
        $telem.TdrEvents.Count | Should -Be 1
        $telem.TdrEvents[0].Code | Should -Be "141"
        $telem.TdrEvents[0].TimeCreated | Should -Be $exactTdrTime
        ($telem.TdrEvents[0].CompanionCodes -join ",") | Should -Match "0xA2000002"
        ($telem.TdrEvents[0].CompanionCodes -join ",") | Should -Match "0xA1000001"
        $telem.TdrEvents[0].Message | Should -Match "Companion dumps:"

        $telem.DisplayHotplugEvents.Count | Should -Be 1
        $telem.DisplayHotplugEvents[0].DeviceInstanceId | Should -Match "DISPLAY\\GSM5CE8"
        $telem.DisplayHotplugEvents[0].IsDisplayMonitor | Should -Be $true

        $telem.TdrWorkloads.Count | Should -Be 1
        $telem.TdrWorkloads[0].ProcessName | Should -Be "gpubench.exe"
        $telem.TdrWorkloads[0].CommandLine | Should -Match "RayScheduling"

        # Verify Resolve-DcDiagnosticFindings surfaces the compute workload, display hotplug, default 2s TdrDelay, and RepairGpuSleep action
        $telem.GraphicsDriverSettings = [PSCustomObject]@{
            TdrDelay        = $null
            TdrLevel        = $null
            TdrDdiDelay     = $null
            HwSchMode       = 2
            HAGSStatus      = "Enabled (Hardware-Accelerated GPU Scheduling)"
            IsUlpsEnabled   = $true
            OverlayTestMode = $null
            IsMpoDisabled   = $false
        }
        $telem.PciePowerManagement = [PSCustomObject]@{ IsEnabled = $false; ACSettingName = "Off"; SchemeName = "Balanced" }
        $telem.FastStartup = [PSCustomObject]@{ FastStartupEnabled = $false }

        $res = Resolve-DcDiagnosticFindings -ParsedDumps @() -Telemetry $telem -ScanMode "LatestIncident" -MaxLookbackDays 30
        $res.PrimaryFinding.Id | Should -Be "GPU_TIMEOUT_EVENT"
        $res.PrimaryFinding.Description | Should -Match "gpubench\.exe"
        $res.PrimaryFinding.Description | Should -Match "DISPLAY\\GSM5CE8"
        $res.PrimaryFinding.Description | Should -Match "2-second default"
    }

    It "Detects 64-bit Resizable BAR (CmResourceTypeMemoryLarge) aperture in Get-DcRebarStatus instead of returning 1 MB from broken __RELPATH join" {
        $rebar = Get-DcRebarStatus
        $rebar | Should -Not -BeNullOrEmpty
        $rebar.BarSizeMb | Should -BeGreaterOrEqual 256
    }
}

Describe "Non-Admin Lock-Safe Shared Log Reading & Steam Game Process History" {
    It "Reads lines from an actively write-locked log file via Read-DcSharedLogLines without sharing violation" {
        $tempLog = Join-Path $PSScriptRoot ("locked_log_" + [guid]::NewGuid().ToString("N") + ".txt")
        $writer = $null
        try {
            $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
            $writer = [System.IO.FileStream]::new($tempLog, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::Write, $share)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes("line-1: init`r`nline-2: shader compile failed`r`nline-3: tail marker`r`n")
            $writer.Write($bytes, 0, $bytes.Length)
            $writer.Flush()

            $readBack = @(Read-DcSharedLogLines -Path $tempLog -Tail 2)
            $readBack.Count | Should -Be 2
            $readBack[0] | Should -Match "shader compile failed"
            $readBack[1] | Should -Match "tail marker"
        } finally {
            if ($writer) { try { $writer.Dispose() } catch {} }
            if (Test-Path $tempLog) { Remove-Item $tempLog -Force -ErrorAction SilentlyContinue }
        }
    }

    It "Parses gameprocess_log.txt exit codes and resolves GameName from appmanifest_*.acf" {
        $tempSteam = Join-Path $PSScriptRoot ("steam_gp_" + [guid]::NewGuid().ToString("N"))
        $logsDir = Join-Path $tempSteam "logs"
        $saDir = Join-Path $tempSteam "steamapps"
        New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
        New-Item -Path $saDir -ItemType Directory -Force | Out-Null

        try {
            $now = Get-Date
            $t0 = $now.AddMinutes(-20).ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
            $t1 = $now.AddMinutes(-5).ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)

            Set-Content -Path (Join-Path $saDir "appmanifest_990080.acf") -Value @(
                '"AppState"'
                '{'
                '    "appid"    "990080"'
                '    "name"     "Test Shader Game 990080"'
                '    "installdir" "TestShaderGame"'
                '}'
            ) -Encoding UTF8

            Set-Content -Path (Join-Path $logsDir "gameprocess_log.txt") -Value @(
                "[$t0] AppID 990080 adding PID 4242"
                "[$t1] AppID 990080 no longer tracking PID 4242, exit code -1073741819"
                "[$t1] Remove 990080 from running list"
            ) -Encoding UTF8

            $sessions = @(Get-DcSteamGameSessions -Cutoff $now.AddHours(-2) -EndTime $now -SteamPath $tempSteam)
            $sessions.Count | Should -Be 1
            $sessions[0].AppId | Should -Be "990080"
            $sessions[0].GameName | Should -Be "Test Shader Game 990080"
            $sessions[0].ExitedAbnormally | Should -Be $true
            $sessions[0].ExitCode | Should -Be -1073741819
        } finally {
            if (Test-Path $tempSteam) { Remove-Item $tempSteam -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe "Minidump Unloaded Modules, Third-Party Overlay Detection & Fast Synthetic Dump Skip" {
    It "Resolves <Unloaded_NahimicOSD.dll> via Type 14 stream, detects overlay fault, and skips CDB fast on tiny synthetic MDMP" {
        $tempDump = Join-Path $PSScriptRoot ("test_unloaded_" + [guid]::NewGuid().ToString("N") + ".dmp")
        try {
            $ms = New-Object System.IO.MemoryStream
            $bw = New-Object System.IO.BinaryWriter($ms)

            # MDMP Header (32 bytes): 4 streams
            $bw.Write([UInt32]0x504D444D)
            $bw.Write([UInt32]0x0000A793)
            $bw.Write([UInt32]4)
            $bw.Write([UInt32]32)
            $bw.Write([UInt32]0)
            $bw.Write([UInt32]0)
            $bw.Write([UInt64]0)

            # Directory (4 * 12 = 48 bytes -> offset 80)
            # 0: SystemInfoStream (7) RVA 80, Size 56
            $bw.Write([UInt32]7);  $bw.Write([UInt32]56);  $bw.Write([UInt32]80)
            # 1: ModuleListStream (4) RVA 136, Size 112 (4 + 108)
            $bw.Write([UInt32]4);  $bw.Write([UInt32]112); $bw.Write([UInt32]136)
            # 2: ExceptionStream (6) RVA 248, Size 168
            $bw.Write([UInt32]6);  $bw.Write([UInt32]168); $bw.Write([UInt32]248)
            # 3: UnloadedModuleListStream (14) RVA 416, Size 36 (12 + 24)
            $bw.Write([UInt32]14); $bw.Write([UInt32]36);  $bw.Write([UInt32]416)

            # SystemInfoStream @ 80 (56 bytes)
            $bw.Write([UInt16]9)
            $bw.Write([byte[]]::new(54))

            # ModuleListStream @ 136 (112 bytes) -> ends at 248
            $bw.Write([UInt32]1)
            $bw.Write([uint64]"0x140000000")
            $bw.Write([uint32]"0x00100000")
            $bw.Write([UInt32]0)
            $bw.Write([UInt32]1700000000)
            $bw.Write([UInt32]452)
            $bw.Write([byte[]]::new(52))
            $bw.Write([byte[]]::new(32))

            # ExceptionStream @ 248 (168 bytes) -> ends at 416
            $bw.Write([UInt32]100)
            $bw.Write([UInt32]0)
            $bw.Write([uint32]"0xC0000005")
            $bw.Write([UInt32]0)
            $bw.Write([uint64]0)
            $bw.Write([uint64]"0x7FFA50001234")
            $bw.Write([byte[]]::new(136))

            # UnloadedModuleListStream @ 416 (36 bytes) -> ends at 452
            $bw.Write([UInt32]12)
            $bw.Write([UInt32]24)
            $bw.Write([UInt32]1)
            $bw.Write([uint64]"0x7FFA50000000")
            $bw.Write([uint32]"0x00010000")
            $bw.Write([UInt32]0)
            $bw.Write([UInt32]0)
            $bw.Write([UInt32]520)

            # Strings @ 452 & 520
            $m0Bytes = [System.Text.Encoding]::Unicode.GetBytes("C:\Games\TestGame.exe")
            $bw.Write([UInt32]$m0Bytes.Length)
            $bw.Write($m0Bytes)
            $padLen = 520 - [int]$ms.Position
            if ($padLen -gt 0) { $bw.Write([byte[]]::new($padLen)) }
            $ulBytes = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Nahimic\NahimicOSD.dll")
            $bw.Write([UInt32]$ulBytes.Length)
            $bw.Write($ulBytes)

            [System.IO.File]::WriteAllBytes($tempDump, $ms.ToArray())
            $bw.Close()
            $ms.Close()

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $parsed = Read-DcMinidump -Path $tempDump
            $sw.Stop()

            $sw.Elapsed.TotalSeconds | Should -BeLessThan 3
            $parsed | Should -Not -BeNullOrEmpty
            $parsed.FaultingIP | Should -Match "<Unloaded_NahimicOSD\.dll>\+0x1234"
            $parsed.IsOverlayFault | Should -Be $true
            $parsed.OverlayName | Should -Match "NahimicOSD"
        } finally {
            if (Test-Path $tempDump) { Remove-Item $tempDump -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe "Non-Admin WER ReportArchive Parsing (Named AppCrash + ACL-Blocked Kernel Metadata)" {
    It "Parses FaultModule/Bucket from AppCrash Report.wer and emits MetadataOnly entry when Kernel_141 Report.wer is ACL-denied" {
        $tempWer = Join-Path $PSScriptRoot ("wer_test_" + [guid]::NewGuid().ToString("N"))
        $appDir = Join-Path $tempWer "AppCrash_mygame.exe_1111"
        $kernDir = Join-Path $tempWer "Kernel_141_2222"
        $kernWer = Join-Path $kernDir "Report.wer"
        $denyRule = $null

        try {
            New-Item -Path $appDir -ItemType Directory -Force | Out-Null
            New-Item -Path $kernDir -ItemType Directory -Force | Out-Null

            $ft = [datetime]::UtcNow.ToFileTime()
            Set-Content -Path (Join-Path $appDir "Report.wer") -Value @(
                "EventType=APPCRASH"
                "FriendlyEventName=Stopped working"
                "AppName=mygame.exe"
                "AppPath=C:\Games\mygame.exe"
                "EventTime=$ft"
                "Bucket=AV_NahimicOSD!Hook"
                "Sig[0].Name=Application Name"
                "Sig[0].Value=mygame.exe"
                "Sig[3].Name=Fault Module Name"
                "Sig[3].Value=NahimicOSD.dll"
                "Sig[6].Name=Exception Code"
                "Sig[6].Value=c0000005"
                "Sig[7].Name=Exception Offset"
                "Sig[7].Value=0000000000012340"
            ) -Encoding Unicode

            Set-Content -Path $kernWer -Value "EventType=LiveKernelEvent" -Encoding Unicode
            $idRef = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule($idRef, "ReadData", "Deny")
            $acl = Get-Acl -LiteralPath $kernWer
            $acl.AddAccessRule($denyRule)
            Set-Acl -LiteralPath $kernWer -AclObject $acl

            $reports = @(Get-DcWerReportArchive -Cutoff (Get-Date).AddHours(-1) -EndTime (Get-Date).AddMinutes(5) -CustomArchivePaths @($tempWer))
            $appRep = $reports | Where-Object { $_.FolderName -eq "AppCrash_mygame.exe_1111" } | Select-Object -First 1
            $kernRep = $reports | Where-Object { $_.FolderName -eq "Kernel_141_2222" } | Select-Object -First 1

            $appRep | Should -Not -BeNullOrEmpty
            $appRep.FaultModule | Should -Be "NahimicOSD.dll"
            $appRep.Bucket | Should -Be "AV_NahimicOSD!Hook"
            $appRep.IsOverlayFault | Should -Be $true

            $kernRep | Should -Not -BeNullOrEmpty
            $kernRep.MetadataOnly | Should -Be $true
            $kernRep.BugCheckOrCode | Should -Be "141"
            $kernRep.IsTdrOrGpu | Should -Be $true
        } finally {
            if ($denyRule -and (Test-Path $kernWer)) {
                try {
                    $aclFix = Get-Acl -LiteralPath $kernWer
                    $aclFix.RemoveAccessRuleAll($denyRule)
                    Set-Acl -LiteralPath $kernWer -AclObject $aclFix
                } catch {}
            }
            if (Test-Path $tempWer) { Remove-Item $tempWer -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe "Timeout & Crash Cause Separation (Resolve-DcIncidentAttribution) & Safe HTML Rendering" {
    It "Classifies overlay TDRs as APP_OR_OVERLAY, excludes DDU recommendation, and HTML-encodes <Unloaded_*.dll>" {
        $now = Get-Date
        $dumpObj = [PSCustomObject]@{
            FileName         = "game.exe.1001.dmp"
            Timestamp        = $now.AddSeconds(-5)
            MainExecutable   = "game.exe"
            ExceptionCode    = "0xC0000005"
            ExceptionMeaning = "Access Violation"
            FaultingModule   = "<Unloaded_NahimicOSD.dll>"
            FaultingIP       = "<Unloaded_NahimicOSD.dll>+0x1234"
            IsOverlayFault   = $true
            OverlayName      = "NahimicOSD.dll"
            IsShaderCompiler = $false
            IsKernelDump     = $false
            Assertions       = @()
            CallStack        = @()
            ApiContext       = ""
            GpuDriverVersion = $null
        }
        $telem = [PSCustomObject]@{
            IsElevated           = $false
            TdrEvents            = @([PSCustomObject]@{ TimeCreated = $now; Code = "141"; Meaning = "VIDEO_ENGINE_TIMEOUT_DETECTED"; Message = "LiveKernelEvent 141" })
            WerKernelEvents      = @()
            WerAppReports        = @()
            AppCrashes           = @()
            TdrWorkloads         = @()
            MemoryExhaustion     = @()
            SleepTransitions     = @()
            PcieWheaErrors       = @()
            WheaErrors           = @()
            DisplayHotplugEvents = @()
            KernelBugChecks      = @()
            AbruptReboots        = @()
        }

        $attrs = @(Resolve-DcIncidentAttribution -Dumps @($dumpObj) -Telemetry $telem)
        $attrs.Count | Should -Be 1
        $attrs[0].Classification | Should -Be "APP_OR_OVERLAY"
        $attrs[0].IsGpuDriverFault | Should -Be $false
        $attrs[0].BlamedComponent | Should -Match "NahimicOSD"

        $fakeForensics = [PSCustomObject]@{
            Crashes              = @()
            GpuDisplayEvents     = @([PSCustomObject]@{ Category = "GPU Driver Timeout (TDR)"; Time = $now; Code = "0x141"; Summary = "TDR"; Explanation = ""; ActiveApps = @(); PrecedingEvents = @() })
            LiveKernelHistory    = @()
            Patterns             = $null
            IncidentAttributions = $attrs
        }
        $plain = Get-DcPlainEnglishSummary -Forensics $fakeForensics -Dumps @($dumpObj) -Telemetry $telem -Attributions $attrs
        (($plain.SensibleNextChecks) -join "`n") | Should -Not -Match "\bDDU\b"

        $tempHtml = Join-Path $PSScriptRoot ("report_encode_" + [guid]::NewGuid().ToString("N") + ".html")
        try {
            $reportData = [PSCustomObject]@{
                RootCauseTitle       = "GPU Timeout Caused by Overlay"
                RootCauseDescription = "NahimicOSD.dll faulted"
                RootCauseSeverity    = "Warning"
                RootCauseGuidance    = ""
                Findings             = @()
                SecondaryFindings    = @()
                Dumps                = @()
                EngineLogs           = @()
                SteamLogs            = @()
                Telemetry            = $telem
                Hardware             = $null
                CrashForensics       = [PSCustomObject]@{
                    Crashes              = @()
                    GpuDisplayEvents     = @()
                    LiveKernelHistory    = @()
                    IncidentAttributions = $attrs
                    PlainSummary         = $plain
                }
            }
            Export-DcHtmlReport -ReportData $reportData -OutputPath $tempHtml
            $htmlContent = [System.IO.File]::ReadAllText($tempHtml)
            $htmlContent | Should -Match "Standard User Scan \(No Admin\)"
            $htmlContent | Should -Match "&lt;Unloaded_NahimicOSD\.dll&gt;"
            $htmlContent | Should -Not -Match "<Unloaded_NahimicOSD\.dll>"
            $htmlContent.Contains('<Unloaded_') | Should -Be $false
        } finally {
            if (Test-Path $tempHtml) { Remove-Item $tempHtml -Force -ErrorAction SilentlyContinue }
        }
    }

    It "Classifies SHADER_OR_WORKLOAD, OS_OR_SYSTEM_EVENT (Event 2004 OOM & 0x193/0x810), DEVICE_OR_HARDWARE (standalone 1010), cross-app GPU_DRIVER, and UNATTRIBUTED accurately" {
        $now = Get-Date
        $baseTel = @{
            IsElevated = $false; WerAppReports = @(); AppCrashes = @(); TdrWorkloads = @()
            MemoryExhaustion = @(); SleepTransitions = @(); PcieWheaErrors = @(); WheaErrors = @()
            DisplayHotplugEvents = @(); KernelBugChecks = @(); AbruptReboots = @(); WerKernelEvents = @(); TdrEvents = @()
        }

        # 1. SHADER_OR_WORKLOAD via engine DRED log
        $tShader = [PSCustomObject]$baseTel
        $tShader.TdrEvents = @([PSCustomObject]@{ TimeCreated = $now; Code = "141"; Meaning = "TDR"; Message = "141" })
        $engDred = [PSCustomObject]@{ FullName = "Saved\Logs\game.log"; LogName = "game.log"; Engine = "Unreal"; GameName = "MyUE5Game"; Timestamp = $now.AddSeconds(-3); GpuErrorCode = "DXGI_ERROR_DEVICE_HUNG"; ShaderInfo = "NaniteBasePass"; Breadcrumbs = "DrawIndexed(Foliage)"; ErrorLines = @() }
        $aShader = @(Resolve-DcIncidentAttribution -Telemetry $tShader -EngineLogs @($engDred))
        $aShader[0].Classification | Should -Be "SHADER_OR_WORKLOAD"
        $aShader[0].IsGpuDriverFault | Should -Be $false

        # 2. OS_OR_SYSTEM_EVENT (Event 2004 OOM + 0x193 P2=0x810)
        $tOom = [PSCustomObject]$baseTel
        $tOom.TdrEvents = @([PSCustomObject]@{ TimeCreated = $now; Code = "141"; Meaning = "TDR"; Message = "141" })
        $tOom.MemoryExhaustion = @([PSCustomObject]@{ TimeCreated = $now.AddSeconds(-45); Id = 2004; Message = "Low virtual memory"; TopConsumers = "app.exe (22 GB)" })
        $tOom.WerKernelEvents = @([PSCustomObject]@{ TimeCreated = $now.AddMinutes(-30); BugCheckOrCode = "193"; Parameter2 = "0x810"; Component = "ProcessDeadlockThread"; Message = "0x193" })
        $aOom = @(Resolve-DcIncidentAttribution -Telemetry $tOom)
        $aOom.Count | Should -Be 2
        $aOom[0].Classification | Should -Be "OS_OR_SYSTEM_EVENT"
        $aOom[1].Classification | Should -Be "OS_OR_SYSTEM_EVENT"
        $aOom[0].IsGpuDriverFault | Should -Be $false

        # 3. DEVICE_OR_HARDWARE (standalone DisplayHotplug 1010)
        $tDisp = [PSCustomObject]$baseTel
        $tDisp.DisplayHotplugEvents = @([PSCustomObject]@{ TimeCreated = $now.AddMinutes(-10); DeviceInstanceId = "DISPLAY\GSM5CE8\5&2ef38343"; IsDisplayMonitor = $true })
        $aDisp = @(Resolve-DcIncidentAttribution -Telemetry $tDisp)
        $aDisp.Count | Should -Be 1
        $aDisp[0].Classification | Should -Be "DEVICE_OR_HARDWARE"
        $aDisp[0].IsGpuDriverFault | Should -Be $false

        # 4. GPU_DRIVER confirmed via identical module+offset across 2+ distinct apps + triggers DDU next check
        $tEmpty = [PSCustomObject]$baseTel
        $d1 = [PSCustomObject]@{ FileName = "pathways.exe.111.dmp"; Timestamp = $now.AddMinutes(-5); MainExecutable = "pathways.exe"; FaultingModule = "amdvlk64.dll"; FaultingIP = "amdvlk64.dll+0x2EA0055"; IsShaderCompiler = $false; IsKernelDump = $false; ApiContext = "" }
        $d2 = [PSCustomObject]@{ FileName = "test_taa.exe.222.dmp"; Timestamp = $now.AddMinutes(-1); MainExecutable = "test_taa.exe"; FaultingModule = "amdvlk64.dll"; FaultingIP = "amdvlk64.dll+0x2EA0055"; IsShaderCompiler = $false; IsKernelDump = $false; ApiContext = "" }
        $aDrv = @(Resolve-DcIncidentAttribution -Dumps @($d1, $d2) -Telemetry $tEmpty)
        $drvHit = $aDrv | Where-Object { $_.Classification -eq "GPU_DRIVER" } | Select-Object -First 1
        $drvHit | Should -Not -BeNullOrEmpty
        $drvHit.IsGpuDriverFault | Should -Be $true
        $drvHit.Confidence | Should -Be "Confirmed"
        $drvHit.FaultKey | Should -Match "amdvlk64\.dll\+0x2ea0055"

        $fakeForensicsDrv = [PSCustomObject]@{ Crashes = @(); GpuDisplayEvents = @(); LiveKernelHistory = @(); Patterns = $null; IncidentAttributions = $aDrv }
        $plainDrv = Get-DcPlainEnglishSummary -Forensics $fakeForensicsDrv -Dumps @($d1, $d2) -Telemetry $tEmpty -Attributions $aDrv
        (($plainDrv.SensibleNextChecks) -join "`n") | Should -Match "\bDDU\b"

        # 5. UNATTRIBUTED bare TDR without logs
        $tBare = [PSCustomObject]$baseTel
        $tBare.TdrEvents = @([PSCustomObject]@{ TimeCreated = $now; Code = "141"; Meaning = "TDR"; Message = "141" })
        $aBare = @(Resolve-DcIncidentAttribution -Telemetry $tBare)
        $aBare.Count | Should -Be 1
        $aBare[0].Classification | Should -Be "UNATTRIBUTED"
        $aBare[0].IsGpuDriverFault | Should -Be $false

        # 6. Non-GPU WerKernelEvents with empty Code should be ignored and never produce 'LiveKernelEvent 0x'
        $tNonGpuWk = [PSCustomObject]$baseTel
        $tNonGpuWk.WerKernelEvents = @([PSCustomObject]@{ TimeCreated = $now.AddMinutes(-2); Code = ""; DumpFile = "NDIS-20261114-1200.dmp"; Component = "NDIS"; Message = "NDIS live dump" })
        $aNonGpuWk = @(Resolve-DcIncidentAttribution -Telemetry $tNonGpuWk)
        $aNonGpuWk.Count | Should -Be 0
        (($aNonGpuWk | ForEach-Object { "$($_.SurfaceSymptom) $($_.PlainVerdict)" }) -join "`n") | Should -Not -Match "0x\)|LiveKernelEvent 0x\b"
    }
}

Describe "Explicit Friendly GPU Driver Version & Post-Install Timing Correlation" {
    It "Formats AMD, NVIDIA, and Intel friendly GPU driver strings via ConvertTo-DcFriendlyGpuVersion without duplication" {
        $amdVer = ConvertTo-DcFriendlyGpuVersion -Vendor "AMD" -WddmVersion "32.0.32015.16001" -MarketingVersion "26.11.2"
        $amdVer.DisplayVersion | Should -Be "26.11.2 (32.0.32015.16001)"
        $amdVer.FriendlyDriverLabel | Should -Be "AMD GPU driver 26.11.2 (32.0.32015.16001)"

        $nvVer = ConvertTo-DcFriendlyGpuVersion -Vendor "NVIDIA" -WddmVersion "32.0.15.6614"
        $nvVer.MarketingVersion | Should -Be "566.14"
        $nvVer.DisplayVersion | Should -Be "566.14 (32.0.15.6614)"
        $nvVer.FriendlyDriverLabel | Should -Be "NVIDIA GPU driver 566.14 (32.0.15.6614)"

        $intelVer = ConvertTo-DcFriendlyGpuVersion -Vendor "Intel" -WddmVersion "32.0.101.6129" -MarketingVersion "32.0.101.6129"
        $intelVer.DisplayVersion | Should -Be "32.0.101.6129"
        $intelVer.FriendlyDriverLabel | Should -Be "Intel GPU driver 32.0.101.6129"
    }

    It "Correlates GPU crashes/timeouts with DriverInstallDate in Format-DcDriverInstallTiming, Resolve-DcIncidentAttribution, and Get-DcPlainEnglishSummary" {
        $now = Get-Date
        $baseDate = [datetime]::new($now.Year, $now.Month, $now.Day, 10, 0, 0).AddDays(-2)
        $instDate = $baseDate                      # e.g. Day -2 at 10:00
        $postCrash = $baseDate.AddDays(1).AddHours(3)  # Day -1 at 13:00 -> calendar day after
        $preCrash = $baseDate.AddHours(-17)            # Day -3 at 17:00 -> day before

        $tAfter = Format-DcDriverInstallTiming -IncidentTime $postCrash -InstallTime $instDate -DriverLabel "AMD GPU driver 26.11.2 (32.0.32015.16001)"
        $tAfter | Should -Not -BeNullOrEmpty
        $tAfter.Relation | Should -Be "AfterInstall"
        $tAfter.Phrase | Should -Match "the day after AMD GPU driver 26\.11\.2 \(32\.0\.32015\.16001\) was installed"

        $tBefore = Format-DcDriverInstallTiming -IncidentTime $preCrash -InstallTime $instDate -DriverLabel "AMD GPU driver 26.11.2 (32.0.32015.16001)"
        $tBefore | Should -Not -BeNullOrEmpty
        $tBefore.Relation | Should -Be "BeforeInstall"
        $tBefore.Phrase | Should -Match "day before AMD GPU driver 26\.11\.2 \(32\.0\.32015\.16001\) was installed"

        $hwMock = [PSCustomObject]@{
            Gpus = @(
                [PSCustomObject]@{
                    Name                = "AMD Radeon RX 7900 XTX"
                    Vendor              = "AMD"
                    DriverVersion       = "32.0.32015.16001"
                    MarketingVersion    = "26.11.2"
                    DisplayVersion      = "26.11.2 (32.0.32015.16001)"
                    FriendlyDriverLabel = "AMD GPU driver 26.11.2 (32.0.32015.16001)"
                    DriverDate          = $instDate.AddDays(-2)
                    DriverPackageDate   = $instDate.AddDays(-2)
                    DriverInstallDate   = $instDate
                    Status              = "OK"
                    IsGeneric           = $false
                    IsHighBoostCard     = $true
                    AmdInstallType      = "Full (Adrenalin GUI)"
                }
            )
            Memory        = $null
            PhysicalDisks = $null
            WheaEvents    = @()
        }

        # Case A: GPU 0x119 BSOD started the day after install
        $bsodAfterDump = [PSCustomObject]@{
            FileName           = "after_install.dmp"
            Timestamp          = $postCrash
            CrashTime          = $postCrash
            ExceptionCode      = "0x00000119"
            DebuggerModuleName = "amdkmdag"
            FailureBucket      = "0x119_5_amdkmdag"
            GpuDriverVersion   = "32.0.32015.16001"
            IsKernelDump       = $true
            CdbInspected       = $true
            BugcheckArgs       = @("0x5", "0x0", "0x0", "0x0")
            AnalysisDetail     = [PSCustomObject]@{ ProcessName = "System" }
        }
        $telemAfter = [PSCustomObject]@{
            IsElevated = $true; WerAppReports = @(); AppCrashes = @(); TdrWorkloads = @()
            MemoryExhaustion = @(); SleepTransitions = @(); PcieWheaErrors = @(); WheaErrors = @()
            DisplayHotplugEvents = @(); AbruptReboots = @(); WerKernelEvents = @(); TdrEvents = @()
            KernelBugChecks = @(
                [PSCustomObject]@{ TimeCreated = $postCrash; Code = "0x00000119"; Meaning = "VIDEO_SCHEDULER_INTERNAL_ERROR"; WatsonBucket = "0x119_5_amdkmdag"; Message = "0x00000119" }
            )
        }
        $fcAfter = @([PSCustomObject]@{ Kind = "Bugcheck (BSOD)"; BugcheckCode = "0x00000119"; LogTime = $postCrash; CrashTime = $postCrash; Dump = $bsodAfterDump })
        $attrsAfter = @(Resolve-DcIncidentAttribution -Dumps @($bsodAfterDump) -Telemetry $telemAfter -Hardware $hwMock -ForensicsCrashes $fcAfter)
        $attrsAfter.Count | Should -Be 1
        $attrsAfter[0].Classification | Should -Be "GPU_DRIVER"
        $attrsAfter[0].BlamedComponent | Should -Match "AMD GPU driver 26\.11\.2 \(32\.0\.32015\.16001\)"
        $attrsAfter[0].PlainVerdict | Should -Match "the day after AMD GPU driver 26\.11\.2 \(32\.0\.32015\.16001\) was installed"

        $fakeForensicsAfter = [PSCustomObject]@{ Crashes = $fcAfter; GpuDisplayEvents = @(); LiveKernelHistory = @(); Patterns = $null; IncidentAttributions = $attrsAfter }
        $plainAfter = Get-DcPlainEnglishSummary -Forensics $fakeForensicsAfter -Dumps @($bsodAfterDump) -Telemetry $telemAfter -Hardware $hwMock -Attributions $attrsAfter
        (($plainAfter.ConfirmedFacts) -join "`n") | Should -Match "the day after AMD GPU driver 26\.11\.2 \(32\.0\.32015\.16001\) was installed"
        (($plainAfter.SensibleNextChecks) -join "`n") | Should -Match "AMD GPU driver 26\.11\.2 \(32\.0\.32015\.16001\)"

        # Case B: Crashes occurred BOTH before and after install (factual distinction, no false sole causation)
        $bsodBeforeDump = [PSCustomObject]@{
            FileName           = "before_install.dmp"
            Timestamp          = $preCrash
            CrashTime          = $preCrash
            ExceptionCode      = "0x00000119"
            DebuggerModuleName = "amdkmdag"
            FailureBucket      = "0x119_5_amdkmdag"
            IsKernelDump       = $true
            CdbInspected       = $true
            BugcheckArgs       = @("0x5", "0x0", "0x0", "0x0")
            AnalysisDetail     = [PSCustomObject]@{ ProcessName = "System" }
        }
        $telemBoth = [PSCustomObject]@{
            IsElevated = $true; WerAppReports = @(); AppCrashes = @(); TdrWorkloads = @()
            MemoryExhaustion = @(); SleepTransitions = @(); PcieWheaErrors = @(); WheaErrors = @()
            DisplayHotplugEvents = @(); AbruptReboots = @(); WerKernelEvents = @(); TdrEvents = @()
            KernelBugChecks = @(
                [PSCustomObject]@{ TimeCreated = $postCrash; Code = "0x00000119"; Meaning = "VIDEO_SCHEDULER_INTERNAL_ERROR"; WatsonBucket = "0x119_5_amdkmdag"; Message = "0x00000119" },
                [PSCustomObject]@{ TimeCreated = $preCrash; Code = "0x00000119"; Meaning = "VIDEO_SCHEDULER_INTERNAL_ERROR"; WatsonBucket = "0x119_5_amdkmdag"; Message = "0x00000119" }
            )
        }
        $fcBoth = @(
            [PSCustomObject]@{ Kind = "Bugcheck (BSOD)"; BugcheckCode = "0x00000119"; LogTime = $postCrash; CrashTime = $postCrash; Dump = $bsodAfterDump },
            [PSCustomObject]@{ Kind = "Bugcheck (BSOD)"; BugcheckCode = "0x00000119"; LogTime = $preCrash; CrashTime = $preCrash; Dump = $bsodBeforeDump }
        )
        $attrsBoth = @(Resolve-DcIncidentAttribution -Dumps @($bsodAfterDump, $bsodBeforeDump) -Telemetry $telemBoth -Hardware $hwMock -ForensicsCrashes $fcBoth)
        $preAttr = @($attrsBoth | Where-Object { $_.Timestamp -eq $preCrash })[0]
        $preAttr | Should -Not -BeNullOrEmpty
        $preAttr.BlamedComponent | Should -Be "amdkmdag (previous GPU driver)"
        $fakeForensicsBoth = [PSCustomObject]@{ Crashes = $fcBoth; GpuDisplayEvents = @(); LiveKernelHistory = @(); Patterns = $null; IncidentAttributions = $attrsBoth }
        $plainBoth = Get-DcPlainEnglishSummary -Forensics $fakeForensicsBoth -Dumps @($bsodAfterDump, $bsodBeforeDump) -Telemetry $telemBoth -Hardware $hwMock -Attributions $attrsBoth
        (($plainBoth.ConfirmedFacts) -join "`n") | Should -Match "occurred both before.*previous driver.*and the day after AMD GPU driver 26\.11\.2 \(32\.0\.32015\.16001\) was installed"
        $gpuRefreshCheck = @($plainBoth.SensibleNextChecks | Where-Object { $_ -match 'Refresh the GPU driver cleanly' })[0]
        $gpuRefreshCheck | Should -Not -Match "26\.11\.2 \(32\.0\.32015\.16001\) \([^)]*26\.11\.2"

        # Case C: HTML report renders Elevated Scan (Admin) via SystemTelemetry and friendly GPU version + Installed date
        $tempHtml = Join-Path $PSScriptRoot ("report_gpuver_" + [guid]::NewGuid().ToString("N") + ".html")
        try {
            $reportObj = [PSCustomObject]@{
                ScanMode             = "AllIncidents"
                HoursScanned         = 48
                RootCauseTitle       = "GPU Driver Test"
                RootCauseDescription = "0x119"
                RootCauseSeverity    = "Critical"
                RootCauseGuidance    = ""
                Findings             = @()
                SecondaryFindings    = @()
                Dumps                = @($bsodAfterDump)
                EngineLogs           = @()
                SteamLogs            = @()
                SystemTelemetry      = $telemAfter
                HardwareHealth       = [PSCustomObject]@{ Gpus = $hwMock.Gpus; Motherboard = $null; Memory = $null; PhysicalDisks = $null; WheaEvents = @(); RebarStatus = $null; KernelDrivers = @(); PnpIssues = @(); Displays = @(); NetworkAdapters = @(); DualGpuConflict = $false; HybridMultiGpu = $false; IsUlpsEnabled = $false }
                CrashForensics       = [PSCustomObject]@{ Crashes = @(); GpuDisplayEvents = @(); LiveKernelHistory = @(); IncidentAttributions = $attrsAfter; PlainSummary = $plainAfter }
            }
            Export-DcHtmlReport -ReportData $reportObj -OutputPath $tempHtml
            $htmlText = [System.IO.File]::ReadAllText($tempHtml)
            $htmlText | Should -Match "Elevated Scan \(Admin\)"
            $htmlText | Should -Match "26\.11\.2 \(32\.0\.32015\.16001\)"
            $htmlText | Should -Match "Installed: $($instDate.ToString('yyyy-MM-dd HH:mm'))"
        } finally {
            if (Test-Path $tempHtml) { Remove-Item $tempHtml -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe "Live-Run Forensics Fixes: LiveKernelReports Separation, HARDWARE_ID, Elevated Prompts & NVMe SMART" {
    It "Deduplicates LiveKernelReports companion dumps and separates non-fatal live dumps from fatal BSODs" {
        $rootTemp = Join-Path $env:TEMP "dc_test_lkr_$([guid]::NewGuid().ToString('N').Substring(0,8))"
        $liveRoot = Join-Path $rootTemp "LiveKernelReports"
        $liveNdis = Join-Path $liveRoot "NDIS"
        $miniDir  = Join-Path $rootTemp "Minidump"
        New-Item -ItemType Directory -Path $liveNdis, $miniDir -Force | Out-Null
        try {
            $subLive = Join-Path $liveNdis "NDIS-20261114-1448.dmp"
            $bigLive = Join-Path $liveRoot "NDIS-20261114-1448.dmp"
            $miniDmp = Join-Path $miniDir  "111426-11031-01.dmp"

            [System.IO.File]::WriteAllBytes($subLive, (New-Object byte[] 256))
            [System.IO.File]::WriteAllBytes($bigLive, (New-Object byte[] 1024))
            [System.IO.File]::WriteAllBytes($miniDmp, (New-Object byte[] 128))

            $now = Get-Date
            (Get-Item $subLive).LastWriteTime = $now.AddMinutes(-7)
            (Get-Item $bigLive).LastWriteTime = $now.AddMinutes(-8)
            (Get-Item $miniDmp).LastWriteTime = $now.AddMinutes(-60)

            $dumps = @(Get-DcCrashDumps -Cutoff $now.AddHours(-24) -EndTime $now -CustomDirectories @($liveRoot, $liveNdis, $miniDir))
            $ndisMatches = @($dumps | Where-Object { $_.Name -eq 'NDIS-20261114-1448.dmp' })
            $ndisMatches.Count | Should -Be 1
            $ndisMatches[0].FullName | Should -Match "LiveKernelReports\\NDIS\\NDIS-20261114-1448\.dmp"

            $latestFatal = Get-DcLatestDumpFile -LookbackDays 2 -CustomDirectories @($liveNdis, $miniDir) -ExcludeLiveKernelReports
            $latestFatal | Should -Not -BeNullOrEmpty
            $latestFatal.Name | Should -Be "111426-11031-01.dmp"

            $latestLive = Get-DcLatestDumpFile -LookbackDays 2 -CustomDirectories @($liveNdis, $miniDir) -LiveKernelReportsOnly
            $latestLive | Should -Not -BeNullOrEmpty
            $latestLive.Name | Should -Be "NDIS-20261114-1448.dmp"
        } finally {
            if (Test-Path $rootTemp) { Remove-Item $rootTemp -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It "Resolves HARDWARE_ID devices, real blamed modules, and 0x15E/0x9F CDB fields without capture wrappers" {
        $resolvedOffline = Resolve-DcHardwareIdName -HardwareId "PCI\VEN_14C3&DEV_0616&SUBSYS_E0CD105B&REV_00" -PnpEntities @()
        $resolvedOffline | Should -Match "MediaTek"
        $resolvedOffline | Should -Match "MT7922"

        $mockPnp = @(
            [PSCustomObject]@{
                Name        = "MediaTek Wi-Fi 6E MT7922 (RZ616) Wireless LAN Card"
                PNPDeviceID = "PCI\VEN_14C3&DEV_0616&SUBSYS_E0CD105B&REV_00\4&1A2B3C"
            }
        )
        $resolvedPnp = Resolve-DcHardwareIdName -HardwareId "PCI\VEN_14C3&DEV_0616&SUBSYS_E0CD105B&REV_00" -PnpEntities $mockPnp
        $resolvedPnp | Should -Match "MediaTek Wi-Fi 6E MT7922"

        $rootTemp = Join-Path $env:TEMP "dc_test_cdb_$([guid]::NewGuid().ToString('N').Substring(0,8))"
        $liveNdis = Join-Path $rootTemp "LiveKernelReports\NDIS"
        $miniDir  = Join-Path $rootTemp "Minidump"
        New-Item -ItemType Directory -Path $liveNdis, $miniDir -Force | Out-Null
        try {
            $bytes = New-Object byte[] 128
            $bytes[0] = 0x4D; $bytes[1] = 0x44; $bytes[2] = 0x4D; $bytes[3] = 0x50
            $bytes[4] = 0x93; $bytes[5] = 0xA7
            $bytes[8] = 1
            $bytes[12] = 32
            $bytes[32] = 7
            $bytes[36] = 56
            $bytes[40] = 44
            $bytes[44] = 9

            $livePath = Join-Path $liveNdis "NDIS-20261114-1448.dmp"
            $bsodPath = Join-Path $miniDir  "111426-11609-01.dmp"
            [System.IO.File]::WriteAllBytes($livePath, $bytes)
            [System.IO.File]::WriteAllBytes($bsodPath, $bytes)

            $cdb0x15e = @"
Bugcheck code 0000015e
Arguments 00000000``00000030 ffff9585``0bb42030 ffff9585``05608120 00000000``00000000
===ANALYZE===
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

BUGCODE_NDIS_DRIVER_LIVE_DUMP (15e)
Arguments:
Arg1: 0000000000000030
Arg2: ffff95850bb42030
Arg3: ffff958505608120
Arg4: 0000000000000000

FAILURE_BUCKET_ID:  LKD_0x15E_Mini_Nbl_Leak_IMAGE_e2fn.sys
IMAGE_NAME:  e2fn.sys
MODULE_NAME: e2fn
BUGCHECK_CODE:  15e

===STACK===
Child-SP          RetAddr           Call Site
00 fffff803``11110000 fffff803``22220000 nt!IopLiveDumpCollectPages+0xd9
01 fffff803``11110008 fffff803``22220010 nt!IopLiveDumpEndMirroringCallback+0x55
02 fffff803``11110010 fffff803``22220020 e2fn+0x1234
===ENDSTACK===
"@

            $cdb0x9f = @"
Bugcheck code 0000009f
Arguments 00000000``00000004 00000000``0000012c ffffc202``0f474040 fffff803``6fb3e060
===ANALYZE===
DRIVER_POWER_STATE_FAILURE (9f)
Arguments:
Arg1: 0000000000000004
Arg2: 000000000000012c
Arg3: ffffc2020f474040
Arg4: fffff8036fb3e060

HARDWARE_ID:  PCI\VEN_14C3&DEV_0616&SUBSYS_E0CD105B&REV_00
FAILURE_BUCKET_ID:  0x9F_4_PCI_ndis!ndisWaitForKernelObject
IMAGE_NAME:  ndis.sys
MODULE_NAME: ndis
SYMBOL_NAME:  ndis!ndisWaitForKernelObject+21
BUGCHECK_CODE:  9f

===STACK===
Child-SP          RetAddr           Call Site
00 fffff803``11110000 fffff803``22220000 nt!KeBugCheckEx
01 fffff803``11110008 fffff803``22220010 nt!PnpBugcheckPowerTimeout+0x65
02 fffff803``11110010 fffff803``22220020 ndis!ndisWaitForKernelObject+0x21
===ENDSTACK===
"@

            $trace15e = Invoke-DcDumpStackTrace -DumpPath $livePath -PreReadOutput $cdb0x15e
            $trace15e.IsLiveKernelDump | Should -Be $true
            $trace15e.FailureBucket | Should -Be "LKD_0x15E_Mini_Nbl_Leak_IMAGE_e2fn.sys"

            $dump15e = Read-DcMinidump -Path $livePath -PreReadCdbOutput $cdb0x15e
            $dump15e.ExceptionCode | Should -Be "0x0000015E"
            $dump15e.IsLiveKernelReport | Should -Be $true
            ($dump15e.FaultingIP -match "IopLiveDumpCollectPages") | Should -Be $false
            $dump15e.FaultingIP | Should -Match "e2fn"

            $dump9f = Read-DcMinidump -Path $bsodPath -PreReadCdbOutput $cdb0x9f
            $dump9f.ExceptionCode | Should -Be "0x0000009F"
            $dump9f.IsLiveKernelReport | Should -Be $false
            $dump9f.HardwareId | Should -Be "PCI\VEN_14C3&DEV_0616&SUBSYS_E0CD105B&REV_00"
            $dump9f.HardwareDeviceName | Should -Match "MediaTek|MT7922"
            ($dump9f.FaultingIP -match "KeBugCheckEx") | Should -Be $false
            $dump9f.FaultingIP | Should -Match "ndis!ndisWaitForKernelObject"
        } finally {
            if (Test-Path $rootTemp) { Remove-Item $rootTemp -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It "Promotes 0x119 BSOD over newer non-fatal 0x15E live dump, suppresses false Admin prompts, and fixes NVMe SMART HTML" {
        $now = Get-Date
        $dumpLive15e = [PSCustomObject]@{
            FileName           = "NDIS-20261114-1448.dmp"
            FullName           = "C:\WINDOWS\LiveKernelReports\NDIS\NDIS-20261114-1448.dmp"
            Timestamp          = $now.AddMinutes(-7)
            CrashTime          = $now.AddMinutes(-7)
            SizeMb             = 1.36
            Architecture       = "64-bit (x64)"
            IsKernelDump       = $true
            IsGraphicsCrash    = $false
            CdbInspected       = $true
            ExceptionCode      = "0x0000015E"
            ExceptionMeaning   = "BUGCODE_NDIS_DRIVER_LIVE_DUMP"
            FaultingIP         = "e2fn.sys"
            FaultingModule     = "e2fn.sys"
            FailureBucket      = "LKD_0x15E_Mini_Nbl_Leak_IMAGE_e2fn.sys"
            DebuggerModuleName = "e2fn"
            DebuggerImageName  = "e2fn.sys"
            DebuggerSymbolName = ""
            ApiContext         = $null
            DriverVersion      = $null
            Assertions         = @()
            CallStack          = @("e2fn+0x1234")
            RawStack           = @("e2fn+0x1234")
            IsLiveKernelReport = $true
            HardwareId         = $null
            HardwareDeviceName = $null
        }
        $dumpGpu119 = [PSCustomObject]@{
            FileName           = "111426-11031-01.dmp"
            FullName           = "C:\WINDOWS\Minidump\111426-11031-01.dmp"
            Timestamp          = $now.AddMinutes(-70)
            CrashTime          = $now.AddMinutes(-70)
            SizeMb             = 4.38
            Architecture       = "64-bit (x64)"
            IsKernelDump       = $true
            IsGraphicsCrash    = $true
            CdbInspected       = $true
            ExceptionCode      = "0x00000119"
            ExceptionMeaning   = "VIDEO_SCHEDULER_INTERNAL_ERROR"
            FaultingIP         = "amdkmdag+1b25c0"
            FaultingModule     = "amdkmdag+1b25c0"
            FailureBucket      = "0x119_5_DRIVER_FAULTED_SYSTEM_COMMAND_amdkmdag!unknown_function"
            DebuggerModuleName = "amdkmdag"
            DebuggerImageName  = "amdkmdag.sys"
            DebuggerSymbolName = "amdkmdag+1b25c0"
            ApiContext         = "AMD Kernel Display Driver (amdkmdag.sys) GPU Scheduler Timeout / Reset"
            DriverVersion      = "32.0.32015.16001"
            Assertions         = @()
            CallStack          = @("dxgmms2!VidSchiProcessIsrFaultedPacket+0x273")
            RawStack           = @("dxgmms2!VidSchiProcessIsrFaultedPacket+0x273")
            IsLiveKernelReport = $false
            HardwareId         = $null
            HardwareDeviceName = $null
        }
        $dumpWifi9f = [PSCustomObject]@{
            FileName           = "111426-11609-01.dmp"
            FullName           = "C:\WINDOWS\Minidump\111426-11609-01.dmp"
            Timestamp          = $now.AddMinutes(-170)
            CrashTime          = $now.AddMinutes(-170)
            SizeMb             = 4.27
            Architecture       = "64-bit (x64)"
            IsKernelDump       = $true
            IsGraphicsCrash    = $false
            CdbInspected       = $true
            ExceptionCode      = "0x0000009F"
            ExceptionMeaning   = "DRIVER_POWER_STATE_FAILURE"
            FaultingIP         = "ndis!ndisWaitForKernelObject+21"
            FaultingModule     = "ndis!ndisWaitForKernelObject+21"
            FailureBucket      = "0x9F_4_PCI_ndis!ndisWaitForKernelObject"
            DebuggerModuleName = "ndis"
            DebuggerImageName  = "ndis.sys"
            DebuggerSymbolName = "ndis!ndisWaitForKernelObject+21"
            ApiContext         = $null
            DriverVersion      = $null
            Assertions         = @()
            CallStack          = @("nt!PnpBugcheckPowerTimeout+0x65")
            RawStack           = @("nt!PnpBugcheckPowerTimeout+0x65")
            IsLiveKernelReport = $false
            HardwareId         = "PCI\VEN_14C3&DEV_0616&SUBSYS_E0CD105B&REV_00"
            HardwareDeviceName = "MediaTek Wi-Fi 6E MT7922 (RZ616) Wireless LAN Card"
        }

        $parsedDumps = @($dumpLive15e, $dumpGpu119, $dumpWifi9f)

        $telMock = [PSCustomObject]@{
            IsElevated            = $true
            KernelBugChecks       = @(
                [PSCustomObject]@{
                    TimeCreated  = $now.AddMinutes(-70)
                    Code         = "0x00000119"
                    Meaning      = "VIDEO_SCHEDULER_INTERNAL_ERROR"
                    Message      = "The computer has rebooted from a bugcheck.  The bugcheck was: 0x00000119 (0x0000000000000005, 0xffffd482e75e7000, 0xffffd482e3156050, 0x000000000000a8af). A dump was saved in: C:\WINDOWS\Minidump\111426-11031-01.dmp. Report Id: 11111111-1111-1111-1111-111111111111."
                    WatsonBucket = "0x119_5_DRIVER_FAULTED_SYSTEM_COMMAND_amdkmdag!unknown_function"
                },
                [PSCustomObject]@{
                    TimeCreated  = $now.AddMinutes(-170)
                    Code         = "0x0000009F"
                    Meaning      = "DRIVER_POWER_STATE_FAILURE"
                    Message      = "The computer has rebooted from a bugcheck.  The bugcheck was: 0x0000009F (0x0000000000000004, 0x000000000000012c, 0xffffc2020f474040, 0xfffff8036fb3e060). A dump was saved in: C:\WINDOWS\Minidump\111426-11609-01.dmp. Report Id: 22222222-2222-2222-2222-222222222222."
                    WatsonBucket = "0x9F_4_PCI_ndis!ndisWaitForKernelObject"
                },
                [PSCustomObject]@{
                    TimeCreated  = $now.AddHours(-18)
                    Code         = "0x0000001A"
                    Meaning      = "MEMORY_MANAGEMENT"
                    Message      = "The computer has rebooted from a bugcheck.  The bugcheck was: 0x0000001A (0x0000000000006000, 0xffffb187a17a7520, 0xffffffffc0000225, 0x0000000000001000). A dump was saved in: C:\WINDOWS\Minidump\older-gone.dmp. Report Id: 33333333-3333-3333-3333-333333333333."
                    WatsonBucket = ""
                }
            )
            DisplayTdrEvents      = @()
            KernelPowerEvents     = @()
            WheaEvents            = @()
            LiveKernelEvents      = @()
            CriticalServiceErrors = @()
            StorageErrorEvents    = @()
            NetworkErrorEvents    = @()
            WerAppCrashes         = @()
            DxgkrnlEvents         = @()
            WerKernelEvents       = @()
        }

        $diag = Resolve-DcDiagnosticFindings -ParsedDumps $parsedDumps -Telemetry $telMock
        $diag.PrimaryFinding | Should -Not -BeNullOrEmpty
        $diag.PrimaryFinding.Id | Should -Be "KERNEL_BUGCHECK"
        $diag.PrimaryFinding.Title | Should -Match "0x00000119"
        $diag.RootCauseTitle | Should -Match "0x00000119"

        $liveFinding = @($diag.Findings | Where-Object { $_.Id -eq "LIVE_KERNEL_DUMP" })
        $liveFinding.Count | Should -Be 1
        $liveFinding[0].Kind | Should -Be "Event"

        $wifiFinding = @($diag.Findings | Where-Object { $_.Id -eq "KERNEL_BUGCHECK" -and $_.Title -match "0x0000009F" })
        $wifiFinding.Count | Should -Be 1
        $wifiFinding[0].Description | Should -Match "MediaTek Wi-Fi 6E MT7922"

        $leadsJoined = (@($diag.Leads) | ForEach-Object { $_.Lead }) -join " | "
        ($leadsJoined -match "crashed 2 times") | Should -Be $false
        ($leadsJoined -match "requires Administrator|Administrator shell|Administrator privileges|elevated PowerShell") | Should -Be $false
        $leadsJoined | Should -Match "NDIS-20261114-1448\.dmp"

        $hwMock = [PSCustomObject]@{
            Devices              = @()
            RecentHardwareEvents = @()
            TdrRegistryInfo      = $null
            Gpus                 = @()
            Motherboard          = $null
            Memory               = $null
            PhysicalDisks        = [PSCustomObject]@{
                Disks    = @(
                    [PSCustomObject]@{
                        FriendlyName           = "WD_BLACK SN850X 4000GB"
                        SizeGb                 = 3726
                        BusType                = "NVMe"
                        HealthStatus           = "Healthy"
                        Wear                   = 4
                        TemperatureC           = 43
                        ReliabilityAvailable   = $true
                        ReadErrorsUncorrected  = $null
                        WriteErrorsUncorrected = $null
                    }
                )
                Findings = @()
            }
            WheaEvents           = @()
            RebarStatus          = $null
            KernelDrivers        = @()
            PnpIssues            = @()
            Displays             = @()
            NetworkAdapters      = @()
            DualGpuConflict      = $false
            HybridMultiGpu       = $false
            IsUlpsEnabled        = $false
        }

        $attribs = @(Resolve-DcIncidentAttribution -Dumps $parsedDumps -Telemetry $telMock -Hardware $hwMock)
        $attribs.Count | Should -BeGreaterOrEqual 3

        $gpuAttrib = @($attribs | Where-Object { $_.SurfaceSymptom -match "0x00000119" })
        $gpuAttrib.Count | Should -Be 1
        $gpuAttrib[0].Classification | Should -Be "GPU_DRIVER"
        $gpuAttrib[0].BlamedComponent | Should -Match "amdkmdag"
        $gpuAttrib[0].IsGpuDriverFault | Should -Be $true

        $wifiAttrib = @($attribs | Where-Object { $_.SurfaceSymptom -match "0x0000009F" })
        $wifiAttrib.Count | Should -Be 1
        $wifiAttrib[0].Classification | Should -Be "DEVICE_OR_HARDWARE"
        $wifiAttrib[0].LayerBadge | Should -Be "Device / Driver Power"
        $wifiAttrib[0].BlamedComponent | Should -Match "MediaTek Wi-Fi 6E MT7922"
        $wifiAttrib[0].IsGpuDriverFault | Should -Be $false

        $ndisAttrib = @($attribs | Where-Object { $_.SurfaceSymptom -match "0x0000015E" })
        $ndisAttrib.Count | Should -Be 1
        $ndisAttrib[0].Classification | Should -Be "DEVICE_OR_HARDWARE"
        $ndisAttrib[0].LayerBadge | Should -Be "Device / Driver (Non-Fatal)"
        $ndisAttrib[0].BlamedComponent | Should -Match "e2fn"
        $ndisAttrib[0].IsGpuDriverFault | Should -Be $false

        $forensicsMock = [PSCustomObject]@{
            Crashes              = @(
                [PSCustomObject]@{
                    Kind         = "Bugcheck (BSOD)"
                    BugcheckCode = "0x00000119"
                    CrashTime    = $now.AddMinutes(-70)
                    LogTime      = $now.AddMinutes(-69)
                    Dump         = $dumpGpu119
                    BugcheckArgs = @()
                    Timeline     = @()
                },
                [PSCustomObject]@{
                    Kind         = "Bugcheck (BSOD)"
                    BugcheckCode = "0x0000009F"
                    CrashTime    = $now.AddMinutes(-170)
                    LogTime      = $now.AddMinutes(-169)
                    Dump         = $dumpWifi9f
                    BugcheckArgs = @()
                    Timeline     = @()
                },
                [PSCustomObject]@{
                    Kind         = "Bugcheck (BSOD)"
                    BugcheckCode = "0x0000001A"
                    CrashTime    = $now.AddHours(-18)
                    LogTime      = $now.AddHours(-18)
                    Dump         = $null
                    BugcheckArgs = @()
                    Timeline     = @()
                }
            )
            GpuDisplayEvents     = @()
            LiveKernelHistory    = @()
            Patterns             = $null
            IncidentAttributions = $attribs
        }
        $plainSummary = Get-DcPlainEnglishSummary -Forensics $forensicsMock -Dumps $parsedDumps -Telemetry $telMock -Hardware $hwMock -Attributions $attribs
        $nextChecksJoined = ($plainSummary.SensibleNextChecks -join " | ")
        ($nextChecksJoined -match "Administrator|cdb\.exe|WinDbg") | Should -Be $false
        $nextChecksJoined | Should -Match "MediaTek Wi-Fi 6E MT7922"
        (($plainSummary.TranslatedIncidents | ForEach-Object { $_.PlainText }) -join " | ") | Should -Match "MediaTek Wi-Fi 6E MT7922"

        $tempHtml = Join-Path $env:TEMP "dc_test_nvme_$([guid]::NewGuid().ToString('N').Substring(0,8)).html"
        try {
            $reportObj = [PSCustomObject]@{
                ScanMode             = "AllIncidents"
                HoursScanned         = 48
                RootCauseTitle       = $diag.RootCauseTitle
                RootCauseDescription = $diag.RootCauseDescription
                RootCauseSeverity    = "Critical"
                RootCauseGuidance    = ""
                Findings             = $diag.Findings
                SecondaryFindings    = $diag.SecondaryFindings
                Dumps                = $parsedDumps
                EngineLogs           = @()
                SteamLogs            = @()
                SystemTelemetry      = $telMock
                HardwareHealth       = $hwMock
                CrashForensics       = [PSCustomObject]@{
                    Crashes              = $forensicsMock.Crashes
                    GpuDisplayEvents     = @()
                    LiveKernelHistory    = @()
                    IncidentAttributions = $attribs
                    PlainSummary         = $plainSummary
                }
            }
            Export-DcHtmlReport -ReportData $reportObj -OutputPath $tempHtml
            $htmlText = [System.IO.File]::ReadAllText($tempHtml)
            $htmlText | Should -Match "Non-Fatal Live Dump"
            $htmlText | Should -Match "Blamed Hardware:"
            $htmlText | Should -Match "MediaTek Wi-Fi 6E MT7922"
            $htmlText | Should -Match "n/a \(NVMe\)"
            ($htmlText -match "<td>\s*/\s*</td>") | Should -Be $false
        } finally {
            if (Test-Path $tempHtml) { Remove-Item $tempHtml -Force -ErrorAction SilentlyContinue }
        }
    }
}
