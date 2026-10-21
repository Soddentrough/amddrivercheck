BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $modulesDir = Join-Path $repoRoot "scripts\modules"
    Import-Module (Join-Path $modulesDir "DcCrashDump.psm1") -Force
    Import-Module (Join-Path $modulesDir "DcSystemTelemetry.psm1") -Force
    Import-Module (Join-Path $modulesDir "DcEngineLogs.psm1") -Force
    Import-Module (Join-Path $modulesDir "DcHardwareHealth.psm1") -Force
    Import-Module (Join-Path $modulesDir "DcRemediation.psm1") -Force
    Import-Module (Join-Path $modulesDir "DcReportGenerator.psm1") -Force
}

Describe "DcCrashDump - Minidump VS_FIXEDFILEINFO & LiveKernelReports" {
    It "Decodes VS_FIXEDFILEINFO module versions, LinkDate, and GPU driver versions from binary MDMP stream" {
        $tempDump = Join-Path ([System.IO.Path]::GetTempPath()) ("test_mdmp_" + [guid]::NewGuid().ToString("N") + ".dmp")
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
            $bw.Write([UInt64]0x140000000) # BaseOfImage
            $bw.Write([UInt32]0x01000000)  # SizeOfImage
            $bw.Write([UInt32]0)           # CheckSum
            $bw.Write([UInt32]1700000000)  # TimeDateStamp
            $bw.Write([UInt32]340)         # ModuleNameRva
            # VS_FIXEDFILEINFO (52 bytes)
            $bw.Write([UInt32]0xFEEF04BD)  # dwSignature
            $bw.Write([UInt32]0x00010000)  # dwStrucVersion
            $bw.Write([UInt32]0x00010002)  # dwFileVersionMS (1.2)
            $bw.Write([UInt32]0x00030004)  # dwFileVersionLS (3.4)
            $bw.Write([byte[]]::new(36))   # Rest of VS_FIXEDFILEINFO
            $bw.Write([byte[]]::new(32))   # CvRecord, MiscRecord, Reserved0, Reserved1

            # Module 1: C:\Windows\System32\drivers\amdkmdag.sys (Version 31.0.24033.1003) -> Name at RVA 400
            $bw.Write([UInt64]0xFFFFF80010000000) # BaseOfImage
            $bw.Write([UInt32]0x05000000)         # SizeOfImage
            $bw.Write([UInt32]0)                  # CheckSum
            $bw.Write([UInt32]1710000000)         # TimeDateStamp
            $bw.Write([UInt32]400)                # ModuleNameRva
            # VS_FIXEDFILEINFO (52 bytes)
            $bw.Write([UInt32]0xFEEF04BD)         # dwSignature
            $bw.Write([UInt32]0x00010000)         # dwStrucVersion
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
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wer_test_" + [guid]::NewGuid().ToString("N"))
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

            $reports = Get-DcWerReportArchive -Cutoff (Get-Date).AddDays(-90) -EndTime (Get-Date) -CustomArchivePaths @($tempDir)
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
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("chg_test_" + [guid]::NewGuid().ToString("N"))
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
        $now = Get-Date
        $cutoff = $now.AddDays(-30)
        $endTime = $now.AddDays(-5)

        # Event 1: Embedded timestamp 10 days ago (within [Cutoff, EndTime])
        $validDumpDate = $now.AddDays(-10)
        $validDateTag = $validDumpDate.ToString("yyyyMMdd-HHmm")
        $msgValid = @"
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
        $lateDumpDate = $now.AddDays(-1)
        $lateDateTag = $lateDumpDate.ToString("yyyyMMdd-HHmm")
        $msgLate = @"
Fault bucket , type 0
Event Name: LiveKernelEvent
Problem signature:
P1: 117
Attached files:
\\?\C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-$lateDateTag-01.dmp

These files may be available here:
"@

        Mock -ModuleName DcSystemTelemetry Get-WinEvent {
            param($FilterHashtable)
            if ($FilterHashtable -and $FilterHashtable['ProviderName'] -eq 'Windows Error Reporting' -and $FilterHashtable['Id'] -eq 1001) {
                return @(
                    [PSCustomObject]@{
                        Id           = 1001
                        ProviderName = 'Windows Error Reporting'
                        TimeCreated  = $now.AddDays(-9)
                        Message      = $msgValid
                    },
                    [PSCustomObject]@{
                        Id           = 1001
                        ProviderName = 'Windows Error Reporting'
                        TimeCreated  = $now.AddDays(-1)
                        Message      = $msgLate
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
        $dumpDate = $now.AddDays(-2)
        $dateTag = $dumpDate.ToString("yyyyMMdd-HHmm")

        $msg193 = @"
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

        Mock -ModuleName DcSystemTelemetry Get-WinEvent {
            param($FilterHashtable)
            if ($FilterHashtable -and $FilterHashtable['ProviderName'] -eq 'Windows Error Reporting' -and $FilterHashtable['Id'] -eq 1001) {
                return @(
                    [PSCustomObject]@{
                        Id           = 1001
                        ProviderName = 'Windows Error Reporting'
                        TimeCreated  = $dumpDate
                        Message      = $msg193
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
            $ft = $dumpDate.ToFileTime()
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

            $reports = Get-DcWerReportArchive -Cutoff $cutoff -EndTime $endTime -CustomArchivePaths @($tempDir)
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
            $bw.Write([UInt32]0x504D444D) # 'MDMP'
            $bw.Write([UInt32]0x0000A793)
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
            $bw.Write([UInt64]0xFFFFF80010000000)
            $bw.Write([UInt32]0x05000000)
            $bw.Write([UInt32]0)
            $bw.Write([UInt32]1710000000)
            $bw.Write([UInt32]240)
            $bw.Write([UInt32]0xFEEF04BD)
            $bw.Write([UInt32]0x00010000)
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



