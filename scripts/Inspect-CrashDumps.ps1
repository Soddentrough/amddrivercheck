<#
.SYNOPSIS
    Deep Crash Dump, Assertion & Minidump Binary Inspector
.DESCRIPTION
    Scans Steam dumps, Windows user-mode crash dumps, Unreal Engine crash folders,
    and Sentry telemetry caches. Parses binary minidump streams to extract exact exception
    codes (e.g. 0xC0000005, 0x887A0006), assertion strings, and active Vulkan hook layers.
.PARAMETER Hours
    Number of hours back to scan (default: 72).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Hours = 72
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$cutoff = (Get-Date).AddHours(-$Hours)
Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  DEEP CRASH DUMP, ASSERTION & MINIDUMP BINARY INSPECTOR" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Scanning past $Hours hours (Cutoff: $($cutoff.ToString('yyyy-MM-dd HH:mm')))" -ForegroundColor DarkGray
Write-Host ""

$searchDirs = @(
    "C:\Program Files (x86)\Steam\dumps",
    "$env:LOCALAPPDATA\CrashDumps",
    "$env:LOCALAPPDATA\Pearl Abyss\DumpCache",
    "$env:LOCALAPPDATA\BeamNG.drive",
    "$env:LOCALAPPDATA\Maine\Saved\Logs",
    "$env:LOCALAPPDATA\Maine\Saved\Crashes"
)

# Also discover any Unreal Engine Saved\Crashes directories in AppData
$ueCrashDirs = Get-ChildItem "$env:LOCALAPPDATA" -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { "$($_.FullName)\Saved\Crashes" } |
    Where-Object { Test-Path $_ }
if ($ueCrashDirs) { $searchDirs += $ueCrashDirs }

$foundCount = 0

foreach ($dir in $searchDirs) {
    if (Test-Path $dir) {
        $files = Get-ChildItem -Path $dir -Recurse -Include "*.dmp", "*.wer", "__sentry-event" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoff }
        
        foreach ($f in $files) {
            $foundCount++
            $sizeMb = [math]::Round($f.Length / 1MB, 2)
            Write-Host "------------------------------------------------------------------------" -ForegroundColor Gray
            Write-Host "Dump File:     $($f.Name)" -ForegroundColor Yellow
            Write-Host "Location:      $($f.FullName)" -ForegroundColor White
            Write-Host "Last Modified: $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
            Write-Host "Size:          $sizeMb MB" -ForegroundColor White
            
            # Binary inspection for Minidump structure
            if ($f.Name -match '\.dmp$') {
                try {
                    $fs = [System.IO.File]::OpenRead($f.FullName)
                    $br = New-Object System.IO.BinaryReader($fs)
                    $sig = $br.ReadUInt32()
                    
                    if ($sig -eq 0x504D444D) { # 'MDMP' signature
                        $version = $br.ReadUInt32()
                        $numStreams = $br.ReadUInt32()
                        $streamDirRva = $br.ReadUInt32()
                        
                        $fs.Position = $streamDirRva
                        $streams = @()
                        for ($i = 0; $i -lt $numStreams; $i++) {
                            $type = $br.ReadUInt32()
                            $size = $br.ReadUInt32()
                            $rva = $br.ReadUInt32()
                            $streams += [PSCustomObject]@{ Type = $type; Size = $size; Rva = $rva }
                        }
                        
                        # Stream 6 = ExceptionStream
                        $excStream = $streams | Where-Object { $_.Type -eq 6 }
                        if ($excStream) {
                            $fs.Position = $excStream.Rva
                            $threadId = $br.ReadUInt32()
                            $alignment = $br.ReadUInt32()
                            $excCode = $br.ReadUInt32()
                            $excFlags = $br.ReadUInt32()
                            $excRecord = $br.ReadUInt64()
                            $excAddr = $br.ReadUInt64()
                            
                            $codeHex = "0x{0:X8}" -f $excCode
                            $codeMeaning = switch ($codeHex) {
                                "0xC0000005" { "STATUS_ACCESS_VIOLATION (Memory Access Violation)" }
                                "0xC0000409" { "STATUS_STACK_BUFFER_OVERRUN (Fast Fail / Stack Guard)" }
                                "0x887A0006" { "DXGI_ERROR_DEVICE_HUNG (GPU TDR / Device Lost)" }
                                "0x887A0005" { "DXGI_ERROR_DEVICE_REMOVED (GPU Reset)" }
                                "0x00000000" { "STATUS_SUCCESS / Manual Process Crash Assertion" }
                                default      { "Exception Code" }
                            }
                            Write-Host "  +- Exception Stream: $codeHex ($codeMeaning)" -ForegroundColor Red
                            Write-Host "  +- Faulting Thread:  0x{0:X} ({0})" -f $threadId -ForegroundColor DarkGray
                        }
                    }
                    $fs.Close()
                } catch {
                    if ($fs) { $fs.Close() }
                }
                
                # String inspection for Assertions and Vulkan Layers
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
                    $asciiText = [System.Text.Encoding]::ASCII.GetString($bytes)
                    
                    # Extract Assertions
                    $assertMatches = [regex]::Matches($asciiText, 'Assert\([^\r\n]{5,220}\)') |
                        Select-Object -ExpandProperty Value -Unique
                    if ($assertMatches) {
                        Write-Host "  +- Extracted Assertions:" -ForegroundColor Red
                        foreach ($am in ($assertMatches | Select-Object -First 5)) {
                            Write-Host "       * $am" -ForegroundColor Red
                        }
                    }
                    
                    # Extract Vulkan Layers
                    $vkLayers = [regex]::Matches($asciiText, 'VK_LAYER_[A-Z0-9_]+') |
                        Select-Object -ExpandProperty Value -Unique
                    if ($vkLayers) {
                        Write-Host "  +- Active Vulkan Layers:" -ForegroundColor Cyan
                        foreach ($vl in ($vkLayers | Select-Object -First 6)) {
                            Write-Host "       * $vl" -ForegroundColor DarkCyan
                        }
                    }
                } catch {}
            }
            
            # Sentry Telemetry Inspection
            if ($f.Name -eq "__sentry-event") {
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
                    $str = [System.Text.Encoding]::UTF8.GetString($bytes)
                    if ($str -match 'release\?[^?]+') { Write-Host "  +- Sentry Release: $($Matches[0])" -ForegroundColor Cyan }
                    if ($str -match 'BuildKey\?[^?]+') { Write-Host "  +- Sentry Build:   $($Matches[0])" -ForegroundColor Cyan }
                } catch {}
            }
        }
    }
}

if ($foundCount -eq 0) {
    Write-Host "  [ OK ] No crash dump files found in searched directories for past $Hours hours." -ForegroundColor Green
}
Write-Host ""
