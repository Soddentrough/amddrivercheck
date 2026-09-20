<#
.SYNOPSIS
    Game Engine & Steam Log Inspector (idTech, Unreal Engine, Steam, CEF)
.DESCRIPTION
    Parses idTech engine console logs (Indiana Jones, Doom), Unreal Engine logs (Grounded),
    Steam Overlay logs, and connection logs for runtime errors, vertex buffer exhaustion,
    streaming timeouts, and network disconnection triggers.
.PARAMETER TailLines
    Number of lines to read from the tail of logs (default: 40).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$TailLines = 40
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  GAME ENGINE & STEAM LOG INSPECTOR" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. idTech Engine Logs (Indiana Jones, Doom Eternal, Doom The Dark Ages)
Write-Host "--- idTech Engine Console Logs (Saved Games) ---" -ForegroundColor Yellow
$idTechDirs = @(
    "$env:USERPROFILE\Saved Games\MachineGames\TheGreatCircle\base",
    "$env:USERPROFILE\Saved Games\id Software\DOOMEternal\base",
    "$env:USERPROFILE\Saved Games\id Software\DOOMTheDarkAges\base"
)

foreach ($dir in $idTechDirs) {
    if (Test-Path $dir) {
        $qconsole = Join-Path $dir "qconsole.log"
        if (Test-Path $qconsole) {
            $item = Get-Item $qconsole
            Write-Host "------------------------------------------------------------------------" -ForegroundColor Gray
            Write-Host "Found Log: $qconsole (Modified: $($item.LastWriteTime), Size: $([math]::Round($item.Length/1MB, 2)) MB)" -ForegroundColor White
            
            # Check for Vertex Allocation Failures
            $allocFails = (Select-String -Path $qconsole -Pattern "Failed to allocate.*material env modification" -ErrorAction SilentlyContinue).Count
            if ($allocFails -gt 0) {
                Write-Host "  [!] WARNING: Detected $allocFails material vertex buffer allocation failures (8MB limit exceeded)." -ForegroundColor Red
            }
            
            # Check for Streaming Prefetch Timeouts
            $prefetchFails = Select-String -Path $qconsole -Pattern "waiting on streaming prefetch.*catchup timeout expired" -ErrorAction SilentlyContinue
            if ($prefetchFails) {
                Write-Host "  [!] WARNING: Detected streaming prefetch catchup timeout(s)." -ForegroundColor Yellow
                foreach ($pf in ($prefetchFails | Select-Object -Last 3)) {
                    Write-Host "        * $($pf.Line.Trim())" -ForegroundColor Yellow
                }
            }

            # Check for Online Manager State Drops
            $onlineDrops = Select-String -Path $qconsole -Pattern "OnlineManager: Go offline|Network Connectivity Level" -ErrorAction SilentlyContinue
            if ($onlineDrops) {
                Write-Host "  [!] Network / Online Service State Events:" -ForegroundColor DarkCyan
                foreach ($od in ($onlineDrops | Select-Object -Last 3)) {
                    Write-Host "        * $($od.Line.Trim())" -ForegroundColor DarkCyan
                }
            }

            # Check for Clean Shutdown vs Crash
            $cleanShutdown = Select-String -Path $qconsole -Pattern "Game Shutdown|Shutting down at" -ErrorAction SilentlyContinue
            if ($cleanShutdown) {
                Write-Host "  [ OK ] Last session ended with a clean engine shutdown." -ForegroundColor Green
            } else {
                Write-Host "  [!] No clean shutdown sequence found at end of log (indicates abrupt crash)." -ForegroundColor Red
            }

            Write-Host "  Tail of $qconsole:" -ForegroundColor DarkGray
            Get-Content $qconsole -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        }
    }
}

# 2. Steam Connection & Overlay Logs
Write-Host ""
Write-Host "--- Steam Logs ---" -ForegroundColor Yellow
$steamLogs = @(
    "C:\Program Files (x86)\Steam\logs\connection_log.txt",
    "C:\Program Files (x86)\Steam\GameOverlayRenderer.log",
    "C:\Program Files (x86)\Steam\logs\error_log.txt"
)

foreach ($log in $steamLogs) {
    if (Test-Path $log) {
        $item = Get-Item $log
        Write-Host "Log: $log (Modified: $($item.LastWriteTime))" -ForegroundColor White
        Get-Content $log -Tail 10 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }
}

# 3. Unreal Engine CEF & Crash Logs
Write-Host ""
Write-Host "--- Unreal Engine Logs ---" -ForegroundColor Yellow
$cefLogs = Get-ChildItem "$env:LOCALAPPDATA" -Recurse -Filter "cef3.log" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 3

foreach ($cl in $cefLogs) {
    Write-Host "CEF Log: $($cl.FullName) (Modified: $($cl.LastWriteTime))" -ForegroundColor White
    Get-Content $cl.FullName -Tail 10 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
}

Write-Host ""
