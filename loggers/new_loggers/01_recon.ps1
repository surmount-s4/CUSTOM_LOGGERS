# Recon Detection in OT Networks (IP-level pktmon + TCP ACK sweep detection)
# Save as ReconDetect.ps1 and run as Admin

$HostSweepThreshold = 5
$TimeWindowSeconds = 60
$LoopSleepSeconds = 3
$PktmonLimit = 1000
$DebugMode = $false

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires Administrator privileges. Rerun PowerShell as Admin."
    exit 1
}

$logDir = "C:\Logs"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$reconCsv = Join-Path $logDir "recon_log.csv"
if (-not (Test-Path $reconCsv)) { "Timestamp,SourceIP,TargetCount,Targets,Type,Details" | Out-File $reconCsv -Encoding utf8 }

$protocolMap = @{
    "TCP/502"  = "Modbus"; "TCP/20000" = "DNP3"; "UDP/20000" = "DNP3";
    "UDP/47808"= "BACnet"; "TCP/44818" = "EtherNet/IP";
    "TCP/102"  = "S7comm"; "UDP/102" = "S7comm"
}
$tcpAckPorts = @(80,443,21,22,23,25,135,139,445,3389)
$extraPorts = ($protocolMap.Keys | ForEach-Object { ($_ -split "/")[1] } | Where-Object { $_ -match '^\d+$' }) + $tcpAckPorts
$extraPorts = $extraPorts | Sort-Object -Unique

function Log-Recon { param($srcIP, $targetCount, $targetList, $type, $details)
    $ts = (Get-Date).ToString("o")
    $row = @($ts, $srcIP, $targetCount, ($targetList -join ';'), $type, $details)
    $row = $row | ForEach-Object { if ($_ -eq $null) { "" } else { ($_.ToString()).Replace('"','""') } }
    '"' + ($row -join '","') + '"' | Out-File -FilePath $reconCsv -Append -Encoding utf8
    if ($DebugMode) { Write-Host "LOGGED: $type from $srcIP -> $($targetList -join ',')" }
}

# prepare pktmon filters and start
try { Stop-Process -Name pktmon -ErrorAction SilentlyContinue } catch {}
$pktCfg = Join-Path $env:TEMP "pktmon_filters.txt"
"reset" | Out-File $pktCfg -Encoding ascii
"filter add 0 IP" | Out-File $pktCfg -Append -Encoding ascii
"filter add 0 ICMP" | Out-File $pktCfg -Append -Encoding ascii
foreach ($p in $extraPorts) { "filter add 0 TCP $p" | Out-File $pktCfg -Append -Encoding ascii; "filter add 0 UDP $p" | Out-File $pktCfg -Append -Encoding ascii }
"start" | Out-File $pktCfg -Append -Encoding ascii
try { Start-Process -FilePath "pktmon.exe" -ArgumentList "start" -NoNewWindow -WindowStyle Hidden -ErrorAction SilentlyContinue } catch {}

$pktSeen = [System.Collections.Generic.HashSet[string]]::new()
$hostTracker = @{}

function Parse-PktmonLive {
    $out = @()
    try {
        $lines = & pktmon.exe list --live --limit $PktmonLimit 2>$null
        foreach ($ln in $lines) {
            if (-not $ln -or $ln.Trim().Length -lt 6) { continue }
            $key = ($ln.GetHashCode().ToString() + ":" + $ln.Length)
            if ($pktSeen.Contains($key)) { continue }
            $pktSeen.Add($key) | Out-Null

            $src="unknown"; $dst=""; $sport=""; $dport=""; $proto="UNK"; $flags=""

            if ($ln -match '(?<s>(?:\d{1,3}\.){3}\d{1,3}):(?<sp>\d+)\s*->\s*(?<d>(?:\d{1,3}\.){3}\d{1,3}):(?<dp>\d+)') {
                $src=$Matches['s']; $sport=$Matches['sp']; $dst=$Matches['d']; $dport=$Matches['dp']
            } elseif ($ln -match '(?<d2>(?:\d{1,3}\.){3}\d{1,3}):(?<p2>\d+)\b') {
                if (-not $dst) { $dst = $Matches['d2']; $dport = $Matches['p2'] }
            } elseif ($ln -match '(?<s2>(?:\d{1,3}\.){3}\d{1,3})\s*->\s*(?<d3>(?:\d{1,3}\.){3}\d{1,3})') {
                $src=$Matches['s2']; $dst=$Matches['d3']
            } elseif ($ln -match '(?<ip>(?:\d{1,3}\.){3}\d{1,3})') {
                if (-not $dst) { $dst = $Matches['ip'] }
            }

            if ($ln -match '\bTCP\b') { $proto='TCP' } elseif ($ln -match '\bUDP\b') { $proto='UDP' } elseif ($ln -match '\bICMP\b') { $proto='ICMP' }
            if ($ln -match '\bACK\b') { $flags += 'ACK,' }
            if ($ln -match '\bSYN\b') { $flags += 'SYN,' }
            if ($ln -match '\bRST\b') { $flags += 'RST,' }
            if ($flags.EndsWith(',')) { $flags = $flags.TrimEnd(',') }

            $out += [PSCustomObject]@{ Src=$src; Dst=$dst; Proto=$proto; Sport=$sport; Dport=$dport; Flags=$flags; Details=$ln }
        }
    } catch {}
    return $out
}

Write-Host "Starting recon detection. Log: $reconCsv"
try {
    while ($true) {
        $pktEvents = Parse-PktmonLive
        foreach ($p in $pktEvents) {
            $src = $p.Src
            if (-not $src) { $src = "unknown" }
            if (-not $hostTracker.ContainsKey($src)) {
                $hostTracker[$src] = @{ Targets = @(); FirstSeen = (Get-Date); Ports = @(); AckCount = 0 }
            }
            if ($p.Dst -and ($hostTracker[$src].Targets -notcontains $p.Dst)) { $hostTracker[$src].Targets += $p.Dst }
            if ($p.Dport -and ($p.Dport -ne "") -and ($hostTracker[$src].Ports -notcontains $p.Dport)) { $hostTracker[$src].Ports += $p.Dport }

            if ($p.Proto -eq "TCP" -and ($p.Flags -match 'ACK' -or ($p.Dport -ne "" -and ($p.Dport -in $tcpAckPorts)))) { $hostTracker[$src].AckCount += 1 }

            $targetsCount = $hostTracker[$src].Targets.Count
            $ackCount = $hostTracker[$src].AckCount

            if ($targetsCount -ge $HostSweepThreshold -or $ackCount -ge $HostSweepThreshold) {
                if ($ackCount -ge $HostSweepThreshold) { $type = "TCP ACK Sweep" }
                elseif ($p.Proto -eq "ICMP") { $type = "ICMP Sweep" }
                else { $type = "OT Protocol Sweep" }
                $details = "Flags:$($p.Flags) Ports:$(($hostTracker[$src].Ports) -join ',')"
                Log-Recon $src $targetsCount $hostTracker[$src].Targets $type $details
                $hostTracker.Remove($src)
            }
        }

        foreach ($srcKey in ($hostTracker.Keys | ForEach-Object { $_ })) {
            $age = (Get-Date) - $hostTracker[$srcKey].FirstSeen
            if ($age.TotalSeconds -gt $TimeWindowSeconds) { $hostTracker.Remove($srcKey) }
        }

        Start-Sleep -Seconds $LoopSleepSeconds
    }
} finally {
    try { Start-Process -FilePath "pktmon.exe" -ArgumentList "stop" -NoNewWindow -WindowStyle Hidden -ErrorAction SilentlyContinue } catch {}
}
