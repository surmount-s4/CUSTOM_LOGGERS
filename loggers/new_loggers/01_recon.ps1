# Recon Detection in OT Networks + TCP ACK Sweeps (Requires Admin)
# Save as ReconDetect.ps1 and run as Admin

$HostSweepThreshold = 5
$TimeWindowSeconds = 60
$LoopSleepSeconds = 5

$logDir = "C:\Logs"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$reconCsv = Join-Path $logDir "recon_log.csv"
if (-not (Test-Path $reconCsv)) { "Timestamp,SourceIP,TargetCount,Targets,Type,Details" | Out-File $reconCsv -Encoding utf8 }

$protocolMap = @{
    "TCP/502"  = "Modbus"; "TCP/20000" = "DNP3"; "UDP/20000" = "DNP3";
    "UDP/47808"= "BACnet"; "TCP/44818" = "EtherNet/IP";
    "TCP/102"  = "S7comm"; "UDP/102" = "S7comm"
}

# Common TCP ACK ping ports used by Nmap
$tcpAckPorts = @(80, 443, 21, 22, 23, 25, 135, 139, 445, 3389)

$extraPorts = ($protocolMap.Keys | ForEach-Object { ($_ -split "/")[1] } |
               Where-Object { $_ -match '^\d+$' }) + $tcpAckPorts
$extraPorts = $extraPorts | Sort-Object -Unique

function Log-Recon {
    param($srcIP, $targetCount, $targetList, $type, $details)
    $ts = (Get-Date).ToString("o")
    $row = @($ts, $srcIP, $targetCount, ($targetList -join ';'), $type, $details)
    $row = $row | ForEach-Object { if ($_ -eq $null) { "" } else { ($_.ToString()).Replace('"','""') } }
    '"' + ($row -join '","') + '"' | Out-File -FilePath $reconCsv -Append -Encoding utf8
}

try { Stop-Process -Name pktmon -ErrorAction SilentlyContinue } catch {}
$pktCfg = Join-Path $env:TEMP "pktmon_filters.txt"
"reset" | Out-File $pktCfg -Encoding ascii
"filter add 0 ICMP" | Out-File $pktCfg -Append -Encoding ascii
foreach ($p in $extraPorts) {
    "filter add 0 TCP $p" | Out-File $pktCfg -Append -Encoding ascii
    "filter add 0 UDP $p" | Out-File $pktCfg -Append -Encoding ascii
}
"start" | Out-File $pktCfg -Append -Encoding ascii
try { Start-Process -FilePath "pktmon.exe" -ArgumentList "start" -NoNewWindow -WindowStyle Hidden -ErrorAction SilentlyContinue } catch {}

$pktSeen = [System.Collections.Generic.HashSet[string]]::new()
$hostTracker = @{}

function Parse-PktmonLive {
    $out = @()
    try {
        $lines = & pktmon.exe list --live --limit 200 2>$null
        foreach ($ln in $lines) {
            if (-not $ln -or $ln.Trim().Length -lt 10) { continue }
            $key = $ln.GetHashCode().ToString() + ":" + ($ln.Length)
            if ($pktSeen.Contains($key)) { continue }
            $pktSeen.Add($key) | Out-Null

            if ($ln -match "ICMP" -and $ln -match "(\d{1,3}\.){3}\d{1,3}") {
                $ip = $matches[0]
                $out += [PSCustomObject]@{ Src="unknown"; Dst=$ip; Proto="ICMP"; Port=""; Details=$ln }
            }
            elseif ($ln -match "(\d{1,3}\.){3}\d{1,3}:(\d{1,5})") {
                $dst = ($matches[0] -split ":")[0]
                $port = $matches[2]
                $proto = if ($ln -match "TCP") { "TCP" } elseif ($ln -match "UDP") { "UDP" } else { "UNK" }
                $out += [PSCustomObject]@{ Src="unknown"; Dst=$dst; Proto=$proto; Port=$port; Details=$ln }
            }
        }
    } catch {}
    return $out
}

Write-Host "Starting recon detection. Log: $reconCsv"

try {
    while ($true) {
        Write-Host "new loop"
        $pktEvents = Parse-PktmonLive
        foreach ($p in $pktEvents) {
            $src = $p.Src
            $dst = $p.Dst
            if (-not $src) { $src = "unknown" }
            if (-not $hostTracker.ContainsKey($src)) {
                $hostTracker[$src] = @{ Targets = @(); FirstSeen = (Get-Date); Ports=@() }
            }
            if ($dst -and ($hostTracker[$src].Targets -notcontains $dst)) {
                $hostTracker[$src].Targets += $dst
            }
            if ($p.Port -and ($hostTracker[$src].Ports -notcontains $p.Port)) {
                $hostTracker[$src].Ports += $p.Port
            }

            # ICMP sweep
            if ($p.Proto -eq "ICMP" -and $hostTracker[$src].Targets.Count -ge $HostSweepThreshold) {
                Log-Recon $src $hostTracker[$src].Targets.Count $hostTracker[$src].Targets "ICMP Sweep" "Multiple ping targets in short time"
                $hostTracker.Remove($src)
            }
            # OT protocol sweep
            elseif ($protocolMap.ContainsKey("$($p.Proto)/$($p.Port)") -and $hostTracker[$src].Targets.Count -ge $HostSweepThreshold) {
                Log-Recon $src $hostTracker[$src].Targets.Count $hostTracker[$src].Targets "OT Protocol Sweep" "Multiple devices scanned over $($protocolMap["$($p.Proto)/$($p.Port)"])"
                $hostTracker.Remove($src)
            }
            # TCP ACK sweep detection
            elseif ($p.Proto -eq "TCP" -and ($p.Port -in $tcpAckPorts) -and $hostTracker[$src].Targets.Count -ge $HostSweepThreshold) {
                Log-Recon $src $hostTracker[$src].Targets.Count $hostTracker[$src].Targets "TCP ACK Sweep" "Multiple targets probed on common ACK ping ports"
                $hostTracker.Remove($src)
            }
        }

        foreach ($src in ($hostTracker.Keys | ForEach-Object { $_ })) {
            $age = (Get-Date) - $hostTracker[$src].FirstSeen
            if ($age.TotalSeconds -gt $TimeWindowSeconds) { $hostTracker.Remove($src) }
        }

        Start-Sleep -Seconds $LoopSleepSeconds
    }
} finally {
    try { Start-Process -FilePath "pktmon.exe" -ArgumentList "stop" -NoNewWindow -WindowStyle Hidden -ErrorAction SilentlyContinue } catch {}
}
