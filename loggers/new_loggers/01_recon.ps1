# Live Recon & Traffic Monitor (Requires Admin)
# Save as LiveReconMonitor.ps1 and run as Admin

# ---------- CONFIG ----------
$PortScanThreshold = 20
$TimeWindowSeconds = 120
$LoopSleepSeconds = 5

$logDir = "C:\ProgramData\CustomSecurityLogs"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

$fullCsv = Join-Path $logDir "full_traffic_log.csv"
$detectCsv = Join-Path $logDir "detection_log.csv"



# ensure headers (use "o" timestamp when writing rows)
if (-not (Test-Path $fullCsv)) { "Timestamp,Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,ProcessId,ProcessName" | Out-File $fullCsv -Encoding utf8 }
if (-not (Test-Path $detectCsv)) { "Timestamp,RemoteIP,PortCount,Ports,DetectionType,Details" | Out-File $detectCsv -Encoding utf8 }

# protocol mapping (common ports)
$protocolMap = @{
    "TCP/53"   = "DNS"; "UDP/53"   = "DNS";
    "TCP/80"   = "HTTP"; "TCP/443" = "HTTPS";
    "TCP/25"   = "SMTP"; "UDP/161" = "SNMP";
    "TCP/21"   = "FTP"; "TCP/22"  = "SSH";
    "TCP/389"  = "LDAP"; "TCP/445" = "SMB";
    "TCP/502"  = "Modbus"; "TCP/20000" = "DNP3"; "UDP/20000" = "DNP3";
    "UDP/47808"= "BACnet"; "TCP/44818" = "EtherNet/IP";
    "TCP/102"  = "S7comm"; "UDP/102" = "S7comm"
}

# extra ports for pktmon filters (industrial + common)
$extraPorts = $protocolMap.Keys | ForEach-Object { ($_ -split "/")[1] } | Where-Object { $_ -match '^\d+$' } | Sort-Object -Unique

# ---------- UTIL FUNCTIONS ----------


# helper to record observed connection into full CSV
function Log-Full {
    param($proto, $laddr, $lport, $raddr, $rport, $state, $pid, $pname)
    $ts = (Get-Date).ToString("o")
    $row = @($ts, $proto, $laddr, $lport, $raddr, $rport, $state, $pid, $pname)
    $row = $row | ForEach-Object {
        if ($_ -eq $null) { "" } else { ($_.ToString()).Replace('"','""') }
    }
    $csv = '"' + ($row -join '","') + '"'
    $csv | Out-File -FilePath $fullCsv -Append -Encoding utf8
}

# helper to write detection row
function Log-Detection {
    param($remoteIP, $portCount, $portsList, $type, $details)
    $ts = (Get-Date).ToString("o")
    $row = @($ts, $remoteIP, $portCount, ($portsList -join ';'), $type, $details)
    $row = $row | ForEach-Object { if ($_ -eq $null) { "" } else { ($_.ToString()).Replace('"','""') } }
    $csv = '"' + ($row -join '","') + '"'
    $csv | Out-File -FilePath $detectCsv -Append -Encoding utf8
    
}

# ---------- PKTMON SETUP ----------
# Try to ensure pktmon is not running twice
try { Stop-Process -Name pktmon -ErrorAction SilentlyContinue } catch {}
# build filters file (temporary) - kept for reference (pktmon invoked with default start)
$pktCfg = Join-Path $env:TEMP "pktmon_filters.txt"
"reset" | Out-File $pktCfg -Encoding ascii
"filter add 0 ICMP" | Out-File $pktCfg -Append -Encoding ascii
foreach ($p in $extraPorts) {
    "filter add 0 TCP $p" | Out-File $pktCfg -Append -Encoding ascii
    "filter add 0 UDP $p" | Out-File $pktCfg -Append -Encoding ascii
}
"start" | Out-File $pktCfg -Append -Encoding ascii

# Start pktmon in live-listen mode (we'll use 'pktmon list --live')
try { Start-Process -FilePath "pktmon.exe" -ArgumentList "start" -NoNewWindow -WindowStyle Hidden -ErrorAction SilentlyContinue } catch {}

# small in-memory dedupe for pktmon entries
$pktSeen = [System.Collections.Generic.HashSet[string]]::new()

# ---------- IP Tracker for Port-Scan Detection ----------
$ipTracker = @{}

# ---------- COLLECTION ROUTINES ----------
function Get-Connections {
    $conns = @()
    $hasNetTCPConnection = Get-Command "Get-NetTCPConnection" -ErrorAction SilentlyContinue
    if ($hasNetTCPConnection) {
        try {
            $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue
            foreach ($c in $tcp) {
                $procName = ""
                try { $procName = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
                $conns += [PSCustomObject]@{
                    Protocol = "TCP"
                    LocalAddress = $c.LocalAddress
                    LocalPort = $c.LocalPort
                    RemoteAddress = $c.RemoteAddress
                    RemotePort = $c.RemotePort
                    State = $c.State
                    ProcessId = $c.OwningProcess
                    ProcessName = $procName
                }
            }
        } catch {}
        $hasUDP = Get-Command "Get-NetUDPEndpoint" -ErrorAction SilentlyContinue
        if ($hasUDP) {
            try {
                $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
                foreach ($u in $udp) {
                    $procName = ""
                    try { $procName = (Get-Process -Id $u.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
                    $conns += [PSCustomObject]@{
                        Protocol = "UDP"
                        LocalAddress = $u.LocalAddress
                        LocalPort = $u.LocalPort
                        RemoteAddress = ""
                        RemotePort = ""
                        State = ""
                        ProcessId = $u.OwningProcess
                        ProcessName = $procName
                    }
                }
            } catch {}
        }
    } else {
        $net = netstat -ano 2>$null
        foreach ($line in $net) {
            if ($line -match "^\s*(TCP|UDP)\s+(\S+):(\d+)\s+(\S+):(\d+|\*)\s*(\S*)\s*(\d+)$") {
                $proto = $matches[1]; $laddr = $matches[2]; $lport = $matches[3]
                $raddr = $matches[4]; $rport = $matches[5]; $state = $matches[6]; $pid = $matches[7]
                $pname = ""
                try { $pname = (Get-Process -Id $pid -ErrorAction SilentlyContinue).ProcessName } catch {}
                $conns += [PSCustomObject]@{
                    Protocol = $proto
                    LocalAddress = $laddr
                    LocalPort = $lport
                    RemoteAddress = $raddr
                    RemotePort = $rport
                    State = $state
                    ProcessId = $pid
                    ProcessName = $pname
                }
            }
        }
    }
    return $conns
}

function Parse-PktmonLive {
    # returns array of PSCustomObject: Protocol, RemoteAddress, RemotePort, Details
    $out = @()
    try {
        $lines = & pktmon.exe list --live --limit 200 2>$null
        foreach ($ln in $lines) {
            if ($null -eq $ln) { continue }
            if ($ln.Trim().Length -lt 10) { continue }
            $key = $ln.GetHashCode().ToString() + ":" + ($ln.Length)
            if ($pktSeen.Contains($key)) { continue }
            $pktSeen.Add($key) | Out-Null
            # basic parsing heuristics: look for ICMP or ip:port pairs
            if ($ln -match "ICMP") {
                if ($ln -match "(\d{1,3}\.){3}\d{1,3}") {
                    $ip = $matches[0]
                    $out += [PSCustomObject]@{ Protocol="ICMP"; RemoteAddress=$ip; RemotePort=""; Details=$ln }
                }
            } else {
                if ($ln -match "(\d{1,3}\.){3}\d{1,3}:(\d{1,5})") {
                    $ip = ($matches[0] -split ":")[0]
                    $port = $matches[2]
                    $proto = if ($ln -match "TCP") { "TCP" } elseif ($ln -match "UDP") { "UDP" } else { "UNK" }
                    $out += [PSCustomObject]@{ Protocol=$proto; RemoteAddress=$ip; RemotePort=$port; Details=$ln }
                }
            }
        }
    } catch {}
    return $out
}

# ---------- MAIN LOOP ----------
Write-Host "Starting live monitor. Logs: $fullCsv and $detectCsv"


try {
    while ($true) {
        # 1) collect socket connections
        $conns = Get-Connections

        # 2) log each observed connection to full CSV and update ipTracker
        foreach ($c in $conns) {
            # normalize addresses
            $raddr = $c.RemoteAddress
            if ($raddr -in @("127.0.0.1","::1","0.0.0.0","")) { $raddr = "" }

            Log-Full -proto $c.Protocol -laddr $c.LocalAddress -lport $c.LocalPort -raddr $raddr -rport $c.RemotePort -state $c.State -pid $c.ProcessId -pname $c.ProcessName

            if ($raddr -ne "") {
                $remotePortStr = if ($c.RemotePort -ne $null -and $c.RemotePort -ne "") { $c.RemotePort.ToString() } else { "" }
                $protoKey = ("{0}/{1}" -f $c.Protocol, $remotePortStr)
                if (-not $ipTracker.ContainsKey($raddr)) {
                    $ipTracker[$raddr] = @{ Ports = @(); FirstSeen = (Get-Date) }
                }
                if ($remotePortStr -ne "" -and ($ipTracker[$raddr].Ports -notcontains $protoKey)) {
                    $ipTracker[$raddr].Ports += $protoKey
                }
            }
            # also detect known-protocol single-flow matches (log as detection)
            $remotePortStr2 = if ($c.RemotePort -ne $null -and $c.RemotePort -ne "") { $c.RemotePort.ToString() } else { "" }
            $protoKeyExact = ("{0}/{1}" -f $c.Protocol, $remotePortStr2)
            if ($protocolMap.ContainsKey($protoKeyExact)) {
                Log-Detection -remoteIP ($c.RemoteAddress) -portCount 1 -portsList @($protoKeyExact) -type "ProtocolMatch" -details $protocolMap[$protoKeyExact]
            }
        }

        # 3) parse pktmon live for ICMP and industrial protocols
        $pktEvents = Parse-PktmonLive
        foreach ($p in $pktEvents) {
            Log-Full -proto $p.Protocol -laddr "" -lport "" -raddr $p.RemoteAddress -rport $p.RemotePort -state "" -pid "" -pname $p.Details
            if ($p.RemoteAddress) {
                $remotePortStr = if ($p.RemotePort -ne $null -and $p.RemotePort -ne "") { $p.RemotePort.ToString() } else { "" }
                $protoKey = ("{0}/{1}" -f $p.Protocol, $remotePortStr)
                if (-not $ipTracker.ContainsKey($p.RemoteAddress)) {
                    $ipTracker[$p.RemoteAddress] = @{ Ports = @(); FirstSeen = (Get-Date) }
                }
                if ($remotePortStr -ne "" -and ($ipTracker[$p.RemoteAddress].Ports -notcontains $protoKey)) {
                    $ipTracker[$p.RemoteAddress].Ports += $protoKey
                }
            }
            # if port maps to protocol, log detection
            $remotePortStr2 = if ($p.RemotePort -ne $null -and $p.RemotePort -ne "") { $p.RemotePort.ToString() } else { "" }
            $protoKeyExact = ("{0}/{1}" -f $p.Protocol, $remotePortStr2)
            if ($protocolMap.ContainsKey($protoKeyExact)) {
                Log-Detection -remoteIP $p.RemoteAddress -portCount 1 -portsList @($protoKeyExact) -type "ProtocolMatch" -details $protocolMap[$protoKeyExact]
            } elseif ($p.Protocol -eq "ICMP") {
                Log-Detection -remoteIP $p.RemoteAddress -portCount 0 -portsList @() -type "ICMP" -details "ICMP packet observed"
            }
        }

        # 4) port-scan detection: check ipTracker entries
        foreach ($ip in ($ipTracker.Keys | ForEach-Object { $_ })) {
            $entry = $ipTracker[$ip]
            $age = (Get-Date) - $entry.FirstSeen
            if ($age.TotalSeconds -gt $TimeWindowSeconds) {
                $ipTracker.Remove($ip)
                continue
            }
            $count = $entry.Ports.Count
            if ($count -gt $PortScanThreshold) {
                $portsResolved = $entry.Ports | ForEach-Object {
                    if ($protocolMap.ContainsKey($_)) { "$_ ($($protocolMap[$_]))" } else { $_ }
                }
                Log-Detection -remoteIP $ip -portCount $count -portsList $portsResolved -type "PortScan" -details "Threshold $PortScanThreshold in $TimeWindowSeconds sec"
                Write-Host "`nALERT: Scan detected from $ip -> $count ports" -ForegroundColor Red
                $ipTracker.Remove($ip)
            }
        }

        Start-Sleep -Seconds $LoopSleepSeconds
    }
} finally {
    # try stopping pktmon gracefully
    try { Start-Process -FilePath "pktmon.exe" -ArgumentList "stop" -NoNewWindow -WindowStyle Hidden -ErrorAction SilentlyContinue } catch {}
    
}
