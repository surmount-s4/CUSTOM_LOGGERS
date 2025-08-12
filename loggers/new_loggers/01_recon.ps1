$logFile = "C:\Logs\ReconLog.csv"
$thresholdPorts = 20
$thresholdHosts = 10
$timeWindowSec = 5

if (-not (Test-Path $logFile)) {
    "Time,SourceIP,ReconType,Details" | Out-File -FilePath $logFile -Encoding utf8
}

$scanTracker = @{}

Write-Host "Starting pktmon for live capture..."
Start-Process -NoNewWindow -FilePath "pktmon.exe" -ArgumentList "start --etw -m real-time" -RedirectStandardOutput "C:\Logs\pktmon.log"

Get-Content "C:\Logs\pktmon.log" -Wait | ForEach-Object {
    $line = $_
    if ($line -match '(\d+\.\d+\.\d+\.\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+):?(\d+)?') {
        $src = $matches[1]
        $dst = $matches[2]
        $port = if ($matches[3]) { [int]$matches[3] } else { 0 }
        $now = Get-Date

        if (-not $scanTracker.ContainsKey($src)) {
            $scanTracker[$src] = [PSCustomObject]@{
                Ports = @{}
                Hosts = @{}
            }
        }

        $scanTracker[$src].Ports[$port] = $now
        $scanTracker[$src].Hosts[$dst] = $now

        $portsCount = ($scanTracker[$src].Ports.GetEnumerator() | Where-Object { ($now - $_.Value).TotalSeconds -le $timeWindowSec }).Count
        $hostsCount = ($scanTracker[$src].Hosts.GetEnumerator() | Where-Object { ($now - $_.Value).TotalSeconds -le $timeWindowSec }).Count

        if ($portsCount -ge $thresholdPorts) {
            "$($now),$src,Port Scan,Ports contacted: $portsCount in $timeWindowSec sec" | Out-File -Append -FilePath $logFile
            $scanTracker[$src].Ports.Clear()
        }
        elseif ($hostsCount -ge $thresholdHosts) {
            "$($now),$src,Host Sweep,Hosts contacted: $hostsCount in $timeWindowSec sec" | Out-File -Append -FilePath $logFile
            $scanTracker[$src].Hosts.Clear()
        }
    }
}
