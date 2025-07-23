#Requires -RunAsAdministrator

# --- Configuration ---
$LogFile = "C:\ProgramData\CustomSecurityLogs\recon_log.txt"
$HoneyfileDir = "C:\ReconTrap"
$DNSLogPath = "C:\Windows\System32\dns\dnssrv.log"
$PortScanThreshold = 20
$TimeWindowSeconds = 120
$RemoteLogEndpoint = "http://192.168.127.139:8000/logs"

# --- Ensure Log Directory Exists ---
$logDir = Split-Path $LogFile
if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# --- Logging Function ---
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] - $Level - $Message"
    $logEntry | Out-File -FilePath $LogFile -Append

    if ($Level -eq "ALERT") {
        try {
            $jsonBody = @{
                timestamp = $timestamp
                level     = $Level
                message   = $Message
            } | ConvertTo-Json -Depth 3

            Invoke-RestMethod -Uri $RemoteLogEndpoint -Method POST -Body $jsonBody -ContentType "application/json" -TimeoutSec 5
        } catch {
            Write-Host "Warning: Failed to send alert to FastAPI: $_" -ForegroundColor Yellow
        }
    }
}

# --- Monitor Failed Login Events (Event ID 4625) ---
function Monitor-FailedLogins {
    $lastEventTime = Get-Date
    
    while ($true) {
        try {
            # Get failed login events since last check
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                Id = 4625
                StartTime = $lastEventTime
            } -ErrorAction SilentlyContinue
            
            foreach ($event in $events) {
                $user = "Unknown"
                $ip = "Unknown"
                
                try {
                    # Extract username and IP from event properties
                    $user = $event.Properties[5].Value  # Target username
                    $ip = $event.Properties[19].Value   # Source IP address
                } catch {
                    $user = "ParseError"
                    $ip = "ParseError"
                }
                
                Write-Log -Level "ALERT" -Message "FAILED_LOGIN: User: $user | Source IP: $ip | Time: $($event.TimeCreated)"
            }
            
            $lastEventTime = Get-Date
        } catch {
            Write-Log -Message "Error monitoring failed logins: $_"
        }
        
        Start-Sleep -Seconds 10
    }
}

# --- Monitor Honeyfile Access ---
function Monitor-Honeyfiles {
    if (-not (Test-Path $HoneyfileDir)) {
        New-Item -ItemType Directory -Path $HoneyfileDir
        Set-Content -Path "$HoneyfileDir\Passwords.txt" -Value "Do not touch"
    }

    $fsw = New-Object System.IO.FileSystemWatcher
    $fsw.Path = $HoneyfileDir
    $fsw.Filter = "*.*"
    $fsw.IncludeSubdirectories = $false
    $fsw.EnableRaisingEvents = $true

    Register-ObjectEvent $fsw Changed -Action {
        $filename = $Event.SourceEventArgs.FullPath
        Write-Log -Level "ALERT" -Message "HONEYFILE_ACCESS: File accessed: $filename"
    }
}

# --- Monitor DNS Debug Log ---
function Monitor-DNSLog {
    if (-Not (Test-Path $DNSLogPath)) {
        Write-Log -Message "DNS log file not found at $DNSLogPath"
        return
    }

    $lastSize = (Get-Item $DNSLogPath).Length
    while ($true) {
        $size = (Get-Item $DNSLogPath).Length
        if ($size -gt $lastSize) {
            $diff = $size - $lastSize
            $stream = New-Object IO.FileStream $DNSLogPath, 'Open', 'Read', 'ReadWrite'
            $stream.Seek($lastSize, 'Begin') | Out-Null
            $reader = New-Object IO.StreamReader $stream
            $newLines = $reader.ReadToEnd()
            $reader.Close(); $stream.Close()

            foreach ($line in $newLines -split "`n") {
                if ($line -match "dev|internal|admin") {
                    Write-Log -Level "ALERT" -Message "DNS_RECON: Suspicious DNS query: $line"
                }
            }
            $lastSize = $size
        }
        Start-Sleep -Seconds 5
    }
}

# --- Monitor Web Root for File Creation ---
function Monitor-SensitiveDirs {
    $sensitivePath = "C:\inetpub\wwwroot"
    if (-Not (Test-Path $sensitivePath)) { return }

    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = $sensitivePath
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true

    Register-ObjectEvent $watcher Created -Action {
        Write-Log -Level "ALERT" -Message "WEB_ENUM: New file or folder created: $($Event.SourceEventArgs.FullPath)"
    }
}

# --- Monitor IIS Logs for Suspicious URL Access ---
function Monitor-IISLogs {
    $iisLogPath = "C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log"
    if (-Not (Test-Path $iisLogPath)) { return }

    $lastTime = Get-Date
    while ($true) {
        $logs = Get-ChildItem -Path $iisLogPath | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($logs.LastWriteTime -gt $lastTime) {
            $lastTime = $logs.LastWriteTime
            $lines = Get-Content $logs.FullName | Select-String -Pattern "/admin|/login|\.git|\.env"
            foreach ($match in $lines) {
                $ip = ($match.Line -split " ")[8]
                $url = ($match.Line -split " ")[10]
                Write-Log -Level "ALERT" -Message "WEB_SCAN: URL accessed: $url | Source IP: $ip"
            }
        }
        Start-Sleep -Seconds 30
    }
}

# --- Advanced Port Scan Detector ---
function Monitor-PortScans {
    $ipTracker = @{}

    while ($true) {
        $connections = Get-NetTCPConnection -State SynSent, TimeWait, Established -ErrorAction SilentlyContinue

        foreach ($conn in $connections) {
            $remoteIP = $conn.RemoteAddress
            if ($remoteIP -eq "127.0.0.1" -or $remoteIP -eq "::1") { continue }

            if (-not $ipTracker.ContainsKey($remoteIP)) {
                $ipTracker[$remoteIP] = @{
                    Ports     = [System.Collections.Generic.HashSet[int]]::new()
                    States    = @{}
                    FirstSeen = Get-Date
                    LastSeen  = Get-Date
                }
            }

            $ipTracker[$remoteIP].Ports.Add($conn.RemotePort) | Out-Null
            $ipTracker[$remoteIP].LastSeen = Get-Date

            $state = $conn.State
            if (-not $ipTracker[$remoteIP].States.ContainsKey($state)) {
                $ipTracker[$remoteIP].States[$state] = 0
            }
            $ipTracker[$remoteIP].States[$state] += 1
        }

        foreach ($ip in @($ipTracker.Keys)) {
            $firstSeen = $ipTracker[$ip].FirstSeen
            $lastSeen = $ipTracker[$ip].LastSeen
            $duration = ($lastSeen - $firstSeen).TotalSeconds

            if ($duration -gt $TimeWindowSeconds) {
                $ipTracker.Remove($ip)
                continue
            }

            $ports = $ipTracker[$ip].Ports
            $portCount = $ports.Count
            if ($portCount -gt $PortScanThreshold) {
                $sortedPorts = $ports | Sort-Object
                $lowPorts = $sortedPorts | Where-Object { $_ -lt 1024 }
                $highPorts = $sortedPorts | Where-Object { $_ -ge 1024 }
                $bannerPorts = @(22, 23, 80, 443, 3389, 445)
                $targetedBanners = $sortedPorts | Where-Object { $bannerPorts -contains $_ }
                $stateInfo = ($ipTracker[$ip].States.Keys | ForEach-Object {
                    "$_=$($ipTracker[$ip].States[$_])"
                }) -join ", "

                $guess = "Unknown scan type"
                if ($ipTracker[$ip].States.ContainsKey("SynSent") -and -not $ipTracker[$ip].States.ContainsKey("Established")) {
                    $guess = "Possible SYN (stealth) scan"
                } elseif ($ipTracker[$ip].States.ContainsKey("Established")) {
                    $guess = "Likely full connect scan"
                }
                if ($targetedBanners.Count -gt 0) {
                    $guess += ", targeting common services"
                }
                if ($highPorts.Count -gt $lowPorts.Count) {
                    $guess += ", probing high/ephemeral ports"
                }
                if ($duration -lt 10) {
                    $guess += ", rapid scan (e.g. -T4 or -T5)"
                }

                $alertMessage = "PORT_SCAN: Scan from ${ip}: $portCount ports " +
                                "($($lowPorts.Count) low, $($highPorts.Count) high), states: $stateInfo. " +
                                "Duration: $([math]::Round($duration, 2))s. Ports: $($sortedPorts -join ','). $guess"
                Write-Log -Level "ALERT" -Message $alertMessage
                $ipTracker.Remove($ip)
            }
        }

        Start-Sleep -Seconds 5
    }
}

# --- Start Services ---
Write-Log -Message "Recon monitoring initialized."
Monitor-Honeyfiles
Monitor-SensitiveDirs
Start-Job { Monitor-DNSLog }
Start-Job { Monitor-IISLogs }
Start-Job { Monitor-PortScans }
Start-Job { Monitor-FailedLogins }

# --- Keep Script Alive ---
while ($true) {
    Start-Sleep -Seconds 300
}
