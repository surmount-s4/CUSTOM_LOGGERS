#Requires -RunAsAdministrator

# PowerShell version compatibility check for Windows Server 2012
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Error "This script requires PowerShell 3.0 or later. Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

# --- Configuration ---
$LogFile = "C:\ProgramData\CustomSecurityLogs\unified_recon_detector.log"
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

# --- Enhanced Logging Function (Windows 2012 Compatible) ---
function Write-Log {
    param(
        [string]$Message, 
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] - $Level - $Message"
    $logEntry | Out-File -FilePath $LogFile -Append

    # Console output for critical alerts
    if ($Level -eq "ALERT") {
        Write-Host "`n[ALERT] $Message" -ForegroundColor Red
    }

    # Send ALERT logs to FastAPI server (Windows 2012 compatible JSON)
    if ($Level -eq "ALERT") {
        try {
            # Windows 2012 compatible JSON creation
            $escapedMessage = $Message -replace '"', '\"' -replace '\\', '\\\\'
            $jsonBody = "{`"timestamp`":`"$timestamp`",`"level`":`"$Level`",`"message`":`"$escapedMessage`"}"
            Invoke-RestMethod -Uri $RemoteLogEndpoint -Method POST -Body $jsonBody -ContentType "application/json" -TimeoutSec 5
        } catch {
            Write-Host "Warning: Failed to send alert to FastAPI: $_" -ForegroundColor Yellow
        }
    }
}

# --- Compatibility Check for Network Commands ---
$hasNetTCPConnection = Get-Command "Get-NetTCPConnection" -ErrorAction SilentlyContinue
$hasRegisterWinEvent = Get-Command "Register-WinEvent" -ErrorAction SilentlyContinue
$hasGetNetAdapter = Get-Command "Get-NetAdapter" -ErrorAction SilentlyContinue

# Display compatibility status
Write-Host "=== Windows Server 2012 Compatibility Check ===" -ForegroundColor Cyan
if (-not $hasNetTCPConnection) {
    Write-Host "[FALLBACK] Get-NetTCPConnection not available - Using netstat" -ForegroundColor Yellow
    Write-Log -Message "Get-NetTCPConnection not available. Using netstat fallback for Windows 2012 compatibility." -Level "INFO"
}
if (-not $hasRegisterWinEvent) {
    Write-Host "[FALLBACK] Register-WinEvent not available - Using WMI/Manual event monitoring" -ForegroundColor Yellow
    Write-Log -Message "Register-WinEvent not available. Using WMI and manual event log monitoring." -Level "INFO"
}
if (-not $hasGetNetAdapter) {
    Write-Host "[FALLBACK] Get-NetAdapter not available - Using WMI performance counters" -ForegroundColor Yellow
    Write-Log -Message "Get-NetAdapter not available. Using WMI performance counters." -Level "INFO"
}

# --- Advanced Nmap/Port Scan Detection ---
function Start-PortScanMonitoring {
    Write-Log -Message "Starting advanced port scan monitoring..." -Level "INFO"
    $ipTracker = @{}

    while ($true) {
        if ($hasNetTCPConnection) {
            # Modern approach using Get-NetTCPConnection
            $connections = Get-NetTCPConnection -State SynSent, TimeWait, Established -ErrorAction SilentlyContinue
            
            foreach ($conn in $connections) {
                $remoteIP = $conn.RemoteAddress
                if ($remoteIP -eq "127.0.0.1" -or $remoteIP -eq "::1") { continue }

                if (-not $ipTracker.ContainsKey($remoteIP)) {
                    $ipTracker[$remoteIP] = @{
                        Ports     = @()
                        States    = @{}
                        FirstSeen = Get-Date
                        LastSeen  = Get-Date
                    }
                }

                # Add port if not already present (Windows 2012 compatible)
                if ($ipTracker[$remoteIP].Ports -notcontains $conn.RemotePort) {
                    $ipTracker[$remoteIP].Ports += $conn.RemotePort
                }
                $ipTracker[$remoteIP].LastSeen = Get-Date

                # Track connection states
                $state = $conn.State
                if (-not $ipTracker[$remoteIP].States.ContainsKey($state)) {
                    $ipTracker[$remoteIP].States[$state] = 0
                }
                $ipTracker[$remoteIP].States[$state] += 1
            }
        } else {
            # Fallback approach using netstat for Windows 2012 compatibility
            $netstatOutput = netstat -an | Where-Object { $_ -match "TCP.*SYN_SENT|TCP.*TIME_WAIT|TCP.*ESTABLISHED" }
            
            foreach ($line in $netstatOutput) {
                if ($line -match "TCP\s+\S+:(\d+)\s+(\S+):(\d+)\s+(\S+)") {
                    $remoteIP = $matches[2]
                    $remotePort = [int]$matches[3]
                    $state = $matches[4]
                    
                    if ($remoteIP -eq "127.0.0.1" -or $remoteIP -eq "::1") { continue }

                    if (-not $ipTracker.ContainsKey($remoteIP)) {
                        $ipTracker[$remoteIP] = @{
                            Ports     = @()
                            States    = @{}
                            FirstSeen = Get-Date
                            LastSeen  = Get-Date
                        }
                    }
                    
                    # Add port if not already present
                    if ($ipTracker[$remoteIP].Ports -notcontains $remotePort) {
                        $ipTracker[$remoteIP].Ports += $remotePort
                    }
                    $ipTracker[$remoteIP].LastSeen = Get-Date

                    # Track connection states
                    if (-not $ipTracker[$remoteIP].States.ContainsKey($state)) {
                        $ipTracker[$remoteIP].States[$state] = 0
                    }
                    $ipTracker[$remoteIP].States[$state] += 1
                }
            }
        }

        # Analyze potential scans
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
                $bannerPorts = @(22, 23, 80, 443, 3389, 445, 135, 139, 21, 25)
                $targetedBanners = $sortedPorts | Where-Object { $bannerPorts -contains $_ }
                
                # Build state information string
                $stateInfo = ""
                if ($ipTracker[$ip].States.Keys.Count -gt 0) {
                    $stateInfo = ($ipTracker[$ip].States.Keys | ForEach-Object {
                        "$_=$($ipTracker[$ip].States[$_])"
                    }) -join ", "
                }

                # Analyze scan characteristics (Nmap detection heuristics)
                $scanType = "Unknown scan type"
                if ($ipTracker[$ip].States.ContainsKey("SynSent") -and -not $ipTracker[$ip].States.ContainsKey("Established")) {
                    $scanType = "Possible NMAP SYN (stealth) scan"
                } elseif ($ipTracker[$ip].States.ContainsKey("Established")) {
                    $scanType = "Likely NMAP full connect scan"
                }
                
                if ($targetedBanners.Count -gt 0) {
                    $scanType += ", targeting common services (possible -sV or -A flags)"
                }
                
                if ($highPorts.Count -gt $lowPorts.Count) {
                    $scanType += ", probing high/ephemeral ports"
                }
                
                if ($duration -lt 10) {
                    $scanType += ", rapid scan (likely nmap -T4 or -T5)"
                } elseif ($duration -lt 30) {
                    $scanType += ", moderate speed (likely nmap -T3)"
                }

                # Check for sequential ports (common nmap behavior)
                $sequentialCount = 0
                for ($i = 0; $i -lt ($sortedPorts.Count - 1); $i++) {
                    if ($sortedPorts[$i+1] - $sortedPorts[$i] -eq 1) {
                        $sequentialCount++
                    }
                }
                if ($sequentialCount -gt 5) {
                    $scanType += ", sequential port pattern (typical nmap behavior)"
                }

                $alertMessage = "NMAP_SCAN_DETECTED: Scan from ${ip}: $portCount ports " +
                                "($($lowPorts.Count) low, $($highPorts.Count) high), states: $stateInfo. " +
                                "Duration: $([math]::Round($duration, 2))s. $scanType. " +
                                "Ports: $($sortedPorts -join ',')"
                
                Write-Log -Level "ALERT" -Message $alertMessage
                $ipTracker.Remove($ip)
            }
        }

        Start-Sleep -Seconds 3
    }
}

# --- Monitor Failed Login Events (Event ID 4625) - Windows 2012 Compatible ---
function Start-LoginMonitoring {
    Write-Log -Message "Starting failed login monitoring (Windows 2012 compatible mode)..." -Level "INFO"
    
    # Check if Register-WinEvent is available
    $hasRegisterWinEvent = Get-Command "Register-WinEvent" -ErrorAction SilentlyContinue
    
    if ($hasRegisterWinEvent) {
        try {
            $LoginWatcher = Register-WinEvent -FilterHashtable @{
                LogName = 'Security'
                Id = 4625
            } -Action {
                $ip = ($Event.Properties[19].Value)
                $user = ($Event.Properties[5].Value)
                Write-Log -Level "ALERT" -Message "FAILED_LOGIN_ATTEMPT: User: $user | Source IP: $ip | Possible brute force attack"
            }
            Write-Log -Message "Failed login monitoring started successfully (Register-WinEvent)" -Level "INFO"
        } catch {
            Write-Log -Message "Failed to start Register-WinEvent login monitoring: $_" -Level "ERROR"
        }
    } else {
        # Fallback using WMI Event Query for Windows 2012
        Write-Log -Message "Register-WinEvent not available, using WMI fallback for Windows 2012" -Level "INFO"
        try {
            $query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.LogFile = 'Security' AND TargetInstance.EventCode = 4625"
            Register-WmiEvent -Query $query -Action {
                $logEntry = $Event.SourceEventArgs.NewEvent.TargetInstance
                $message = $logEntry.Message
                if ($message -match "Source Network Address:\s+(\S+)") {
                    $ip = $matches[1]
                    if ($message -match "Account Name:\s+(\S+)") {
                        $user = $matches[1]
                        Write-Log -Level "ALERT" -Message "FAILED_LOGIN_ATTEMPT: User: $user | Source IP: $ip | Possible brute force attack (WMI Detection)"
                    }
                }
            } | Out-Null
            Write-Log -Message "Failed login monitoring started successfully (WMI fallback)" -Level "INFO"
        } catch {
            Write-Log -Message "Failed to start WMI login monitoring: $_. Manual log checking will be used." -Level "WARNING"
        }
    }
}

# --- Monitor Honeyfile Access ---
function Start-HoneyfileMonitoring {
    Write-Log -Message "Setting up honeyfile monitoring..." -Level "INFO"
    
    if (-not (Test-Path $HoneyfileDir)) {
        New-Item -ItemType Directory -Path $HoneyfileDir -Force | Out-Null
        Set-Content -Path "$HoneyfileDir\Passwords.txt" -Value "admin:password123`nroot:toor`nservice:service123"
        Set-Content -Path "$HoneyfileDir\DatabaseConfig.txt" -Value "Server=localhost;Database=prod;User=sa;Password=admin123"
        Set-Content -Path "$HoneyfileDir\BackupCredentials.txt" -Value "BackupUser=backup_admin`nBackupPass=B@ckup2023"
        Write-Log -Message "Created honeyfiles in $HoneyfileDir" -Level "INFO"
    }

    try {
        $fsw = New-Object System.IO.FileSystemWatcher
        $fsw.Path = $HoneyfileDir
        $fsw.Filter = "*.*"
        $fsw.IncludeSubdirectories = $false
        $fsw.EnableRaisingEvents = $true

        Register-ObjectEvent $fsw Changed -Action {
            $filename = $Event.SourceEventArgs.FullPath
            $process = Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -eq $PID }
            Write-Log -Level "ALERT" -Message "HONEYFILE_ACCESS: Suspicious file access detected: $filename | Process: $($process.Name)"
        } | Out-Null

        Register-ObjectEvent $fsw Created -Action {
            $filename = $Event.SourceEventArgs.FullPath
            Write-Log -Level "ALERT" -Message "HONEYFILE_CREATION: New file created in honey directory: $filename"
        } | Out-Null

        Write-Log -Message "Honeyfile monitoring started successfully" -Level "INFO"
    } catch {
        Write-Log -Message "Failed to start honeyfile monitoring: $_" -Level "ERROR"
    }
}

# --- Monitor DNS Debug Log ---
function Start-DNSMonitoring {
    Write-Log -Message "Starting DNS reconnaissance monitoring..." -Level "INFO"
    
    if (-Not (Test-Path $DNSLogPath)) {
        Write-Log -Message "DNS log file not found at $DNSLogPath. Skipping DNS monitoring." -Level "WARNING"
        return
    }

    $lastSize = (Get-Item $DNSLogPath).Length
    while ($true) {
        try {
            $size = (Get-Item $DNSLogPath).Length
            if ($size -gt $lastSize) {
                $diff = $size - $lastSize
                $stream = New-Object IO.FileStream $DNSLogPath, 'Open', 'Read', 'ReadWrite'
                $stream.Seek($lastSize, 'Begin') | Out-Null
                $reader = New-Object IO.StreamReader $stream
                $newLines = $reader.ReadToEnd()
                $reader.Close(); $stream.Close()

                foreach ($line in $newLines -split "`n") {
                    if ($line -match "dev|internal|admin|test|staging|backup|mail|ftp|ssh|vpn|db|database") {
                        Write-Log -Level "ALERT" -Message "DNS_RECONNAISSANCE: Suspicious DNS query detected: $line"
                    }
                }
                $lastSize = $size
            }
        } catch {
            Write-Log -Message "Error monitoring DNS log: $_" -Level "ERROR"
        }
        Start-Sleep -Seconds 10
    }
}

# --- Monitor Web Root for File Creation ---
function Start-WebDirectoryMonitoring {
    Write-Log -Message "Starting web directory monitoring..." -Level "INFO"
    $sensitivePaths = @("C:\inetpub\wwwroot", "C:\xampp\htdocs", "C:\Program Files\Apache\htdocs")
    
    foreach ($sensitivePath in $sensitivePaths) {
        if (Test-Path $sensitivePath) {
            try {
                $watcher = New-Object System.IO.FileSystemWatcher
                $watcher.Path = $sensitivePath
                $watcher.IncludeSubdirectories = $true
                $watcher.EnableRaisingEvents = $true

                Register-ObjectEvent $watcher Created -Action {
                    Write-Log -Level "ALERT" -Message "WEB_ENUMERATION: New file created in web directory: $($Event.SourceEventArgs.FullPath)"
                } | Out-Null

                Write-Log -Message "Web directory monitoring started for: $sensitivePath" -Level "INFO"
            } catch {
                Write-Log -Message "Failed to monitor $sensitivePath`: $_" -Level "ERROR"
            }
        }
    }
}

# --- Monitor IIS Logs for Suspicious URL Access ---
function Start-IISLogMonitoring {
    Write-Log -Message "Starting IIS log monitoring..." -Level "INFO"
    $iisLogPath = "C:\inetpub\logs\LogFiles\W3SVC1"
    
    if (-Not (Test-Path $iisLogPath)) { 
        Write-Log -Message "IIS log directory not found. Skipping IIS monitoring." -Level "WARNING"
        return 
    }

    $lastTime = Get-Date
    while ($true) {
        try {
            $logs = Get-ChildItem -Path "$iisLogPath\u_ex*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($logs -and $logs.LastWriteTime -gt $lastTime) {
                $lastTime = $logs.LastWriteTime
                $lines = Get-Content $logs.FullName | Select-String -Pattern "/admin|/login|\.git|\.env|/phpmyadmin|/wp-admin|/config|/backup"
                foreach ($match in $lines) {
                    $fields = $match.Line -split " "
                    if ($fields.Count -gt 10) {
                        $ip = $fields[8]
                        $url = $fields[4]
                        Write-Log -Level "ALERT" -Message "WEB_RECONNAISSANCE: Suspicious URL accessed: $url | Source IP: $ip | User-Agent: $($fields[9])"
                    }
                }
            }
        } catch {
            Write-Log -Message "Error monitoring IIS logs: $_" -Level "ERROR"
        }
        Start-Sleep -Seconds 30
    }
}

# --- Manual Security Log Monitoring for Windows 2012 Fallback ---
function Start-ManualSecurityLogMonitoring {
    Write-Log -Message "Starting manual security log monitoring as fallback..." -Level "INFO"
    $lastEventTime = Get-Date
    
    while ($true) {
        try {
            # Check for recent failed login events (Event ID 4625)
            $failedLogins = Get-EventLog -LogName Security -After $lastEventTime -InstanceId 4625 -ErrorAction SilentlyContinue
            
            foreach ($event in $failedLogins) {
                $message = $event.Message
                $ip = "Unknown"
                $user = "Unknown"
                
                # Extract IP address from message
                if ($message -match "Source Network Address:\s+(\S+)") {
                    $ip = $matches[1]
                }
                
                # Extract username from message
                if ($message -match "Account Name:\s+(\S+)") {
                    $user = $matches[1]
                }
                
                Write-Log -Level "ALERT" -Message "FAILED_LOGIN_ATTEMPT: User: $user | Source IP: $ip | Time: $($event.TimeGenerated) | Manual Detection"
            }
            
            $lastEventTime = Get-Date
        } catch {
            Write-Log -Message "Error in manual security log monitoring: $_" -Level "ERROR"
        }
        
        Start-Sleep -Seconds 60  # Check every minute
    }
}

# --- Process Monitoring for Reconnaissance Tools ---
function Start-ProcessMonitoring {
    Write-Log -Message "Starting process monitoring for reconnaissance tools..." -Level "INFO"
    $suspiciousProcesses = @("nmap", "masscan", "zmap", "rustscan", "unicornscan", "hping", "netcat", "nc", "telnet", "ftp")
    
    while ($true) {
        try {
            $processes = Get-Process | Where-Object { $suspiciousProcesses -contains $_.ProcessName.ToLower() }
            foreach ($proc in $processes) {
                $commandLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
                Write-Log -Level "ALERT" -Message "RECON_TOOL_DETECTED: Suspicious process detected: $($proc.ProcessName) (PID: $($proc.Id)) | Command: $commandLine"
            }
        } catch {
            Write-Log -Message "Error monitoring processes: $_" -Level "ERROR"
        }
        Start-Sleep -Seconds 15
    }
}

# --- Network Interface Monitoring (Windows 2012 Compatible) ---
function Start-NetworkInterfaceMonitoring {
    Write-Log -Message "Starting network interface monitoring (Windows 2012 compatible)..." -Level "INFO"
    $lastStats = @{}
    
    while ($true) {
        try {
            if ($hasNetTCPConnection) {
                # Try modern approach first
                try {
                    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
                    
                    foreach ($adapter in $adapters) {
                        $adapterName = $adapter.Name
                        $stats = Get-NetAdapterStatistics -Name $adapterName -ErrorAction SilentlyContinue
                        if ($stats) {
                            $currentPackets = $stats.ReceivedPackets + $stats.SentPackets
                            if ($lastStats.ContainsKey($adapterName)) {
                                $packetDiff = $currentPackets - $lastStats[$adapterName]
                                if ($packetDiff -gt 10000) {  # High packet rate threshold
                                    Write-Log -Level "ALERT" -Message "HIGH_NETWORK_ACTIVITY: Unusual network activity on $adapterName`: $packetDiff packets in 30 seconds"
                                }
                            }
                            $lastStats[$adapterName] = $currentPackets
                        }
                    }
                } catch {
                    # Fall through to WMI approach
                    throw $_
                }
            } else {
                throw "Using WMI fallback"
            }
        } catch {
            # Fallback for Windows 2012 using WMI and Performance Counters
            try {
                $adapters = Get-WmiObject -Class Win32_PerfRawData_Tcpip_NetworkInterface | Where-Object { $_.Name -notlike "*Loopback*" -and $_.Name -ne "_Total" }
                
                foreach ($adapter in $adapters) {
                    $adapterName = $adapter.Name
                    $currentPackets = [int64]$adapter.PacketsReceivedPerSec + [int64]$adapter.PacketsSentPerSec
                    
                    if ($lastStats.ContainsKey($adapterName)) {
                        $packetDiff = $currentPackets - $lastStats[$adapterName]
                        if ($packetDiff -gt 5000) {  # Lower threshold for WMI counters
                            Write-Log -Level "ALERT" -Message "HIGH_NETWORK_ACTIVITY: Unusual network activity on $adapterName`: $packetDiff packet counter increase (WMI Detection)"
                        }
                    }
                    $lastStats[$adapterName] = $currentPackets
                }
            } catch {
                Write-Log -Message "Error monitoring network interfaces (both methods failed): $_" -Level "ERROR"
            }
        }
        Start-Sleep -Seconds 30
    }
}

# --- Main Script Execution ---
Write-Host "=== Unified Reconnaissance Detection System ===" -ForegroundColor Cyan
Write-Host "Windows Server 2012 Compatible Version" -ForegroundColor Green
Write-Host "Log File: $LogFile" -ForegroundColor Yellow
Write-Host "Remote Endpoint: $RemoteLogEndpoint" -ForegroundColor Yellow

Write-Log -Message "Unified Reconnaissance Detection System started." -Level "INFO"

# Initialize monitoring components
Start-LoginMonitoring
Start-HoneyfileMonitoring
Start-WebDirectoryMonitoring

# Start background monitoring jobs
$jobs = @()
$jobs += Start-Job -ScriptBlock ${function:Start-DNSMonitoring}
$jobs += Start-Job -ScriptBlock ${function:Start-IISLogMonitoring}
$jobs += Start-Job -ScriptBlock ${function:Start-ProcessMonitoring}
$jobs += Start-Job -ScriptBlock ${function:Start-NetworkInterfaceMonitoring}

# Add manual security log monitoring as fallback
$jobs += Start-Job -ScriptBlock ${function:Start-ManualSecurityLogMonitoring}

Write-Log -Message "Background monitoring jobs started: $($jobs.Count) jobs running" -Level "INFO"

# Start main port scan monitoring (foreground)
Write-Host "`nStarting main port scan detection engine..." -ForegroundColor Green
Write-Log -Message "Main port scan detection engine starting..." -Level "INFO"

try {
    Start-PortScanMonitoring
} catch {
    Write-Log -Message "Critical error in main monitoring loop: $_" -Level "ERROR"
    Write-Host "Critical error occurred. Check log file for details." -ForegroundColor Red
} finally {
    # Cleanup jobs on exit
    Write-Log -Message "Shutting down monitoring system..." -Level "INFO"
    $jobs | Stop-Job
    $jobs | Remove-Job
}
