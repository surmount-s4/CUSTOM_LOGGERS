# Windows Recon Attack Monitor
# Basic version - monitors for common reconnaissance activities

param(
    [int]$MonitorDurationMinutes = 60,
    [int]$PortScanThreshold = 10,
    [int]$FailedLoginThreshold = 5,
    [string]$LogFile = "C:\Temp\ReconMonitor.log"
)

# Function to write logs
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $(if($Level -eq "ALERT") {"Red"} elseif($Level -eq "WARN") {"Yellow"} else {"Green"})
    Add-Content -Path $LogFile -Value $logEntry
}

# Function to monitor failed login attempts
function Monitor-FailedLogins {
    Write-Log "Monitoring failed login attempts..."
    
    $startTime = (Get-Date).AddMinutes(-5)
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4625  # Failed logon
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    if ($events) {
        $failedLogins = $events | Group-Object {$_.Properties[19].Value} | 
                       Where-Object {$_.Count -ge $FailedLoginThreshold}
        
        foreach ($login in $failedLogins) {
            $sourceIP = $login.Name
            $attempts = $login.Count
            Write-Log "POTENTIAL BRUTE FORCE: $attempts failed login attempts from $sourceIP" "ALERT"
        }
    }
}

# Function to monitor network connections for suspicious activity
function Monitor-NetworkConnections {
    Write-Log "Monitoring network connections..."
    
    $connections = Get-NetTCPConnection -State Listen
    $suspiciousPorts = @()
    
    # Check for uncommon listening ports
    $commonPorts = @(80, 443, 135, 139, 445, 3389, 5985, 5986)
    
    foreach ($conn in $connections) {
        if ($conn.LocalPort -notin $commonPorts -and $conn.LocalPort -lt 1024) {
            $suspiciousPorts += $conn.LocalPort
        }
    }
    
    if ($suspiciousPorts.Count -gt 0) {
        Write-Log "SUSPICIOUS LISTENING PORTS detected: $($suspiciousPorts -join ', ')" "WARN"
    }
    
    # Monitor for multiple connections from same external IP
    $externalConnections = Get-NetTCPConnection -State Established | 
                          Where-Object {$_.RemoteAddress -notmatch "^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"} |
                          Group-Object RemoteAddress | 
                          Where-Object {$_.Count -ge $PortScanThreshold}
    
    foreach ($conn in $externalConnections) {
        $remoteIP = $conn.Name
        $connectionCount = $conn.Count
        Write-Log "POTENTIAL PORT SCAN: $connectionCount connections from external IP $remoteIP" "ALERT"
    }
}

# Function to monitor for reconnaissance tools
function Monitor-ReconProcesses {
    Write-Log "Monitoring for reconnaissance tools..."
    
    $reconTools = @("nmap", "masscan", "zmap", "nessus", "openvas", "nikto", "dirb", "gobuster", "wfuzz")
    $runningProcesses = Get-Process | Select-Object -ExpandProperty ProcessName
    
    foreach ($tool in $reconTools) {
        if ($runningProcesses -contains $tool) {
            Write-Log "RECON TOOL DETECTED: $tool is running on the system" "ALERT"
        }
    }
}

# Function to monitor Windows Event Logs for suspicious activities
function Monitor-SecurityEvents {
    Write-Log "Monitoring security events..."
    
    $startTime = (Get-Date).AddMinutes(-5)
    
    # Monitor for account enumeration (Event ID 4798)
    $enumEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4798
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    if ($enumEvents -and $enumEvents.Count -ge 5) {
        Write-Log "ACCOUNT ENUMERATION: Multiple account enumeration attempts detected ($($enumEvents.Count) events)" "ALERT"
    }
    
    # Monitor for privilege escalation attempts (Event ID 4672)
    $privEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4672
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    if ($privEvents) {
        $suspiciousPriv = $privEvents | Group-Object {$_.Properties[1].Value} |
                         Where-Object {$_.Count -ge 3}
        
        foreach ($priv in $suspiciousPriv) {
            $account = $priv.Name
            $attempts = $priv.Count
            Write-Log "PRIVILEGE ESCALATION: Multiple privilege use attempts by $account ($attempts times)" "WARN"
        }
    }
}

# Main monitoring loop
Write-Log "Starting Windows Recon Attack Monitor"
Write-Log "Monitor Duration: $MonitorDurationMinutes minutes"
Write-Log "Port Scan Threshold: $PortScanThreshold connections"
Write-Log "Failed Login Threshold: $FailedLoginThreshold attempts"
Write-Log "Log File: $LogFile"

$endTime = (Get-Date).AddMinutes($MonitorDurationMinutes)

try {
    while ((Get-Date) -lt $endTime) {
        Write-Log "Running monitoring cycle..."
        
        # Run all monitoring functions
        Monitor-FailedLogins
        Monitor-NetworkConnections
        Monitor-ReconProcesses
        Monitor-SecurityEvents
        
        Write-Log "Monitoring cycle complete. Waiting 30 seconds..."
        Start-Sleep -Seconds 30
    }
}
catch {
    Write-Log "Error occurred: $($_.Exception.Message)" "ERROR"
}
finally {
    Write-Log "Windows Recon Attack Monitor stopped"
}

Write-Host "`nMonitoring completed. Check log file at: $LogFile" -ForegroundColor Cyan
