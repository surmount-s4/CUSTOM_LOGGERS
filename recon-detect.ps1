#Requires -RunAsAdministrator

# PowerShell version compatibility check for Windows Server 2012
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Error "This script requires PowerShell 3.0 or later. Current version: $($PSVersionTable.PSVersion)"
    exit 1
}

# --- Configuration ---
$PortScanThreshold = 20
$TimeWindowSeconds = 120
$logFile = "C:\ProgramData\CustomSecurityLogs\recon_detector.log"
$remoteLogEndpoint = "http://192.168.127.139:8000/logs"

# Ensure log directory exists
$logDir = Split-Path $logFile
if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# --- Helper Function for Logging ---
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] - $Level - $Message"
    $logEntry | Out-File -FilePath $logFile -Append

    # Send ALERT logs to FastAPI server
    if ($Level -eq "ALERT") {
        try {
            # Windows 2012 compatible JSON creation
            $jsonBody = "{`"timestamp`":`"$timestamp`",`"level`":`"$Level`",`"message`":`"$($Message -replace '\"', '\\\"')`"}"
            Invoke-RestMethod -Uri $remoteLogEndpoint -Method POST -Body $jsonBody -ContentType "application/json" -TimeoutSec 5
        }
        catch {
            Write-Host "Warning: Failed to send log to FastAPI server: $_" -ForegroundColor Yellow
        }
    }
}

# --- Compatibility Check ---
$hasNetTCPConnection = Get-Command "Get-NetTCPConnection" -ErrorAction SilentlyContinue
if (-not $hasNetTCPConnection) {
    Write-Log -Message "Get-NetTCPConnection not available. Using netstat fallback for Windows 2012 compatibility." -Level "INFO"
}

# --- Initialization ---
$ipTracker = @{}
Write-Host "Starting Reconnaissance Scan Detector. Logs at $logFile"
Write-Log -Message "Scan detector service started."

# --- Main Loop ---
while ($true) {
    if ($hasNetTCPConnection) {
        # Modern approach using Get-NetTCPConnection
        $connections = Get-NetTCPConnection -State SynSent, TimeWait -ErrorAction SilentlyContinue
        
        foreach ($conn in $connections) {
            $remoteIP = $conn.RemoteAddress
            if ($remoteIP -eq "127.0.0.1" -or $remoteIP -eq "::1") { continue }

            if (-not $ipTracker.ContainsKey($remoteIP)) {
                $ipTracker[$remoteIP] = @{
                    Ports     = @()
                    FirstSeen = (Get-Date)
                }
            }
            
            # Add port if not already present (Windows 2012 compatible array handling)
            if ($ipTracker[$remoteIP].Ports -notcontains $conn.RemotePort) {
                $ipTracker[$remoteIP].Ports += $conn.RemotePort
            }
        }
    } else {
        # Fallback approach using netstat for Windows 2012 compatibility
        $netstatOutput = netstat -an | Where-Object { $_ -match "TCP.*SYN_SENT|TCP.*TIME_WAIT" }
        
        foreach ($line in $netstatOutput) {
            if ($line -match "TCP\s+\S+:(\d+)\s+(\S+):(\d+)\s+") {
                $remoteIP = $matches[2]
                $remotePort = [int]$matches[3]
                
                if ($remoteIP -eq "127.0.0.1" -or $remoteIP -eq "::1") { continue }

                if (-not $ipTracker.ContainsKey($remoteIP)) {
                    $ipTracker[$remoteIP] = @{
                        Ports     = @()
                        FirstSeen = (Get-Date)
                    }
                }
                
                # Add port if not already present
                if ($ipTracker[$remoteIP].Ports -notcontains $remotePort) {
                    $ipTracker[$remoteIP].Ports += $remotePort
                }
            }
        }
    }

    foreach ($ip in ($ipTracker.Keys | ForEach-Object { $_ })) {
        $timeDiff = (Get-Date) - $ipTracker[$ip].FirstSeen
        if ($timeDiff.TotalSeconds -gt $TimeWindowSeconds) {
            $ipTracker.Remove($ip)
            continue
        }

        $portCount = $ipTracker[$ip].Ports.Count
        if ($portCount -gt $PortScanThreshold) {
            $scannedPorts = $ipTracker[$ip].Ports | Sort-Object
            $alertMessage = "Potential network scan detected from source IP: $ip. Attempted to connect to $portCount unique ports. Ports: $($scannedPorts -join ',')."
            Write-Log -Message $alertMessage -Level "ALERT"
            Write-Host "`nALERT: Scan detected from $($ip)! See local log or FastAPI server." -ForegroundColor Red
            $ipTracker.Remove($ip)
        }
    }

    Start-Sleep -Seconds 5
}
