#Requires -RunAsAdministrator

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
            $jsonBody = @{
                timestamp = $timestamp
                level = $Level
                message = $Message
            } | ConvertTo-Json
            Invoke-RestMethod -Uri $remoteLogEndpoint -Method POST -Body $jsonBody -ContentType "application/json" -TimeoutSec 5
        }
        catch {
            Write-Host "Warning: Failed to send log to FastAPI server: $_" -ForegroundColor Yellow
        }
    }
}

# --- Initialization ---
$ipTracker = @{}
Write-Host "Starting Reconnaissance Scan Detector. Logs at $logFile"
Write-Log -Message "Scan detector service started."

# --- Main Loop ---
while ($true) {
    $connections = Get-NetTCPConnection -State SynSent, TimeWait -ErrorAction SilentlyContinue

    foreach ($conn in $connections) {
        $remoteIP = $conn.RemoteAddress
        if ($remoteIP -eq "127.0.0.1" -or $remoteIP -eq "::1") { continue }

        if (-not $ipTracker.ContainsKey($remoteIP)) {
            $ipTracker[$remoteIP] = @{
                Ports     = [System.Collections.Generic.HashSet[int]]::new()
                FirstSeen = (Get-Date)
            }
        }
        $ipTracker[$remoteIP].Ports.Add($conn.RemotePort) | Out-Null
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
