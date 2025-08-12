# =======================
# Configurable CSV paths
# =======================
$fullLogFile     = "C:\Logs\full_traffic_log.csv"
$detectionLogFile = "C:\Logs\detections_log.csv"

# =======================
# Ensure CSV headers exist
# =======================
if (-not (Test-Path $fullLogFile)) {
    "Time,Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,ProcessName" | Out-File -FilePath $fullLogFile -Encoding utf8
}
if (-not (Test-Path $detectionLogFile)) {
    "Time,ProtocolType,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,ProcessName" | Out-File -FilePath $detectionLogFile -Encoding utf8
}

# =======================
# Function: Write-LogRow
# =======================
function Write-LogRow($filePath, $row) {
    Add-Content -Path $filePath -Value $row
}

# =======================
# Detect Get-NetTCPConnection availability
# =======================
$hasNetTCPConnection = Get-Command "Get-NetTCPConnection" -ErrorAction SilentlyContinue
if (-not $hasNetTCPConnection) {
    Write-Host "Get-NetTCPConnection not available. Using netstat fallback." -ForegroundColor Yellow
}

# =======================
# Protocol mapping for detection
# =======================
$protocolPorts = @{
    "HTTP"     = 80,8080
    "HTTPS"    = 443
    "DNS"      = 53
    "SMTP"     = 25
    "SNMP"     = 161
    "FTP"      = 20,21
    "SSH"      = 22
    "LDAP"     = 389
    "SMB"      = 445
    "Modbus"   = 502
    "DNP3"     = 20000
    "BACnet"   = 47808
    "EtherNet/IP" = 44818
    "Profinet/Profibus" = 34964
    "S7Comm"   = 102
}

# =======================
# Data aggregation arrays
# =======================
$detectionsBuffer = @()
$fullLogsBuffer   = @()

# =======================
# Get connection data
# =======================
if ($hasNetTCPConnection) {
    $connections = Get-NetTCPConnection | ForEach-Object {
        $procName = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        [PSCustomObject]@{
            Time          = (Get-Date).ToString("o")
            Protocol      = "TCP"
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = $_.State
            ProcessName   = $procName
        }
    }
} else {
    $connections = netstat -ano | Select-String "TCP|UDP" | ForEach-Object {
        $parts = $_ -split "\s+"
        if ($parts[1] -match "TCP|UDP") {
            $proto = $parts[1]
            $local = $parts[2] -split ":"
            $remote = $parts[3] -split ":"
            [PSCustomObject]@{
                Time          = (Get-Date).ToString("o")
                Protocol      = $proto
                LocalAddress  = $local[0]
                LocalPort     = $local[1]
                RemoteAddress = $remote[0]
                RemotePort    = $remote[1]
                State         = if ($proto -eq "TCP") { $parts[4] } else { "N/A" }
                ProcessName   = try { (Get-Process -Id $parts[-1] -ErrorAction SilentlyContinue).ProcessName } catch { "Unknown" }
            }
        }
    }
}

# =======================
# Classify and store
# =======================
foreach ($conn in $connections) {
    # Always log full traffic
    $fullLogsBuffer += "$($conn.Time),$($conn.Protocol),$($conn.LocalAddress),$($conn.LocalPort),$($conn.RemoteAddress),$($conn.RemotePort),$($conn.State),$($conn.ProcessName)"

    # Detect specific protocols
    foreach ($proto in $protocolPorts.Keys) {
        if ($protocolPorts[$proto] -contains [int]$conn.LocalPort -or $protocolPorts[$proto] -contains [int]$conn.RemotePort) {
            $detectionsBuffer += "$($conn.Time),$proto,$($conn.LocalAddress),$($conn.LocalPort),$($conn.RemoteAddress),$($conn.RemotePort),$($conn.State),$($conn.ProcessName)"
        }
    }
}

# =======================
# Write aggregated logs to files
# =======================
if ($fullLogsBuffer.Count -gt 0) { $fullLogsBuffer   | ForEach-Object { Write-LogRow $fullLogFile $_ } }
if ($detectionsBuffer.Count -gt 0) { $detectionsBuffer | ForEach-Object { Write-LogRow $detectionLogFile $_ } }
