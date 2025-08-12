#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Initial Access Tactics Logger using Sysmon and Windows Event Logs - Windows Server 2012 Compatible
.DESCRIPTION
    Monitors and logs Initial Access techniques using Sysmon events and Windows Security logs
    Compatible with PowerShell 3.0+ and Windows Server 2012
.PARAMETER OutputPath
    Path where log files will be stored
.PARAMETER LogLevel
    Logging level (Info, Warning, Critical)
.PARAMETER MonitorDuration
    Duration in minutes to monitor (0 = continuous)
.PARAMETER RefreshInterval
    Interval in seconds between monitoring checks (default: 30)
#>

param(
    [string]$OutputPath = "$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS",
    [ValidateSet("Info", "Warning", "Critical")]
    [string]$LogLevel = "Info",
    [int]$MonitorDuration = 0,
    [int]$RefreshInterval = 30
)

# Global variables
$Script:LogFile = ""
$Script:StartTime = Get-Date
$Script:EventCounters = @{}
$Script:LastEventTime = Get-Date

# Initialize logging
function Initialize-Logger {
    param([string]$Path)
    
    if (!(Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:LogFile = Join-Path $Path "InitialAccess_$timestamp.log"
    
    # Write initial log header without verbose console output
    $headerInfo = @"
=== Initial Access Logger Started ===
Start Time: $(Get-Date)
PowerShell Version: $($PSVersionTable.PSVersion)
OS: $((Get-WmiObject Win32_OperatingSystem).Caption)
Log File: $Script:LogFile
=====================================
"@
    Add-Content -Path $Script:LogFile -Value $headerInfo
}

# Write log entries - Windows Server 2012 compatible with enhanced field support
function Write-LogEntry {
    param(
        [string]$Level,
        [string]$Message,
        [string]$EventID = "",
        [string]$ProcessName = "",
        [string]$CommandLine = "",
        [string]$Technique = "",
        [string]$TargetFilename = "",
        [string]$ProcessId = "",
        [string]$User = "",
        [string]$ProcessGuid = "",
        [string]$Hashes = "",
        [string]$AdditionalFields = ""
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if ($EventID) { $logEntry += " | EventID: $EventID" }
    if ($ProcessName) { $logEntry += " | Process: $ProcessName" }
    if ($ProcessId) { $logEntry += " | PID: $ProcessId" }
    if ($User) { $logEntry += " | User: $User" }
    if ($CommandLine) { $logEntry += " | CommandLine: $CommandLine" }
    if ($TargetFilename) { $logEntry += " | TargetFile: $TargetFilename" }
    if ($ProcessGuid) { $logEntry += " | GUID: $ProcessGuid" }
    if ($Hashes) { $logEntry += " | Hashes: $Hashes" }
    if ($Technique) { $logEntry += " | Technique: $Technique" }
    if ($AdditionalFields) { $logEntry += " | Additional: $AdditionalFields" }
    
    # Write to console based on log level setting
    if ($Level -eq "CRITICAL" -or ($Level -eq "WARNING" -and $LogLevel -in @("Info", "Warning")) -or $LogLevel -eq "Info") {
        switch ($Level) {
            "CRITICAL" { Write-Host $logEntry -ForegroundColor Red }
            "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
            default { Write-Host $logEntry -ForegroundColor Green }
        }
    }
    
    # Write to file
    Add-Content -Path $Script:LogFile -Value $logEntry
    
    # Update counters - PowerShell 3.0 compatible
    if ($Technique) {
        if ($Script:EventCounters.ContainsKey($Technique)) {
            $Script:EventCounters[$Technique] = $Script:EventCounters[$Technique] + 1
        } else {
            $Script:EventCounters[$Technique] = 1
        }
    }
    
    $Script:LastEventTime = Get-Date
}

# Check if Sysmon is available
function Test-SysmonAvailable {
    try {
        $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
        if ($sysmonService -and $sysmonService.Status -eq "Running") {
            return $true
        }
        
        # Test if we can query Sysmon log
        $null = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Get events with error handling for Windows Server 2012
function Get-EventsSecure {
    param(
        [string]$LogName,
        [hashtable]$FilterHashtable = @{},
        [int]$MaxEvents = 50
    )
    
    try {
        # Windows Server 2012 compatible event filtering
        if ($FilterHashtable.Count -gt 0) {
            return Get-WinEvent -FilterHashtable $FilterHashtable -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        } else {
            return Get-WinEvent -LogName $LogName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        }
    } catch {
        Write-LogEntry "WARNING" "Failed to retrieve events from $LogName : $($_.Exception.Message)"
        return @()
    }
}

# Parse event data - Windows Server 2012 compatible
function Get-EventData {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)
    
    try {
        $eventXML = [xml]$Event.ToXml()
        $eventData = @{}
        
        # Extract data fields
        if ($eventXML.Event.EventData.Data) {
            foreach ($data in $eventXML.Event.EventData.Data) {
                if ($data.Name) {
                    $eventData[$data.Name] = $data.'#text'
                }
            }
        }
        
        return $eventData
    } catch {
        return @{}
    }
}

# Monitor Initial Access - T1566 Spearphishing Attachment
function Monitor-SpearphishingAttachment {
    param([array]$Events)
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $image = $eventData["Image"]
        $commandLine = $eventData["CommandLine"]
        $parentImage = $eventData["ParentImage"]
        $processId = $eventData["ProcessId"]
        $user = $eventData["User"]
        $processGuid = $eventData["ProcessGuid"]
        $hashes = $eventData["Hashes"]
        
        # Detect script execution from email clients
        if ($parentImage -match "outlook\.exe|thunderbird\.exe|mailbird\.exe") {
            if ($image -match "powershell\.exe|wscript\.exe|cscript\.exe|cmd\.exe") {
                Write-LogEntry "CRITICAL" "Spearphishing attachment detected: Email client spawned script interpreter" `
                    -EventID "1" -ProcessName $image -CommandLine $commandLine -Technique "T1566.001" `
                    -ProcessId $processId -User $user -ProcessGuid $processGuid -Hashes $hashes `
                    -AdditionalFields "Parent: $parentImage"
            }
        }
        
        # Detect Office macro execution
        if ($parentImage -match "winword\.exe|excel\.exe|powerpnt\.exe") {
            if ($image -match "powershell\.exe|wscript\.exe|cscript\.exe|cmd\.exe|dllhost\.exe") {
                Write-LogEntry "CRITICAL" "Office macro execution detected" `
                    -EventID "1" -ProcessName $image -CommandLine $commandLine -Technique "T1566.001" `
                    -ProcessId $processId -User $user -ProcessGuid $processGuid -Hashes $hashes `
                    -AdditionalFields "Office App: $parentImage"
            }
        }
    }
}

# Monitor Initial Access - T1189 Drive-by Compromise
function Monitor-DriveByCompromise {
    param([array]$Events)
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $image = $eventData["Image"]
        $commandLine = $eventData["CommandLine"]
        $parentImage = $eventData["ParentImage"]
        $processId = $eventData["ProcessId"]
        $user = $eventData["User"]
        
        # Detect suspicious process spawning from browsers
        if ($parentImage -match "chrome\.exe|firefox\.exe|msedge\.exe|iexplore\.exe") {
            if ($image -match "powershell\.exe|wscript\.exe|cscript\.exe|cmd\.exe") {
                Write-LogEntry "CRITICAL" "Drive-by compromise detected: Browser spawned script interpreter" `
                    -EventID "1" -ProcessName $image -CommandLine $commandLine -Technique "T1189" `
                    -ProcessId $processId -User $user -AdditionalFields "Browser: $parentImage"
            }
        }
    }
}

# Monitor Initial Access - T1190 Exploit Public-Facing Application
function Monitor-ExploitPublicApplication {
    param([array]$Events)
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $image = $eventData["Image"]
        $commandLine = $eventData["CommandLine"]
        $parentImage = $eventData["ParentImage"]
        $processId = $eventData["ProcessId"]
        
        # Detect web server spawning suspicious processes
        if ($parentImage -match "w3wp\.exe|httpd\.exe|nginx\.exe|apache\.exe|iisexpress\.exe") {
            if ($image -match "powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe") {
                Write-LogEntry "CRITICAL" "Web server exploit detected: Web server spawned system process" `
                    -EventID "1" -ProcessName $image -CommandLine $commandLine -Technique "T1190" `
                    -ProcessId $processId -AdditionalFields "WebServer: $parentImage"
            }
        }
    }
}

# Monitor Initial Access - T1133 External Remote Services
function Monitor-ExternalRemoteServices {
    param([array]$SecurityEvents)
    
    foreach ($event in $SecurityEvents) {
        $eventData = Get-EventData -Event $event
        
        # Monitor RDP logons (Event ID 4624, Logon Type 10)
        if ($event.Id -eq 4624) {
            $logonType = $eventData["LogonType"]
            $targetUserName = $eventData["TargetUserName"]
            $ipAddress = $eventData["IpAddress"]
            $workstationName = $eventData["WorkstationName"]
            
            if ($logonType -eq "10") { # RDP logon
                # Check for external IP addresses (not private ranges)
                if ($ipAddress -and $ipAddress -notmatch "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\.|^169\.254\.") {
                    Write-LogEntry "WARNING" "External RDP logon detected" `
                        -EventID "4624" -User $targetUserName -Technique "T1133" `
                        -AdditionalFields "SourceIP: $ipAddress, Workstation: $workstationName, LogonType: RDP"
                }
            }
        }
        
        # Monitor failed RDP attempts (Event ID 4625)
        if ($event.Id -eq 4625) {
            $targetUserName = $eventData["TargetUserName"]
            $ipAddress = $eventData["IpAddress"]
            $failureReason = $eventData["FailureReason"]
            
            if ($ipAddress -and $ipAddress -notmatch "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\.|^169\.254\.") {
                Write-LogEntry "INFO" "Failed external logon attempt" `
                    -EventID "4625" -User $targetUserName -Technique "T1133" `
                    -AdditionalFields "SourceIP: $ipAddress, Reason: $failureReason"
            }
        }
    }
}

# Monitor Initial Access - T1078 Valid Accounts
function Monitor-ValidAccounts {
    param([array]$SecurityEvents)
    
    foreach ($event in $SecurityEvents) {
        if ($event.Id -eq 4624) {
            $eventData = Get-EventData -Event $event
            $targetUserName = $eventData["TargetUserName"]
            $logonType = $eventData["LogonType"]
            $ipAddress = $eventData["IpAddress"]
            
            # Monitor for unusual logon times or patterns
            $currentHour = (Get-Date).Hour
            if ($currentHour -lt 6 -or $currentHour -gt 22) {
                if ($logonType -in @("2", "3", "10")) { # Interactive, Network, RDP
                    Write-LogEntry "WARNING" "Off-hours logon detected" `
                        -EventID "4624" -User $targetUserName -Technique "T1078" `
                        -AdditionalFields "LogonType: $logonType, Time: $(Get-Date), SourceIP: $ipAddress"
                }
            }
        }
    }
}

# Monitor file creation for dropped payloads
function Monitor-FileCreation {
    param([array]$Events)
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $targetFilename = $eventData["TargetFilename"]
        $image = $eventData["Image"]
        $processId = $eventData["ProcessId"]
        
        # Monitor executable files created in temp directories
        if ($targetFilename -match "\\Temp\\.*\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js)$") {
            Write-LogEntry "WARNING" "Suspicious file created in temp directory" `
                -EventID "11" -ProcessName $image -TargetFilename $targetFilename -Technique "T1566.001" `
                -ProcessId $processId
        }
        
        # Monitor files with double extensions
        if ($targetFilename -match "\.(pdf|doc|docx|xls|xlsx|ppt|pptx)\.(exe|scr|com|bat|cmd|ps1|vbs)$") {
            Write-LogEntry "CRITICAL" "File with double extension detected" `
                -EventID "11" -ProcessName $image -TargetFilename $targetFilename -Technique "T1566.001" `
                -ProcessId $processId
        }
    }
}

# Print summary statistics
function Show-Summary {
    Write-Host "`n=== Initial Access Monitoring Summary ===" -ForegroundColor Cyan
    Write-Host "Monitoring Duration: $([math]::Round(((Get-Date) - $Script:StartTime).TotalMinutes, 2)) minutes" -ForegroundColor White
    Write-Host "Last Event Time: $($Script:LastEventTime)" -ForegroundColor White
    Write-Host "Log File: $Script:LogFile" -ForegroundColor White
    
    if ($Script:EventCounters.Count -gt 0) {
        Write-Host "`nDetected Techniques:" -ForegroundColor Yellow
        foreach ($technique in $Script:EventCounters.Keys | Sort-Object) {
            Write-Host "  $technique : $($Script:EventCounters[$technique]) events" -ForegroundColor White
        }
    } else {
        Write-Host "`nNo suspicious activities detected." -ForegroundColor Green
    }
    Write-Host "==========================================`n" -ForegroundColor Cyan
}

# Main monitoring function
function Start-InitialAccessMonitoring {
    Initialize-Logger -Path $OutputPath
    Write-LogEntry "INFO" "Initial Access monitoring started"
    
    $sysmonAvailable = Test-SysmonAvailable
    Write-LogEntry "INFO" "Sysmon available: $sysmonAvailable"
    
    Write-Host "Initial Access Live Monitor v1.0 (Server 2012 Compatible)" -ForegroundColor Cyan
    Write-Host "Sysmon Available: $sysmonAvailable" -ForegroundColor $(if ($sysmonAvailable) { "Green" } else { "Yellow" })
    Write-Host "Press Ctrl+C to stop monitoring`n" -ForegroundColor Gray
    
    $endTime = if ($MonitorDuration -gt 0) { (Get-Date).AddMinutes($MonitorDuration) } else { [DateTime]::MaxValue }
    
    try {
        while ((Get-Date) -lt $endTime) {
            try {
                # Monitor Sysmon events if available
                if ($sysmonAvailable) {
                    # Process Creation (Event ID 1)
                    $processEvents = Get-EventsSecure -FilterHashtable @{
                        LogName = "Microsoft-Windows-Sysmon/Operational"
                        ID = 1
                        StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                    } -MaxEvents 100
                    
                    if ($processEvents) {
                        Monitor-SpearphishingAttachment -Events $processEvents
                        Monitor-DriveByCompromise -Events $processEvents
                        Monitor-ExploitPublicApplication -Events $processEvents
                    }
                    
                    # File Creation (Event ID 11)
                    $fileEvents = Get-EventsSecure -FilterHashtable @{
                        LogName = "Microsoft-Windows-Sysmon/Operational"
                        ID = 11
                        StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                    } -MaxEvents 100
                    
                    if ($fileEvents) {
                        Monitor-FileCreation -Events $fileEvents
                    }
                }
                
                # Monitor Security events
                $securityEvents = Get-EventsSecure -FilterHashtable @{
                    LogName = "Security"
                    ID = @(4624, 4625)
                    StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                } -MaxEvents 100
                
                if ($securityEvents) {
                    Monitor-ExternalRemoteServices -SecurityEvents $securityEvents
                    Monitor-ValidAccounts -SecurityEvents $securityEvents
                }
                
            } catch {
                Write-LogEntry "WARNING" "Error in monitoring cycle: $($_.Exception.Message)"
            }
            
            Start-Sleep -Seconds $RefreshInterval
        }
    } catch {
        Write-LogEntry "CRITICAL" "Monitoring stopped due to error: $($_.Exception.Message)"
    }
    
    Show-Summary
    Write-LogEntry "INFO" "Initial Access monitoring stopped"
}

# Handle Ctrl+C gracefully
$null = Register-ObjectEvent -InputObject ([Console]) -EventName "CancelKeyPress" -Action {
    Write-Host "`n`nStopping Initial Access monitoring..." -ForegroundColor Yellow
    Show-Summary
    Write-LogEntry "INFO" "Initial Access monitoring stopped by user"
    exit
}

# Start monitoring
Start-InitialAccessMonitoring
