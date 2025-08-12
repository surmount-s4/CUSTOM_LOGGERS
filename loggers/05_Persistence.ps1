#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Persistence Tactics Logger using Sysmon and Windows Event Logs - Windows Server 2012 Compatible
.DESCRIPTION
    Monitors and logs Persistence techniques using Sysmon events and Windows Security logs
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
    $Script:LogFile = Join-Path $Path "Persistence_$timestamp.log"
    
    # Write initial log header without verbose console output
    $headerInfo = @"
=== Persistence Logger Started ===
Start Time: $(Get-Date)
PowerShell Version: $($PSVersionTable.PSVersion)
OS: $((Get-WmiObject Win32_OperatingSystem).Caption)
Log File: $Script:LogFile
==================================
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

# Monitor Persistence - T1547 Boot or Logon Autostart Execution
function Monitor-AutostartExecution {
    param([array]$RegistryEvents)
    
    $autostartKeys = @(
        "CurrentVersion\\Run",
        "CurrentVersion\\RunOnce",
        "CurrentVersion\\RunServices",
        "CurrentVersion\\RunServicesOnce",
        "CurrentVersion\\Windows\\Load",
        "CurrentVersion\\Windows\\Run",
        "CurrentVersion\\Winlogon",
        "Policies\\Explorer\\Run"
    )
    
    foreach ($event in $RegistryEvents) {
        $eventData = Get-EventData -Event $event
        $targetObject = $eventData["TargetObject"]
        $processName = $eventData["Image"]
        $processId = $eventData["ProcessId"]
        $details = $eventData["Details"]
        
        foreach ($key in $autostartKeys) {
            if ($targetObject -match $key) {
                Write-LogEntry "WARNING" "Autostart registry key modified" `
                    -EventID $event.Id -ProcessName $processName -Technique "T1547" `
                    -ProcessId $processId -AdditionalFields "RegistryKey: $targetObject, Value: $details"
            }
        }
    }
}

# Monitor Persistence - T1053 Scheduled Tasks
function Monitor-ScheduledTasks {
    param([array]$SecurityEvents, [array]$RegistryEvents)
    
    # Monitor Security Event 4698 (Scheduled task created)
    foreach ($event in $SecurityEvents) {
        if ($event.Id -eq 4698) {
            $eventData = Get-EventData -Event $event
            $taskName = $eventData["TaskName"]
            $subjectUserName = $eventData["SubjectUserName"]
            $taskContent = $eventData["TaskContent"]
            
            Write-LogEntry "WARNING" "Scheduled task created" `
                -EventID "4698" -User $subjectUserName -Technique "T1053" `
                -AdditionalFields "TaskName: $taskName, Content: $([System.Text.RegularExpressions.Regex]::Replace($taskContent, '\s+', ' '))"
        }
    }
    
    # Monitor Registry changes to Task Scheduler
    foreach ($event in $RegistryEvents) {
        $eventData = Get-EventData -Event $event
        $targetObject = $eventData["TargetObject"]
        
        if ($targetObject -match "Schedule\\TaskCache") {
            $processName = $eventData["Image"]
            $processId = $eventData["ProcessId"]
            
            Write-LogEntry "INFO" "Task Scheduler registry modified" `
                -EventID $event.Id -ProcessName $processName -Technique "T1053" `
                -ProcessId $processId -AdditionalFields "RegistryPath: $targetObject"
        }
    }
}

# Monitor Persistence - T1543 Create or Modify System Process
function Monitor-SystemProcessModification {
    param([array]$SecurityEvents, [array]$RegistryEvents)
    
    # Monitor Security Event 7045 (New service installed)
    foreach ($event in $SecurityEvents) {
        if ($event.Id -eq 7045) {
            $eventData = Get-EventData -Event $event
            $serviceName = $eventData["ServiceName"]
            $imagePath = $eventData["ImagePath"]
            $serviceType = $eventData["ServiceType"]
            
            Write-LogEntry "WARNING" "New service installed" `
                -EventID "7045" -Technique "T1543.003" `
                -AdditionalFields "ServiceName: $serviceName, ImagePath: $imagePath, ServiceType: $serviceType"
        }
        
        # Monitor Security Event 4697 (Service installed)
        if ($event.Id -eq 4697) {
            $eventData = Get-EventData -Event $event
            $serviceName = $eventData["ServiceName"]
            $serviceFileName = $eventData["ServiceFileName"]
            $subjectUserName = $eventData["SubjectUserName"]
            
            Write-LogEntry "WARNING" "Service installed by user" `
                -EventID "4697" -User $subjectUserName -Technique "T1543.003" `
                -AdditionalFields "ServiceName: $serviceName, ServiceFile: $serviceFileName"
        }
    }
    
    # Monitor Registry changes to Services
    foreach ($event in $RegistryEvents) {
        $eventData = Get-EventData -Event $event
        $targetObject = $eventData["TargetObject"]
        
        if ($targetObject -match "ControlSet\\Services\\") {
            $processName = $eventData["Image"]
            $processId = $eventData["ProcessId"]
            $details = $eventData["Details"]
            
            Write-LogEntry "INFO" "Service registry modified" `
                -EventID $event.Id -ProcessName $processName -Technique "T1543.003" `
                -ProcessId $processId -AdditionalFields "RegistryPath: $targetObject, Value: $details"
        }
    }
}

# Monitor Persistence - T1546 Event Triggered Execution
function Monitor-EventTriggeredExecution {
    param([array]$RegistryEvents, [array]$WMIEvents)
    
    # Monitor Registry changes for hijacking
    $hijackKeys = @(
        "Image File Execution Options",
        "Classes\\CLSID",
        "Classes\\Folder\\shell",
        "Classes\\exefile\\shell"
    )
    
    foreach ($event in $RegistryEvents) {
        $eventData = Get-EventData -Event $event
        $targetObject = $eventData["TargetObject"]
        
        foreach ($key in $hijackKeys) {
            if ($targetObject -match $key) {
                $processName = $eventData["Image"]
                $processId = $eventData["ProcessId"]
                $details = $eventData["Details"]
                
                Write-LogEntry "WARNING" "Potential execution hijacking detected" `
                    -EventID $event.Id -ProcessName $processName -Technique "T1546" `
                    -ProcessId $processId -AdditionalFields "RegistryKey: $targetObject, Value: $details"
            }
        }
    }
    
    # Monitor WMI Event Subscriptions
    foreach ($event in $WMIEvents) {
        $eventData = Get-EventData -Event $event
        $operation = $eventData["Operation"]
        
        if ($operation -eq "Created") {
            $processName = $eventData["Image"]
            $processId = $eventData["ProcessId"]
            
            Write-LogEntry "WARNING" "WMI Event Subscription created" `
                -EventID $event.Id -ProcessName $processName -Technique "T1546.003" `
                -ProcessId $processId
        }
    }
}

# Monitor file modifications in startup directories
function Monitor-StartupDirectories {
    param([array]$FileEvents)
    
    $startupPaths = @(
        "\\Start Menu\\Programs\\Startup",
        "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    )
    
    foreach ($event in $FileEvents) {
        $eventData = Get-EventData -Event $event
        $targetFilename = $eventData["TargetFilename"]
        $processName = $eventData["Image"]
        $processId = $eventData["ProcessId"]
        
        foreach ($path in $startupPaths) {
            if ($targetFilename -match [regex]::Escape($path)) {
                Write-LogEntry "WARNING" "File created in startup directory" `
                    -EventID $event.Id -ProcessName $processName -TargetFilename $targetFilename `
                    -Technique "T1547.001" -ProcessId $processId
            }
        }
    }
}

# Print summary statistics
function Show-Summary {
    Write-Host "`n=== Persistence Monitoring Summary ===" -ForegroundColor Cyan
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
    Write-Host "========================================`n" -ForegroundColor Cyan
}

# Main monitoring function
function Start-PersistenceMonitoring {
    Initialize-Logger -Path $OutputPath
    Write-LogEntry "INFO" "Persistence monitoring started"
    
    $sysmonAvailable = Test-SysmonAvailable
    Write-LogEntry "INFO" "Sysmon available: $sysmonAvailable"
    
    Write-Host "Persistence Live Monitor v1.0 (Server 2012 Compatible)" -ForegroundColor Cyan
    Write-Host "Sysmon Available: $sysmonAvailable" -ForegroundColor $(if ($sysmonAvailable) { "Green" } else { "Yellow" })
    Write-Host "Press Ctrl+C to stop monitoring`n" -ForegroundColor Gray
    
    $endTime = if ($MonitorDuration -gt 0) { (Get-Date).AddMinutes($MonitorDuration) } else { [DateTime]::MaxValue }
    
    try {
        while ((Get-Date) -lt $endTime) {
            try {
                # Monitor Sysmon events if available
                if ($sysmonAvailable) {
                    # Registry Events (Event ID 12, 13, 14)
                    $registryEvents = Get-EventsSecure -FilterHashtable @{
                        LogName = "Microsoft-Windows-Sysmon/Operational"
                        ID = @(12, 13, 14)
                        StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                    } -MaxEvents 100
                    
                    if ($registryEvents) {
                        Monitor-AutostartExecution -RegistryEvents $registryEvents
                        Monitor-ScheduledTasks -RegistryEvents $registryEvents -SecurityEvents @()
                        Monitor-SystemProcessModification -RegistryEvents $registryEvents -SecurityEvents @()
                        Monitor-EventTriggeredExecution -RegistryEvents $registryEvents -WMIEvents @()
                    }
                    
                    # File Creation (Event ID 11)
                    $fileEvents = Get-EventsSecure -FilterHashtable @{
                        LogName = "Microsoft-Windows-Sysmon/Operational"
                        ID = 11
                        StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                    } -MaxEvents 100
                    
                    if ($fileEvents) {
                        Monitor-StartupDirectories -FileEvents $fileEvents
                    }
                    
                    # WMI Events (Event ID 19, 20, 21)
                    $wmiEvents = Get-EventsSecure -FilterHashtable @{
                        LogName = "Microsoft-Windows-Sysmon/Operational"
                        ID = @(19, 20, 21)
                        StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                    } -MaxEvents 100
                    
                    if ($wmiEvents) {
                        Monitor-EventTriggeredExecution -RegistryEvents @() -WMIEvents $wmiEvents
                    }
                }
                
                # Monitor Security events
                $securityEvents = Get-EventsSecure -FilterHashtable @{
                    LogName = "Security"
                    ID = @(4697, 4698)
                    StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                } -MaxEvents 50
                
                if ($securityEvents) {
                    Monitor-ScheduledTasks -SecurityEvents $securityEvents -RegistryEvents @()
                    Monitor-SystemProcessModification -SecurityEvents $securityEvents -RegistryEvents @()
                }
                
                # Monitor System events
                $systemEvents = Get-EventsSecure -FilterHashtable @{
                    LogName = "System"
                    ID = 7045
                    StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                } -MaxEvents 20
                
                if ($systemEvents) {
                    Monitor-SystemProcessModification -SecurityEvents $systemEvents -RegistryEvents @()
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
    Write-LogEntry "INFO" "Persistence monitoring stopped"
}

# Handle Ctrl+C gracefully
$null = Register-ObjectEvent -InputObject ([Console]) -EventName "CancelKeyPress" -Action {
    Write-Host "`n`nStopping Persistence monitoring..." -ForegroundColor Yellow
    Show-Summary
    Write-LogEntry "INFO" "Persistence monitoring stopped by user"
    exit
}

# Start monitoring
Start-PersistenceMonitoring
