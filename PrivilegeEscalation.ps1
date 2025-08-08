#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Privilege Escalation Tactics Logger using Sysmon and Windows Event Logs - Windows Server 2012 Compatible
.DESCRIPTION
    Monitors and logs Privilege Escalation techniques using Sysmon events and Windows Security logs
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
    $Script:LogFile = Join-Path $Path "PrivilegeEscalation_$timestamp.log"
    
    # Write initial log header without verbose console output
    $headerInfo = @"
=== Privilege Escalation Logger Started ===
Start Time: $(Get-Date)
PowerShell Version: $($PSVersionTable.PSVersion)
OS: $((Get-WmiObject Win32_OperatingSystem).Caption)
Log File: $Script:LogFile
============================================
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

# Monitor Privilege Escalation - T1134 Access Token Manipulation
function Monitor-AccessTokenManipulation {
    param([array]$Events)
    
    $tokenManipulationIndicators = @(
        "SeDebugPrivilege",
        "SeTcbPrivilege", 
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeLoadDriverPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege"
    )
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $processName = $eventData["Image"]
        $commandLine = $eventData["CommandLine"]
        $processId = $eventData["ProcessId"]
        $user = $eventData["User"]
        $processGuid = $eventData["ProcessGuid"]
        
        # Check for privilege escalation attempts
        foreach ($privilege in $tokenManipulationIndicators) {
            if ($commandLine -match $privilege) {
                Write-LogEntry "CRITICAL" "Access token manipulation attempt detected" `
                    -EventID "1" -ProcessName $processName -CommandLine $commandLine -Technique "T1134" `
                    -ProcessId $processId -User $user -ProcessGuid $processGuid `
                    -AdditionalFields "DetectedPrivilege: $privilege"
            }
        }
        
        # Monitor specific tools
        if ($processName -match "incognito|Cobalt Strike|Metasploit") {
            Write-LogEntry "CRITICAL" "Known privilege escalation tool detected" `
                -EventID "1" -ProcessName $processName -CommandLine $commandLine -Technique "T1134" `
                -ProcessId $processId -User $user -ProcessGuid $processGuid
        }
    }
}

# Monitor Privilege Escalation - T1055 Process Injection
function Monitor-ProcessInjection {
    param([array]$Events)
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $sourceProcessId = $eventData["SourceProcessId"]
        $targetProcessId = $eventData["TargetProcessId"]
        $sourceImage = $eventData["SourceImage"]
        $targetImage = $eventData["TargetImage"]
        $grantedAccess = $eventData["GrantedAccess"]
        $callTrace = $eventData["CallTrace"]
        
        # Suspicious process access patterns
        if ($grantedAccess -match "0x1F3FFF|0x1FFFFF") {
            Write-LogEntry "WARNING" "Suspicious process access with high privileges detected" `
                -EventID "10" -ProcessName $sourceImage -Technique "T1055" `
                -ProcessId $sourceProcessId -AdditionalFields "Target: $targetImage (PID: $targetProcessId), Access: $grantedAccess"
        }
        
        # Cross-process memory access
        if ($sourceImage -ne $targetImage -and $grantedAccess -match "0x40|0x20|0x8") {
            Write-LogEntry "INFO" "Cross-process memory access detected" `
                -EventID "10" -ProcessName $sourceImage -Technique "T1055" `
                -ProcessId $sourceProcessId -AdditionalFields "Target: $targetImage, Access: $grantedAccess"
        }
        
        # Suspicious call traces
        if ($callTrace -match "ntdll.dll|kernel32.dll.*WriteProcessMemory|VirtualAllocEx") {
            Write-LogEntry "WARNING" "Suspicious API call trace detected" `
                -EventID "10" -ProcessName $sourceImage -Technique "T1055" `
                -ProcessId $sourceProcessId -AdditionalFields "CallTrace: $callTrace"
        }
    }
}

# Monitor Privilege Escalation - T1068 Exploitation for Privilege Escalation
function Monitor-ExploitationPrivilegeEscalation {
    param([array]$Events)
    
    $exploitIndicators = @(
        "CVE-",
        "MS\d{2}-\d{3}",
        "exploit",
        "privilege escalation",
        "UAC bypass",
        "token manipulation"
    )
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $processName = $eventData["Image"]
        $commandLine = $eventData["CommandLine"]
        $processId = $eventData["ProcessId"]
        $user = $eventData["User"]
        $parentImage = $eventData["ParentImage"]
        
        foreach ($indicator in $exploitIndicators) {
            if ($commandLine -match $indicator) {
                Write-LogEntry "CRITICAL" "Potential exploitation for privilege escalation detected" `
                    -EventID "1" -ProcessName $processName -CommandLine $commandLine -Technique "T1068" `
                    -ProcessId $processId -User $user -AdditionalFields "Parent: $parentImage, Indicator: $indicator"
            }
        }
        
        # Monitor unusual system processes
        if ($processName -match "svchost\.exe|winlogon\.exe|csrss\.exe" -and $user -notmatch "SYSTEM|LOCAL SERVICE|NETWORK SERVICE") {
            Write-LogEntry "WARNING" "System process running under unusual user context" `
                -EventID "1" -ProcessName $processName -CommandLine $commandLine -Technique "T1068" `
                -ProcessId $processId -User $user
        }
    }
}

# Monitor Privilege Escalation - T1548 Abuse Elevation Control Mechanism
function Monitor-ElevationControlAbuse {
    param([array]$Events)
    
    $uacBypassIndicators = @(
        "fodhelper\.exe",
        "ComputerDefaults\.exe",
        "eventvwr\.exe",
        "sdclt\.exe",
        "SilentCleanup",
        "ms-settings:",
        "wsreset\.exe"
    )
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $processName = $eventData["Image"]
        $commandLine = $eventData["CommandLine"]
        $processId = $eventData["ProcessId"]
        $user = $eventData["User"]
        $parentImage = $eventData["ParentImage"]
        
        # UAC bypass detection
        foreach ($indicator in $uacBypassIndicators) {
            if ($processName -match $indicator -or $commandLine -match $indicator) {
                Write-LogEntry "WARNING" "Potential UAC bypass attempt detected" `
                    -EventID "1" -ProcessName $processName -CommandLine $commandLine -Technique "T1548.002" `
                    -ProcessId $processId -User $user -AdditionalFields "Parent: $parentImage, Method: $indicator"
            }
        }
        
        # Monitor runas usage
        if ($processName -match "runas\.exe") {
            Write-LogEntry "INFO" "RunAs command execution detected" `
                -EventID "1" -ProcessName $processName -CommandLine $commandLine -Technique "T1548" `
                -ProcessId $processId -User $user
        }
    }
}

# Monitor Registry Events for Privilege Escalation
function Monitor-RegistryPrivilegeEscalation {
    param([array]$RegistryEvents)
    
    $privilegeEscalationKeys = @(
        "\\Environment\\",
        "\\Winlogon\\",
        "\\CurrentVersion\\Run",
        "\\CurrentVersion\\Windows",
        "\\Control\\Lsa\\",
        "\\SAM\\",
        "\\SECURITY\\",
        "\\System\\CurrentControlSet\\Services\\"
    )
    
    foreach ($event in $RegistryEvents) {
        $eventData = Get-EventData -Event $event
        $processName = $eventData["Image"]
        $targetObject = $eventData["TargetObject"]
        $details = $eventData["Details"]
        $processId = $eventData["ProcessId"]
        $user = $eventData["User"]
        
        foreach ($key in $privilegeEscalationKeys) {
            if ($targetObject -match $key) {
                $level = if ($key -match "SAM|SECURITY|Lsa") { "CRITICAL" } else { "WARNING" }
                
                Write-LogEntry $level "Registry modification in privilege escalation sensitive area" `
                    -EventID $event.Id -ProcessName $processName -Technique "T1548" `
                    -ProcessId $processId -User $user -TargetFilename $targetObject `
                    -AdditionalFields "Details: $details"
            }
        }
    }
}

# Monitor Security Events for Privilege Changes
function Monitor-SecurityPrivilegeEvents {
    param([array]$SecurityEvents)
    
    foreach ($event in $SecurityEvents) {
        switch ($event.Id) {
            4672 { # Special privileges assigned to new logon
                $eventData = Get-EventData -Event $event
                $subjectUserName = $eventData["SubjectUserName"]
                $privilegeList = $eventData["PrivilegeList"]
                $logonId = $eventData["SubjectLogonId"]
                
                Write-LogEntry "INFO" "Special privileges assigned to user logon" `
                    -EventID "4672" -User $subjectUserName -Technique "T1134" `
                    -AdditionalFields "Privileges: $privilegeList, LogonId: $logonId"
            }
            
            4673 { # A privileged service was called
                $eventData = Get-EventData -Event $event
                $subjectUserName = $eventData["SubjectUserName"]
                $serviceName = $eventData["Service"]
                $privilegeList = $eventData["PrivilegeList"]
                
                if ($privilegeList -match "SeDebugPrivilege|SeTcbPrivilege|SeImpersonatePrivilege") {
                    Write-LogEntry "WARNING" "High-value privilege used for service call" `
                        -EventID "4673" -User $subjectUserName -Technique "T1134" `
                        -AdditionalFields "Service: $serviceName, Privileges: $privilegeList"
                }
            }
            
            4648 { # A logon was attempted using explicit credentials
                $eventData = Get-EventData -Event $event
                $subjectUserName = $eventData["SubjectUserName"]
                $targetUserName = $eventData["TargetUserName"]
                $processName = $eventData["ProcessName"]
                
                if ($subjectUserName -ne $targetUserName) {
                    Write-LogEntry "INFO" "Explicit credential usage detected" `
                        -EventID "4648" -User $subjectUserName -ProcessName $processName -Technique "T1134" `
                        -AdditionalFields "TargetUser: $targetUserName"
                }
            }
        }
    }
}

# Print summary statistics
function Show-Summary {
    Write-Host "`n=== Privilege Escalation Monitoring Summary ===" -ForegroundColor Cyan
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
    Write-Host "===============================================`n" -ForegroundColor Cyan
}

# Main monitoring function
function Start-PrivilegeEscalationMonitoring {
    Initialize-Logger -Path $OutputPath
    Write-LogEntry "INFO" "Privilege escalation monitoring started"
    
    $sysmonAvailable = Test-SysmonAvailable
    Write-LogEntry "INFO" "Sysmon available: $sysmonAvailable"
    
    Write-Host "Privilege Escalation Live Monitor v1.0 (Server 2012 Compatible)" -ForegroundColor Cyan
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
                        Monitor-AccessTokenManipulation -Events $processEvents
                        Monitor-ExploitationPrivilegeEscalation -Events $processEvents
                        Monitor-ElevationControlAbuse -Events $processEvents
                    }
                    
                    # Process Access (Event ID 10)
                    $processAccessEvents = Get-EventsSecure -FilterHashtable @{
                        LogName = "Microsoft-Windows-Sysmon/Operational"
                        ID = 10
                        StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                    } -MaxEvents 100
                    
                    if ($processAccessEvents) {
                        Monitor-ProcessInjection -Events $processAccessEvents
                    }
                    
                    # Registry Events (Event IDs 12, 13, 14)
                    $registryEvents = Get-EventsSecure -FilterHashtable @{
                        LogName = "Microsoft-Windows-Sysmon/Operational"
                        ID = @(12, 13, 14)
                        StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                    } -MaxEvents 100
                    
                    if ($registryEvents) {
                        Monitor-RegistryPrivilegeEscalation -RegistryEvents $registryEvents
                    }
                }
                
                # Monitor Security events for privilege changes
                $securityEvents = Get-EventsSecure -FilterHashtable @{
                    LogName = "Security"
                    ID = @(4648, 4672, 4673)
                    StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                } -MaxEvents 100
                
                if ($securityEvents) {
                    Monitor-SecurityPrivilegeEvents -SecurityEvents $securityEvents
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
    Write-LogEntry "INFO" "Privilege escalation monitoring stopped"
}

# Handle Ctrl+C gracefully
$null = Register-ObjectEvent -InputObject ([Console]) -EventName "CancelKeyPress" -Action {
    Write-Host "`n`nStopping Privilege Escalation monitoring..." -ForegroundColor Yellow
    Show-Summary
    Write-LogEntry "INFO" "Privilege escalation monitoring stopped by user"
    exit
}

# Start monitoring
Start-PrivilegeEscalationMonitoring
