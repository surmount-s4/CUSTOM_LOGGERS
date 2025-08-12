#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Defense Evasion Tactics Logger using Sysmon and Windows Event Logs - Windows Server 2012 Compatible
.DESCRIPTION
    Monitors and logs Defense Evasion techniques using Sysmon events and Windows Security logs
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
    $Script:LogFile = Join-Path $Path "DefenseEvasion_$timestamp.log"
    
    # Write initial log header without verbose console output
    $headerInfo = @"
=== Defense Evasion Logger Started ===
Start Time: $(Get-Date)
PowerShell Version: $($PSVersionTable.PSVersion)
OS: $((Get-WmiObject Win32_OperatingSystem).Caption)
Log File: $Script:LogFile
=======================================
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
    
    # Write to console
    switch ($Level) {
        "CRITICAL" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        default { Write-Host $logEntry -ForegroundColor Green }
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
}

# Check if Sysmon is installed and running - Compatible with existing setup
function Test-SysmonInstalled {
    try {
        # Try multiple service name patterns to match existing setup
        $sysmonServices = @("Sysmon", "Sysmon64", "SysmonDrv")
        $sysmonService = $null
        
        foreach ($serviceName in $sysmonServices) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    $sysmonService = $service
                    break
                }
            } catch {
                # Continue to next service name
            }
        }
        
        # Fallback: Use wildcard search
        if (-not $sysmonService) {
            $sysmonService = Get-Service | Where-Object { $_.Name -like "Sysmon*" } | Select-Object -First 1
        }
        
        if ($sysmonService -and $sysmonService.Status -eq "Running") {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

# Get events with error handling for Windows Server 2012
function Get-EventsSafe {
    param(
        [string]$LogName,
        [array]$EventIDs,
        [datetime]$StartTime
    )
    
    try {
        # Windows Server 2012 compatible event filtering
        $events = @()
        foreach ($id in $EventIDs) {
            try {
                $filterHash = @{
                    LogName = $LogName
                    ID = $id
                    StartTime = $StartTime
                }
                $eventBatch = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue
                if ($eventBatch) {
                    $events += $eventBatch
                }
            } catch {
                # Silent continue for individual event ID failures
            }
        }
        return $events
    } catch {
        return @()
    }
}

# Parse event data - Windows Server 2012 compatible
function Get-EventData {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)
    
    try {
        $eventData = @{}
        $xml = [xml]$Event.ToXml()
        
        if ($xml.Event.EventData.Data) {
            foreach ($data in $xml.Event.EventData.Data) {
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

# Monitor for Access Token Manipulation (T1134)
function Monitor-AccessTokenManipulation {
    $events = Get-EventsSafe -LogName 'Security' -EventIDs @(4624, 4625, 4648, 4672, 4673) -StartTime $Script:LastEventTime

    foreach ($event in $events) {
        $eventData = Get-EventData -Event $event
        
        # Detect token manipulation patterns
        if ($event.Id -eq 4648 -and $eventData.TargetUserName -and $eventData.SubjectUserName) {
            if ($eventData.TargetUserName -ne $eventData.SubjectUserName) {
                Write-LogEntry "WARNING" "Potential token manipulation detected" -EventID $event.Id -Technique "T1134.001 - Token Impersonation/Theft"
            }
        }
        
        if ($event.Id -eq 4672 -and $eventData.PrivilegeList) {
            if ($eventData.PrivilegeList -match "SeDebugPrivilege|SeImpersonatePrivilege") {
                Write-LogEntry "WARNING" "Sensitive privilege assignment detected" -EventID $event.Id -Technique "T1134 - Access Token Manipulation"
            }
        }
    }
}

# Monitor for Process Injection (T1055)
function Monitor-ProcessInjection {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 8, 10) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Detect process injection patterns
            if ($event.Id -eq 8 -and $eventData.TargetImage) {
                Write-LogEntry "WARNING" "Cross-process thread creation detected" -EventID $event.Id -ProcessName $eventData.SourceImage -Technique "T1055 - Process Injection"
            }
            
            if ($event.Id -eq 10 -and $eventData.GrantedAccess) {
                $suspiciousAccess = $eventData.GrantedAccess -match "0x1F3FFF|0x143A|0x1410"
                if ($suspiciousAccess -and $eventData.CallTrace -and $eventData.CallTrace -notmatch "ntdll|kernel32") {
                    Write-LogEntry "CRITICAL" "Suspicious process access detected" -EventID $event.Id -ProcessName $eventData.SourceImage -Technique "T1055 - Process Injection"
                }
            }
        }
    }
}

# Monitor for Masquerading (T1036)
function Monitor-Masquerading {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.Image) {
                $image = $eventData.Image
                $originalFileName = $eventData.OriginalFileName
                
                # Check for system binary masquerading
                $systemBinaries = @("svchost.exe", "lsass.exe", "winlogon.exe", "csrss.exe", "smss.exe")
                foreach ($binary in $systemBinaries) {
                    if ($image -match $binary -and $image -notmatch "System32|SysWOW64") {
                        Write-LogEntry "CRITICAL" "Potential system binary masquerading" -EventID $event.Id -ProcessName $image -Technique "T1036.003 - Rename System Utilities"
                    }
                }
                
                # Check for suspicious paths
                $suspiciousPaths = @("\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Desktop\\")
                foreach ($path in $suspiciousPaths) {
                    if ($image -match $path -and $originalFileName -match "\.exe$") {
                        Write-LogEntry "WARNING" "Executable in suspicious location" -EventID $event.Id -ProcessName $image -Technique "T1036.005 - Match Legitimate Name or Location"
                    }
                }
            }
        }
    }
}

# Monitor for Registry Modifications (T1112)
function Monitor-RegistryModification {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(12, 13, 14) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.TargetObject) {
                $targetObject = $eventData.TargetObject
                
                # Monitor critical registry keys
                $criticalKeys = @(
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
                    "SYSTEM\\CurrentControlSet\\Services",
                    "SOFTWARE\\Microsoft\\Windows Defender",
                    "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders"
                )
                
                foreach ($key in $criticalKeys) {
                    if ($targetObject -match [regex]::Escape($key)) {
                        Write-LogEntry "WARNING" "Critical registry modification detected" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1112 - Modify Registry"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for System Binary Proxy Execution (T1218)
function Monitor-SystemBinaryProxy {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.Image -and $eventData.CommandLine) {
                $image = $eventData.Image
                $commandLine = $eventData.CommandLine
                
                # Check for common proxy execution binaries
                $proxyBinaries = @{
                    "rundll32.exe" = "T1218.011 - Rundll32"
                    "regsvr32.exe" = "T1218.010 - Regsvr32"
                    "mshta.exe" = "T1218.005 - Mshta"
                    "certutil.exe" = "T1218.003 - Certutil"
                    "wscript.exe" = "T1218.001 - Scripting"
                    "cscript.exe" = "T1218.001 - Scripting"
                    "powershell.exe" = "T1218.001 - PowerShell"
                    "msiexec.exe" = "T1218.007 - Msiexec"
                    "installutil.exe" = "T1218.004 - InstallUtil"
                }
                
                foreach ($binary in $proxyBinaries.Keys) {
                    if ($image -match $binary) {
                        # Check for suspicious command line patterns
                        if ($commandLine -match "http|ftp|\.ps1|\.vbs|\.js|\.hta|javascript:|vbscript:") {
                            Write-LogEntry "WARNING" "Potential proxy execution detected" -EventID $event.Id -ProcessName $image -CommandLine $commandLine -Technique $proxyBinaries[$binary]
                        }
                    }
                }
            }
        }
    }
}

# Monitor for Hide Artifacts (T1564)
function Monitor-HideArtifacts {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(11, 12, 13) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                # Check for hidden files/ADS
                if ($targetFilename -match ":.:|^\.\.|\\\.[^\\]*$") {
                    Write-LogEntry "WARNING" "Potential file hiding detected" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1564.004 - NTFS File Attributes"
                }
            }
            
            if ($event.Id -eq 13 -and $eventData.TargetObject -and $eventData.Details) {
                $targetObject = $eventData.TargetObject
                $details = $eventData.Details
                
                # Check for hidden registry keys/values
                if ($targetObject -match "\\Software\\Classes\\.+\\shell\\" -and $details -match "DWORD \(0x00000000\)") {
                    Write-LogEntry "WARNING" "Potential registry hiding detected" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1564.001 - Hidden Files and Directories"
                }
            }
        }
    }
}

# Monitor for Impair Defenses (T1562)
function Monitor-ImpairDefenses {
    # Security log events
    $events = Get-EventsSafe -LogName 'Security' -EventIDs @(4719, 4739, 4946, 4947, 4948, 4949) -StartTime $Script:LastEventTime

    foreach ($event in $events) {
        Write-LogEntry "CRITICAL" "Security policy modification detected" -EventID $event.Id -Technique "T1562.002 - Disable Windows Event Logging"
    }
    
    # Sysmon events
    if (Test-SysmonInstalled) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 12, 13) -StartTime $Script:LastEventTime

        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for defense evasion commands
                $defenseEvasionPatterns = @(
                    "Set-MpPreference.*-DisableRealtimeMonitoring",
                    "netsh.*firewall.*disable",
                    "sc.*stop.*windefend",
                    "taskkill.*/f.*/im.*antivirus",
                    "wevtutil.*cl.*Security"
                )
                
                foreach ($pattern in $defenseEvasionPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "CRITICAL" "Defense impairment command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1562 - Impair Defenses"
                    }
                }
            }
        }
    }
}

# Monitor for Obfuscated Files or Information (T1027)
function Monitor-ObfuscatedFiles {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for obfuscation patterns
                if ($commandLine -match "-enc.|[A-Za-z0-9+/]{20,}.==|\\x[0-9a-f]{2}|%[0-9a-f]{2}") {
                    Write-LogEntry "WARNING" "Potential obfuscated command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1027 - Obfuscated Files or Information"
                }
            }
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                # Check for suspicious file extensions/patterns
                if ($targetFilename -match "\.tmp$|\.temp$|[0-9a-f]{32,}|[A-Za-z0-9+/]{20,}") {
                    Write-LogEntry "INFO" "Potentially obfuscated file created" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1027.009 - Embedded Payloads"
                }
            }
        }
    }
}

# Monitor for Indicator Removal (T1070)
function Monitor-IndicatorRemoval {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 23) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for log clearing commands
                $logClearPatterns = @(
                    "wevtutil.*cl",
                    "Clear-EventLog",
                    "Remove-Item.*\.log",
                    "del.*\.log",
                    "fsutil.*deletejournal"
                )
                
                foreach ($pattern in $logClearPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "CRITICAL" "Log clearing activity detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1070.001 - Clear Windows Event Logs"
                    }
                }
            }
            
            if ($event.Id -eq 23) {
                # Enhanced logging for file deletion events with critical fields
                $targetFilename = if ($eventData.TargetFilename) { $eventData.TargetFilename } else { "Unknown" }
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                $user = if ($eventData.User) { $eventData.User } else { "Unknown" }
                $processGuid = if ($eventData.ProcessGuid) { $eventData.ProcessGuid } else { "Unknown" }
                $utcTime = if ($eventData.UtcTime) { $eventData.UtcTime } else { $event.TimeCreated }
                $hashes = if ($eventData.Hashes) { $eventData.Hashes } else { "N/A" }
                $isExecutable = if ($eventData.IsExecutable) { $eventData.IsExecutable } else { "Unknown" }
                
                $enhancedMessage = "File deletion detected | TargetFile: $targetFilename | PID: $processId | User: $user | GUID: $processGuid | Hashes: $hashes | Executable: $isExecutable"
                Write-LogEntry "INFO" $enhancedMessage -EventID $event.Id -ProcessName $eventData.Image -Technique "T1070.004 - File Deletion"
            }
        }
    }
}

# Display real-time status
# Display real-time status (disabled for clean logging)
# function Show-MonitoringStatus {
#     $uptime = (Get-Date) - $Script:StartTime
#     $totalEvents = ($Script:EventCounters.Values | Measure-Object -Sum).Sum
#     
#     Write-Host "`n=== Defense Evasion Monitor Status ===" -ForegroundColor Cyan
#     Write-Host "Uptime: $($uptime.ToString('hh\:mm\:ss'))" -ForegroundColor White
#     Write-Host "Total Events: $totalEvents" -ForegroundColor White
#     Write-Host "Sysmon Status: $(if (Test-SysmonInstalled) { 'Active' } else { 'Not Available' })" -ForegroundColor White
#     Write-Host "Next check in: $RefreshInterval seconds" -ForegroundColor Gray
#     
#     if ($Script:EventCounters.Count -gt 0) {
#         Write-Host "`nTop Techniques Detected:" -ForegroundColor Yellow
#         $topTechniques = $Script:EventCounters.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
#         foreach ($technique in $topTechniques) {
#             Write-Host "  $($technique.Name): $($technique.Value)" -ForegroundColor White
#         }
#     }
#     Write-Host "=================================" -ForegroundColor Cyan
# }

# Generate summary report
function Generate-Summary {
    $summaryInfo = @"

=== Defense Evasion Monitoring Summary ===
Duration: $((Get-Date) - $Script:StartTime)
Techniques Detected: $($Script:EventCounters.Count)
"@
    Add-Content -Path $Script:LogFile -Value $summaryInfo
    
    if ($Script:EventCounters.Count -gt 0) {
        $sortedTechniques = $Script:EventCounters.GetEnumerator() | Sort-Object Name
        foreach ($technique in $sortedTechniques) {
            Add-Content -Path $Script:LogFile -Value "$($technique.Name): $($technique.Value) events"
        }
    } else {
        Add-Content -Path $Script:LogFile -Value "No defense evasion techniques detected during monitoring period"
    }
    
    Add-Content -Path $Script:LogFile -Value "=== Defense Evasion Logger Stopped at $(Get-Date) ==="
}

# Main monitoring loop with clean detection-only logging
function Start-Monitoring {
    $endTime = if ($MonitorDuration -gt 0) { 
        $Script:StartTime.AddMinutes($MonitorDuration) 
    } else { 
        [DateTime]::MaxValue 
    }
    
    while ((Get-Date) -lt $endTime) {
        try {
            $iterationStart = Get-Date
            
            # Run all monitoring functions
            Monitor-AccessTokenManipulation
            Monitor-ProcessInjection
            Monitor-Masquerading
            Monitor-RegistryModification
            Monitor-SystemBinaryProxy
            Monitor-HideArtifacts
            Monitor-ImpairDefenses
            Monitor-ObfuscatedFiles
            Monitor-IndicatorRemoval
            
            # Update last event time for next iteration
            $Script:LastEventTime = $iterationStart
            
            # Sleep for specified interval
            Start-Sleep -Seconds $RefreshInterval
            
        } catch {
            # Silent error handling - only log critical errors
            Start-Sleep -Seconds 10  # Brief pause on error
        }
    }
}

# Cleanup function
function Stop-Monitoring {
    Generate-Summary
}

# Main execution
try {
    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
    Write-Host "Defense Evasion Live Monitor v2.0 (Server 2012 Compatible)" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    # Initialize
    Initialize-Logger -Path $OutputPath
    
    # Check Sysmon status
    $sysmonAvailable = Test-SysmonInstalled
    if (-not $sysmonAvailable) {
        Write-Host "WARNING: Sysmon not detected. Some detection capabilities will be limited." -ForegroundColor Yellow
        Write-Host "INFO: Run Setup-SysmonPipeline.ps1 to install Sysmon for enhanced monitoring" -ForegroundColor Gray
    }
    
    # Display monitoring configuration
    Write-Host "`nMonitoring Configuration:" -ForegroundColor Yellow
    Write-Host "  Output Path: $OutputPath" -ForegroundColor White
    Write-Host "  Log Level: $LogLevel" -ForegroundColor White
    Write-Host "  Duration: $(if ($MonitorDuration -eq 0) { 'Continuous' } else { "$MonitorDuration minutes" })" -ForegroundColor White
    Write-Host "  Refresh Interval: $RefreshInterval seconds" -ForegroundColor White
    Write-Host "  Sysmon Available: $(if ($sysmonAvailable) { 'Yes' } else { 'No' })" -ForegroundColor White
    
    Write-Host "`nStarting Defense Evasion monitoring... Press Ctrl+C to stop" -ForegroundColor Green
    Write-Host "Only detection events will be logged for clean output`n" -ForegroundColor Gray
    
    # Register cleanup on script termination
    Register-EngineEvent PowerShell.Exiting -Action { Stop-Monitoring }
    
    # Start monitoring
    Start-Monitoring
    
} catch {
    Write-Host "FATAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Stop-Monitoring
}
