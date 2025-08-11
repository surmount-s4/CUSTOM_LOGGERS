#Requires -RunAsAdministrator

<#
.SYNOPSIS
OT-Focused Process Parent→Child Correlation Monitor with Whitelisting

.DESCRIPTION
This script monitors parent→child process relationships in Operational Technology (OT) environments,
focusing on detecting unauthorized process spawning that could indicate compromise of critical systems.
Uses both Sysmon Event ID 1 integration and WMI fallback with comprehensive whitelisting capabilities.

Key Features:
- OT-specific process monitoring (HMI, SCADA, Engineering tools)
- Whitelist-based approach to reduce false positives
- Sysmon Event ID 1 integration for real-time detection
- Short-lived PID correlation mapping
- Industrial protocol and tool awareness

Compatible with: sysmon-config-comprehensive-updated.xml
Author: Custom Security Loggers Project - OT Security Team
Version: 1.0
#>

# ============================================================================
# CONFIGURATION SECTION
# ============================================================================

$LogFile = "C:\ProgramData\CustomSecurityLogs\OT_ProcessCorrelation.log"
$WhitelistFile = "C:\ProgramData\CustomSecurityLogs\OT_ProcessWhitelist.json"
$ProcessMap = @{}
$MapCleanupInterval = 600 # Clean entries older than 10 minutes (longer for OT stability)
$LastCleanup = Get-Date
$MonitoringActive = $true

# Sysmon Event Log Configuration
$SysmonLogName = "Microsoft-Windows-Sysmon/Operational"
$LastEventRecordId = 0

# ============================================================================
# OT-SPECIFIC PROCESS DEFINITIONS
# ============================================================================

# Critical OT processes that should never spawn unexpected children
$CriticalOTProcesses = @(
    "wonderware.exe",           # Wonderware HMI
    "intouch.exe",             # Wonderware InTouch
    "rsview32.exe",            # RSView32 HMI
    "factorytalk.exe",         # FactoryTalk View
    "citect.exe",              # Citect SCADA
    "genesis.exe",             # GE iFIX
    "wincc.exe",               # Siemens WinCC
    "lookout.exe",             # National Instruments Lookout
    "rslinx.exe",              # Rockwell RSLinx
    "rslogix5000.exe",         # Rockwell Studio 5000
    "step7.exe",               # Siemens STEP 7
    "tiaportal.exe",           # Siemens TIA Portal
    "unity.exe",               # Schneider Unity Pro
    "kepserverex.exe",         # KEPServerEX
    "matrikon.exe",            # Matrikon OPC Server
    "schneiderelect.exe",      # Schneider Electric tools
    "abb.exe",                 # ABB automation tools
    "emerson.exe",             # Emerson DeltaV
    "honeywell.exe",           # Honeywell Experion
    "invensys.exe",            # Invensys Wonderware
    "aveva.exe",               # AVEVA solutions
    "indusoft.exe",            # InduSoft Web Studio
    "iconics.exe",             # ICONICS GENESIS64
    "ge-proficy.exe",          # GE Proficy suite
    "rockwell.exe"             # General Rockwell Automation tools
)

# Default whitelist for legitimate parent→child relationships in OT environments
$DefaultWhitelist = @{
    # Engineering Workstation Patterns
    "rslogix5000.exe" = @("rslinx.exe", "factorytalk.exe", "excel.exe", "notepad.exe")
    "step7.exe" = @("wincc.exe", "notepad.exe", "excel.exe", "simatic.exe")
    "tiaportal.exe" = @("wincc.exe", "step7.exe", "notepad.exe", "excel.exe")
    "unity.exe" = @("schneiderelect.exe", "notepad.exe", "excel.exe")
    
    # HMI and SCADA Legitimate Children
    "wonderware.exe" = @("intouch.exe", "excel.exe", "notepad.exe", "calc.exe")
    "wincc.exe" = @("excel.exe", "notepad.exe", "calc.exe", "simatic.exe")
    "citect.exe" = @("excel.exe", "notepad.exe", "calc.exe")
    "factorytalk.exe" = @("rslinx.exe", "excel.exe", "notepad.exe")
    
    # OPC and Communication Tools
    "kepserverex.exe" = @("excel.exe", "notepad.exe", "rslinx.exe")
    "rslinx.exe" = @("factorytalk.exe", "rslogix5000.exe")
    "matrikon.exe" = @("excel.exe", "notepad.exe")
    
    # System Processes (Limited whitelist for OT)
    "explorer.exe" = @("rslogix5000.exe", "step7.exe", "tiaportal.exe", "unity.exe", "wonderware.exe", "wincc.exe", "citect.exe", "factorytalk.exe", "kepserverex.exe", "notepad.exe", "calc.exe", "excel.exe", "word.exe")
    "services.exe" = @("svchost.exe", "spoolsv.exe", "lsass.exe")
    "winlogon.exe" = @("explorer.exe", "userinit.exe")
    
    # Remote Access (Controlled)
    "mstsc.exe" = @("rdpclip.exe")
    "teamviewer.exe" = @("tv_w32.exe", "tv_x64.exe")
    
    # Maintenance Tools (Limited)
    "mmc.exe" = @("notepad.exe")
    "regedit.exe" = @()  # Empty array means no children allowed
    "taskmgr.exe" = @()  # Task manager should not spawn children
}

# ============================================================================
# WHITELIST MANAGEMENT FUNCTIONS
# ============================================================================

function Initialize-Whitelist {
    if (Test-Path $WhitelistFile) {
        try {
            $script:Whitelist = Get-Content $WhitelistFile | ConvertFrom-Json -AsHashtable
            Write-Log -Message "Loaded whitelist from $WhitelistFile" -Level "INFO"
        } catch {
            Write-Log -Message "Failed to load whitelist file, using defaults: $($_.Exception.Message)" -Level "WARNING"
            $script:Whitelist = $DefaultWhitelist
            Save-Whitelist
        }
    } else {
        Write-Log -Message "No whitelist file found, creating default whitelist" -Level "INFO"
        $script:Whitelist = $DefaultWhitelist
        Save-Whitelist
    }
}

function Save-Whitelist {
    try {
        $script:Whitelist | ConvertTo-Json -Depth 3 | Set-Content $WhitelistFile
        Write-Log -Message "Whitelist saved to $WhitelistFile" -Level "INFO"
    } catch {
        Write-Log -Message "Failed to save whitelist: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Test-ProcessWhitelisted {
    param(
        [string]$ParentProcess,
        [string]$ChildProcess
    )
    
    $parentName = [System.IO.Path]::GetFileName($ParentProcess).ToLower()
    $childName = [System.IO.Path]::GetFileName($ChildProcess).ToLower()
    
    if ($script:Whitelist.ContainsKey($parentName)) {
        return $childName -in $script:Whitelist[$parentName]
    }
    
    return $false
}

function Add-WhitelistEntry {
    param(
        [string]$ParentProcess,
        [string]$ChildProcess
    )
    
    $parentName = [System.IO.Path]::GetFileName($ParentProcess).ToLower()
    $childName = [System.IO.Path]::GetFileName($ChildProcess).ToLower()
    
    if (-not $script:Whitelist.ContainsKey($parentName)) {
        $script:Whitelist[$parentName] = @()
    }
    
    if ($childName -notin $script:Whitelist[$parentName]) {
        $script:Whitelist[$parentName] += $childName
        Save-Whitelist
        Write-Log -Message "Added whitelist entry: $parentName → $childName" -Level "INFO"
        return $true
    }
    
    return $false
}

# ============================================================================
# LOGGING AND ALERTING FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [hashtable]$StructuredData = @{}
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] - $Level - $Message"
    
    # Add structured data for SIEM integration
    if ($StructuredData.Count -gt 0) {
        $dataString = ($StructuredData.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " | "
        $logEntry += " | $dataString"
    }
    
    $logEntry | Out-File -FilePath $LogFile -Append
    
    switch ($Level) {
        "CRITICAL" { Write-Host $logEntry -ForegroundColor Red -BackgroundColor Yellow }
        "ALERT" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry }
    }
}

function Send-OTSecurityAlert {
    param(
        [string]$AlertType,
        [string]$ParentProcess,
        [string]$ChildProcess,
        [string]$ParentPID,
        [string]$ChildPID,
        [string]$CommandLine,
        [string]$User
    )
    
    $structuredData = @{
        "AlertType" = $AlertType
        "ParentProcess" = $ParentProcess
        "ChildProcess" = $ChildProcess
        "ParentPID" = $ParentPID
        "ChildPID" = $ChildPID
        "User" = $User
        "CommandLine" = $CommandLine
        "Timestamp" = Get-Date -Format "o"
        "Environment" = "OT"
        "Severity" = if ($ParentProcess -in $CriticalOTProcesses) { "CRITICAL" } else { "HIGH" }
    }
    
    $alertMessage = "OT_SECURITY_VIOLATION: Unauthorized process spawning detected"
    
    if ($ParentProcess -in $CriticalOTProcesses) {
        Write-Log -Level "CRITICAL" -Message $alertMessage -StructuredData $structuredData
    } else {
        Write-Log -Level "ALERT" -Message $alertMessage -StructuredData $structuredData
    }
}

# ============================================================================
# SYSMON INTEGRATION FUNCTIONS
# ============================================================================

function Test-SysmonAvailability {
    try {
        $sysmonEvents = Get-WinEvent -LogName $SysmonLogName -MaxEvents 1 -ErrorAction Stop
        return $true
    } catch {
        Write-Log -Message "Sysmon not available, falling back to WMI monitoring: $($_.Exception.Message)" -Level "WARNING"
        return $false
    }
}

function Process-SysmonEvents {
    try {
        # Get new Sysmon Event ID 1 (Process Creation) events
        $events = Get-WinEvent -LogName $SysmonLogName -FilterHashtable @{ID=1} | 
                  Where-Object { $_.RecordId -gt $LastEventRecordId } |
                  Sort-Object RecordId
        
        foreach ($event in $events) {
            $eventXML = [xml]$event.ToXml()
            $eventData = @{}
            
            foreach ($data in $eventXML.Event.EventData.Data) {
                $eventData[$data.Name] = $data.'#text'
            }
            
            Process-ProcessCreation -ProcessInfo $eventData -Source "Sysmon"
            $script:LastEventRecordId = $event.RecordId
        }
        
        return $events.Count
    } catch {
        Write-Log -Message "Error processing Sysmon events: $($_.Exception.Message)" -Level "ERROR"
        return 0
    }
}

# ============================================================================
# PROCESS MONITORING FUNCTIONS
# ============================================================================

function Process-ProcessCreation {
    param(
        [hashtable]$ProcessInfo,
        [string]$Source = "WMI"
    )
    
    $processId = if ($Source -eq "Sysmon") { $ProcessInfo.ProcessId } else { $ProcessInfo.ProcessId }
    $parentProcessId = if ($Source -eq "Sysmon") { $ProcessInfo.ParentProcessId } else { $ProcessInfo.ParentProcessId }
    $processName = if ($Source -eq "Sysmon") { $ProcessInfo.Image } else { $ProcessInfo.Name }
    $commandLine = if ($Source -eq "Sysmon") { $ProcessInfo.CommandLine } else { $ProcessInfo.CommandLine }
    $user = if ($Source -eq "Sysmon") { $ProcessInfo.User } else { "Unknown" }
    
    # Add to process map
    $ProcessMap[$processId] = @{
        Name = [System.IO.Path]::GetFileName($processName)
        FullPath = $processName
        ParentPID = $parentProcessId
        CommandLine = $commandLine
        User = $user
        CreationTime = Get-Date
        Source = $Source
    }
    
    # Check parent→child relationship
    if ($parentProcessId -and $ProcessMap.ContainsKey($parentProcessId)) {
        $parentInfo = $ProcessMap[$parentProcessId]
        $parentName = $parentInfo.Name
        $childName = [System.IO.Path]::GetFileName($processName)
        
        # Check if this relationship is whitelisted
        if (-not (Test-ProcessWhitelisted -ParentProcess $parentName -ChildProcess $childName)) {
            # This is a non-whitelisted relationship
            $alertType = if ($parentName -in $CriticalOTProcesses) { "CRITICAL_OT_PROCESS_SPAWN" } else { "UNAUTHORIZED_PROCESS_SPAWN" }
            
            Send-OTSecurityAlert -AlertType $alertType -ParentProcess $parentName -ChildProcess $childName -ParentPID $parentProcessId -ChildPID $processId -CommandLine $commandLine -User $user
        }
    }
}

function Monitor-ProcessesWMI {
    try {
        $currentProcesses = Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine, CreationDate
        
        foreach ($proc in $currentProcesses) {
            if (-not $ProcessMap.ContainsKey($proc.ProcessId)) {
                Process-ProcessCreation -ProcessInfo $proc -Source "WMI"
            }
        }
        
        return $currentProcesses.Count
    } catch {
        Write-Log -Message "Error in WMI process monitoring: $($_.Exception.Message)" -Level "ERROR"
        return 0
    }
}

function Cleanup-ProcessMap {
    $cutoffTime = (Get-Date).AddSeconds(-$MapCleanupInterval)
    $toRemove = @()
    
    foreach ($pid in $ProcessMap.Keys) {
        if ($ProcessMap[$pid].CreationTime -lt $cutoffTime) {
            $toRemove += $pid
        }
    }
    
    foreach ($pid in $toRemove) {
        $ProcessMap.Remove($pid)
    }
    
    if ($toRemove.Count -gt 0) {
        Write-Log -Message "Cleaned up $($toRemove.Count) old process entries from correlation map"
    }
}

# ============================================================================
# MAIN MONITORING LOOP
# ============================================================================

function Start-OTProcessMonitoring {
    Write-Log -Message "=== OT Process Correlation Monitor Starting ===" -Level "INFO"
    Write-Log -Message "Critical OT processes monitored: $($CriticalOTProcesses.Count)" -Level "INFO"
    Write-Log -Message "Whitelist entries loaded: $($script:Whitelist.Keys.Count)" -Level "INFO"
    
    # Test Sysmon availability
    $useSysmon = Test-SysmonAvailability
    
    if ($useSysmon) {
        Write-Log -Message "Sysmon integration enabled - using Event ID 1 for real-time monitoring" -Level "INFO"
        $script:LastEventRecordId = (Get-WinEvent -LogName $SysmonLogName -MaxEvents 1).RecordId
    } else {
        Write-Log -Message "Using WMI fallback for process monitoring" -Level "INFO"
    }
    
    $monitoringStats = @{
        SysmonEvents = 0
        WMIProcesses = 0
        AlertsGenerated = 0
        StartTime = Get-Date
    }
    
    while ($MonitoringActive) {
        try {
            if ($useSysmon) {
                $eventsProcessed = Process-SysmonEvents
                $monitoringStats.SysmonEvents += $eventsProcessed
            } else {
                $processesMonitored = Monitor-ProcessesWMI
                $monitoringStats.WMIProcesses = $processesMonitored
            }
            
            # Periodic cleanup
            if ((Get-Date) -gt $LastCleanup.AddSeconds($MapCleanupInterval)) {
                Cleanup-ProcessMap
                $LastCleanup = Get-Date
                
                # Log monitoring statistics
                $runtime = (Get-Date) - $monitoringStats.StartTime
                Write-Log -Message "Monitoring stats - Runtime: $($runtime.TotalHours.ToString('F1'))h | Process map size: $($ProcessMap.Count) | Sysmon events: $($monitoringStats.SysmonEvents) | WMI processes: $($monitoringStats.WMIProcesses)" -Level "INFO"
            }
            
        } catch {
            Write-Log -Level "ERROR" -Message "Process monitoring error: $($_.Exception.Message)"
        }
        
        Start-Sleep -Seconds 5  # More frequent monitoring for OT environments
    }
}

# ============================================================================
# INITIALIZATION AND STARTUP
# ============================================================================

# Ensure log directory exists
$logDir = Split-Path $LogFile
if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Initialize whitelist
Initialize-Whitelist

# Display OT-specific information
Write-Host @"

==============================================================
OT Process Correlation Monitor v1.0
==============================================================

This monitor is specifically designed for Operational Technology
environments and focuses on detecting unauthorized process spawning
that could indicate compromise of critical industrial systems.

WHITELISTING APPROACH:
- Uses a whitelist-based detection model to minimize false positives
- Whitelist file: $WhitelistFile
- Critical OT processes: $($CriticalOTProcesses.Count) defined
- Whitelist entries: $($script:Whitelist.Keys.Count) loaded

SYSMON INTEGRATION:
- Compatible with sysmon-config-comprehensive-updated.xml
- Uses Event ID 1 (Process Creation) for real-time monitoring
- Fallback to WMI if Sysmon unavailable

MONITORING FOCUS:
- HMI applications (Wonderware, WinCC, FactoryTalk, etc.)
- Engineering tools (Studio 5000, STEP 7, TIA Portal, etc.)
- Communication servers (KEPServerEX, RSLinx, etc.)
- SCADA systems and industrial protocols

Press Ctrl+C to stop monitoring...
==============================================================

"@ -ForegroundColor Cyan

# Start monitoring
Start-OTProcessMonitoring
