#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Unified Security Logger Service - All MITRE ATT&CK Detection Modules
.DESCRIPTION
    Single comprehensive service that combines all security detection capabilities
    - Compatible with PowerShell 3.0+ and Windows Server 2012+
    - CSV logging format for database integration
    - Multi-file logging strategy with correlation separation
    - Enhanced mobile device detection integration
.AUTHOR
    Custom Security Team
.VERSION
    1.0
#>

param(
    [Parameter()]
    [ValidateSet('Install', 'Uninstall', 'Start', 'Stop', 'Restart', 'Status', 'Run')]
    [string]$Action = 'Run',
    
    [Parameter()]
    [string]$ServiceName = 'CustomSecurityLogger',
    
    [Parameter()]
    [string]$ServiceDisplayName = 'Custom Security Logger Service',
    
    [Parameter()]
    [string]$ConfigPath = 'C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\service-config.json'
)

# ============================================================================
# GLOBAL CONFIGURATION AND CONSTANTS
# ============================================================================

# Event Deduplication System
$Global:EventDeduplicationCache = @{}
$Global:DeduplicationWindow = 10  # seconds
$Global:MaxCacheSize = 1000

$Global:ServiceConfig = @{
    LogBasePath = 'C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS'
    UnifiedLogFile = 'UnifiedSecurityEvents.csv'
    MaxLogSize = 100MB
    LogRotationDays = 30
    ServiceInterval = 5  # seconds
    CorrelationWindow = 900  # 15 minutes
    EnabledModules = @('InitialAccess', 'Execution', 'Persistence', 'PrivilegeEscalation', 
                       'DefenseEvasion', 'CredentialAccess', 'Discovery', 'LateralMovement',
                       'Collection', 'CommandAndControl', 'Exfiltration', 'Impact', 'USB', 'OT')
}

$Global:EventQueue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
$Global:CorrelationEvents = [System.Collections.Generic.List[object]]::new()
$Global:ServiceRunning = $false
$Global:LogWriters = @{}

# CSV Headers for unified log file
$Global:CSVHeaders = @{
    Unified = 'Timestamp,LogType,Severity,MITRE_Technique,Detection_Module,Event_Details,Company,Description,IntegrityLevel,LogonGuid,LogonId,ParentProcessGuid,ParentProcessId,ProcessGuid,ProcessId,Product,TerminalSessionId,User,EventID,UtcTime,host_name,node_id,parent_node_id,Image,FileVersion,ImageLoaded,OriginalFileName,Signature,SignatureStatus,Signed,EventType,RuleName,TargetObject,DestinationHostname,DestinationIp,DestinationPort,DestinationPortName,Initiated,Protocol,SourcePortName,TargetFilename,TargetProcessGuid,TargetImage,StartFunction,CreationUtcTime,PreviousCreationUtcTime,Command_Line,Source_IP,Dest_IP,File_Path,Registry_Key,Additional_Context'
}

# ============================================================================
# SERVICE MANAGEMENT FUNCTIONS
# ============================================================================

function Install-SecurityService {
    try {
        $servicePath = $MyInvocation.ScriptName
        $serviceArgs = "-ExecutionPolicy Bypass -File `"$servicePath`" -Action Run"
        
        # Create the service
        New-Service -Name $ServiceName -DisplayName $ServiceDisplayName -BinaryPathName "powershell.exe $serviceArgs" -StartupType Automatic -Description "Unified Security Logger for MITRE ATT&CK Detection"
        
        Write-Host "Service '$ServiceDisplayName' installed successfully." -ForegroundColor Green
        Write-Host "Use 'Start-Service $ServiceName' to start the service." -ForegroundColor Yellow
    }
    catch {
        Write-Error "Failed to install service: $($_.Exception.Message)"
    }
}

function Uninstall-SecurityService {
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Remove-Service -Name $ServiceName -ErrorAction Stop
        Write-Host "Service '$ServiceDisplayName' uninstalled successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to uninstall service: $($_.Exception.Message)"
    }
}

function Get-ServiceStatus {
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        Write-Host "Service Status: $($service.Status)" -ForegroundColor Cyan
        Write-Host "Service Name: $($service.Name)" -ForegroundColor White
        Write-Host "Display Name: $($service.DisplayName)" -ForegroundColor White
    }
    catch {
        Write-Host "Service '$ServiceName' not found or error occurred: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================================
# LOGGING INFRASTRUCTURE
# ============================================================================

function Initialize-LoggingSystem {
    try {
        # Create log directory if it doesn't exist
        if (!(Test-Path $Global:ServiceConfig.LogBasePath)) {
            New-Item -Path $Global:ServiceConfig.LogBasePath -ItemType Directory -Force | Out-Null
        }
        
        # Initialize unified log file with header
        $logFile = Join-Path $Global:ServiceConfig.LogBasePath $Global:ServiceConfig.UnifiedLogFile
        
        # Create file with header if it doesn't exist
        if (!(Test-Path $logFile)) {
            $Global:CSVHeaders.Unified | Out-File -FilePath $logFile -Encoding UTF8
        }
        
        # Initialize log writer
        $Global:LogWriters = @{
            Path = $logFile
            LastWrite = Get-Date
            EventCount = 0
        }
        
        Write-Host "Logging system initialized successfully - Output: $logFile" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to initialize logging system: $($_.Exception.Message)"
        throw
    }
}

function Write-SecurityEvent {
    param(
        [Parameter(Mandatory)]
        [string]$LogType,
        
        [Parameter(Mandatory)]
        [hashtable]$EventData,
        
        [switch]$SkipDeduplication
    )
    
    try {
        # Event Deduplication with null value protection
        if (-not $SkipDeduplication) {
            # Safe event hash generation - handle null values
            $mitreTechnique = if ($EventData.MitreTechnique) { $EventData.MitreTechnique } else { "UNKNOWN" }
            $processID = if ($EventData.ProcessID) { $EventData.ProcessID } else { "0" }
            $eventDetails = if ($EventData.EventDetails) { $EventData.EventDetails } else { "NO_DETAILS" }
            
            $eventHash = "$mitreTechnique-$processID-$eventDetails"
            $currentTime = Get-Date
            
            # Ensure hash is not null or empty
            if ([string]::IsNullOrWhiteSpace($eventHash)) {
                $eventHash = "UNKNOWN-$(Get-Random)-$currentTime"
            }
            
            # Clean old entries from cache
            $expiredKeys = @()
            foreach ($key in $Global:EventDeduplicationCache.Keys) {
                if (($currentTime - $Global:EventDeduplicationCache[$key]).TotalSeconds -gt $Global:DeduplicationWindow) {
                    $expiredKeys += $key
                }
            }
            foreach ($key in $expiredKeys) {
                $Global:EventDeduplicationCache.Remove($key)
            }
            
            # Check if event is duplicate
            if ($Global:EventDeduplicationCache.ContainsKey($eventHash)) {
                return  # Skip duplicate event
            }
            
            # Add to cache
            if ($Global:EventDeduplicationCache.Count -lt $Global:MaxCacheSize) {
                $Global:EventDeduplicationCache[$eventHash] = $currentTime
            }
        }
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        
        # Build unified CSV row - all events go to same file with LogType column
        $csvRow = "$timestamp," +
                  "$LogType," +
                  "$($EventData.Severity)," +
                  "$($EventData.MitreTechnique)," +
                  "$($EventData.DetectionModule)," +
                  "`"$($EventData.EventDetails -replace '"', '""')`"," +
                  "`"$($EventData.Company -replace '"', '""')`"," +
                  "`"$($EventData.Description -replace '"', '""')`"," +
                  "`"$($EventData.IntegrityLevel -replace '"', '""')`"," +
                  "`"$($EventData.LogonGuid -replace '"', '""')`"," +
                  "`"$($EventData.LogonId -replace '"', '""')`"," +
                  "`"$($EventData.ParentProcessGuid -replace '"', '""')`"," +
                  "$($EventData.ParentProcessId)," +
                  "`"$($EventData.ProcessGuid -replace '"', '""')`"," +
                  "$($EventData.ProcessID)," +
                  "`"$($EventData.Product -replace '"', '""')`"," +
                  "$($EventData.TerminalSessionId)," +
                  "$($EventData.User)," +
                  "$($EventData.EventID)," +
                  "`"$($EventData.UtcTime -replace '"', '""')`"," +
                  "`"$($EventData.HostName -replace '"', '""')`"," +
                  "`"$($EventData.NodeId -replace '"', '""')`"," +
                  "`"$($EventData.ParentNodeId -replace '"', '""')`"," +
                  "`"$($EventData.Image -replace '"', '""')`"," +
                  "`"$($EventData.FileVersion -replace '"', '""')`"," +
                  "`"$($EventData.ImageLoaded -replace '"', '""')`"," +
                  "`"$($EventData.OriginalFileName -replace '"', '""')`"," +
                  "`"$($EventData.Signature -replace '"', '""')`"," +
                  "`"$($EventData.SignatureStatus -replace '"', '""')`"," +
                  "`"$($EventData.Signed -replace '"', '""')`"," +
                  "`"$($EventData.EventType -replace '"', '""')`"," +
                  "`"$($EventData.RuleName -replace '"', '""')`"," +
                  "`"$($EventData.TargetObject -replace '"', '""')`"," +
                  "`"$($EventData.DestinationHostname -replace '"', '""')`"," +
                  "`"$($EventData.DestinationIp -replace '"', '""')`"," +
                  "$($EventData.DestinationPort)," +
                  "`"$($EventData.DestinationPortName -replace '"', '""')`"," +
                  "`"$($EventData.Initiated -replace '"', '""')`"," +
                  "`"$($EventData.Protocol -replace '"', '""')`"," +
                  "`"$($EventData.SourcePortName -replace '"', '""')`"," +
                  "`"$($EventData.TargetFilename -replace '"', '""')`"," +
                  "`"$($EventData.TargetProcessGuid -replace '"', '""')`"," +
                  "`"$($EventData.TargetImage -replace '"', '""')`"," +
                  "`"$($EventData.StartFunction -replace '"', '""')`"," +
                  "`"$($EventData.CreationUtcTime -replace '"', '""')`"," +
                  "`"$($EventData.PreviousCreationUtcTime -replace '"', '""')`"," +
                  "`"$($EventData.ProcessName -replace '"', '""')`"," +
                  "$($EventData.SourceIP)," +
                  "$($EventData.DestIP)," +
                  "`"$($EventData.FilePath -replace '"', '""')`"," +
                  "`"$($EventData.RegistryKey -replace '"', '""')`"," +
                  "`"$($EventData.AdditionalContext -replace '"', '""')`""
        
        # Write to unified log file
        $logFile = $Global:LogWriters.Path
        $csvRow | Out-File -FilePath $logFile -Append -Encoding UTF8
        
        # Update statistics
        $Global:LogWriters.EventCount++
        $Global:LogWriters.LastWrite = Get-Date
        
        # Check for log rotation
        if ((Get-Item $logFile).Length -gt $Global:ServiceConfig.MaxLogSize) {
            Invoke-LogRotation
        }
    }
    catch {
        Write-Error "Failed to write security event: $($_.Exception.Message)"
    }
}

function Write-RawWindowsEvent {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event,
        
        [Parameter(Mandatory)]
        [string]$LogType,
        
        [string]$DetectionModule = "WindowsEventLog",
        [string]$Severity = "INFO"
    )
    
    try {
        $xml = [xml]$Event.ToXml()
        $eventData = @{}
        
        # Extract event data from XML
        if ($xml.Event.EventData.Data) {
            foreach ($data in $xml.Event.EventData.Data) {
                if ($data.Name) { 
                    $eventData[$data.Name] = $data.'#text' 
                }
            }
        }
        
        # Helper function to safely get field value
        function Get-SafeValue {
            param($Field, $Default = "")
            if ($Field) { return $Field } else { return $Default }
        }
        
        # Create unified event record with all requested fields
        $unifiedEvent = @{
            Severity = $Severity
            MitreTechnique = "N/A"
            DetectionModule = $DetectionModule
            EventDetails = "EventID: $($Event.Id), LogName: $($Event.LogName)"
            
            # Core process information
            Company = Get-SafeValue $eventData["Company"]
            Description = Get-SafeValue $eventData["Description"]
            IntegrityLevel = Get-SafeValue $eventData["IntegrityLevel"]
            LogonGuid = Get-SafeValue $eventData["LogonGuid"]
            LogonId = Get-SafeValue $eventData["LogonId"]
            ParentProcessGuid = Get-SafeValue $eventData["ParentProcessGuid"]
            ParentProcessId = Get-SafeValue $eventData["ParentProcessId"]
            ProcessGuid = Get-SafeValue $eventData["ProcessGuid"]
            ProcessID = Get-SafeValue $eventData["ProcessId"]
            Product = Get-SafeValue $eventData["Product"]
            TerminalSessionId = Get-SafeValue $eventData["TerminalSessionId"]
            User = Get-SafeValue ($eventData["User"] -or $eventData["SubjectUserName"])
            EventID = $Event.Id
            UtcTime = Get-SafeValue $eventData["UtcTime"]
            HostName = $Event.MachineName
            NodeId = Get-SafeValue $eventData["node_id"]
            ParentNodeId = Get-SafeValue $eventData["parent_node_id"]
            
            # Image and file information
            Image = Get-SafeValue ($eventData["Image"] -or $eventData["ProcessName"])
            FileVersion = Get-SafeValue $eventData["FileVersion"]
            ImageLoaded = Get-SafeValue $eventData["ImageLoaded"]
            OriginalFileName = Get-SafeValue $eventData["OriginalFileName"]
            Signature = Get-SafeValue $eventData["Signature"]
            SignatureStatus = Get-SafeValue $eventData["SignatureStatus"]
            Signed = Get-SafeValue $eventData["Signed"]
            
            # Event type and rules
            EventType = Get-SafeValue $eventData["EventType"]
            RuleName = Get-SafeValue $eventData["RuleName"]
            TargetObject = Get-SafeValue $eventData["TargetObject"]
            
            # Network information
            DestinationHostname = Get-SafeValue $eventData["DestinationHostname"]
            DestinationIp = Get-SafeValue ($eventData["DestinationIp"] -or $eventData["DestinationAddress"])
            DestinationPort = Get-SafeValue $eventData["DestinationPort"]
            DestinationPortName = Get-SafeValue $eventData["DestinationPortName"]
            Initiated = Get-SafeValue $eventData["Initiated"]
            Protocol = Get-SafeValue $eventData["Protocol"]
            SourcePortName = Get-SafeValue $eventData["SourcePortName"]
            
            # File and target information
            TargetFilename = Get-SafeValue $eventData["TargetFilename"]
            TargetProcessGuid = Get-SafeValue $eventData["TargetProcessGuid"]
            TargetImage = Get-SafeValue $eventData["TargetImage"]
            StartFunction = Get-SafeValue $eventData["StartFunction"]
            CreationUtcTime = Get-SafeValue $eventData["CreationUtcTime"]
            PreviousCreationUtcTime = Get-SafeValue $eventData["PreviousCreationUtcTime"]
            
            # Legacy fields for compatibility
            ProcessName = Get-SafeValue ($eventData["Image"] -or $eventData["ProcessName"])
            SourceIP = Get-SafeValue ($eventData["SourceAddress"] -or $eventData["IpAddress"])
            DestIP = Get-SafeValue ($eventData["DestinationIp"] -or $eventData["DestinationAddress"])
            FilePath = Get-SafeValue ($eventData["TargetFilename"] -or $eventData["ObjectName"])
            RegistryKey = Get-SafeValue $eventData["TargetObject"]
            AdditionalContext = "TimeCreated: $($Event.TimeCreated), RecordId: $($Event.RecordId), MachineName: $($Event.MachineName), CommandLine: $(Get-SafeValue $eventData['CommandLine'])"
        }
        
        Write-SecurityEvent -LogType $LogType -EventData $unifiedEvent -SkipDeduplication
    }
    catch {
        Write-Error "Failed to write raw Windows event: $($_.Exception.Message)"
    }
}

function Invoke-LogRotation {
    try {
        $logFile = $Global:LogWriters.Path
        $backupFile = $logFile -replace '\.csv$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        # Rename current log
        Rename-Item -Path $logFile -NewName $backupFile
        
        # Create new log with header
        $Global:CSVHeaders.Unified | Out-File -FilePath $logFile -Encoding UTF8
        
        Write-Host "Log rotation completed - New file: $logFile, Backup: $backupFile" -ForegroundColor Yellow
    }
    catch {
        Write-Error "Log rotation failed: $($_.Exception.Message)"
    }
}

# ============================================================================
# MITRE ATT&CK DETECTION MODULES
# ============================================================================

function Start-InitialAccessDetection {
    try {
        # Get events with proper error handling - log all relevant events for analysis
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,11)} -MaxEvents 100 -ErrorAction SilentlyContinue
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4624,4625)} -MaxEvents 100 -ErrorAction SilentlyContinue
        
        # Log all Sysmon process creation events for analysis
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                if ($event.Id -eq 1) {
                    # Log process creation events
                    Write-RawWindowsEvent -Event $event -LogType "ProcessCreation" -DetectionModule "InitialAccess" -Severity "INFO"
                } elseif ($event.Id -eq 11) {
                    # Log file creation events
                    Write-RawWindowsEvent -Event $event -LogType "FileCreation" -DetectionModule "InitialAccess" -Severity "INFO"
                }
            }
        }
        
        # Log all Security events for analysis
        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                if ($event.Id -eq 4624) {
                    # Log successful logons
                    Write-RawWindowsEvent -Event $event -LogType "SuccessfulLogon" -DetectionModule "InitialAccess" -Severity "INFO"
                } elseif ($event.Id -eq 4625) {
                    # Log failed logons
                    Write-RawWindowsEvent -Event $event -LogType "FailedLogon" -DetectionModule "InitialAccess" -Severity "WARNING"
                }
            }
        }
    }
    catch {
        Write-Error "InitialAccess detection error: $($_.Exception.Message)"
    }
}

function Start-ExecutionDetection {
    try {
        # Log Sysmon process execution events
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                Write-RawWindowsEvent -Event $event -LogType "ProcessExecution" -DetectionModule "Execution" -Severity "INFO"
            }
        }
        
        # Log Security process creation events  
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                Write-RawWindowsEvent -Event $event -LogType "ProcessCreation" -DetectionModule "Execution" -Severity "INFO"
            }
        }
    }
    catch {
        Write-Error "Execution detection error: $($_.Exception.Message)"
    }
}

function Start-PersistenceDetection {
    try {
        # Log Sysmon registry events
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(11,12,13,14)} -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                if ($event.Id -eq 11) {
                    Write-RawWindowsEvent -Event $event -LogType "FileCreation" -DetectionModule "Persistence" -Severity "INFO"
                } else {
                    Write-RawWindowsEvent -Event $event -LogType "RegistryModification" -DetectionModule "Persistence" -Severity "INFO"
                }
            }
        }
        
        # Log service creation events
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4697,4698)} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                Write-RawWindowsEvent -Event $event -LogType "ServiceCreation" -DetectionModule "Persistence" -Severity "WARNING"
            }
        }
        
        # Log system service events
        $systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} -MaxEvents 20 -ErrorAction SilentlyContinue
        if ($systemEvents) {
            foreach ($event in $systemEvents) {
                Write-RawWindowsEvent -Event $event -LogType "ServiceInstall" -DetectionModule "Persistence" -Severity "WARNING"
            }
        }
    }
    catch {
        Write-Error "Persistence detection error: $($_.Exception.Message)"
    }
}

function Start-DefenseEvasionDetection {
    try {
        # Log Sysmon events related to defense evasion
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,5,7,8,10,15)} -MaxEvents 200 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                $logType = switch ($event.Id) {
                    1 { "ProcessCreation" }
                    5 { "ProcessTermination" }
                    7 { "ImageLoaded" }
                    8 { "CreateRemoteThread" }
                    10 { "ProcessAccess" }
                    15 { "FileCreateStreamHash" }
                }
                Write-RawWindowsEvent -Event $event -LogType $logType -DetectionModule "DefenseEvasion" -Severity "INFO"
            }
        }
    }
    catch {
        Write-Error "DefenseEvasion detection error: $($_.Exception.Message)"
    }
}

function Start-DiscoveryDetection {
    try {
        # Log Sysmon process creation for discovery commands
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                Write-RawWindowsEvent -Event $event -LogType "ProcessCreation" -DetectionModule "Discovery" -Severity "INFO"
            }
        }
    }
    catch {
        Write-Error "Discovery detection error: $($_.Exception.Message)"
    }
}

function Start-USBThreatDetection {
    try {
        # Log system events for USB devices
        $systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=@(20001,20003,4001)} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($systemEvents) {
            foreach ($event in $systemEvents) {
                Write-RawWindowsEvent -Event $event -LogType "USBDeviceEvent" -DetectionModule "USB" -Severity "INFO"
            }
        }
    }
    catch {
        Write-Error "USB detection error: $($_.Exception.Message)"
    }
}

function Start-CredentialAccessDetection {
    try {
        # Log Sysmon process access events (LSASS access)
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=10} -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                Write-RawWindowsEvent -Event $event -LogType "ProcessAccess" -DetectionModule "CredentialAccess" -Severity "WARNING"
            }
        }
        
        # Log Security logon events
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4624,4625,4648)} -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                $logType = switch ($event.Id) {
                    4624 { "LogonSuccess" }
                    4625 { "LogonFailure" }
                    4648 { "ExplicitLogon" }
                }
                Write-RawWindowsEvent -Event $event -LogType $logType -DetectionModule "CredentialAccess" -Severity "INFO"
            }
        }
    }
    catch {
        Write-Error "CredentialAccess detection error: $($_.Exception.Message)"
    }
}

function Start-LateralMovementDetection {
    try {
        # Log Security logon events for lateral movement
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4624,4625,4778,4779)} -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                Write-RawWindowsEvent -Event $event -LogType "NetworkLogon" -DetectionModule "LateralMovement" -Severity "INFO"
            }
        }
        
        # Log WinRM events
        $winrmEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'; ID=@(91,168)} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($winrmEvents) {
            foreach ($event in $winrmEvents) {
                Write-RawWindowsEvent -Event $event -LogType "WinRMActivity" -DetectionModule "LateralMovement" -Severity "INFO"
            }
        }
    }
    catch {
        Write-Error "LateralMovement detection error: $($_.Exception.Message)"
    }
}

function Start-CollectionDetection {
    try {
        # Log Sysmon events for data collection
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,7,11)} -MaxEvents 200 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                $logType = switch ($event.Id) {
                    1 { "ProcessCreation" }
                    7 { "ImageLoaded" }
                    11 { "FileCreation" }
                }
                Write-RawWindowsEvent -Event $event -LogType $logType -DetectionModule "Collection" -Severity "INFO"
            }
        }
    }
    catch {
        Write-Error "Collection detection error: $($_.Exception.Message)"
    }
}

function Start-CommandAndControlDetection {
    try {
        # Log Sysmon network connections
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,3,22)} -MaxEvents 200 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                $logType = switch ($event.Id) {
                    1 { "ProcessCreation" }
                    3 { "NetworkConnection" }
                    22 { "DNSQuery" }
                }
                Write-RawWindowsEvent -Event $event -LogType $logType -DetectionModule "CommandAndControl" -Severity "INFO"
            }
        }
    }
    catch {
        Write-Error "CommandAndControl detection error: $($_.Exception.Message)"
    }
}

function Start-ExfiltrationDetection {
    try {
        # Log Sysmon events for exfiltration
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,3,11,22,23)} -MaxEvents 200 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                $logType = switch ($event.Id) {
                    1 { "ProcessCreation" }
                    3 { "NetworkConnection" }
                    11 { "FileCreation" }
                    22 { "DNSQuery" }
                    23 { "FileDeletion" }
                }
                Write-RawWindowsEvent -Event $event -LogType $logType -DetectionModule "Exfiltration" -Severity "INFO"
            }
        }
        
        # Log Task Scheduler events
        $taskEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; ID=@(106,200,201)} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($taskEvents) {
            foreach ($event in $taskEvents) {
                Write-RawWindowsEvent -Event $event -LogType "TaskScheduler" -DetectionModule "Exfiltration" -Severity "INFO"
            }
        }
    }
    catch {
        Write-Error "Exfiltration detection error: $($_.Exception.Message)"
    }
}

function Start-ImpactDetection {
    try {
        # Log Sysmon events for impact
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,11,23)} -MaxEvents 200 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                $logType = switch ($event.Id) {
                    1 { "ProcessCreation" }
                    11 { "FileCreation" }
                    23 { "FileDeletion" }
                }
                Write-RawWindowsEvent -Event $event -LogType $logType -DetectionModule "Impact" -Severity "INFO"
            }
        }
        
        # Log Security account events
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4725,4726,4740,4767,4794)} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                Write-RawWindowsEvent -Event $event -LogType "AccountModification" -DetectionModule "Impact" -Severity "WARNING"
            }
        }
        
        # Log System service events
        $systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=@(7034,7035,7036,7040,6005,6006,6008,6013)} -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($systemEvents) {
            foreach ($event in $systemEvents) {
                $logType = switch ($event.Id) {
                    7034 { "ServiceCrash" }
                    7035 { "ServiceControl" }
                    7036 { "ServiceStateChange" }
                    7040 { "ServiceStartTypeChange" }
                    6005 { "SystemStart" }
                    6006 { "SystemShutdown" }
                    6008 { "UnexpectedShutdown" }
                    6013 { "SystemUptime" }
                }
                Write-RawWindowsEvent -Event $event -LogType $logType -DetectionModule "Impact" -Severity "INFO"
            }
        }
        
        # Log Application events
        $appEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; ID=@(1000,1001,1002)} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($appEvents) {
            foreach ($event in $appEvents) {
                Write-RawWindowsEvent -Event $event -LogType "ApplicationCrash" -DetectionModule "Impact" -Severity "WARNING"
            }
        }
    }
    catch {
        Write-Error "Impact detection error: $($_.Exception.Message)"
    }
}

function Start-PrivilegeEscalationDetection {
    try {
        # Log Sysmon events for privilege escalation
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,10,12,13,14)} -MaxEvents 200 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                $logType = switch ($event.Id) {
                    1 { "ProcessCreation" }
                    10 { "ProcessAccess" }
                    12 { "RegistryKeyCreated" }
                    13 { "RegistryValueSet" }
                    14 { "RegistryKeyRenamed" }
                }
                Write-RawWindowsEvent -Event $event -LogType $logType -DetectionModule "PrivilegeEscalation" -Severity "INFO"
            }
        }
        
        # Log Security privilege events
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4648,4672,4673)} -MaxEvents 100 -ErrorAction SilentlyContinue
        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                $logType = switch ($event.Id) {
                    4648 { "ExplicitLogon" }
                    4672 { "SpecialLogon" }
                    4673 { "PrivilegedService" }
                }
                Write-RawWindowsEvent -Event $event -LogType $logType -DetectionModule "PrivilegeEscalation" -Severity "WARNING"
            }
        }
    }
    catch {
        Write-Error "PrivilegeEscalation detection error: $($_.Exception.Message)"
    }
}
            "regasm\.exe" = @("/u", "\.dll")
            "regsvcs\.exe" = @("/u", "\.dll")
        }
        
        # Process Sysmon events
        foreach ($event in $sysmonEvents) {
            $xml = [xml]$event.ToXml()
            $eventData = @{}
            foreach ($data in $xml.Event.EventData.Data) {
                if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
            }
            
            $image = $eventData["Image"]
            $commandLine = $eventData["CommandLine"]
            $parentImage = $eventData["ParentImage"]
            $processId = $eventData["ProcessId"]
            $user = $eventData["User"]
            $processGuid = $eventData["ProcessGuid"]
            $hashes = $eventData["Hashes"]
            
            # T1059 - Command and Scripting Interpreter
            foreach ($interpreter in $scriptInterpreters) {
                if ($image -match $interpreter) {
                    $detected = $false
                    $matchedArgs = @()
                    
                    foreach ($arg in $suspiciousArgs) {
                        if ($commandLine -match $arg) {
                            $detected = $true
                            $matchedArgs += $arg
                        }
                    }
                    
                    if ($detected) {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1059'
                            DetectionModule = 'Execution'
                            EventDetails = 'Suspicious script interpreter execution detected'
                            ProcessID = $processId
                            ProcessName = $image
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Parent: $parentImage, SuspiciousArgs: $($matchedArgs -join ', '), ProcessGuid: $processGuid, Hashes: $hashes"
                        }
                    }
                }
            }
            
            # T1203 - Exploitation for Client Execution
            $officeApps = @("winword\.exe", "excel\.exe", "powerpnt\.exe", "acrord32\.exe", "acrobat\.exe")
            $browserApps = @("chrome\.exe", "firefox\.exe", "msedge\.exe", "iexplore\.exe")
            
            # Office applications spawning processes
            foreach ($office in $officeApps) {
                if ($parentImage -match $office) {
                    if ($image -match "powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe|dllhost\.exe") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'CRITICAL'
                            MitreTechnique = 'T1203'
                            DetectionModule = 'Execution'
                            EventDetails = 'Office application spawned suspicious process'
                            ProcessID = $processId
                            ProcessName = $image
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "OfficeApp: $parentImage"
                        }
                    }
                }
            }
            
            # Browser applications spawning processes
            foreach ($browser in $browserApps) {
                if ($parentImage -match $browser) {
                    if ($image -match "powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1203'
                            DetectionModule = 'Execution'
                            EventDetails = 'Browser spawned suspicious process'
                            ProcessID = $processId
                            ProcessName = $image
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Browser: $parentImage"
                        }
                    }
                }
            }
            
            # T1218 - System Binary Proxy Execution
            foreach ($binary in $lolbins.Keys) {
                if ($image -match $binary) {
                    $suspicious = $false
                    $matchedIndicators = @()
                    
                    foreach ($indicator in $lolbins[$binary]) {
                        if ($commandLine -match $indicator) {
                            $suspicious = $true
                            $matchedIndicators += $indicator
                        }
                    }
                    
                    if ($suspicious) {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1218'
                            DetectionModule = 'Execution'
                            EventDetails = 'Living-off-the-land binary execution detected'
                            ProcessID = $processId
                            ProcessName = $image
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "MatchedIndicators: $($matchedIndicators -join ', ')"
                        }
                    }
                }
            }
            
            # T1204 - User Execution
            # Monitor execution from temp/downloads directories
            if ($image -match "\\Temp\\|\\Downloads\\|\\AppData\\Local\\Temp\\") {
                Write-SecurityEvent -LogType 'Main' -EventData @{
                    Severity = 'WARNING'
                    MitreTechnique = 'T1204'
                    DetectionModule = 'Execution'
                    EventDetails = 'Process executed from temporary directory'
                    ProcessID = $processId
                    ProcessName = $image
                    CommandLine = $commandLine
                    User = $user
                    SourceIP = ''
                    DestIP = ''
                    FilePath = $image
                    RegistryKey = ''
                    AdditionalContext = "Location: Temporary Directory"
                }
            }
            
            # Monitor files with double extensions
            if ($image -match "\.(pdf|doc|docx|xls|xlsx|txt)\.(exe|scr|com|bat)$") {
                Write-SecurityEvent -LogType 'Main' -EventData @{
                    Severity = 'CRITICAL'
                    MitreTechnique = 'T1204'
                    DetectionModule = 'Execution'
                    EventDetails = 'Execution of file with double extension'
                    ProcessID = $processId
                    ProcessName = $image
                    CommandLine = $commandLine
                    User = $user
                    SourceIP = ''
                    DestIP = ''
                    FilePath = $image
                    RegistryKey = ''
                    AdditionalContext = "DoubleExtension: True"
                }
            }
        }
        
        # Process Security log events (Event ID 4688 - Process Creation)
        foreach ($event in $securityEvents) {
            $xml = [xml]$event.ToXml()
            $eventData = @{}
            foreach ($data in $xml.Event.EventData.Data) {
                if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
            }
            
            $newProcessName = $eventData["NewProcessName"]
            $commandLine = $eventData["CommandLine"]
            $subjectUserName = $eventData["SubjectUserName"]
            $newProcessId = $eventData["NewProcessId"]
            
            # Log high-value process creation from Security log
            if ($newProcessName -match "powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe") {
                Write-SecurityEvent -LogType 'Main' -EventData @{
                    Severity = 'INFO'
                    MitreTechnique = 'T1059'
                    DetectionModule = 'Execution'
                    EventDetails = 'Script interpreter process created (Security Log)'
                    ProcessID = $newProcessId
                    ProcessName = $newProcessName
                    CommandLine = $commandLine
                    User = $subjectUserName
                    SourceIP = ''
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "Source: SecurityEventLog"
                }
            }
        }
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'Execution'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-PersistenceDetection {
    try {
        # Get events with proper error handling
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(11,12,13,14,19,20,21)} -MaxEvents 200 -ErrorAction SilentlyContinue
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4697,4698)} -MaxEvents 50 -ErrorAction SilentlyContinue
        $systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} -MaxEvents 20 -ErrorAction SilentlyContinue
        
        # Autostart registry keys to monitor
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
        
        # Hijack registry keys to monitor
        $hijackKeys = @(
            "Image File Execution Options",
            "Classes\\CLSID",
            "Classes\\Folder\\shell",
            "Classes\\exefile\\shell"
        )
        
        # Startup paths to monitor
        $startupPaths = @(
            "\\Start Menu\\Programs\\Startup",
            "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        )
        
        # Process Sysmon events
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                $xml = [xml]$event.ToXml()
                $eventData = @{}
                foreach ($data in $xml.Event.EventData.Data) {
                    if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
                }
                
                # T1547 - Boot or Logon Autostart Execution (Registry Events 12,13,14)
                if ($event.Id -in @(12,13,14)) {
                    $targetObject = $eventData["TargetObject"]
                    $processName = $eventData["Image"]
                    $processId = $eventData["ProcessId"]
                    $details = $eventData["Details"]
                    $user = $eventData["User"]
                    
                    foreach ($key in $autostartKeys) {
                        if ($targetObject -match $key) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1547'
                                DetectionModule = 'Persistence'
                                EventDetails = 'Autostart registry key modified'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = $targetObject
                                AdditionalContext = "Value: $details, EventID: $($event.Id)"
                            }
                        }
                    }
                    
                    # T1053 - Scheduled Tasks (Registry changes)
                    if ($targetObject -match "Schedule\\TaskCache") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1053'
                            DetectionModule = 'Persistence'
                            EventDetails = 'Task Scheduler registry modified'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = $targetObject
                            AdditionalContext = "Operation: Registry modification"
                        }
                    }
                    
                    # T1543.003 - Windows Service (Registry changes) - FILTERED
                    if ($targetObject -match "ControlSet\\Services\\") {
                        # Filter out legitimate system operations
                        $isLegitimate = $false
                        
                        # BAM (Background Activity Moderator) entries are normal system behavior
                        if ($targetObject -match "Services\\bam\\State\\UserSettings") { $isLegitimate = $true }
                        
                        # Windows Update service operations
                        if ($targetObject -match "Services\\(wuauserv|UsoSvc|WaaSMedicSvc)\\") { $isLegitimate = $true }
                        
                        # System service normal operations
                        if ($targetObject -match "Services\\(Themes|AudioSrv|BITS|Winmgmt|EventLog)\\") { $isLegitimate = $true }
                        
                        # Only log if not legitimate system operation
                        if (-not $isLegitimate) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1543.003'
                                DetectionModule = 'Persistence'
                                EventDetails = 'Suspicious service registry modification'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = $targetObject
                                AdditionalContext = "Value: $details"
                            }
                        }
                    }
                    
                    # T1546 - Event Triggered Execution (Registry hijacking)
                    foreach ($hijackKey in $hijackKeys) {
                        if ($targetObject -match $hijackKey) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1546'
                                DetectionModule = 'Persistence'
                                EventDetails = 'Potential execution hijacking detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = $targetObject
                                AdditionalContext = "Value: $details, HijackType: $hijackKey"
                            }
                        }
                    }
                }
                
                # T1547.001 - Registry Run Keys / Startup Folder (File Creation Event 11)
                if ($event.Id -eq 11) {
                    $targetFilename = $eventData["TargetFilename"]
                    $processName = $eventData["Image"]
                    $processId = $eventData["ProcessId"]
                    $user = $eventData["User"]
                    
                    foreach ($path in $startupPaths) {
                        if ($targetFilename -match [regex]::Escape($path)) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1547.001'
                                DetectionModule = 'Persistence'
                                EventDetails = 'File created in startup directory'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $targetFilename
                                RegistryKey = ''
                                AdditionalContext = "StartupLocation: $path"
                            }
                        }
                    }
                }
                
                # T1546.003 - Windows Management Instrumentation Event Subscription (WMI Events 19,20,21)
                if ($event.Id -in @(19,20,21)) {
                    $operation = $eventData["Operation"]
                    $processName = $eventData["Image"]
                    $processId = $eventData["ProcessId"]
                    $user = $eventData["User"]
                    $eventType = $eventData["EventType"]
                    $consumer = $eventData["Consumer"]
                    $query = $eventData["Query"]
                    
                    if ($operation -eq "Created" -or $event.Id -eq 19) {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1546.003'
                            DetectionModule = 'Persistence'
                            EventDetails = 'WMI Event Subscription created'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "EventType: $eventType, Consumer: $consumer, Query: $query"
                        }
                    }
                }
            }
        }
        
        # Process Security events
        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                $xml = [xml]$event.ToXml()
                $eventData = @{}
                foreach ($data in $xml.Event.EventData.Data) {
                    if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
                }
                
                # T1053 - Scheduled Task Created (Event 4698)
                if ($event.Id -eq 4698) {
                    $taskName = $eventData["TaskName"]
                    $subjectUserName = $eventData["SubjectUserName"]
                    $taskContent = $eventData["TaskContent"]
                    
                    Write-SecurityEvent -LogType 'Main' -EventData @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1053'
                        DetectionModule = 'Persistence'
                        EventDetails = 'Scheduled task created'
                        ProcessID = ''
                        ProcessName = ''
                        CommandLine = ''
                        User = $subjectUserName
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "TaskName: $taskName, Content: $([System.Text.RegularExpressions.Regex]::Replace($taskContent, '\s+', ' '))"
                    }
                }
                
                # T1543.003 - Service Installed (Event 4697)
                if ($event.Id -eq 4697) {
                    $serviceName = $eventData["ServiceName"]
                    $serviceFileName = $eventData["ServiceFileName"]
                    $subjectUserName = $eventData["SubjectUserName"]
                    $serviceType = $eventData["ServiceType"]
                    
                    Write-SecurityEvent -LogType 'Main' -EventData @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1543.003'
                        DetectionModule = 'Persistence'
                        EventDetails = 'Service installed by user'
                        ProcessID = ''
                        ProcessName = ''
                        CommandLine = ''
                        User = $subjectUserName
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $serviceFileName
                        RegistryKey = ''
                        AdditionalContext = "ServiceName: $serviceName, ServiceType: $serviceType"
                    }
                }
            }
        }
        
        # Process System events
        if ($systemEvents) {
            foreach ($event in $systemEvents) {
                $xml = [xml]$event.ToXml()
                $eventData = @{}
                foreach ($data in $xml.Event.EventData.Data) {
                    if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
                }
                
                # T1543.003 - New Service Installed (System Event 7045)
                if ($event.Id -eq 7045) {
                    $serviceName = $eventData["ServiceName"]
                    $imagePath = $eventData["ImagePath"]
                    $serviceType = $eventData["ServiceType"]
                    $accountName = $eventData["AccountName"]
                    
                    Write-SecurityEvent -LogType 'Main' -EventData @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1543.003'
                        DetectionModule = 'Persistence'
                        EventDetails = 'New service installed'
                        ProcessID = ''
                        ProcessName = ''
                        CommandLine = ''
                        User = $accountName
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $imagePath
                        RegistryKey = ''
                        AdditionalContext = "ServiceName: $serviceName, ServiceType: $serviceType"
                    }
                }
            }
        }
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'Persistence'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-DefenseEvasionDetection {
    try {
        # Get events from multiple sources with error handling
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,8,10,11,12,13,14,23)} -MaxEvents 200 -ErrorAction SilentlyContinue
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4624,4625,4648,4672,4673,4719,4739,4946,4947,4948,4949)} -MaxEvents 100 -ErrorAction SilentlyContinue
        
        # T1134 - Access Token Manipulation
        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                $xml = [xml]$event.ToXml()
                $eventData = @{}
                foreach ($data in $xml.Event.EventData.Data) {
                    if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
                }
                
                # Detect token manipulation patterns
                if ($event.Id -eq 4648 -and $eventData["TargetUserName"] -and $eventData["SubjectUserName"]) {
                    if ($eventData["TargetUserName"] -ne $eventData["SubjectUserName"]) {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1134.001'
                            DetectionModule = 'DefenseEvasion'
                            EventDetails = 'Potential token manipulation detected'
                            ProcessID = $eventData["ProcessId"]
                            ProcessName = $eventData["ProcessName"]
                            CommandLine = ''
                            User = $eventData["SubjectUserName"]
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Target: $($eventData['TargetUserName']), LogonId: $($eventData['SubjectLogonId'])"
                        }
                    }
                }
                
                if ($event.Id -eq 4672 -and $eventData["PrivilegeList"]) {
                    if ($eventData["PrivilegeList"] -match "SeDebugPrivilege|SeImpersonatePrivilege") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1134'
                            DetectionModule = 'DefenseEvasion'
                            EventDetails = 'Sensitive privilege assignment detected'
                            ProcessID = $eventData["ProcessId"]
                            ProcessName = $eventData["ProcessName"]
                            CommandLine = ''
                            User = $eventData["SubjectUserName"]
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Privileges: $($eventData['PrivilegeList'])"
                        }
                    }
                }
                
                # T1562.002 - Disable Windows Event Logging
                if ($event.Id -in @(4719, 4739, 4946, 4947, 4948, 4949)) {
                    Write-SecurityEvent -LogType 'Main' -EventData @{
                        Severity = 'CRITICAL'
                        MitreTechnique = 'T1562.002'
                        DetectionModule = 'DefenseEvasion'
                        EventDetails = 'Security policy modification detected'
                        ProcessID = $eventData["ProcessId"]
                        ProcessName = $eventData["ProcessName"]
                        CommandLine = ''
                        User = $eventData["SubjectUserName"]
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "EventID: $($event.Id)"
                    }
                }
            }
        }
        
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                $xml = [xml]$event.ToXml()
                $eventData = @{}
                foreach ($data in $xml.Event.EventData.Data) {
                    if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
                }
                
                # T1055 - Process Injection
                if ($event.Id -eq 8 -and $eventData["TargetImage"]) {
                    Write-SecurityEvent -LogType 'Main' -EventData @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1055'
                        DetectionModule = 'DefenseEvasion'
                        EventDetails = 'Cross-process thread creation detected'
                        ProcessID = $eventData["SourceProcessId"]
                        ProcessName = $eventData["SourceImage"]
                        CommandLine = ''
                        User = $eventData["User"]
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "Target: $($eventData['TargetImage']), GUID: $($eventData['SourceProcessGuid'])"
                    }
                }
                
                if ($event.Id -eq 10 -and $eventData["GrantedAccess"]) {
                    $suspiciousAccess = $eventData["GrantedAccess"] -match "0x1F3FFF|0x143A|0x1410"
                    if ($suspiciousAccess -and $eventData["CallTrace"] -and $eventData["CallTrace"] -notmatch "ntdll|kernel32") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'CRITICAL'
                            MitreTechnique = 'T1055'
                            DetectionModule = 'DefenseEvasion'
                            EventDetails = 'Suspicious process access detected'
                            ProcessID = $eventData["SourceProcessId"]
                            ProcessName = $eventData["SourceImage"]
                            CommandLine = ''
                            User = $eventData["User"]
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Target: $($eventData['TargetImage']), Access: $($eventData['GrantedAccess'])"
                        }
                    }
                }
                
                # T1036 - Masquerading
                if ($event.Id -eq 1 -and $eventData["Image"]) {
                    $image = $eventData["Image"]
                    $originalFileName = $eventData["OriginalFileName"]
                    
                    # Check for system binary masquerading
                    $systemBinaries = @("svchost.exe", "lsass.exe", "winlogon.exe", "csrss.exe", "smss.exe")
                    foreach ($binary in $systemBinaries) {
                        if ($image -match $binary -and $image -notmatch "System32|SysWOW64") {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1036.003'
                                DetectionModule = 'DefenseEvasion'
                                EventDetails = 'Potential system binary masquerading'
                                ProcessID = $eventData["ProcessId"]
                                ProcessName = $image
                                CommandLine = $eventData["CommandLine"]
                                User = $eventData["User"]
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $image
                                RegistryKey = ''
                                AdditionalContext = "OriginalFile: $originalFileName, GUID: $($eventData['ProcessGuid'])"
                            }
                        }
                    }
                    
                    # Check for suspicious paths
                    $suspiciousPaths = @("\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Desktop\\")
                    foreach ($path in $suspiciousPaths) {
                        if ($image -match $path -and $originalFileName -match "\.exe$") {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1036.005'
                                DetectionModule = 'DefenseEvasion'
                                EventDetails = 'Executable in suspicious location'
                                ProcessID = $eventData["ProcessId"]
                                ProcessName = $image
                                CommandLine = $eventData["CommandLine"]
                                User = $eventData["User"]
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $image
                                RegistryKey = ''
                                AdditionalContext = "Location: $path, GUID: $($eventData['ProcessGuid'])"
                            }
                        }
                    }
                    
                    # T1218 - System Binary Proxy Execution
                    $commandLine = $eventData["CommandLine"]
                    $proxyBinaries = @{
                        "rundll32.exe" = "T1218.011"
                        "regsvr32.exe" = "T1218.010"
                        "mshta.exe" = "T1218.005"
                        "certutil.exe" = "T1218.003"
                        "wscript.exe" = "T1218.001"
                        "cscript.exe" = "T1218.001"
                        "powershell.exe" = "T1218.001"
                        "msiexec.exe" = "T1218.007"
                        "installutil.exe" = "T1218.004"
                    }
                    
                    foreach ($binary in $proxyBinaries.Keys) {
                        if ($image -match $binary -and $commandLine -match "http|ftp|\.ps1|\.vbs|\.js|\.hta|javascript:|vbscript:") {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = $proxyBinaries[$binary]
                                DetectionModule = 'DefenseEvasion'
                                EventDetails = 'Potential proxy execution detected'
                                ProcessID = $eventData["ProcessId"]
                                ProcessName = $image
                                CommandLine = $commandLine
                                User = $eventData["User"]
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $image
                                RegistryKey = ''
                                AdditionalContext = "Binary: $binary, GUID: $($eventData['ProcessGuid'])"
                            }
                        }
                    }
                    
                    # T1027 - Obfuscated Files or Information
                    if ($commandLine -match "-enc.|[A-Za-z0-9+/]{20,}.==|\\x[0-9a-f]{2}|%[0-9a-f]{2}") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1027'
                            DetectionModule = 'DefenseEvasion'
                            EventDetails = 'Potential obfuscated command detected'
                            ProcessID = $eventData["ProcessId"]
                            ProcessName = $image
                            CommandLine = $commandLine
                            User = $eventData["User"]
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $image
                            RegistryKey = ''
                            AdditionalContext = "Pattern: ObfuscatedCommand, GUID: $($eventData['ProcessGuid'])"
                        }
                    }
                    
                    # T1562 - Impair Defenses
                    $defenseEvasionPatterns = @(
                        "Set-MpPreference.*-DisableRealtimeMonitoring",
                        "netsh.*firewall.*disable",
                        "sc.*stop.*windefend",
                        "taskkill.*/f.*/im.*antivirus",
                        "wevtutil.*cl.*Security"
                    )
                    
                    foreach ($pattern in $defenseEvasionPatterns) {
                        if ($commandLine -match $pattern) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1562'
                                DetectionModule = 'DefenseEvasion'
                                EventDetails = 'Defense impairment command detected'
                                ProcessID = $eventData["ProcessId"]
                                ProcessName = $image
                                CommandLine = $commandLine
                                User = $eventData["User"]
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $image
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, GUID: $($eventData['ProcessGuid'])"
                            }
                        }
                    }
                    
                    # T1070.001 - Clear Windows Event Logs
                    $logClearPatterns = @(
                        "wevtutil.*cl",
                        "Clear-EventLog",
                        "Remove-Item.*\.log",
                        "del.*\.log",
                        "fsutil.*deletejournal"
                    )
                    
                    foreach ($pattern in $logClearPatterns) {
                        if ($commandLine -match $pattern) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1070.001'
                                DetectionModule = 'DefenseEvasion'
                                EventDetails = 'Log clearing activity detected'
                                ProcessID = $eventData["ProcessId"]
                                ProcessName = $image
                                CommandLine = $commandLine
                                User = $eventData["User"]
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $image
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, GUID: $($eventData['ProcessGuid'])"
                            }
                        }
                    }
                }
                
                # T1564 - Hide Artifacts
                if ($event.Id -eq 11 -and $eventData["TargetFilename"]) {
                    $targetFilename = $eventData["TargetFilename"]
                    
                    # Check for hidden files/ADS
                    if ($targetFilename -match ":.:|^\.\.|\\\.[^\\]*$") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1564.004'
                            DetectionModule = 'DefenseEvasion'
                            EventDetails = 'Potential file hiding detected'
                            ProcessID = $eventData["ProcessId"]
                            ProcessName = $eventData["Image"]
                            CommandLine = ''
                            User = $eventData["User"]
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $targetFilename
                            RegistryKey = ''
                            AdditionalContext = "HiddenPattern: ADS/DotFile, GUID: $($eventData['ProcessGuid'])"
                        }
                    }
                    
                    # T1027.009 - Embedded Payloads
                    if ($targetFilename -match "\.tmp$|\.temp$|[0-9a-f]{32,}|[A-Za-z0-9+/]{20,}") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1027.009'
                            DetectionModule = 'DefenseEvasion'
                            EventDetails = 'Potentially obfuscated file created'
                            ProcessID = $eventData["ProcessId"]
                            ProcessName = $eventData["Image"]
                            CommandLine = ''
                            User = $eventData["User"]
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $targetFilename
                            RegistryKey = ''
                            AdditionalContext = "Pattern: ObfuscatedFilename, GUID: $($eventData['ProcessGuid'])"
                        }
                    }
                }
                
                # T1112 - Modify Registry
                if ($event.Id -in @(12,13,14) -and $eventData["TargetObject"]) {
                    $targetObject = $eventData["TargetObject"]
                    
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
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1112'
                                DetectionModule = 'DefenseEvasion'
                                EventDetails = 'Critical registry modification detected'
                                ProcessID = $eventData["ProcessId"]
                                ProcessName = $eventData["Image"]
                                CommandLine = ''
                                User = $eventData["User"]
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = $targetObject
                                AdditionalContext = "Details: $($eventData['Details']), GUID: $($eventData['ProcessGuid'])"
                            }
                            break
                        }
                    }
                    
                    # T1564.001 - Hidden Files and Directories (Registry)
                    if ($targetObject -match "\\Software\\Classes\\.+\\shell\\" -and $eventData["Details"] -match "DWORD \(0x00000000\)") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1564.001'
                            DetectionModule = 'DefenseEvasion'
                            EventDetails = 'Potential registry hiding detected'
                            ProcessID = $eventData["ProcessId"]
                            ProcessName = $eventData["Image"]
                            CommandLine = ''
                            User = $eventData["User"]
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = $targetObject
                            AdditionalContext = "Pattern: HiddenRegistry, GUID: $($eventData['ProcessGuid'])"
                        }
                    }
                }
                
                # T1070.004 - File Deletion (Enhanced logging)
                if ($event.Id -eq 23) {
                    $targetFilename = if ($eventData["TargetFilename"]) { $eventData["TargetFilename"] } else { "Unknown" }
                    $processId = if ($eventData["ProcessId"]) { $eventData["ProcessId"] } else { "Unknown" }
                    $user = if ($eventData["User"]) { $eventData["User"] } else { "Unknown" }
                    $processGuid = if ($eventData["ProcessGuid"]) { $eventData["ProcessGuid"] } else { "Unknown" }
                    $hashes = if ($eventData["Hashes"]) { $eventData["Hashes"] } else { "N/A" }
                    $isExecutable = if ($eventData["IsExecutable"]) { $eventData["IsExecutable"] } else { "Unknown" }
                    
                    Write-SecurityEvent -LogType 'Main' -EventData @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1070.004'
                        DetectionModule = 'DefenseEvasion'
                        EventDetails = 'File deletion detected'
                        ProcessID = $processId
                        ProcessName = $eventData["Image"]
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "Hashes: $hashes, Executable: $isExecutable, GUID: $processGuid"
                    }
                }
            }
        }
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'DefenseEvasion'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-DiscoveryDetection {
    try {
        # Initialize process whitelist for legitimate admin activities
        $legitimateProcesses = @(
            "C:\Windows\System32\taskmgr.exe",
            "C:\Windows\System32\perfmon.exe", 
            "C:\Windows\System32\resmon.exe",
            "C:\Program Files\System Center",
            "C:\Program Files (x86)\Microsoft",
            "C:\Windows\System32\mmc.exe"
        )
        
        $legitimateUsers = @(
            "NT AUTHORITY\SYSTEM",
            "NT AUTHORITY\LOCAL SERVICE", 
            "NT AUTHORITY\NETWORK SERVICE"
        )
        
        # Monitor for Account Discovery (T1087) - with context awareness
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $sysmonEvents) {
            $xml = [xml]$event.ToXml()
            $commandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
            $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
            $processGuid = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessGuid'} | Select-Object -ExpandProperty '#text'
            
            if ($commandLine) {
                # Check if this is a legitimate process/user
                $isLegitimate = $false
                
                # Check process whitelist
                foreach ($legitProcess in $legitimateProcesses) {
                    if ($processName -like "$legitProcess*") {
                        $isLegitimate = $true
                        break
                    }
                }
                
                # Check user whitelist
                if ($user -in $legitimateUsers) {
                    $isLegitimate = $true
                }
                
                # Skip logging for legitimate processes/users unless suspicious
                if ($isLegitimate) {
                    continue
                }
                
                # Account enumeration patterns - only log if suspicious context
                $accountDiscoveryPatterns = @(
                    @{ Pattern = "net user"; Suspicious = $commandLine -match "net user.*\s+/domain" },
                    @{ Pattern = "net localgroup"; Suspicious = $commandLine -match "administrators|`"domain admins`"" },
                    @{ Pattern = "net group"; Suspicious = $commandLine -match "/domain|`"enterprise admins`"" },
                    @{ Pattern = "Get-LocalUser"; Suspicious = $commandLine -match "Get-LocalUser.*\|" },
                    @{ Pattern = "Get-ADUser"; Suspicious = $true },  # Always suspicious
                    @{ Pattern = "whoami"; Suspicious = $commandLine -match "/all|/priv|/groups" },
                    @{ Pattern = "wmic useraccount"; Suspicious = $true },
                    @{ Pattern = "dsquery user"; Suspicious = $true },
                    @{ Pattern = "nltest /domain_trusts"; Suspicious = $true }
                )
                
                foreach ($patternObj in $accountDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($patternObj.Pattern) -and $patternObj.Suspicious) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1087'
                            DetectionModule = 'Discovery'
                            EventDetails = 'Suspicious account discovery activity'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $($patternObj.Pattern), ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # System information discovery patterns (T1082) - reduced sensitivity
                $systemInfoPatterns = @(
                    "systeminfo",
                    "hostname", 
                    "wmic computersystem",
                    "Get-ComputerInfo",
                    "uname -a",
                    "ver",
                    "wmic os"
                )
                
                foreach ($pattern in $systemInfoPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1082'
                            DetectionModule = 'Discovery'
                            EventDetails = 'System information discovery detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # Process discovery patterns (T1057)
                $processDiscoveryPatterns = @(
                    "tasklist",
                    "Get-Process",
                    "wmic process",
                    "ps aux",
                    "ps -ef"
                )
                
                foreach ($pattern in $processDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1057'
                            DetectionModule = 'Discovery'
                            EventDetails = 'Process discovery activity detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # Network service discovery patterns (T1046)
                $serviceDiscoveryPatterns = @(
                    "nmap",
                    "portqry",
                    "telnet.*[0-9]+$",
                    "nc -zv",
                    "netcat",
                    "Test-NetConnection",
                    "portscan",
                    "masscan"
                )
                
                foreach ($pattern in $serviceDiscoveryPatterns) {
                    if ($commandLine -match $pattern) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1046'
                            DetectionModule = 'Discovery'
                            EventDetails = 'Network service discovery/scanning detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # Network configuration discovery patterns (T1016)
                $networkConfigPatterns = @(
                    "ipconfig",
                    "ifconfig",
                    "Get-NetIPConfiguration",
                    "arp -a",
                    "route print",
                    "netsh interface",
                    "Get-NetRoute",
                    "Get-NetAdapter"
                )
                
                foreach ($pattern in $networkConfigPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1016'
                            DetectionModule = 'Discovery'
                            EventDetails = 'Network configuration discovery detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # File and directory discovery patterns (T1083)
                if ($commandLine -match "dir /s|tree /f|forfiles|Get-ChildItem -Recurse|ls -la|find \. -type f|wmic datafile|where /r") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1083'
                        DetectionModule = 'Discovery'
                        EventDetails = 'File and directory discovery detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = $commandLine
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "ProcessGuid: $processGuid"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Network share discovery patterns (T1135)
                $shareDiscoveryPatterns = @(
                    "net view",
                    "net share",
                    "Get-SmbShare",
                    "Get-WmiObject.*Win32_Share",
                    "wmic share",
                    "showmount",
                    "smbclient -L"
                )
                
                foreach ($pattern in $shareDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1135'
                            DetectionModule = 'Discovery'
                            EventDetails = 'Network share discovery detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # Remote system discovery patterns (T1018)
                $remoteDiscoveryPatterns = @(
                    "ping",
                    "nslookup",
                    "dig",
                    "Get-NetNeighbor",
                    "arp -a",
                    "net view /domain"
                )
                
                foreach ($pattern in $remoteDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1018'
                            DetectionModule = 'Discovery'
                            EventDetails = 'Remote system discovery detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
            }
        }
        
        # Monitor file access for browser information discovery (T1217)
        $fileEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=11} -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $fileEvents) {
            $xml = [xml]$event.ToXml()
            $targetFile = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetFilename'} | Select-Object -ExpandProperty '#text'
            $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
            
            if ($targetFile) {
                # Browser data paths
                $browserPaths = @(
                    "\\Google\\Chrome\\User Data",
                    "\\Mozilla\\Firefox\\Profiles",
                    "\\Microsoft\\Edge\\User Data",
                    "\\Opera\\Opera Stable",
                    "\\Safari\\Bookmarks.plist",
                    "History",
                    "Bookmarks",
                    "Cookies",
                    "Login Data",
                    "Preferences"
                )
                
                foreach ($path in $browserPaths) {
                    if ($targetFile -match [regex]::Escape($path)) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1217'
                            DetectionModule = 'Discovery'
                            EventDetails = 'Browser information discovery detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $targetFile
                            RegistryKey = ''
                            AdditionalContext = "Browser path accessed: $path"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
            }
        }
        
        # Monitor network connections for scanning (T1046)
        $netEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} -MaxEvents 100 -ErrorAction SilentlyContinue
        
        foreach ($event in $netEvents) {
            $xml = [xml]$event.ToXml()
            $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            $destPort = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationPort'} | Select-Object -ExpandProperty '#text'
            $destIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationIp'} | Select-Object -ExpandProperty '#text'
            $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
            
            # Scanning ports detection
            $scanningPorts = @("21", "22", "23", "25", "53", "80", "110", "135", "139", "143", "443", "445", "993", "995", "1433", "3389", "5985", "5986")
            
            if ($scanningPorts -contains $destPort -and $destIP -notmatch "^(127\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)") {
                $eventData = @{
                    Severity = 'INFO'
                    MitreTechnique = 'T1046'
                    DetectionModule = 'Discovery'
                    EventDetails = 'Potential network service probing detected'
                    ProcessID = $processId
                    ProcessName = $processName
                    CommandLine = ''
                    User = $user
                    SourceIP = ''
                    DestIP = $destIP
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "Port: $destPort, External IP scan"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
        }
        
        # Monitor registry access for query registry (T1012)
        $regEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=12} -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $regEvents) {
            $xml = [xml]$event.ToXml()
            $targetObject = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetObject'} | Select-Object -ExpandProperty '#text'
            $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
            
            if ($targetObject) {
                $eventData = @{
                    Severity = 'INFO'
                    MitreTechnique = 'T1012'
                    DetectionModule = 'Discovery'
                    EventDetails = 'Registry access detected'
                    ProcessID = $processId
                    ProcessName = $processName
                    CommandLine = ''
                    User = $user
                    SourceIP = ''
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = $targetObject
                    AdditionalContext = "Registry key accessed"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
        }
        
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'Discovery'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-USBThreatDetection {
    try {
        # USB Device State Tracking - only detect changes, not continuous scanning
        if (-not $Global:USBDeviceState) {
            $Global:USBDeviceState = @{}
        }
        
        # Get current USB devices
        $currentUSBDevices = @()
        try {
            $currentUSBDevices = Get-WmiObject -Class Win32_PnPEntity -ErrorAction SilentlyContinue | 
                Where-Object { 
                    $_.DeviceID -like "*USB*" -and 
                    $_.Status -eq "OK" -and
                    $_.DeviceID -notlike "*ROOT_HUB*" -and  # Exclude USB hubs
                    $_.DeviceID -notlike "*COMPOSITE*"      # Exclude composite devices
                }
        } catch {
            Write-ServiceLog "Error getting USB devices: $($_.Exception.Message)" "ERROR"
            return
        }
        
        # Compare with previous state to detect changes only
        $currentDeviceIDs = @($currentUSBDevices | ForEach-Object { $_.DeviceID })
        $previousDeviceIDs = @($Global:USBDeviceState.Keys)
        
        # Find newly connected devices
        $newDevices = $currentDeviceIDs | Where-Object { $_ -notin $previousDeviceIDs }
        
        # Find disconnected devices  
        $removedDevices = $previousDeviceIDs | Where-Object { $_ -notin $currentDeviceIDs }
        
        # Update state
        $Global:USBDeviceState = @{}
        foreach ($device in $currentUSBDevices) {
            $Global:USBDeviceState[$device.DeviceID] = @{
                Name = $device.Name
                Description = $device.Description
                LastSeen = Get-Date
            }
        }
        
        # Only process if there are actual device changes
        if ($newDevices.Count -eq 0 -and $removedDevices.Count -eq 0) {
            return  # No changes, skip processing
        }
        
        # Enhanced USB threat detection with comprehensive scanning
        # Creates separate USB-specific log file for detailed analysis
        $usbLogPath = Join-Path $Global:ServiceConfig.LogBasePath "USB-ThreatDetection.log"
        $quarantineDir = Join-Path $Global:ServiceConfig.LogBasePath "USBQuarantine"
        
        # Ensure quarantine directory exists
        if (-not (Test-Path $quarantineDir)) {
            New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
        }
        
        function Write-USBThreatLog {
            param(
                [string]$Message,
                [string]$Level = "INFO",
                [hashtable]$ThreatData = @{},
                [hashtable]$DeviceInfo = @{}
            )
            
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
            $logEntry = "[$timestamp] [$Level] [$env:COMPUTERNAME\$env:USERNAME] $Message"
            
            # Write to both main service log and USB-specific log
            Add-Content -Path $usbLogPath -Value $logEntry -ErrorAction SilentlyContinue
            
            # Enhanced structured data for main service log
            $eventData = @{
                Severity = $Level
                MitreTechnique = if ($ThreatData.ThreatType) { 'T1052.001' } else { 'T1091' }
                DetectionModule = 'USB'
                EventDetails = $Message
                ProcessID = ''
                ProcessName = ''
                CommandLine = ''
                User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                SourceIP = ''
                DestIP = ''
                FilePath = if ($ThreatData.FilePath) { $ThreatData.FilePath } else { '' }
                RegistryKey = ''
                AdditionalContext = "ThreatData: $(if($ThreatData.Count -gt 0) { ($ThreatData | ConvertTo-Json -Compress) } else { 'None' }), DeviceInfo: $(if($DeviceInfo.Count -gt 0) { ($DeviceInfo | ConvertTo-Json -Compress) } else { 'None' })"
            }
            
            Write-SecurityEvent -LogType 'Main' -EventData $eventData
        }
        
        function Test-SuspiciousFileExtensions {
            param([string]$FilePath)
            
            $suspiciousExtensions = @(
                ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jar", ".wsf", ".wsh",
                ".ps1", ".psm1", ".psd1", ".msi", ".msp", ".reg", ".hta", ".cpl", ".inf", ".lnk", ".url",
                ".application", ".gadget", ".msp", ".mst", ".paf", ".settingcontent-ms", ".diagcab", ".diagcfg"
            )
            
            $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
            return $suspiciousExtensions -contains $extension
        }
        
        function Test-AutorunThreats {
            param([string]$DrivePath)
            
            $threats = @()
            $autorunFiles = @('autorun.inf', 'autorun.exe', 'autoplay.exe')
            
            foreach ($autorunFile in $autorunFiles) {
                $fullPath = Join-Path $DrivePath $autorunFile
                if (Test-Path $fullPath) {
                    $threat = @{
                        ThreatType = "Autorun"
                        FilePath = $fullPath
                        FileName = $autorunFile
                        Severity = "HIGH"
                        MitreTechnique = "T1091"
                        Description = "Autorun file detected on USB device"
                    }
                    
                    # Additional analysis for autorun.inf
                    if ($autorunFile -eq "autorun.inf") {
                        try {
                            $content = Get-Content $fullPath -Raw -ErrorAction SilentlyContinue
                            if ($content -match "open=|shellexecute=|action=") {
                                $threat.Severity = "CRITICAL"
                                $threat.Description += " - Contains execution commands"
                                $threat.CommandContent = $content
                            }
                        } catch { }
                    }
                    
                    $threats += $threat
                }
            }
            
            return $threats
        }
        
        function Test-HiddenThreats {
            param([string]$DrivePath)
            
            $threats = @()
            
            try {
                $hiddenItems = Get-ChildItem -Path $DrivePath -Recurse -Hidden -Force -ErrorAction SilentlyContinue | Select-Object -First 50
                
                foreach ($item in $hiddenItems) {
                    # Skip legitimate system files
                    if ($item.Name -match "^(\$RECYCLE\.BIN|System Volume Information|\.Trash|\.DS_Store)$") {
                        continue
                    }
                    
                    $threat = @{
                        ThreatType = "Hidden"
                        FilePath = $item.FullName
                        FileName = $item.Name
                        Severity = "MEDIUM"
                        MitreTechnique = "T1564.001"
                        Description = "Hidden file/folder detected"
                        IsDirectory = $item.PSIsContainer
                    }
                    
                    # Escalate severity for suspicious hidden executables
                    if (Test-SuspiciousFileExtensions -FilePath $item.Name) {
                        $threat.Severity = "HIGH"
                        $threat.Description += " - Hidden executable file"
                    }
                    
                    $threats += $threat
                }
            } catch {
                Write-USBThreatLog "Error scanning for hidden files: $($_.Exception.Message)" "WARN"
            }
            
            return $threats
        }
        
        function Test-SuspiciousFiles {
            param([string]$DrivePath)
            
            $threats = @()
            
            try {
                $files = Get-ChildItem -Path $DrivePath -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1000
                
                foreach ($file in $files) {
                    $fileName = $file.Name.ToLower()
                    $fileExt = $file.Extension.ToLower()
                    
                    $threat = $null
                    
                    # Check suspicious file extensions
                    if (Test-SuspiciousFileExtensions -FilePath $file.Name) {
                        $threat = @{
                            ThreatType = "Suspicious File"
                            FilePath = $file.FullName
                            FileName = $file.Name
                            Severity = "HIGH"
                            MitreTechnique = "T1204"
                            Description = "Executable file on USB device"
                        }
                    }
                    
                    # Check suspicious filenames
                    $suspiciousNames = @("password", "crack", "keygen", "hack", "exploit", "payload", "shell", "backdoor", "trojan", "virus")
                    foreach ($suspiciousName in $suspiciousNames) {
                        if ($fileName -like "*$suspiciousName*") {
                            $threat = @{
                                ThreatType = "Suspicious File"
                                FilePath = $file.FullName
                                FileName = $file.Name
                                Severity = "HIGH"
                                MitreTechnique = "T1204"
                                Description = "Suspicious filename pattern detected"
                            }
                            break
                        }
                    }
                    
                    # Check double extensions
                    if ($fileName -match "\.(pdf|doc|txt|jpg|png)\.exe$") {
                        $threat = @{
                            ThreatType = "Suspicious File"
                            FilePath = $file.FullName
                            FileName = $file.Name
                            Severity = "CRITICAL"
                            MitreTechnique = "T1036"
                            Description = "Double extension detected - possible masquerading"
                        }
                    }
                    
                    # Check file size anomalies
                    if ($file.Length -eq 0) {
                        $threat = @{
                            ThreatType = "Suspicious File"
                            FilePath = $file.FullName
                            FileName = $file.Name
                            Severity = "MEDIUM"
                            MitreTechnique = "T1027"
                            Description = "Zero-byte file detected"
                        }
                    }
                    
                    if ($threat) {
                        $threats += $threat
                    }
                }
            } catch {
                Write-USBThreatLog "Error scanning files: $($_.Exception.Message)" "WARN"
            }
            
            return $threats
        }
        
        function Invoke-ThreatQuarantine {
            param([hashtable]$Threat)
            
            try {
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $quarantineSubDir = Join-Path $quarantineDir $timestamp
                
                if (-not (Test-Path $quarantineSubDir)) {
                    New-Item -ItemType Directory -Path $quarantineSubDir -Force | Out-Null
                }
                
                $originalPath = $Threat.FilePath
                $fileName = [System.IO.Path]::GetFileName($originalPath)
                $quarantinePath = Join-Path $quarantineSubDir "$fileName.quarantine"
                $metadataPath = Join-Path $quarantineSubDir "$fileName.quarantine.metadata.json"
                
                # Move file to quarantine
                Move-Item -Path $originalPath -Destination $quarantinePath -Force
                
                # Create metadata
                $metadata = @{
                    OriginalPath = $originalPath
                    QuarantineTime = Get-Date -Format "o"
                    ThreatData = $Threat
                    SystemInfo = @{
                        ComputerName = $env:COMPUTERNAME
                        UserName = $env:USERNAME
                        Domain = $env:USERDOMAIN
                    }
                }
                
                $metadata | ConvertTo-Json -Depth 5 | Set-Content -Path $metadataPath
                
                Write-USBThreatLog "File quarantined: $originalPath -> $quarantinePath" "INFO" $Threat
                return $true
            } catch {
                Write-USBThreatLog "Failed to quarantine file: $($_.Exception.Message)" "CRITICAL" $Threat
                return $false
            }
        }
        
        function Invoke-USBThreatScan {
            param([string]$DriveLetter)
            
            Write-USBThreatLog "Starting comprehensive threat scan of USB drive: $DriveLetter" "INFO"
            
            $allThreats = @()
            
            try {
                # Test if drive is accessible
                if (-not (Test-Path $DriveLetter)) {
                    Write-USBThreatLog "Drive $DriveLetter is not accessible" "WARN"
                    return
                }
                
                # Autorun threat detection
                $autorunThreats = Test-AutorunThreats -DrivePath $DriveLetter
                $allThreats += $autorunThreats
                
                # Hidden file detection
                $hiddenThreats = Test-HiddenThreats -DrivePath $DriveLetter
                $allThreats += $hiddenThreats
                
                # Suspicious file detection
                $suspiciousThreats = Test-SuspiciousFiles -DrivePath $DriveLetter
                $allThreats += $suspiciousThreats
                
                # Process all detected threats
                $criticalThreats = $allThreats | Where-Object { $_.Severity -eq "CRITICAL" }
                $highThreats = $allThreats | Where-Object { $_.Severity -eq "HIGH" }
                $mediumThreats = $allThreats | Where-Object { $_.Severity -eq "MEDIUM" }
                
                # Log summary
                $summary = @"
USB Threat Scan Summary for $DriveLetter
========================================
Total Threats Found: $($allThreats.Count)
- Critical: $($criticalThreats.Count)
- High: $($highThreats.Count)  
- Medium: $($mediumThreats.Count)
"@
                
                Write-USBThreatLog $summary "INFO"
                
                # Report individual threats and quarantine critical/high threats
                foreach ($threat in $allThreats) {
                    Write-USBThreatLog "$($threat.Severity) threat detected: $($threat.FileName) - $($threat.Description)" $threat.Severity $threat
                    
                    # Auto-quarantine critical and high severity threats
                    if ($threat.Severity -in @("CRITICAL", "HIGH")) {
                        $quarantineResult = Invoke-ThreatQuarantine -Threat $threat
                        if ($quarantineResult) {
                            Write-USBThreatLog "Threat automatically quarantined: $($threat.FileName)" "INFO" $threat
                        }
                    }
                }
                
                Write-USBThreatLog "USB threat scan completed for $DriveLetter" "INFO"
            } catch {
                Write-USBThreatLog "Error during USB threat scan: $($_.Exception.Message)" "CRITICAL"
            }
        }
        
        # Enhanced mobile device detection (incorporating Test-PhoneDetection functionality)
        $usbDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { 
            $_.DeviceID -like "*USB*" -and $_.Status -eq "OK"
        }
        
        Write-USBThreatLog "Starting USB device enumeration - found $($usbDevices.Count) total USB devices" "INFO"
        
        $mobileDeviceCount = 0
        $storageDeviceCount = 0
        
        foreach ($device in $usbDevices) {
            $name = $device.Name.ToLower()
            $desc = $device.Description.ToLower()
            
            # Skip system USB components
            if ($name -like "*hub*" -or $name -like "*root*" -or $name -like "*host*" -or 
                $name -like "*enhanced*" -or $name -like "*standard*" -or $name -like "*controller*") {
                continue
            }
            
            # Mobile device keywords (from Test-PhoneDetection.ps1)
            $mobileKeywords = @("samsung", "oneplus", "vivo", "oppo", "motorola", "poco", "xiaomi", "redmi", 
                               "realme", "nokia", "phone", "android", "mtp", "ptp", "composite", "adb", "apple", "iphone", "ipad")
            
            $isMobile = $false
            $matchedKeyword = ""
            
            foreach ($keyword in $mobileKeywords) {
                if ($name -like "*$keyword*" -or $desc -like "*$keyword*") {
                    $isMobile = $true
                    $matchedKeyword = $keyword
                    break
                }
            }
            
            if ($isMobile) {
                $mobileDeviceCount++
                
                # Determine threat level
                $threatLevel = "LOW"
                $severity = "INFO"
                
                if ($name -match "adb|debug" -or $desc -match "adb|debug") {
                    $threatLevel = "HIGH"
                    $severity = "WARNING"
                } elseif ($name -match "mtp|ptp" -or $desc -match "mtp|ptp") {
                    $threatLevel = "MEDIUM"
                    $severity = "INFO"
                }
                
                $deviceInfo = @{
                    DeviceType = "Mobile"
                    DeviceName = $device.Name
                    DeviceID = $device.DeviceID
                    Description = $device.Description
                    ClassGuid = $device.ClassGuid
                    MatchedKeyword = $matchedKeyword
                    ThreatLevel = $threatLevel
                }
                
                Write-USBThreatLog "MOBILE DEVICE DETECTED: $($device.Name) - Threat Level: $threatLevel" $severity @{} $deviceInfo
            }
            
            # Monitor for USB mass storage devices
            if ($desc -match "mass storage|removable|flash|disk") {
                $storageDeviceCount++
                
                $deviceInfo = @{
                    DeviceType = "Storage" 
                    DeviceName = $device.Name
                    DeviceID = $device.DeviceID
                    Description = $device.Description
                }
                
                Write-USBThreatLog "USB STORAGE DEVICE DETECTED: $($device.Name)" "INFO" @{} $deviceInfo
                
                # Check if we can find the drive letter for this device
                $driveLetters = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | Select-Object -ExpandProperty DeviceID
                
                foreach ($driveLetter in $driveLetters) {
                    if ($driveLetter -and $driveLetter -match '^[A-Z]:$') {
                        Write-USBThreatLog "Scanning USB storage device: $driveLetter" "INFO"
                        Invoke-USBThreatScan -DriveLetter $driveLetter
                    }
                }
            }
        }
        
        # Summary logging
        Write-USBThreatLog "USB device detection completed - Mobile devices: $mobileDeviceCount, Storage devices: $storageDeviceCount" "INFO"
        
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'USB'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-OTProcessCorrelation {
    try {
        # Enhanced OT Process Correlation with comprehensive whitelisting and monitoring
        # Creates separate OT-specific log file for detailed analysis
        $otLogPath = Join-Path $Global:ServiceConfig.LogBasePath "OT_ProcessCorrelation.log"
        
        function Write-OTLog {
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
            
            # Write to both main service log and OT-specific log
            Add-Content -Path $otLogPath -Value $logEntry -ErrorAction SilentlyContinue
            
            # Enhanced structured data for main service log
            $eventData = @{
                Severity = switch ($Level) {
                    "CRITICAL" { "CRITICAL" }
                    "ALERT" { "WARNING" }
                    "WARNING" { "WARNING" }
                    default { "INFO" }
                }
                MitreTechnique = 'T1055'
                DetectionModule = 'OTCorrelation'
                EventDetails = $Message
                ProcessID = if ($StructuredData.ChildPID) { $StructuredData.ChildPID } else { '' }
                ProcessName = if ($StructuredData.ChildProcess) { $StructuredData.ChildProcess } else { '' }
                CommandLine = if ($StructuredData.CommandLine) { $StructuredData.CommandLine } else { '' }
                User = if ($StructuredData.User) { $StructuredData.User } else { '' }
                SourceIP = ''
                DestIP = ''
                FilePath = ''
                RegistryKey = ''
                AdditionalContext = if ($StructuredData.Count -gt 0) { ($StructuredData | ConvertTo-Json -Compress) } else { '' }
            }
            
            Write-SecurityEvent -LogType 'Main' -EventData $eventData
        }
        
        # Critical OT processes that should never spawn unexpected children
        $CriticalOTProcesses = @(
            "wonderware.exe", "intouch.exe", "rsview32.exe", "factorytalk.exe", "citect.exe",
            "genesis.exe", "wincc.exe", "lookout.exe", "rslinx.exe", "rslogix5000.exe",
            "step7.exe", "tiaportal.exe", "unity.exe", "kepserverex.exe", "matrikon.exe",
            "schneiderelect.exe", "abb.exe", "emerson.exe", "honeywell.exe", "invensys.exe",
            "aveva.exe", "indusoft.exe", "iconics.exe", "ge-proficy.exe", "rockwell.exe"
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
        
        # Load whitelist from file if exists
        $whitelistPath = Join-Path $Global:ServiceConfig.LogBasePath "OT_ProcessWhitelist.json"
        $whitelist = $DefaultWhitelist
        
        if (Test-Path $whitelistPath) {
            try {
                $loadedWhitelist = Get-Content $whitelistPath | ConvertFrom-Json
                # Convert PSCustomObject to hashtable
                $customWhitelist = @{}
                $loadedWhitelist.PSObject.Properties | ForEach-Object {
                    $customWhitelist[$_.Name] = $_.Value
                }
                $whitelist = $customWhitelist
                Write-OTLog "Loaded custom whitelist from $whitelistPath" "INFO"
            }
            catch {
                Write-OTLog "Failed to load OT whitelist, using default: $($_.Exception.Message)" "WARNING"
                # Save default whitelist for reference
                try {
                    $DefaultWhitelist | ConvertTo-Json -Depth 3 | Set-Content -Path $whitelistPath -ErrorAction SilentlyContinue
                    Write-OTLog "Default whitelist saved to $whitelistPath" "INFO"
                } catch {
                    Write-OTLog "Failed to save default whitelist: $($_.Exception.Message)" "WARNING"
                }
            }
        } else {
            # Save default whitelist
            try {
                $DefaultWhitelist | ConvertTo-Json -Depth 3 | Set-Content -Path $whitelistPath -ErrorAction SilentlyContinue
                Write-OTLog "Default whitelist created at $whitelistPath" "INFO"
            } catch {
                Write-OTLog "Failed to create default whitelist: $($_.Exception.Message)" "WARNING"
            }
        }
        
        function Test-ProcessWhitelisted {
            param(
                [string]$ParentProcess,
                [string]$ChildProcess
            )
            
            $parentName = [System.IO.Path]::GetFileName($ParentProcess).ToLower()
            $childName = [System.IO.Path]::GetFileName($ChildProcess).ToLower()
            
            if ($whitelist.ContainsKey($parentName)) {
                return $childName -in $whitelist[$parentName]
            }
            
            return $false
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
            
            $isCriticalOT = [System.IO.Path]::GetFileName($ParentProcess).ToLower() -in $CriticalOTProcesses.ToLower()
            $severity = if ($isCriticalOT) { "CRITICAL" } else { "ALERT" }
            
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
                "Severity" = $severity
                "IsCriticalOT" = $isCriticalOT
            }
            
            $alertMessage = if ($isCriticalOT) {
                "OT_CRITICAL_VIOLATION: Critical OT process spawned unauthorized child"
            } else {
                "OT_SECURITY_VIOLATION: Unauthorized process spawning detected"
            }
            
            Write-OTLog $alertMessage $severity $structuredData
        }
        
        # Process map for tracking parent-child relationships
        $ProcessMap = @{}
        $MapCleanupInterval = 600 # 10 minutes
        $LastCleanup = Get-Date
        
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
                Write-OTLog "Cleaned up $($toRemove.Count) old process map entries" "INFO"
            }
        }
        
        # Monitor process creation events from Sysmon
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 100 -ErrorAction SilentlyContinue
        
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                $xml = [xml]$event.ToXml()
                
                # Extract process information
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $parentProcessId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ParentProcessId'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $commandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                $processGuid = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessGuid'} | Select-Object -ExpandProperty '#text'
                
                # Add to process map
                $ProcessMap[$processId] = @{
                    Name = [System.IO.Path]::GetFileName($processName)
                    FullPath = $processName
                    ParentPID = $parentProcessId
                    CommandLine = $commandLine
                    User = $user
                    CreationTime = Get-Date
                    ProcessGuid = $processGuid
                }
                
                # Check parent→child relationship if parent exists in our map
                if ($parentProcessId -and $ProcessMap.ContainsKey($parentProcessId)) {
                    $parentInfo = $ProcessMap[$parentProcessId]
                    $parentName = $parentInfo.Name
                    $childName = [System.IO.Path]::GetFileName($processName)
                    
                    # Check if this relationship is whitelisted
                    $isWhitelisted = Test-ProcessWhitelisted -ParentProcess $parentName -ChildProcess $childName
                    
                    if (-not $isWhitelisted) {
                        # Check if parent is a critical OT process
                        $isCriticalOTParent = $parentName.ToLower() -in $CriticalOTProcesses.ToLower()
                        
                        # Send alert for non-whitelisted relationships
                        Send-OTSecurityAlert -AlertType "UnauthorizedProcessSpawning" -ParentProcess $parentInfo.FullPath -ChildProcess $processName -ParentPID $parentProcessId -ChildPID $processId -CommandLine $commandLine -User $user
                        
                        # Additional logging for analysis
                        $analysisData = @{
                            "ParentProcess" = $parentInfo.FullPath
                            "ParentPID" = $parentProcessId
                            "ChildProcess" = $processName
                            "ChildPID" = $processId
                            "CommandLine" = $commandLine
                            "User" = $user
                            "IsCriticalOTParent" = $isCriticalOTParent
                            "ParentGuid" = $parentInfo.ProcessGuid
                            "ChildGuid" = $processGuid
                        }
                        
                        Write-OTLog "Non-whitelisted process relationship detected: $parentName → $childName" "WARNING" $analysisData
                    } else {
                        # Log whitelisted relationships for auditing (reduced verbosity)
                        Write-OTLog "Whitelisted process relationship: $parentName → $childName" "INFO" @{
                            "ParentProcess" = $parentInfo.FullPath
                            "ChildProcess" = $processName
                            "Relationship" = "Whitelisted"
                        }
                    }
                }
            }
        } else {
            Write-OTLog "No Sysmon events available for OT process correlation" "INFO"
        }
        
        # Periodic cleanup of process map
        if ((Get-Date) - $LastCleanup -gt (New-TimeSpan -Seconds $MapCleanupInterval)) {
            Cleanup-ProcessMap
            $LastCleanup = Get-Date
        }
        
        # Additional monitoring for current running processes in OT environment
        try {
            $currentProcesses = Get-Process | Where-Object { $_.ProcessName -and $_.Path }
            $otProcessesRunning = @()
            
            foreach ($process in $currentProcesses) {
                $processFileName = "$($process.ProcessName).exe".ToLower()
                if ($processFileName -in $CriticalOTProcesses.ToLower()) {
                    $otProcessesRunning += @{
                        Name = $process.ProcessName
                        PID = $process.Id
                        Path = $process.Path
                        StartTime = $process.StartTime
                    }
                }
            }
            
            if ($otProcessesRunning.Count -gt 0) {
                Write-OTLog "Active critical OT processes detected: $($otProcessesRunning.Count)" "INFO" @{
                    "ActiveOTProcesses" = ($otProcessesRunning | ConvertTo-Json -Compress)
                    "ProcessNames" = ($otProcessesRunning | ForEach-Object { $_.Name }) -join ", "
                }
            } else {
                Write-OTLog "No critical OT processes currently running" "INFO"
            }
        } catch {
            Write-OTLog "Error monitoring current OT processes: $($_.Exception.Message)" "WARNING"
        }
        
        Write-OTLog "OT Process Correlation scan completed. Whitelist entries: $($whitelist.Keys.Count), Critical OT processes: $($CriticalOTProcesses.Count)" "INFO" @{
            "WhitelistEntries" = $whitelist.Keys.Count
            "CriticalOTProcesses" = $CriticalOTProcesses.Count
            "ProcessMapEntries" = $ProcessMap.Keys.Count
        }
        
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'OTCorrelation'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

# Additional MITRE modules would continue here...
# For brevity, I'll add placeholders for the remaining modules

function Start-CredentialAccessDetection {
    try {
        # Get events from multiple sources with error handling
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,7,10,11)} -MaxEvents 200 -ErrorAction SilentlyContinue
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4624,4625,4648,4672,4673,4768,4769,4771,4776,4740,4767)} -MaxEvents 100 -ErrorAction SilentlyContinue
        
        # T1003 - OS Credential Dumping
        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                $xml = [xml]$event.ToXml()
                $eventData = @{}
                foreach ($data in $xml.Event.EventData.Data) {
                    if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
                }
                
                # Detect LSASS memory dumping patterns
                if ($event.Id -eq 4672 -and $eventData["PrivilegeList"]) {
                    if ($eventData["PrivilegeList"] -match "SeDebugPrivilege") {
                        $subjectUserName = if ($eventData["SubjectUserName"]) { $eventData["SubjectUserName"] } else { "Unknown" }
                        $subjectLogonId = if ($eventData["SubjectLogonId"]) { $eventData["SubjectLogonId"] } else { "Unknown" }
                        $privilegeList = if ($eventData["PrivilegeList"]) { $eventData["PrivilegeList"] } else { "Unknown" }
                        $processId = if ($eventData["ProcessId"]) { $eventData["ProcessId"] } else { "Unknown" }
                        $processName = if ($eventData["ProcessName"]) { $eventData["ProcessName"] } else { "Unknown" }
                        
                        # Skip if it's a typical system process unless it's suspicious
                        if ($subjectUserName -eq "SYSTEM" -and $processName -notmatch "lsass|winlogon|csrss") {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'INFO'
                                MitreTechnique = 'T1003.001'
                                DetectionModule = 'CredentialAccess'
                                EventDetails = 'Debug privilege assigned to system process - monitoring for suspicious activity'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $subjectUserName
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "LogonId: $subjectLogonId, Privileges: $privilegeList"
                            }
                        } else {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1003.001'
                                DetectionModule = 'CredentialAccess'
                                EventDetails = 'SeDebugPrivilege granted - potential LSASS access'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $subjectUserName
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "LogonId: $subjectLogonId, Privileges: $privilegeList"
                            }
                        }
                    }
                }
                
                # Detect unusual authentication patterns
                if ($event.Id -eq 4624 -and $eventData["LogonType"] -eq "3" -and $eventData["IpAddress"]) {
                    if ($eventData["IpAddress"] -notmatch "^(127\.|::1|fe80:)") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1003'
                            DetectionModule = 'CredentialAccess'
                            EventDetails = 'Network logon detected'
                            ProcessID = $eventData["ProcessId"]
                            ProcessName = $eventData["ProcessName"]
                            CommandLine = ''
                            User = $eventData["TargetUserName"]
                            SourceIP = $eventData["IpAddress"]
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "LogonType: Network, Workstation: $($eventData['WorkstationName'])"
                        }
                    }
                }
                
                # T1110 - Brute Force attacks
                if ($event.Id -eq 4625) {
                    # Failed logon attempts
                    $targetUser = $eventData["TargetUserName"]
                    $sourceIP = $eventData["IpAddress"]
                    $logonType = $eventData["LogonType"]
                    
                    # Immediate detection for high-value accounts
                    if ($targetUser -match "admin|administrator|root|service") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1110.001'
                            DetectionModule = 'CredentialAccess'
                            EventDetails = 'Failed logon attempt on privileged account'
                            ProcessID = $eventData["ProcessId"]
                            ProcessName = $eventData["ProcessName"]
                            CommandLine = ''
                            User = $targetUser
                            SourceIP = $sourceIP
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "LogonType: $logonType, Status: $($eventData['Status']), SubStatus: $($eventData['SubStatus'])"
                        }
                    }
                }
                
                if ($event.Id -eq 4771) {
                    # Kerberos pre-authentication failed
                    Write-SecurityEvent -LogType 'Main' -EventData @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1110.003'
                        DetectionModule = 'CredentialAccess'
                        EventDetails = 'Kerberos pre-authentication failure'
                        ProcessID = $eventData["ProcessId"]
                        ProcessName = $eventData["ProcessName"]
                        CommandLine = ''
                        User = $eventData["TargetUserName"]
                        SourceIP = $eventData["IpAddress"]
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "ServiceName: $($eventData['ServiceName']), Status: $($eventData['Status'])"
                    }
                }
                
                if ($event.Id -eq 4740) {
                    # Account lockout
                    Write-SecurityEvent -LogType 'Main' -EventData @{
                        Severity = 'CRITICAL'
                        MitreTechnique = 'T1110'
                        DetectionModule = 'CredentialAccess'
                        EventDetails = 'Account lockout detected - possible brute force'
                        ProcessID = $eventData["ProcessId"]
                        ProcessName = $eventData["ProcessName"]
                        CommandLine = ''
                        User = $eventData["TargetUserName"]
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "CallerComputer: $($eventData['CallerComputerName'])"
                    }
                }
                
                # T1558 - Kerberos Attacks
                if ($event.Id -eq 4769 -and $eventData["ServiceName"]) {
                    $serviceName = $eventData["ServiceName"]
                    $ticketEncryptionType = $eventData["TicketEncryptionType"]
                    
                    # RC4 encryption for service tickets (potential Kerberoasting)
                    if ($ticketEncryptionType -eq "0x17") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1558.003'
                            DetectionModule = 'CredentialAccess'
                            EventDetails = 'RC4 service ticket requested - potential Kerberoasting'
                            ProcessID = $eventData["ProcessId"]
                            ProcessName = $eventData["ProcessName"]
                            CommandLine = ''
                            User = $eventData["TargetUserName"]
                            SourceIP = $eventData["IpAddress"]
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Service: $serviceName, EncryptionType: $ticketEncryptionType"
                        }
                    }
                }
                
                # AS-REP Roasting detection
                if ($event.Id -eq 4768 -and $eventData["PreAuthType"] -eq "0") {
                    Write-SecurityEvent -LogType 'Main' -EventData @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1558.004'
                        DetectionModule = 'CredentialAccess'
                        EventDetails = 'Pre-authentication not required - potential AS-REP Roasting'
                        ProcessID = $eventData["ProcessId"]
                        ProcessName = $eventData["ProcessName"]
                        CommandLine = ''
                        User = $eventData["TargetUserName"]
                        SourceIP = $eventData["IpAddress"]
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "ServiceName: $($eventData['ServiceName']), CertThumbprint: $($eventData['CertThumbprint'])"
                    }
                }
                
                # Golden/Silver ticket detection
                if ($event.Id -eq 4624 -and $eventData["LogonType"] -eq "3") {
                    $authenticationPackage = $eventData["AuthenticationPackageName"]
                    if ($authenticationPackage -eq "Kerberos" -and $eventData["LogonProcessName"] -ne "Kerberos") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'CRITICAL'
                            MitreTechnique = 'T1558.001'
                            DetectionModule = 'CredentialAccess'
                            EventDetails = 'Suspicious Kerberos authentication'
                            ProcessID = $eventData["ProcessId"]
                            ProcessName = $eventData["ProcessName"]
                            CommandLine = ''
                            User = $eventData["TargetUserName"]
                            SourceIP = $eventData["IpAddress"]
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "AuthPackage: $authenticationPackage, LogonProcess: $($eventData['LogonProcessName'])"
                        }
                    }
                }
            }
        }
        
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                $xml = [xml]$event.ToXml()
                $eventData = @{}
                foreach ($data in $xml.Event.EventData.Data) {
                    if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
                }
                
                # Detect credential dumping tools
                if ($event.Id -eq 1 -and $eventData["CommandLine"]) {
                    $commandLine = $eventData["CommandLine"]
                    $image = $eventData["Image"]
                    $processId = if ($eventData["ProcessId"]) { $eventData["ProcessId"] } else { "Unknown" }
                    $parentImage = if ($eventData["ParentImage"]) { $eventData["ParentImage"] } else { "Unknown" }
                    $user = if ($eventData["User"]) { $eventData["User"] } else { "Unknown" }
                    $processGuid = if ($eventData["ProcessGuid"]) { $eventData["ProcessGuid"] } else { "Unknown" }
                    
                    # Known credential dumping patterns
                    $dumpingPatterns = @(
                        "mimikatz",
                        "sekurlsa",
                        "lsadump",
                        "procdump.*lsass",
                        "rundll32.*comsvcs.*MiniDump",
                        "task manager.*lsass",
                        "ntdsutil",
                        "vssadmin.*create.*shadow",
                        "wmic.*process.*call.*create.*cmd",
                        "reg.*save.*HKLM\\SAM",
                        "reg.*save.*HKLM\\SYSTEM"
                    )
                    
                    foreach ($pattern in $dumpingPatterns) {
                        if ($commandLine -match $pattern) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1003'
                                DetectionModule = 'CredentialAccess'
                                EventDetails = 'Credential dumping tool or command detected'
                                ProcessID = $processId
                                ProcessName = $image
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $image
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, Parent: $parentImage, GUID: $processGuid"
                            }
                            break
                        }
                    }
                    
                    # T1040 - Network Sniffing tools
                    $sniffingPatterns = @(
                        "wireshark",
                        "tshark",
                        "tcpdump",
                        "windump",
                        "netsh.*trace.*start",
                        "pktmon",
                        "netcap"
                    )
                    
                    foreach ($pattern in $sniffingPatterns) {
                        if ($commandLine -match $pattern) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1040'
                                DetectionModule = 'CredentialAccess'
                                EventDetails = 'Network sniffing tool detected'
                                ProcessID = $processId
                                ProcessName = $image
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $image
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, Parent: $parentImage, GUID: $processGuid"
                            }
                            break
                        }
                    }
                    
                    # T1056 - Input Capture (Keylogging)
                    $inputCapturePatterns = @(
                        "keylogger",
                        "GetAsyncKeyState",
                        "SetWindowsHookEx",
                        "GetForegroundWindow",
                        "Get-Keystroke"
                    )
                    
                    foreach ($pattern in $inputCapturePatterns) {
                        if ($commandLine -match $pattern) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1056.001'
                                DetectionModule = 'CredentialAccess'
                                EventDetails = 'Input capture/keylogging tool detected'
                                ProcessID = $processId
                                ProcessName = $image
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $image
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, Parent: $parentImage, GUID: $processGuid"
                            }
                            break
                        }
                    }
                    
                    # T1555 - Credentials from Password Stores
                    $passwordStorePatterns = @(
                        "vaultcmd",
                        "LaZagne",
                        "browser.*password",
                        "chrome.*login",
                        "firefox.*password",
                        "Get-ChromePasswords",
                        "Get-FirefoxPasswords"
                    )
                    
                    foreach ($pattern in $passwordStorePatterns) {
                        if ($commandLine -match $pattern) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1555'
                                DetectionModule = 'CredentialAccess'
                                EventDetails = 'Password store access tool detected'
                                ProcessID = $processId
                                ProcessName = $image
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $image
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, Parent: $parentImage, GUID: $processGuid"
                            }
                            break
                        }
                    }
                    
                    # Kerberos attack tools
                    if ($commandLine -match "rubeus|kekeo|asktgt|asktgs|golden|silver|kerberoast") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'CRITICAL'
                            MitreTechnique = 'T1558'
                            DetectionModule = 'CredentialAccess'
                            EventDetails = 'Kerberos attack tool detected'
                            ProcessID = $processId
                            ProcessName = $image
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $image
                            RegistryKey = ''
                            AdditionalContext = "Tool: KerberosAttack, Parent: $parentImage, GUID: $processGuid"
                        }
                    }
                }
                
                # Detect LSASS process access
                if ($event.Id -eq 10 -and $eventData["TargetImage"] -match "lsass\.exe") {
                    $grantedAccess = $eventData["GrantedAccess"]
                    $sourceImage = if ($eventData["SourceImage"]) { $eventData["SourceImage"] } else { "Unknown" }
                    $sourceProcessId = if ($eventData["SourceProcessId"]) { $eventData["SourceProcessId"] } else { "Unknown" }
                    $targetProcessId = if ($eventData["TargetProcessId"]) { $eventData["TargetProcessId"] } else { "Unknown" }
                    $callTrace = if ($eventData["CallTrace"]) { $eventData["CallTrace"] } else { "Unknown" }
                    $user = if ($eventData["User"]) { $eventData["User"] } else { "Unknown" }
                    $processGuid = if ($eventData["SourceProcessGuid"]) { $eventData["SourceProcessGuid"] } else { "Unknown" }
                    
                    if ($grantedAccess -match "0x1010|0x1038|0x1fffff") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'CRITICAL'
                            MitreTechnique = 'T1003.001'
                            DetectionModule = 'CredentialAccess'
                            EventDetails = 'Suspicious LSASS process access detected'
                            ProcessID = $sourceProcessId
                            ProcessName = $sourceImage
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $sourceImage
                            RegistryKey = ''
                            AdditionalContext = "GrantedAccess: $grantedAccess, TargetPID: $targetProcessId, CallTrace: $callTrace, GUID: $processGuid"
                        }
                    }
                }
                
                # Monitor DLL injection into processes handling user input
                if ($event.Id -eq 7 -and $eventData["ImageLoaded"]) {
                    $imageLoaded = $eventData["ImageLoaded"]
                    $processName = $eventData["Image"]
                    $processId = if ($eventData["ProcessId"]) { $eventData["ProcessId"] } else { "Unknown" }
                    $user = if ($eventData["User"]) { $eventData["User"] } else { "Unknown" }
                    $processGuid = if ($eventData["ProcessGuid"]) { $eventData["ProcessGuid"] } else { "Unknown" }
                    
                    if ($processName -match "explorer\.exe|winlogon\.exe|dwm\.exe" -and $imageLoaded -notmatch "Windows\\System32|Windows\\SysWOW64") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1056.002'
                            DetectionModule = 'CredentialAccess'
                            EventDetails = 'Suspicious DLL injection into input-handling process'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $imageLoaded
                            RegistryKey = ''
                            AdditionalContext = "DLL: $imageLoaded, Target: $processName, GUID: $processGuid"
                        }
                    }
                }
                
                # Monitor file access to credential stores
                if ($event.Id -eq 11 -and $eventData["TargetFilename"]) {
                    $targetFilename = $eventData["TargetFilename"]
                    $processId = if ($eventData["ProcessId"]) { $eventData["ProcessId"] } else { "Unknown" }
                    $user = if ($eventData["User"]) { $eventData["User"] } else { "Unknown" }
                    $processGuid = if ($eventData["ProcessGuid"]) { $eventData["ProcessGuid"] } else { "Unknown" }
                    
                    $credentialFiles = @(
                        "\\AppData\\Local\\Microsoft\\Credentials\\",
                        "\\AppData\\Roaming\\Microsoft\\Credentials\\",
                        "\\Login Data$",
                        "\\key3\.db$",
                        "\\logins\.json$",
                        "\\ntuser\.dat$",
                        "\\SYSTEM$",
                        "\\SAM$"
                    )
                    
                    foreach ($pattern in $credentialFiles) {
                        if ($targetFilename -match $pattern) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1555'
                                DetectionModule = 'CredentialAccess'
                                EventDetails = 'Access to credential store detected'
                                ProcessID = $processId
                                ProcessName = $eventData["Image"]
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $targetFilename
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, GUID: $processGuid"
                            }
                            break
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'CredentialAccess'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-LateralMovementDetection {
    try {
        # Monitor for Exploitation of Remote Services (T1210)
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,3)} -MaxEvents 200 -ErrorAction SilentlyContinue
        
        foreach ($event in $sysmonEvents) {
            $xml = [xml]$event.ToXml()
            
            if ($event.Id -eq 1) {
                $commandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                $processGuid = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessGuid'} | Select-Object -ExpandProperty '#text'
                
                if ($commandLine) {
                    # Remote exploitation tool patterns
                    $exploitPatterns = @(
                        "psexec",
                        "wmiexec",
                        "smbexec",
                        "atexec",
                        "dcomexec",
                        "exploit.*remote",
                        "metasploit",
                        "cobalt.*strike",
                        "impacket"
                    )
                    
                    foreach ($pattern in $exploitPatterns) {
                        if ($commandLine -match $pattern) {
                            $eventData = @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1210'
                                DetectionModule = 'LateralMovement'
                                EventDetails = 'Remote service exploitation tool detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # SMB/Windows Admin Shares patterns (T1021.002)
                    $smbPatterns = @(
                        "net use.*\\\\",
                        "pushd.*\\\\",
                        "dir.*\\\\.*\\admin\$",
                        "dir.*\\\\.*\\c\$",
                        "psexec.*\\\\",
                        "wmic.*node:"
                    )
                    
                    foreach ($pattern in $smbPatterns) {
                        if ($commandLine -match $pattern) {
                            $eventData = @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1021.002'
                                DetectionModule = 'LateralMovement'
                                EventDetails = 'SMB/Windows Admin Shares access detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # Lateral tool transfer patterns (T1570)
                    $transferPatterns = @(
                        "copy.*\\\\",
                        "xcopy.*\\\\",
                        "robocopy.*\\\\",
                        "scp ",
                        "sftp ",
                        "rsync ",
                        "pscp",
                        "winscp",
                        "certutil.*-urlcache",
                        "powershell.*Download",
                        "wget ",
                        "curl ",
                        "bitsadmin.*transfer"
                    )
                    
                    foreach ($pattern in $transferPatterns) {
                        if ($commandLine -match $pattern) {
                            $eventData = @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1570'
                                DetectionModule = 'LateralMovement'
                                EventDetails = 'Lateral tool transfer activity detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # Software deployment tool patterns (T1072)
                    $deploymentPatterns = @(
                        "msiexec.*/i.*http",
                        "psexec.*-s",
                        "wmic.*product.*install",
                        "powershell.*Install-Package",
                        "chocolatey|choco.*install",
                        "ansible",
                        "puppet",
                        "sccm|ConfigMgr",
                        "wsus",
                        "group.*policy",
                        "gpo.*install"
                    )
                    
                    foreach ($pattern in $deploymentPatterns) {
                        if ($commandLine -match $pattern) {
                            $eventData = @{
                                Severity = 'INFO'
                                MitreTechnique = 'T1072'
                                DetectionModule = 'LateralMovement'
                                EventDetails = 'Software deployment tool execution detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # SSH patterns (T1021.004)
                    if ($processName -match "ssh\.exe" -or $commandLine -match "ssh ") {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1021.004'
                            DetectionModule = 'LateralMovement'
                            EventDetails = 'SSH client execution detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Credential theft tool patterns for alternate auth material (T1550)
                    $credentialTheftPatterns = @(
                        "mimikatz",
                        "kerberoast", 
                        "rubeus",
                        "impacket.*getTGT",
                        "sekurlsa",
                        "lsadump",
                        "dcsync"
                    )
                    
                    foreach ($pattern in $credentialTheftPatterns) {
                        if ($commandLine -match $pattern) {
                            $eventData = @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1550'
                                DetectionModule = 'LateralMovement'
                                EventDetails = 'Credential theft tool execution detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                }
            }
            
            # Network connection monitoring (T1210, T1021)
            if ($event.Id -eq 3) {
                $destPort = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationPort'} | Select-Object -ExpandProperty '#text'
                $destIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationIp'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                
                # Administrative service connections
                $adminPorts = @("135", "445", "5985", "5986", "3389")
                
                if ($adminPorts -contains $destPort -and $destIP -notmatch "^127\.") {
                    $eventData = @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1210'
                        DetectionModule = 'LateralMovement'
                        EventDetails = 'Connection to administrative service detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = $destIP
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "Port: $destPort"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # SMB connections
                if ($destPort -eq "445") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1021.002'
                        DetectionModule = 'LateralMovement'
                        EventDetails = 'SMB connection detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = $destIP
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "SMB protocol connection"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # WinRM connections
                if ($destPort -eq "5985" -or $destPort -eq "5986") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1021.006'
                        DetectionModule = 'LateralMovement'
                        EventDetails = 'WinRM connection detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = $destIP
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "Port: $destPort"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # SSH connections
                if ($destPort -eq "22") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1021.004'
                        DetectionModule = 'LateralMovement'
                        EventDetails = 'SSH connection detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = $destIP
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "SSH protocol connection"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # File transfer connections (T1570)
                $transferPorts = @("20", "21", "22", "80", "443", "990", "989")
                
                if ($transferPorts -contains $destPort -and $processName -notmatch "browser|chrome|firefox|edge") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1570'
                        DetectionModule = 'LateralMovement'
                        EventDetails = 'Potential file transfer connection detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = $destIP
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "Port: $destPort"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
            }
        }
        
        # Monitor file creation in admin shares (T1570)
        $fileEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=11} -MaxEvents 100 -ErrorAction SilentlyContinue
        
        foreach ($event in $fileEvents) {
            $xml = [xml]$event.ToXml()
            $targetFile = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetFilename'} | Select-Object -ExpandProperty '#text'
            $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
            
            if ($targetFile) {
                # Admin share file creation
                if ($targetFile -match "\\\\.*\\(admin\$|c\$|ipc\$)" -or $targetFile -match "\\\\.*\\SYSVOL" -or $targetFile -match "\\\\.*\\NETLOGON") {
                    $eventData = @{
                        Severity = 'CRITICAL'
                        MitreTechnique = 'T1570'
                        DetectionModule = 'LateralMovement'
                        EventDetails = 'File created in administrative share'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFile
                        RegistryKey = ''
                        AdditionalContext = "Administrative share file creation"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Taint shared content (T1080)
                $sharedPaths = @(
                    "\\\\.*\\SYSVOL",
                    "\\\\.*\\NETLOGON", 
                    "\\\\.*\\Public",
                    "\\\\.*\\Share",
                    "C:\\Users\\Public",
                    "C:\\Temp",
                    "C:\\Windows\\Temp"
                )
                
                foreach ($path in $sharedPaths) {
                    if ($targetFile -match $path) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1080'
                            DetectionModule = 'LateralMovement'
                            EventDetails = 'File created in shared location'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $targetFile
                            RegistryKey = ''
                            AdditionalContext = "Shared path: $path"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # Removable media replication (T1091)
                if ($targetFile -match "^[D-Z]:.*" -and $targetFile -notmatch "^C:") {
                    $suspiciousExtensions = @(".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar")
                    
                    foreach ($ext in $suspiciousExtensions) {
                        if ($targetFile.EndsWith($ext)) {
                            $eventData = @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1091'
                                DetectionModule = 'LateralMovement'
                                EventDetails = 'Suspicious executable created on removable media'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $targetFile
                                RegistryKey = ''
                                AdditionalContext = "Extension: $ext"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # Autorun files
                    if ($targetFile -match "autorun\.inf|autoplay\.inf") {
                        $eventData = @{
                            Severity = 'CRITICAL'
                            MitreTechnique = 'T1091'
                            DetectionModule = 'LateralMovement'
                            EventDetails = 'Autorun file created on removable media'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $targetFile
                            RegistryKey = ''
                            AdditionalContext = "Autorun mechanism detected"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                }
            }
        }
        
        # Monitor RDP and logon events (T1021.001, T1563)
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4624,4625,4778,4779)} -MaxEvents 100 -ErrorAction SilentlyContinue
        
        foreach ($event in $securityEvents) {
            $xml = [xml]$event.ToXml()
            $logonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
            $targetUserName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            $ipAddress = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
            
            # RDP logons (T1021.001)
            if ($logonType -eq "10") {
                $status = if ($event.Id -eq 4624) { "successful" } else { "failed" }
                $eventData = @{
                    Severity = 'INFO'
                    MitreTechnique = 'T1021.001'
                    DetectionModule = 'LateralMovement'
                    EventDetails = "RDP logon $status"
                    ProcessID = ''
                    ProcessName = ''
                    CommandLine = ''
                    User = $targetUserName
                    SourceIP = $ipAddress
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "LogonType: 10 (RDP)"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
            
            # RDP session hijacking indicators (T1563.002)
            if ($event.Id -eq 4778 -or $event.Id -eq 4779) {
                $sessionId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SessionID'} | Select-Object -ExpandProperty '#text'
                $clientName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ClientName'} | Select-Object -ExpandProperty '#text'
                
                $eventData = @{
                    Severity = 'WARNING'
                    MitreTechnique = 'T1563.002'
                    DetectionModule = 'LateralMovement'
                    EventDetails = 'RDP session reconnection detected'
                    ProcessID = ''
                    ProcessName = ''
                    CommandLine = ''
                    User = $targetUserName
                    SourceIP = ''
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "SessionID: $sessionId, ClientName: $clientName"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
            
            # NewCredentials logon (potential PTH/PTT) (T1550)
            if ($event.Id -eq 4624 -and $logonType -eq "9") {
                $eventData = @{
                    Severity = 'WARNING'
                    MitreTechnique = 'T1550'
                    DetectionModule = 'LateralMovement'
                    EventDetails = 'NewCredentials logon detected (potential PTH/PTT)'
                    ProcessID = ''
                    ProcessName = ''
                    CommandLine = ''
                    User = $targetUserName
                    SourceIP = $ipAddress
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "LogonType: 9 (NewCredentials)"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
        }
        
        # Monitor process access to LSASS (T1550)
        $processEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=10} -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $processEvents) {
            $xml = [xml]$event.ToXml()
            $targetImage = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetImage'} | Select-Object -ExpandProperty '#text'
            $sourceImage = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceImage'} | Select-Object -ExpandProperty '#text'
            $grantedAccess = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'GrantedAccess'} | Select-Object -ExpandProperty '#text'
            $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SourceProcessId'} | Select-Object -ExpandProperty '#text'
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
            
            if ($targetImage -match "lsass\.exe") {
                if ($grantedAccess -match "(0x1010|0x1038|0x143A|0x1410)") {
                    $eventData = @{
                        Severity = 'CRITICAL'
                        MitreTechnique = 'T1550.002'
                        DetectionModule = 'LateralMovement'
                        EventDetails = 'Suspicious LSASS process access detected'
                        ProcessID = $processId
                        ProcessName = $sourceImage
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "GrantedAccess: $grantedAccess"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
            }
        }
        
        # Monitor WinRM events
        $winrmEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'; ID=@(91,168)} -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $winrmEvents) {
            $eventData = @{
                Severity = 'INFO'
                MitreTechnique = 'T1021.006'
                DetectionModule = 'LateralMovement'
                EventDetails = 'WinRM activity detected'
                ProcessID = ''
                ProcessName = ''
                CommandLine = ''
                User = ''
                SourceIP = ''
                DestIP = ''
                FilePath = ''
                RegistryKey = ''
                AdditionalContext = "WinRM operational event"
            }
            Write-SecurityEvent -LogType 'Main' -EventData $eventData
        }
        
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'LateralMovement'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-CollectionDetection {
    try {
        # Monitor for Data from Local System (T1005)
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,11)} -MaxEvents 200 -ErrorAction SilentlyContinue
        
        foreach ($event in $sysmonEvents) {
            $xml = [xml]$event.ToXml()
            $commandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
            $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
            $targetFilename = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetFilename'} | Select-Object -ExpandProperty '#text'
            $processGuid = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessGuid'} | Select-Object -ExpandProperty '#text'
            
            if ($event.Id -eq 1 -and $commandLine) {
                # Data collection patterns (T1005)
                $dataCollectionPatterns = @(
                    "xcopy.*\/s|robocopy.*\/s|copy.*\*\.",
                    "findstr.*\/s.*\.txt|findstr.*\/s.*\.doc",
                    "dir.*\/s.*\.log|dir.*\/s.*\.txt|dir.*\/s.*\.doc",
                    "Get-ChildItem.*-Recurse.*\.(txt|doc|pdf|xls)",
                    "Select-String.*-Path.*-Pattern"
                )
                
                foreach ($pattern in $dataCollectionPatterns) {
                    if ($commandLine -match $pattern) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1005'
                            DetectionModule = 'Collection'
                            EventDetails = 'Potential local data collection detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # Network shared drive access patterns (T1039)
                if ($commandLine -match "\\\\[^\\]+\\|net use|pushd \\\\|popd|copy.*\\\\|xcopy.*\\\\|robocopy.*\\\\") {
                    $eventData = @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1039'
                        DetectionModule = 'Collection'
                        EventDetails = 'Network shared drive access detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = $commandLine
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "ProcessGuid: $processGuid"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Removable media access patterns (T1025)
                if ($commandLine -match "[A-Z]:\\.*copy|[A-Z]:\\.*xcopy|[A-Z]:\\.*robocopy" -and $commandLine -match "[D-Z]:\\") {
                    $eventData = @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1025'
                        DetectionModule = 'Collection'
                        EventDetails = 'Potential removable media data collection'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = $commandLine
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "ProcessGuid: $processGuid"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Screen capture patterns (T1113)
                $screenshotPatterns = @(
                    "Add-Type.*System\.Drawing|System\.Windows\.Forms",
                    "Graphics\.CopyFromScreen|DrawingSettings",
                    "PrintWindow|BitBlt",
                    "screenshot|screencap|printscreen",
                    "nircmd.*savescreenshot|nircmd.*screenshot"
                )
                
                foreach ($pattern in $screenshotPatterns) {
                    if ($commandLine -match $pattern) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1113'
                            DetectionModule = 'Collection'
                            EventDetails = 'Screen capture activity detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # Video capture patterns (T1125)
                if ($commandLine -match "ffmpeg.*-f.*gdigrab|vlc.*--intf.*dummy.*--vout.*dummy") {
                    $eventData = @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1125'
                        DetectionModule = 'Collection'
                        EventDetails = 'Video capture activity detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = $commandLine
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "ProcessGuid: $processGuid"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Audio capture patterns (T1123)
                if ($commandLine -match "ffmpeg.*-f.*dshow.*audio|sox.*-t.*waveaudio") {
                    $eventData = @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1123'
                        DetectionModule = 'Collection'
                        EventDetails = 'Audio capture activity detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = $commandLine
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "ProcessGuid: $processGuid"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Clipboard access patterns (T1115)
                $clipboardPatterns = @(
                    "Get-Clipboard|Set-Clipboard",
                    "Windows\.Forms\.Clipboard",
                    "clip\.exe",
                    "AddClipboardFormatListener|GetClipboardData"
                )
                
                foreach ($pattern in $clipboardPatterns) {
                    if ($commandLine -match $pattern) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1115'
                            DetectionModule = 'Collection'
                            EventDetails = 'Clipboard access detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # Input capture/keylogging patterns (T1056)
                $keylogPatterns = @(
                    "SetWindowsHookEx|GetAsyncKeyState",
                    "RegisterHotKey|UnregisterHotKey",
                    "keylogger|keystroke",
                    "GetKeyboardState|GetKeyState"
                )
                
                foreach ($pattern in $keylogPatterns) {
                    if ($commandLine -match $pattern) {
                        $eventData = @{
                            Severity = 'CRITICAL'
                            MitreTechnique = 'T1056'
                            DetectionModule = 'Collection'
                            EventDetails = 'Potential input capture activity detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # Archive/compression patterns (T1560)
                $archivePatterns = @(
                    "7z\.exe.*a.*-p|winrar\.exe.*a.*-hp",
                    "tar.*-c.*-z|gzip.*-r",
                    "Compress-Archive|New-ZipFile",
                    "makecab\.exe|expand\.exe"
                )
                
                foreach ($pattern in $archivePatterns) {
                    if ($commandLine -match $pattern) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1560'
                            DetectionModule = 'Collection'
                            EventDetails = 'Data archiving activity detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
                
                # Data staging patterns (T1074)
                if ($commandLine -match "copy.*\\temp\\|copy.*\\appdata\\|move.*\\temp\\|xcopy.*\\temp\\") {
                    $eventData = @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1074'
                        DetectionModule = 'Collection'
                        EventDetails = 'Data staging activity detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = $commandLine
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "ProcessGuid: $processGuid"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Automated collection patterns (T1119)
                $automatedPatterns = @(
                    "for.*in.*do.*copy|for.*in.*do.*xcopy",
                    "while.*copy|while.*xcopy",
                    "ForEach.*Copy-Item|ForEach.*Move-Item",
                    "Get-ChildItem.*ForEach.*Copy",
                    "dir.*\\/s.*\\|.*findstr.*\\|.*copy"
                )
                
                foreach ($pattern in $automatedPatterns) {
                    if ($commandLine -match $pattern) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1119'
                            DetectionModule = 'Collection'
                            EventDetails = 'Automated data collection detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        break
                    }
                }
            }
            
            # File creation monitoring
            if ($event.Id -eq 11 -and $targetFilename) {
                # Sensitive file access (T1005)
                if ($targetFilename -match "\\Users\\.*\\Documents|\\Users\\.*\\Desktop|\\ProgramData\\.*\.log|\\Windows\\System32\\config") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1005'
                        DetectionModule = 'Collection'
                        EventDetails = 'Access to sensitive local data location'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "Sensitive data access"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Network share file operations (T1039)
                if ($targetFilename -match "\\\\[^\\]+\\") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1039'
                        DetectionModule = 'Collection'
                        EventDetails = 'Network share file operation detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "Network share access"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Removable media operations (T1025)
                if ($targetFilename -match "^[D-Z]:\\") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1025'
                        DetectionModule = 'Collection'
                        EventDetails = 'Removable media file operation detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "Removable drive access"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Screenshot files (T1113)
                if ($targetFilename -match "\.(png|jpg|jpeg|bmp|gif)$") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1113'
                        DetectionModule = 'Collection'
                        EventDetails = 'Image file created - potential screenshot'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "Image file creation"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Video files (T1125)
                if ($targetFilename -match "\.(avi|mp4|wmv|mov|mkv)$") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1125'
                        DetectionModule = 'Collection'
                        EventDetails = 'Video file created'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "Video file creation"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Audio files (T1123)
                if ($targetFilename -match "\.(wav|mp3|wma|flac|m4a)$") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1123'
                        DetectionModule = 'Collection'
                        EventDetails = 'Audio file created'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "Audio file creation"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Archive files (T1560)
                if ($targetFilename -match "\.(zip|rar|7z|tar|gz|cab)$") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1560'
                        DetectionModule = 'Collection'
                        EventDetails = 'Archive file created'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "Archive file creation"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Staged data files (T1074)
                if ($targetFilename -match "\\Temp\\.*\.(txt|doc|pdf|xls)|\\AppData\\.*\.(txt|doc|pdf|xls)") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1074'
                        DetectionModule = 'Collection'
                        EventDetails = 'File staged in temporary location'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "Data staging detected"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
            }
        }
        
        # Monitor DLL loading for hooks (T1056)
        $dllEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=7} -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $dllEvents) {
            $xml = [xml]$event.ToXml()
            $imageLoaded = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ImageLoaded'} | Select-Object -ExpandProperty '#text'
            $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
            
            # Graphics/screen capture libraries (T1113)
            if ($imageLoaded -match "gdi32\.dll|user32\.dll" -and $processName -match "powershell|cmd") {
                $eventData = @{
                    Severity = 'INFO'
                    MitreTechnique = 'T1113'
                    DetectionModule = 'Collection'
                    EventDetails = 'Graphics library loaded by script'
                    ProcessID = $processId
                    ProcessName = $processName
                    CommandLine = ''
                    User = $user
                    SourceIP = ''
                    DestIP = ''
                    FilePath = $imageLoaded
                    RegistryKey = ''
                    AdditionalContext = "Graphics DLL loading"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
            
            # Hook-related DLL loading (T1056)
            if ($imageLoaded -match "user32\.dll" -and $processName -match "powershell|cmd|rundll32") {
                $eventData = @{
                    Severity = 'INFO'
                    MitreTechnique = 'T1056'
                    DetectionModule = 'Collection'
                    EventDetails = 'User32.dll loaded - potential hook installation'
                    ProcessID = $processId
                    ProcessName = $processName
                    CommandLine = ''
                    User = $user
                    SourceIP = ''
                    DestIP = ''
                    FilePath = $imageLoaded
                    RegistryKey = ''
                    AdditionalContext = "Hook DLL loading"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
        }
        
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'Collection'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-CommandAndControlDetection {
    try {
        # Monitor network connections and process creation
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,3,22)} -MaxEvents 200 -ErrorAction SilentlyContinue
        
        foreach ($event in $sysmonEvents) {
            $xml = [xml]$event.ToXml()
            
            if ($event.Id -eq 1) {
                $commandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                $processGuid = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessGuid'} | Select-Object -ExpandProperty '#text'
                
                if ($commandLine) {
                    # Data encoding patterns (T1132)
                    if ($commandLine -match "base64|FromBase64String|ToBase64String|-enc|-decode") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1132.001'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Base64 encoding/decoding detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    if ($commandLine -match "certutil.*-encode|certutil.*-decode") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1132.001'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Certutil encoding/decoding detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Protocol tunneling patterns (T1572)
                    if ($commandLine -match "ssh.*-L|ssh.*-R|ssh.*-D|stunnel|socat|chisel|ngrok|plink") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1572'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Potential protocol tunneling tool'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # DNS tunneling tools (T1572)
                    if ($commandLine -match "dnscat|iodine|dns2tcp") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1572'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'DNS tunneling tool detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Proxy/anonymization tools (T1090)
                    if ($commandLine -match "proxychains|tor|i2p|freegate|ultrasurf|psiphon") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1090.003'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Proxy/anonymization tool detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Encryption tool usage (T1573)
                    if ($commandLine -match "openssl|gpg|aes|des|blowfish|twofish|serpent") {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1573.001'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Encryption tool usage detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Download/transfer tools (T1105)
                    if ($commandLine -match "wget|curl|bitsadmin|certutil.*-urlcache|powershell.*downloadfile|invoke-webrequest") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1105'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Download tool execution detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # FTP/TFTP transfers (T1105)
                    if ($commandLine -match "ftp.*-s|tftp.*-i|scp|rsync") {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1105'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'File transfer protocol usage detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                }
                
                # Remote access tools (T1219)
                if ($processName -match "teamviewer|anydesk") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1219'
                        DetectionModule = 'CommandAndControl'
                        EventDetails = 'Remote access software execution detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = $commandLine
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "ProcessGuid: $processGuid"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
            }
            
            # Network connection monitoring (T1071)
            if ($event.Id -eq 3) {
                $destinationPort = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationPort'} | Select-Object -ExpandProperty '#text'
                $destinationIp = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationIp'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                $protocol = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Protocol'} | Select-Object -ExpandProperty '#text'
                
                if ($destinationPort -and $destinationIp) {
                    # Suspicious application protocols (T1071)
                    if (($destinationPort -eq "80" -or $destinationPort -eq "443") -and $processName -notmatch "chrome|firefox|iexplore|edge|browser") {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1071.001'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Non-browser process using web protocols'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = $destinationIp
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Port: $destinationPort, Protocol: HTTP/HTTPS"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Suspicious DNS traffic (T1071.004)
                    if ($destinationPort -eq "53" -and $processName -notmatch "svchost|dns|nslookup|dig") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1071.004'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Non-standard process using DNS'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = $destinationIp
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Port: $destinationPort, Protocol: DNS"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Non-application layer protocols (T1095)
                    if ($protocol -match "icmp|raw|igmp" -or $destinationPort -eq "0") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1095'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Non-application layer protocol usage'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = $destinationIp
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Protocol: $protocol, Port: $destinationPort"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Non-standard ports (T1571)
                    $portInt = [int]$destinationPort
                    if (($portInt -gt 1024 -and $portInt -lt 5000) -or ($portInt -gt 8000 -and $portInt -lt 9000)) {
                        if ($processName -notmatch "chrome|firefox|iexplore|edge|teams|skype|zoom") {
                            $eventData = @{
                                Severity = 'INFO'
                                MitreTechnique = 'T1571'
                                DetectionModule = 'CommandAndControl'
                                EventDetails = 'Communication on non-standard port'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = $destinationIp
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Port: $destinationPort"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        }
                    }
                    
                    # High port usage (T1571)
                    if ($portInt -gt 49152) {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1571'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Communication on high port number'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = $destinationIp
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Port: $destinationPort"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Encrypted protocols on non-standard processes (T1573)
                    $encryptedPorts = @("443", "993", "995", "465", "22", "990")
                    if ($encryptedPorts -contains $destinationPort -and $processName -notmatch "chrome|firefox|iexplore|edge|outlook|thunderbird|ssh") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1573.002'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Non-standard process using encrypted protocol'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = $destinationIp
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Port: $destinationPort, Encrypted protocol"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # RAT port detection (T1219)
                    $ratPorts = @("3389", "5900", "5901", "5800", "4899", "6129", "1604")
                    if ($ratPorts -contains $destinationPort) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1219'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Connection to common RAT port detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = $destinationIp
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Port: $destinationPort, RAT port"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Port knocking patterns (T1205)
                    if ($portInt -lt 1024) {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1205'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Connection to low-numbered port (potential port knocking)'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = $destinationIp
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Port: $destinationPort, Low port access"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                }
            }
            
            # DNS query monitoring (T1568, T1071.004)
            if ($event.Id -eq 22) {
                $queryName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'QueryName'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                
                if ($queryName) {
                    # DNS tunneling patterns (T1071.004)
                    if ($queryName.Length -gt 50 -or ($queryName -split '\.').Count -gt 5) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1071.004'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Potential DNS tunneling detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "QueryName: $queryName"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # DGA domain patterns (T1568.002)
                    if ($queryName -match "^[a-z0-9]{8,20}\.(com|net|org|info)$" -and $queryName -notmatch "[aeiou]{2}") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1568.002'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Potential DGA domain detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Domain: $queryName"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Suspicious TLDs (T1568.001)
                    if ($queryName -match "\.(tk|ml|ga|cf)$") {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1568.001'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'Suspicious top-level domain query'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Domain: $queryName"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # DNS over HTTPS (T1568.003)
                    if ($queryName -match "dns\.google|cloudflare-dns|quad9") {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1568.003'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'DNS over HTTPS usage detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "DoH Provider: $queryName"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Web service C2 detection (T1102)
                    $webServices = @{
                        "pastebin.com" = "T1102 - Dead Drop Resolver"
                        "github.com" = "T1102 - Dead Drop Resolver"
                        "dropbox.com" = "T1102 - Dead Drop Resolver"
                        "googledrive.com" = "T1102 - Dead Drop Resolver"
                        "onedrive.com" = "T1102 - Dead Drop Resolver"
                        "twitter.com" = "T1102 - Bidirectional Communication"
                        "reddit.com" = "T1102 - Dead Drop Resolver"
                        "instagram.com" = "T1102 - One-Way Communication"
                    }
                    
                    foreach ($service in $webServices.Keys) {
                        if ($queryName -match [regex]::Escape($service)) {
                            $eventData = @{
                                Severity = 'INFO'
                                MitreTechnique = 'T1102'
                                DetectionModule = 'CommandAndControl'
                                EventDetails = 'Connection to potential web service C2'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Service: $service, QueryName: $queryName"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                }
            }
        }
        
        # Monitor file operations for C2 artifacts
        $fileEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(11,23)} -MaxEvents 100 -ErrorAction SilentlyContinue
        
        foreach ($event in $fileEvents) {
            $xml = [xml]$event.ToXml()
            $targetFilename = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetFilename'} | Select-Object -ExpandProperty '#text'
            $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
            
            if ($targetFilename) {
                # Removable media communication (T1092)
                if ($targetFilename -match "^[D-Z]:\\") {
                    if ($event.Id -eq 11) {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1092'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'File created on removable media'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $targetFilename
                            RegistryKey = ''
                            AdditionalContext = "Removable media communication"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    if ($event.Id -eq 23) {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1092'
                            DetectionModule = 'CommandAndControl'
                            EventDetails = 'File deleted from removable media'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $targetFilename
                            RegistryKey = ''
                            AdditionalContext = "Potential cleanup"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                }
                
                # Steganography/obfuscation files (T1001)
                if ($targetFilename -match "\.(jpg|png|gif|bmp|wav|mp3)$" -and $targetFilename -match "temp|tmp|appdata") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1001.002'
                        DetectionModule = 'CommandAndControl'
                        EventDetails = 'Media file created in suspicious location'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "Potential steganography"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
                
                # Downloaded executable files (T1105)
                if ($targetFilename -match "\.(exe|dll|scr|bat|cmd|ps1|vbs|js)$" -and $targetFilename -match "temp|tmp|downloads|appdata") {
                    $eventData = @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1105'
                        DetectionModule = 'CommandAndControl'
                        EventDetails = 'Executable file in download/temp location'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "Potential ingress tool transfer"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
            }
        }
        
        # Monitor registry modifications for proxy settings (T1090)
        $regEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=13} -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $regEvents) {
            $xml = [xml]$event.ToXml()
            $targetObject = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetObject'} | Select-Object -ExpandProperty '#text'
            $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
            $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
            $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
            
            if ($targetObject -match "ProxyServer|ProxyEnable|ProxyOverride") {
                $eventData = @{
                    Severity = 'WARNING'
                    MitreTechnique = 'T1090.001'
                    DetectionModule = 'CommandAndControl'
                    EventDetails = 'Proxy configuration modified in registry'
                    ProcessID = $processId
                    ProcessName = $processName
                    CommandLine = ''
                    User = $user
                    SourceIP = ''
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = $targetObject
                    AdditionalContext = "Proxy settings modification"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
        }
        
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'CommandAndControl'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-ExfiltrationDetection {
    try {
        # Monitor for Automated Exfiltration (T1020) and Exfiltration Over C2 Channel (T1041)
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,3,11,22,23)} -MaxEvents 200 -ErrorAction SilentlyContinue
        
        # OT-specific file extensions and paths for enhanced detection
        $OTFileExtensions = @(
            ".plc", ".hmi", ".scada", ".cfg", ".config", ".ini", ".xml", ".json", ".csv", ".log",
            ".db", ".sqlite", ".mdb", ".accdb", ".xls", ".xlsx", ".txt", ".dat", ".backup", ".bak",
            ".his", ".trend", ".alarm", ".event", ".recipe", ".program", ".ladder", ".st", ".fbd"
        )
        
        $OTPaths = @(
            "C:\Program Files\*",
            "C:\ProgramData\*", 
            "C:\Users\*\Documents\*",
            "*\HMI\*",
            "*\SCADA\*",
            "*\PLC\*",
            "*\Historian\*",
            "*\OPC\*"
        )
        
        foreach ($event in $sysmonEvents) {
            $xml = [xml]$event.ToXml()
            
            if ($event.Id -eq 1) {
                $commandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                $processGuid = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessGuid'} | Select-Object -ExpandProperty '#text'
                
                if ($commandLine) {
                    # Automated exfiltration patterns (T1020)
                    $automationPatterns = @(
                        "schtasks.*create.*daily|schtasks.*create.*hourly|schtasks.*create.*minute",
                        "powershell.*-windowstyle.*hidden.*invoke-webrequest",
                        "curl.*-o.*--data-binary",
                        "wget.*--post-file|wget.*--post-data",
                        "robocopy.*\\\\.*\/E.*\/R:0",
                        "xcopy.*\/s.*\/h.*\/y.*\\\\",
                        "7z.*a.*-r.*-mx=0",
                        "winrar.*a.*-r.*-ep1"
                    )
                    
                    foreach ($pattern in $automationPatterns) {
                        if ($commandLine -match $pattern) {
                            $eventData = @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1020'
                                DetectionModule = 'Exfiltration'
                                EventDetails = 'Automated exfiltration activity detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # C2 communication patterns (T1041)
                    $c2Patterns = @(
                        "powershell.*invoke-webrequest.*-method.*post.*-body",
                        "curl.*-X.*POST.*--data",
                        "certutil.*-urlcache.*-split.*-f.*http",
                        "bitsadmin.*\/transfer.*\/download.*\/priority.*high",
                        "mshta.*http.*\.hta",
                        "regsvr32.*\/s.*\/n.*\/u.*\/i:http",
                        "wmic.*process.*call.*create.*cmd.*\/c.*powershell"
                    )
                    
                    foreach ($pattern in $c2Patterns) {
                        if ($commandLine -match $pattern) {
                            $eventData = @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1041'
                                DetectionModule = 'Exfiltration'
                                EventDetails = 'C2 channel communication detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # Alternative protocol exfiltration patterns (T1048)
                    if ($commandLine -match "ftp.*-s|sftp.*-b|scp.*-r|rsync.*-av") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1048'
                            DetectionModule = 'Exfiltration'
                            EventDetails = 'Alternative protocol data transfer detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Web service exfiltration patterns (T1567)
                    if ($commandLine -match "dropbox|googledrive|onedrive|icloud|mega\.nz|wetransfer|pastebin|github|gitlab") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1567'
                            DetectionModule = 'Exfiltration'
                            EventDetails = 'Web service exfiltration detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                }
            }
            
            # Network connection monitoring (T1041, T1048, T1567)
            if ($event.Id -eq 3) {
                $destinationIp = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationIp'} | Select-Object -ExpandProperty '#text'
                $destinationPort = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationPort'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                $destinationHostname = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'DestinationHostname'} | Select-Object -ExpandProperty '#text'
                
                if ($destinationIp -and $destinationIp -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|::1|fe80:)") {
                    # External connections from automation tools (T1020)
                    if ($processName -match "powershell|cmd|wscript|cscript|python|curl|wget") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1020'
                            DetectionModule = 'Exfiltration'
                            EventDetails = 'External connection from automation tool'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = $destinationIp
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Port: $destinationPort, Hostname: $destinationHostname"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Suspicious processes making external connections (T1041)
                    $suspiciousProcesses = @("powershell", "cmd", "certutil", "bitsadmin", "mshta", "regsvr32", "wmic", "rundll32")
                    
                    foreach ($suspiciousProcess in $suspiciousProcesses) {
                        if ($processName -match $suspiciousProcess) {
                            $eventData = @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1041'
                                DetectionModule = 'Exfiltration'
                                EventDetails = 'Suspicious process external connection'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = $destinationIp
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Port: $destinationPort, Suspicious process"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # Alternative protocol detection (T1048)
                    $alternativePorts = @("21", "22", "69", "443", "53", "143", "993", "995")
                    if ($alternativePorts -contains $destinationPort) {
                        $eventData = @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1048'
                            DetectionModule = 'Exfiltration'
                            EventDetails = 'Alternative protocol connection detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = $destinationIp
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Port: $destinationPort, Protocol analysis"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                }
            }
            
            # File operations monitoring (T1052, OT data protection)
            if ($event.Id -eq 11) {
                $targetFilename = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetFilename'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                
                if ($targetFilename) {
                    # Removable media exfiltration (T1052)
                    $driveLetter = $targetFilename.Substring(0, 2)
                    if ($targetFilename -match "^[D-Z]:\\") {
                        # Check for OT-related files
                        $isOTFile = $false
                        foreach ($extension in $OTFileExtensions) {
                            if ($targetFilename.EndsWith($extension)) {
                                $isOTFile = $true
                                break
                            }
                        }
                        
                        if ($isOTFile) {
                            $eventData = @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1052'
                                DetectionModule = 'Exfiltration'
                                EventDetails = 'OT-related file copied to removable media'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $targetFilename
                                RegistryKey = ''
                                AdditionalContext = "Drive: $driveLetter, OT file detected"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        } else {
                            $eventData = @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1052'
                                DetectionModule = 'Exfiltration'
                                EventDetails = 'File copied to removable media'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $targetFilename
                                RegistryKey = ''
                                AdditionalContext = "Drive: $driveLetter"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        }
                    }
                    
                    # Data staging detection (T1074)
                    if ($targetFilename -match "temp|staging|export|backup.*\d{8}|dump") {
                        # Check if it's an OT file
                        $isOTFile = $false
                        foreach ($extension in $OTFileExtensions) {
                            if ($targetFilename.EndsWith($extension)) {
                                $isOTFile = $true
                                break
                            }
                        }
                        
                        foreach ($path in $OTPaths) {
                            if ($targetFilename -like $path) {
                                $isOTFile = $true
                                break
                            }
                        }
                        
                        if ($isOTFile) {
                            $eventData = @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1074'
                                DetectionModule = 'Exfiltration'
                                EventDetails = 'OT data staging detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $targetFilename
                                RegistryKey = ''
                                AdditionalContext = "OT file staging detected"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        }
                    }
                }
            }
            
            # DNS query monitoring for tunneling (T1048)
            if ($event.Id -eq 22) {
                $queryName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'QueryName'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                
                if ($queryName) {
                    # DNS tunneling patterns
                    if ($queryName.Length -gt 50 -or ($queryName -split '\.').Count -gt 5) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1048.003'
                            DetectionModule = 'Exfiltration'
                            EventDetails = 'Potential DNS tunneling detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "QueryName: $queryName, Length: $($queryName.Length)"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Cloud service DNS queries (T1567)
                    $cloudServices = @(
                        "dropbox.com",
                        "googledrive.com",
                        "onedrive.live.com",
                        "mega.nz",
                        "wetransfer.com",
                        "pastebin.com",
                        "github.com",
                        "gitlab.com"
                    )
                    
                    foreach ($service in $cloudServices) {
                        if ($queryName -match [regex]::Escape($service)) {
                            $eventData = @{
                                Severity = 'INFO'
                                MitreTechnique = 'T1567'
                                DetectionModule = 'Exfiltration'
                                EventDetails = 'Cloud service DNS query detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Service: $service, QueryName: $queryName"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                }
            }
            
            # File deletion monitoring for cleanup (T1070)
            if ($event.Id -eq 23) {
                $targetFilename = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetFilename'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                
                if ($targetFilename -and ($targetFilename -match "temp|staging|export|backup.*\d{8}|dump")) {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1070'
                        DetectionModule = 'Exfiltration'
                        EventDetails = 'Potential cleanup of staged data detected'
                        ProcessID = $processId
                        ProcessName = $processName
                        CommandLine = ''
                        User = $user
                        SourceIP = ''
                        DestIP = ''
                        FilePath = $targetFilename
                        RegistryKey = ''
                        AdditionalContext = "File deletion after potential staging"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
            }
        }
        
        # Monitor Task Scheduler for scheduled transfers (T1029)
        $taskEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; ID=@(106,200,201)} -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $taskEvents) {
            $xml = [xml]$event.ToXml()
            $taskName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TaskName'} | Select-Object -ExpandProperty '#text'
            $actionName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ActionName'} | Select-Object -ExpandProperty '#text'
            
            if ($event.Id -eq 106 -and $taskName -and $actionName) {
                # Scheduled data transfer tasks
                if ($taskName -match "backup|export|sync|transfer|upload|send|copy|move" -and
                    $actionName -match "powershell|cmd|robocopy|xcopy|curl|wget|scp|ftp") {
                    $eventData = @{
                        Severity = 'WARNING'
                        MitreTechnique = 'T1029'
                        DetectionModule = 'Exfiltration'
                        EventDetails = 'Scheduled task with data transfer capability registered'
                        ProcessID = ''
                        ProcessName = ''
                        CommandLine = $actionName
                        User = ''
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "TaskName: $taskName"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
            }
            
            if ($event.Id -eq 200 -and $taskName -and $actionName) {
                # Scheduled task execution
                if ($taskName -match "backup|export|sync|transfer|upload" -and
                    $actionName -match "powershell|cmd|robocopy|xcopy|curl|wget") {
                    $eventData = @{
                        Severity = 'INFO'
                        MitreTechnique = 'T1029'
                        DetectionModule = 'Exfiltration'
                        EventDetails = 'Data transfer scheduled task executed'
                        ProcessID = ''
                        ProcessName = ''
                        CommandLine = $actionName
                        User = ''
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "TaskName: $taskName"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
            }
        }
        
        # Monitor System events for USB device insertion (T1052)
        $systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=@(20001,20003,4001)} -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $systemEvents) {
            if ($event.Id -in @(20001, 20003)) {
                $eventData = @{
                    Severity = 'INFO'
                    MitreTechnique = 'T1052.001'
                    DetectionModule = 'Exfiltration'
                    EventDetails = 'USB device activity detected'
                    ProcessID = ''
                    ProcessName = ''
                    CommandLine = ''
                    User = ''
                    SourceIP = ''
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "USB device insertion/removal"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
        }
        
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'Exfiltration'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-ImpactDetection {
    try {
        # Monitor for Data Encrypted for Impact (T1486) and other Impact techniques
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,11,23)} -MaxEvents 200 -ErrorAction SilentlyContinue
        
        # OT-specific file extensions, directories, and services for enhanced protection
        $OTFileExtensions = @(
            ".plc", ".hmi", ".scada", ".cfg", ".config", ".ini", ".xml", ".json", ".csv", ".log",
            ".db", ".sqlite", ".mdb", ".accdb", ".xls", ".xlsx", ".txt", ".dat", ".backup", ".bak",
            ".his", ".trend", ".alarm", ".event", ".recipe", ".program", ".ladder", ".st", ".fbd",
            ".fbd", ".sfc", ".il", ".ld", ".gxw", ".gx3", ".rslogix", ".rslogix5000", ".acd", ".apa"
        )
        
        $OTCriticalDirs = @(
            "C:\Program Files\*\HMI\*",
            "C:\Program Files\*\SCADA\*",
            "C:\Program Files\*\PLC\*",
            "C:\ProgramData\*\Historian\*",
            "C:\ProgramData\*\OPC\*",
            "C:\Users\*\Documents\*HMI*",
            "C:\Users\*\Documents\*SCADA*",
            "C:\Users\*\Documents\*Control*",
            "*\Rockwell\*",
            "*\Schneider*",
            "*\Siemens\*",
            "*\ABB\*",
            "*\GE\*",
            "*\Honeywell\*"
        )
        
        $OTServices = @(
            "OpcEnum", "OPCExpert", "KEPServerEX", "RSLinx", "FactoryTalk*", 
            "WonderwareInTouch", "InTouch*", "Historian*", "PlantPAx",
            "Unity Pro", "TIA Portal", "Step 7", "WinCC", "iFIX",
            "CitectSCADA", "Vijeo*", "Control Expert", "SoMachine"
        )
        
        foreach ($event in $sysmonEvents) {
            $xml = [xml]$event.ToXml()
            
            if ($event.Id -eq 1) {
                $commandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                $processGuid = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessGuid'} | Select-Object -ExpandProperty '#text'
                
                if ($commandLine) {
                    # Ransomware patterns (T1486)
                    $ransomwarePatterns = @(
                        "vssadmin.*delete.*shadows",
                        "wbadmin.*delete.*backup",
                        "bcdedit.*set.*recoveryenabled.*no",
                        "bcdedit.*set.*bootstatuspolicy.*ignoreallfailures",
                        "wevtutil.*cl.*Application",
                        "wevtutil.*cl.*System",
                        "wevtutil.*cl.*Security",
                        "cipher.*\/w:C:",
                        "sdelete.*-z.*C:",
                        "icacls.*\/grant.*Everyone:F.*\/T.*\/C",
                        "takeown.*\/f.*\/r.*\/d.*y",
                        "net.*stop.*`"Vss`"",
                        "net.*stop.*`"MSSQL.*`"",
                        "net.*stop.*`"MySQL.*`"",
                        "reg.*add.*HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender.*DisableRealtimeMonitoring.*1",
                        "powershell.*-enc.*[A-Za-z0-9+/]{100,}"
                    )
                    
                    foreach ($pattern in $ransomwarePatterns) {
                        if ($commandLine -match $pattern) {
                            $eventData = @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1486'
                                DetectionModule = 'Impact'
                                EventDetails = 'Ransomware activity detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # Service stop patterns (T1489)
                    if ($commandLine -match "net.*stop|sc.*stop|Get-Service.*Stop-Service|Stop-Service") {
                        # Check if it's targeting OT services
                        $isOTService = $false
                        foreach ($service in $OTServices) {
                            if ($commandLine -match [regex]::Escape($service)) {
                                $isOTService = $true
                                $severity = 'CRITICAL'
                                break
                            }
                        }
                        
                        # Check for critical services
                        $criticalServices = @("Windefend", "MpsSvc", "WinRM", "BITS", "Spooler", "W32Time", "Dnscache")
                        foreach ($service in $criticalServices) {
                            if ($commandLine -match [regex]::Escape($service)) {
                                $isOTService = $true
                                $severity = 'WARNING'
                                break
                            }
                        }
                        
                        if ($isOTService) {
                            $eventData = @{
                                Severity = $severity
                                MitreTechnique = 'T1489'
                                DetectionModule = 'Impact'
                                EventDetails = if ($severity -eq 'CRITICAL') { 'OT service stop attempt detected' } else { 'Critical service stop attempt detected' }
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "ProcessGuid: $processGuid"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                        }
                    }
                    
                    # System shutdown/reboot patterns (T1529)
                    if ($commandLine -match "shutdown.*\/s|shutdown.*\/r|Restart-Computer|Stop-Computer|wmic.*os.*Win32_OperatingSystem.*Shutdown") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1529'
                            DetectionModule = 'Impact'
                            EventDetails = 'System shutdown/reboot command detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Data destruction patterns (T1485)
                    $destructionPatterns = @(
                        "del.*\/s.*\/q.*\/f.*\*.*",
                        "rmdir.*\/s.*\/q.*",
                        "rd.*\/s.*\/q.*",
                        "format.*\/fs:.*\/q.*\/y",
                        "cipher.*\/w:.*",
                        "sdelete.*-z.*-s.*",
                        "powershell.*Remove-Item.*-Recurse.*-Force",
                        "wmic.*logicaldisk.*format.*quick"
                    )
                    
                    foreach ($pattern in $destructionPatterns) {
                        if ($commandLine -match $pattern) {
                            $eventData = @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1485'
                                DetectionModule = 'Impact'
                                EventDetails = 'Data destruction activity detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # Disk wipe patterns (T1561)
                    if ($commandLine -match "diskpart.*clean.*all|cipher.*\/w|sdelete.*-z|dd.*if=\/dev\/zero") {
                        $eventData = @{
                            Severity = 'CRITICAL'
                            MitreTechnique = 'T1561'
                            DetectionModule = 'Impact'
                            EventDetails = 'Disk wipe activity detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Account access removal patterns (T1531)
                    if ($commandLine -match "net.*user.*\/delete|net.*localgroup.*administrators.*\/delete|Remove-LocalUser|Disable-LocalUser") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1531'
                            DetectionModule = 'Impact'
                            EventDetails = 'Account access removal detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Endpoint DoS patterns (T1499)
                    $dosPatterns = @(
                        "ping.*-t.*-l.*65500",
                        "ping.*flood",
                        "hping.*-S.*--flood",
                        "powershell.*while.*\$true.*Invoke-WebRequest",
                        "for.*\/l.*ping.*-n.*1000000"
                    )
                    
                    foreach ($pattern in $dosPatterns) {
                        if ($commandLine -match $pattern) {
                            $eventData = @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1499'
                                DetectionModule = 'Impact'
                                EventDetails = 'Endpoint DoS activity detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern, ProcessGuid: $processGuid"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # Defacement patterns (T1491)
                    if ($commandLine -match "echo.*>.*index.html|echo.*>.*default.htm|copy.*ransom.*html") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1491'
                            DetectionModule = 'Impact'
                            EventDetails = 'Potential defacement activity detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                }
            }
            
            # File creation/modification monitoring for encryption (T1486) and destruction (T1485)
            if ($event.Id -eq 11) {
                $targetFilename = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetFilename'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                
                if ($targetFilename) {
                    # Ransomware file extensions
                    $ransomwareExtensions = @(
                        ".encrypted", ".locked", ".crypto", ".crypt", ".enc", ".vault", ".xxx", ".zzz", ".aaa",
                        ".abc", ".xyz", ".xtbl", ".cerber", ".locky", ".zepto", ".odin", ".thor", ".aesir",
                        ".teslacrypt", ".cryptolocker", ".cryptowall", ".wannacry", ".petya", ".goldeneye",
                        ".jaff", ".bart", ".sage", ".spora", ".globe", ".purge", ".dharma", ".karma",
                        ".osiris", ".legion", ".atom", ".fonix", ".maze", ".eking", ".phobos", ".makop",
                        ".conti", ".ryuk", ".revil", ".sodinokibi", ".darkside", ".babuk", ".avaddon"
                    )
                    
                    foreach ($extension in $ransomwareExtensions) {
                        if ($targetFilename.EndsWith($extension)) {
                            # Check if it's an OT file
                            $isOTFile = $false
                            $originalExtension = ""
                            foreach ($otExt in $OTFileExtensions) {
                                if ($targetFilename -match [regex]::Escape($otExt) + [regex]::Escape($extension) + "$") {
                                    $isOTFile = $true
                                    $originalExtension = $otExt
                                    break
                                }
                            }
                            
                            $severity = if ($isOTFile) { 'CRITICAL' } else { 'WARNING' }
                            $details = if ($isOTFile) { 'OT file encrypted by ransomware' } else { 'File encrypted by ransomware' }
                            
                            $eventData = @{
                                Severity = $severity
                                MitreTechnique = 'T1486'
                                DetectionModule = 'Impact'
                                EventDetails = $details
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $targetFilename
                                RegistryKey = ''
                                AdditionalContext = "Extension: $extension, OriginalExtension: $originalExtension"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # Ransom note creation
                    $ransomNotePatterns = @(
                        "readme.*\.txt$", "decrypt.*\.txt$", "restore.*\.txt$", "recovery.*\.txt$",
                        "how.*to.*decrypt.*\.txt$", "ransom.*\.txt$", "your.*files.*\.txt$",
                        "important.*\.txt$", "attention.*\.txt$", "help.*decrypt.*\.txt$"
                    )
                    
                    foreach ($pattern in $ransomNotePatterns) {
                        if ($targetFilename -match $pattern) {
                            $eventData = @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1486'
                                DetectionModule = 'Impact'
                                EventDetails = 'Ransom note created'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $targetFilename
                                RegistryKey = ''
                                AdditionalContext = "Pattern: $pattern"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # OT critical directory monitoring
                    foreach ($dir in $OTCriticalDirs) {
                        if ($targetFilename -like $dir) {
                            $eventData = @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1485'
                                DetectionModule = 'Impact'
                                EventDetails = 'File activity in OT critical directory'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = $targetFilename
                                RegistryKey = ''
                                AdditionalContext = "OT critical directory"
                            }
                            Write-SecurityEvent -LogType 'Main' -EventData $eventData
                            break
                        }
                    }
                    
                    # Backup file tampering (T1485)
                    if ($targetFilename -match "backup|\.bak$|\.backup$|\.vhd$|\.vhdx$|\.vmdk$") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1485'
                            DetectionModule = 'Impact'
                            EventDetails = 'Backup file tampering detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $targetFilename
                            RegistryKey = ''
                            AdditionalContext = "Backup file modification"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                }
            }
            
            # File deletion monitoring (T1485, T1070)
            if ($event.Id -eq 23) {
                $targetFilename = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetFilename'} | Select-Object -ExpandProperty '#text'
                $processName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Image'} | Select-Object -ExpandProperty '#text'
                $processId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ProcessId'} | Select-Object -ExpandProperty '#text'
                $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'User'} | Select-Object -ExpandProperty '#text'
                
                if ($targetFilename) {
                    # OT file deletion
                    $isOTFile = $false
                    foreach ($extension in $OTFileExtensions) {
                        if ($targetFilename.EndsWith($extension)) {
                            $isOTFile = $true
                            break
                        }
                    }
                    
                    foreach ($dir in $OTCriticalDirs) {
                        if ($targetFilename -like $dir) {
                            $isOTFile = $true
                            break
                        }
                    }
                    
                    if ($isOTFile) {
                        $eventData = @{
                            Severity = 'CRITICAL'
                            MitreTechnique = 'T1485'
                            DetectionModule = 'Impact'
                            EventDetails = 'OT file deletion detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $targetFilename
                            RegistryKey = ''
                            AdditionalContext = "OT critical file deletion"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                    
                    # Backup and log file deletion
                    if ($targetFilename -match "backup|\.bak$|\.backup$|\.log$|shadow.*copy") {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1485'
                            DetectionModule = 'Impact'
                            EventDetails = 'Backup or log file deletion detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = $targetFilename
                            RegistryKey = ''
                            AdditionalContext = "Critical file deletion"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                }
            }
        }
        
        # Monitor Security events for account lockouts and modifications
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4725,4726,4740,4767,4794)} -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $securityEvents) {
            $xml = [xml]$event.ToXml()
            $targetUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            $subjectUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'} | Select-Object -ExpandProperty '#text'
            
            if ($event.Id -eq 4725) { # User account disabled
                $eventData = @{
                    Severity = 'WARNING'
                    MitreTechnique = 'T1531'
                    DetectionModule = 'Impact'
                    EventDetails = 'User account disabled'
                    ProcessID = ''
                    ProcessName = ''
                    CommandLine = ''
                    User = $subjectUser
                    SourceIP = ''
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "TargetUser: $targetUser"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
            
            if ($event.Id -eq 4726) { # User account deleted
                $eventData = @{
                    Severity = 'WARNING'
                    MitreTechnique = 'T1531'
                    DetectionModule = 'Impact'
                    EventDetails = 'User account deleted'
                    ProcessID = ''
                    ProcessName = ''
                    CommandLine = ''
                    User = $subjectUser
                    SourceIP = ''
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "TargetUser: $targetUser"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
            
            if ($event.Id -eq 4740) { # Account locked out
                $eventData = @{
                    Severity = 'INFO'
                    MitreTechnique = 'T1499.004'
                    DetectionModule = 'Impact'
                    EventDetails = 'Account locked out (potential DoS)'
                    ProcessID = ''
                    ProcessName = ''
                    CommandLine = ''
                    User = ''
                    SourceIP = ''
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "TargetUser: $targetUser"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
        }
        
        # Monitor System events for service failures and system events
        $systemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=@(7034,7035,7036,7040,6005,6006,6008,6013)} -MaxEvents 100 -ErrorAction SilentlyContinue
        
        foreach ($event in $systemEvents) {
            $xml = [xml]$event.ToXml()
            
            if ($event.Id -eq 7034) { # Service crashed unexpectedly
                $serviceName = $xml.Event.EventData.Data | Select-Object -ExpandProperty '#text' -First 1
                
                # Check if it's an OT service
                $isOTService = $false
                foreach ($service in $OTServices) {
                    if ($serviceName -match [regex]::Escape($service)) {
                        $isOTService = $true
                        break
                    }
                }
                
                if ($isOTService) {
                    $eventData = @{
                        Severity = 'CRITICAL'
                        MitreTechnique = 'T1489'
                        DetectionModule = 'Impact'
                        EventDetails = 'OT service crashed unexpectedly'
                        ProcessID = ''
                        ProcessName = ''
                        CommandLine = ''
                        User = ''
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "ServiceName: $serviceName"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
            }
            
            if ($event.Id -eq 7036) { # Service state change
                $serviceName = $xml.Event.EventData.Data | Select-Object -ExpandProperty '#text' -First 1
                $state = $xml.Event.EventData.Data | Select-Object -ExpandProperty '#text' -Skip 1 -First 1
                
                if ($state -eq "stopped") {
                    # Check if it's an OT service
                    $isOTService = $false
                    foreach ($service in $OTServices) {
                        if ($serviceName -match [regex]::Escape($service)) {
                            $isOTService = $true
                            break
                        }
                    }
                    
                    if ($isOTService) {
                        $eventData = @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1489'
                            DetectionModule = 'Impact'
                            EventDetails = 'OT service stopped'
                            ProcessID = ''
                            ProcessName = ''
                            CommandLine = ''
                            User = ''
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ServiceName: $serviceName"
                        }
                        Write-SecurityEvent -LogType 'Main' -EventData $eventData
                    }
                }
            }
            
            if ($event.Id -eq 6005) { # System started
                $eventData = @{
                    Severity = 'INFO'
                    MitreTechnique = 'T1529'
                    DetectionModule = 'Impact'
                    EventDetails = 'System startup detected'
                    ProcessID = ''
                    ProcessName = ''
                    CommandLine = ''
                    User = ''
                    SourceIP = ''
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "System boot event"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
            
            if ($event.Id -eq 6006) { # System shutdown
                $eventData = @{
                    Severity = 'INFO'
                    MitreTechnique = 'T1529'
                    DetectionModule = 'Impact'
                    EventDetails = 'System shutdown detected'
                    ProcessID = ''
                    ProcessName = ''
                    CommandLine = ''
                    User = ''
                    SourceIP = ''
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "System shutdown event"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
            
            if ($event.Id -eq 6008) { # Unexpected shutdown
                $eventData = @{
                    Severity = 'WARNING'
                    MitreTechnique = 'T1529'
                    DetectionModule = 'Impact'
                    EventDetails = 'Unexpected system shutdown detected'
                    ProcessID = ''
                    ProcessName = ''
                    CommandLine = ''
                    User = ''
                    SourceIP = ''
                    DestIP = ''
                    FilePath = ''
                    RegistryKey = ''
                    AdditionalContext = "Unexpected shutdown - potential impact"
                }
                Write-SecurityEvent -LogType 'Main' -EventData $eventData
            }
        }
        
        # Monitor Application logs for critical application failures
        $appEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; ID=@(1000,1001,1002)} -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $appEvents) {
            $xml = [xml]$event.ToXml()
            $faultingApp = $xml.Event.EventData.Data | Select-Object -ExpandProperty '#text' -First 1
            
            if ($faultingApp) {
                # Check if it's an OT application
                $isOTApp = $false
                $otApps = @("FactoryTalk", "RSLogix", "Unity", "Step7", "TIA", "WinCC", "iFIX", "InTouch", "Wonderware", "Citect", "Vijeo")
                
                foreach ($app in $otApps) {
                    if ($faultingApp -match [regex]::Escape($app)) {
                        $isOTApp = $true
                        break
                    }
                }
                
                if ($isOTApp) {
                    $eventData = @{
                        Severity = 'CRITICAL'
                        MitreTechnique = 'T1499'
                        DetectionModule = 'Impact'
                        EventDetails = 'OT application failure detected'
                        ProcessID = ''
                        ProcessName = $faultingApp
                        CommandLine = ''
                        User = ''
                        SourceIP = ''
                        DestIP = ''
                        FilePath = ''
                        RegistryKey = ''
                        AdditionalContext = "OT application crash"
                    }
                    Write-SecurityEvent -LogType 'Main' -EventData $eventData
                }
            }
        }
        
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'Impact'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-PrivilegeEscalationDetection {
    try {
        # Get events with proper error handling
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=@(1,10,12,13,14)} -MaxEvents 200 -ErrorAction SilentlyContinue
        $securityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4648,4672,4673)} -MaxEvents 100 -ErrorAction SilentlyContinue
        
        # Token manipulation indicators
        $tokenManipulationIndicators = @(
            "SeDebugPrivilege",
            "SeTcbPrivilege", 
            "SeImpersonatePrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeLoadDriverPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege"
        )
        
        # Exploitation indicators
        $exploitIndicators = @(
            "CVE-",
            "MS\d{2}-\d{3}",
            "exploit",
            "privilege escalation",
            "UAC bypass",
            "token manipulation"
        )
        
        # UAC bypass indicators
        $uacBypassIndicators = @(
            "fodhelper\.exe",
            "ComputerDefaults\.exe",
            "eventvwr\.exe",
            "sdclt\.exe",
            "SilentCleanup",
            "ms-settings:",
            "wsreset\.exe"
        )
        
        # Privilege escalation sensitive registry keys
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
        
        # Process Sysmon events
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                $xml = [xml]$event.ToXml()
                $eventData = @{}
                foreach ($data in $xml.Event.EventData.Data) {
                    if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
                }
                
                # T1134 - Access Token Manipulation (Process Creation Event 1)
                if ($event.Id -eq 1) {
                    $processName = $eventData["Image"]
                    $commandLine = $eventData["CommandLine"]
                    $processId = $eventData["ProcessId"]
                    $user = $eventData["User"]
                    $processGuid = $eventData["ProcessGuid"]
                    $parentImage = $eventData["ParentImage"]
                    $hashes = $eventData["Hashes"]
                    
                    # Check for token manipulation privileges
                    foreach ($privilege in $tokenManipulationIndicators) {
                        if ($commandLine -match $privilege) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1134'
                                DetectionModule = 'PrivilegeEscalation'
                                EventDetails = 'Access token manipulation attempt detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "DetectedPrivilege: $privilege, ProcessGuid: $processGuid, Hashes: $hashes"
                            }
                        }
                    }
                    
                    # Monitor known privilege escalation tools
                    if ($processName -match "incognito|Cobalt Strike|Metasploit") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'CRITICAL'
                            MitreTechnique = 'T1134'
                            DetectionModule = 'PrivilegeEscalation'
                            EventDetails = 'Known privilege escalation tool detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ProcessGuid: $processGuid"
                        }
                    }
                    
                    # T1068 - Exploitation for Privilege Escalation
                    foreach ($indicator in $exploitIndicators) {
                        if ($commandLine -match $indicator) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'CRITICAL'
                                MitreTechnique = 'T1068'
                                DetectionModule = 'PrivilegeEscalation'
                                EventDetails = 'Potential exploitation for privilege escalation detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Parent: $parentImage, Indicator: $indicator"
                            }
                        }
                    }
                    
                    # Monitor unusual system processes
                    if ($processName -match "svchost\.exe|winlogon\.exe|csrss\.exe" -and $user -notmatch "SYSTEM|LOCAL SERVICE|NETWORK SERVICE") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1068'
                            DetectionModule = 'PrivilegeEscalation'
                            EventDetails = 'System process running under unusual user context'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ExpectedUser: SYSTEM/SERVICE, ActualUser: $user"
                        }
                    }
                    
                    # T1548 - Abuse Elevation Control Mechanism (UAC bypass)
                    foreach ($indicator in $uacBypassIndicators) {
                        if ($processName -match $indicator -or $commandLine -match $indicator) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1548.002'
                                DetectionModule = 'PrivilegeEscalation'
                                EventDetails = 'Potential UAC bypass attempt detected'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = $commandLine
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Parent: $parentImage, Method: $indicator"
                            }
                        }
                    }
                    
                    # Monitor runas usage
                    if ($processName -match "runas\.exe") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1548'
                            DetectionModule = 'PrivilegeEscalation'
                            EventDetails = 'RunAs command execution detected'
                            ProcessID = $processId
                            ProcessName = $processName
                            CommandLine = $commandLine
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "ElevationAttempt: True"
                        }
                    }
                }
                
                # T1055 - Process Injection (Process Access Event 10)
                if ($event.Id -eq 10) {
                    $sourceProcessId = $eventData["SourceProcessId"]
                    $targetProcessId = $eventData["TargetProcessId"]
                    $sourceImage = $eventData["SourceImage"]
                    $targetImage = $eventData["TargetImage"]
                    $grantedAccess = $eventData["GrantedAccess"]
                    $callTrace = $eventData["CallTrace"]
                    $user = $eventData["User"]
                    
                    # Suspicious process access patterns
                    if ($grantedAccess -match "0x1F3FFF|0x1FFFFF") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1055'
                            DetectionModule = 'PrivilegeEscalation'
                            EventDetails = 'Suspicious process access with high privileges detected'
                            ProcessID = $sourceProcessId
                            ProcessName = $sourceImage
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Target: $targetImage (PID: $targetProcessId), Access: $grantedAccess"
                        }
                    }
                    
                    # Cross-process memory access
                    if ($sourceImage -ne $targetImage -and $grantedAccess -match "0x40|0x20|0x8") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1055'
                            DetectionModule = 'PrivilegeEscalation'
                            EventDetails = 'Cross-process memory access detected'
                            ProcessID = $sourceProcessId
                            ProcessName = $sourceImage
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Target: $targetImage, Access: $grantedAccess"
                        }
                    }
                    
                    # Suspicious call traces
                    if ($callTrace -match "ntdll.dll|kernel32.dll.*WriteProcessMemory|VirtualAllocEx") {
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'WARNING'
                            MitreTechnique = 'T1055'
                            DetectionModule = 'PrivilegeEscalation'
                            EventDetails = 'Suspicious API call trace detected'
                            ProcessID = $sourceProcessId
                            ProcessName = $sourceImage
                            CommandLine = ''
                            User = $user
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "CallTrace: $callTrace"
                        }
                    }
                }
                
                # T1548 - Registry Events for Privilege Escalation (Events 12,13,14)
                if ($event.Id -in @(12,13,14)) {
                    $processName = $eventData["Image"]
                    $targetObject = $eventData["TargetObject"]
                    $details = $eventData["Details"]
                    $processId = $eventData["ProcessId"]
                    $user = $eventData["User"]
                    
                    foreach ($key in $privilegeEscalationKeys) {
                        if ($targetObject -match $key) {
                            $level = if ($key -match "SAM|SECURITY|Lsa") { "CRITICAL" } else { "WARNING" }
                            
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = $level
                                MitreTechnique = 'T1548'
                                DetectionModule = 'PrivilegeEscalation'
                                EventDetails = 'Registry modification in privilege escalation sensitive area'
                                ProcessID = $processId
                                ProcessName = $processName
                                CommandLine = ''
                                User = $user
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = $targetObject
                                AdditionalContext = "Details: $details, SensitiveArea: $key"
                            }
                        }
                    }
                }
            }
        }
        
        # Process Security events
        if ($securityEvents) {
            foreach ($event in $securityEvents) {
                $xml = [xml]$event.ToXml()
                $eventData = @{}
                foreach ($data in $xml.Event.EventData.Data) {
                    if ($data.Name) { $eventData[$data.Name] = $data.'#text' }
                }
                
                switch ($event.Id) {
                    4672 { # Special privileges assigned to new logon
                        $subjectUserName = $eventData["SubjectUserName"]
                        $privilegeList = $eventData["PrivilegeList"]
                        $logonId = $eventData["SubjectLogonId"]
                        
                        Write-SecurityEvent -LogType 'Main' -EventData @{
                            Severity = 'INFO'
                            MitreTechnique = 'T1134'
                            DetectionModule = 'PrivilegeEscalation'
                            EventDetails = 'Special privileges assigned to user logon'
                            ProcessID = ''
                            ProcessName = ''
                            CommandLine = ''
                            User = $subjectUserName
                            SourceIP = ''
                            DestIP = ''
                            FilePath = ''
                            RegistryKey = ''
                            AdditionalContext = "Privileges: $privilegeList, LogonId: $logonId"
                        }
                    }
                    
                    4673 { # A privileged service was called
                        $subjectUserName = $eventData["SubjectUserName"]
                        $serviceName = $eventData["Service"]
                        $privilegeList = $eventData["PrivilegeList"]
                        
                        if ($privilegeList -match "SeDebugPrivilege|SeTcbPrivilege|SeImpersonatePrivilege") {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'WARNING'
                                MitreTechnique = 'T1134'
                                DetectionModule = 'PrivilegeEscalation'
                                EventDetails = 'High-value privilege used for service call'
                                ProcessID = ''
                                ProcessName = ''
                                CommandLine = ''
                                User = $subjectUserName
                                SourceIP = ''
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "Service: $serviceName, Privileges: $privilegeList"
                            }
                        }
                    }
                    
                    4648 { # A logon was attempted using explicit credentials
                        $subjectUserName = $eventData["SubjectUserName"]
                        $targetUserName = $eventData["TargetUserName"]
                        $processName = $eventData["ProcessName"]
                        $ipAddress = $eventData["IpAddress"]
                        
                        if ($subjectUserName -ne $targetUserName) {
                            Write-SecurityEvent -LogType 'Main' -EventData @{
                                Severity = 'INFO'
                                MitreTechnique = 'T1134'
                                DetectionModule = 'PrivilegeEscalation'
                                EventDetails = 'Explicit credential usage detected'
                                ProcessID = ''
                                ProcessName = $processName
                                CommandLine = ''
                                User = $subjectUserName
                                SourceIP = $ipAddress
                                DestIP = ''
                                FilePath = ''
                                RegistryKey = ''
                                AdditionalContext = "TargetUser: $targetUserName"
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-SecurityEvent -LogType 'Error' -EventData @{
            Module = 'PrivilegeEscalation'
            ErrorType = 'DetectionError'
            ErrorMessage = $_.Exception.Message
            StackTrace = $_.ScriptStackTrace
            RecoveryAction = 'Continue monitoring'
        }
    }
}

function Start-OTProcessCorrelation {
    try {
        # Log OT-specific process events
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 50 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            foreach ($event in $sysmonEvents) {
                Write-RawWindowsEvent -Event $event -LogType "OTProcess" -DetectionModule "OT" -Severity "INFO"
            }
        }
    }
    catch {
        Write-Error "OT detection error: $($_.Exception.Message)"
    }
}

# ============================================================================
# MAIN SERVICE LOOP
# ============================================================================

function Start-SecurityServiceLoop {
    try {
        Initialize-LoggingSystem
        Write-Host "Security Logger Service started successfully" -ForegroundColor Green
        
        $Global:ServiceRunning = $true
        $loopCount = 0
        
        while ($Global:ServiceRunning) {
            try {
                $loopStart = Get-Date
                
                # Run enabled detection modules
                foreach ($module in $Global:ServiceConfig.EnabledModules) {
                    try {
                        switch ($module) {
                            'InitialAccess' { Start-InitialAccessDetection }
                            'Execution' { Start-ExecutionDetection }
                            'Persistence' { Start-PersistenceDetection }
                            'PrivilegeEscalation' { Start-PrivilegeEscalationDetection }
                            'DefenseEvasion' { Start-DefenseEvasionDetection }
                            'CredentialAccess' { Start-CredentialAccessDetection }
                            'Discovery' { Start-DiscoveryDetection }
                            'LateralMovement' { Start-LateralMovementDetection }
                            'Collection' { Start-CollectionDetection }
                            'CommandAndControl' { Start-CommandAndControlDetection }
                            'Exfiltration' { Start-ExfiltrationDetection }
                            'Impact' { Start-ImpactDetection }
                            'USB' { Start-USBThreatDetection }
                            'OT' { Start-OTProcessCorrelation }
                        }
                    }
                    catch {
                        Write-Host "Module $module failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
                
                $loopCount++
                $loopDuration = (Get-Date) - $loopStart
                
                # Display health check every 100 loops
                if ($loopCount % 100 -eq 0) {
                    Write-Host "Service health check - Loop: $loopCount, Duration: $($loopDuration.TotalSeconds)s, Events: $($Global:LogWriters.EventCount)" -ForegroundColor Yellow
                }
                
                # Sleep for configured interval
                Start-Sleep -Seconds $Global:ServiceConfig.ServiceInterval
            }
            catch {
                Write-Host "Service loop error: $($_.Exception.Message)" -ForegroundColor Red
                Start-Sleep -Seconds 30  # Longer sleep on error
            }
        }
        
        Write-Host "Security Logger Service stopped" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Critical service error: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

function Stop-SecurityService {
    $Global:ServiceRunning = $false
    Write-Host "Service stop requested" -ForegroundColor Yellow
}

# ============================================================================
# MAIN EXECUTION LOGIC
# ============================================================================

# Handle different actions
switch ($Action.ToLower()) {
    'install' {
        Write-Host "Installing Security Logger Service..." -ForegroundColor Cyan
        Install-SecurityService
    }
    'uninstall' {
        Write-Host "Uninstalling Security Logger Service..." -ForegroundColor Cyan
        Uninstall-SecurityService
    }
    'start' {
        Write-Host "Starting Security Logger Service..." -ForegroundColor Cyan
        Start-Service -Name $ServiceName
    }
    'stop' {
        Write-Host "Stopping Security Logger Service..." -ForegroundColor Cyan
        Stop-Service -Name $ServiceName -Force
    }
    'restart' {
        Write-Host "Restarting Security Logger Service..." -ForegroundColor Cyan
        Restart-Service -Name $ServiceName -Force
    }
    'status' {
        Get-ServiceStatus
    }
    'run' {
        # This is the main service execution
        try {
            # Set up signal handlers for graceful shutdown
            Register-ObjectEvent -InputObject ([System.Console]) -EventName CancelKeyPress -Action {
                Stop-SecurityService
            } | Out-Null
            
            # Start the main service loop
            Start-SecurityServiceLoop
        }
        catch {
            Write-Error "Service execution failed: $($_.Exception.Message)"
            exit 1
        }
    }
    default {
        Write-Host @"
Unified Security Logger Service

Usage: .\Unified-SecurityLogger-Service.ps1 -Action <action>

Actions:
  Install     - Install the service
  Uninstall   - Remove the service
  Start       - Start the service
  Stop        - Stop the service
  Restart     - Restart the service
  Status      - Show service status
  Run         - Run service directly (for debugging)

Examples:
  .\Unified-SecurityLogger-Service.ps1 -Action Install
  .\Unified-SecurityLogger-Service.ps1 -Action Start
  .\Unified-SecurityLogger-Service.ps1 -Action Run

Output:
  UnifiedSecurityEvents.csv - Single CSV file containing all Windows event logs with categorization
  
The script collects raw Windows event logs from:
- Sysmon/Operational
- Security
- System
- Application
- WinRM/Operational
- TaskScheduler/Operational

Each event is logged with its original data plus categorization by detection module and event type.
"@ -ForegroundColor Yellow
    }
}
