#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Impact Tactics Logger using Sysmon and Windows Event Logs - OT Environment Compatible
.DESCRIPTION
    Monitors and logs Impact techniques using Sysmon events and Windows Security logs
    Designed for OT environments with critical system monitoring
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
$Script:SysmonAvailable = $false
$Script:SysmonStatusChecked = $false

# OT Critical System Processes and Services
$Script:OTCriticalProcesses = @(
    "HMIService.exe", "SCADA.exe", "PLCComm.exe", "ModbusService.exe", 
    "FactoryTalk", "WinCC", "iFIX", "Citect", "InTouch", "RSLinx",
    "OPCServer", "KEPServerEX", "Matrikon", "Historian", "WonderwareDAServer"
)

$Script:OTCriticalServices = @(
    "HMIService", "SCADAService", "PLCCommunication", "ModbusTCP", 
    "OPCServer", "KEPServerEX", "RSLinx", "FactoryTalkLinx", 
    "WinCCOLEDBProvider", "iFIXGateway", "InTouchService",
    "WonderwareDAServer", "Historian", "MatrikonOPC"
)

# Initialize logging
function Initialize-Logger {
    param([string]$Path)
    
    if (!(Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:LogFile = Join-Path $Path "Impact_$timestamp.log"
    
    Write-LogEntry "INFO" "Impact Tactics Logger started at $(Get-Date)"
    Write-LogEntry "INFO" "Log file: $Script:LogFile"
    Write-LogEntry "INFO" "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-LogEntry "INFO" "OS: $((Get-WmiObject Win32_OperatingSystem).Caption)"
    Write-LogEntry "INFO" "OT Environment Monitoring Enabled"
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
        [string]$SourceIP = "",
        [string]$TargetIP = "",
        [string]$ServiceName = "",
        [string]$NetworkDestination = "",
        [string]$FileSize = "",
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
    if ($SourceIP) { $logEntry += " | SourceIP: $SourceIP" }
    if ($TargetIP) { $logEntry += " | TargetIP: $TargetIP" }
    if ($ServiceName) { $logEntry += " | Service: $ServiceName" }
    if ($NetworkDestination) { $logEntry += " | NetDest: $NetworkDestination" }
    if ($FileSize) { $logEntry += " | FileSize: $FileSize" }
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
    param([bool]$Quiet = $false)
    
    # Return cached result if already checked
    if ($Script:SysmonStatusChecked) {
        return $Script:SysmonAvailable
    }
    
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
            $Script:SysmonAvailable = $true
            if (-not $Quiet) {
                Write-LogEntry "INFO" "Sysmon service detected and running: $($sysmonService.Name)"
            }
        } else {
            $Script:SysmonAvailable = $false
            if (-not $Quiet) {
                Write-LogEntry "WARNING" "Sysmon service not found or not running"
            }
        }
        
        $Script:SysmonStatusChecked = $true
        return $Script:SysmonAvailable
        
    } catch {
        $Script:SysmonAvailable = $false
        $Script:SysmonStatusChecked = $true
        if (-not $Quiet) {
            Write-LogEntry "WARNING" "Could not check Sysmon status: $($_.Exception.Message)"
        }
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

# Check if process is OT-critical
function Test-OTCriticalProcess {
    param([string]$ProcessName)
    
    if (-not $ProcessName) { return $false }
    
    foreach ($criticalProcess in $Script:OTCriticalProcesses) {
        if ($ProcessName -match [regex]::Escape($criticalProcess)) {
            return $true
        }
    }
    return $false
}

# Check if service is OT-critical
function Test-OTCriticalService {
    param([string]$ServiceName)
    
    if (-not $ServiceName) { return $false }
    
    foreach ($criticalService in $Script:OTCriticalServices) {
        if ($ServiceName -match [regex]::Escape($criticalService)) {
            return $true
        }
    }
    return $false
}

# Monitor for Account Access Removal (T1531)
function Monitor-AccountAccessRemoval {
    $events = Get-EventsSafe -LogName 'Security' -EventIDs @(4726, 4727, 4730, 4731, 4734, 4735, 4737, 4754, 4758) -StartTime $Script:LastEventTime

    foreach ($event in $events) {
        $eventData = Get-EventData -Event $event
        
        # Critical account deletions and group removals
        if ($event.Id -eq 4726) {
            Write-LogEntry "CRITICAL" "User account deleted" -EventID $event.Id -User $eventData.TargetUserName -Technique "T1531 - Account Access Removal" -AdditionalFields "DeletedBy: $($eventData.SubjectUserName)"
        }
        
        if ($event.Id -eq 4727 -or $event.Id -eq 4730) {
            Write-LogEntry "WARNING" "Security group deleted or member removed" -EventID $event.Id -User $eventData.TargetUserName -Technique "T1531 - Account Access Removal"
        }
        
        if ($event.Id -eq 4734 -or $event.Id -eq 4735) {
            Write-LogEntry "WARNING" "Security-enabled group deleted or changed" -EventID $event.Id -User $eventData.TargetUserName -Technique "T1531 - Account Access Removal"
        }
    }
}

# Monitor for Data Destruction (T1485)
function Monitor-DataDestruction {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11, 23, 26) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Monitor for file deletion tools and patterns
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                
                # Detect destructive commands
                $destructiveCommands = @("del /s", "rmdir /s", "format ", "sdelete", "cipher /w", "wipe", "shred", "bcwipe")
                foreach ($command in $destructiveCommands) {
                    if ($commandLine -match [regex]::Escape($command)) {
                        $severity = if (Test-OTCriticalProcess -ProcessName $eventData.Image) { "CRITICAL" } else { "WARNING" }
                        Write-LogEntry $severity "Potential data destruction command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1485 - Data Destruction"
                        break
                    }
                }
                
                # OT-specific data destruction patterns
                $otDataPatterns = @("*.his", "*.log", "*.cfg", "*.prn", "*.bak", "*.mdb", "*.db")
                foreach ($pattern in $otDataPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "CRITICAL" "OT data files targeted for destruction" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1485.001 - Data Destruction"
                        break
                    }
                }
            }
            
            # Monitor for mass file deletions
            if ($event.Id -eq 23) {
                $targetFilename = $eventData.TargetFilename
                if ($targetFilename -match "\.(his|log|cfg|prn|bak|mdb|db|xml|ini)$") {
                    Write-LogEntry "WARNING" "OT-related file deleted" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFilename -Technique "T1485 - Data Destruction"
                }
            }
        }
    }
}

# Monitor for Data Encrypted for Impact (T1486)
function Monitor-DataEncryptedForImpact {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11, 15, 17, 18) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Monitor for encryption tools and ransomware patterns
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                
                # Detect encryption tools
                $encryptionTools = @("gpg ", "7z ", "rar ", "winzip", "bcrypt", "cryptoapi", "cipher", "schtasks", "vssadmin delete shadows")
                foreach ($tool in $encryptionTools) {
                    if ($commandLine -match [regex]::Escape($tool)) {
                        Write-LogEntry "WARNING" "Potential encryption tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1486 - Data Encrypted for Impact"
                        break
                    }
                }
                
                # Ransomware indicators
                if ($commandLine -match "readme|decrypt|ransom|bitcoin|payment|unlock|restore") {
                    Write-LogEntry "CRITICAL" "Ransomware indicators detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1486 - Data Encrypted for Impact"
                }
            }
            
            # Monitor for suspicious file creations (ransom notes, encrypted files)
            if ($event.Id -eq 11) {
                $targetFilename = $eventData.TargetFilename
                if ($targetFilename -match "\.(encrypted|locked|crypto|ransom|readme|txt|html)$" -or $targetFilename -match "decrypt|ransom|readme|howto") {
                    Write-LogEntry "CRITICAL" "Potential ransom note or encrypted file created" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFilename -Technique "T1486 - Data Encrypted for Impact"
                }
            }
        }
    }
}

# Monitor for Data Manipulation (T1565)
function Monitor-DataManipulation {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11, 15) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Monitor for data manipulation tools and patterns
            if ($event.Id -eq 11) {
                $targetFilename = $eventData.TargetFilename
                
                # OT configuration file manipulation
                $otConfigFiles = @("*.cfg", "*.prn", "*.ini", "*.xml", "*.conf", "*.properties", "*.settings")
                foreach ($pattern in $otConfigFiles) {
                    $regexPattern = $pattern -replace '\*', '.*'
                    if ($targetFilename -match $regexPattern) {
                        $processName = $eventData.Image
                        if ($processName -and -not (Test-OTCriticalProcess -ProcessName $processName)) {
                            Write-LogEntry "WARNING" "OT configuration file modified by non-OT process" -EventID $event.Id -ProcessName $processName -TargetFilename $targetFilename -Technique "T1565.001 - Stored Data Manipulation"
                        }
                        break
                    }
                }
                
                # Database file manipulation
                if ($targetFilename -match "\.(mdb|db|sqlite|his)$") {
                    Write-LogEntry "WARNING" "Database file modification detected" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFilename -Technique "T1565.001 - Stored Data Manipulation"
                }
            }
            
            # Command-line data manipulation
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                if ($commandLine -match "echo.*>|type.*>|copy.*>|move.*>|ren.*\.|attrib.*") {
                    Write-LogEntry "INFO" "File manipulation command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1565.002 - Runtime Data Manipulation"
                }
            }
        }
    }
}

# Monitor for Defacement (T1491)
function Monitor-Defacement {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11, 15) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Monitor for web defacement patterns
            if ($event.Id -eq 11) {
                $targetFilename = $eventData.TargetFilename
                
                # Web files
                if ($targetFilename -match "\.(html|htm|php|asp|aspx|jsp|css|js)$") {
                    Write-LogEntry "WARNING" "Web file modification detected" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFilename -Technique "T1491.001 - Internal Defacement"
                }
                
                # HMI interface files
                if ($targetFilename -match "\.(hmi|scr|gfx|ftu|mer|pag)$") {
                    Write-LogEntry "CRITICAL" "HMI interface file modified" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFilename -Technique "T1491.002 - External Defacement"
                }
            }
        }
    }
}

# Monitor for Disk Wipe (T1561)
function Monitor-DiskWipe {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                
                # Disk wiping tools and commands
                $diskWipeCommands = @("format /q", "diskpart", "sdelete", "dban", "wipe", "shred", "cipher /w", "fsutil file createnew", "dd if=/dev/zero")
                foreach ($command in $diskWipeCommands) {
                    if ($commandLine -match [regex]::Escape($command)) {
                        Write-LogEntry "CRITICAL" "Disk wipe command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1561.001 - Disk Content Wipe"
                        break
                    }
                }
                
                # MBR/Boot sector manipulation
                if ($commandLine -match "bootrec|bcdedit|mbr|partition") {
                    Write-LogEntry "CRITICAL" "Boot sector/MBR manipulation detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1561.002 - Disk Structure Wipe"
                }
            }
        }
    }
}

# Monitor for Email Bombing (T1499)
function Monitor-EmailBombing {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Monitor for email-related network connections
            if ($event.Id -eq 3) {
                $destinationPort = $eventData.DestinationPort
                $processName = $eventData.Image
                
                # SMTP connections from non-email clients
                if ($destinationPort -eq "25" -or $destinationPort -eq "587" -or $destinationPort -eq "465") {
                    if ($processName -and $processName -notmatch "outlook|thunderbird|mail|exchange") {
                        Write-LogEntry "WARNING" "Suspicious SMTP connection detected" -EventID $event.Id -ProcessName $processName -TargetIP $eventData.DestinationIp -Technique "T1499.003 - Email Bombing"
                    }
                }
            }
            
            # Command-line email tools
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                if ($commandLine -match "blat|sendmail|telnet.*25|powershell.*send-mailmessage") {
                    Write-LogEntry "WARNING" "Command-line email tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1499.003 - Email Bombing"
                }
            }
        }
    }
}

# Monitor for Endpoint Denial of Service (T1499)
function Monitor-EndpointDenialOfService {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                
                # Resource exhaustion commands
                $dosCommands = @(":(){ :|:& };:", "while true", "for /l", "ping -t", "stress", "burnin", "prime95")
                foreach ($command in $dosCommands) {
                    if ($commandLine -match [regex]::Escape($command)) {
                        Write-LogEntry "CRITICAL" "Potential DoS command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1499.004 - Application or System Exploitation"
                        break
                    }
                }
                
                # OT-specific DoS patterns targeting HMI/SCADA
                $otDosPatterns = @("taskkill.*hmi", "taskkill.*scada", "taskkill.*plc", "stop.*hmi", "stop.*scada")
                foreach ($pattern in $otDosPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "CRITICAL" "OT system DoS command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1499.001 - OS Exhaustion Flood"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Financial Theft (T1657)
function Monitor-FinancialTheft {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Monitor for financial applications and connections
            if ($event.Id -eq 3) {
                $processName = $eventData.Image
                $destinationIp = $eventData.DestinationIp
                
                # Banking/Financial application network activity
                if ($processName -match "bank|finance|payment|pos|atm|swift|ach") {
                    Write-LogEntry "INFO" "Financial application network activity" -EventID $event.Id -ProcessName $processName -TargetIP $destinationIp -Technique "T1657 - Financial Theft"
                }
            }
            
            # Monitor for financial data file access
            if ($event.Id -eq 11) {
                $targetFilename = $eventData.TargetFilename
                if ($targetFilename -match "payment|transaction|ledger|accounting|financial|invoice|billing") {
                    Write-LogEntry "WARNING" "Financial data file accessed" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFilename -Technique "T1657 - Financial Theft"
                }
            }
        }
    }
}

# Monitor for Firmware Corruption (T1495)
function Monitor-FirmwareCorruption {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Monitor for firmware-related tools and files
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                
                # Firmware manipulation tools
                $firmwareTools = @("flashrom", "bios", "uefi", "firmware", "nvram", "afudos", "awdflash", "uniflash")
                foreach ($tool in $firmwareTools) {
                    if ($commandLine -match [regex]::Escape($tool)) {
                        Write-LogEntry "CRITICAL" "Firmware manipulation tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1495 - Firmware Corruption"
                        break
                    }
                }
            }
            
            # Monitor for firmware file modifications
            if ($event.Id -eq 11) {
                $targetFilename = $eventData.TargetFilename
                if ($targetFilename -match "\.(rom|bin|cap|fd|img|efi)$" -or $targetFilename -match "firmware|bios|uefi") {
                    Write-LogEntry "CRITICAL" "Firmware file modification detected" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFilename -Technique "T1495 - Firmware Corruption"
                }
            }
        }
    }
}

# Monitor for Inhibit System Recovery (T1490)
function Monitor-InhibitSystemRecovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                
                # Recovery inhibition commands
                $recoveryCommands = @(
                    "vssadmin delete shadows",
                    "wbadmin delete catalog",
                    "bcdedit /set.*recoveryenabled no",
                    "wmic shadowcopy delete",
                    "diskshadow delete",
                    "backup delete"
                )
                
                foreach ($command in $recoveryCommands) {
                    if ($commandLine -match [regex]::Escape($command)) {
                        Write-LogEntry "CRITICAL" "System recovery inhibition detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1490 - Inhibit System Recovery"
                        break
                    }
                }
                
                # OT backup system targeting
                if ($commandLine -match "historian.*delete|backup.*scada|backup.*hmi") {
                    Write-LogEntry "CRITICAL" "OT backup system targeting detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1490 - Inhibit System Recovery"
                }
            }
        }
    }
}

# Monitor for Network Denial of Service (T1498)
function Monitor-NetworkDenialOfService {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Monitor for DoS tools and network flooding
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                
                # Network DoS tools
                $dosTools = @("hping", "nping", "flood", "dos", "ddos", "syn flood", "ping -l", "ping -n")
                foreach ($tool in $dosTools) {
                    if ($commandLine -match [regex]::Escape($tool)) {
                        Write-LogEntry "CRITICAL" "Network DoS tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1498.001 - Direct Network Flood"
                        break
                    }
                }
            }
            
            # Monitor for suspicious network connections
            if ($event.Id -eq 3) {
                $processName = $eventData.Image
                $destinationIp = $eventData.DestinationIp
                
                # Multiple connections to same destination (potential flooding)
                if ($destinationIp -and $processName -match "flood|dos|attack") {
                    Write-LogEntry "WARNING" "Suspicious network flooding activity" -EventID $event.Id -ProcessName $processName -TargetIP $destinationIp -Technique "T1498.002 - Reflection Amplification"
                }
            }
        }
    }
}

# Monitor for Resource Hijacking (T1496)
function Monitor-ResourceHijacking {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Monitor for cryptocurrency mining and resource hijacking
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                
                # Cryptocurrency mining indicators
                $miningIndicators = @("miner", "mining", "crypto", "bitcoin", "ethereum", "monero", "xmr", "btc", "eth", "stratum", "pool")
                foreach ($indicator in $miningIndicators) {
                    if ($commandLine -match [regex]::Escape($indicator)) {
                        Write-LogEntry "WARNING" "Potential cryptocurrency mining detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1496 - Resource Hijacking"
                        break
                    }
                }
            }
            
            # Monitor for mining pool connections
            if ($event.Id -eq 3) {
                $destinationPort = $eventData.DestinationPort
                $processName = $eventData.Image
                
                # Common mining pool ports
                $miningPorts = @("3333", "4444", "8080", "9999", "14444")
                if ($destinationPort -and $miningPorts -contains $destinationPort) {
                    Write-LogEntry "WARNING" "Connection to potential mining pool" -EventID $event.Id -ProcessName $processName -TargetIP $eventData.DestinationIp -Technique "T1496 - Resource Hijacking"
                }
            }
        }
    }
}

# Monitor for Service Stop (T1489)
function Monitor-ServiceStop {
    $events = Get-EventsSafe -LogName 'System' -EventIDs @(7034, 7035, 7036, 7040) -StartTime $Script:LastEventTime

    foreach ($event in $events) {
        $eventData = Get-EventData -Event $event
        
        # Monitor for critical service stops
        if ($event.Id -eq 7034 -or $event.Id -eq 7036) {
            $serviceName = $eventData.param1
            
            if (Test-OTCriticalService -ServiceName $serviceName) {
                Write-LogEntry "CRITICAL" "Critical OT service stopped" -EventID $event.Id -ServiceName $serviceName -Technique "T1489 - Service Stop"
            }
            
            # Security services
            $securityServices = @("Windows Defender", "Antivirus", "Firewall", "Security Center", "WinDefend")
            foreach ($secService in $securityServices) {
                if ($serviceName -match [regex]::Escape($secService)) {
                    Write-LogEntry "CRITICAL" "Security service stopped" -EventID $event.Id -ServiceName $serviceName -Technique "T1489 - Service Stop"
                    break
                }
            }
        }
        
        # Service configuration changes
        if ($event.Id -eq 7040) {
            $serviceName = $eventData.param1
            if (Test-OTCriticalService -ServiceName $serviceName) {
                Write-LogEntry "WARNING" "Critical OT service configuration changed" -EventID $event.Id -ServiceName $serviceName -Technique "T1489 - Service Stop"
            }
        }
    }
    
    # Monitor Sysmon for service manipulation commands
    if (Test-SysmonInstalled) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime
        
        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                
                # Service manipulation commands
                $serviceCommands = @("net stop", "sc stop", "taskkill", "services.msc", "sc config.*disabled")
                foreach ($command in $serviceCommands) {
                    if ($commandLine -match [regex]::Escape($command)) {
                        Write-LogEntry "WARNING" "Service manipulation command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1489 - Service Stop"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for System Shutdown/Reboot (T1529)
function Monitor-SystemShutdownReboot {
    $events = Get-EventsSafe -LogName 'System' -EventIDs @(1074, 6005, 6006, 6008, 6009, 6013) -StartTime $Script:LastEventTime

    foreach ($event in $events) {
        $eventData = Get-EventData -Event $event
        
        # System shutdown/restart events
        if ($event.Id -eq 1074) {
            $processName = $eventData.param5
            $reason = $eventData.param6
            Write-LogEntry "CRITICAL" "System shutdown/restart initiated" -EventID $event.Id -ProcessName $processName -Technique "T1529 - System Shutdown/Reboot" -AdditionalFields "Reason: $reason"
        }
        
        # Unexpected shutdowns
        if ($event.Id -eq 6008) {
            Write-LogEntry "CRITICAL" "Unexpected system shutdown detected" -EventID $event.Id -Technique "T1529 - System Shutdown/Reboot"
        }
        
        # System startup after shutdown
        if ($event.Id -eq 6005 -or $event.Id -eq 6009) {
            Write-LogEntry "INFO" "System startup detected" -EventID $event.Id -Technique "T1529 - System Shutdown/Reboot"
        }
    }
    
    # Monitor Sysmon for shutdown commands
    if (Test-SysmonInstalled) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime
        
        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine.ToLower()
                
                # Shutdown/reboot commands
                $shutdownCommands = @("shutdown", "restart", "reboot", "halt", "poweroff", "init 0", "init 6")
                foreach ($command in $shutdownCommands) {
                    if ($commandLine -match [regex]::Escape($command)) {
                        Write-LogEntry "CRITICAL" "Shutdown/reboot command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1529 - System Shutdown/Reboot"
                        break
                    }
                }
            }
        }
    }
}

# Generate summary statistics
function Generate-Summary {
    if ($Script:EventCounters.Count -gt 0) {
        $summaryInfo = "`n=== Impact Detection Summary ==="
        $summaryInfo += "`nTotal Techniques Detected: $($Script:EventCounters.Count)"
        $summaryInfo += "`nEvents by Technique:"
        
        foreach ($technique in $Script:EventCounters.Keys | Sort-Object) {
            $summaryInfo += "`n  $technique : $($Script:EventCounters[$technique]) events"
        }
        
        $summaryInfo += "`nMonitoring Duration: $((Get-Date) - $Script:StartTime)"
        $summaryInfo += "`n================================"
        
        Write-Host $summaryInfo -ForegroundColor Cyan
        Add-Content -Path $Script:LogFile -Value $summaryInfo
    }
    
    Add-Content -Path $Script:LogFile -Value "=== Impact Logger Stopped at $(Get-Date) ==="
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
            Monitor-AccountAccessRemoval
            Monitor-DataDestruction
            Monitor-DataEncryptedForImpact
            Monitor-DataManipulation
            Monitor-Defacement
            Monitor-DiskWipe
            Monitor-EmailBombing
            Monitor-EndpointDenialOfService
            Monitor-FinancialTheft
            Monitor-FirmwareCorruption
            Monitor-InhibitSystemRecovery
            Monitor-NetworkDenialOfService
            Monitor-ResourceHijacking
            Monitor-ServiceStop
            Monitor-SystemShutdownReboot
            
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
    Write-Host "`n" + "=" * 70 -ForegroundColor Cyan
    Write-Host "Impact Tactics Live Monitor v1.0 (OT Environment Compatible)" -ForegroundColor Cyan
    Write-Host "=" * 70 -ForegroundColor Cyan
    
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
    Write-Host "  OT Environment Monitoring: Enabled" -ForegroundColor White
    
    Write-Host "`nStarting Impact tactics monitoring... Press Ctrl+C to stop" -ForegroundColor Green
    Write-Host "Monitoring for destructive and disruptive activities in OT environment`n" -ForegroundColor Gray
    
    # Register cleanup on script termination
    Register-EngineEvent PowerShell.Exiting -Action { Stop-Monitoring }
    
    # Start monitoring
    Start-Monitoring
    
} catch {
    Write-Host "FATAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Stop-Monitoring
}
