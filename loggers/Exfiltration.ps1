#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Exfiltration Tactics Logger using Sysmon and Windows Event Logs - Windows Server 2012 Compatible
.DESCRIPTION
    Monitors and logs Exfiltration techniques using Sysmon events and Windows Security logs
    Compatible with PowerShell 3.0+ and Windows Server 2012
    Optimized for OT environments with focus on data exfiltration detection
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

# OT-specific file extensions and paths
$Script:OTFileExtensions = @(
    ".plc", ".hmi", ".scada", ".cfg", ".config", ".ini", ".xml", ".json", ".csv", ".log",
    ".db", ".sqlite", ".mdb", ".accdb", ".xls", ".xlsx", ".txt", ".dat", ".backup", ".bak",
    ".his", ".trend", ".alarm", ".event", ".recipe", ".program", ".ladder", ".st", ".fbd"
)

$Script:OTPaths = @(
    "C:\Program Files\*",
    "C:\ProgramData\*",
    "C:\Users\*\Documents\*",
    "*\HMI\*",
    "*\SCADA\*",
    "*\PLC\*",
    "*\Historian\*",
    "*\OPC\*",
    "*\Wonderware\*",
    "*\RSLogix\*",
    "*\TIA Portal\*"
)

# Network protocols and ports commonly used in OT
$Script:OTNetworkPorts = @(502, 44818, 102, 2404, 9600, 20000, 20547, 789, 1962, 2455, 4840, 5007)

# Initialize logging
function Initialize-Logger {
    param([string]$Path)
    
    if (!(Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:LogFile = Join-Path $Path "Exfiltration_$timestamp.log"
    
    Write-LogEntry "INFO" "Exfiltration Logger started at $(Get-Date)"
    Write-LogEntry "INFO" "Log file: $Script:LogFile"
    Write-LogEntry "INFO" "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-LogEntry "INFO" "OS: $((Get-WmiObject Win32_OperatingSystem).Caption)"
    Write-LogEntry "INFO" "OT Environment Detection Enabled"
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
        [string]$DestinationHostname = "",
        [string]$NetworkProtocol = "",
        [string]$DataSize = "",
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
    if ($DestinationHostname) { $logEntry += " | DestHost: $DestinationHostname" }
    if ($NetworkProtocol) { $logEntry += " | Protocol: $NetworkProtocol" }
    if ($DataSize) { $logEntry += " | DataSize: $DataSize" }
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
        Write-LogEntry "WARNING" "Error retrieving events from $LogName : $($_.Exception.Message)"
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
        Write-LogEntry "WARNING" "Error parsing event data: $($_.Exception.Message)"
        return @{}
    }
}

# Helper function to check if file is OT-related
function Test-OTFile {
    param([string]$FilePath)
    
    if (-not $FilePath) { return $false }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    if ($Script:OTFileExtensions -contains $extension) {
        return $true
    }
    
    foreach ($otPath in $Script:OTPaths) {
        if ($FilePath -like $otPath) {
            return $true
        }
    }
    
    return $false
}

# Monitor for Automated Exfiltration (T1020)
function Monitor-AutomatedExfiltration {
    # Monitor for scheduled tasks and scripts that might exfiltrate data
    if (Test-SysmonInstalled -Quiet $true) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3, 11) -StartTime $Script:LastEventTime

        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            # Detect automated data collection and transfer
            if ($event.Id -eq 1) {
                $commandLine = $eventData.CommandLine
                $image = $eventData.Image
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                $user = if ($eventData.User) { $eventData.User } else { "Unknown" }
                $parentImage = if ($eventData.ParentImage) { $eventData.ParentImage } else { "Unknown" }
                
                # Detect automation tools and scripts
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
                        $processDetails = "PID:$processId|Parent:$parentImage|User:$user"
                        Write-LogEntry "WARNING" "Automated data transfer tool detected" -EventID $event.Id -ProcessName $image -CommandLine $commandLine -ProcessId $processId -User $user -AdditionalFields $processDetails -Technique "T1020 - Automated Exfiltration"
                        break
                    }
                }
            }
            
            # Monitor network connections for automated transfers
            if ($event.Id -eq 3) {
                $sourceIp = $eventData.SourceIp
                $destinationIp = $eventData.DestinationIp
                $destinationPort = $eventData.DestinationPort
                $image = $eventData.Image
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                
                # Check for external connections from automation tools
                if ($destinationIp -and $destinationIp -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|::1|fe80:)") {
                    if ($image -match "powershell|cmd|wscript|cscript|python|curl|wget") {
                        Write-LogEntry "WARNING" "External network connection from script/automation tool" -EventID $event.Id -ProcessName $image -SourceIP $sourceIp -TargetIP $destinationIp -ProcessId $processId -NetworkProtocol "TCP" -AdditionalFields "Port:$destinationPort" -Technique "T1020 - Automated Exfiltration"
                    }
                }
            }
            
            # Monitor file operations for data staging
            if ($event.Id -eq 11) {
                $targetFilename = $eventData.TargetFilename
                $image = $eventData.Image
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                
                if ($targetFilename -and (Test-OTFile -FilePath $targetFilename)) {
                    # Check if file is being moved to temp or staging location
                    if ($targetFilename -match "temp|staging|export|backup.*\d{8}|dump") {
                        Write-LogEntry "INFO" "OT file moved to potential staging location" -EventID $event.Id -ProcessName $image -TargetFilename $targetFilename -ProcessId $processId -Technique "T1020 - Automated Exfiltration"
                    }
                }
            }
        }
    }
    
    # Monitor Task Scheduler events
    $taskEvents = Get-EventsSafe -LogName 'Microsoft-Windows-TaskScheduler/Operational' -EventIDs @(106, 200, 201) -StartTime $Script:LastEventTime
    
    foreach ($event in $taskEvents) {
        $eventData = Get-EventData -Event $event
        
        if ($event.Id -eq 106 -and $eventData.TaskName) {
            $taskName = $eventData.TaskName
            $actionName = if ($eventData.ActionName) { $eventData.ActionName } else { "Unknown" }
            
            # Detect suspicious scheduled tasks
            if ($taskName -match "backup|export|sync|transfer|upload" -and 
                $actionName -match "powershell|cmd|curl|wget|robocopy|xcopy") {
                Write-LogEntry "WARNING" "Scheduled task with potential data exfiltration capability" -EventID $event.Id -AdditionalFields "TaskName:$taskName|Action:$actionName" -Technique "T1020 - Automated Exfiltration"
            }
        }
    }
}

# Monitor for Exfiltration Over Alternative Protocol (T1048)
function Monitor-ExfiltrationOverAlternativeProtocol {
    if (Test-SysmonInstalled -Quiet $true) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(3, 22) -StartTime $Script:LastEventTime

        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            # Monitor network connections for alternative protocols
            if ($event.Id -eq 3) {
                $destinationIp = $eventData.DestinationIp
                $destinationPort = $eventData.DestinationPort
                $image = $eventData.Image
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                $user = if ($eventData.User) { $eventData.User } else { "Unknown" }
                
                # Check for non-standard protocols and ports
                if ($destinationPort -and $destinationIp -and $destinationIp -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|::1|fe80:)") {
                    $port = [int]$destinationPort
                    
                    # Detect unusual protocols for data exfiltration
                    $suspiciousPorts = @(
                        @{Port=53; Protocol="DNS Tunneling"},
                        @{Port=443; Protocol="HTTPS"},
                        @{Port=993; Protocol="IMAPS"},
                        @{Port=587; Protocol="SMTP TLS"},
                        @{Port=22; Protocol="SSH/SCP"},
                        @{Port=21; Protocol="FTP"},
                        @{Port=990; Protocol="FTPS"}
                    )
                    
                    foreach ($suspiciousPort in $suspiciousPorts) {
                        if ($port -eq $suspiciousPort.Port) {
                            # Additional checks for legitimate vs suspicious usage
                            $isLegitimate = $false
                            
                            # Check if it's a known legitimate process
                            $legitimateProcesses = @("outlook", "thunderbird", "chrome", "firefox", "iexplore", "msedge", "putty", "winscp", "filezilla")
                            foreach ($legitProcess in $legitimateProcesses) {
                                if ($image -match $legitProcess) {
                                    $isLegitimate = $true
                                    break
                                }
                            }
                            
                            if (-not $isLegitimate -or $suspiciousPort.Protocol -eq "DNS Tunneling") {
                                $processDetails = "Process:$image|PID:$processId|User:$user"
                                Write-LogEntry "WARNING" "External connection on alternative protocol - potential exfiltration" -EventID $event.Id -ProcessName $image -TargetIP $destinationIp -NetworkProtocol $suspiciousPort.Protocol -ProcessId $processId -User $user -AdditionalFields $processDetails -Technique "T1048 - Exfiltration Over Alternative Protocol"
                            }
                            break
                        }
                    }
                    
                    # Check for OT protocol abuse
                    if ($Script:OTNetworkPorts -contains $port) {
                        Write-LogEntry "WARNING" "External connection on OT protocol port - potential data exfiltration" -EventID $event.Id -ProcessName $image -TargetIP $destinationIp -NetworkProtocol "OT Protocol" -ProcessId $processId -User $user -AdditionalFields "Port:$destinationPort" -Technique "T1048.003 - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol"
                    }
                }
            }
            
            # Monitor DNS queries for potential tunneling
            if ($event.Id -eq 22) {
                $queryName = $eventData.QueryName
                $image = $eventData.Image
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                
                if ($queryName) {
                    # Detect DNS tunneling patterns
                    if ($queryName.Length -gt 50 -or 
                        $queryName -match "[0-9a-f]{32,}" -or
                        $queryName -match "^[a-z0-9]{20,}\." -or
                        ($queryName.Split('.').Length -gt 5)) {
                        Write-LogEntry "WARNING" "Suspicious DNS query - potential DNS tunneling" -EventID $event.Id -ProcessName $image -ProcessId $processId -AdditionalFields "QueryName:$queryName" -Technique "T1048.004 - Exfiltration Over DNS"
                    }
                }
            }
        }
    }
}

# Monitor for Exfiltration Over C2 Channel (T1041)
function Monitor-ExfiltrationOverC2Channel {
    if (Test-SysmonInstalled -Quiet $true) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            # Detect command and control communication patterns
            if ($event.Id -eq 1) {
                $commandLine = $eventData.CommandLine
                $image = $eventData.Image
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                $user = if ($eventData.User) { $eventData.User } else { "Unknown" }
                
                # Detect C2 communication tools and patterns
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
                        $processDetails = "PID:$processId|User:$user|Image:$image"
                        Write-LogEntry "CRITICAL" "Command and control communication pattern detected" -EventID $event.Id -ProcessName $image -CommandLine $commandLine -ProcessId $processId -User $user -AdditionalFields $processDetails -Technique "T1041 - Exfiltration Over C2 Channel"
                        break
                    }
                }
            }
            
            # Monitor network connections for C2 patterns
            if ($event.Id -eq 3) {
                $destinationIp = $eventData.DestinationIp
                $destinationPort = $eventData.DestinationPort
                $image = $eventData.Image
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                
                # Check for connections to suspicious external IPs
                if ($destinationIp -and $destinationIp -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|::1|fe80:)") {
                    # Detect potential C2 processes
                    $suspiciousProcesses = @("powershell", "cmd", "certutil", "bitsadmin", "mshta", "regsvr32", "wmic", "rundll32")
                    
                    foreach ($suspiciousProcess in $suspiciousProcesses) {
                        if ($image -match $suspiciousProcess) {
                            Write-LogEntry "WARNING" "External connection from suspicious process - potential C2 communication" -EventID $event.Id -ProcessName $image -TargetIP $destinationIp -ProcessId $processId -NetworkProtocol "TCP" -AdditionalFields "Port:$destinationPort" -Technique "T1041 - Exfiltration Over C2 Channel"
                            break
                        }
                    }
                }
            }
        }
    }
}

# Monitor for Exfiltration Over Physical Medium (T1052)
function Monitor-ExfiltrationOverPhysicalMedium {
    # Monitor USB and removable device activity
    if (Test-SysmonInstalled -Quiet $true) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(11, 2) -StartTime $Script:LastEventTime

        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            # Monitor file creation on removable media
            if ($event.Id -eq 11) {
                $targetFilename = $eventData.TargetFilename
                $image = $eventData.Image
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                $user = if ($eventData.User) { $eventData.User } else { "Unknown" }
                
                if ($targetFilename) {
                    # Check if file is being written to removable drive
                    $driveLetter = $targetFilename.Substring(0, 2)
                    try {
                        $driveInfo = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $driveLetter }
                        if ($driveInfo -and $driveInfo.DriveType -eq 2) {  # Removable disk
                            # Check if it's an OT-related file
                            if (Test-OTFile -FilePath $targetFilename) {
                                Write-LogEntry "WARNING" "OT file written to removable media" -EventID $event.Id -ProcessName $image -TargetFilename $targetFilename -ProcessId $processId -User $user -Technique "T1052.001 - Exfiltration over USB"
                            } else {
                                Write-LogEntry "INFO" "File written to removable media" -EventID $event.Id -ProcessName $image -TargetFilename $targetFilename -ProcessId $processId -User $user -Technique "T1052.001 - Exfiltration over USB"
                            }
                        }
                    } catch {
                        # Unable to determine drive type
                    }
                }
            }
        }
    }
    
    # Monitor system events for USB device insertion
    $systemEvents = Get-EventsSafe -LogName 'System' -EventIDs @(20001, 20003, 4001) -StartTime $Script:LastEventTime
    
    foreach ($event in $systemEvents) {
        if ($event.Id -in @(20001, 20003)) {
            Write-LogEntry "INFO" "USB device activity detected" -EventID $event.Id -Technique "T1052.001 - Exfiltration over USB"
        }
    }
}

# Monitor for Exfiltration Over Web Service (T1567)
function Monitor-ExfiltrationOverWebService {
    if (Test-SysmonInstalled -Quiet $true) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(3, 22) -StartTime $Script:LastEventTime

        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            # Monitor network connections to known cloud services
            if ($event.Id -eq 3) {
                $destinationHostname = $eventData.DestinationHostname
                $destinationIp = $eventData.DestinationIp
                $image = $eventData.Image
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                $user = if ($eventData.User) { $eventData.User } else { "Unknown" }
                
                # Known cloud service domains
                $cloudServices = @(
                    @{Service="Dropbox"; Pattern="dropbox|dbapi"},
                    @{Service="Google Drive"; Pattern="drive\.google|googleapis"},
                    @{Service="OneDrive"; Pattern="onedrive|sharepoint|office365"},
                    @{Service="Box"; Pattern="box\.com|boxapi"},
                    @{Service="AWS S3"; Pattern="s3\.amazonaws|s3-"},
                    @{Service="Azure Blob"; Pattern="blob\.core\.windows"},
                    @{Service="iCloud"; Pattern="icloud\.com"},
                    @{Service="Mega"; Pattern="mega\.nz|mega\.co"},
                    @{Service="GitHub"; Pattern="github\.com|raw\.githubusercontent"},
                    @{Service="Pastebin"; Pattern="pastebin\.com"},
                    @{Service="Discord"; Pattern="discord\.com|discordapp"},
                    @{Service="Telegram"; Pattern="telegram\.org|t\.me"},
                    @{Service="WeTransfer"; Pattern="wetransfer\.com"}
                )
                
                if ($destinationHostname) {
                    foreach ($cloudService in $cloudServices) {
                        if ($destinationHostname -match $cloudService.Pattern) {
                            # Check if it's from a suspicious process or non-browser
                            $isBrowser = $image -match "chrome|firefox|iexplore|msedge|opera|safari"
                            
                            if (-not $isBrowser) {
                                Write-LogEntry "WARNING" "Non-browser connection to cloud service - potential exfiltration" -EventID $event.Id -ProcessName $image -DestinationHostname $destinationHostname -ProcessId $processId -User $user -AdditionalFields "Service:$($cloudService.Service)" -Technique "T1567 - Exfiltration Over Web Service"
                            } else {
                                Write-LogEntry "INFO" "Browser connection to cloud service" -EventID $event.Id -ProcessName $image -DestinationHostname $destinationHostname -ProcessId $processId -User $user -AdditionalFields "Service:$($cloudService.Service)" -Technique "T1567 - Exfiltration Over Web Service"
                            }
                            break
                        }
                    }
                }
            }
            
            # Monitor DNS queries for cloud services
            if ($event.Id -eq 22) {
                $queryName = $eventData.QueryName
                $image = $eventData.Image
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                
                if ($queryName) {
                    # Check for cloud service DNS queries
                    $cloudDomains = @("dropbox", "googleapis", "onedrive", "box.com", "amazonaws", "blob.core.windows", "github.com", "pastebin.com")
                    
                    foreach ($domain in $cloudDomains) {
                        if ($queryName -match $domain) {
                            Write-LogEntry "INFO" "DNS query to cloud service domain" -EventID $event.Id -ProcessName $image -ProcessId $processId -AdditionalFields "QueryName:$queryName|Domain:$domain" -Technique "T1567 - Exfiltration Over Web Service"
                            break
                        }
                    }
                }
            }
        }
    }
}

# Monitor for Scheduled Transfer (T1029)
function Monitor-ScheduledTransfer {
    # Monitor Task Scheduler and cron-like activities
    $taskEvents = Get-EventsSafe -LogName 'Microsoft-Windows-TaskScheduler/Operational' -EventIDs @(106, 200, 201, 140, 141) -StartTime $Script:LastEventTime
    
    foreach ($event in $taskEvents) {
        $eventData = Get-EventData -Event $event
        
        # Task registration and execution
        if ($event.Id -eq 106) {
            $taskName = if ($eventData.TaskName) { $eventData.TaskName } else { "Unknown" }
            $actionName = if ($eventData.ActionName) { $eventData.ActionName } else { "Unknown" }
            $triggerType = if ($eventData.TriggerType) { $eventData.TriggerType } else { "Unknown" }
            
            # Check for data transfer related scheduled tasks
            if ($taskName -match "backup|export|sync|transfer|upload|send|copy|move" -and
                $actionName -match "powershell|cmd|robocopy|xcopy|curl|wget|scp|ftp") {
                Write-LogEntry "WARNING" "Scheduled task with data transfer capability registered" -EventID $event.Id -AdditionalFields "TaskName:$taskName|Action:$actionName|Trigger:$triggerType" -Technique "T1029 - Scheduled Transfer"
            }
        }
        
        # Task execution
        if ($event.Id -eq 200) {
            $taskName = if ($eventData.TaskName) { $eventData.TaskName } else { "Unknown" }
            $actionName = if ($eventData.ActionName) { $eventData.ActionName } else { "Unknown" }
            
            if ($taskName -match "backup|export|sync|transfer|upload" -and
                $actionName -match "powershell|cmd|robocopy|xcopy|curl|wget") {
                Write-LogEntry "INFO" "Data transfer scheduled task executed" -EventID $event.Id -AdditionalFields "TaskName:$taskName|Action:$actionName" -Technique "T1029 - Scheduled Transfer"
            }
        }
    }
    
    # Monitor Sysmon for scheduled activities
    if (Test-SysmonInstalled -Quiet $true) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1) {
                $commandLine = $eventData.CommandLine
                $image = $eventData.Image
                $parentImage = if ($eventData.ParentImage) { $eventData.ParentImage } else { "Unknown" }
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                $user = if ($eventData.User) { $eventData.User } else { "Unknown" }
                
                # Detect at/schtasks commands for scheduling transfers
                if ($commandLine -match "schtasks.*create.*robocopy|schtasks.*create.*xcopy|schtasks.*create.*curl|schtasks.*create.*wget|at.*\d{2}:\d{2}.*robocopy|at.*\d{2}:\d{2}.*xcopy") {
                    $processDetails = "PID:$processId|Parent:$parentImage|User:$user"
                    Write-LogEntry "WARNING" "Command to schedule data transfer detected" -EventID $event.Id -ProcessName $image -CommandLine $commandLine -ProcessId $processId -User $user -AdditionalFields $processDetails -Technique "T1029 - Scheduled Transfer"
                }
            }
        }
    }
}

# Generate monitoring summary
function Generate-Summary {
    Write-LogEntry "INFO" "=== Exfiltration Monitoring Summary ==="
    Write-LogEntry "INFO" "Monitoring Duration: $((Get-Date) - $Script:StartTime)"
    Write-LogEntry "INFO" "Total Detections by Technique:"
    
    if ($Script:EventCounters.Count -eq 0) {
        Write-LogEntry "INFO" "No exfiltration techniques detected during monitoring period"
    } else {
        foreach ($technique in $Script:EventCounters.Keys) {
            Write-LogEntry "INFO" "  $technique : $($Script:EventCounters[$technique]) events"
        }
    }
    
    Write-LogEntry "INFO" "=== End Summary ==="
}

# Show monitoring status
function Show-MonitoringStatus {
    $uptime = (Get-Date) - $Script:StartTime
    $totalDetections = ($Script:EventCounters.Values | Measure-Object -Sum).Sum
    
    Write-Host "`n--- Exfiltration Monitor Status ---" -ForegroundColor Cyan
    Write-Host "Uptime: $($uptime.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host "Total Detections: $totalDetections" -ForegroundColor White
    Write-Host "Last Check: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor White
    
    if ($Script:EventCounters.Count -gt 0) {
        Write-Host "Active Techniques:" -ForegroundColor Yellow
        foreach ($technique in $Script:EventCounters.Keys) {
            Write-Host "  $technique : $($Script:EventCounters[$technique])" -ForegroundColor Gray
        }
    }
    Write-Host "-----------------------------------`n" -ForegroundColor Cyan
}

# Main monitoring loop
function Start-Monitoring {
    Write-LogEntry "INFO" "Starting exfiltration monitoring loop..."
    
    $iterationCount = 0
    $endTime = if ($MonitorDuration -gt 0) { $Script:StartTime.AddMinutes($MonitorDuration) } else { [DateTime]::MaxValue }
    
    while ((Get-Date) -lt $endTime) {
        try {
            $iterationStart = Get-Date
            $iterationCount++
            
            # Run all monitoring functions
            Monitor-AutomatedExfiltration
            Monitor-ExfiltrationOverAlternativeProtocol
            Monitor-ExfiltrationOverC2Channel
            Monitor-ExfiltrationOverPhysicalMedium
            Monitor-ExfiltrationOverWebService
            Monitor-ScheduledTransfer
            
            # Update last event time for next iteration
            $Script:LastEventTime = $iterationStart
            
            # Show live status every 5 iterations or every 2.5 minutes
            if ($iterationCount % 5 -eq 0) {
                Show-MonitoringStatus
            }
            
            # Sleep for specified interval
            Start-Sleep -Seconds $RefreshInterval
            
        } catch {
            Write-LogEntry "ERROR" "Monitoring error in iteration #$iterationCount : $($_.Exception.Message)"
            Start-Sleep -Seconds 10  # Brief pause on error
        }
    }
}

# Cleanup function
function Stop-Monitoring {
    Write-LogEntry "INFO" "Stopping Exfiltration monitoring..."
    Generate-Summary
    Write-LogEntry "INFO" "Exfiltration Logger stopped at $(Get-Date)"
}

# Main execution
try {
    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
    Write-Host "Exfiltration Live Monitor v1.0 (Server 2012 Compatible)" -ForegroundColor Cyan
    Write-Host "OT Environment Optimized" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    # Initialize
    Initialize-Logger -Path $OutputPath
    
    # Check Sysmon status (this will cache the result and log once)
    $sysmonAvailable = Test-SysmonInstalled
    if (-not $sysmonAvailable) {
        Write-LogEntry "WARNING" "Sysmon not detected. Some detection capabilities will be limited."
        Write-LogEntry "INFO" "Run Setup-SysmonPipeline.ps1 to install Sysmon for enhanced monitoring"
    }
    
    # Display monitoring configuration
    Write-Host "`nMonitoring Configuration:" -ForegroundColor Yellow
    Write-Host "  Output Path: $OutputPath" -ForegroundColor White
    Write-Host "  Log Level: $LogLevel" -ForegroundColor White
    Write-Host "  Duration: $(if ($MonitorDuration -eq 0) { 'Continuous' } else { "$MonitorDuration minutes" })" -ForegroundColor White
    Write-Host "  Refresh Interval: $RefreshInterval seconds" -ForegroundColor White
    Write-Host "  Sysmon Available: $(if ($sysmonAvailable) { 'Yes' } else { 'No' })" -ForegroundColor White
    Write-Host "  OT File Extensions: $($Script:OTFileExtensions.Count) monitored" -ForegroundColor White
    
    Write-Host "`nPress Ctrl+C to stop monitoring..." -ForegroundColor Green
    Write-Host ""
    
    # Register cleanup on script termination
    Register-EngineEvent PowerShell.Exiting -Action { Stop-Monitoring }
    
    # Start monitoring
    Start-Monitoring
    
} catch {
    Write-LogEntry "ERROR" "Fatal error: $($_.Exception.Message)"
    Write-LogEntry "ERROR" "Stack trace: $($_.ScriptStackTrace)"
} finally {
    Stop-Monitoring
}
