#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Lateral Movement Tactics Logger using Sysmon and Windows Event Logs - Windows Server 2012 Compatible
.DESCRIPTION
    Monitors and logs Lateral Movement techniques using Sysmon events and Windows Security logs
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
    $Script:LogFile = Join-Path $Path "LateralMovement_$timestamp.log"
    
    # Write initial log header without verbose console output
    $headerInfo = @"
=== Lateral Movement Logger Started ===
Start Time: $(Get-Date)
PowerShell Version: $($PSVersionTable.PSVersion)
OS: $((Get-WmiObject Win32_OperatingSystem).Caption)
Log File: $Script:LogFile
==========================================
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

# Monitor for Exploitation of Remote Services (T1210)
function Monitor-ExploitationRemoteServices {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Process creation for remote exploitation tools
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
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
                        Write-LogEntry "CRITICAL" "Remote service exploitation tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1210 - Exploitation of Remote Services"
                        break
                    }
                }
            }
            
            # Network connections to admin ports
            if ($event.Id -eq 3 -and $eventData.DestinationPort) {
                $destPort = $eventData.DestinationPort
                $adminPorts = @("135", "445", "5985", "5986", "3389")
                
                if ($adminPorts -contains $destPort -and $eventData.DestinationIp -notmatch "^127\.") {
                    Write-LogEntry "WARNING" "Connection to administrative service detected" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1210 - Exploitation of Remote Services" -AdditionalFields "Port: $destPort, IP: $($eventData.DestinationIp)"
                }
            }
        }
    }
}

# Monitor for Internal Spearphishing (T1534)
function Monitor-InternalSpearphishing {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Email client usage and file attachments
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                $emailPatterns = @(
                    "outlook.*-embedding",
                    "powershell.*Send-MailMessage",
                    "blat\.exe",
                    "smtp.*relay"
                )
                
                foreach ($pattern in $emailPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "WARNING" "Internal email activity detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1534 - Internal Spearphishing"
                        break
                    }
                }
            }
            
            # Suspicious email attachments
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFile = $eventData.TargetFilename
                
                if ($targetFile -match "\\AppData\\.*\\(.*\.(doc|docx|xls|xlsx|ppt|pptx|pdf|zip|rar)$)" -and $targetFile -match "Temp") {
                    Write-LogEntry "WARNING" "Potential internal spearphishing attachment detected" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFile -Technique "T1534 - Internal Spearphishing"
                }
            }
        }
    }
}

# Monitor for Lateral Tool Transfer (T1570)
function Monitor-LateralToolTransfer {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # File transfer tools
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
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
                        Write-LogEntry "WARNING" "Lateral tool transfer activity detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1570 - Lateral Tool Transfer"
                        break
                    }
                }
            }
            
            # Network file transfers
            if ($event.Id -eq 3 -and $eventData.DestinationPort) {
                $destPort = $eventData.DestinationPort
                $transferPorts = @("20", "21", "22", "80", "443", "990", "989")
                
                if ($transferPorts -contains $destPort -and $eventData.Image -notmatch "browser|chrome|firefox|edge") {
                    Write-LogEntry "INFO" "Potential file transfer connection detected" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1570 - Lateral Tool Transfer" -AdditionalFields "Port: $destPort, IP: $($eventData.DestinationIp)"
                }
            }
            
            # Files created in admin shares
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFile = $eventData.TargetFilename
                
                if ($targetFile -match "\\\\.*\\(admin\$|c\$|ipc\$)" -or $targetFile -match "\\\\.*\\SYSVOL" -or $targetFile -match "\\\\.*\\NETLOGON") {
                    Write-LogEntry "CRITICAL" "File created in administrative share" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFile -Technique "T1570 - Lateral Tool Transfer"
                }
            }
        }
    }
}

# Monitor for Remote Service Session Hijacking (T1563)
function Monitor-RemoteServiceSessionHijacking {
    # Monitor RDP Session Hijacking (T1563.002)
    $securityEvents = Get-EventsSafe -LogName 'Security' -EventIDs @(4778, 4779, 4624, 4634) -StartTime $Script:LastEventTime
    
    foreach ($event in $securityEvents) {
        $eventData = Get-EventData -Event $event
        
        # RDP session hijacking indicators
        if ($event.Id -eq 4778 -or $event.Id -eq 4779) {
            Write-LogEntry "WARNING" "RDP session reconnection detected" -EventID $event.Id -User $eventData.AccountName -Technique "T1563.002 - RDP Hijacking" -AdditionalFields "SessionID: $($eventData.SessionID), ClientName: $($eventData.ClientName)"
        }
    }
    
    # Monitor SSH Hijacking (T1563.001)
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                $sshHijackPatterns = @(
                    "ssh.*-o.*ControlMaster",
                    "ssh.*-S.*",
                    "ssh.*agent.*hijack"
                )
                
                foreach ($pattern in $sshHijackPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "CRITICAL" "Potential SSH session hijacking detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1563.001 - SSH Hijacking"
                        break
                    }
                }
            }
            
            # SSH connections from unusual processes
            if ($event.Id -eq 3 -and $eventData.DestinationPort -eq "22") {
                Write-LogEntry "INFO" "SSH connection detected" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1563.001 - SSH Hijacking" -AdditionalFields "IP: $($eventData.DestinationIp)"
            }
        }
    }
}

# Monitor for Remote Services (T1021)
function Monitor-RemoteServices {
    # Monitor RDP (T1021.001)
    $rdpEvents = Get-EventsSafe -LogName 'Security' -EventIDs @(4624, 4625) -StartTime $Script:LastEventTime
    
    foreach ($event in $rdpEvents) {
        $eventData = Get-EventData -Event $event
        
        if ($eventData.LogonType -eq "10") {
            $status = if ($event.Id -eq 4624) { "successful" } else { "failed" }
            Write-LogEntry "INFO" "RDP logon $status" -EventID $event.Id -User $eventData.TargetUserName -Technique "T1021.001 - Remote Desktop Protocol" -AdditionalFields "SourceIP: $($eventData.IpAddress)"
        }
    }
    
    # Monitor SMB/Windows Admin Shares (T1021.002)
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
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
                        Write-LogEntry "WARNING" "SMB/Admin shares usage detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1021.002 - SMB/Windows Admin Shares"
                        break
                    }
                }
            }
            
            # SMB connections
            if ($event.Id -eq 3 -and $eventData.DestinationPort -eq "445") {
                Write-LogEntry "INFO" "SMB connection detected" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1021.002 - SMB/Windows Admin Shares" -AdditionalFields "IP: $($eventData.DestinationIp)"
            }
        }
    }
    
    # Monitor WinRM (T1021.006)
    $winrmEvents = Get-EventsSafe -LogName 'Microsoft-Windows-WinRM/Operational' -EventIDs @(91, 168) -StartTime $Script:LastEventTime
    
    foreach ($event in $winrmEvents) {
        Write-LogEntry "INFO" "WinRM activity detected" -EventID $event.Id -Technique "T1021.006 - Windows Remote Management"
    }
    
    if (Test-SysmonInstalled) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(3) -StartTime $Script:LastEventTime

        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            if (($eventData.DestinationPort -eq "5985" -or $eventData.DestinationPort -eq "5986") -and $eventData.DestinationIp -notmatch "^127\.") {
                Write-LogEntry "INFO" "WinRM connection detected" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1021.006 - Windows Remote Management" -AdditionalFields "Port: $($eventData.DestinationPort), IP: $($eventData.DestinationIp)"
            }
        }
    }
    
    # Monitor SSH (T1021.004)
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.Image -match "ssh\.exe") {
                Write-LogEntry "INFO" "SSH client execution detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $eventData.CommandLine -Technique "T1021.004 - SSH"
            }
            
            if ($event.Id -eq 3 -and $eventData.DestinationPort -eq "22") {
                Write-LogEntry "INFO" "SSH connection detected" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1021.004 - SSH" -AdditionalFields "IP: $($eventData.DestinationIp)"
            }
        }
    }
}

# Monitor for Replication Through Removable Media (T1091)
function Monitor-ReplicationRemovableMedia {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.TargetFilename) {
                $targetFile = $eventData.TargetFilename
                
                # Files created on removable media
                if ($targetFile -match "^[D-Z]:.*" -and $targetFile -notmatch "^C:") {
                    $suspiciousExtensions = @(".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar")
                    
                    foreach ($ext in $suspiciousExtensions) {
                        if ($targetFile.EndsWith($ext)) {
                            Write-LogEntry "WARNING" "Executable file created on removable media" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFile -Technique "T1091 - Replication Through Removable Media"
                            break
                        }
                    }
                    
                    # Autorun files
                    if ($targetFile -match "autorun\.inf|autoplay\.inf") {
                        Write-LogEntry "CRITICAL" "Autorun file created on removable media" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFile -Technique "T1091 - Replication Through Removable Media"
                    }
                }
            }
        }
    }
}

# Monitor for Software Deployment Tools (T1072)
function Monitor-SoftwareDeploymentTools {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                $processImage = $eventData.Image
                
                # Common deployment tools
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
                
                # Deployment tool executables
                $deploymentTools = @(
                    "psexec.exe",
                    "paexec.exe",
                    "ansible.exe",
                    "puppet.exe",
                    "chef.exe",
                    "saltstack.exe"
                )
                
                $isDeploymentTool = $false
                foreach ($tool in $deploymentTools) {
                    if ($processImage -match $tool) {
                        $isDeploymentTool = $true
                        break
                    }
                }
                
                if ($isDeploymentTool) {
                    Write-LogEntry "INFO" "Software deployment tool execution detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1072 - Software Deployment Tools"
                } else {
                    foreach ($pattern in $deploymentPatterns) {
                        if ($commandLine -match $pattern) {
                            Write-LogEntry "INFO" "Software deployment activity detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1072 - Software Deployment Tools"
                            break
                        }
                    }
                }
            }
        }
    }
}

# Monitor for Taint Shared Content (T1080)
function Monitor-TaintSharedContent {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(11, 2) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # File modifications in shared locations
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFile = $eventData.TargetFilename
                
                # Shared folders and common locations
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
                        $suspiciousExtensions = @(".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".doc", ".docx", ".xls", ".xlsx")
                        
                        foreach ($ext in $suspiciousExtensions) {
                            if ($targetFile.EndsWith($ext)) {
                                Write-LogEntry "WARNING" "File created in shared location" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFile -Technique "T1080 - Taint Shared Content"
                                break
                            }
                        }
                        break
                    }
                }
            }
            
            # Timestomping in shared locations
            if ($event.Id -eq 2 -and $eventData.TargetFilename) {
                $targetFile = $eventData.TargetFilename
                
                if ($targetFile -match "\\\\.*\\(SYSVOL|NETLOGON|Public|Share)" -or $targetFile -match "C:\\Users\\Public") {
                    Write-LogEntry "CRITICAL" "File timestamp modification in shared location" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFile -Technique "T1080 - Taint Shared Content"
                }
            }
        }
    }
}

# Monitor for Use Alternate Authentication Material (T1550)
function Monitor-AlternateAuthMaterial {
    # Monitor Pass the Hash (T1550.002) and Pass the Ticket (T1550.003)
    $securityEvents = Get-EventsSafe -LogName 'Security' -EventIDs @(4624, 4625, 4768, 4769, 4771) -StartTime $Script:LastEventTime
    
    foreach ($event in $securityEvents) {
        $eventData = Get-EventData -Event $event
        
        # Unusual logon patterns that might indicate PTH/PTT
        if ($event.Id -eq 4624 -and $eventData.LogonType -eq "9") {
            Write-LogEntry "WARNING" "NewCredentials logon detected (potential PTH/PTT)" -EventID $event.Id -User $eventData.TargetUserName -Technique "T1550 - Use Alternate Authentication Material" -AdditionalFields "LogonType: 9, SourceIP: $($eventData.IpAddress)"
        }
        
        # Kerberos ticket anomalies
        if ($event.Id -eq 4768 -or $event.Id -eq 4769) {
            if ($eventData.CertThumbprint -or $eventData.CertIssuerName) {
                Write-LogEntry "INFO" "Certificate-based Kerberos authentication detected" -EventID $event.Id -User $eventData.TargetUserName -Technique "T1550.001 - Application Access Token"
            }
        }
    }
    
    # Monitor for credential theft tools
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 10) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
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
                        Write-LogEntry "CRITICAL" "Credential theft tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1550 - Use Alternate Authentication Material"
                        break
                    }
                }
            }
            
            # Process access to LSASS
            if ($event.Id -eq 10 -and $eventData.TargetImage -match "lsass\.exe") {
                $grantedAccess = $eventData.GrantedAccess
                if ($grantedAccess -match "(0x1010|0x1038|0x143A|0x1410)") {
                    Write-LogEntry "CRITICAL" "Suspicious LSASS process access detected" -EventID $event.Id -ProcessName $eventData.SourceImage -Technique "T1550.002 - Pass the Hash" -AdditionalFields "GrantedAccess: $grantedAccess"
                }
            }
        }
    }
}

# Main monitoring function
function Start-Monitoring {
    Write-Host "Starting Lateral Movement monitoring..." -ForegroundColor Green
    Write-Host "Monitoring for lateral movement techniques with $RefreshInterval second intervals" -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Yellow
    Write-Host ""
    
    $endTime = if ($MonitorDuration -gt 0) { 
        (Get-Date).AddMinutes($MonitorDuration) 
    } else { 
        [DateTime]::MaxValue 
    }
    
    while ((Get-Date) -lt $endTime) {
        try {
            # Update last event time
            $Script:LastEventTime = (Get-Date).AddSeconds(-$RefreshInterval - 5)
            
            # Run all monitoring functions
            Monitor-ExploitationRemoteServices
            Monitor-InternalSpearphishing
            Monitor-LateralToolTransfer
            Monitor-RemoteServiceSessionHijacking
            Monitor-RemoteServices
            Monitor-ReplicationRemovableMedia
            Monitor-SoftwareDeploymentTools
            Monitor-TaintSharedContent
            Monitor-AlternateAuthMaterial
            
            Start-Sleep -Seconds $RefreshInterval
        } catch {
            # Silent error handling to prevent monitoring interruption
            Start-Sleep -Seconds $RefreshInterval
        }
    }
}

# Generate summary report
function Generate-Summary {
    Write-Host "`n=== Lateral Movement Monitoring Summary ===" -ForegroundColor Cyan
    Write-Host "Monitor Duration: $(((Get-Date) - $Script:StartTime).ToString('hh\:mm\:ss'))" -ForegroundColor Green
    Write-Host "Log File: $Script:LogFile" -ForegroundColor Green
    
    if ($Script:EventCounters.Count -gt 0) {
        Write-Host "`nTechnique Detection Summary:" -ForegroundColor Yellow
        foreach ($technique in $Script:EventCounters.Keys | Sort-Object) {
            Write-Host "  $technique : $($Script:EventCounters[$technique]) events" -ForegroundColor White
        }
    } else {
        Write-Host "`nNo lateral movement techniques detected during monitoring period." -ForegroundColor Green
    }
    
    Write-Host ""
}

# Main execution
try {
    Initialize-Logger -Path $OutputPath
    Start-Monitoring
} catch {
    Write-Host "Monitoring interrupted: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Generate-Summary
}
