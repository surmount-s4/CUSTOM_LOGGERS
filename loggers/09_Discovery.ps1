#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Discovery Tactics Logger using Sysmon and Windows Event Logs - Windows Server 2012 Compatible
.DESCRIPTION
    Monitors and logs Discovery techniques using Sysmon events and Windows Security logs
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
    $Script:LogFile = Join-Path $Path "Discovery_$timestamp.log"
    
    # Write initial log header without verbose console output
    $headerInfo = @"
=== Discovery Logger Started ===
Start Time: $(Get-Date)
PowerShell Version: $($PSVersionTable.PSVersion)
OS: $((Get-WmiObject Win32_OperatingSystem).Caption)
Log File: $Script:LogFile
================================
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

# Monitor for Account Discovery (T1087)
function Monitor-AccountDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Account enumeration patterns
                $accountDiscoveryPatterns = @(
                    "net user",
                    "net localgroup",
                    "net group",
                    "Get-LocalUser",
                    "Get-ADUser",
                    "Get-LocalGroupMember",
                    "whoami",
                    "quser",
                    "query user",
                    "wmic useraccount",
                    "dsquery user",
                    "nltest /domain_trusts"
                )
                
                foreach ($pattern in $accountDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        $technique = "T1087 - Account Discovery"
                        if ($pattern -match "net localgroup|Get-LocalUser|Get-LocalGroupMember") {
                            $technique = "T1087.001 - Local Account"
                        } elseif ($pattern -match "net group|Get-ADUser|dsquery") {
                            $technique = "T1087.002 - Domain Account"
                        } elseif ($pattern -match "wmic|query") {
                            $technique = "T1087.003 - Email Account"
                        }
                        
                        Write-LogEntry "INFO" "Account discovery command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique $technique
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Application Window Discovery (T1010)
function Monitor-ApplicationWindowDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Window discovery patterns
                $windowDiscoveryPatterns = @(
                    "tasklist",
                    "Get-Process",
                    "wmic process",
                    "Get-WindowTitle",
                    "EnumWindows",
                    "FindWindow",
                    "GetWindowText",
                    "GetForegroundWindow"
                )
                
                foreach ($pattern in $windowDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "INFO" "Application window discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1010 - Application Window Discovery"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Browser Information Discovery (T1217)
function Monitor-BrowserInformationDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # File access patterns for browser data
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFile = $eventData.TargetFilename
                
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
                        Write-LogEntry "WARNING" "Browser information access detected" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFile -Technique "T1217 - Browser Information Discovery"
                        break
                    }
                }
            }
            
            # Command line patterns
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                if ($commandLine -match "chrome.*--dump-dom|firefox.*--dump|Get-BrowserData|sqlite3.*History") {
                    Write-LogEntry "WARNING" "Browser information extraction detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1217 - Browser Information Discovery"
                }
            }
        }
    }
}

# Monitor for File and Directory Discovery (T1083)
function Monitor-FileDirectoryDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # File/Directory enumeration patterns
                $fileDiscoveryPatterns = @(
                    "dir /s",
                    "tree /f",
                    "forfiles",
                    "Get-ChildItem -Recurse",
                    "ls -la",
                    "find . -type f",
                    "wmic datafile",
                    "where /r"
                )
                
                foreach ($pattern in $fileDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "INFO" "File and directory discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1083 - File and Directory Discovery"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Network Service Discovery (T1046)
function Monitor-NetworkServiceDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Network service discovery patterns
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
                        Write-LogEntry "WARNING" "Network service discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1046 - Network Service Discovery"
                        break
                    }
                }
            }
            
            # Network connections to unusual ports (potential scanning)
            if ($event.Id -eq 3 -and $eventData.DestinationPort) {
                $destPort = $eventData.DestinationPort
                $scanningPorts = @("21", "22", "23", "25", "53", "80", "110", "135", "139", "143", "443", "445", "993", "995", "1433", "3389", "5985", "5986")
                
                if ($scanningPorts -contains $destPort -and $eventData.DestinationIp -notmatch "^(127\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)") {
                    Write-LogEntry "INFO" "Potential network service probing detected" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1046 - Network Service Discovery" -AdditionalFields "Port: $destPort, IP: $($eventData.DestinationIp)"
                }
            }
        }
    }
}

# Monitor for Network Share Discovery (T1135)
function Monitor-NetworkShareDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Network share discovery patterns
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
                        Write-LogEntry "INFO" "Network share discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1135 - Network Share Discovery"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Process Discovery (T1057)
function Monitor-ProcessDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Process discovery patterns
                $processDiscoveryPatterns = @(
                    "tasklist",
                    "Get-Process",
                    "wmic process",
                    "ps aux",
                    "pgrep",
                    "pkill -0"
                )
                
                foreach ($pattern in $processDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "INFO" "Process discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1057 - Process Discovery"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Query Registry (T1012)
function Monitor-QueryRegistry {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 12) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Registry query patterns
                $registryQueryPatterns = @(
                    "reg query",
                    "Get-ItemProperty",
                    "Get-RegistryValue",
                    "regedit /e",
                    "[Microsoft.Win32.Registry]"
                )
                
                foreach ($pattern in $registryQueryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "INFO" "Registry query detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1012 - Query Registry"
                        break
                    }
                }
            }
            
            # Sysmon registry read events
            if ($event.Id -eq 12 -and $eventData.TargetObject) {
                Write-LogEntry "INFO" "Registry access detected" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1012 - Query Registry" -AdditionalFields "Key: $($eventData.TargetObject)"
            }
        }
    }
}

# Monitor for Remote System Discovery (T1018)
function Monitor-RemoteSystemDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Remote system discovery patterns
                $remoteDiscoveryPatterns = @(
                    "ping -t",
                    "ping.*-a",
                    "nslookup",
                    "arp -a",
                    "net view",
                    "nltest",
                    "Get-ADComputer",
                    "dsquery computer",
                    "wmic /node",
                    "Get-NetNeighbor"
                )
                
                foreach ($pattern in $remoteDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "INFO" "Remote system discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1018 - Remote System Discovery"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Software Discovery (T1518)
function Monitor-SoftwareDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Software discovery patterns
                $softwareDiscoveryPatterns = @(
                    "wmic product",
                    "Get-WmiObject.*Win32_Product",
                    "Get-ItemProperty.*Uninstall",
                    "reg query.*Uninstall",
                    "dpkg -l",
                    "rpm -qa",
                    "yum list installed"
                )
                
                foreach ($pattern in $softwareDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        $technique = "T1518.001 - Security Software Discovery"
                        if ($commandLine -match "antivirus|defender|kaspersky|norton|mcafee|avast") {
                            $technique = "T1518.001 - Security Software Discovery"
                        } else {
                            $technique = "T1518 - Software Discovery"
                        }
                        
                        Write-LogEntry "INFO" "Software discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique $technique
                        break
                    }
                }
            }
        }
    }
}

# Monitor for System Information Discovery (T1082)
function Monitor-SystemInformationDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # System information discovery patterns
                $systemInfoPatterns = @(
                    "systeminfo",
                    "wmic computersystem",
                    "Get-ComputerInfo",
                    "Get-WmiObject.*Win32_ComputerSystem",
                    "hostname",
                    "uname -a",
                    "cat /proc/version",
                    "ver"
                )
                
                foreach ($pattern in $systemInfoPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "INFO" "System information discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1082 - System Information Discovery"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for System Network Configuration Discovery (T1016)
function Monitor-SystemNetworkConfigDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Network configuration discovery patterns
                $networkConfigPatterns = @(
                    "ipconfig",
                    "ifconfig",
                    "Get-NetIPConfiguration",
                    "Get-NetAdapter",
                    "netsh interface",
                    "route print",
                    "ip route",
                    "arp -a",
                    "Get-NetRoute"
                )
                
                foreach ($pattern in $networkConfigPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        $technique = "T1016 - System Network Configuration Discovery"
                        if ($pattern -match "route|Get-NetRoute") {
                            $technique = "T1016.001 - Internet Connection Discovery"
                        } elseif ($pattern -match "ipconfig|ifconfig|Get-NetIPConfiguration") {
                            $technique = "T1016.002 - Network Configuration"
                        }
                        
                        Write-LogEntry "INFO" "Network configuration discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique $technique
                        break
                    }
                }
            }
        }
    }
}

# Monitor for System Network Connections Discovery (T1049)
function Monitor-SystemNetworkConnectionsDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Network connections discovery patterns
                $connectionDiscoveryPatterns = @(
                    "netstat",
                    "Get-NetTCPConnection",
                    "ss -",
                    "lsof -i",
                    "netsh wlan show"
                )
                
                foreach ($pattern in $connectionDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "INFO" "Network connections discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1049 - System Network Connections Discovery"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for System Owner/User Discovery (T1033)
function Monitor-SystemOwnerUserDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # System owner/user discovery patterns
                $userDiscoveryPatterns = @(
                    "whoami",
                    "id",
                    "w",
                    "who",
                    "users",
                    "Get-WmiObject.*Win32_UserAccount",
                    "query user",
                    "quser"
                )
                
                foreach ($pattern in $userDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "INFO" "System owner/user discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1033 - System Owner/User Discovery"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for System Service Discovery (T1007)
function Monitor-SystemServiceDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Service discovery patterns
                $serviceDiscoveryPatterns = @(
                    "sc query",
                    "Get-Service",
                    "wmic service",
                    "systemctl",
                    "service --status-all",
                    "net start"
                )
                
                foreach ($pattern in $serviceDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "INFO" "System service discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1007 - System Service Discovery"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for System Time Discovery (T1124)
function Monitor-SystemTimeDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Time discovery patterns
                $timeDiscoveryPatterns = @(
                    "time /t",
                    "date /t",
                    "Get-Date",
                    "w32tm",
                    "net time",
                    "timedatectl"
                )
                
                foreach ($pattern in $timeDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "INFO" "System time discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1124 - System Time Discovery"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Password Policy Discovery (T1201)
function Monitor-PasswordPolicyDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Password policy discovery patterns
                $passwordPolicyPatterns = @(
                    "net accounts",
                    "Get-ADDefaultDomainPasswordPolicy",
                    "chage -l",
                    "pwpolicy"
                )
                
                foreach ($pattern in $passwordPolicyPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        Write-LogEntry "INFO" "Password policy discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1201 - Password Policy Discovery"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Permission Groups Discovery (T1069)
function Monitor-PermissionGroupsDiscovery {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Permission groups discovery patterns
                $groupsDiscoveryPatterns = @(
                    "net localgroup",
                    "net group",
                    "Get-LocalGroup",
                    "Get-ADGroup",
                    "groups",
                    "id -Gn",
                    "getent group"
                )
                
                foreach ($pattern in $groupsDiscoveryPatterns) {
                    if ($commandLine -match [regex]::Escape($pattern)) {
                        $technique = "T1069 - Permission Groups Discovery"
                        if ($pattern -match "net localgroup|Get-LocalGroup") {
                            $technique = "T1069.001 - Local Groups"
                        } elseif ($pattern -match "net group|Get-ADGroup") {
                            $technique = "T1069.002 - Domain Groups"
                        } elseif ($pattern -match "groups|id|getent") {
                            $technique = "T1069.003 - Cloud Groups"
                        }
                        
                        Write-LogEntry "INFO" "Permission groups discovery detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique $technique
                        break
                    }
                }
            }
        }
    }
}

# Display real-time status (disabled for clean logging)
# function Show-MonitoringStatus {
#     $uptime = (Get-Date) - $Script:StartTime
#     $totalEvents = ($Script:EventCounters.Values | Measure-Object -Sum).Sum
#     
#     Write-Host "`n=== Discovery Monitor Status ===" -ForegroundColor Cyan
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

=== Discovery Monitoring Summary ===
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
        Add-Content -Path $Script:LogFile -Value "No discovery techniques detected during monitoring period"
    }
    
    Add-Content -Path $Script:LogFile -Value "=== Discovery Logger Stopped at $(Get-Date) ==="
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
            Monitor-AccountDiscovery
            Monitor-ApplicationWindowDiscovery
            Monitor-BrowserInformationDiscovery
            Monitor-FileDirectoryDiscovery
            Monitor-NetworkServiceDiscovery
            Monitor-NetworkShareDiscovery
            Monitor-ProcessDiscovery
            Monitor-QueryRegistry
            Monitor-RemoteSystemDiscovery
            Monitor-SoftwareDiscovery
            Monitor-SystemInformationDiscovery
            Monitor-SystemNetworkConfigDiscovery
            Monitor-SystemNetworkConnectionsDiscovery
            Monitor-SystemOwnerUserDiscovery
            Monitor-SystemServiceDiscovery
            Monitor-SystemTimeDiscovery
            Monitor-PasswordPolicyDiscovery
            Monitor-PermissionGroupsDiscovery
            
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
    Write-Host "Discovery Live Monitor v1.0 (Server 2012 Compatible)" -ForegroundColor Cyan
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
    
    Write-Host "`nStarting Discovery monitoring... Press Ctrl+C to stop" -ForegroundColor Green
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
