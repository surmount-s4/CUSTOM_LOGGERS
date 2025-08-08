#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Credential Access Tactics Logger using Sysmon and Windows Event Logs - Windows Server 2012 Compatible
.DESCRIPTION
    Monitors and logs Credential Access techniques using Sysmon events and Windows Security logs
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

# Initialize logging
function Initialize-Logger {
    param([string]$Path)
    
    if (!(Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:LogFile = Join-Path $Path "CredentialAccess_$timestamp.log"
    
    Write-LogEntry "INFO" "Credential Access Logger started at $(Get-Date)"
    Write-LogEntry "INFO" "Log file: $Script:LogFile"
    Write-LogEntry "INFO" "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-LogEntry "INFO" "OS: $((Get-WmiObject Win32_OperatingSystem).Caption)"
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

# Monitor for OS Credential Dumping (T1003)
function Monitor-OSCredentialDumping {
    # Security events for credential access
    $events = Get-EventsSafe -LogName 'Security' -EventIDs @(4624, 4625, 4648, 4672, 4673, 4769, 4771) -StartTime $Script:LastEventTime

    foreach ($event in $events) {
        $eventData = Get-EventData -Event $event
        
        # Detect LSASS memory dumping patterns with enhanced details
        if ($event.Id -eq 4672 -and $eventData.PrivilegeList) {
            if ($eventData.PrivilegeList -match "SeDebugPrivilege") {
                # Filter out common system processes to reduce false positives
                $subjectUserName = if ($eventData.SubjectUserName) { $eventData.SubjectUserName } else { "Unknown" }
                $subjectLogonId = if ($eventData.SubjectLogonId) { $eventData.SubjectLogonId } else { "Unknown" }
                $privilegeList = if ($eventData.PrivilegeList) { $eventData.PrivilegeList } else { "Unknown" }
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                $processName = if ($eventData.ProcessName) { $eventData.ProcessName } else { "Unknown" }
                
                # Skip if it's a typical system process unless it's suspicious
                if ($subjectUserName -eq "SYSTEM" -and $processName -notmatch "lsass|winlogon|csrss") {
                    # Only alert if there are additional suspicious indicators
                    $additionalInfo = "LogonID:$subjectLogonId|PID:$processId|Process:$processName|Privileges:$privilegeList"
                    Write-LogEntry "INFO" "Debug privilege assigned to system process - monitoring for suspicious activity" -EventID $event.Id -User $subjectUserName -ProcessId $processId -AdditionalFields $additionalInfo -Technique "T1003.001 - LSASS Memory"
                } else {
                    # Non-system user or suspicious system process
                    $additionalInfo = "LogonID:$subjectLogonId|PID:$processId|Process:$processName|Privileges:$privilegeList"
                    Write-LogEntry "WARNING" "Debug privilege assigned - potential LSASS dumping" -EventID $event.Id -User $subjectUserName -ProcessId $processId -AdditionalFields $additionalInfo -Technique "T1003.001 - LSASS Memory"
                }
            }
        }
        
        # Detect unusual authentication patterns
        if ($event.Id -eq 4624 -and $eventData.LogonType -eq "3" -and $eventData.IpAddress) {
            if ($eventData.IpAddress -notmatch "^(127\.|::1|fe80:)") {
                Write-LogEntry "INFO" "Network logon detected" -EventID $event.Id -User $eventData.TargetUserName -SourceIP $eventData.IpAddress -Technique "T1003 - OS Credential Dumping"
            }
        }
    }
    
    # Sysmon events for credential dumping
    if (Test-SysmonInstalled -Quiet $true) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 7, 10, 11) -StartTime $Script:LastEventTime

        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            # Detect credential dumping tools with enhanced details
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                $image = $eventData.Image
                $processId = if ($eventData.ProcessId) { $eventData.ProcessId } else { "Unknown" }
                $parentImage = if ($eventData.ParentImage) { $eventData.ParentImage } else { "Unknown" }
                $user = if ($eventData.User) { $eventData.User } else { "Unknown" }
                $workingDirectory = if ($eventData.CurrentDirectory) { $eventData.CurrentDirectory } else { "Unknown" }
                
                # Known credential dumping patterns
                $dumpingPatterns = @(
                    "mimikatz|sekurlsa|lsadump|dcsync",
                    "procdump.*lsass",
                    "comsvcs.*MiniDump",
                    "rundll32.*comsvcs.*MiniDump",
                    "ntdsutil.*create.*full",
                    "vssadmin.*create.*shadow",
                    "reg.*save.*sam|reg.*save.*security|reg.*save.*system"
                )
                
                foreach ($pattern in $dumpingPatterns) {
                    if ($commandLine -match $pattern) {
                        $processDetails = "PID:$processId|Parent:$parentImage|User:$user|WorkDir:$workingDirectory"
                        Write-LogEntry "CRITICAL" "Credential dumping tool detected" -EventID $event.Id -ProcessName $image -CommandLine $commandLine -ProcessId $processId -User $user -AdditionalFields $processDetails -Technique "T1003 - OS Credential Dumping"
                        break
                    }
                }
            }
            
            # Detect LSASS process access with enhanced details
            if ($event.Id -eq 10 -and $eventData.TargetImage -match "lsass\.exe") {
                $grantedAccess = $eventData.GrantedAccess
                $sourceImage = if ($eventData.SourceImage) { $eventData.SourceImage } else { "Unknown" }
                $sourceProcessId = if ($eventData.SourceProcessId) { $eventData.SourceProcessId } else { "Unknown" }
                $targetProcessId = if ($eventData.TargetProcessId) { $eventData.TargetProcessId } else { "Unknown" }
                $callTrace = if ($eventData.CallTrace) { $eventData.CallTrace } else { "Unknown" }
                
                if ($grantedAccess -match "0x1010|0x1038|0x1fffff") {
                    $accessDetails = "GrantedAccess:$grantedAccess|SourcePID:$sourceProcessId|TargetPID:$targetProcessId|CallTrace:$($callTrace -replace '\|', ';')"
                    Write-LogEntry "CRITICAL" "Suspicious LSASS memory access detected" -EventID $event.Id -ProcessName $sourceImage -ProcessId $sourceProcessId -AdditionalFields $accessDetails -Technique "T1003.001 - LSASS Memory"
                }
            }
        }
    }
}

# Monitor for Brute Force attacks (T1110)
function Monitor-BruteForce {
    $events = Get-EventsSafe -LogName 'Security' -EventIDs @(4625, 4771, 4776, 4740, 4767) -StartTime $Script:LastEventTime

    # Count failed logons by user and source
    $failedLogons = @{}
    
    foreach ($event in $events) {
        $eventData = Get-EventData -Event $event
        
        if ($event.Id -eq 4625) {
            # Failed logon attempts
            $targetUser = $eventData.TargetUserName
            $sourceIP = $eventData.IpAddress
            $logonType = $eventData.LogonType
            
            $key = "$targetUser-$sourceIP"
            if ($failedLogons.ContainsKey($key)) {
                $failedLogons[$key] = $failedLogons[$key] + 1
            } else {
                $failedLogons[$key] = 1
            }
            
            # Immediate detection for high-value accounts
            if ($targetUser -match "admin|administrator|root|service") {
                Write-LogEntry "WARNING" "Failed logon attempt on privileged account" -EventID $event.Id -User $targetUser -SourceIP $sourceIP -Technique "T1110.001 - Password Guessing"
            }
        }
        
        if ($event.Id -eq 4771) {
            # Kerberos pre-authentication failed
            Write-LogEntry "WARNING" "Kerberos pre-authentication failure" -EventID $event.Id -User $eventData.TargetUserName -SourceIP $eventData.IpAddress -Technique "T1110.003 - Password Spraying"
        }
        
        if ($event.Id -eq 4740) {
            # Account lockout
            Write-LogEntry "CRITICAL" "Account lockout detected - possible brute force" -EventID $event.Id -User $eventData.TargetUserName -Technique "T1110 - Brute Force"
        }
    }
    
    # Analyze failed logon patterns
    foreach ($key in $failedLogons.Keys) {
        if ($failedLogons[$key] -ge 5) {
            $parts = $key -split "-"
            Write-LogEntry "CRITICAL" "Multiple failed logons detected ($($failedLogons[$key]) attempts)" -User $parts[0] -SourceIP $parts[1] -Technique "T1110 - Brute Force"
        }
    }
}

# Monitor for Network Sniffing (T1040)
function Monitor-NetworkSniffing {
    if (Test-SysmonInstalled -Quiet $true) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3, 7) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Network sniffing tools and commands
                $sniffingPatterns = @(
                    "wireshark|tshark|tcpdump|netcap",
                    "netsh.*trace.*capture",
                    "pktmon.*start",
                    "netstat.*-an.*>",
                    "arp.*-a.*>",
                    "nmap.*-sS|nmap.*-sT"
                )
                
                foreach ($pattern in $sniffingPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "WARNING" "Network sniffing tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1040 - Network Sniffing"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Input Capture (T1056)
function Monitor-InputCapture {
    if (Test-SysmonInstalled -Quiet $true) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 7, 13) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Keylogging and input capture patterns
                $inputCapturePatterns = @(
                    "keylogger|keylog",
                    "SetWindowsHookEx|GetAsyncKeyState",
                    "user32.*GetForegroundWindow",
                    "kernel32.*GetKeyState"
                )
                
                foreach ($pattern in $inputCapturePatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "CRITICAL" "Potential input capture tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1056.001 - Keylogging"
                        break
                    }
                }
            }
            
            # Monitor for DLL injection into processes handling user input
            if ($event.Id -eq 7 -and $eventData.ImageLoaded) {
                $imageLoaded = $eventData.ImageLoaded
                $processName = $eventData.Image
                
                if ($processName -match "explorer\.exe|winlogon\.exe|dwm\.exe" -and $imageLoaded -notmatch "Windows\\System32|Windows\\SysWOW64") {
                    Write-LogEntry "WARNING" "Suspicious DLL loaded into UI process" -EventID $event.Id -ProcessName $processName -TargetFilename $imageLoaded -Technique "T1056.004 - Credential API Hooking"
                }
            }
        }
    }
}

# Monitor for Credentials from Password Stores (T1555)
function Monitor-PasswordStores {
    if (Test-SysmonInstalled -Quiet $true) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Password store access patterns
                $passwordStorePatterns = @(
                    "vaultcmd|cmdkey.*\/list",
                    "rundll32.*keymgr\.dll",
                    "reg.*query.*Credential.*Manager",
                    "powershell.*Get-Credential",
                    "chrome.*Login.*Data|firefox.*logins\.json",
                    "1Password|LastPass|KeePass|Bitwarden"
                )
                
                foreach ($pattern in $passwordStorePatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "WARNING" "Password store access detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1555 - Credentials from Password Stores"
                        break
                    }
                }
            }
            
            # Monitor file access to credential stores
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                $credentialFiles = @(
                    "Login Data|logins\.json|key[0-9]\.db",
                    "Credential Manager|Windows Vault",
                    "\.kdbx$|\.1pif$|LastPass"
                )
                
                foreach ($pattern in $credentialFiles) {
                    if ($targetFilename -match $pattern) {
                        Write-LogEntry "INFO" "Credential store file accessed" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFilename -Technique "T1555 - Credentials from Password Stores"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Kerberos Attacks (T1558)
function Monitor-KerberosAttacks {
    $events = Get-EventsSafe -LogName 'Security' -EventIDs @(4768, 4769, 4771, 4624, 4648) -StartTime $Script:LastEventTime

    foreach ($event in $events) {
        $eventData = Get-EventData -Event $event
        
        # Kerberoasting detection
        if ($event.Id -eq 4769 -and $eventData.ServiceName) {
            $serviceName = $eventData.ServiceName
            $ticketEncryptionType = $eventData.TicketEncryptionType
            
            # RC4 encryption for service tickets (potential Kerberoasting)
            if ($ticketEncryptionType -eq "0x17") {
                Write-LogEntry "WARNING" "RC4 service ticket requested - potential Kerberoasting" -EventID $event.Id -User $eventData.TargetUserName -AdditionalFields "Service:$serviceName" -Technique "T1558.003 - Kerberoasting"
            }
        }
        
        # AS-REP Roasting detection
        if ($event.Id -eq 4768 -and $eventData.PreAuthType -eq "0") {
            Write-LogEntry "WARNING" "Pre-authentication not required - potential AS-REP Roasting" -EventID $event.Id -User $eventData.TargetUserName -Technique "T1558.004 - AS-REP Roasting"
        }
        
        # Golden/Silver ticket detection
        if ($event.Id -eq 4624 -and $eventData.LogonType -eq "3") {
            $authenticationPackage = $eventData.AuthenticationPackageName
            if ($authenticationPackage -eq "Kerberos" -and $eventData.LogonProcessName -ne "Kerberos") {
                Write-LogEntry "CRITICAL" "Suspicious Kerberos authentication" -EventID $event.Id -User $eventData.TargetUserName -Technique "T1558.001 - Golden Ticket"
            }
        }
    }
    
    # Sysmon events for Kerberos tools
    if (Test-SysmonInstalled -Quiet $true) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Kerberos attack tools
                if ($commandLine -match "rubeus|kekeo|asktgt|asktgs|golden|silver|kerberoast") {
                    Write-LogEntry "CRITICAL" "Kerberos attack tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1558 - Steal or Forge Kerberos Tickets"
                }
            }
        }
    }
}

# Monitor for Adversary-in-the-Middle (T1557)
function Monitor-AdversaryInTheMiddle {
    if (Test-SysmonInstalled -Quiet $true) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # AITM tools and techniques
                $aitmPatterns = @(
                    "responder|impacket|ntlmrelayx",
                    "arpspoof|ettercap|bettercap",
                    "netsh.*dhcp.*scope",
                    "mitm6|dns2proxy"
                )
                
                foreach ($pattern in $aitmPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "CRITICAL" "Adversary-in-the-Middle tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1557 - Adversary-in-the-Middle"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Modify Authentication Process (T1556)
function Monitor-ModifyAuthenticationProcess {
    # Security events for authentication modifications
    $events = Get-EventsSafe -LogName 'Security' -EventIDs @(4657, 4719, 4738, 4739) -StartTime $Script:LastEventTime

    foreach ($event in $events) {
        $eventData = Get-EventData -Event $event
        
        if ($event.Id -eq 4657) {
            # Registry modifications affecting authentication
            $objectName = $eventData.ObjectName
            if ($objectName -match "Authentication Packages|Security Packages|Notification Packages") {
                Write-LogEntry "CRITICAL" "Authentication package modification detected" -EventID $event.Id -User $eventData.SubjectUserName -Technique "T1556.002 - Password Filter DLL"
            }
        }
    }
    
    # Sysmon events
    if (Test-SysmonInstalled -Quiet $true) {
        $sysmonEvents = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11, 12, 13) -StartTime $Script:LastEventTime

        foreach ($event in $sysmonEvents) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Authentication modification commands
                if ($commandLine -match "lsass.*inject|ssp.*dll|auth.*package") {
                    Write-LogEntry "CRITICAL" "Authentication process modification attempt" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1556 - Modify Authentication Process"
                }
            }
            
            # Monitor for malicious DLL drops in system directories
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                if ($targetFilename -match "system32.*\.dll$|syswow64.*\.dll$" -and $eventData.Image -notmatch "msiexec|windows.*installer") {
                    Write-LogEntry "WARNING" "Suspicious DLL created in system directory" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFilename -Technique "T1556.002 - Password Filter DLL"
                }
            }
        }
    }
}

# Monitor for Unsecured Credentials (T1552)
function Monitor-UnsecuredCredentials {
    if (Test-SysmonInstalled -Quiet $true) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Commands searching for credentials
                $credSearchPatterns = @(
                    "findstr.*password|findstr.*credential",
                    "dir.*password.*\.txt|dir.*credential.*\.txt",
                    "type.*password|type.*credential",
                    "select-string.*password|select-string.*credential",
                    "reg.*query.*password|reg.*query.*credential"
                )
                
                foreach ($pattern in $credSearchPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "WARNING" "Credential search command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1552 - Unsecured Credentials"
                        break
                    }
                }
            }
            
            # Monitor for access to credential files
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                if ($targetFilename -match "password|credential|\.pwd$|\.key$|id_rsa|id_dsa") {
                    Write-LogEntry "INFO" "Potential credential file accessed" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFilename -Technique "T1552.001 - Credentials In Files"
                }
            }
        }
    }
}

# Monitor for Web Session Cookie Theft (T1539)
function Monitor-WebSessionCookies {
    if (Test-SysmonInstalled -Quiet $true) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                # Browser cookie files
                if ($targetFilename -match "Cookies|cookies\.sqlite|sessionstore\.js") {
                    Write-LogEntry "INFO" "Browser cookie file accessed" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $targetFilename -Technique "T1539 - Steal Web Session Cookie"
                }
            }
        }
    }
}

# Monitor for Multi-Factor Authentication attacks (T1621, T1668)
function Monitor-MFAAttacks {
    $events = Get-EventsSafe -LogName 'Security' -EventIDs @(4625, 4648, 4768, 4771) -StartTime $Script:LastEventTime

    # Track repeated authentication attempts that might indicate MFA fatigue
    $mfaAttempts = @{}
    
    foreach ($event in $events) {
        $eventData = Get-EventData -Event $event
        
        if ($event.Id -eq 4625 -and $eventData.SubStatusCode -eq "0xC000006A") {
            # Failed authentication with wrong password - potential MFA bypass attempt
            $user = $eventData.TargetUserName
            $sourceIP = $eventData.IpAddress
            
            $key = "$user-$sourceIP"
            if ($mfaAttempts.ContainsKey($key)) {
                $mfaAttempts[$key] = $mfaAttempts[$key] + 1
            } else {
                $mfaAttempts[$key] = 1
            }
            
            if ($mfaAttempts[$key] -ge 10) {
                Write-LogEntry "CRITICAL" "Potential MFA fatigue attack detected" -EventID $event.Id -User $user -SourceIP $sourceIP -Technique "T1668 - Multi-Factor Authentication Request Generation"
            }
        }
    }
}

# Display real-time status
function Show-MonitoringStatus {
    $uptime = (Get-Date) - $Script:StartTime
    $totalEvents = ($Script:EventCounters.Values | Measure-Object -Sum).Sum
    
    Write-Host "`n=== Credential Access Monitor Status ===" -ForegroundColor Cyan
    Write-Host "Uptime: $($uptime.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host "Total Events: $totalEvents" -ForegroundColor White
    Write-Host "Sysmon Status: $(if (Test-SysmonInstalled -Quiet $true) { 'Active' } else { 'Not Available' })" -ForegroundColor White
    Write-Host "Next check in: $RefreshInterval seconds" -ForegroundColor Gray
    
    if ($Script:EventCounters.Count -gt 0) {
        Write-Host "`nTop Techniques Detected:" -ForegroundColor Yellow
        $topTechniques = $Script:EventCounters.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
        foreach ($technique in $topTechniques) {
            Write-Host "  $($technique.Name): $($technique.Value)" -ForegroundColor White
        }
    }
    Write-Host "======================================" -ForegroundColor Cyan
}

# Generate summary report
function Generate-Summary {
    Write-LogEntry "INFO" "=== Credential Access Monitoring Summary ==="
    Write-LogEntry "INFO" "Monitoring duration: $((Get-Date) - $Script:StartTime)"
    Write-LogEntry "INFO" "Total techniques detected: $($Script:EventCounters.Count)"
    
    if ($Script:EventCounters.Count -gt 0) {
        $sortedTechniques = $Script:EventCounters.GetEnumerator() | Sort-Object Name
        foreach ($technique in $sortedTechniques) {
            Write-LogEntry "INFO" "$($technique.Name) : $($technique.Value) events"
        }
    } else {
        Write-LogEntry "INFO" "No credential access techniques detected during monitoring period"
    }
}

# Main monitoring loop with live updates
function Start-Monitoring {
    Write-LogEntry "INFO" "Starting Credential Access live monitoring..."
    Write-LogEntry "INFO" "Refresh interval: $RefreshInterval seconds"
    
    $endTime = if ($MonitorDuration -gt 0) { 
        $Script:StartTime.AddMinutes($MonitorDuration) 
    } else { 
        [DateTime]::MaxValue 
    }
    
    $iterationCount = 0
    
    while ((Get-Date) -lt $endTime) {
        try {
            $iterationStart = Get-Date
            $iterationCount++
            
            # Run all monitoring functions
            Monitor-OSCredentialDumping
            Monitor-BruteForce
            Monitor-NetworkSniffing
            Monitor-InputCapture
            Monitor-PasswordStores
            Monitor-KerberosAttacks
            Monitor-AdversaryInTheMiddle
            Monitor-ModifyAuthenticationProcess
            Monitor-UnsecuredCredentials
            Monitor-WebSessionCookies
            Monitor-MFAAttacks
            
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
    Write-LogEntry "INFO" "Stopping Credential Access monitoring..."
    Generate-Summary
    Write-LogEntry "INFO" "Credential Access Logger stopped at $(Get-Date)"
}

# Main execution
try {
    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
    Write-Host "Credential Access Live Monitor v1.0 (Server 2012 Compatible)" -ForegroundColor Cyan
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
