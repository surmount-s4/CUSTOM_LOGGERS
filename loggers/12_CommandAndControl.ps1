#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Command And Control Tactics Logger using Sysmon and Windows Event Logs - Windows Server 2012 Compatible
.DESCRIPTION
    Monitors and logs Command And Control techniques using Sysmon events and Windows Security logs
    Compatible with PowerShell 3.0+ and Windows Server 2012
.PARAMETER OutputPath
    Path where log files will be stored
.PARAMETER MonitorDuration
    Duration in minutes to monitor (0 = continuous)
.PARAMETER RefreshInterval
    Interval in seconds between monitoring checks (default: 30)
#>

param(
    [string]$OutputPath = "$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS",
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
    $Script:LogFile = Join-Path $Path "CommandAndControl_$timestamp.log"
    
    # Write initial log header without verbose console output
    $headerInfo = @"
=== Command And Control Logger Started ===
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
        [string]$Protocol = "",
        [string]$DestinationPort = "",
        [string]$AdditionalFields = ""
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] $Message"
    
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
    if ($Protocol) { $logEntry += " | Protocol: $Protocol" }
    if ($DestinationPort) { $logEntry += " | DestPort: $DestinationPort" }
    if ($Technique) { $logEntry += " | Technique: $Technique" }
    if ($AdditionalFields) { $logEntry += " | Additional: $AdditionalFields" }
    
    # Write to console
    Write-Host $logEntry -ForegroundColor White
    
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

# Monitor for Application Layer Protocol (T1071)
function Monitor-ApplicationLayerProtocol {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(3, 22) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 3 -and $eventData.DestinationPort -and $eventData.DestinationIp) {
                $port = $eventData.DestinationPort
                $destinationIp = $eventData.DestinationIp
                
                # Monitor for suspicious application protocols
                $suspiciousProtocols = @{
                    "80" = "T1071.001 - Web Protocols (HTTP)"
                    "443" = "T1071.001 - Web Protocols (HTTPS)" 
                    "53" = "T1071.004 - DNS"
                    "25" = "T1071.003 - Mail Protocols (SMTP)"
                    "110" = "T1071.003 - Mail Protocols (POP3)"
                    "143" = "T1071.003 - Mail Protocols (IMAP)"
                    "21" = "T1071.002 - File Transfer Protocols (FTP)"
                }
                
                if ($suspiciousProtocols.ContainsKey($port)) {
                    # Check for non-browser processes using web protocols
                    if (($port -eq "80" -or $port -eq "443") -and $eventData.Image -notmatch "chrome|firefox|iexplore|edge|browser") {
                        Write-LogEntry "Non-browser process using web protocol" -EventID $event.Id -ProcessName $eventData.Image -DestinationPort $port -TargetIP $destinationIp -Technique $suspiciousProtocols[$port]
                    }
                    
                    # Check for suspicious DNS traffic patterns
                    if ($port -eq "53" -and $eventData.Image -notmatch "svchost|dns|nslookup|dig") {
                        Write-LogEntry "Suspicious DNS traffic from non-standard process" -EventID $event.Id -ProcessName $eventData.Image -TargetIP $destinationIp -Technique $suspiciousProtocols[$port]
                    }
                }
            }
            
            if ($event.Id -eq 22 -and $eventData.QueryName) {
                # Monitor for DNS tunneling patterns
                $queryName = $eventData.QueryName
                if ($queryName.Length -gt 50 -or ($queryName -split '\.').Count -gt 5) {
                    Write-LogEntry "Potential DNS tunneling detected" -EventID $event.Id -ProcessName $eventData.Image -AdditionalFields "QueryName: $queryName" -Technique "T1071.004 - DNS Tunneling"
                }
            }
        }
    }
}

# Monitor for Communication Through Removable Media (T1092)
function Monitor-RemovableMediaCommunication {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(11, 23) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.TargetFilename -and $eventData.TargetFilename -match "^[D-Z]:\\") {
                # Check for file creation on removable drives
                if ($event.Id -eq 11) {
                    Write-LogEntry "File created on removable media" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $eventData.TargetFilename -Technique "T1092 - Communication Through Removable Media"
                }
                
                # Check for file deletion on removable drives (potential cleanup)
                if ($event.Id -eq 23) {
                    Write-LogEntry "File deleted from removable media" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $eventData.TargetFilename -Technique "T1092 - Communication Through Removable Media"
                }
            }
        }
    }
}

# Monitor for Data Encoding (T1132)
function Monitor-DataEncoding {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for base64 encoding/decoding operations
                if ($commandLine -match "base64|FromBase64String|ToBase64String|-enc|-decode") {
                    Write-LogEntry "Base64 encoding/decoding detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1132.001 - Standard Encoding"
                }
                
                # Check for other encoding methods
                if ($commandLine -match "certutil.*-encode|certutil.*-decode") {
                    Write-LogEntry "Certutil encoding/decoding detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1132.001 - Standard Encoding"
                }
            }
        }
    }
}

# Monitor for Data Obfuscation (T1001)
function Monitor-DataObfuscation {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(3, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            # Monitor network traffic for potential obfuscation
            if ($event.Id -eq 3 -and $eventData.DestinationPort) {
                $port = $eventData.DestinationPort
                $image = $eventData.Image
                
                # Check for steganography tools or suspicious image/media transfers
                if ($image -match "steghide|outguess|jphide|f5|openstego" -and ($port -eq "80" -or $port -eq "443")) {
                    Write-LogEntry "Potential steganography tool network activity" -EventID $event.Id -ProcessName $image -DestinationPort $port -Technique "T1001.002 - Steganography"
                }
            }
            
            # Monitor file creation for potential obfuscated files
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $filename = $eventData.TargetFilename
                
                # Check for suspicious image files with unusual sizes or in temp directories
                if ($filename -match "\.(jpg|png|gif|bmp|wav|mp3)$" -and $filename -match "temp|tmp|appdata") {
                    Write-LogEntry "Media file created in suspicious location" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $filename -Technique "T1001.002 - Steganography"
                }
            }
        }
    }
}

# Monitor for Dynamic Resolution (T1568)
function Monitor-DynamicResolution {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(22) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.QueryName) {
                $queryName = $eventData.QueryName
                
                # Check for Domain Generation Algorithm (DGA) patterns
                if ($queryName -match "^[a-z0-9]{8,20}\.(com|net|org|info)$" -and $queryName -notmatch "[aeiou]{2}") {
                    Write-LogEntry "Potential DGA domain detected" -EventID $event.Id -ProcessName $eventData.Image -AdditionalFields "Domain: $queryName" -Technique "T1568.002 - Domain Generation Algorithms"
                }
                
                # Check for fast flux patterns (multiple A records)
                if ($queryName -match "\.(tk|ml|ga|cf)$") {
                    Write-LogEntry "Suspicious top-level domain query" -EventID $event.Id -ProcessName $eventData.Image -AdditionalFields "Domain: $queryName" -Technique "T1568.001 - Fast Flux DNS"
                }
                
                # Check for DNS over HTTPS (DoH) usage
                if ($queryName -match "dns\.google|cloudflare-dns|quad9") {
                    Write-LogEntry "DNS over HTTPS usage detected" -EventID $event.Id -ProcessName $eventData.Image -AdditionalFields "DoH Provider: $queryName" -Technique "T1568.003 - DNS over HTTPS"
                }
            }
        }
    }
}

# Monitor for Encrypted Channel (T1573)
function Monitor-EncryptedChannel {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(3, 1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 3 -and $eventData.DestinationPort) {
                $port = $eventData.DestinationPort
                $image = $eventData.Image
                
                # Monitor for encrypted protocols on non-standard ports
                $encryptedPorts = @("443", "993", "995", "465", "22", "990")
                if ($encryptedPorts -contains $port -and $image -notmatch "chrome|firefox|iexplore|edge|outlook|thunderbird|ssh") {
                    Write-LogEntry "Non-standard process using encrypted protocol" -EventID $event.Id -ProcessName $image -DestinationPort $port -Technique "T1573.002 - Asymmetric Cryptography"
                }
            }
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for custom encryption tools
                if ($commandLine -match "openssl|gpg|aes|des|blowfish|twofish|serpent") {
                    Write-LogEntry "Encryption tool usage detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1573.001 - Symmetric Cryptography"
                }
            }
        }
    }
}

# Monitor for Non-Application Layer Protocol (T1095)
function Monitor-NonApplicationLayerProtocol {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.Protocol -and $eventData.DestinationPort) {
                $protocol = $eventData.Protocol
                $port = $eventData.DestinationPort
                
                # Monitor for ICMP, raw sockets, and other low-level protocols
                if ($protocol -match "icmp|raw|igmp" -or $port -eq "0") {
                    Write-LogEntry "Non-application layer protocol usage" -EventID $event.Id -ProcessName $eventData.Image -Protocol $protocol -DestinationPort $port -Technique "T1095 - Non-Application Layer Protocol"
                }
            }
        }
    }
}

# Monitor for Non-Standard Port (T1571)
function Monitor-NonStandardPort {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.DestinationPort -and $eventData.Image) {
                $port = [int]$eventData.DestinationPort
                $image = $eventData.Image
                
                # Check for standard services on non-standard ports
                if (($port -gt 1024 -and $port -lt 5000) -or ($port -gt 8000 -and $port -lt 9000)) {
                    if ($image -notmatch "chrome|firefox|iexplore|edge|teams|skype|zoom") {
                        Write-LogEntry "Communication on non-standard port" -EventID $event.Id -ProcessName $image -DestinationPort $eventData.DestinationPort -Technique "T1571 - Non-Standard Port"
                    }
                }
                
                # Check for high ports that might indicate covert channels
                if ($port -gt 49152) {
                    Write-LogEntry "Communication on high port number" -EventID $event.Id -ProcessName $image -DestinationPort $eventData.DestinationPort -Technique "T1571 - Non-Standard Port"
                }
            }
        }
    }
}

# Monitor for Protocol Tunneling (T1572)
function Monitor-ProtocolTunneling {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for tunneling tools
                if ($commandLine -match "ssh.*-L|ssh.*-R|ssh.*-D|stunnel|socat|chisel|ngrok|plink") {
                    Write-LogEntry "Potential protocol tunneling tool" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1572 - Protocol Tunneling"
                }
                
                # Check for DNS tunneling tools
                if ($commandLine -match "dnscat|iodine|dns2tcp") {
                    Write-LogEntry "DNS tunneling tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1572 - Protocol Tunneling"
                }
            }
        }
    }
}

# Monitor for Proxy (T1090)
function Monitor-Proxy {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3, 13) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for proxy tools and configurations
                if ($commandLine -match "proxychains|tor|i2p|freegate|ultrasurf|psiphon") {
                    Write-LogEntry "Proxy/anonymization tool detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1090.003 - Multi-hop Proxy"
                }
            }
            
            if ($event.Id -eq 13 -and $eventData.TargetObject) {
                $targetObject = $eventData.TargetObject
                
                # Monitor proxy-related registry modifications
                if ($targetObject -match "ProxyServer|ProxyEnable|ProxyOverride") {
                    Write-LogEntry "Proxy configuration modified in registry" -EventID $event.Id -ProcessName $eventData.Image -AdditionalFields "Registry: $targetObject" -Technique "T1090.001 - Internal Proxy"
                }
            }
        }
    }
}

# Monitor for Remote Access Tools (T1219)
function Monitor-RemoteAccessTools {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.Image -or $eventData.TargetFilename) {
                $filename = if ($eventData.Image) { $eventData.Image } else { $eventData.TargetFilename }
                
                # Check for common RAT tools
                $ratTools = @{
                    "teamviewer" = "T1219 - Remote Access Software"
                    "anydesk" = "T1219 - Remote Access Software"
                    "vnc" = "T1219 - Remote Access Software"
                    "rdp" = "T1219 - Remote Access Software"
                    "logmein" = "T1219 - Remote Access Software"
                    "ammyy" = "T1219 - Remote Access Software"
                    "supremo" = "T1219 - Remote Access Software"
                    "chrome.*remote.*desktop" = "T1219 - Remote Access Software"
                }
                
                foreach ($tool in $ratTools.Keys) {
                    if ($filename -match $tool) {
                        Write-LogEntry "Remote access tool detected" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $eventData.TargetFilename -Technique $ratTools[$tool]
                        break
                    }
                }
            }
            
            if ($event.Id -eq 3 -and $eventData.DestinationPort) {
                $port = $eventData.DestinationPort
                
                # Check for common RAT ports
                $ratPorts = @("3389", "5900", "5901", "5800", "4899", "6129", "1604")
                if ($ratPorts -contains $port) {
                    Write-LogEntry "Connection on common remote access port" -EventID $event.Id -ProcessName $eventData.Image -DestinationPort $port -Technique "T1219 - Remote Access Software"
                }
            }
        }
    }
}

# Monitor for Traffic Signaling (T1205)
function Monitor-TrafficSignaling {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(3, 22) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 3 -and $eventData.DestinationPort) {
                $port = $eventData.DestinationPort
                
                # Check for port knocking patterns - multiple connections to different ports in sequence
                if ($port -match "^[0-9]{1,5}$" -and [int]$port -lt 1024) {
                    Write-LogEntry "Connection to low-numbered port (potential port knocking)" -EventID $event.Id -ProcessName $eventData.Image -DestinationPort $port -Technique "T1205.001 - Port Knocking"
                }
            }
        }
    }
}

# Monitor for Web Service (T1102)
function Monitor-WebService {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(3, 22) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($eventData.DestinationHostname -or $eventData.QueryName) {
                $hostname = if ($eventData.DestinationHostname) { $eventData.DestinationHostname } else { $eventData.QueryName }
                
                # Check for connections to common web services used for C2
                $webServices = @{
                    "pastebin\.com" = "T1102.001 - Dead Drop Resolver"
                    "github\.com" = "T1102.001 - Dead Drop Resolver"
                    "dropbox\.com" = "T1102.002 - Bidirectional Communication"
                    "googledrive\.com" = "T1102.002 - Bidirectional Communication"
                    "onedrive\.com" = "T1102.002 - Bidirectional Communication"
                    "imgur\.com" = "T1102.001 - Dead Drop Resolver"
                    "reddit\.com" = "T1102.001 - Dead Drop Resolver"
                    "twitter\.com" = "T1102.002 - Bidirectional Communication"
                    "telegram\.org" = "T1102.002 - Bidirectional Communication"
                    "discord\.com" = "T1102.002 - Bidirectional Communication"
                }
                
                foreach ($service in $webServices.Keys) {
                    if ($hostname -match $service) {
                        # Only flag non-browser processes
                        if ($eventData.Image -notmatch "chrome|firefox|iexplore|edge|browser") {
                            Write-LogEntry "Non-browser process accessing web service" -EventID $event.Id -ProcessName $eventData.Image -DestinationHostname $hostname -Technique $webServices[$service]
                        }
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Ingress Tool Transfer (T1105)
function Monitor-IngressToolTransfer {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for download tools and commands
                if ($commandLine -match "wget|curl|bitsadmin|certutil.*-urlcache|powershell.*downloadfile|invoke-webrequest") {
                    Write-LogEntry "Tool download command detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1105 - Ingress Tool Transfer"
                }
                
                # Check for FTP/TFTP transfers
                if ($commandLine -match "ftp.*-s|tftp.*-i|scp|rsync") {
                    Write-LogEntry "File transfer tool usage" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1105 - Ingress Tool Transfer"
                }
            }
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $filename = $eventData.TargetFilename
                
                # Check for executable files downloaded to temp directories
                if ($filename -match "\.(exe|dll|scr|bat|cmd|ps1|vbs|js)$" -and $filename -match "temp|tmp|downloads|appdata") {
                    Write-LogEntry "Executable file created in temp location" -EventID $event.Id -ProcessName $eventData.Image -TargetFilename $filename -Technique "T1105 - Ingress Tool Transfer"
                }
            }
        }
    }
}

# Summary and cleanup functions
function Write-Summary {
    $summary = @"

=== Command And Control Monitoring Summary ===
Monitoring Period: $($Script:StartTime) to $(Get-Date)
Total Runtime: $((Get-Date) - $Script:StartTime)

Technique Detection Counts:
"@
    Add-Content -Path $Script:LogFile -Value $summary
    
    if ($Script:EventCounters.Count -gt 0) {
        foreach ($technique in $Script:EventCounters.Keys | Sort-Object) {
            $line = "  $technique : $($Script:EventCounters[$technique])"
            Add-Content -Path $Script:LogFile -Value $line
            Write-Host $line -ForegroundColor Cyan
        }
    } else {
        $noEvents = "  No suspicious Command And Control activities detected during monitoring period."
        Add-Content -Path $Script:LogFile -Value $noEvents
        Write-Host $noEvents -ForegroundColor Green
    }
}

function Stop-Monitoring {
    if ($Script:LogFile -and (Test-Path $Script:LogFile)) {
        Write-Summary
    }
    
    Add-Content -Path $Script:LogFile -Value "=== Command And Control Logger Stopped at $(Get-Date) ==="
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
            Monitor-ApplicationLayerProtocol
            Monitor-RemovableMediaCommunication
            Monitor-DataEncoding
            Monitor-DataObfuscation
            Monitor-DynamicResolution
            Monitor-EncryptedChannel
            Monitor-NonApplicationLayerProtocol
            Monitor-NonStandardPort
            Monitor-ProtocolTunneling
            Monitor-Proxy
            Monitor-RemoteAccessTools
            Monitor-TrafficSignaling
            Monitor-WebService
            Monitor-IngressToolTransfer
            
            # Update last event time for next iteration
            $Script:LastEventTime = $iterationStart
            
            # Sleep for refresh interval
            Start-Sleep -Seconds $RefreshInterval
            
        } catch {
            Write-LogEntry "Monitoring iteration failed: $($_.Exception.Message)"
            Start-Sleep -Seconds $RefreshInterval
        }
    }
}

# Main execution block
try {
    # Initialize logging
    Initialize-Logger -Path $OutputPath
    
    # Check Sysmon availability
    $sysmonAvailable = Test-SysmonInstalled
    if (-not $sysmonAvailable) {
        Write-Host "WARNING: Sysmon is not installed or not running. Some detections may be limited." -ForegroundColor Yellow
        Write-LogEntry "Sysmon not available - limited monitoring capabilities"
    } else {
        Write-LogEntry "Sysmon service detected and running"
    }
    
    # Display monitoring configuration
    Write-Host "`nMonitoring Configuration:" -ForegroundColor Yellow
    Write-Host "  Output Path: $OutputPath" -ForegroundColor White
    Write-Host "  Duration: $(if ($MonitorDuration -eq 0) { 'Continuous' } else { "$MonitorDuration minutes" })" -ForegroundColor White
    Write-Host "  Refresh Interval: $RefreshInterval seconds" -ForegroundColor White
    Write-Host "  Sysmon Available: $(if ($sysmonAvailable) { 'Yes' } else { 'No' })" -ForegroundColor White
    
    Write-Host "`nStarting Command And Control monitoring... Press Ctrl+C to stop" -ForegroundColor Green
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
