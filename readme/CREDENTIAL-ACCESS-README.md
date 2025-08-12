# Credential Access Live Monitor

## Overview
The Credential Access Live Monitor is a Windows Server 2012+ compatible PowerShell script that provides real-time monitoring and logging of Credential Access techniques based on the MITRE ATT&CK framework.

## Features
- **Real-time monitoring** with live status updates
- **Windows Server 2012 compatible** (PowerShell 3.0+)
- **Sysmon integration** for enhanced detection capabilities
- **Live dashboard** showing monitoring status and statistics
- **Comprehensive logging** with structured output
- **MITRE ATT&CK mapping** for all detected techniques

## Monitored Techniques

### T1557 - Adversary-in-the-Middle (4 sub-techniques)
- LLMNR/NBT-NS Poisoning and SMB Relay
- ARP Cache Poisoning
- DHCP Spoofing
- Network device manipulation

### T1110 - Brute Force (4 sub-techniques)
- Password Guessing
- Password Cracking
- Password Spraying
- Credential Stuffing

### T1555 - Credentials from Password Stores (6 sub-techniques)
- Keychain
- Securely Stored Credentials
- Credentials from Web Browsers
- Windows Credential Manager
- Password Managers
- Cloud Secrets Management Stores

### T1212 - Exploitation for Credential Access
- Software vulnerability exploitation for credential access

### T1187 - Forced Authentication
- Forced NTLM authentication attempts

### T1606 - Forge Web Credentials (2 sub-techniques)
- Web Cookies
- SAML Tokens

### T1056 - Input Capture (4 sub-techniques)
- Keylogging
- GUI Input Capture
- Web Portal Capture
- Credential API Hooking

### T1556 - Modify Authentication Process (9 sub-techniques)
- Domain Controller Authentication
- Password Filter DLL
- Pluggable Authentication Modules
- Network Device Authentication
- Reversible Encryption
- Multi-Factor Authentication
- Hybrid Identity
- Network Provider DLL
- Windows Account Persistence Modifications

### T1621 - Multi-Factor Authentication Interception
- MFA token interception

### T1668 - Multi-Factor Authentication Request Generation
- MFA fatigue attacks

### T1040 - Network Sniffing
- Network credential capture

### T1003 - OS Credential Dumping (8 sub-techniques)
- LSASS Memory
- Security Account Manager
- NTDS
- LSA Secrets
- Cached Domain Credentials
- DCSync
- Proc Filesystem
- /etc/passwd and /etc/shadow

### T1528 - Steal Application Access Token
- Application token theft

### T1649 - Steal or Forge Authentication Certificates
- Certificate theft and forgery

### T1558 - Steal or Forge Kerberos Tickets (5 sub-techniques)
- Golden Ticket
- Silver Ticket
- Kerberoasting
- AS-REP Roasting
- Forged PAC

### T1539 - Steal Web Session Cookie
- Web session hijacking

### T1552 - Unsecured Credentials
- Credentials in files, registry, or other locations

## Requirements
- Windows Server 2012 or later
- PowerShell 3.0 or later
- Administrator privileges
- Sysmon (recommended for full functionality)

## Installation
1. Place the script in the CUSTOM_LOGGERS directory
2. Ensure Sysmon is installed using Setup-SysmonPipeline.ps1
3. Run the script as Administrator

## Usage

### Basic Usage
```powershell
# Run with default settings (continuous monitoring)
.\CredentialAccess.ps1

# Monitor for specific duration (60 minutes)
.\CredentialAccess.ps1 -MonitorDuration 60

# Custom refresh interval (15 seconds)
.\CredentialAccess.ps1 -RefreshInterval 15
```

### Advanced Usage
```powershell
# Custom output path and settings
.\CredentialAccess.ps1 -OutputPath "C:\MyLogs" -LogLevel "Warning" -MonitorDuration 120

# High-frequency monitoring
.\CredentialAccess.ps1 -RefreshInterval 10 -LogLevel "Info"
```

### Parameters
- **OutputPath**: Directory for log files (default: CUSTOM_LOGGERS folder)
- **LogLevel**: Minimum log level (Info, Warning, Critical)
- **MonitorDuration**: Minutes to monitor (0 = continuous)
- **RefreshInterval**: Seconds between checks (default: 30)

## Output Files
- **CredentialAccess_YYYYMMDD_HHMMSS.log**: Main detection log
- Real-time console output with color coding
- Structured logging with technique mapping

## Integration with Sysmon
The script automatically detects Sysmon installation and enhances monitoring when available:
- Uses existing Sysmon service detection logic
- Compatible with Setup-SysmonPipeline.ps1 configuration
- Graceful degradation when Sysmon is not available

## Live Monitoring Features
- Real-time status dashboard
- Event counters by technique
- Uptime tracking
- Top detected techniques display
- Continuous monitoring with Ctrl+C to stop

## Log Format
```
[YYYY-MM-DD HH:MM:SS] [LEVEL] Message | EventID: XXX | Process: process.exe | CommandLine: command | PID: XXXX | User: username | Additional: detailed_context | Technique: TXXXX.XXX - Name
```

## Enhanced Detection Features
- **Zero noise monitoring**: No iteration or repetitive status logs
- **Context-rich alerts**: Detailed process information, PIDs, users, and call traces
- **Smart filtering**: Reduces false positives from system processes
- **Enhanced LSASS monitoring**: Detailed process access patterns and call traces
- **Credential tool detection**: Comprehensive command-line and process analysis

## Compatibility Notes
- Uses PowerShell 3.0+ compatible syntax
- Avoids null-coalescing operator (??) for Server 2012 compatibility
- Enhanced error handling for older PowerShell versions
- Compatible event filtering for Windows Server 2012

## Troubleshooting

### Common Issues
1. **Sysmon not detected**: Install using Setup-SysmonPipeline.ps1
2. **Permission errors**: Run as Administrator
3. **Event log access**: Ensure proper Windows Event Log permissions
4. **High CPU usage**: Increase RefreshInterval parameter

### Performance Optimization
- Increase RefreshInterval for less frequent checking
- Use LogLevel "Warning" or "Critical" to reduce noise
- Monitor for specific durations rather than continuous

## Security Considerations
- Logs may contain sensitive credential information
- Ensure log file permissions are properly configured
- Monitor log file size for long-running sessions
- Consider log rotation for continuous monitoring
- Be aware that this script detects credential access attempts

## Integration with Other Scripts
This script is designed to work alongside other Custom Security Logger scripts:
- Uses same logging format and directory structure
- Compatible with existing Sysmon configuration
- Can run simultaneously with other monitors

## Detection Accuracy
- High rate of credential dumping detection
- Network sniffing detection requires proper network monitoring
- Some techniques require specific configurations or tools to detect
- False positives may occur with legitimate administrative activities

## Support
For issues or questions:
1. Check Sysmon installation status
2. Verify PowerShell version compatibility
3. Review Event Viewer for related errors
4. Check log files for detailed error messages
