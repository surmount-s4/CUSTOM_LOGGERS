# Discovery Live Monitor

## Overview
The Discovery Live Monitor is a Windows Server 2012+ compatible PowerShell script that provides real-time monitoring and logging of Discovery techniques based on the MITRE ATT&CK framework. This script follows the same architecture and patterns as the Defense Evasion monitor.

## Features
- **Real-time monitoring** with live status updates
- **Windows Server 2012 compatible** (PowerShell 3.0+)
- **Sysmon integration** for enhanced detection capabilities
- **Live dashboard** showing monitoring status and statistics
- **Comprehensive logging** with structured output
- **MITRE ATT&CK mapping** for all detected techniques
- **18+ Discovery techniques covered**

## Monitored Techniques

### T1087 - Account Discovery
- **T1087.001 - Local Account**: Local user enumeration
- **T1087.002 - Domain Account**: Active Directory user discovery
- **T1087.003 - Email Account**: Email account enumeration
- Monitors: `net user`, `Get-LocalUser`, `Get-ADUser`, `whoami`, `dsquery user`

### T1010 - Application Window Discovery
- Window enumeration and application discovery
- Monitors: `tasklist`, `Get-Process`, `wmic process`, Windows API calls

### T1217 - Browser Information Discovery
- Browser data access and extraction
- Monitors: Chrome/Firefox/Edge profile access, history/bookmarks/cookies access
- File access patterns: User Data folders, browser databases

### T1083 - File and Directory Discovery
- File system enumeration and exploration
- Monitors: `dir /s`, `tree /f`, `Get-ChildItem -Recurse`, `forfiles`, `find`

### T1046 - Network Service Discovery
- Network service scanning and discovery
- Monitors: `nmap`, `portqry`, `telnet`, `Test-NetConnection`, port scanning activity

### T1135 - Network Share Discovery
- Network share enumeration
- Monitors: `net view`, `net share`, `Get-SmbShare`, `showmount`

### T1057 - Process Discovery
- Running process enumeration
- Monitors: `tasklist`, `Get-Process`, `wmic process`, `ps aux`

### T1012 - Query Registry
- Registry key and value enumeration
- Monitors: `reg query`, `Get-ItemProperty`, registry access via Sysmon

### T1018 - Remote System Discovery
- Remote system and network discovery
- Monitors: `ping`, `nslookup`, `arp`, `nltest`, `Get-ADComputer`

### T1518 - Software Discovery
- **T1518.001 - Security Software Discovery**: Antivirus/security tool discovery
- Installed software enumeration
- Monitors: `wmic product`, `Get-WmiObject Win32_Product`, uninstall registry queries

### T1082 - System Information Discovery
- System configuration and information gathering
- Monitors: `systeminfo`, `hostname`, `Get-ComputerInfo`, `uname -a`

### T1016 - System Network Configuration Discovery
- **T1016.001 - Internet Connection Discovery**: Route discovery
- **T1016.002 - Network Configuration**: Network adapter configuration
- Monitors: `ipconfig`, `ifconfig`, `Get-NetIPConfiguration`, `route print`

### T1049 - System Network Connections Discovery
- Active network connection enumeration
- Monitors: `netstat`, `Get-NetTCPConnection`, `ss`, `lsof -i`

### T1033 - System Owner/User Discovery
- Current user and ownership discovery
- Monitors: `whoami`, `id`, `who`, `query user`

### T1007 - System Service Discovery
- System service enumeration
- Monitors: `sc query`, `Get-Service`, `wmic service`, `systemctl`

### T1124 - System Time Discovery
- System time and timezone discovery
- Monitors: `time`, `date`, `Get-Date`, `w32tm`, `net time`

### T1201 - Password Policy Discovery
- Password policy enumeration
- Monitors: `net accounts`, `Get-ADDefaultDomainPasswordPolicy`, `chage -l`

### T1069 - Permission Groups Discovery
- **T1069.001 - Local Groups**: Local group enumeration
- **T1069.002 - Domain Groups**: Domain group discovery
- **T1069.003 - Cloud Groups**: Cloud group enumeration
- Monitors: `net localgroup`, `net group`, `Get-LocalGroup`, `Get-ADGroup`

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
.\Discovery.ps1

# Monitor for specific duration (60 minutes)
.\Discovery.ps1 -MonitorDuration 60

# Custom refresh interval (15 seconds)
.\Discovery.ps1 -RefreshInterval 15
```

### Advanced Usage
```powershell
# Custom output path and settings
.\Discovery.ps1 -OutputPath "C:\MyLogs" -LogLevel "Warning" -MonitorDuration 120

# High-frequency monitoring
.\Discovery.ps1 -RefreshInterval 10 -LogLevel "Info"
```

### Parameters
- **OutputPath**: Directory for log files (default: CUSTOM_LOGGERS folder)
- **LogLevel**: Minimum log level (Info, Warning, Critical)
- **MonitorDuration**: Minutes to monitor (0 = continuous)
- **RefreshInterval**: Seconds between checks (default: 30)

## Output Files
- **Discovery_YYYYMMDD_HHMMSS.log**: Main detection log
- Real-time console output with color coding
- Structured logging with technique mapping

## Integration with Sysmon
The script automatically detects Sysmon installation and enhances monitoring when available:
- Uses existing Sysmon service detection logic
- Compatible with Setup-SysmonPipeline.ps1 configuration
- Monitors Sysmon Event IDs: 1 (Process Creation), 3 (Network Connection), 11 (File Create), 12 (Registry Read)
- Graceful degradation when Sysmon is not available

## Live Monitoring Features
- Real-time status dashboard
- Event counters by technique
- Uptime tracking
- Top detected techniques display
- Continuous monitoring with Ctrl+C to stop
- Live updates every 5 monitoring iterations

## Log Format
```
[YYYY-MM-DD HH:MM:SS] [LEVEL] Message | EventID: XXX | Process: process.exe | CommandLine: command | Technique: TXXXX.XXX - Name
```

### Example Log Entries
```
[2025-08-07 10:30:45] [INFO] Account discovery command detected | EventID: 1 | Process: cmd.exe | CommandLine: net user | Technique: T1087.001 - Local Account
[2025-08-07 10:31:02] [WARNING] Network service discovery detected | EventID: 1 | Process: nmap.exe | CommandLine: nmap -sS 192.168.1.0/24 | Technique: T1046 - Network Service Discovery
[2025-08-07 10:31:15] [INFO] System information discovery detected | EventID: 1 | Process: systeminfo.exe | Technique: T1082 - System Information Discovery
```

## Detection Capabilities

### Command Line Analysis
- Pattern matching for known discovery commands
- Regular expression-based detection
- Cross-platform command recognition (Windows/Linux)

### File System Monitoring
- Browser data access detection
- Suspicious file enumeration patterns
- Registry access monitoring

### Network Activity Analysis
- Port scanning detection
- Network service probing
- Unusual connection patterns

## Compatibility Notes
- Uses PowerShell 3.0+ compatible syntax
- Avoids null-coalescing operator (??) for Server 2012 compatibility
- Enhanced error handling for older PowerShell versions
- Compatible event filtering for Windows Server 2012
- Same logging format as Defense Evasion monitor

## Performance Considerations
- **Default refresh interval**: 30 seconds (adjustable)
- **Event processing**: Batch processing for efficiency
- **Memory usage**: Minimal footprint with incremental event processing
- **CPU impact**: Low impact during normal operation

## Troubleshooting

### Common Issues
1. **Sysmon not detected**: Install using Setup-SysmonPipeline.ps1
2. **Permission errors**: Run as Administrator
3. **Event log access**: Ensure proper Windows Event Log permissions
4. **High CPU usage**: Increase RefreshInterval parameter
5. **Missing events**: Check Sysmon configuration and ensure proper event logging

### Performance Optimization
- Increase RefreshInterval for less frequent checking (recommended: 30-60 seconds)
- Use LogLevel "Warning" or "Critical" to reduce noise
- Monitor for specific durations rather than continuous for resource optimization

## Security Considerations
- **Sensitive data**: Logs may contain command line arguments and file paths
- **Log permissions**: Ensure log file permissions are properly configured
- **Log rotation**: Monitor log file size for long-running sessions
- **Storage**: Consider log retention policies for continuous monitoring

## Integration with Other Scripts
This script is designed to work alongside other Custom Security Logger scripts:
- **Same architecture**: Compatible with DefenseEvasion.ps1 and other monitors
- **Consistent logging**: Uses same logging format and directory structure
- **Sysmon compatibility**: Works with existing Sysmon configuration
- **Parallel execution**: Can run simultaneously with other monitors

## Detection Coverage Analysis

### High-Fidelity Techniques (Low False Positives)
- T1087 - Account Discovery
- T1135 - Network Share Discovery
- T1201 - Password Policy Discovery
- T1069 - Permission Groups Discovery

### Medium-Fidelity Techniques (Moderate Filtering Required)
- T1057 - Process Discovery
- T1007 - System Service Discovery
- T1082 - System Information Discovery
- T1033 - System Owner/User Discovery

### Noisy Techniques (Require Context Analysis)
- T1083 - File and Directory Discovery
- T1012 - Query Registry
- T1049 - System Network Connections Discovery
- T1010 - Application Window Discovery

## Advanced Configuration

### Custom Pattern Matching
Modify the pattern arrays in each monitoring function to add custom detection rules:

```powershell
$accountDiscoveryPatterns = @(
    "net user",
    "custom-enum-script.ps1",  # Add custom patterns
    "your-discovery-tool"
)
```

### Event ID Customization
Adjust Sysmon event IDs based on your configuration:

```powershell
$events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 3, 11, 12, 22) -StartTime $Script:LastEventTime
```

## Future Enhancements
- Machine learning-based anomaly detection
- Behavioral analysis for discovery patterns
- Integration with threat intelligence feeds
- Advanced correlation across multiple techniques
- Export capabilities (JSON, CSV, SIEM formats)

## Support
For issues or questions:
1. Check Sysmon installation status
2. Verify PowerShell version compatibility (3.0+)
3. Review Event Viewer for related errors
4. Check log files for detailed error messages
5. Ensure proper administrator privileges
