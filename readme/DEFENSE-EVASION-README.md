# Defense Evasion Live Monitor

## Overview
The Defense Evasion Live Monitor is a Windows Server 2012+ compatible PowerShell script that provides real-time monitoring and logging of Defense Evasion techniques based on the MITRE ATT&CK framework.

## Features
- **Real-time monitoring** with live status updates
- **Windows Server 2012 compatible** (PowerShell 3.0+)
- **Sysmon integration** for enhanced detection capabilities
- **Live dashboard** showing monitoring status and statistics
- **Comprehensive logging** with structured output
- **MITRE ATT&CK mapping** for all detected techniques

## Monitored Techniques

### T1134 - Access Token Manipulation
- Token impersonation and theft detection
- Privilege escalation monitoring
- Sensitive privilege assignments

### T1055 - Process Injection
- Cross-process thread creation
- Suspicious process access patterns
- Memory manipulation detection

### T1036 - Masquerading
- System binary impersonation
- Suspicious file locations
- Process name spoofing

### T1112 - Modify Registry
- Critical registry key modifications
- Persistence mechanism detection
- Security setting changes

### T1218 - System Binary Proxy Execution
- Living-off-the-land binary abuse
- Script execution via system tools
- Command line analysis

### T1564 - Hide Artifacts
- Hidden files and directories
- NTFS alternate data streams
- Registry hiding techniques

### T1562 - Impair Defenses
- Security tool tampering
- Event log manipulation
- Antivirus bypass attempts

### T1027 - Obfuscated Files or Information
- Encoded command detection
- Suspicious file patterns
- Payload obfuscation

### T1070 - Indicator Removal
- Log clearing activities
- File deletion monitoring
- Evidence destruction

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
.\DefenseEvasion.ps1

# Monitor for specific duration (60 minutes)
.\DefenseEvasion.ps1 -MonitorDuration 60

# Custom refresh interval (15 seconds)
.\DefenseEvasion.ps1 -RefreshInterval 15
```

### Advanced Usage
```powershell
# Custom output path and settings
.\DefenseEvasion.ps1 -OutputPath "C:\MyLogs" -LogLevel "Warning" -MonitorDuration 120

# High-frequency monitoring
.\DefenseEvasion.ps1 -RefreshInterval 10 -LogLevel "Info"
```

### Parameters
- **OutputPath**: Directory for log files (default: CUSTOM_LOGGERS folder)
- **LogLevel**: Minimum log level (Info, Warning, Critical)
- **MonitorDuration**: Minutes to monitor (0 = continuous)
- **RefreshInterval**: Seconds between checks (default: 30)

## Output Files
- **DefenseEvasion_YYYYMMDD_HHMMSS.log**: Main detection log
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
[YYYY-MM-DD HH:MM:SS] [LEVEL] Message | EventID: XXX | Process: process.exe | CommandLine: command | Technique: TXXXX.XXX - Name
```

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
- Logs may contain sensitive command line information
- Ensure log file permissions are properly configured
- Monitor log file size for long-running sessions
- Consider log rotation for continuous monitoring

## Integration with Other Scripts
This script is designed to work alongside other Custom Security Logger scripts:
- Uses same logging format and directory structure
- Compatible with existing Sysmon configuration
- Can run simultaneously with other monitors

## Support
For issues or questions:
1. Check Sysmon installation status
2. Verify PowerShell version compatibility
3. Review Event Viewer for related errors
4. Check log files for detailed error messages
