# Impact Tactics Detection - README

## Overview
The `Impact.ps1` script is designed to monitor and log Impact tactics (MITRE ATT&CK Tactic TA0040) in OT (Operational Technology) environments. This script detects destructive and disruptive techniques that adversaries use to manipulate, interrupt, or destroy systems and data.

## Features
- **Real-time monitoring** of Impact techniques using Sysmon and Windows Event Logs
- **OT-specific detection** tailored for industrial control systems
- **Comprehensive coverage** of 15 Impact sub-techniques
- **Windows Server 2012 compatible** with PowerShell 3.0+
- **Continuous logging** with configurable refresh intervals
- **Critical system protection** with OT process/service awareness

## Supported Impact Techniques

### Account Access Removal (T1531)
- Monitors user account deletions
- Tracks security group modifications
- Detects privilege removal activities

### Data Destruction (T1485)
- Detects destructive file operations
- Monitors OT-specific data files (.his, .cfg, .prn, .bak)
- Identifies mass deletion patterns

### Data Encrypted for Impact (T1486)
- Identifies encryption tools and ransomware
- Monitors for ransom note creation
- Detects suspicious file encryption patterns

### Data Manipulation (T1565)
- Monitors OT configuration file changes
- Detects database manipulation
- Tracks runtime data modification

### Defacement (T1491)
- Monitors web file modifications
- Detects HMI interface tampering
- Tracks visual system alterations

### Disk Wipe (T1561)
- Identifies disk wiping tools
- Monitors boot sector manipulation
- Detects partition destruction

### Email Bombing (T1499.003)
- Monitors suspicious SMTP connections
- Detects bulk email activities
- Identifies email flooding patterns

### Endpoint Denial of Service (T1499.004)
- Detects resource exhaustion commands
- Monitors OT system targeting
- Identifies process flooding

### Financial Theft (T1657)
- Monitors financial application activity
- Detects payment system access
- Tracks financial data manipulation

### Firmware Corruption (T1495)
- Identifies firmware manipulation tools
- Monitors BIOS/UEFI modifications
- Detects firmware file changes

### Inhibit System Recovery (T1490)
- Monitors backup deletion commands
- Detects shadow copy removal
- Tracks recovery system disabling

### Network Denial of Service (T1498)
- Identifies network flooding tools
- Monitors DDoS activities
- Detects reflection attacks

### Resource Hijacking (T1496)
- Detects cryptocurrency mining
- Monitors resource consumption
- Identifies unauthorized computing usage

### Service Stop (T1489)
- Monitors critical service stops
- Detects OT service disruption
- Tracks security service disabling

### System Shutdown/Reboot (T1529)
- Monitors system shutdown events
- Detects unexpected restarts
- Tracks forced system interruption

## OT-Specific Features

### Critical Process Monitoring
The script includes awareness of common OT processes:
- HMI applications (WinCC, iFIX, InTouch, Citect)
- SCADA systems (FactoryTalk, Historian)
- Communication services (OPC, Modbus, RSLinx)
- Data historians and databases

### Critical Service Protection
Monitors essential OT services:
- HMI and SCADA services
- PLC communication services
- OPC servers and data historians
- Industrial protocol handlers

### OT File Type Awareness
Enhanced detection for industrial file types:
- Configuration files (.cfg, .prn, .ini)
- Historical data files (.his)
- Database files (.mdb, .db)
- HMI graphics (.hmi, .scr, .gfx)

## Usage

### Basic Usage
```powershell
.\Impact.ps1
```

### Custom Configuration
```powershell
.\Impact.ps1 -OutputPath "C:\Logs\Impact" -LogLevel "Critical" -RefreshInterval 15
```

### Continuous Monitoring
```powershell
.\Impact.ps1 -MonitorDuration 0 -RefreshInterval 30
```

### Timed Monitoring
```powershell
.\Impact.ps1 -MonitorDuration 480 -LogLevel "Warning"
```

## Parameters

| Parameter | Description | Default | Values |
|-----------|-------------|---------|--------|
| OutputPath | Directory for log files | `$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS` | Any valid path |
| LogLevel | Minimum log level to display | Info | Info, Warning, Critical |
| MonitorDuration | Monitoring duration in minutes (0 = continuous) | 0 | Any integer |
| RefreshInterval | Check interval in seconds | 30 | Any integer |

## Prerequisites

### Required
- Windows PowerShell 3.0 or later
- Administrator privileges
- Windows Event Log access

### Recommended
- Sysmon installed and running
- Enhanced logging configuration
- Sufficient disk space for logs

## Installation

1. **Copy the script** to your CUSTOM_LOGGERS directory
2. **Run as Administrator** to ensure proper event access
3. **Install Sysmon** for enhanced detection (optional but recommended)

```powershell
# Install Sysmon (if not already installed)
.\Setup-SysmonPipeline.ps1

# Run Impact monitoring
.\Impact.ps1
```

## Log Format

Each log entry includes:
- **Timestamp**: Precise event timing
- **Log Level**: INFO, WARNING, or CRITICAL
- **Event Description**: Human-readable description
- **Event ID**: Windows/Sysmon event identifier
- **Process Information**: Process name, PID, user
- **Technique Mapping**: MITRE ATT&CK technique ID
- **Additional Context**: Command lines, file paths, network details

### Example Log Entry
```
[2025-08-10 14:30:22] [CRITICAL] System shutdown/restart initiated | EventID: 1074 | Process: shutdown.exe | Technique: T1529 - System Shutdown/Reboot | Additional: Reason: System reboot required
```

## Output Files

### Log File Naming
- Format: `Impact_YYYYMMDD_HHMMSS.log`
- Location: Specified OutputPath
- Example: `Impact_20250810_143022.log`

### Summary Statistics
- Total techniques detected
- Event counts by technique
- Monitoring duration
- Detection effectiveness metrics

## Integration

### With Other Scripts
The Impact script integrates with other MITRE ATT&CK detection scripts:
- Run alongside DefenseEvasion.ps1, CredentialAccess.ps1, etc.
- Shared logging architecture for consistent output
- Compatible event filtering and parsing

### With SIEM Systems
- Structured log format for easy parsing
- JSON-compatible field separation
- Standardized technique mapping
- Event correlation support

## Troubleshooting

### Common Issues
1. **No events detected**: Check Sysmon installation and Windows Event Log service
2. **Permission errors**: Ensure script runs as Administrator
3. **High CPU usage**: Increase RefreshInterval for large environments
4. **Missing log entries**: Verify OutputPath permissions and disk space

### Performance Tuning
- Adjust RefreshInterval based on environment size
- Filter by LogLevel to reduce noise
- Use timed monitoring for scheduled assessments
- Monitor system resources during extended runs

## Security Considerations

### OT Environment Safety
- **Read-only monitoring**: Script does not modify systems
- **Minimal network impact**: Uses local event logs only
- **Process isolation**: No interference with critical OT processes
- **Emergency stop**: Ctrl+C for immediate termination

### Data Protection
- Logs may contain sensitive system information
- Secure log storage location recommended
- Regular log rotation to prevent disk exhaustion
- Access control for log files

## Support and Updates

For issues, enhancements, or questions:
- Check existing documentation
- Review Windows Event Log configuration
- Verify Sysmon installation and configuration
- Test with known Impact technique simulations

## Version History

- **v1.0** - Initial release with comprehensive Impact technique coverage
- OT-specific enhancements for industrial environments
- Windows Server 2012 compatibility
- Integration with existing logging architecture
