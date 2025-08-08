# Command And Control (C2) Detection Script

## Overview
This PowerShell script monitors and logs Command And Control tactics using Sysmon and Windows Event Logs. It's designed to be compatible with PowerShell 3.0+ and Windows Server 2012, following the same logging architecture as other security monitoring scripts in this project.

## MITRE ATT&CK Coverage

### Tactics Covered
- **TA0011 - Command And Control**

### Techniques Monitored

| Technique ID | Technique Name | Sub-techniques |
|--------------|----------------|----------------|
| T1071 | Application Layer Protocol | T1071.001 (Web Protocols), T1071.002 (File Transfer Protocols), T1071.003 (Mail Protocols), T1071.004 (DNS) |
| T1092 | Communication Through Removable Media | - |
| T1132 | Data Encoding | T1132.001 (Standard Encoding), T1132.002 (Non-Standard Encoding) |
| T1001 | Data Obfuscation | T1001.001 (Junk Data), T1001.002 (Steganography), T1001.003 (Protocol Impersonation) |
| T1568 | Dynamic Resolution | T1568.001 (Fast Flux DNS), T1568.002 (Domain Generation Algorithms), T1568.003 (DNS over HTTPS) |
| T1573 | Encrypted Channel | T1573.001 (Symmetric Cryptography), T1573.002 (Asymmetric Cryptography) |
| T1568 | Fallback Channels | - |
| T1564 | Hide Infrastructure | - |
| T1105 | Ingress Tool Transfer | - |
| T1104 | Multi-Stage Channels | - |
| T1095 | Non-Application Layer Protocol | - |
| T1571 | Non-Standard Port | - |
| T1572 | Protocol Tunneling | - |
| T1090 | Proxy | T1090.001 (Internal Proxy), T1090.002 (External Proxy), T1090.003 (Multi-hop Proxy), T1090.004 (Domain Fronting) |
| T1219 | Remote Access Tools | - |
| T1205 | Traffic Signaling | T1205.001 (Port Knocking), T1205.002 (Socket Filters) |
| T1102 | Web Service | T1102.001 (Dead Drop Resolver), T1102.002 (Bidirectional Communication) |

## Features

### Detection Capabilities
- **Application Layer Protocol Monitoring**: Detects suspicious use of HTTP/HTTPS, DNS, FTP, and mail protocols by non-standard processes
- **DNS Tunneling Detection**: Identifies potential DNS exfiltration through unusual query patterns
- **Removable Media Communication**: Monitors file operations on removable drives
- **Data Encoding Detection**: Identifies base64 and other encoding/decoding operations
- **Steganography Detection**: Monitors for suspicious media file operations
- **Dynamic DNS Resolution**: Detects Domain Generation Algorithms and Fast Flux DNS
- **Encrypted Channel Monitoring**: Identifies non-standard encrypted communications
- **Protocol Tunneling**: Detects SSH tunneling, DNS tunneling, and other tunneling tools
- **Proxy Usage**: Monitors proxy configurations and anonymization tools
- **Remote Access Tools**: Identifies legitimate and illegitimate RAT usage
- **Traffic Signaling**: Detects port knocking and other signaling techniques
- **Web Service C2**: Monitors connections to common web services used for C2
- **Tool Transfer**: Detects ingress of tools and executables

### Logging Architecture
- **Real-time Monitoring**: Continuous event processing with configurable refresh intervals
- **Structured Logging**: Consistent log format with technique attribution
- **Event Correlation**: Links events to specific MITRE ATT&CK techniques
- **Summary Reporting**: Provides monitoring summaries with detection counts
- **Error Handling**: Robust error handling for enterprise environments

## Prerequisites

### Required Services
- **Sysmon**: Required for advanced process, network, and file monitoring
  - Events used: 1 (Process Creation), 3 (Network Connection), 11 (File Created), 13 (Registry Value Set), 22 (DNS Query), 23 (File Deleted)
- **Windows Event Log**: Used for security events and system monitoring
- **PowerShell 3.0+**: Compatible with Windows Server 2012 and later

### Required Permissions
- **Administrator Rights**: Required for accessing security logs and Sysmon events
- **Log Access**: Read access to Windows Security and Sysmon operational logs
- **File System**: Write access to output directory

## Usage

### Basic Usage
```powershell
# Run with default settings (continuous monitoring)
.\CommandAndControl.ps1

# Run for 60 minutes with 15-second refresh interval
.\CommandAndControl.ps1 -MonitorDuration 60 -RefreshInterval 15

# Run with custom output path and log level
.\CommandAndControl.ps1 -OutputPath "C:\Security\Logs" -LogLevel "Warning"
```

### Parameters
- **OutputPath**: Directory where log files will be stored (default: `$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS`)
- **LogLevel**: Minimum log level to display - `Info`, `Warning`, `Critical` (default: `Info`)
- **MonitorDuration**: Duration in minutes to monitor; 0 = continuous (default: `0`)
- **RefreshInterval**: Seconds between monitoring checks (default: `30`)

### Example Commands
```powershell
# Continuous monitoring with warnings only
.\CommandAndControl.ps1 -LogLevel "Warning"

# 2-hour monitoring session with detailed logging
.\CommandAndControl.ps1 -MonitorDuration 120 -RefreshInterval 10

# Custom output location for centralized logging
.\CommandAndControl.ps1 -OutputPath "\\LogServer\SecurityLogs\C2Detection"
```

## Output Format

### Log File Structure
```
=== Command And Control Logger Started ===
Start Time: 2025-01-15 14:30:25
PowerShell Version: 5.1.17763.1
OS: Microsoft Windows Server 2016 Standard
Log File: C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\CommandAndControl_20250115_143025.log
=======================================

[2025-01-15 14:30:26] [WARNING] Non-browser process using web protocol | EventID: 3 | Process: C:\Windows\System32\powershell.exe | DestPort: 443 | TargetIP: 192.168.1.100 | Technique: T1071.001 - Web Protocols (HTTPS)
[2025-01-15 14:30:28] [CRITICAL] DNS tunneling tool detected | EventID: 1 | Process: C:\Tools\dnscat2.exe | CommandLine: dnscat2 -c example.com | Technique: T1572 - Protocol Tunneling
```

### Detection Categories
- **CRITICAL**: High-confidence malicious activity (tunneling tools, known C2 infrastructure)
- **WARNING**: Suspicious activity requiring investigation (unusual protocols, non-standard behavior)
- **INFO**: Informational events for baseline understanding (standard ports, legitimate tools)

## Integration

### SIEM Integration
The script outputs structured logs suitable for ingestion by:
- **Splunk**: Parse timestamp and technique fields for correlation
- **ELK Stack**: JSON-compatible field extraction
- **Microsoft Sentinel**: KQL queries for advanced analytics
- **IBM QRadar**: DSM compatibility for event parsing

### Automation Integration
- **Task Scheduler**: Run as scheduled task for continuous monitoring
- **PowerShell Jobs**: Background execution with `Start-Job`
- **Windows Services**: Convert to service using NSSM or similar tools

## Tuning and Customization

### False Positive Reduction
1. **Process Whitelisting**: Modify detection functions to exclude legitimate processes
2. **Time-based Filtering**: Ignore events during maintenance windows
3. **Network Segmentation**: Focus on specific network ranges or exclude trusted subnets

### Detection Enhancement
1. **Custom Indicators**: Add organization-specific indicators to detection logic
2. **Threat Intelligence**: Integrate IOCs from threat feeds
3. **Behavioral Baselines**: Establish normal communication patterns for comparison

### Performance Optimization
1. **Event Filtering**: Adjust Sysmon configuration to reduce noise
2. **Batch Processing**: Increase refresh intervals for high-volume environments
3. **Log Rotation**: Implement log archival to manage disk usage

## Monitoring Best Practices

### Deployment Strategy
1. **Pilot Testing**: Deploy in test environment first
2. **Gradual Rollout**: Start with critical systems before full deployment
3. **Baseline Establishment**: Run for 1-2 weeks to establish normal patterns

### Operational Considerations
1. **Resource Monitoring**: Monitor CPU and memory usage during operation
2. **Log Management**: Implement log rotation and archival policies
3. **Alert Tuning**: Adjust detection thresholds based on environment noise

### Response Procedures
1. **Escalation Matrix**: Define response procedures for different alert levels
2. **Investigation Playbooks**: Create standardized investigation procedures
3. **Documentation**: Maintain incident response documentation

## Troubleshooting

### Common Issues
1. **Sysmon Not Found**: Ensure Sysmon is installed and running
2. **Permission Denied**: Verify script runs with administrator privileges
3. **High False Positives**: Review and tune detection logic for environment
4. **Performance Issues**: Adjust refresh intervals and event filtering

### Debugging
1. Enable verbose logging by setting `$LogLevel = "Info"`
2. Check Windows Event Viewer for Sysmon events
3. Verify network connectivity and DNS resolution
4. Review PowerShell execution policies

## Version History
- **v1.0**: Initial release with comprehensive C2 detection capabilities
- Supports PowerShell 3.0+ and Windows Server 2012 compatibility
- Implements 14 MITRE ATT&CK techniques across Command And Control tactics

## Related Scripts
This script is part of a comprehensive security monitoring suite:
- `DefenseEvasion.ps1`: Defense evasion technique monitoring
- `CredentialAccess.ps1`: Credential theft and access monitoring
- `LateralMovement.ps1`: Network lateral movement detection
- `Persistence.ps1`: Persistence mechanism detection
- `Discovery.ps1`: Reconnaissance and discovery activity monitoring

## Support and Maintenance
- Regular updates to include new C2 techniques and IOCs
- Community contributions welcome for additional detection logic
- Integration with threat intelligence feeds for enhanced detection
