# Exfiltration Detection Script

## Overview
The `Exfiltration.ps1` script is designed to monitor and detect data exfiltration techniques in OT (Operational Technology) environments. It follows the same logging architecture as other detection scripts in this suite, providing comprehensive monitoring for MITRE ATT&CK Exfiltration tactics.

## MITRE ATT&CK Techniques Covered

### T1020 - Automated Exfiltration
**Detection Capabilities:**
- **Data Transfer Size Limits**: Monitors for automated data collection and transfer tools
- **Scheduled Tasks**: Detects tasks that may be used for automated data exfiltration
- **Script-based Automation**: Identifies PowerShell, CMD, and other scripts performing automated transfers
- **Network Automation**: Monitors external connections from automation tools

**Detection Methods:**
- Sysmon Event ID 1 (Process Creation) - Automation tools and scripts
- Sysmon Event ID 3 (Network Connections) - External connections from scripts
- Sysmon Event ID 11 (File Creation) - Data staging operations
- Task Scheduler Events (106, 200, 201) - Scheduled data transfer tasks

### T1048 - Exfiltration Over Alternative Protocol
**Detection Capabilities:**
- **DNS Tunneling (T1048.004)**: Detects suspicious DNS queries and potential tunneling
- **Non-HTTP Protocols**: Monitors HTTPS, IMAPS, SMTP TLS, SSH/SCP, FTP, FTPS connections
- **OT Protocol Abuse (T1048.003)**: Detects external connections on OT protocol ports
- **Protocol Analysis**: Identifies legitimate vs suspicious protocol usage

**Detection Methods:**
- Sysmon Event ID 3 (Network Connections) - Alternative protocol usage
- Sysmon Event ID 22 (DNS Queries) - DNS tunneling patterns
- Port analysis for OT protocols (502, 44818, 102, 2404, etc.)
- Process legitimacy checks for protocol usage

### T1041 - Exfiltration Over C2 Channel
**Detection Capabilities:**
- **Command & Control Communication**: Detects C2 tools and patterns
- **Data Exfiltration via C2**: Monitors data transfer over established C2 channels
- **Suspicious Process Connections**: Identifies non-legitimate processes making external connections

**Detection Methods:**
- Sysmon Event ID 1 (Process Creation) - C2 communication tools
- Sysmon Event ID 3 (Network Connections) - C2 network patterns
- Command-line analysis for C2 patterns (PowerShell, CURL, CertUtil, etc.)
- Network connection analysis from suspicious processes

### T1052 - Exfiltration Over Physical Medium
**Detection Capabilities:**
- **USB Exfiltration (T1052.001)**: Monitors file operations on removable media
- **OT File Protection**: Special monitoring for OT-related file extensions
- **Device Activity**: Tracks USB device insertion and activity

**Detection Methods:**
- Sysmon Event ID 11 (File Creation) - Files written to removable media
- System Events (20001, 20003, 4001) - USB device activity
- WMI Drive Type Analysis - Identification of removable drives
- OT file extension monitoring (.plc, .hmi, .scada, .cfg, etc.)

### T1567 - Exfiltration Over Web Service
**Detection Capabilities:**
- **Cloud Service Detection**: Monitors connections to major cloud platforms
- **Non-Browser Connections**: Identifies suspicious non-browser cloud access
- **Multi-Service Coverage**: Supports 13+ major cloud services

**Supported Services:**
- Dropbox, Google Drive, OneDrive, Box, AWS S3, Azure Blob
- iCloud, Mega, GitHub, Pastebin, Discord, Telegram, WeTransfer

**Detection Methods:**
- Sysmon Event ID 3 (Network Connections) - Cloud service connections
- Sysmon Event ID 22 (DNS Queries) - Cloud service domain queries
- Process analysis - Browser vs non-browser connections
- Hostname pattern matching for cloud services

### T1029 - Scheduled Transfer
**Detection Capabilities:**
- **Task Scheduler Monitoring**: Detects scheduled data transfer tasks
- **Command Scheduling**: Monitors AT and SCHTASKS commands
- **Transfer Tool Integration**: Identifies scheduled robocopy, xcopy, curl, wget operations

**Detection Methods:**
- Task Scheduler Events (106, 200, 201, 140, 141) - Task registration and execution
- Sysmon Event ID 1 (Process Creation) - Scheduling commands
- Pattern matching for data transfer task names and actions
- Command-line analysis for scheduling transfers

## OT Environment Optimizations

### File Type Monitoring
The script includes comprehensive monitoring for OT-specific file extensions:
- `.plc`, `.hmi`, `.scada`, `.cfg`, `.config`, `.ini`, `.xml`, `.json`
- `.csv`, `.log`, `.db`, `.sqlite`, `.mdb`, `.accdb`, `.xls`, `.xlsx`
- `.txt`, `.dat`, `.backup`, `.bak`, `.his`, `.trend`, `.alarm`, `.event`
- `.recipe`, `.program`, `.ladder`, `.st`, `.fbd`

### OT Path Monitoring
Monitors critical OT directories:
- HMI, SCADA, PLC, Historian, OPC directories
- Wonderware, RSLogix, TIA Portal application paths
- Program Files and ProgramData OT installations

### OT Protocol Monitoring
Monitors common OT network ports:
- Modbus TCP (502), OPC UA (4840), IEC 61850 (102)
- EtherNet/IP (44818, 2222), DNP3 (20000)
- And other common industrial protocols

## Usage

### Basic Usage
```powershell
# Run with default settings
.\Exfiltration.ps1

# Specify custom output path
.\Exfiltration.ps1 -OutputPath "C:\Security\Logs"

# Run for specific duration
.\Exfiltration.ps1 -MonitorDuration 60

# Adjust refresh interval
.\Exfiltration.ps1 -RefreshInterval 10
```

### Parameters
- **OutputPath**: Directory for log files (default: `$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS`)
- **LogLevel**: Logging level - Info, Warning, Critical (default: Info)
- **MonitorDuration**: Minutes to monitor, 0 = continuous (default: 0)
- **RefreshInterval**: Seconds between checks (default: 30)

## Prerequisites

### Required
- Windows PowerShell 3.0+ (Windows Server 2012 compatible)
- Administrator privileges
- Windows Event Logs access

### Recommended
- Sysmon installed and running (enhances detection capabilities)
- Network monitoring enabled
- USB device audit policies enabled

## Log Output

### Log Format
Each detection event includes:
- Timestamp, Log Level, Message
- Event ID, Process Name, Process ID, User
- Command Line, Target Filename, Network details
- MITRE ATT&CK Technique mapping
- Additional contextual fields

### Sample Log Entry
```
[2024-08-10 14:30:15] [WARNING] External connection from suspicious process - potential C2 communication | EventID: 3 | Process: powershell.exe | PID: 1234 | User: DOMAIN\user | TargetIP: 203.0.113.100 | Protocol: TCP | Additional: Port:443 | Technique: T1041 - Exfiltration Over C2 Channel
```

## Integration

### With Existing Scripts
- Uses same logging architecture as DefenseEvasion.ps1 and CredentialAccess.ps1
- Compatible with existing Sysmon configuration
- Consistent event counter and summary reporting

### SIEM Integration
- Structured logging format suitable for SIEM ingestion
- MITRE ATT&CK technique tagging for threat hunting
- Severity levels for alert prioritization

## Monitoring Status

The script provides real-time status updates including:
- Monitoring uptime
- Total detections by technique
- Active monitoring techniques
- Last check timestamp

## False Positive Reduction

### Built-in Filters
- Legitimate process identification for cloud services
- Internal network exclusions
- System process filtering
- OT-specific context awareness

### Tuning Recommendations
- Whitelist known legitimate cloud usage
- Adjust OT file path monitoring for environment
- Configure network exclusions for trusted internal transfers
- Customize USB monitoring based on policy requirements

## Troubleshooting

### Common Issues
1. **Sysmon Not Detected**: Install Sysmon using Setup-SysmonPipeline.ps1
2. **Limited Detections**: Verify event log access and Sysmon configuration
3. **High False Positives**: Review legitimate process patterns and adjust filters
4. **Missing OT Files**: Customize OT file extensions and paths for your environment

### Performance Considerations
- Default 30-second refresh interval balances detection speed and system impact
- Event filtering reduces log volume while maintaining detection capability
- Background monitoring mode available for continuous operation

## Version History
- v1.0: Initial release with comprehensive exfiltration detection for OT environments
- Compatible with Windows Server 2012+ and PowerShell 3.0+
