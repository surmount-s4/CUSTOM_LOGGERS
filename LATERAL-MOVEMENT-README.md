# Lateral Movement Monitor Documentation

## Overview
The Lateral Movement monitor (`LateralMovement.ps1`) is designed to detect and log lateral movement techniques used by attackers to move through a network after initial compromise. This monitor is fully compatible with Windows Server 2012 and your existing Sysmon configuration.

## Supported Techniques

### T1210 - Exploitation of Remote Services
**Description**: Detects attempts to exploit remote services for lateral movement
**Detection Methods**:
- Monitors for remote exploitation tools (psexec, wmiexec, smbexec, etc.)
- Tracks network connections to administrative ports (135, 445, 5985, 5986, 3389)
- Identifies suspicious remote service interaction patterns

### T1534 - Internal Spearphishing  
**Description**: Detects internal phishing campaigns used for lateral movement
**Detection Methods**:
- Monitors email client activities with embedding parameters
- Tracks suspicious attachment creation in temporary directories
- Identifies internal email relay activities

### T1570 - Lateral Tool Transfer
**Description**: Detects tools being transferred between systems for lateral movement
**Detection Methods**:
- Monitors file transfer commands (copy, xcopy, robocopy, scp, sftp)
- Tracks network connections to file transfer ports (20, 21, 22, 80, 443)
- Identifies files created in administrative shares (admin$, c$, SYSVOL, NETLOGON)
- Detects download utilities (certutil, bitsadmin, curl, wget)

### T1563 - Remote Service Session Hijacking
**Sub-techniques**:
- **T1563.001 - SSH Hijacking**: Detects SSH session hijacking attempts
- **T1563.002 - RDP Hijacking**: Monitors RDP session reconnections

**Detection Methods**:
- Tracks RDP session events (4778, 4779)
- Monitors SSH ControlMaster and agent hijacking patterns
- Identifies unusual session reconnection activities

### T1021 - Remote Services
**Sub-techniques**:
- **T1021.001 - Remote Desktop Protocol**: RDP logon monitoring
- **T1021.002 - SMB/Windows Admin Shares**: SMB and admin share usage
- **T1021.003 - Distributed Component Object Model**: DCOM usage patterns  
- **T1021.004 - SSH**: SSH client execution and connections
- **T1021.006 - Windows Remote Management**: WinRM activity detection

**Detection Methods**:
- Security event log analysis for logon types
- Network connection monitoring for service ports
- Command line analysis for remote service tools

### T1091 - Replication Through Removable Media
**Description**: Detects malware spreading via removable media
**Detection Methods**:
- Monitors executable file creation on removable drives
- Detects autorun.inf and autoplay.inf file creation
- Tracks suspicious file types on external media

### T1072 - Software Deployment Tools
**Description**: Detects abuse of legitimate deployment tools
**Detection Methods**:
- Monitors deployment tool execution (psexec, ansible, puppet, chef)
- Tracks software installation commands (msiexec, Install-Package)
- Identifies configuration management tool abuse

### T1080 - Taint Shared Content
**Description**: Detects modification of shared content to deliver payloads
**Detection Methods**:
- Monitors file creation in shared folders (SYSVOL, NETLOGON, Public)
- Detects timestamp modifications in shared locations
- Tracks suspicious file types in common shared directories

### T1550 - Use Alternate Authentication Material
**Sub-techniques**:
- **T1550.001 - Application Access Token**: Certificate-based authentication
- **T1550.002 - Pass the Hash**: NTLM hash reuse detection
- **T1550.003 - Pass the Ticket**: Kerberos ticket reuse

**Detection Methods**:
- Analyzes unusual logon patterns (LogonType 9)
- Monitors credential theft tool execution (mimikatz, rubeus, kerberoast)
- Detects suspicious LSASS process access
- Tracks Kerberos ticket anomalies

## Event Sources

### Sysmon Events Used
- **Event ID 1**: Process Creation - Command line analysis
- **Event ID 2**: File Creation Time Changed - Timestomping detection
- **Event ID 3**: Network Connection - Lateral movement connections
- **Event ID 10**: Process Access - Credential theft detection
- **Event ID 11**: File Create - Malicious file placement
- **Event ID 12-14**: Registry Events - Persistence mechanisms

### Windows Security Events Used
- **Event ID 4624/4625**: Logon Events - Authentication monitoring
- **Event ID 4778/4779**: RDP Session Events - Session hijacking
- **Event ID 4768/4769**: Kerberos Events - Ticket analysis

### Windows Operational Logs
- **Microsoft-Windows-WinRM/Operational**: WinRM activity detection

## Configuration Requirements

### Sysmon Configuration
Your comprehensive Sysmon configuration (`sysmon-config-comprehensive.xml`) is fully compatible:
- ✅ Schema version 4.82 (Sysmon v13+)
- ✅ All required Event IDs are configured
- ✅ Windows Server 2012 compatibility confirmed

### Required Permissions
- **Administrator privileges** (script uses `#Requires -RunAsAdministrator`)
- **Event log read access** for Security and Sysmon logs
- **Network access** for connection monitoring

## Usage

### Basic Usage
```powershell
# Start continuous monitoring
.\LateralMovement.ps1

# Monitor for 60 minutes with custom path
.\LateralMovement.ps1 -MonitorDuration 60 -OutputPath "C:\CustomLogs"

# High verbosity monitoring
.\LateralMovement.ps1 -LogLevel "Info" -RefreshInterval 15
```

### Parameters
- **`-OutputPath`**: Directory for log files (default: `$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS`)
- **`-LogLevel`**: Logging verbosity - Info, Warning, Critical (default: Info)
- **`-MonitorDuration`**: Minutes to monitor (0 = continuous)
- **`-RefreshInterval`**: Seconds between checks (default: 30)

### Testing
Use the provided test script to validate detection:
```powershell
.\Test-LateralMovementDetection.ps1
```

## Log Format

### Sample Log Entry
```
[2025-08-07 14:30:45] [CRITICAL] Remote service exploitation tool detected | EventID: 1 | Process: cmd.exe | PID: 1234 | User: DOMAIN\user | CommandLine: psexec.exe \\target -s cmd.exe | Technique: T1210 - Exploitation of Remote Services
```

### Log Fields
- **Timestamp**: yyyy-MM-dd HH:mm:ss format
- **Level**: INFO, WARNING, CRITICAL
- **Message**: Human-readable detection description
- **EventID**: Source event ID from logs
- **Process**: Process name and path
- **PID**: Process identifier
- **User**: Associated user account
- **CommandLine**: Full command line (when available)
- **Technique**: MITRE ATT&CK technique identifier
- **Additional**: Context-specific information

## Integration

### SIEM Integration
The monitor outputs structured logs suitable for SIEM ingestion:
- Consistent timestamp format
- Technique tagging for correlation
- Severity levels for alerting
- Rich context for investigation

### Alerting Recommendations
- **CRITICAL**: Immediate investigation required
  - Credential theft tools
  - LSASS access
  - Admin share file placement
- **WARNING**: Potential lateral movement
  - Remote service connections
  - Tool transfer activities
  - Session hijacking attempts
- **INFO**: Baseline monitoring
  - Normal remote service usage
  - Legitimate file transfers

## Performance Considerations

### Windows Server 2012 Optimization
- PowerShell 3.0 compatible syntax
- Efficient event filtering with hashtables
- Error handling for missing cmdlets
- Memory-conscious event processing

### Monitoring Impact
- **CPU Usage**: Low (event-driven processing)
- **Memory Usage**: Moderate (event buffering)
- **Disk I/O**: Low (efficient log writing)
- **Network Impact**: None (local monitoring only)

## Troubleshooting

### Common Issues
1. **No events detected**: Verify Sysmon is running and configured
2. **Permission errors**: Ensure script runs as Administrator
3. **High CPU usage**: Increase RefreshInterval parameter
4. **Missing events**: Check Windows Event Log service status

### Verification Commands
```powershell
# Check Sysmon status
Get-Service | Where-Object {$_.Name -like "Sysmon*"}

# Verify event logs
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"

# Test permissions
Get-WinEvent -LogName Security -MaxEvents 1
```

## Compatibility Matrix

| Component | Requirement | Status |
|-----------|-------------|---------|
| Windows Server 2012 | PowerShell 3.0+ | ✅ Compatible |
| Sysmon v13+ | Schema 4.82 | ✅ Compatible |
| Event Log Access | Administrator | ✅ Required |
| .NET Framework | 4.0+ | ✅ Compatible |

## Security Considerations

### Detection Evasion
- Monitor uses native Windows capabilities (harder to detect)
- No network footprint (local monitoring only)
- Minimal system impact (event-driven)

### False Positives
- Legitimate administrative tools may trigger alerts
- Normal remote access patterns are documented
- Thresholds can be adjusted via parameters

## Support and Maintenance

### Regular Maintenance
- Review log files weekly for disk space
- Update technique patterns as threats evolve
- Validate detection coverage monthly with test script

### Updates
- Monitor Microsoft security bulletins for new techniques
- Update Sysmon configuration as needed
- Correlate with threat intelligence feeds
