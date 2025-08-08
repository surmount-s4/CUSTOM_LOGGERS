# Discovery vs Defense Evasion Coverage Analysis

## Overview
This document provides a detailed comparison of the monitoring coverage between Defense Evasion and Discovery tactics, highlighting the detection approaches, event sources, and monitoring patterns.

## Coverage Summary

### Defense Evasion Techniques (9 Covered)
| Technique ID | Technique Name | Sub-Techniques | Primary Event Source | Detection Approach |
|--------------|----------------|----------------|---------------------|-------------------|
| T1134 | Access Token Manipulation | 2 | Security Logs | Privilege escalation patterns |
| T1055 | Process Injection | Multiple | Sysmon (1,8,10) | Cross-process activity |
| T1036 | Masquerading | 2 | Sysmon (1,11) | Binary name/location analysis |
| T1112 | Modify Registry | - | Sysmon (12,13,14) | Critical registry monitoring |
| T1218 | System Binary Proxy Execution | 11 | Sysmon (1) | Command line analysis |
| T1564 | Hide Artifacts | 4 | Sysmon (11,12,13) | Hidden file/registry detection |
| T1562 | Impair Defenses | 2 | Security + Sysmon | Defense tampering detection |
| T1027 | Obfuscated Files or Information | 9 | Sysmon (1,11) | Encoding/obfuscation patterns |
| T1070 | Indicator Removal | 4 | Sysmon (1,23) | Evidence destruction |

### Discovery Techniques (18+ Covered)
| Technique ID | Technique Name | Sub-Techniques | Primary Event Source | Detection Approach |
|--------------|----------------|----------------|---------------------|-------------------|
| T1087 | Account Discovery | 4 | Sysmon (1) | Account enumeration commands |
| T1010 | Application Window Discovery | - | Sysmon (1) | Process/window enumeration |
| T1217 | Browser Information Discovery | - | Sysmon (1,11) | Browser data access |
| T1083 | File and Directory Discovery | - | Sysmon (1) | File enumeration commands |
| T1046 | Network Service Discovery | - | Sysmon (1,3) | Port scanning/probing |
| T1135 | Network Share Discovery | - | Sysmon (1) | Share enumeration |
| T1057 | Process Discovery | - | Sysmon (1) | Process enumeration |
| T1012 | Query Registry | - | Sysmon (1,12) | Registry access patterns |
| T1018 | Remote System Discovery | - | Sysmon (1) | Network discovery commands |
| T1518 | Software Discovery | 1 | Sysmon (1) | Software enumeration |
| T1082 | System Information Discovery | - | Sysmon (1) | System info commands |
| T1016 | System Network Configuration Discovery | 2 | Sysmon (1) | Network config commands |
| T1049 | System Network Connections Discovery | - | Sysmon (1) | Connection enumeration |
| T1033 | System Owner/User Discovery | - | Sysmon (1) | User identification |
| T1007 | System Service Discovery | - | Sysmon (1) | Service enumeration |
| T1124 | System Time Discovery | - | Sysmon (1) | Time/date commands |
| T1201 | Password Policy Discovery | - | Sysmon (1) | Policy enumeration |
| T1069 | Permission Groups Discovery | 3 | Sysmon (1) | Group enumeration |

## Detection Architecture Comparison

### Common Foundation
Both monitors share the same architectural foundation:
- **PowerShell 3.0+ compatibility** (Windows Server 2012+)
- **Sysmon integration** with graceful degradation
- **Real-time monitoring** with configurable intervals
- **Structured logging** with MITRE ATT&CK mapping
- **Live dashboard** with statistics and counters

### Event Source Utilization

#### Defense Evasion Event Sources
```
Security Logs: 4624, 4625, 4648, 4672, 4673, 4719, 4739, 4946-4949
Sysmon Events: 1, 8, 10, 11, 12, 13, 14, 23
```

#### Discovery Event Sources
```
Security Logs: Limited usage (authentication events only)
Sysmon Events: 1, 3, 11, 12 (primarily process creation and network)
```

### Detection Approach Differences

#### Defense Evasion Patterns
- **Behavioral Analysis**: Cross-process interactions, privilege escalations
- **File System Monitoring**: Hidden files, ADS, suspicious locations
- **Registry Protection**: Critical key modifications, hiding techniques
- **Process Manipulation**: Injection, masquerading, proxy execution
- **Evidence Destruction**: Log clearing, file deletion

#### Discovery Patterns
- **Command Line Analysis**: Enumeration command detection
- **Sequential Discovery**: Patterns of reconnaissance activities
- **Information Gathering**: System, network, and user enumeration
- **File Access Patterns**: Browser data, configuration files
- **Network Reconnaissance**: Scanning, probing, service discovery

## Monitoring Effectiveness Analysis

### High-Fidelity Detection (Low False Positives)

#### Defense Evasion
- T1562 - Impair Defenses (Defense tampering)
- T1070 - Indicator Removal (Log clearing)
- T1055 - Process Injection (Cross-process activity)

#### Discovery
- T1201 - Password Policy Discovery
- T1135 - Network Share Discovery
- T1069 - Permission Groups Discovery
- T1087 - Account Discovery

### Medium-Fidelity Detection

#### Defense Evasion
- T1218 - System Binary Proxy Execution
- T1036 - Masquerading
- T1112 - Modify Registry

#### Discovery
- T1082 - System Information Discovery
- T1007 - System Service Discovery
- T1033 - System Owner/User Discovery

### Noisy Detection (Requires Context)

#### Defense Evasion
- T1564 - Hide Artifacts
- T1027 - Obfuscated Files

#### Discovery
- T1083 - File and Directory Discovery
- T1012 - Query Registry
- T1057 - Process Discovery
- T1010 - Application Window Discovery

## Event Correlation Opportunities

### Cross-Tactic Detection Patterns
1. **Discovery → Defense Evasion Sequence**
   - T1083 (File Discovery) → T1564 (Hide Artifacts)
   - T1012 (Registry Query) → T1112 (Registry Modification)
   - T1057 (Process Discovery) → T1055 (Process Injection)

2. **Shared Command Patterns**
   - PowerShell usage in both tactics
   - Registry access patterns
   - File system operations

### Enhanced Detection Logic
```powershell
# Example: Detect discovery followed by evasion
if ($DiscoveryEvents.Count -gt 5 -and $DefenseEvasionEvents.Count -gt 2) {
    Write-LogEntry "CRITICAL" "Potential attack chain detected" -Technique "Multi-Tactic Sequence"
}
```

## Technical Implementation Comparison

### Shared Functions (Identical Implementation)
- `Initialize-Logger`
- `Write-LogEntry`
- `Test-SysmonInstalled`
- `Get-EventsSafe`
- `Get-EventData`
- `Show-MonitoringStatus`
- `Generate-Summary`

### Technique-Specific Functions
- **Defense Evasion**: 9 monitoring functions focusing on evasive behaviors
- **Discovery**: 18 monitoring functions focusing on reconnaissance activities

### Configuration Compatibility
Both scripts use identical parameter sets and configuration options:
```powershell
param(
    [string]$OutputPath = "$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS",
    [ValidateSet("Info", "Warning", "Critical")]
    [string]$LogLevel = "Info",
    [int]$MonitorDuration = 0,
    [int]$RefreshInterval = 30
)
```

## Performance Characteristics

### Resource Usage Comparison

#### Defense Evasion Monitor
- **CPU Usage**: Moderate (multiple event sources)
- **Memory Usage**: Higher (complex pattern matching)
- **I/O Impact**: Higher (file system monitoring)
- **Event Volume**: Lower but more complex

#### Discovery Monitor
- **CPU Usage**: Lower (primarily command line analysis)
- **Memory Usage**: Lower (simpler pattern matching)
- **I/O Impact**: Lower (command-focused)
- **Event Volume**: Higher but simpler processing

### Scalability Considerations
- **Parallel Execution**: Both can run simultaneously
- **Resource Sharing**: Minimal conflict when co-deployed
- **Event Processing**: Independent event streams

## Detection Coverage Gaps

### Missing Defense Evasion Techniques
- T1620 - Reflective Code Loading
- T1574 - Hijack Execution Flow
- T1497 - Virtualization/Sandbox Evasion
- T1542 - Pre-OS Boot
- T1599 - Network Boundary Bridging

### Missing Discovery Techniques
- T1622 - Debugger Evasion
- T1652 - Device Driver Discovery
- T1482 - Domain Trust Discovery
- T1615 - Group Policy Discovery
- T1654 - Log Enumeration
- T1040 - Network Sniffing
- T1120 - Peripheral Device Discovery
- T1614 - System Location Discovery

## Recommendations

### Immediate Enhancements
1. **Add missing Discovery techniques** listed above
2. **Implement correlation engine** for cross-tactic detection
3. **Enhance network monitoring** for T1040 (Network Sniffing)
4. **Add WMI-based detection** for additional coverage

### Future Development
1. **Behavioral Analytics**: Pattern-based detection across time windows
2. **Machine Learning**: Anomaly detection for unusual discovery patterns
3. **Threat Intelligence**: IOC integration for known discovery tools
4. **SIEM Integration**: Export formats for centralized analysis

### Operational Guidelines
1. **Simultaneous Deployment**: Run both monitors concurrently
2. **Log Correlation**: Cross-reference events across tactic logs
3. **Alerting Rules**: Create high-priority alerts for specific combinations
4. **Regular Updates**: Update detection patterns based on new threats

## Conclusion

The Discovery monitor provides comprehensive coverage of reconnaissance techniques with 18+ monitored techniques, complementing the Defense Evasion monitor's focus on evasive behaviors. Together, they provide robust detection coverage across two critical phases of the attack lifecycle:

- **Discovery Phase**: Early warning of reconnaissance activities
- **Defense Evasion Phase**: Detection of attempts to avoid security controls

The shared architecture ensures consistent deployment, management, and analysis while maintaining technique-specific detection logic optimized for each tactic's unique characteristics.
