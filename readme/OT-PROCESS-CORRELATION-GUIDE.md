# OT Process Correlation Monitor - Implementation Guide

## Overview

The **OT-ProcessCorrelation.ps1** script is specifically designed for Operational Technology (OT) environments where industrial control systems, SCADA, HMI applications, and engineering workstations require specialized monitoring. Unlike traditional IT environments, OT systems have predictable process relationships and long-running applications that make whitelist-based monitoring highly effective.

## Why Whitelisting for OT Environments?

### Traditional IT vs OT Security Approach

**IT Environments (Blacklist Approach):**
- High process diversity and frequent changes
- Unknown applications and user-driven installations
- Focus on detecting known malicious patterns
- Acceptable false positive rates

**OT Environments (Whitelist Approach):**
- Stable, predictable application ecosystem
- Limited, well-known industrial applications
- Change control processes prevent unauthorized software
- Zero tolerance for false positives (operational disruption)

### Whitelist Benefits in OT:

1. **Reduced False Positives**: Industrial applications have predictable parent→child relationships
2. **Operational Stability**: Alerts only trigger on genuinely suspicious activity
3. **Compliance**: Meets regulatory requirements for industrial control systems
4. **Baseline Security**: Any deviation from approved processes is potentially malicious

## Sysmon Integration and Compatibility

### Compatibility with sysmon-config-comprehensive-updated.xml

The script is designed to work with your Sysmon configuration:

**✅ Compatible Event Types:**
- **Event ID 1 (Process Creation)**: Core functionality - monitors all process spawning
- **Event ID 3 (Network Connection)**: Complementary - can be extended for network correlation
- **Event ID 5 (Process Termination)**: Complementary - tracks when critical processes stop

**Configuration Alignment:**
```xml
<!--SYSMON EVENT ID 1 : PROCESS CREATION-->
<ProcessCreate onmatch="exclude">
    <!-- Minimal exclusions to capture suspicious activity -->
</ProcessCreate>
```

Your Sysmon config captures almost all process creation events, which is perfect for this script's correlation engine.

### Real-time vs Polling Comparison

| Aspect | Sysmon Integration | WMI Polling |
|--------|-------------------|-------------|
| **Detection Speed** | Real-time (immediate) | 5-second intervals |
| **Resource Usage** | Low (event-driven) | Higher (continuous polling) |
| **Data Quality** | Rich metadata | Basic process info |
| **Reliability** | High (Windows ETW) | Medium (WMI dependencies) |
| **Scalability** | Excellent | Limited |

## OT-Specific Process Monitoring

### Critical OT Processes Monitored

The script monitors 20+ categories of industrial applications:

**HMI Systems:**
- Wonderware InTouch/System Platform
- Siemens WinCC
- Rockwell FactoryTalk View
- GE iFIX
- Schneider Vijeo Citect

**Engineering Tools:**
- Rockwell Studio 5000 (RSLogix5000)
- Siemens STEP 7/TIA Portal
- Schneider Unity Pro
- ABB Control Builder

**Communication Servers:**
- KEPServerEX (PTC)
- Rockwell RSLinx
- Matrikon OPC Server

### Default Whitelist Structure

```json
{
    "rslogix5000.exe": ["rslinx.exe", "factorytalk.exe", "excel.exe", "notepad.exe"],
    "wonderware.exe": ["intouch.exe", "excel.exe", "notepad.exe", "calc.exe"],
    "wincc.exe": ["excel.exe", "notepad.exe", "calc.exe", "simatic.exe"]
}
```

**Rationale for Common Children:**
- **excel.exe**: Data export, reporting functions
- **notepad.exe**: Configuration file editing
- **calc.exe**: Engineering calculations
- **OPC clients**: Data communication

## Implementation Strategy

### Phase 1: Baseline Establishment (Weeks 1-2)
1. Deploy script in monitoring-only mode
2. Review generated whitelist violations
3. Tune whitelist based on legitimate operations
4. Establish normal behavior patterns

### Phase 2: Active Monitoring (Weeks 3-4)
1. Enable alerting for non-whitelisted relationships
2. Integrate with SIEM/alerting systems
3. Train operations team on alert response
4. Document incident response procedures

### Phase 3: Advanced Correlation (Month 2+)
1. Add network correlation capabilities
2. Implement user behavior analytics
3. Integrate with asset management systems
4. Develop custom rules for specific processes

## Alert Categories and Response

### Critical Alerts (Immediate Response Required)

**CRITICAL_OT_PROCESS_SPAWN:**
- Critical HMI/SCADA spawning unauthorized children
- Potential compromise of safety systems
- **Response**: Immediate isolation and investigation

### High Priority Alerts (Response within 1 hour)

**UNAUTHORIZED_PROCESS_SPAWN:**
- Non-critical OT process spawning unauthorized children
- Potential lateral movement or reconnaissance
- **Response**: Detailed forensic analysis

### Example Alert Structure:
```
[2025-08-10 14:30:15.123] - CRITICAL - OT_SECURITY_VIOLATION: Unauthorized process spawning detected | 
AlertType=CRITICAL_OT_PROCESS_SPAWN | 
ParentProcess=wonderware.exe | 
ChildProcess=powershell.exe | 
ParentPID=1234 | 
ChildPID=5678 | 
User=OT\operator | 
CommandLine=powershell.exe -EncodedCommand [...] | 
Environment=OT | 
Severity=CRITICAL
```

## Maintenance and Tuning

### Regular Tasks:

1. **Monthly Whitelist Review**: Validate all entries are still relevant
2. **Quarterly Process Audit**: Review new applications and update whitelist
3. **Annual Security Assessment**: Full review of OT process relationships
4. **Change Management**: Update whitelist during planned system changes

### Performance Monitoring:

- Process map size (target: <1000 entries)
- Memory usage (target: <100MB)
- Event processing rate (target: <1 second latency)
- False positive rate (target: <1% of total alerts)

## Integration Points

### SIEM Integration:
- Structured logging format for easy parsing
- JSON export capabilities for log aggregation
- Standard severity levels (CRITICAL, HIGH, MEDIUM, LOW)

### Asset Management:
- Process inventory correlation
- Change management workflow integration
- Asset criticality classification

### Incident Response:
- Automated alert forwarding
- Forensic data collection
- Timeline reconstruction capabilities

## Security Considerations

### Script Security:
- Requires Administrator privileges (process monitoring)
- Whitelist file integrity protection
- Secure log file permissions
- Regular security updates

### OT Environment Impact:
- Minimal CPU usage (<1% on dedicated monitoring server)
- Non-intrusive monitoring (read-only operations)
- Graceful degradation if Sysmon unavailable
- No impact on real-time control systems

This implementation provides comprehensive process correlation monitoring specifically tailored for OT environments while maintaining the operational stability and security requirements of industrial systems.
