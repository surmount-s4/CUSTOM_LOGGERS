# CUSTOM_LOGGERS – Unified Monitoring Suite

> Centralized PowerShell-based detection framework mapping Windows & Sysmon telemetry to MITRE ATT&CK tactics on Windows Server 2012+ (PowerShell 3.0 compatible).

---

## 1. Project Overview
The suite provides modular monitors per ATT&CK tactic (Execution, Persistence, Credential Access, Discovery, Lateral Movement, Command & Control, Impact, Initial Access, Defense Evasion, etc.). Each script:
- Uses a lightweight polling loop (or legacy WMI/event queries) with sliding time window.
- Consumes Sysmon Operational log plus selected Security/System events.
- Outputs human-readable, technique-tagged flat log files suitable for SIEM ingestion.

---

## 2. Standard Logging Architecture (Reference Pattern)
Adopted in fully compliant monitors (e.g., DefenseEvasion.ps1, CredentialAccess.ps1, Discovery.ps1, LateralMovement.ps1, Execution.ps1, InitialAccess.ps1, Persistence.ps1 after modernization):
- Parameters: `-OutputPath -LogLevel (Info|Warning|Critical) -MonitorDuration (minutes, 0=continuous) -RefreshInterval (seconds)`
- Initialization:
  - Creates timestamped log: `<Tactic>_yyyyMMdd_HHmmss.log`
  - Records environment header (time, PSVersion, OS).
- Core function: `Write-LogEntry` builds line:
  ```
  [YYYY-MM-DD HH:MM:SS] [LEVEL] Message | EventID: n | Process: image | PID: id | User: DOMAIN\user | CommandLine: ... | Technique: T####(.###) | Additional: context
  ```
  Optional fields appended only if present (ProcessGuid, Hashes, TargetFile, etc.).
- Event acquisition: `Get-WinEvent -FilterHashtable @{ LogName=<name>; Id=<id array>; StartTime=<LastEventTime minus buffer> }`
- Sliding window: `$Script:LastEventTime` updated after each cycle to prevent reprocessing.
- Technique counters: Hashtable keyed by Technique → incremented in `Write-LogEntry`.
- Summary: Printed/logged on graceful stop or duration expiry (totals + per-technique counts).
- Graceful termination: Ctrl+C handler / `PowerShell.Exiting` event writes summary.
- Compatibility: No PowerShell 5+ specific syntax (avoids `??`, pipeline classes, etc.).

---

## 3. Architecture Status Categories
| Status | Meaning |
|--------|---------|
| Fully Compliant | Implements standard parameter set, `Write-LogEntry`, counters, summary, sliding window polling. |
| Partially Compliant | Functional detections but deviates (naming, missing levels, reduced parameters, older logging). |
| Utility | Support / infrastructure (setup, validation, raw logging helpers). |
| Legacy / Refactor | Older pattern (baseline diff only, or broad snapshot logic) – slated for modernization or deprecation. |

---

## 4. Script Inventory (Current State)
| Script | Primary Tactic(s) | Purpose / Focus | Log Filename Pattern | Architecture Status | Sysmon Required (Full Value) |
|--------|-------------------|-----------------|----------------------|--------------------|------------------------------|
| DefenseEvasion.ps1 | Defense Evasion | Hides/injection, tamper & evasion behaviors | DefenseEvasion_*.log | Fully Compliant | Yes (falls back limited) |
| CredentialAccess.ps1 | Credential Access | LSASS access, dumping, Kerberos, token abuse | CredentialAccess_*.log | Fully Compliant | Yes |
| Discovery.ps1 | Discovery | Enumeration (accounts, system, network, shares) | Discovery_*.log | Fully Compliant | Yes |
| LateralMovement.ps1 | Lateral Movement | RDP sessions, admin share, tool transfer | LateralMovement_*.log | Fully Compliant | Yes |
| Execution.ps1 | Execution | Command/script interpreters, LOLBins, user execution | Execution_*.log | Fully Compliant | Yes |
| InitialAccess.ps1 | Initial Access | Phishing chains, drive‑by, dropped payloads, external RDP | InitialAccess_*.log | Fully Compliant | Yes |
| Persistence.ps1 | Persistence | Registry/services/tasks/WMI persistence | Persistence_*.log | Fully Compliant | Yes |
| Persistence_old.ps1 | Persistence | Baseline diff (registry, tasks, WMI, files) | Execution-Detect.log / baseline set | Legacy / Refactor | Beneficial |
| CommandAndControl.ps1 | Command & Control | Protocol misuse, tunneling, DNS, RAT indicators | CommandAndControl_*.log | Partially Compliant (simplified logger, no LogLevel param) | Yes |
| Impact.ps1 | Impact | Destructive / disruptive OT targets (ransomware, wipe) | Impact_*.log | Fully Compliant | Yes |
| Validate-SysmonSetup.ps1 | Infrastructure | Validate Sysmon install, config, events | (console summary) | Utility | Yes |
| Setup-SysmonPipeline.ps1 | Infrastructure | Deploy/update Sysmon config | sysmon-setup.log | Utility | Yes |
| Test-SysmonDetection.ps1 | Test | Generates sample events | Test log / console | Utility | Yes |
| Test-*Detection.ps1 (various) | Test | Scenario validation per tactic | Test_*_*.log | Utility | Yes |
| PrivlegeEscalation.ps1 (typo) | Privilege Escalation | Token, service, registry abuse (needs rename) | PrivilegeEscalation_*.log | Partially Compliant | Yes |
| Recon_full__scan.ps1 | Recon / Hybrid | Wide reconnaissance & honeypot hooks | recon_log.txt | Legacy / Specialized | Partial |
| Reconnaissance_full__scan.ps1 | Recon / Duplicate | Duplicate variant | recon_log.txt | Legacy / Duplicate | Partial |
| recon-detect.ps1 | Recon | Lightweight recon detection | recon_log.txt | Legacy | Optional |
| ps_cmd_logs.ps1 | Utility | PowerShell script block logging aggregator | ps_cmd_logs.log | Utility | Optional |
| cmdline_logger.ps1 | Utility | Command line capture (process start) | cmdline_logger.log | Utility | Optional |
| COMPLIANCE-ANALYSIS-REPORT.md | Documentation | Architecture alignment assessment | (markdown) | Doc | N/A |
| *README tactic files* | Documentation | Deep dive per tactic | (markdown) | Doc | N/A |

---

## 5. Core Event Sources
| Category | Examples |
|----------|----------|
| Sysmon | 1 (Process), 3 (Network), 7 (ImageLoad), 8 (CreateRemoteThread), 10 (ProcessAccess), 11 (FileCreate), 12/13/14 (Registry), 19–21 (WMI), 22 (DNS), 23 (FileDelete) |
| Security Log | 4624/4625 (Logon), 4648, 4672/4673, 4688 (Process), 4697 (Service Installed), 4698/4702 (Scheduled Task), 7045 (System service via System log), 4768/4769/4771 (Kerberos), 4778/4779 (RDP session) |
| System | 7045 (Service install) |
| PowerShell (when enabled) | 4104 Script Block (external in utility scripts) |

---

## 6. Common Parameters & Behavior
| Parameter | Meaning | Notes |
|-----------|---------|-------|
| OutputPath | Directory for log files | Defaults to ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS |
| LogLevel | Minimum console emission | File always receives full detail |
| MonitorDuration | Minutes (0 = run until interrupted) | Loop stops gracefully & summarizes |
| RefreshInterval | Polling cadence (seconds) | Small values increase CPU/IO |

Scripts without LogLevel or full parity (e.g., CommandAndControl.ps1) are candidates for standardization.

---

## 7. Log Consumption & SIEM Tips
- Stable delimiter: pipe characters (`| Field: Value`) allow straightforward splitting.
- Technique tagging enables ATT&CK dimension pivoting (group by Technique).
- Recommended ingestion fields: Timestamp, Level, Technique, Process, PID, User, EventID, CommandLine hash (for dedup), Additional.
- Implement downstream dictionary for technique → tactic mapping (if not already enriched).

---

## 8. Extension Guidelines
When adding a new tactic script:
1. Copy a fully compliant template (e.g., CredentialAccess.ps1).
2. Replace tactic name, log prefix, detection functions.
3. Define `Monitor-<TechniqueGroup>` functions encapsulating pattern logic.
4. Restrict filters to needed Event IDs (performance).
5. Append MITRE technique IDs exactly (T#### with optional sub-tech .###).
6. Maintain backward compatibility (avoid unsupported syntax).

---

## 9. Modernization Targets
| Item | Action |
|------|--------|
| CommandAndControl.ps1 | Add LogLevel + severity classifications + summary block |
| Persistence_old.ps1 | Migrate to real-time model or archive as legacy |
| Recon* scripts | Consolidate into Discovery.ps1 (optional modular plugin approach) |
| PrivlegeEscalation.ps1 | Rename (PrivilegeEscalation.ps1) & refactor to standard logger |
| Utilities | Document separation from primary tactical monitors |

---

## 10. Quick Start
```powershell
# Validate Sysmon
.\Validate-SysmonSetup.ps1

# Launch several tactic monitors concurrently (separate consoles)
.\Execution.ps1 -LogLevel Info
.\CredentialAccess.ps1 -LogLevel Warning -RefreshInterval 20
.\LateralMovement.ps1 -MonitorDuration 120 -RefreshInterval 15
```

Stop with Ctrl+C → summary printed + counters recorded.

---

## 11. First-Time Checklist
- [ ] Sysmon installed & Operational log populated
- [ ] Security log auditing (process creation, logon events) enabled
- [ ] PowerShell script block logging (optional enrichment) configured
- [ ] Output directory write permissions verified
- [ ] Baseline noise reviewed (adjust LogLevel or patterns)

---

## 12. Roadmap Ideas
- JSON dual-output mode (file + structured)
- Central aggregator (merge multi-tactic events + correlation)
- Whitelist/allowlist configuration file (regex-based suppression)
- Optional module-based packaging / manifest
- Live metrics endpoint (e.g., named pipe or lightweight HTTP listener)
- Unified orchestrator to manage all tactic monitors

---

## 13. Support / Troubleshooting
| Symptom | Likely Cause | Action |
|---------|--------------|-------|
| Empty logs | Missing Sysmon events | Verify configuration / service state |
| High CPU | Too small RefreshInterval | Increase interval (≥15s) |
| Duplicate detections | LastEventTime not advancing | Ensure system clock stable / no manual time shifts |
| Missing Technique counters | Technique not passed to logger | Confirm detection functions supply `-Technique` |
| Noise overload | Broad patterns (e.g., discovery) | Raise LogLevel or refine regex lists |

---

## 14. Compliance Snapshot (Condensed)
Fully Compliant: DefenseEvasion, CredentialAccess, Discovery, LateralMovement, Execution, InitialAccess, Persistence, Impact  
Partially: CommandAndControl, PrivlegeEscalation  
Legacy / Refactor: Persistence_old, Recon_full__scan, Reconnaissance_full__scan, recon-detect  
Utilities: Setup-SysmonPipeline, Validate-SysmonSetup, ps_cmd_logs, cmdline_logger, test scripts  
Documentation: Individual tactic READMEs & Compliance Report  

---

## 15. Licensing / Security Note
Logs may contain sensitive command lines & user context; treat as confidential security telemetry. Implement retention & access controls.

---

(Original tactic-specific functionality sections retained below)

# CUSTOM_LOGGERS
Loggers made for monitoring and logging signatures corresponding to Mitre Attack Tactics 

# Reconnaissance:

| **Functionality**                                   | **What It Does**                                                                                                        | **What It Detects**                                                                     |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| **1. Failed Login Detection**<br>(Event ID 4625)    | Watches Windows Security log for failed login attempts.                                                                 | Brute-force login attempts via RDP, SMB, etc.                                           |
| **2. Port Scan Detection**<br>(Advanced Heuristics) | Monitors network connections, tracks TCP states, port diversity, and timing to identify scanning behavior.              | Nmap scans, SYN scans, full-connect scans, masscan, banner grabbing, high-speed probes. |
| **3. Honeyfile Access Monitoring**                  | Creates a decoy file (`Passwords.txt`) in a trap directory and logs access or modification.                             | Unauthorized file access or internal recon by an intruder.                              |
| **4. DNS Recon Detection**<br>(Optional)            | Parses `dnssrv.log` (if DNS debug logging is enabled) for suspicious domain lookups (e.g., `dev`, `internal`, `admin`). | DNS-based reconnaissance or subdomain fuzzing (e.g., using `dnsenum`, `dig`).           |
| **5. Web Directory Monitoring**                     | Monitors `C:\inetpub\wwwroot` for any newly created files or folders.                                                   | Web shell uploads, unauthorized file drops via exploited IIS or upload forms.           |
| **6. IIS Log Monitoring**                           | Reads latest IIS log file and searches for access to sensitive paths like `/admin`, `/login`, `.env`, etc.              | Web recon and brute-forcing tools like Gobuster, Dirb, Nikto, etc.                      |
| **7. Centralized Alerting (FastAPI)**               | Sends all high-level alerts (e.g., scans, honeyfile access, failed logins) to a remote FastAPI server via HTTP POST.    | Real-time alerting for external monitoring, dashboards, or SIEM integration.            |
| **8. Local Log File**                               | All events are written to a log file at `C:\ProgramData\CustomSecurityLogs\recon_log.txt`.                              | Persistent, searchable log for forensics or historical review.                          |

  
# Resource Development:

| **Functionality**               | **What It Does**                                                              | **What It Detects**                                                                                                                                                               |
| ------------------------------- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Monitor-Processes**           | Scans all active processes and their command lines                            | - Use of LOLBins (`certutil`, `mshta`, etc.)<br>- PowerShell misuse<br>- Obfuscated/encoded commands<br>- Fileless payloads<br>- Suspicious domains<br>- `cmd.exe` recon commands |
| **Monitor-NetworkConnections**  | Reviews active TCP connections and reverse-resolves remote hosts              | - Connections to known malicious infrastructure (e.g., Pastebin, GitHub, Mega.nz)<br>- Non-browser apps using TLS ports<br>- Potential C2 activity                                |
| **Monitor-Files**               | Recursively scans suspicious directories for file indicators                  | - Dropped payloads or toolkits (e.g., `cobalt`, `sliver`, `.ps1`, `.exe`) in suspicious locations like `C:\Users\Public` or `$env:TEMP`                                           |
| **Monitor-EventLog**            | Retrieves recent Windows Security events                                      | - Remote Desktop Protocol (RDP) logons via event ID patterns (`Logon Type 10`)                                                                                                    |
| **Monitor-ScheduledTasks**      | Queries and parses scheduled tasks                                            | - Persistence via PowerShell-based tasks or tasks using encoded payloads                                                                                                          |
| **Discovery Command Detection** | Looks for known discovery/recon commands in both PowerShell and cmd processes | - Use of `whoami`, `net user`, `ipconfig`, `systeminfo`, `tasklist`, etc.                                                                                                         |
| **Domain Detection**            | Matches domain keywords in command lines or network traffic                   | - Use of cloud/dev platforms for delivery or staging (e.g., GitHub, Dropbox)                                                                                                      |
| **Obfuscation Detection**       | Matches encoding, base64 strings, and other obfuscation patterns in commands  | - Base64/encoded payloads, reflection-based attacks, `-EncodedCommand` flags                                                                                                      |
| **Log Writer**                  | Logs structured detection messages to a custom path                           | - Human-readable alerts for all detected threats                                                                                                                                  |

# Initial Access:

| Functionality              | What It Does                                                                                              | What It Detects                                                                                   |
| -------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **SuspiciousProcessChain** | Hooks into Sysmon EventID 1 (or WMI ProcessStartTrace) to inspect parent→child process chains             | PowerShell (or other) spawned by browsers, email clients, or Office apps                          |
| **LOLBinUsage**            | Monitors process creations for known “Living‑Off‑the‑Land” binaries with suspicious switches              | Execution of `mshta`, `regsvr32`, `rundll32`, `certutil`, `bitsadmin` with encoded/download flags |
| **OfficeMacroExec**        | Detects Office hosts spawning script engines via Sysmon or WMI                                            | Word/Excel launching `wscript`, `cscript`, `powershell`, or `dllhost`                             |
| **RegistryRunKeySet**      | Watches for registry “Run” or “RunOnce” values being created/modified (Sysmon EventID 13 or WMI fallback) | New persistence entries under `HKLM\…\Run*` or `HKCU\…\Run*`                                      |
| **ScheduledTaskCreated**   | Uses WMI file‑watch on the System32\Tasks folder to catch new task XML files                              | Creation of any new Scheduled Task definition                                                     |


# Execution:

| **Functionality**                        | **What It Does**                                                                 | **What It Detects**                                                                |
| ---------------------------------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Process Execution via WMI**            | Monitors creation of suspicious processes like `powershell.exe`, `cmd.exe`, etc. | T1059 (Command and Scripting Interpreter), T1204 (User Execution), T1218 (LOLBins) |
| **Command Line Analysis**                | Checks command lines for keywords like `-EncodedCommand`, `IEX`, `bypass`        | Obfuscated or encoded execution, AMSI bypasses, T1059, T1086                       |
| **ScriptBlock Logging (Event ID 4104)**  | Parses PowerShell block logs for malicious functions                             | T1059.001, T1086, fileless execution, in-memory code                               |
| **Scheduled Task Creation (WMI & COM)**  | Detects job creation via `Win32_ScheduledJob` & `Win32_ScheduledTask`            | T1053.005 (Scheduled Task/Job), T1204.002                                          |
| **New Service Installation**             | Monitors `Win32_Service` for new entries                                         | T1543.003 (Create or Modify System Process), Persistence via services              |
| **Executable/Script File Detection**     | Watches for execution of files with suspicious extensions                        | T1059, T1036 (Masquerading), Initial Access/Execution via droppers                 |
| **DLL Load Monitoring (Sysmon ID 7)**    | Flags DLLs loaded from temp/user folders                                         | T1574.002 (DLL Sideloading), T1055 (Injection)                                     |
| **Process Injection (Sysmon IDs 8, 10)** | Detects remote thread injection & process tampering                              | T1055 (Process Injection), T1105 (Ingress Tool Transfer)                           |
| **Parent–Child Correlation**             | Flags Office-spawned interpreters (e.g., `winword.exe` → `powershell.exe`)       | T1203 (Office Apps), T1566.001 (Phishing w/Attachment), T1059                      |
| **Defender Alerts (Event ID 1116)**      | Monitors for real-time Microsoft Defender detections                             | T1204, T1036, T1059, zero-day or AV-flagged binaries                               |
| **Sysmon Process Monitoring (ID 1)**     | Captures full process creation logs (fallback to command line)                   | Broad detection of T1059, T1547, T1218                                             |
| **Resilient Error Handling**             | Tries catch blocks if logs are missing (no crash)                                | Ensures uptime across all Windows versions                                         |

# Persistence:

| Functionality                         | What It Does                                                                                                    | What It Detects                                                                                                                                                                   |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Baseline Diff Engine**              | Compares a newly captured snapshot against the stored baseline file and logs any differences.                   | Additions, deletions or modifications in any monitored artifact (registry, files, event logs, WMI/ETW).                                                                           |
| **Registry Monitoring**               | Reads and snapshots values under both 32‑ and 64‑bit registry hives for Run, RunOnce, IFEO, AppInit\_DLLs, COM  | Creation, modification or removal of autostart entries (Run/RunOnce), IFEO hijacks, AppInit\_DLLs loads, COM hijacking registrations.                                             |
| **File‑Integrity Monitoring**         | Recursively lists file paths + timestamps under Startup folders, the Tasks directory, Chrome extension folders. | New, removed or changed files in common persistence locations (Startup LNKs, scheduled‑task XMLs, browser hooks/extensions).                                                      |
| **Event Log Monitoring**              | Queries Windows Event Logs (Sysmon/Operational, Security, System) for a set of persistence‑relevant Event IDs   | Process executions (Sysmon ID 1), image loads (ID 7), code injections (IDs 8/10), service installations (System 7045/Security 4697), task creation (4702), token ops (4673/4696). |
| **WMI & ETW Subscription Monitoring** | Captures legacy WMI filters/consumers/bindings and lists active ETW session names via wevtutil.                 | New or altered WMI event filters/consumers/bindings (T1546.004) and creation or removal of ETW sessions that could hide event consumers.                                          |


# Privlege Escalation:

| Functionality                 | What It Does                                                         | What It Detects                                                                                     |
| ----------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Sysmon Presence Check         | Detects if Sysmon is installed and enables advanced event monitoring | Enables collection of deep system-level telemetry if Sysmon is available                            |
| Monitor-Sysmon                | Hooks into Sysmon event log for PE-relevant IDs                      | Process injection (IDs 8, 10), DLL/Image load hijacking (ID 7), outbound network connections (ID 3) |
| Monitor-TokenManipulation     | Listens to Windows Security logs                                     | Privilege use attempts, SeDebugPrivilege, impersonation (Event IDs 4673, 4674, 4696)                |
| Monitor-PowerShellBlocks      | Parses PowerShell script block logs (ID 4104)                        | Suspicious PowerShell execution like reflection, obfuscation, or encoded payloads                   |
| WMI Registry Change Detection | (from earlier script) Watches Run/RunOnce/IFEO registry keys         | Persistence via registry autostarts, execution hijacking                                            |
| WMI Service Creation Monitor  | Captures Win32\_Service creation events                              | Service creation/modification attacks                                                               |
| WMI Scheduled Task Monitor    | Detects newly registered scheduled tasks                             | Persistence or escalation via task abuse                                                            |
| WMI User Account Monitoring   | Watches for account additions or privilege changes                   | Account manipulation, privilege group escalation                                                    |
| WMI File Write Watcher        | Monitors sensitive folders like Startup, Tasks folder                | File drops related to persistence or PE via autostart vectors                                       |
| Fallback Logging              | Uses WMI-based detection if Sysmon is unavailable                    | Ensures minimum detection on legacy systems without Sysmon                                          |
| Log-Detection Handler         | Central logging to flat text file with timestamps                    | Records all detection events for analyst review or further processing                               |
