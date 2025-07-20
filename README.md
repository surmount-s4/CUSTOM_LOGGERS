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
