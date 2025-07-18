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

  
