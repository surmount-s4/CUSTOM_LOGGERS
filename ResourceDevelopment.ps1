# ==============================
# Resource & Threat Monitor v2.0
# ==============================

$logPath = "C:\ProgramData\CustomSecurityLogs\ResourceDevelopment.log"

# Ensure log directory exists
$logDir = Split-Path $logPath
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Watch list: domains, commands, files, recon, etc.
$watchList = @{
    Domains = @("pastebin", "github", "gitlab", "mega.nz", "dropbox", "sendgrid", "mailgun", "cloudflare", "aws", "azure", "gcp", "ovh", "contabo", "vultr", "digitalocean", "namesilo", "namecheap", "bit.ly", "cutt.ly")
    FileIndicators = @("cobalt", "bruteratel", "sliver", "payload", "malware", "stager", ".bat", ".ps1", ".vbs", ".exe", ".dll", ".com")
    CommandIndicators = @(
        "certutil", "mshta", "regsvr32", "rundll32", "wmic",
        "New-Object Net.WebClient", "Invoke-WebRequest", "Invoke-RestMethod",
        "wget", "curl", "iex", "Add-MpPreference", "Set-MpPreference",
        "-EncodedCommand", "FromBase64String", "DownloadString", "reflection"
    )
    SuspiciousPaths = @(
        "C:\Users\Public", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA",
        "C:\Windows", "C:\Windows\System32"
    )
    KnownBrowsers = @("chrome", "firefox", "msedge", "iexplore")
    DiscoveryCommands = @(
        "whoami", "hostname", "ipconfig", "systeminfo", "net user", "net group", "net localgroup",
        "net use", "net share", "query user", "tasklist", "netstat", "nltest", "dsquery",
        "Get-ADUser", "Get-Process", "Get-Service", "Get-WmiObject", "Get-NetTCPConnection"
    )
}

function Log-Detection {
    param ($type, $data)
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $type, $data
    Add-Content -Path $logPath -Value $entry
}

function Monitor-Processes {
    Get-WmiObject Win32_Process | ForEach-Object {
        $proc = $_
        if ($proc.CommandLine) {

            # Command indicators (e.g., downloaders, fileless)
            foreach ($indicator in $watchList.CommandIndicators) {
                if ($proc.CommandLine -match $indicator) {
                    Log-Detection "CommandMatch" "[$($proc.ProcessId)] $($proc.Name) - $($proc.CommandLine)"
                }
            }

            # Suspicious domain names in command
            foreach ($domain in $watchList.Domains) {
                if ($proc.CommandLine -match $domain) {
                    Log-Detection "SuspiciousDomainInCmd" "[$($proc.ProcessId)] $($proc.Name) - $($proc.CommandLine)"
                }
            }

            # Obfuscated/Encoded PowerShell
            if ($proc.CommandLine -match "-EncodedCommand" -or $proc.CommandLine -match "[A-Za-z0-9+/]{100,}") {
                Log-Detection "ObfuscatedCommand" "[$($proc.ProcessId)] $($proc.Name) - $($proc.CommandLine)"
            }

            # Fileless payload techniques
            if ($proc.CommandLine -match "DownloadString" -or $proc.CommandLine -match "IEX\s*\(") {
                Log-Detection "FilelessExecution" "[$($proc.ProcessId)] $($proc.Name) - $($proc.CommandLine)"
            }

            # Recon via PowerShell
            foreach ($cmd in $watchList.DiscoveryCommands) {
                if ($proc.CommandLine -match $cmd -and $proc.Name -match "powershell") {
                    Log-Detection "ReconCommand" "[$($proc.ProcessId)] $($proc.Name) ran discovery cmd: $($cmd) → $($proc.CommandLine)"
                }
            }

            # Explicit cmd.exe monitoring
            if ($proc.Name -ieq "cmd.exe") {
                Log-Detection "CmdUsage" "[$($proc.ProcessId)] cmd.exe was run with: $($proc.CommandLine)"

                foreach ($cmd in $watchList.DiscoveryCommands) {
                    if ($proc.CommandLine -match $cmd) {
                        Log-Detection "CmdRecon" "[$($proc.ProcessId)] cmd.exe ran discovery cmd: $($cmd) → $($proc.CommandLine)"
                    }
                }
            }
        }
    }
}

function Monitor-NetworkConnections {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    foreach ($conn in $conns) {
        try {
            $remote = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress).HostName
        } catch {
            $remote = $conn.RemoteAddress
        }

        foreach ($domain in $watchList.Domains) {
            if ($remote -match $domain) {
                Log-Detection "DomainNetworkConn" "Remote: $($remote):$($conn.RemotePort)"
            }
        }

        # Suspicious TLS usage
        if ($conn.RemotePort -in 443, 8443) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -notin $watchList.KnownBrowsers) {
                Log-Detection "SuspiciousTLS" "[$($proc.Id)] $($proc.ProcessName) → $($conn.RemoteAddress):$($conn.RemotePort)"
            }
        }
    }
}

function Monitor-Files {
    foreach ($path in $watchList.SuspiciousPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                $file = $_
                foreach ($keyword in $watchList.FileIndicators) {
                    if ($file.Name -match $keyword) {
                        Log-Detection "SuspiciousFile" "$($file.FullName)"
                    }
                }
            }
        }
    }
}

function Monitor-EventLog {
    $events = Get-WinEvent -LogName "Security" -MaxEvents 25 -ErrorAction SilentlyContinue
    foreach ($e in $events) {
        if ($e.Message -match "New Logon" -and $e.Message -match "Logon Type:\s*10") {
            Log-Detection "RDPAccess" "$($e.TimeCreated): RDP login detected"
        }
    }
}

function Monitor-ScheduledTasks {
    try {
        $tasks = schtasks /query /fo LIST /v 2>$null
        foreach ($task in $tasks) {
            if ($task -match "powershell" -or $task -match "-EncodedCommand") {
                Log-Detection "SuspiciousScheduledTask" "$task"
            }
        }
    } catch {
        Log-Detection "Error" "Scheduled task scan failed: $($_.Exception.Message)"
    }
}

# === Main Loop ===
while ($true) {
    try {
        Monitor-Processes
        Monitor-NetworkConnections
        Monitor-Files
        Monitor-EventLog
        Monitor-ScheduledTasks
    } catch {
        Log-Detection "RuntimeError" $_.Exception.Message
    }
    Start-Sleep -Seconds 60
}
