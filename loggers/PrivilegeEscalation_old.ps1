# === CONFIGURATION ===
$logPath = "$env:ProgramData\CustomSecurityLogs\PrivlegeEscalation.log"
$EventLogQueryInterval = 5  # in seconds

# Ensure log folder exists
$logFolder = Split-Path $LogPath
if (-not (Test-Path $logFolder)) {
    New-Item -ItemType Directory -Path $logFolder | Out-Null
}

function Log-Detection {
    param([string]$Source, [string]$Detail)
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$time [$Source] $Detail" | Out-File -FilePath $LogPath -Append -Encoding utf8
}

# === FUNCTION TO CHECK IF SYSMON IS PRESENT ===
function Is-SysmonInstalled {
    try {
        # Check if Sysmon log exists and is accessible
        $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
        if ($sysmonLog -and $sysmonLog.IsEnabled) {
            return $true
        }
        
        # Alternative check: Look for Sysmon service
        $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
        if ($sysmonService -and $sysmonService.Status -eq "Running") {
            return $true
        }
        
        # Alternative check: Look for recent Sysmon events
        $recentEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Sysmon/Operational'
            StartTime = (Get-Date).AddMinutes(-10)
        } -MaxEvents 1 -ErrorAction SilentlyContinue
        
        return $recentEvents -ne $null
    } catch {
        Log-Detection "System" "Sysmon detection failed: $_"
        return $false
    }
}

# === SYSMON MONITORING: DLL Hijack, Injection, Network, Image Load ===
function Monitor-Sysmon {
    Write-Output "Sysmon found. Monitoring relevant Event IDs..."
    
    $lastEventTime = Get-Date
    
    while ($true) {
        try {
            # Event ID 3: Network connections
            $networkEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Sysmon/Operational'
                Id = 3
                StartTime = $lastEventTime
            } -ErrorAction SilentlyContinue
            
            foreach ($event in $networkEvents) {
                try {
                    $xml = [xml]$event.ToXml()
                    $destHost = ($xml.Event.EventData.Data | Where-Object Name -eq 'DestinationHostname').'#text'
                    $destPort = ($xml.Event.EventData.Data | Where-Object Name -eq 'DestinationPort').'#text'
                    $image = ($xml.Event.EventData.Data | Where-Object Name -eq 'Image').'#text'
                    
                    if ($destHost -and $destPort) {
                        Log-Detection "Sysmon-Network" "[Sysmon-ID3] Outbound connection: $([System.IO.Path]::GetFileName($image)) to $destHost`:$destPort"
                    }
                } catch { 
                    Log-Detection "Sysmon-Network" "[Sysmon-ID3] Parse EventID3 failed: $_" 
                }
            }

            # Event ID 7: Image/DLL loads
            $imageLoadEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Sysmon/Operational'
                Id = 7
                StartTime = $lastEventTime
            } -ErrorAction SilentlyContinue
            
            foreach ($event in $imageLoadEvents) {
                try {
                    $xml = [xml]$event.ToXml()
                    $imageLoaded = ($xml.Event.EventData.Data | Where-Object Name -eq 'ImageLoaded').'#text'
                    $processImage = ($xml.Event.EventData.Data | Where-Object Name -eq 'Image').'#text'
                    
                    # Focus on suspicious DLL loads
                    if ($imageLoaded -match 'AppData|Temp|Users.*\.dll' -or $imageLoaded -match 'amsi\.dll|wldap32\.dll') {
                        Log-Detection "Sysmon-ImageLoad" "[Sysmon-ID7] Suspicious DLL load: $([System.IO.Path]::GetFileName($processImage)) loaded $imageLoaded"
                    }
                } catch { 
                    Log-Detection "Sysmon-ImageLoad" "[Sysmon-ID7] Parse EventID7 failed: $_" 
                }
            }

            # Event ID 8: CreateRemoteThread (Process injection)
            $injectionEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Sysmon/Operational'
                Id = 8
                StartTime = $lastEventTime
            } -ErrorAction SilentlyContinue
            
            foreach ($event in $injectionEvents) {
                try {
                    $xml = [xml]$event.ToXml()
                    $sourceImage = ($xml.Event.EventData.Data | Where-Object Name -eq 'SourceImage').'#text'
                    $targetImage = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetImage').'#text'
                    
                    if ($sourceImage -and $targetImage) {
                        Log-Detection "Sysmon-InjectStart" "[Sysmon-ID8] Remote thread creation: $([System.IO.Path]::GetFileName($sourceImage)) into $([System.IO.Path]::GetFileName($targetImage))"
                    }
                } catch { 
                    Log-Detection "Sysmon-InjectStart" "[Sysmon-ID8] Parse EventID8 failed: $_" 
                }
            }

            # Event ID 10: ProcessAccess
            $accessEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Sysmon/Operational'
                Id = 10
                StartTime = $lastEventTime
            } -ErrorAction SilentlyContinue
            
            foreach ($event in $accessEvents) {
                try {
                    $xml = [xml]$event.ToXml()
                    $sourceImage = ($xml.Event.EventData.Data | Where-Object Name -eq 'SourceImage').'#text'
                    $targetImage = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetImage').'#text'
                    $grantedAccess = ($xml.Event.EventData.Data | Where-Object Name -eq 'GrantedAccess').'#text'
                    
                    # Focus on LSASS and other critical process access
                    if ($targetImage -match 'lsass\.exe|winlogon\.exe|csrss\.exe') {
                        Log-Detection "Sysmon-InjectWrite" "[Sysmon-ID10] Process access: $([System.IO.Path]::GetFileName($sourceImage)) -> $([System.IO.Path]::GetFileName($targetImage)) Access: $grantedAccess"
                    }
                } catch { 
                    Log-Detection "Sysmon-InjectWrite" "[Sysmon-ID10] Parse EventID10 failed: $_" 
                }
            }
            
            $lastEventTime = Get-Date
        } catch {
            Log-Detection "Sysmon-Monitor" "Error monitoring Sysmon events: $_"
        }
        
        Start-Sleep -Seconds $EventLogQueryInterval
    }
}

# === SECURITY LOG: Token Manipulation ===
function Monitor-TokenManipulation {
    $lastEventTime = Get-Date
    
    while ($true) {
        try {
            # Get privilege-related security events
            $tokenEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                Id = 4673, 4674, 4696
                StartTime = $lastEventTime
            } -ErrorAction SilentlyContinue
            
            foreach ($event in $tokenEvents) {
                try {
                    $xml = [xml]$event.ToXml()
                    $eventId = $xml.Event.System.EventID
                    
                    # Parse based on event ID
                    switch ($eventId) {
                        4673 { # Privileged service called
                            $subjectUserName = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
                            $privilegeName = ($xml.Event.EventData.Data | Where-Object Name -eq 'PrivilegeName').'#text'
                            $serviceName = ($xml.Event.EventData.Data | Where-Object Name -eq 'Service').'#text'
                            Log-Detection "Token-Abuse" "Privileged service call - User: $subjectUserName, Privilege: $privilegeName, Service: $serviceName"
                        }
                        4674 { # An operation was attempted on a privileged object
                            $subjectUserName = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
                            $privilegeName = ($xml.Event.EventData.Data | Where-Object Name -eq 'PrivilegeName').'#text'
                            Log-Detection "Token-Abuse" "Privileged operation - User: $subjectUserName, Privilege: $privilegeName"
                        }
                        4696 { # A primary token was assigned to process
                            $subjectUserName = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
                            $targetUserName = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
                            Log-Detection "Token-Abuse" "Token assignment - Subject: $subjectUserName, Target: $targetUserName"
                        }
                    }
                } catch { 
                    Log-Detection "Token-Abuse" "Parse Security event failed: $_" 
                }
            }
            
            $lastEventTime = Get-Date
        } catch { 
            Log-Detection "Token-Abuse" "Error monitoring Security events: $_" 
        }
        
        Start-Sleep -Seconds $EventLogQueryInterval
    }
}

# === POWERSHELL BLOCK LOGGING MONITORING ===
function Monitor-PowerShellBlocks {
    $lastEventTime = Get-Date
    
    while ($true) {
        try {
            # Get PowerShell script block events
            $psEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-PowerShell/Operational'
                Id = 4104
                StartTime = $lastEventTime
            } -ErrorAction SilentlyContinue
            
            foreach ($event in $psEvents) {
                try {
                    $xml = [xml]$event.ToXml()
                    $scriptBlockText = ($xml.Event.EventData.Data | Where-Object Name -eq 'ScriptBlockText').'#text'
                    
                    # Check for privilege escalation patterns - using safer detection
                    $suspiciousTerms = @(
                        'run.*as', 'elevat', 'uac.*bypass', 'admin.*bypass', 'privil.*escal',
                        'get.*system', 'debug.*privil', 'token.*import', 'duplic.*token'
                    )
                    
                    if ($scriptBlockText) {
                        $lowerScript = $scriptBlockText.ToLower()
                        $foundPatterns = $suspiciousTerms | Where-Object { $lowerScript -match $_ }
                        
                        if ($foundPatterns) {
                            $truncatedScript = if ($scriptBlockText.Length -gt 200) { 
                                $scriptBlockText.Substring(0, 200) + "..." 
                            } else { 
                                $scriptBlockText 
                            }
                            Log-Detection "PS-Escalation" "Suspicious PowerShell detected: $truncatedScript"
                        }
                    }
                } catch { 
                    Log-Detection "PS-Escalation" "Parse PowerShell event failed: $_" 
                }
            }
            
            $lastEventTime = Get-Date
        } catch { 
            Log-Detection "PS-Escalation" "Error monitoring PowerShell events: $_" 
        }
        
        Start-Sleep -Seconds $EventLogQueryInterval
    }
}

# === MAIN ===
# Check if script is already running
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$runningInstances = Get-Process -Name "powershell" -ErrorAction SilentlyContinue | 
    Where-Object { $_.CommandLine -like "*$scriptName*" -and $_.Id -ne $PID }

if ($runningInstances.Count -gt 0) {
    Log-Detection "System" "Script already running (PID: $($runningInstances.Id -join ',')). Exiting."
    exit
}

Log-Detection "System" "Privilege Escalation monitoring started (PID: $PID)"

# Test Sysmon detection
$sysmonDetected = Is-SysmonInstalled
Log-Detection "System" "Sysmon detection result: $sysmonDetected"

if ($sysmonDetected) {
    Log-Detection "System" "Starting Sysmon monitoring"
    Start-Job -Name "SysmonMonitor" -ScriptBlock { 
        # Re-import the functions and variables for the job
        . $using:PSCommandPath
        Monitor-Sysmon
    }
} else {
    Log-Detection "System" "Sysmon not detected - skipping Sysmon monitoring"
}

Log-Detection "System" "Starting Token Manipulation monitoring"
Start-Job -Name "TokenMonitor" -ScriptBlock { 
    # Re-import the functions and variables for the job
    . $using:PSCommandPath
    Monitor-TokenManipulation
}

Log-Detection "System" "Starting PowerShell Block monitoring"
Start-Job -Name "PSBlockMonitor" -ScriptBlock { 
    # Re-import the functions and variables for the job
    . $using:PSCommandPath
    Monitor-PowerShellBlocks
}

Log-Detection "System" "All monitoring jobs started. Main script entering keep-alive loop."

# Keep-alive loop with job monitoring
while ($true) {
    # Check if jobs are still running
    $jobs = Get-Job | Where-Object { $_.Name -in @("SysmonMonitor", "TokenMonitor", "PSBlockMonitor") -and $_.State -eq "Failed" }
    if ($jobs) {
        foreach ($job in $jobs) {
            Log-Detection "System" "Job $($job.Name) failed. Error: $($job.ChildJobs[0].JobStateInfo.Reason)"
        }
    }
    
    Start-Sleep -Seconds 30
}
