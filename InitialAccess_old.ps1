# Enhanced Initial Access Detection Monitor with Sysmon (if available) and WMI/FSW fallback
# ---------------------------------------------------------------
# This script integrates advanced detections (LOLBins, registry/task persistence,
# Office macros) and automatically prefers Sysmon with Register-WinEvent,
# falling back to WMI or FileSystemWatcher where necessary.

# Log file path (folder auto-created)
$LogFile = "$env:ProgramData\CustomSecurityLogs\InitialAccess.log"
$LogPath = Split-Path $LogFile
if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force }

function Write-Log {
    param($Type, $Details, $Severity = 'Medium', $Description = '', $SeverityReason = '')
    try {
        $Event = @{
            Timestamp = (Get-Date).ToString('o')
            EventType = $Type
            Severity = $Severity
            SeverityReason = $SeverityReason
            Description = $Description
            ComputerName = $env:COMPUTERNAME
            UserName = $env:USERNAME
            ProcessId = $PID
            Details = $Details
        }
        
        # Pretty print for readability
        $LogEntry = "=" * 80
        $LogEntry += "`n[$(Get-Date)] SECURITY ALERT - $Type"
        $LogEntry += "`nSeverity: $Severity $(if($SeverityReason) { "($SeverityReason)" })"
        $LogEntry += "`n$Description"
        $LogEntry += "`nHost: $env:COMPUTERNAME | User: $env:USERNAME"
        $LogEntry += "`nJSON: $($Event | ConvertTo-Json -Compress)"
        $LogEntry += "`n" + "=" * 80 + "`n"
        
        $LogEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8
    } catch {
        Write-Error "Failed to write log: $_"
    }
}

# Cleanup existing event subscriptions to avoid duplicates
Get-EventSubscriber | Unregister-Event -ErrorAction SilentlyContinue

# Determine availability of Sysmon and WinEvent cmdlets
$HasSysmon = $false
try { if ((Get-Service -Name Sysmon -ErrorAction Stop).Status -eq 'Running') { $HasSysmon = $true } } catch {}
$HasWinEvent = (Get-Command Get-WinEvent -ErrorAction SilentlyContinue) -ne $null

Write-Host "System Configuration:" -ForegroundColor Yellow
Write-Host "  HasSysmon: $HasSysmon" -ForegroundColor Gray  
Write-Host "  HasWinEvent: $HasWinEvent" -ForegroundColor Gray
if ($HasSysmon -and $HasWinEvent) {
    Write-Host "  Using Sysmon event monitoring" -ForegroundColor Green
} else {
    Write-Host "  Using WMI monitoring for process events" -ForegroundColor Green
}

# 1. PROCESS CREATION: Suspicious chains, LOLBins, Office macros
if ($HasSysmon -and $HasWinEvent) {
    Write-Host "Registering Sysmon event monitoring..." -ForegroundColor Green
    
    # Create a runspace for Sysmon event monitoring
    $SysmonMonitor = {
        try {
            # Monitor Sysmon process creation events (Event ID 1)
            $events = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System/EventID=1]" -MaxEvents 10 -ErrorAction SilentlyContinue
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $eventData = $xml.Event.EventData.Data
                
                $Parent = ($eventData | Where-Object Name -eq 'ParentImage').'#text'
                $Image = ($eventData | Where-Object Name -eq 'Image').'#text' 
                $Cmd = ($eventData | Where-Object Name -eq 'CommandLine').'#text'
                $ProcessId = ($eventData | Where-Object Name -eq 'ProcessId').'#text'
                $ParentProcessId = ($eventData | Where-Object Name -eq 'ParentProcessId').'#text'
                
                # Check for suspicious PowerShell chains
                if ($Image -imatch 'powershell.exe' -and $Parent -imatch 'chrome|firefox|msedge|outlook|thunderbird|winword|excel') {
                    $parentApp = ($Parent -split '\\')[-1]
                    $description = "[SYSMON] [Sysmon-ID1] DETECTED: Suspicious PowerShell execution spawned from $parentApp. This could indicate a malicious script or exploit delivery via web browser or email client."
                    Write-Log 'SysmonProcessChain' @{ 
                        ParentProcess = $Parent
                        ChildProcess = $Image
                        CommandLine = $Cmd
                        ProcessId = $ProcessId
                        ParentProcessId = $ParentProcessId
                        EventTime = $evt.TimeCreated
                        SysmonEventId = 1
                        EventSource = 'Sysmon'
                    } 'High' $description 'Sysmon Event ID 1 detected browser/email spawned PowerShell'
                }
                
                # Check for LOLBins
                foreach ($Bin in 'mshta.exe','regsvr32.exe','rundll32.exe','certutil.exe','bitsadmin.exe') {
                    if ($Image -match $Bin -and $Cmd -imatch '-encodedcommand|-url|-addstore|-install|-download') {
                        $suspiciousArgs = if ($Cmd) { ($Cmd | Select-String -Pattern '(-encodedcommand|-url|-addstore|-install|-download)' -AllMatches).Matches.Value -join ', ' } else { 'Unknown' }
                        $description = "[SYSMON] [Sysmon-ID1] DETECTED: Living-off-the-land binary ($Bin) with suspicious arguments: $suspiciousArgs"
                        Write-Log 'SysmonLOLBinUsage' @{ 
                            Binary = $Image
                            ProcessId = $ProcessId
                            FullCommandLine = $Cmd
                            SuspiciousArguments = $suspiciousArgs
                            EventTime = $evt.TimeCreated
                            SysmonEventId = 1
                            EventSource = 'Sysmon'
                        } 'High' $description 'Sysmon Event ID 1 detected LOLBin usage'
                    }
                }
                
                # Check for Office macro execution
                if ($Parent -imatch 'winword.exe|excel.exe' -and $Image -imatch 'wscript.exe|cscript.exe|powershell.exe|dllhost.exe') {
                    $officeApp = ($Parent -split '\\')[-1]
                    $scriptEngine = ($Image -split '\\')[-1]
                    $description = "SYSMON DETECTED: Office application ($officeApp) spawned script interpreter ($scriptEngine). Strong indicator of macro-based malware execution."
                    Write-Log 'SysmonOfficeMacroExec' @{ 
                        OfficeApplication = $Parent
                        SpawnedProcess = $Image
                        ScriptEngine = $scriptEngine
                        CommandLine = $Cmd
                        ProcessId = $ProcessId
                        ParentProcessId = $ParentProcessId  
                        EventTime = $evt.TimeCreated
                        EventSource = 'Sysmon'
                    } 'Critical' $description 'Sysmon detected Office macro execution'
                }
            }
        } catch {
            Write-Log 'SysmonMonitorError' @{ Error=$_.Exception.Message; EventSource = 'Sysmon' } 'Low' "Sysmon monitoring error: $($_.Exception.Message)"
        }
    }
    
    # Register Sysmon monitoring as a periodic job
    $SysmonTimer = New-Object Timers.Timer 3000  # Check every 3 seconds
    $SysmonTimer.AutoReset = $true
    $SysmonTimer.Enabled = $true
    Register-ObjectEvent -InputObject $SysmonTimer -EventName Elapsed -SourceIdentifier 'SysmonMonitor' -Action $SysmonMonitor
} else {
    Write-Host "Registering WMI process monitoring..." -ForegroundColor Green
    Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -SourceIdentifier 'WMIProc' -Action {
        try {
            $P = Get-CimInstance Win32_Process -Filter "ProcessId=$($Event.NewEvent.ProcessId)" -ErrorAction SilentlyContinue
            if (-not $P) { return }
            
            $Parent = try { Get-CimInstance Win32_Process -Filter "ProcessId=$($P.ParentProcessId)" -ErrorAction SilentlyContinue } catch { $null }
            $Image = $P.Name; $Cmd = $P.CommandLine
            
            # Debug: Log all process creation for troubleshooting
            Write-Log 'ProcessCreated' @{
                ProcessName = $Image
                ProcessID = $P.ProcessId
                CommandLine = $Cmd
                ParentName = if ($Parent) { $Parent.Name } else { 'Unknown' }
                ParentPID = if ($Parent) { $Parent.ProcessId } else { 0 }
            } 'Low' "Process created: $Image" 'WMI process monitoring'
            
            if ($Image -imatch 'powershell.exe' -and $Parent -and $Parent.Name -imatch 'chrome|firefox|msedge|outlook|thunderbird|winword|excel') {
                $parentApp = $Parent.Name
                $description = "Suspicious PowerShell execution spawned from $parentApp. This could indicate a malicious script or exploit delivery via web browser or email client."
                Write-Log 'SuspiciousProcessChain' @{ 
                    ParentProcess = $Parent.Name
                    ParentPID = $Parent.ProcessId
                    ChildProcess = $Image
                    ChildPID = $P.ProcessId
                    CommandLine = $Cmd
                    ProcessCreationTime = (Get-Date).ToString('o')
                } 'High' $description 'Process spawned from browser/email client'
            }
            
            foreach ($Bin in 'mshta.exe','regsvr32.exe','rundll32.exe','certutil.exe','bitsadmin.exe') {
                if ($Image -ieq $Bin -and $Cmd -imatch '-encodedcommand|-url|-addstore|-install|-download') {
                    $suspiciousArgs = if ($Cmd) { ($Cmd | Select-String -Pattern '(-encodedcommand|-url|-addstore|-install|-download)' -AllMatches).Matches.Value -join ', ' } else { 'Unknown' }
                    $description = "Living-off-the-land binary ($Bin) detected with suspicious arguments: $suspiciousArgs. This technique is commonly used to evade detection while executing malicious payloads."
                    Write-Log 'LOLBinUsage' @{ 
                        Binary = $Image
                        ProcessID = $P.ProcessId
                        FullCommandLine = $Cmd
                        SuspiciousArguments = $suspiciousArgs
                        WorkingDirectory = $P.ExecutablePath
                    } 'High' $description 'Living-off-the-land binary with suspicious args'
                }
            }
            
            if ($Parent -and $Parent.Name -imatch 'winword.exe|excel.exe' -and $Image -imatch 'wscript.exe|cscript.exe|powershell.exe|dllhost.exe') {
                $officeApp = $Parent.Name
                $scriptEngine = $Image
                $description = "Office application ($officeApp) spawned script interpreter ($scriptEngine). This is a strong indicator of macro-based malware execution."
                Write-Log 'OfficeMacroExec' @{ 
                    OfficeApplication = $Parent.Name
                    OfficePID = $Parent.ProcessId
                    SpawnedProcess = $Image
                    SpawnedPID = $P.ProcessId
                    ScriptEngine = $scriptEngine
                    CommandLine = $Cmd
                } 'Critical' $description 'Office app spawned script interpreter'
            }
        } catch {
            Write-Log 'ProcessMonitorError' @{ Error=$_.Exception.Message }
        }
    }
}

# 2. REGISTRY PERSISTENCE: Run keys via periodic snapshot
$RunPaths = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
function Get-RunEntries {
    $entries = @{}
    foreach ($p in $RunPaths) {
        try {
            if (Test-Path $p) {
                $props = (Get-ItemProperty -Path $p -ErrorAction Stop).PSObject.Properties.Name | Where-Object { $_ -notmatch '^PS' }
                foreach ($name in $props) { 
                    $value = (Get-ItemProperty -Path $p -Name $name -ErrorAction SilentlyContinue).$name
                    if ($value) { $entries["$p::$name"] = $value }
                }
            }
        } catch {}
    }
    return $entries
}

$script:PrevRun = Get-RunEntries
$RegTimer = New-Object Timers.Timer 5000
$RegTimer.AutoReset = $true
$RegTimer.Enabled = $true
Register-ObjectEvent -InputObject $RegTimer -EventName Elapsed -SourceIdentifier 'RegScan' -Action {
    try {
        $CurrRun = Get-RunEntries
        $added = $CurrRun.Keys | Where-Object { -not $script:PrevRun.ContainsKey($_) }
        foreach ($key in $added) { 
            $keyPath = $key -split '::'
            $regPath = $keyPath[0]
            $valueName = $keyPath[1]
            $value = $CurrRun[$key]
            
            $description = "New registry Run key persistence detected at $regPath. Value '$valueName' set to '$value'. This is a common persistence mechanism used by malware to maintain access."
            $riskIndicators = @()
            
            # Risk assessment
            if ($value -imatch '\.tmp|temp|appdata\\local\\temp') { $riskIndicators += 'Temporary directory execution' }
            if ($value -imatch 'powershell|cmd\.exe|wscript|cscript') { $riskIndicators += 'Script interpreter usage' }
            if ($value -imatch '-enc|-hidden|-bypass|-exec') { $riskIndicators += 'Suspicious command line arguments' }
            if ($value -imatch 'http|ftp|download') { $riskIndicators += 'Network activity indicators' }
            
            $severity = if ($riskIndicators.Count -gt 2) { 'Critical' } elseif ($riskIndicators.Count -gt 0) { 'High' } else { 'Medium' }
            $severityReason = if ($riskIndicators.Count -gt 0) { "$($riskIndicators.Count) risk indicators found" } else { 'Standard registry persistence' }
            
            Write-Log 'RegistryRunKeySet' @{ 
                RegistryPath = $regPath
                ValueName = $valueName
                ValueData = $value
                RiskIndicators = $riskIndicators
                UserContext = if ($regPath -like '*HKCU*') { 'Current User' } else { 'All Users' }
                DetectionTime = (Get-Date).ToString('o')
            } $severity $description $severityReason
        }
        $script:PrevRun = $CurrRun
    } catch {
        Write-Log 'RegistryMonitorError' @{ Error=$_.Exception.Message }
    }
}

# 3. SCHEDULED TASKS: FileSystemWatcher with fallback
$TaskFolder = "$env:windir\System32\Tasks"
if (Test-Path $TaskFolder) {
    try {
        $FSW = New-Object IO.FileSystemWatcher $TaskFolder
        $FSW.Filter = "*"
        $FSW.IncludeSubdirectories = $false
        $FSW.EnableRaisingEvents = $true
        Register-ObjectEvent -InputObject $FSW -EventName Created -SourceIdentifier 'TaskCreation' -Action {
            $taskName = $Event.SourceEventArgs.Name
            $taskPath = $Event.SourceEventArgs.FullPath
            $description = "New scheduled task file created: $taskName. Scheduled tasks are commonly used by attackers for persistence and privilege escalation."
            
            # Try to read task details if possible
            $taskDetails = @{
                TaskName = $taskName
                TaskPath = $taskPath
                CreationTime = (Get-Date).ToString('o')
                FileSize = if (Test-Path $taskPath) { (Get-Item $taskPath).Length } else { 'Unknown' }
            }
            
            Write-Log 'ScheduledTaskCreated' $taskDetails 'Medium' $description 'Scheduled task file detected'
        }
    } catch {
        # Fallback to periodic scanning
        $script:ExistingTasks = Get-ChildItem -Path $TaskFolder -Name -ErrorAction SilentlyContinue
        $TaskTimer = New-Object Timers.Timer 5000
        $TaskTimer.AutoReset = $true
        $TaskTimer.Enabled = $true
        Register-ObjectEvent -InputObject $TaskTimer -EventName Elapsed -SourceIdentifier 'TaskScan' -Action {
            try {
                $CurrTasks = Get-ChildItem -Path $TaskFolder -Name -ErrorAction SilentlyContinue
                if ($script:ExistingTasks -and $CurrTasks) {
                    $added = Compare-Object -ReferenceObject $script:ExistingTasks -DifferenceObject $CurrTasks | Where-Object SideIndicator -eq '=>' | Select-Object -ExpandProperty InputObject
                    foreach ($t in $added) { 
                        $taskPath = Join-Path $TaskFolder $t
                        $description = "New scheduled task file detected: $t. Scheduled tasks are commonly used by attackers for persistence and privilege escalation."
                        Write-Log 'ScheduledTaskCreated' @{
                            TaskName = $t
                            TaskPath = $taskPath
                            DetectionMethod = 'Periodic Scan'
                            CreationTime = (Get-Date).ToString('o')
                            FileSize = if (Test-Path $taskPath) { (Get-Item $taskPath).Length } else { 'Unknown' }
                        } 'Medium' $description 'Scheduled task detected via scan'
                    }
                }
                $script:ExistingTasks = $CurrTasks
            } catch {
                Write-Log 'TaskMonitorError' @{ Error=$_.Exception.Message }
            }
        }
    }
}

# 4. USB Autorun & Device Arrival
Register-WmiEvent -Class Win32_VolumeChangeEvent -SourceIdentifier 'USBDetect' -Action {
    try {
        $Drive = $Event.NewEvent.DriveName
        if ($Drive -and (Test-Path (Join-Path $Drive 'autorun.inf'))) {
            $autorunPath = Join-Path $Drive 'autorun.inf'
            $autorunContent = if (Test-Path $autorunPath) { Get-Content $autorunPath -Raw -ErrorAction SilentlyContinue } else { 'Unable to read' }
            $description = "USB device with autorun.inf detected on drive $Drive. This could be an attempt to execute malicious code automatically when the device is accessed."
            
            Write-Log 'USB_Autorun_Detected' @{ 
                DriveLetter = $Drive
                AutorunPath = $autorunPath
                AutorunContent = $autorunContent
                DetectionTime = (Get-Date).ToString('o')
                VolumeLabel = (Get-Volume -DriveLetter $Drive.Replace(':','') -ErrorAction SilentlyContinue).FileSystemLabel
            } 'High' $description 'USB with autorun.inf detected'
        }
    } catch {
        Write-Log 'USBMonitorError' @{ Error=$_.Exception.Message }
    }
}

# Track existing USB devices to detect new arrivals
$script:ExistingUSBDevices = Get-PnpDevice -Class USB -Status OK | Where-Object { $_.InstanceId -match '^USB' } | Select-Object -ExpandProperty InstanceId
Register-WmiEvent -Class Win32_DeviceChangeEvent -SourceIdentifier 'USBDeviceArrival' -Action {
    try {
        if ($Event.NewEvent.EventType -eq 2) {
            $CurrentUSBDevices = Get-PnpDevice -Class USB -Status OK | Where-Object { $_.InstanceId -match '^USB' }
            $NewDevices = $CurrentUSBDevices | Where-Object { $_.InstanceId -notin $script:ExistingUSBDevices }
            foreach ($device in $NewDevices) {
                $description = "New USB device connected: $($device.FriendlyName). Monitor for potential data exfiltration or malware introduction."
                $deviceInfo = @{
                    DeviceName = $device.FriendlyName
                    DeviceID = $device.InstanceId
                    DeviceClass = $device.Class
                    DeviceStatus = $device.Status
                    ConnectionTime = (Get-Date).ToString('o')
                    HardwareID = $device.HardwareID -join '; '
                }
                
                # Enhanced risk assessment for USB devices
                $riskLevel = 'Low'
                $riskReason = 'Standard USB device'
                if ($device.FriendlyName -imatch 'mass storage|disk|drive') { 
                    $riskLevel = 'Medium'
                    $riskReason = 'Storage device detected'
                }
                if ($device.FriendlyName -imatch 'unknown|generic') { 
                    $riskLevel = 'High'
                    $riskReason = 'Unknown/generic device'
                }
                
                Write-Log 'USB_DeviceConnected' $deviceInfo $riskLevel $description $riskReason
            }
            $script:ExistingUSBDevices = $CurrentUSBDevices | Select-Object -ExpandProperty InstanceId
        }
    } catch {
        Write-Log 'USBDeviceMonitorError' @{ Error=$_.Exception.Message }
    }
}

# 5. BUILT-IN ACCOUNT LOGONS (4624/4625) via WinEvent only if available
if ($HasWinEvent) {
    Write-Host "Registering Security event monitoring..." -ForegroundColor Green
    
    $SecurityMonitor = {
        try {
            # Check recent logon events
            $events = Get-WinEvent -LogName 'Security' -FilterXPath "*[System[(EventID=4624 or EventID=4625)]]" -MaxEvents 5 -ErrorAction SilentlyContinue
            foreach ($evt in $events) {
                $xml = [xml]$evt.ToXml()
                $eventData = $xml.Event.EventData.Data
                
                $Account = ($eventData | Where-Object Name -eq 'TargetUserName').'#text'
                $LogonType = ($eventData | Where-Object Name -eq 'LogonType').'#text'
                $WorkstationName = ($eventData | Where-Object Name -eq 'WorkstationName').'#text'
                $SourceIP = ($eventData | Where-Object Name -eq 'IpAddress').'#text'
                
                if ($Account -imatch 'Administrator|Guest|root') {
                    $eventType = if ($evt.Id -eq 4624) { 'Successful Logon' } else { 'Failed Logon' }
                    $description = "SECURITY LOG: $eventType attempt for built-in account '$Account' from $WorkstationName (IP: $SourceIP). Built-in account usage often indicates reconnaissance or privilege escalation attempts."
                    
                    Write-Log 'SecurityLogonEvent' @{ 
                        Account = $Account
                        EventID = $evt.Id
                        EventType = $eventType
                        LogonType = $LogonType
                        Workstation = $WorkstationName
                        SourceIP = $SourceIP
                        EventTime = $evt.TimeCreated
                        EventSource = 'Security Log'
                    } 'High' $description 'Security log detected suspicious logon'
                }
            }
        } catch {
            Write-Log 'SecurityMonitorError' @{ Error=$_.Exception.Message; EventSource = 'Security Log' } 'Low' "Security event monitoring error: $($_.Exception.Message)"
        }
    }
    
    # Register Security log monitoring
    $SecurityTimer = New-Object Timers.Timer 10000  # Check every 10 seconds
    $SecurityTimer.AutoReset = $true
    $SecurityTimer.Enabled = $true
    Register-ObjectEvent -InputObject $SecurityTimer -EventName Elapsed -SourceIdentifier 'SecurityMonitor' -Action $SecurityMonitor
}

# 6. SUSPICIOUS PORT LISTENERS
$NetTimer = New-Object Timers.Timer 30000
$NetTimer.AutoReset = $true
$NetTimer.Enabled = $true
Register-ObjectEvent -InputObject $NetTimer -EventName Elapsed -SourceIdentifier 'NetPortScan' -Action {
    try {
        # Detect any listening TCP ports of interest
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in 21,22,23,80,443,3389 }
        foreach ($conn in $listeners) {
            $processInfo = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $processName = if ($processInfo) { $processInfo.ProcessName } else { 'Unknown' }
            $processPath = if ($processInfo) { $processInfo.Path } else { 'Unknown' }
            
            $portDescription = switch ($conn.LocalPort) {
                21 { 'FTP Service' }
                22 { 'SSH Service' }
                23 { 'Telnet Service' }
                80 { 'HTTP Web Service' }
                443 { 'HTTPS Web Service' }
                3389 { 'Remote Desktop Service' }
                default { 'Unknown Service' }
            }
            
            $description = "Suspicious port listener detected: $portDescription (Port $($conn.LocalPort)) owned by process $processName (PID: $($conn.OwningProcess)). Unexpected services may indicate backdoor or C2 communications."
            
            Write-Log 'SuspiciousPortListener' @{ 
                Port = $conn.LocalPort
                ProcessID = $conn.OwningProcess
                ProcessName = $processName
                ProcessPath = $processPath
                LocalAddress = $conn.LocalAddress
                ServiceType = $portDescription
                ConnectionState = $conn.State
                DetectionTime = (Get-Date).ToString('o')
            } 'Medium' $description 'Unexpected network service detected'
        }
    } catch {
        Write-Log 'NetworkMonitorError' @{ Error=$_.Exception.Message }
    }
}

# Log script startup
Write-Log 'MonitorStartup' @{ 
    HasSysmon=$HasSysmon; 
    HasWinEvent=$HasWinEvent; 
    Timestamp=(Get-Date).ToString('o')
    EventSubscribers=(Get-EventSubscriber).Count
} 'Medium' 'Security monitoring script started' 'System initialization'

Write-Host "Active Event Subscribers: $((Get-EventSubscriber).Count)" -ForegroundColor Green
Get-EventSubscriber | ForEach-Object { Write-Host "  - $($_.SourceIdentifier)" -ForegroundColor Gray }

# Keep the script running indefinitely
while ($true) { Start-Sleep -Seconds 30 }