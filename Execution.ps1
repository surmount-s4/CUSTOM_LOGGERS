#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Execution Tactics Logger using Sysmon and Windows Event Logs - Windows Server 2012 Compatible
.DESCRIPTION
    Monitors and logs Execution techniques using Sysmon events and Windows Security logs
    Compatible with PowerShell 3.0+ and Windows Server 2012
.PARAMETER OutputPath
    Path where log files will be stored
.PARAMETER LogLevel
    Logging level (Info, Warning, Critical)
.PARAMETER MonitorDuration
    Duration in minutes to monitor (0 = continuous)
.PARAMETER RefreshInterval
    Interval in seconds between monitoring checks (default: 30)
#>

param(
    [string]$OutputPath = "$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS",
    [ValidateSet("Info", "Warning", "Critical")]
    [string]$LogLevel = "Info",
    [int]$MonitorDuration = 0,
    [int]$RefreshInterval = 30
)

# Global variables
$Script:LogFile = ""
$Script:StartTime = Get-Date
$Script:EventCounters = @{}
$Script:LastEventTime = Get-Date

# Initialize logging
function Initialize-Logger {
    param([string]$Path)
    
    if (!(Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:LogFile = Join-Path $Path "Execution_$timestamp.log"
    
    # Write initial log header without verbose console output
    $headerInfo = @"
=== Execution Logger Started ===
Start Time: $(Get-Date)
PowerShell Version: $($PSVersionTable.PSVersion)
OS: $((Get-WmiObject Win32_OperatingSystem).Caption)
Log File: $Script:LogFile
================================
"@
    Add-Content -Path $Script:LogFile -Value $headerInfo
}

# Write log entries - Windows Server 2012 compatible with enhanced field support
function Write-LogEntry {
    param(
        [string]$Level,
        [string]$Message,
        [string]$EventID = "",
        [string]$ProcessName = "",
        [string]$CommandLine = "",
        [string]$Technique = "",
        [string]$TargetFilename = "",
        [string]$ProcessId = "",
        [string]$User = "",
        [string]$ProcessGuid = "",
        [string]$Hashes = "",
        [string]$AdditionalFields = ""
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if ($EventID) { $logEntry += " | EventID: $EventID" }
    if ($ProcessName) { $logEntry += " | Process: $ProcessName" }
    if ($ProcessId) { $logEntry += " | PID: $ProcessId" }
    if ($User) { $logEntry += " | User: $User" }
    if ($CommandLine) { $logEntry += " | CommandLine: $CommandLine" }
    if ($TargetFilename) { $logEntry += " | TargetFile: $TargetFilename" }
    if ($ProcessGuid) { $logEntry += " | GUID: $ProcessGuid" }
    if ($Hashes) { $logEntry += " | Hashes: $Hashes" }
    if ($Technique) { $logEntry += " | Technique: $Technique" }
    if ($AdditionalFields) { $logEntry += " | Additional: $AdditionalFields" }
    
    # Write to console based on log level setting
    if ($Level -eq "CRITICAL" -or ($Level -eq "WARNING" -and $LogLevel -in @("Info", "Warning")) -or $LogLevel -eq "Info") {
        switch ($Level) {
            "CRITICAL" { Write-Host $logEntry -ForegroundColor Red }
            "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
            default { Write-Host $logEntry -ForegroundColor Green }
        }
    }
    
    # Write to file
    Add-Content -Path $Script:LogFile -Value $logEntry
    
    # Update counters - PowerShell 3.0 compatible
    if ($Technique) {
        if ($Script:EventCounters.ContainsKey($Technique)) {
            $Script:EventCounters[$Technique] = $Script:EventCounters[$Technique] + 1
        } else {
            $Script:EventCounters[$Technique] = 1
        }
    }
    
    $Script:LastEventTime = Get-Date
}

# Check if Sysmon is available
function Test-SysmonAvailable {
    try {
        $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
        if ($sysmonService -and $sysmonService.Status -eq "Running") {
            return $true
        }
        
        # Test if we can query Sysmon log
        $null = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Get events with error handling for Windows Server 2012
function Get-EventsSecure {
    param(
        [string]$LogName,
        [hashtable]$FilterHashtable = @{},
        [int]$MaxEvents = 50
    )
    
    try {
        # Windows Server 2012 compatible event filtering
        if ($FilterHashtable.Count -gt 0) {
            return Get-WinEvent -FilterHashtable $FilterHashtable -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        } else {
            return Get-WinEvent -LogName $LogName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        }
    } catch {
        Write-LogEntry "WARNING" "Failed to retrieve events from $LogName : $($_.Exception.Message)"
        return @()
    }
}

# Parse event data - Windows Server 2012 compatible
function Get-EventData {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)
    
    try {
        $eventXML = [xml]$Event.ToXml()
        $eventData = @{}
        
        # Extract data fields
        if ($eventXML.Event.EventData.Data) {
            foreach ($data in $eventXML.Event.EventData.Data) {
                if ($data.Name) {
                    $eventData[$data.Name] = $data.'#text'
                }
            }
        }
        
        return $eventData
    } catch {
        return @{}
    }
}

# Monitor Execution - T1059 Command and Scripting Interpreter
function Monitor-CommandScriptingInterpreter {
    param([array]$Events)
    
    $scriptInterpreters = @(
        "powershell\.exe",
        "pwsh\.exe", 
        "cmd\.exe",
        "wscript\.exe",
        "cscript\.exe",
        "python\.exe",
        "node\.exe"
    )
    
    $suspiciousArgs = @(
        "-encodedcommand",
        "-enc",
        "-nop",
        "-w hidden",
        "-windowstyle hidden",
        "bypass",
        "iex",
        "invoke-expression",
        "downloadstring",
        "frombase64string",
        "reflection.assembly"
    )
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $image = $eventData["Image"]
        $commandLine = $eventData["CommandLine"]
        $parentImage = $eventData["ParentImage"]
        $processId = $eventData["ProcessId"]
        $user = $eventData["User"]
        $processGuid = $eventData["ProcessGuid"]
        $hashes = $eventData["Hashes"]
        
        # Check for script interpreter execution
        foreach ($interpreter in $scriptInterpreters) {
            if ($image -match $interpreter) {
                $detected = $false
                $matchedArgs = @()
                
                # Check for suspicious arguments
                foreach ($arg in $suspiciousArgs) {
                    if ($commandLine -match $arg) {
                        $detected = $true
                        $matchedArgs += $arg
                    }
                }
                
                if ($detected) {
                    Write-LogEntry "WARNING" "Suspicious script interpreter execution detected" `
                        -EventID "1" -ProcessName $image -CommandLine $commandLine -Technique "T1059" `
                        -ProcessId $processId -User $user -ProcessGuid $processGuid -Hashes $hashes `
                        -AdditionalFields "Parent: $parentImage, SuspiciousArgs: $($matchedArgs -join ', ')"
                }
            }
        }
    }
}

# Monitor Execution - T1203 Exploitation for Client Execution
function Monitor-ClientExecution {
    param([array]$Events)
    
    $officeApps = @("winword\.exe", "excel\.exe", "powerpnt\.exe", "acrord32\.exe", "acrobat\.exe")
    $browserApps = @("chrome\.exe", "firefox\.exe", "msedge\.exe", "iexplore\.exe")
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $image = $eventData["Image"]
        $parentImage = $eventData["ParentImage"]
        $commandLine = $eventData["CommandLine"]
        $processId = $eventData["ProcessId"]
        
        # Detect child processes of office applications
        foreach ($office in $officeApps) {
            if ($parentImage -match $office) {
                if ($image -match "powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe|dllhost\.exe") {
                    Write-LogEntry "CRITICAL" "Office application spawned suspicious process" `
                        -EventID "1" -ProcessName $image -CommandLine $commandLine -Technique "T1203" `
                        -ProcessId $processId -AdditionalFields "OfficeApp: $parentImage"
                }
            }
        }
        
        # Detect child processes of browser applications
        foreach ($browser in $browserApps) {
            if ($parentImage -match $browser) {
                if ($image -match "powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe") {
                    Write-LogEntry "WARNING" "Browser spawned suspicious process" `
                        -EventID "1" -ProcessName $image -CommandLine $commandLine -Technique "T1203" `
                        -ProcessId $processId -AdditionalFields "Browser: $parentImage"
                }
            }
        }
    }
}

# Monitor Execution - T1218 System Binary Proxy Execution
function Monitor-SystemBinaryProxyExecution {
    param([array]$Events)
    
    $lolbins = @{
        "mshta\.exe" = @("http", "javascript", "vbscript", "\.hta")
        "rundll32\.exe" = @("javascript", "regsvr32", "comctl32", "shell32")
        "regsvr32\.exe" = @("/i", "/n", "/s", "scrobj\.dll", "http")
        "certutil\.exe" = @("-decode", "-decodehex", "-urlcache", "-split", "-encode")
        "bitsadmin\.exe" = @("/transfer", "/download", "http")
        "wmic\.exe" = @("process call create", "/format:")
        "msbuild\.exe" = @("\.xml", "\.csproj", "\.proj")
        "installutil\.exe" = @("/logfile", "/logtoconsole", "\.exe")
        "regasm\.exe" = @("/u", "\.dll")
        "regsvcs\.exe" = @("/u", "\.dll")
    }
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $image = $eventData["Image"]
        $commandLine = $eventData["CommandLine"]
        $processId = $eventData["ProcessId"]
        $user = $eventData["User"]
        
        foreach ($binary in $lolbins.Keys) {
            if ($image -match $binary) {
                $suspicious = $false
                $matchedIndicators = @()
                
                foreach ($indicator in $lolbins[$binary]) {
                    if ($commandLine -match $indicator) {
                        $suspicious = $true
                        $matchedIndicators += $indicator
                    }
                }
                
                if ($suspicious) {
                    Write-LogEntry "WARNING" "Living-off-the-land binary execution detected" `
                        -EventID "1" -ProcessName $image -CommandLine $commandLine -Technique "T1218" `
                        -ProcessId $processId -User $user `
                        -AdditionalFields "MatchedIndicators: $($matchedIndicators -join ', ')"
                }
            }
        }
    }
}

# Monitor Execution - T1204 User Execution
function Monitor-UserExecution {
    param([array]$Events)
    
    foreach ($event in $Events) {
        $eventData = Get-EventData -Event $event
        $image = $eventData["Image"]
        $commandLine = $eventData["CommandLine"]
        $processId = $eventData["ProcessId"]
        $user = $eventData["User"]
        
        # Monitor execution from temp/downloads directories
        if ($image -match "\\Temp\\|\\Downloads\\|\\AppData\\Local\\Temp\\") {
            Write-LogEntry "WARNING" "Process executed from temporary directory" `
                -EventID "1" -ProcessName $image -CommandLine $commandLine -Technique "T1204" `
                -ProcessId $processId -User $user -AdditionalFields "Location: Temporary Directory"
        }
        
        # Monitor files with double extensions
        if ($image -match "\.(pdf|doc|docx|xls|xlsx|txt)\.(exe|scr|com|bat)$") {
            Write-LogEntry "CRITICAL" "Execution of file with double extension" `
                -EventID "1" -ProcessName $image -CommandLine $commandLine -Technique "T1204" `
                -ProcessId $processId -User $user -AdditionalFields "DoubleExtension: True"
        }
    }
}

# Monitor Process Creation Events from Security Log
function Monitor-SecurityProcessCreation {
    param([array]$SecurityEvents)
    
    foreach ($event in $SecurityEvents) {
        if ($event.Id -eq 4688) {
            $eventData = Get-EventData -Event $event
            $newProcessName = $eventData["NewProcessName"]
            $commandLine = $eventData["CommandLine"]
            $subjectUserName = $eventData["SubjectUserName"]
            $processId = $eventData["NewProcessId"]
            
            # Log high-value process creation
            if ($newProcessName -match "powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe") {
                Write-LogEntry "INFO" "Script interpreter process created (Security Log)" `
                    -EventID "4688" -ProcessName $newProcessName -CommandLine $commandLine `
                    -User $subjectUserName -ProcessId $processId -Technique "T1059"
            }
        }
    }
}

# Print summary statistics
function Show-Summary {
    Write-Host "`n=== Execution Monitoring Summary ===" -ForegroundColor Cyan
    Write-Host "Monitoring Duration: $([math]::Round(((Get-Date) - $Script:StartTime).TotalMinutes, 2)) minutes" -ForegroundColor White
    Write-Host "Last Event Time: $($Script:LastEventTime)" -ForegroundColor White
    Write-Host "Log File: $Script:LogFile" -ForegroundColor White
    
    if ($Script:EventCounters.Count -gt 0) {
        Write-Host "`nDetected Techniques:" -ForegroundColor Yellow
        foreach ($technique in $Script:EventCounters.Keys | Sort-Object) {
            Write-Host "  $technique : $($Script:EventCounters[$technique]) events" -ForegroundColor White
        }
    } else {
        Write-Host "`nNo suspicious activities detected." -ForegroundColor Green
    }
    Write-Host "====================================`n" -ForegroundColor Cyan
}

# Main monitoring function
function Start-ExecutionMonitoring {
    Initialize-Logger -Path $OutputPath
    Write-LogEntry "INFO" "Execution monitoring started"
    
    $sysmonAvailable = Test-SysmonAvailable
    Write-LogEntry "INFO" "Sysmon available: $sysmonAvailable"
    
    Write-Host "Execution Live Monitor v1.0 (Server 2012 Compatible)" -ForegroundColor Cyan
    Write-Host "Sysmon Available: $sysmonAvailable" -ForegroundColor $(if ($sysmonAvailable) { "Green" } else { "Yellow" })
    Write-Host "Press Ctrl+C to stop monitoring`n" -ForegroundColor Gray
    
    $endTime = if ($MonitorDuration -gt 0) { (Get-Date).AddMinutes($MonitorDuration) } else { [DateTime]::MaxValue }
    
    try {
        while ((Get-Date) -lt $endTime) {
            try {
                # Monitor Sysmon events if available
                if ($sysmonAvailable) {
                    # Process Creation (Event ID 1)
                    $processEvents = Get-EventsSecure -FilterHashtable @{
                        LogName = "Microsoft-Windows-Sysmon/Operational"
                        ID = 1
                        StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                    } -MaxEvents 100
                    
                    if ($processEvents) {
                        Monitor-CommandScriptingInterpreter -Events $processEvents
                        Monitor-ClientExecution -Events $processEvents
                        Monitor-SystemBinaryProxyExecution -Events $processEvents
                        Monitor-UserExecution -Events $processEvents
                    }
                }
                
                # Monitor Security events for process creation
                $securityEvents = Get-EventsSecure -FilterHashtable @{
                    LogName = "Security"
                    ID = 4688
                    StartTime = $Script:LastEventTime.AddSeconds(-$RefreshInterval)
                } -MaxEvents 100
                
                if ($securityEvents) {
                    Monitor-SecurityProcessCreation -SecurityEvents $securityEvents
                }
                
            } catch {
                Write-LogEntry "WARNING" "Error in monitoring cycle: $($_.Exception.Message)"
            }
            
            Start-Sleep -Seconds $RefreshInterval
        }
    } catch {
        Write-LogEntry "CRITICAL" "Monitoring stopped due to error: $($_.Exception.Message)"
    }
    
    Show-Summary
    Write-LogEntry "INFO" "Execution monitoring stopped"
}

# Handle Ctrl+C gracefully
$null = Register-ObjectEvent -InputObject ([Console]) -EventName "CancelKeyPress" -Action {
    Write-Host "`n`nStopping Execution monitoring..." -ForegroundColor Yellow
    Show-Summary
    Write-LogEntry "INFO" "Execution monitoring stopped by user"
    exit
}

# Start monitoring
Start-ExecutionMonitoring
