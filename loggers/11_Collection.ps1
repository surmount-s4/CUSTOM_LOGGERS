#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Collection Tactics Live Monitor v2.0 - MITRE ATT&CK Collection Techniques for OT Environments
.DESCRIPTION
    Real-time monitoring and logging of Collection techniques using Sysmon events and Windows Security logs
    Enhanced with DefenseEvasion.ps1-style logging architecture and live monitoring capabilities
    Compatible with PowerShell 3.0+ and Windows Server 2012+
.PARAMETER OutputPath
    Path where log files will be stored
.PARAMETER LogLevel
    Logging level (INFO, WARNING, CRITICAL, ERROR)
.PARAMETER MonitorDuration
    Duration in minutes to monitor (0 = continuous)
.PARAMETER RefreshInterval
    Interval in seconds between monitoring checks (default: 30)
.NOTES
    Monitors: T1005, T1039, T1025, T1113, T1125, T1123, T1115, T1056, T1560, T1074, T1119
#>

param(
    [string]$OutputPath = "C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS",
    [ValidateSet("INFO", "WARNING", "CRITICAL", "ERROR")]
    [string]$LogLevel = "INFO",
    [int]$MonitorDuration = 0,
    [int]$RefreshInterval = 30
)

# Global variables
$Script:LogFile = ""
$Script:EventCounters = @{}
$Script:StartTime = Get-Date
$Script:LastEventTime = (Get-Date).AddMinutes(-10)

# Enhanced logging initialization
function Initialize-Logger {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:LogFile = Join-Path $Path "Collection_$timestamp.log"
    
    $header = @"
=== Collection Tactics Live Monitor Started at $(Get-Date) ===
PowerShell Version: $($PSVersionTable.PSVersion)
OS: $([System.Environment]::OSVersion.VersionString)
User: $([System.Environment]::UserName)
Log Level: $LogLevel
Monitor Duration: $(if ($MonitorDuration -eq 0) { "Continuous" } else { "$MonitorDuration minutes" })
Refresh Interval: $RefreshInterval seconds
=== Collection Techniques Monitored ===
T1005 - Data from Local System
T1039 - Data from Network Shared Drive  
T1025 - Data from Removable Media
T1113 - Screen Capture
T1125 - Video Capture
T1123 - Audio Capture
T1115 - Clipboard Data
T1056 - Input Capture
T1560 - Archive Collected Data
T1074 - Data Staged
T1119 - Automated Collection
==========================================

"@
    
    Add-Content -Path $Script:LogFile -Value $header -Encoding UTF8
}

# Enhanced logging function with multiple field support
function Write-LogEntry {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("INFO", "WARNING", "CRITICAL", "ERROR")]
        [string]$Level,
        
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [string]$EventID = "",
        [string]$ProcessName = "",
        [string]$CommandLine = "",
        [string]$Technique = "",
        [string]$User = "",
        [string]$TargetFile = "",
        [string]$ProcessId = ""
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Build enhanced log entry with all available fields
    $logFields = @()
    $logFields += "Timestamp: $timestamp"
    $logFields += "Level: $Level"
    $logFields += "Message: $Message"
    
    if ($EventID) { $logFields += "EventID: $EventID" }
    if ($ProcessName) { $logFields += "ProcessName: $ProcessName" }
    if ($CommandLine) { $logFields += "CommandLine: $CommandLine" }
    if ($Technique) { $logFields += "Technique: $Technique" }
    if ($User) { $logFields += "User: $User" }
    if ($TargetFile) { $logFields += "TargetFile: $TargetFile" }
    if ($ProcessId) { $logFields += "ProcessID: $ProcessId" }
    
    $logEntry = $logFields -join " | "
    
    # Write to log file
    Add-Content -Path $Script:LogFile -Value $logEntry -Encoding UTF8
    
    # Console output with color coding
    $color = switch ($Level) {
        "INFO" { "White" }
        "WARNING" { "Yellow" }  
        "CRITICAL" { "Red" }
        "ERROR" { "Red" }
        default { "Gray" }
    }
    
    Write-Host $logEntry -ForegroundColor $color
    
    # Update counters for tracking
    if ($Technique) {
        if ($Script:EventCounters.ContainsKey($Technique)) {
            $Script:EventCounters[$Technique]++
        } else {
            $Script:EventCounters[$Technique] = 1
        }
    }
}

# Check if Sysmon is installed and running
function Test-SysmonInstalled {
    try {
        $service = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
        return ($service -and $service.Status -eq "Running")
    } catch {
        return $false
    }
}

# Safe event retrieval with error handling
function Get-EventsSafe {
    param(
        [string]$LogName,
        [int[]]$EventIDs,
        [datetime]$StartTime
    )
    
    try {
        $events = @()
        foreach ($eventId in $EventIDs) {
            $eventList = Get-WinEvent -FilterHashtable @{
                LogName = $LogName
                ID = $eventId
                StartTime = $StartTime
            } -ErrorAction SilentlyContinue -MaxEvents 100
            
            if ($eventList) {
                $events += $eventList
            }
        }
        return $events | Sort-Object TimeCreated -Descending
    } catch {
        return @()
    }
}

# Extract event data from XML
function Get-EventData {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)
    
    try {
        $eventXML = [xml]$Event.ToXml()
        $eventData = @{}
        
        foreach ($data in $eventXML.Event.EventData.Data) {
            if ($data.Name) {
                $eventData[$data.Name] = $data.'#text'
            }
        }
        
        return $eventData
    } catch {
        return @{}
    }
}

# Monitor for Data from Local System (T1005)
function Monitor-DataFromLocalSystem {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for data collection patterns
                $dataCollectionPatterns = @(
                    "xcopy.*\/s|robocopy.*\/s|copy.*\*\.",
                    "findstr.*\/s.*\.txt|findstr.*\/s.*\.doc",
                    "dir.*\/s.*\.log|dir.*\/s.*\.txt|dir.*\/s.*\.doc",
                    "Get-ChildItem.*-Recurse.*\.(txt|doc|pdf|xls)",
                    "Select-String.*-Path.*-Pattern"
                )
                
                foreach ($pattern in $dataCollectionPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "WARNING" "Potential local data collection detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1005 - Data from Local System"
                        break
                    }
                }
            }
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                # Monitor for sensitive file access
                if ($targetFilename -match "\\Users\\.*\\Documents|\\Users\\.*\\Desktop|\\ProgramData\\.*\.log|\\Windows\\System32\\config") {
                    Write-LogEntry "INFO" "Access to sensitive local data location" -EventID $event.Id -ProcessName $eventData.Image -TargetFile $targetFilename -Technique "T1005 - Data from Local System"
                }
            }
        }
    }
}

# Monitor for Data from Network Shared Drive (T1039)
function Monitor-DataFromNetworkSharedDrive {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for network share access patterns
                if ($commandLine -match "\\\\[^\\]+\\|net use|pushd \\\\|popd|copy.*\\\\|xcopy.*\\\\|robocopy.*\\\\") {
                    Write-LogEntry "WARNING" "Network shared drive access detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1039 - Data from Network Shared Drive"
                }
            }
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                # Monitor for network share file operations
                if ($targetFilename -match "\\\\[^\\]+\\") {
                    Write-LogEntry "INFO" "Network share file operation detected" -EventID $event.Id -ProcessName $eventData.Image -TargetFile $targetFilename -Technique "T1039 - Data from Network Shared Drive"
                }
            }
        }
    }
}

# Monitor for Data from Removable Media (T1025)
function Monitor-DataFromRemovableMedia {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for removable media access patterns
                if ($commandLine -match "[A-Z]:\\.*copy|[A-Z]:\\.*xcopy|[A-Z]:\\.*robocopy" -and $commandLine -match "[D-Z]:\\") {
                    Write-LogEntry "WARNING" "Potential removable media data collection" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1025 - Data from Removable Media"
                }
            }
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                # Monitor for removable media file operations (drives D: and higher)
                if ($targetFilename -match "^[D-Z]:\\") {
                    Write-LogEntry "INFO" "Removable media file operation detected" -EventID $event.Id -ProcessName $eventData.Image -TargetFile $targetFilename -Technique "T1025 - Data from Removable Media"
                }
            }
        }
    }
}

# Monitor for Screen Capture (T1113)
function Monitor-ScreenCapture {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 7, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for screenshot tools and commands
                $screenshotPatterns = @(
                    "Add-Type.*System\.Drawing|System\.Windows\.Forms",
                    "Graphics\.CopyFromScreen|DrawingSettings",
                    "PrintWindow|BitBlt",
                    "screenshot|screencap|printscreen",
                    "nircmd.*savescreenshot|nircmd.*screenshot"
                )
                
                foreach ($pattern in $screenshotPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "WARNING" "Screen capture activity detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1113 - Screen Capture"
                        break
                    }
                }
            }
            
            if ($event.Id -eq 7 -and $eventData.ImageLoaded) {
                $imageLoaded = $eventData.ImageLoaded
                
                # Monitor for screenshot-related DLL loading
                if ($imageLoaded -match "gdi32\.dll|user32\.dll" -and $eventData.Image -match "powershell|cmd") {
                    Write-LogEntry "INFO" "Graphics library loaded by script" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1113 - Screen Capture"
                }
            }
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                # Monitor for screenshot file creation
                if ($targetFilename -match "\.(png|jpg|jpeg|bmp|gif)$") {
                    Write-LogEntry "INFO" "Image file created - potential screenshot" -EventID $event.Id -ProcessName $eventData.Image -TargetFile $targetFilename -Technique "T1113 - Screen Capture"
                }
            }
        }
    }
}

# Monitor for Video Capture (T1125)
function Monitor-VideoCapture {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for video capture patterns
                if ($commandLine -match "ffmpeg.*-f.*gdigrab|vlc.*--intf.*dummy.*--vout.*dummy") {
                    Write-LogEntry "WARNING" "Video capture activity detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1125 - Video Capture"
                }
            }
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                # Monitor for video file creation
                if ($targetFilename -match "\.(avi|mp4|wmv|mov|mkv)$") {
                    Write-LogEntry "INFO" "Video file created" -EventID $event.Id -ProcessName $eventData.Image -TargetFile $targetFilename -Technique "T1125 - Video Capture"
                }
            }
        }
    }
}

# Monitor for Audio Capture (T1123)
function Monitor-AudioCapture {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for audio capture patterns
                if ($commandLine -match "ffmpeg.*-f.*dshow.*audio|sox.*-t.*waveaudio") {
                    Write-LogEntry "WARNING" "Audio capture activity detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1123 - Audio Capture"
                }
            }
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                # Monitor for audio file creation
                if ($targetFilename -match "\.(wav|mp3|wma|flac|m4a)$") {
                    Write-LogEntry "INFO" "Audio file created" -EventID $event.Id -ProcessName $eventData.Image -TargetFile $targetFilename -Technique "T1123 - Audio Capture"
                }
            }
        }
    }
}

# Monitor for Clipboard Data (T1115)
function Monitor-ClipboardData {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for clipboard access patterns
                $clipboardPatterns = @(
                    "Get-Clipboard|Set-Clipboard",
                    "Windows\.Forms\.Clipboard",
                    "clip\.exe",
                    "AddClipboardFormatListener|GetClipboardData"
                )
                
                foreach ($pattern in $clipboardPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "WARNING" "Clipboard access detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1115 - Clipboard Data"
                        break
                    }
                }
            }
        }
    }
}

# Monitor for Input Capture (T1056)
function Monitor-InputCapture {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 7, 13) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for keylogging patterns
                $keylogPatterns = @(
                    "SetWindowsHookEx|GetAsyncKeyState",
                    "RegisterHotKey|UnregisterHotKey",
                    "keylogger|keystroke",
                    "GetKeyboardState|GetKeyState"
                )
                
                foreach ($pattern in $keylogPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "CRITICAL" "Potential input capture activity detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1056 - Input Capture"
                        break
                    }
                }
            }
            
            if ($event.Id -eq 7 -and $eventData.ImageLoaded) {
                $imageLoaded = $eventData.ImageLoaded
                
                # Monitor for hook-related DLL loading
                if ($imageLoaded -match "user32\.dll" -and $eventData.Image -match "powershell|cmd|rundll32") {
                    Write-LogEntry "INFO" "User32.dll loaded - potential hook installation" -EventID $event.Id -ProcessName $eventData.Image -Technique "T1056 - Input Capture"
                }
            }
        }
    }
}

# Monitor for Archive Collected Data (T1560)
function Monitor-ArchiveCollectedData {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for archiving patterns
                $archivePatterns = @(
                    "7z\.exe.*a.*-p|winrar\.exe.*a.*-hp",
                    "tar.*-c.*-z|gzip.*-r",
                    "Compress-Archive|New-ZipFile",
                    "makecab\.exe|expand\.exe"
                )
                
                foreach ($pattern in $archivePatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "WARNING" "Data archiving activity detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1560 - Archive Collected Data"
                        break
                    }
                }
            }
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                # Monitor for archive file creation
                if ($targetFilename -match "\.(zip|rar|7z|tar|gz|cab)$") {
                    Write-LogEntry "INFO" "Archive file created" -EventID $event.Id -ProcessName $eventData.Image -TargetFile $targetFilename -Technique "T1560 - Archive Collected Data"
                }
            }
        }
    }
}

# Monitor for Data Staged (T1074)
function Monitor-DataStaged {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1, 11) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for staging patterns
                if ($commandLine -match "copy.*\\temp\\|copy.*\\appdata\\|move.*\\temp\\|xcopy.*\\temp\\") {
                    Write-LogEntry "WARNING" "Data staging activity detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1074 - Data Staged"
                }
            }
            
            if ($event.Id -eq 11 -and $eventData.TargetFilename) {
                $targetFilename = $eventData.TargetFilename
                
                # Monitor for suspicious staging locations
                if ($targetFilename -match "\\Temp\\.*\.(txt|doc|pdf|xls)|\\AppData\\.*\.(txt|doc|pdf|xls)") {
                    Write-LogEntry "INFO" "File staged in temporary location" -EventID $event.Id -ProcessName $eventData.Image -TargetFile $targetFilename -Technique "T1074 - Data Staged"
                }
            }
        }
    }
}

# Monitor for Automated Collection (T1119)
function Monitor-AutomatedCollection {
    if (Test-SysmonInstalled) {
        $events = Get-EventsSafe -LogName 'Microsoft-Windows-Sysmon/Operational' -EventIDs @(1) -StartTime $Script:LastEventTime

        foreach ($event in $events) {
            $eventData = Get-EventData -Event $event
            
            if ($event.Id -eq 1 -and $eventData.CommandLine) {
                $commandLine = $eventData.CommandLine
                
                # Check for automated collection patterns
                $automatedPatterns = @(
                    "for.*in.*do.*copy|for.*in.*do.*xcopy",
                    "while.*copy|while.*xcopy",
                    "ForEach.*Copy-Item|ForEach.*Move-Item",
                    "Get-ChildItem.*ForEach.*Copy",
                    "dir.*\\/s.*\\|.*findstr.*\\|.*copy"
                )
                
                foreach ($pattern in $automatedPatterns) {
                    if ($commandLine -match $pattern) {
                        Write-LogEntry "WARNING" "Automated data collection detected" -EventID $event.Id -ProcessName $eventData.Image -CommandLine $commandLine -Technique "T1119 - Automated Collection"
                        break
                    }
                }
            }
        }
    }
}

# Generate summary report
function Generate-Summary {
    $summaryInfo = @"

=== Collection Monitoring Summary ===
Duration: $((Get-Date) - $Script:StartTime)
Techniques Detected: $($Script:EventCounters.Count)
"@
    Add-Content -Path $Script:LogFile -Value $summaryInfo
    
    if ($Script:EventCounters.Count -gt 0) {
        $sortedTechniques = $Script:EventCounters.GetEnumerator() | Sort-Object Name
        foreach ($technique in $sortedTechniques) {
            Add-Content -Path $Script:LogFile -Value "$($technique.Name): $($technique.Value) events"
        }
    } else {
        Add-Content -Path $Script:LogFile -Value "No collection techniques detected during monitoring period"
    }
    
    Add-Content -Path $Script:LogFile -Value "=== Collection Logger Stopped at $(Get-Date) ==="
}

# Main monitoring loop with clean detection-only logging
function Start-Monitoring {
    $endTime = if ($MonitorDuration -gt 0) { 
        $Script:StartTime.AddMinutes($MonitorDuration) 
    } else { 
        [DateTime]::MaxValue 
    }
    
    while ((Get-Date) -lt $endTime) {
        try {
            $iterationStart = Get-Date
            
            # Run all monitoring functions
            Monitor-DataFromLocalSystem
            Monitor-DataFromNetworkSharedDrive
            Monitor-DataFromRemovableMedia
            Monitor-ScreenCapture
            Monitor-VideoCapture
            Monitor-AudioCapture
            Monitor-ClipboardData
            Monitor-InputCapture
            Monitor-ArchiveCollectedData
            Monitor-DataStaged
            Monitor-AutomatedCollection
            
            # Update last event time for next iteration
            $Script:LastEventTime = $iterationStart
            
            # Sleep for specified interval
            Start-Sleep -Seconds $RefreshInterval
            
        } catch {
            # Silent error handling - only log critical errors
            Start-Sleep -Seconds 10  # Brief pause on error
        }
    }
}

# Cleanup function
function Stop-Monitoring {
    Generate-Summary
}

# Main execution
try {
    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
    Write-Host "Collection Tactics Live Monitor v2.0 (Server 2012 Compatible)" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    # Initialize
    Initialize-Logger -Path $OutputPath
    
    # Check Sysmon status
    $sysmonAvailable = Test-SysmonInstalled
    if (-not $sysmonAvailable) {
        Write-Host "WARNING: Sysmon not detected. Some detection capabilities will be limited." -ForegroundColor Yellow
        Write-Host "INFO: Run Setup-SysmonPipeline.ps1 to install Sysmon for enhanced monitoring" -ForegroundColor Gray
    }
    
    # Display monitoring configuration
    Write-Host "`nMonitoring Configuration:" -ForegroundColor Yellow
    Write-Host "  Output Path: $OutputPath" -ForegroundColor White
    Write-Host "  Log Level: $LogLevel" -ForegroundColor White
    Write-Host "  Duration: $(if ($MonitorDuration -eq 0) { 'Continuous' } else { "$MonitorDuration minutes" })" -ForegroundColor White
    Write-Host "  Refresh Interval: $RefreshInterval seconds" -ForegroundColor White
    Write-Host "  Sysmon Available: $(if ($sysmonAvailable) { 'Yes' } else { 'No' })" -ForegroundColor White
    
    Write-Host "`nStarting Collection monitoring... Press Ctrl+C to stop" -ForegroundColor Green
    Write-Host "Only detection events will be logged for clean output`n" -ForegroundColor Gray
    
    # Register cleanup on script termination
    Register-EngineEvent PowerShell.Exiting -Action { Stop-Monitoring }
    
    # Start monitoring
    Start-Monitoring
    
} catch {
    Write-Host "FATAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Stop-Monitoring
}
