# === Execution Monitoring Script - Compatible Version ===
# Designed for PowerShell 5.1 Desktop Edition compatibility

# === Setup ===
$logPath = "$env:ProgramData\CustomSecurityLogs\Execution-Detect.log"
if (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType File -Force }

# Track script start time for uptime calculation
$scriptStartTime = Get-Date

function Write-Log($msg) {
    $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $LogPath -Value "[$time] $msg"
}

Write-Log "Execution monitoring script started (Compatible Version)."

# Check PowerShell version and capabilities
Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)"
Write-Log "PowerShell Edition: $($PSVersionTable.PSEdition)"

# === System Information ===
try {
    $os = Get-WmiObject -Class Win32_OperatingSystem
    Write-Log "OS: $($os.Caption) Build $($os.BuildNumber)"
} catch {
    Write-Log "Could not retrieve OS information: $_"
}

# === WMI Process Monitoring with Parent-Child Correlation ===
try {
    Register-WmiEvent -Class Win32_ProcessStartTrace -Action {
        try {
            $exe = $Event.SourceEventArgs.NewEvent.ProcessName.ToLower()
            $cmd = $Event.SourceEventArgs.NewEvent.CommandLine
            $pid = $Event.SourceEventArgs.NewEvent.ProcessId
            $ppid = $Event.SourceEventArgs.NewEvent.ParentProcessId

            # Expanded list of LOLBins and script hosts
            $suspiciousExecutables = @(
                'powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe',
                'mshta.exe','rundll32.exe','regsvr32.exe','wmic.exe','schtasks.exe',
                'at.exe','taskeng.exe','msbuild.exe','csc.exe','python.exe','node.exe',
                'regsvcs.exe','regasm.exe','fxssvc.exe','icacls.exe','w32tm.exe','wsl.exe',
                'installutil.exe','certutil.exe','bitsadmin.exe'
            )
            $suspiciousArgs = @('encodedcommand','bypass','hidden','iex','invoke-','frombase64string','reflection.assembly','-enc','-nop','-w hidden')

            $flag = $false
            if ($suspiciousExecutables -contains $exe) { $flag = $true }
            foreach ($word in $suspiciousArgs) {
                if ($cmd -and $cmd.ToLower().Contains($word)) { $flag = $true; break }
            }

            # Parent-child correlation for Office macros, browser launches, etc.
            try {
                $parent = Get-Process -Id $ppid -ErrorAction Stop
                $parentExe = $parent.ProcessName.ToLower() + '.exe'
                $officeHosts = @('winword.exe','excel.exe','powerpnt.exe','outlook.exe','acrord32.exe','msaccess.exe')
                if ($officeHosts -contains $parentExe -and $flag) {
                    Write-Log "[CRITICAL] Parent-Child Alert: $parentExe -> $exe CMD: $cmd"
                    return
                }
            } catch {}

            if ($flag) {
                Write-Log "[SUSPICIOUS] WMI Exec: $exe (PID: $pid) [Parent PID: $ppid] CMD: $cmd"
            }
        } catch {
            Write-Log "[ERROR] WMI Process monitoring error: $_"
        }
    }
    Write-Log "[SUCCESS] WMI Process monitoring enabled."
} catch {
    Write-Log "[ERROR] WMI Process monitoring failed: $_"
}

# === Scheduled Task & Service Monitoring (WMI Classes) ===
# Legacy Scheduled Job monitoring
try {
    Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_ScheduledJob'" -Action {
        try {
            Write-Log "[ALERT] WMI: Legacy Scheduled Job created: $($Event.SourceEventArgs.NewEvent.TargetInstance.Command)"
        } catch {
            Write-Log "[ERROR] Scheduled job parsing failed: $_"
        }
    }
    Write-Log "[SUCCESS] Legacy Scheduled Job monitoring enabled."
} catch {
    Write-Log "[WARNING] Legacy Scheduled Job monitoring failed: $_"
}

# Service monitoring
try {
    Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Service'" -Action {
        try {
            $serviceName = $Event.SourceEventArgs.NewEvent.TargetInstance.Name
            $servicePath = $Event.SourceEventArgs.NewEvent.TargetInstance.PathName
            Write-Log "[ALERT] WMI: New service installed: '$serviceName' Path: '$servicePath'"
        } catch {
            Write-Log "[ERROR] Service monitoring parsing failed: $_"
        }
    }
    Write-Log "[SUCCESS] Service monitoring enabled."
} catch {
    Write-Log "[WARNING] Service monitoring failed: $_"
}

# === PowerShell ScriptBlock Monitoring (Alternative method) ===
try {
    $job = Start-Job -ScriptBlock {
        param($logPath)
        function Write-Log($msg) {
            $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Add-Content -Path $logPath -Value "[$time] $msg"
        }
        
        while ($true) {
            try {
                $events = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue | 
                          Where-Object { $_.Id -eq 4104 -and $_.TimeCreated -gt (Get-Date).AddMinutes(-1) }
                
                foreach ($event in $events) {
                    $scriptText = $event.Properties[2].Value
                    if ($scriptText -match 'Invoke|FromBase64String|Download|Reflection|bypass|hidden|encodedcommand|-enc|-nop') {
                        Write-Log "[POWERSHELL] [PS-ID4104] ScriptBlock: PowerShell: $($scriptText.Substring(0,[Math]::Min(150,$scriptText.Length)))..."
                    }
                }
            } catch {
                # Silently continue if PowerShell operational log is not available
            }
            Start-Sleep -Seconds 30
        }
    } -ArgumentList $logPath
    Write-Log "[SUCCESS] PowerShell ScriptBlock monitoring job started (Job ID: $($job.Id))."
} catch {
    Write-Log "[WARNING] PowerShell ScriptBlock monitoring not available: $_"
}

# === WMI File Execution Type Monitoring ===
try {
    Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'" -Action {
        try {
            $executablePath = $Event.SourceEventArgs.NewEvent.TargetInstance.ExecutablePath
            if ($executablePath) {
                $ext = ($executablePath -split '\.')[-1].ToLower()
                $dangerousExt = @('vbs','js','jse','wsf','ps1','bat','cmd','scr','lnk','exe','msi')
                if ($dangerousExt -contains $ext) {
                    Write-Log "[FILE] Script or binary executed: $executablePath"
                }
                
                # Check for execution from suspicious locations
                if ($executablePath -match 'temp|appdata|downloads|users\\.*?\\desktop|users\\.*?\\documents') {
                    Write-Log "[SUSPICIOUS] Execution from user directory: $executablePath"
                }
            }
        } catch {
            Write-Log "[ERROR] File system monitoring error: $_"
        }
    }
    Write-Log "[SUCCESS] File system monitoring enabled."
} catch {
    Write-Log "[ERROR] File system monitoring failed: $_"
}

# === Sysmon Event Monitoring (Background Job) ===
try {
    $sysmonJob = Start-Job -ScriptBlock {
        param($logPath)
        function Write-Log($msg) {
            $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Add-Content -Path $logPath -Value "[$time] $msg"
        }
        
        while ($true) {
            try {
                # Sysmon Process Creation (Event ID 1)
                $processEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 -ErrorAction SilentlyContinue | 
                               Where-Object { $_.Id -eq 1 -and $_.TimeCreated -gt (Get-Date).AddMinutes(-1) }
                
                foreach ($event in $processEvents) {
                    try {
                        $xml = [xml]$event.ToXml()
                        $image = ($xml.Event.EventData.Data | Where-Object Name -eq 'Image').'#text'
                        $cmdLine = ($xml.Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'
                        $parentImage = ($xml.Event.EventData.Data | Where-Object Name -eq 'ParentImage').'#text'
                        
                        $lolbins = @('mshta.exe','rundll32.exe','regsvr32.exe','powershell.exe','pwsh.exe','wmic.exe','certutil.exe','bitsadmin.exe')
                        $suspiciousPatterns = @('invoke-','frombase64string','download','bypass','encodedcommand','-enc','-hidden')
                        
                        $suspicious = $false
                        if ($image -and ($lolbins -contains ([System.IO.Path]::GetFileName($image).ToLower()))) { $suspicious = $true }
                        foreach ($pat in $suspiciousPatterns) {
                            if ($cmdLine -and $cmdLine.ToLower().Contains($pat)) { $suspicious = $true; break }
                        }
                        
                        # Check for Office macro execution
                        if ($parentImage -match 'winword.exe|excel.exe|powerpnt.exe' -and $image -match 'powershell.exe|cmd.exe|wscript.exe|cscript.exe') {
                            $suspicious = $true
                            Write-Log "[SYSMON] [Sysmon-ID1] Office Macro Execution: $([System.IO.Path]::GetFileName($parentImage)) spawned $([System.IO.Path]::GetFileName($image))"
                        }
                        
                        if ($suspicious) {
                            Write-Log "[SYSMON] [Sysmon-ID1] Suspicious Execution: $([System.IO.Path]::GetFileName($image)) CMD: $cmdLine"
                        }
                    } catch {}
                }
            } catch {
                # Silently continue if Sysmon log is not available
            }
            Start-Sleep -Seconds 30
        }
    } -ArgumentList $logPath
    Write-Log "[SUCCESS] Sysmon monitoring job started (Job ID: $($sysmonJob.Id))."
} catch {
    Write-Log "[WARNING] Sysmon monitoring not available: $_"
}

# === Windows Defender Monitoring (Background Job) ===
try {
    $defenderJob = Start-Job -ScriptBlock {
        param($logPath)
        function Write-Log($msg) {
            $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Add-Content -Path $logPath -Value "[$time] $msg"
        }
        
        while ($true) {
            try {
                $defenderEvents = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue | 
                                Where-Object { $_.Id -eq 1116 -and $_.TimeCreated -gt (Get-Date).AddMinutes(-1) }
                
                foreach ($event in $defenderEvents) {
                    try {
                        $xml = [xml]$event.ToXml()
                        $threatName = ($xml.Event.EventData.Data | Where-Object Name -eq 'Threat Name').'#text'
                        $path = ($xml.Event.EventData.Data | Where-Object Name -eq 'Path').'#text'
                        Write-Log "[DEFENDER] [Defender-ID1116] Malware detection: Threat='$threatName' Path='$path'"
                    } catch {
                        Write-Log "[DEFENDER] [Defender-ID1116] Malware detection: EventID 1116"
                    }
                }
            } catch {
                # Silently continue if Defender log is not available
            }
            Start-Sleep -Seconds 30
        }
    } -ArgumentList $logPath
    Write-Log "[SUCCESS] Windows Defender monitoring job started (Job ID: $($defenderJob.Id))."
} catch {
    Write-Log "[WARNING] Windows Defender monitoring not available: $_"
}

Write-Log "[INFO] All monitoring systems initialized. Script running continuously..."
Write-Log "[INFO] To stop monitoring, close this PowerShell session or stop the running jobs."

# === Keep Alive with Status Updates ===
$lastStatusTime = Get-Date
while ($true) { 
    Start-Sleep -Seconds 300  # 5 minutes
    $currentTime = Get-Date
    if (($currentTime - $lastStatusTime).TotalMinutes -ge 30) {
        $uptimeHours = [math]::Round(($currentTime - $scriptStartTime).TotalHours, 2)
        Write-Log "[STATUS] Monitoring active - Uptime: $uptimeHours hours"
        $lastStatusTime = $currentTime
    }
}
