#!/usr/bin/env pwsh
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Validate Sysmon Configuration Compatibility for OT Process Correlation

.DESCRIPTION
This script validates that the current Sysmon installation and configuration
are compatible with the OT-ProcessCorrelation.ps1 monitoring script.

.NOTES
Run this before deploying the OT Process Correlation Monitor
#>

Write-Host "=== Sysmon Compatibility Validation ===" -ForegroundColor Cyan
Write-Host "Checking Sysmon installation and configuration..." -ForegroundColor Yellow
Write-Host ""

$ValidationResults = @()

# Test 1: Check if Sysmon is installed
try {
    $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction Stop
    $ValidationResults += @{
        Test = "Sysmon Service"
        Status = "PASS"
        Details = "Service: $($sysmonService.Name) - Status: $($sysmonService.Status)"
    }
    Write-Host "✅ Sysmon service found: $($sysmonService.Name)" -ForegroundColor Green
} catch {
    $ValidationResults += @{
        Test = "Sysmon Service"
        Status = "FAIL"
        Details = "Sysmon service not found or not running"
    }
    Write-Host "❌ Sysmon service not found" -ForegroundColor Red
}

# Test 2: Check Sysmon Event Log availability
try {
    $logName = "Microsoft-Windows-Sysmon/Operational"
    $recentEvents = Get-WinEvent -LogName $logName -MaxEvents 5 -ErrorAction Stop
    $ValidationResults += @{
        Test = "Sysmon Event Log"
        Status = "PASS"
        Details = "Found $($recentEvents.Count) recent events in $logName"
    }
    Write-Host "✅ Sysmon event log accessible with $($recentEvents.Count) recent events" -ForegroundColor Green
} catch {
    $ValidationResults += @{
        Test = "Sysmon Event Log"
        Status = "FAIL"
        Details = "Cannot access Sysmon event log: $($_.Exception.Message)"
    }
    Write-Host "❌ Cannot access Sysmon event log" -ForegroundColor Red
}

# Test 3: Check for Event ID 1 (Process Creation) events
try {
    $processEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{ID=1} -MaxEvents 10 -ErrorAction Stop
    $ValidationResults += @{
        Test = "Event ID 1 (Process Creation)"
        Status = "PASS"
        Details = "Found $($processEvents.Count) process creation events"
    }
    Write-Host "✅ Event ID 1 (Process Creation) events available: $($processEvents.Count) found" -ForegroundColor Green
    
    # Check if events have required fields
    if ($processEvents.Count -gt 0) {
        $eventXML = [xml]$processEvents[0].ToXml()
        $hasRequiredFields = $false
        
        foreach ($data in $eventXML.Event.EventData.Data) {
            if ($data.Name -in @("ProcessId", "ParentProcessId", "Image", "CommandLine")) {
                $hasRequiredFields = $true
                break
            }
        }
        
        if ($hasRequiredFields) {
            Write-Host "   ✅ Required fields present in Event ID 1" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Some required fields may be missing" -ForegroundColor Yellow
        }
    }
} catch {
    $ValidationResults += @{
        Test = "Event ID 1 (Process Creation)"
        Status = "FAIL"
        Details = "No Event ID 1 events found: $($_.Exception.Message)"
    }
    Write-Host "❌ No Event ID 1 events found" -ForegroundColor Red
}

# Test 4: Check Sysmon version (if possible)
try {
    $sysmonPath = Get-ChildItem -Path "C:\Windows\*sysmon*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($sysmonPath) {
        $versionInfo = Get-ItemProperty -Path $sysmonPath.FullName | Select-Object VersionInfo
        $ValidationResults += @{
            Test = "Sysmon Version"
            Status = "PASS"
            Details = "Version: $($versionInfo.VersionInfo.FileVersion) at $($sysmonPath.FullName)"
        }
        Write-Host "✅ Sysmon executable found: Version $($versionInfo.VersionInfo.FileVersion)" -ForegroundColor Green
    } else {
        $ValidationResults += @{
            Test = "Sysmon Version"
            Status = "WARNING"
            Details = "Sysmon executable not found in standard locations"
        }
        Write-Host "⚠️  Sysmon executable not found in standard locations" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠️  Could not determine Sysmon version" -ForegroundColor Yellow
}

# Test 5: Check configuration file compatibility
$configPaths = @(
    "C:\ProgramData\CustomSecurityLogs\sysmon-config-comprehensive-updated.xml",
    "C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\sysmon-config-comprehensive-updated.xml",
    "C:\ProgramData\CustomSecurityLogs\Configs\sysmon-config-comprehensive-updated.xml"
)

$configFound = $false
foreach ($configPath in $configPaths) {
    if (Test-Path $configPath) {
        try {
            $configContent = Get-Content $configPath -Raw
            if ($configContent -match "ProcessCreate.*onmatch.*exclude" -and 
                $configContent -match "SYSMON EVENT ID 1.*PROCESS CREATION") {
                
                $ValidationResults += @{
                    Test = "Configuration File"
                    Status = "PASS"
                    Details = "Compatible configuration found at $configPath"
                }
                Write-Host "✅ Compatible Sysmon configuration found: $configPath" -ForegroundColor Green
                $configFound = $true
                break
            }
        } catch {
            Write-Host "⚠️  Could not read configuration file: $configPath" -ForegroundColor Yellow
        }
    }
}

if (-not $configFound) {
    $ValidationResults += @{
        Test = "Configuration File"
        Status = "WARNING"
        Details = "No compatible configuration file found in expected locations"
    }
    Write-Host "⚠️  No compatible configuration file found" -ForegroundColor Yellow
}

# Test 6: Performance check - Event generation rate
Write-Host ""
Write-Host "Checking event generation rate..." -ForegroundColor Yellow
try {
    $startTime = Get-Date
    Start-Sleep -Seconds 5
    $endTime = Get-Date
    
    $eventsInPeriod = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{ID=1; StartTime=$startTime; EndTime=$endTime} -ErrorAction Stop
    $eventsPerSecond = $eventsInPeriod.Count / 5
    
    if ($eventsPerSecond -lt 10) {
        $status = "OPTIMAL"
        $color = "Green"
    } elseif ($eventsPerSecond -lt 50) {
        $status = "ACCEPTABLE"
        $color = "Yellow"
    } else {
        $status = "HIGH"
        $color = "Red"
    }
    
    $ValidationResults += @{
        Test = "Event Generation Rate"
        Status = $status
        Details = "$($eventsInPeriod.Count) events in 5 seconds ($($eventsPerSecond.ToString('F1')) events/sec)"
    }
    Write-Host "📊 Event generation rate: $($eventsPerSecond.ToString('F1')) events/second ($status)" -ForegroundColor $color
} catch {
    Write-Host "⚠️  Could not measure event generation rate" -ForegroundColor Yellow
}

# Summary
Write-Host ""
Write-Host "=== Validation Summary ===" -ForegroundColor Cyan
$passCount = ($ValidationResults | Where-Object { $_.Status -eq "PASS" }).Count
$failCount = ($ValidationResults | Where-Object { $_.Status -eq "FAIL" }).Count
$warnCount = ($ValidationResults | Where-Object { $_.Status -in @("WARNING", "OPTIMAL", "ACCEPTABLE", "HIGH") }).Count

foreach ($result in $ValidationResults) {
    $symbol = switch ($result.Status) {
        "PASS" { "✅" }
        "FAIL" { "❌" }
        "OPTIMAL" { "✅" }
        "ACCEPTABLE" { "⚠️ " }
        "HIGH" { "⚠️ " }
        default { "⚠️ " }
    }
    
    $color = switch ($result.Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "OPTIMAL" { "Green" }
        "ACCEPTABLE" { "Yellow" }
        "HIGH" { "Yellow" }
        default { "Yellow" }
    }
    
    Write-Host "$symbol $($result.Test): $($result.Details)" -ForegroundColor $color
}

Write-Host ""
if ($failCount -eq 0) {
    Write-Host "🎉 All critical tests passed! OT Process Correlation Monitor is compatible." -ForegroundColor Green
    Write-Host "   You can proceed with deploying the OT-ProcessCorrelation.ps1 script." -ForegroundColor Green
} elseif ($failCount -le 2) {
    Write-Host "⚠️  Minor issues detected. Review failed tests before deployment." -ForegroundColor Yellow
    Write-Host "   The script may work but consider addressing the issues first." -ForegroundColor Yellow
} else {
    Write-Host "❌ Critical issues detected. Address these before deploying OT monitoring." -ForegroundColor Red
    Write-Host "   Install and configure Sysmon properly before proceeding." -ForegroundColor Red
}

Write-Host ""
Write-Host "Results: $passCount passed, $failCount failed, $warnCount warnings" -ForegroundColor White
