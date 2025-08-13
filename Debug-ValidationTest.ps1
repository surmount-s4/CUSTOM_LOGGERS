# ====================================================================
# Unified Security Logger - Debug and Validation Script
# ====================================================================
# This script tests and validates the fixes implemented for:
# 1. Registry logging deduplication
# 2. USB device state tracking 
# 3. Event deduplication system
# 4. Severity-based throttling
# 5. Context-aware discovery detection
# ====================================================================

param(
    [ValidateSet("All", "Registry", "USB", "Deduplication", "Throttling", "Discovery")]
    [string]$TestType = "All",
    
    [switch]$Verbose,
    [switch]$CreateTestEvents,
    [int]$TestDuration = 30  # seconds
)

# Configuration
$LogBasePath = "$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS"
$SecurityEventsPath = Join-Path $LogBasePath "SecurityEvents.csv"
$USBLogPath = Join-Path $LogBasePath "USB-ThreatDetection.log"
$BackupPath = Join-Path $LogBasePath "SecurityEvents_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

function Write-TestLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        "INFO" { "Cyan" }
        default { "White" }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Backup-LogFile {
    if (Test-Path $SecurityEventsPath) {
        try {
            Copy-Item $SecurityEventsPath $BackupPath -Force
            Write-TestLog "Created backup: $BackupPath" "SUCCESS"
            return $true
        } catch {
            Write-TestLog "Failed to create backup: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    return $true
}

function Get-LogFileStats {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        return @{
            Exists = $false
            LineCount = 0
            FileSize = 0
            LastModified = $null
        }
    }
    
    $file = Get-Item $FilePath
    $content = Get-Content $FilePath -ErrorAction SilentlyContinue
    
    return @{
        Exists = $true
        LineCount = if ($content) { $content.Count } else { 0 }
        FileSize = $file.Length
        LastModified = $file.LastWriteTime
    }
}

function Test-RegistryDeduplication {
    Write-TestLog "=== TESTING REGISTRY DEDUPLICATION ===" "INFO"
    
    # Get initial log stats
    $initialStats = Get-LogFileStats $SecurityEventsPath
    Write-TestLog "Initial log entries: $($initialStats.LineCount)" "INFO"
    
    # Wait and check for BAM entries
    Write-TestLog "Monitoring for BAM registry entries (should be filtered)..." "INFO"
    Start-Sleep -Seconds 10
    
    $currentStats = Get-LogFileStats $SecurityEventsPath
    $newEntries = $currentStats.LineCount - $initialStats.LineCount
    
    if ($newEntries -eq 0) {
        Write-TestLog "PASS: No excessive registry logging detected" "SUCCESS"
        return $true
    } else {
        # Check if new entries contain BAM
        $recentEntries = Get-Content $SecurityEventsPath | Select-Object -Last $newEntries
        $bamEntries = $recentEntries | Where-Object { $_ -match "Services\\bam\\State" }
        
        if ($bamEntries.Count -gt 0) {
            Write-TestLog "FAIL: Found $($bamEntries.Count) BAM entries (should be filtered)" "ERROR"
            Write-TestLog "Sample BAM entry: $($bamEntries[0])" "ERROR"
            return $false
        } else {
            Write-TestLog "PASS: No BAM entries found in new logs" "SUCCESS"
            return $true
        }
    }
}

function Test-USBStateTracking {
    Write-TestLog "=== TESTING USB STATE TRACKING ===" "INFO"
    
    # Check initial USB log
    $initialUSBStats = Get-LogFileStats $USBLogPath
    Write-TestLog "Initial USB log entries: $($initialUSBStats.LineCount)" "INFO"
    
    # Monitor for USB activity
    Write-TestLog "Monitoring USB detection (should only trigger on device changes)..." "INFO"
    Start-Sleep -Seconds 15
    
    $currentUSBStats = Get-LogFileStats $USBLogPath
    $newUSBEntries = $currentUSBStats.LineCount - $initialUSBStats.LineCount
    
    if ($newUSBEntries -eq 0) {
        Write-TestLog "PASS: No unnecessary USB scanning detected" "SUCCESS"
        return $true
    } else {
        Write-TestLog "INFO: $newUSBEntries new USB log entries detected" "INFO"
        
        # Check if entries indicate actual device changes
        if (Test-Path $USBLogPath) {
            $recentUSBEntries = Get-Content $USBLogPath | Select-Object -Last $newUSBEntries
            $deviceChangeEntries = $recentUSBEntries | Where-Object { $_ -match "(connected|disconnected|inserted|removed)" }
            
            if ($deviceChangeEntries.Count -gt 0) {
                Write-TestLog "PASS: USB entries indicate actual device changes" "SUCCESS"
                return $true
            } else {
                Write-TestLog "WARN: USB entries may not be related to device changes" "WARN"
                return $false
            }
        }
    }
    
    return $true
}

function Test-EventDeduplication {
    Write-TestLog "=== TESTING EVENT DEDUPLICATION ===" "INFO"
    
    if (-not $CreateTestEvents) {
        Write-TestLog "Skipping deduplication test (use -CreateTestEvents to enable)" "INFO"
        return $true
    }
    
    # Get initial stats
    $initialStats = Get-LogFileStats $SecurityEventsPath
    
    # Create duplicate events by running multiple discovery commands
    Write-TestLog "Creating test events to check deduplication..." "INFO"
    
    # Execute commands that should be detected
    for ($i = 1; $i -le 3; $i++) {
        Write-TestLog "Running test command set $i" "INFO"
        Start-Process "cmd.exe" -ArgumentList "/c whoami /all > nul 2>&1" -WindowStyle Hidden -Wait
        Start-Sleep -Seconds 2
    }
    
    Start-Sleep -Seconds 5
    
    # Check results
    $finalStats = Get-LogFileStats $SecurityEventsPath
    $totalNewEntries = $finalStats.LineCount - $initialStats.LineCount
    
    Write-TestLog "New log entries after duplicate test commands: $totalNewEntries" "INFO"
    
    if ($totalNewEntries -le 3) {
        Write-TestLog "PASS: Event deduplication appears to be working" "SUCCESS"
        return $true
    } else {
        Write-TestLog "WARN: More entries than expected - check deduplication logic" "WARN"
        return $false
    }
}

function Test-SeverityThrottling {
    Write-TestLog "=== TESTING SEVERITY THROTTLING ===" "INFO"
    
    # Check recent entries for severity distribution
    if (Test-Path $SecurityEventsPath) {
        $recentEntries = Get-Content $SecurityEventsPath | Select-Object -Last 100
        
        # Count by severity
        $severityCounts = @{
            INFO = ($recentEntries | Where-Object { $_ -match ",INFO," }).Count
            WARNING = ($recentEntries | Where-Object { $_ -match ",WARNING," }).Count
            ERROR = ($recentEntries | Where-Object { $_ -match ",ERROR," }).Count
            CRITICAL = ($recentEntries | Where-Object { $_ -match ",CRITICAL," }).Count
        }
        
        Write-TestLog "Recent severity distribution:" "INFO"
        foreach ($severity in $severityCounts.Keys) {
            Write-TestLog "  $severity : $($severityCounts[$severity])" "INFO"
        }
        
        # Check if INFO level is reasonably limited
        if ($severityCounts.INFO -le 20) {
            Write-TestLog "PASS: INFO level events appear to be throttled" "SUCCESS"
            return $true
        } else {
            Write-TestLog "WARN: High number of INFO events - check throttling" "WARN"
            return $false
        }
    }
    
    Write-TestLog "INFO: No recent events to analyze" "INFO"
    return $true
}

function Test-DiscoveryContextAwareness {
    Write-TestLog "=== TESTING DISCOVERY CONTEXT AWARENESS ===" "INFO"
    
    if (-not $CreateTestEvents) {
        Write-TestLog "Skipping discovery test (use -CreateTestEvents to enable)" "INFO"
        return $true
    }
    
    # Get initial stats
    $initialStats = Get-LogFileStats $SecurityEventsPath
    
    # Run legitimate administrative commands
    Write-TestLog "Running legitimate administrative commands..." "INFO"
    Start-Process "tasklist" -ArgumentList "/svc" -WindowStyle Hidden -Wait
    Start-Sleep -Seconds 2
    
    Start-Process "hostname" -WindowStyle Hidden -Wait
    Start-Sleep -Seconds 2
    
    # Run more suspicious commands
    Write-TestLog "Running suspicious discovery commands..." "INFO"
    Start-Process "cmd.exe" -ArgumentList "/c net user > nul 2>&1" -WindowStyle Hidden -Wait
    Start-Sleep -Seconds 2
    
    Start-Process "cmd.exe" -ArgumentList "/c whoami /all > nul 2>&1" -WindowStyle Hidden -Wait
    Start-Sleep -Seconds 5
    
    # Analyze results
    $finalStats = Get-LogFileStats $SecurityEventsPath
    $newEntries = $finalStats.LineCount - $initialStats.LineCount
    
    Write-TestLog "New entries after discovery tests: $newEntries" "INFO"
    
    if ($newEntries -le 2) {
        Write-TestLog "PASS: Context-aware filtering appears effective" "SUCCESS"
        return $true
    } else {
        # Check if entries are for suspicious commands only
        $recentEntries = Get-Content $SecurityEventsPath | Select-Object -Last $newEntries
        $suspiciousEntries = $recentEntries | Where-Object { $_ -match "(whoami.*\/all|net user)" }
        
        if ($suspiciousEntries.Count -gt 0 -and $suspiciousEntries.Count -eq $newEntries) {
            Write-TestLog "PASS: Only suspicious commands were logged" "SUCCESS"
            return $true
        } else {
            Write-TestLog "WARN: Context awareness may need adjustment" "WARN"
            return $false
        }
    }
}

function Show-TestSummary {
    param([hashtable]$Results)
    
    Write-TestLog "`n" + "=" * 80 "INFO"
    Write-TestLog "UNIFIED SECURITY LOGGER - DEBUG VALIDATION SUMMARY" "INFO" 
    Write-TestLog "=" * 80 "INFO"
    
    $totalTests = $Results.Count
    $passedTests = ($Results.Values | Where-Object { $_ -eq $true }).Count
    
    foreach ($test in $Results.Keys) {
        $status = if ($Results[$test]) { "PASS" } else { "FAIL" }
        $color = if ($Results[$test]) { "SUCCESS" } else { "ERROR" }
        Write-TestLog "$($test.PadRight(25)): $status" $color
    }
    
    $successRate = if ($totalTests -gt 0) { [math]::Round(($passedTests / $totalTests) * 100) } else { 0 }
    Write-TestLog "`nOVERALL RESULT: $passedTests/$totalTests tests passed ($successRate%)" "INFO"
    
    if ($successRate -ge 80) {
        Write-TestLog "EXCELLENT: Debug fixes are working well" "SUCCESS"
    } elseif ($successRate -ge 60) {
        Write-TestLog "GOOD: Most fixes are working, minor issues detected" "SUCCESS"
    } else {
        Write-TestLog "NEEDS ATTENTION: Several debug fixes require review" "ERROR"
    }
    
    Write-TestLog "`nRECOMMENDATIONS:" "INFO"
    
    if (-not $Results["RegistryDeduplication"]) {
        Write-TestLog "- Review registry filtering logic for BAM entries" "WARN"
    }
    
    if (-not $Results["USBStateTracking"]) {
        Write-TestLog "- Check USB device state management" "WARN"
    }
    
    if (-not $Results["EventDeduplication"]) {
        Write-TestLog "- Verify event deduplication window and caching" "WARN"
    }
    
    if (-not $Results["SeverityThrottling"]) {
        Write-TestLog "- Adjust severity-based logging thresholds" "WARN"
    }
    
    if (-not $Results["DiscoveryContextAwareness"]) {
        Write-TestLog "- Fine-tune discovery detection context rules" "WARN"
    }
    
    Write-TestLog "=" * 80 "INFO"
}

# Main execution
Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
Write-Host "UNIFIED SECURITY LOGGER - DEBUG VALIDATION" -ForegroundColor Cyan
Write-Host "Testing implemented fixes for false positives and duplicates" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan

Write-TestLog "Starting debug validation tests..." "INFO"
Write-TestLog "Test Type: $TestType" "INFO"
Write-TestLog "Test Duration: $TestDuration seconds" "INFO"
Write-TestLog "Create Test Events: $CreateTestEvents" "INFO"

# Backup current log
if (-not (Backup-LogFile)) {
    Write-TestLog "Warning: Could not create backup, proceeding anyway..." "WARN"
}

$TestResults = @{}

# Run selected tests
if ($TestType -in @("All", "Registry")) {
    $TestResults["RegistryDeduplication"] = Test-RegistryDeduplication
}

if ($TestType -in @("All", "USB")) {
    $TestResults["USBStateTracking"] = Test-USBStateTracking
}

if ($TestType -in @("All", "Deduplication")) {
    $TestResults["EventDeduplication"] = Test-EventDeduplication
}

if ($TestType -in @("All", "Throttling")) {
    $TestResults["SeverityThrottling"] = Test-SeverityThrottling
}

if ($TestType -in @("All", "Discovery")) {
    $TestResults["DiscoveryContextAwareness"] = Test-DiscoveryContextAwareness
}

# Show results
Show-TestSummary $TestResults

Write-TestLog "`nDebug validation completed at $(Get-Date)" "INFO"

if (Test-Path $BackupPath) {
    Write-TestLog "Log backup available at: $BackupPath" "INFO"
}
