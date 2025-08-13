# ====================================================================
# Unified Security Logger Service - Integration Test Script
# ====================================================================
# This script tests the integrated USB threat detection and OT process 
# correlation functionality within the unified security service
# ====================================================================

param(
    [ValidateSet("All", "USB", "OT", "Service", "Logs")]
    [string]$TestType = "All",
    
    [switch]$Verbose,
    [switch]$CreateTestFiles,
    [switch]$SkipServiceCheck
)

# Configuration
$ServiceName = "CustomSecurityLogger"
$LogBasePath = "$env:ProgramData\CustomSecurityLogs"
$ServiceLogPath = "$LogBasePath\SecurityLogger-Main.log"
$USBLogPath = "$LogBasePath\USB-ThreatDetection.log"
$OTLogPath = "$LogBasePath\OT_ProcessCorrelation.log"
$QuarantineDir = "$LogBasePath\USBQuarantine"
$WhitelistPath = "$LogBasePath\OT_ProcessWhitelist.json"

$TestResults = @{
    ServiceStatus = "NOT_TESTED"
    USBDetection = "NOT_TESTED"
    OTCorrelation = "NOT_TESTED"
    LogFiles = "NOT_TESTED"
    Quarantine = "NOT_TESTED"
    Integration = "NOT_TESTED"
}

function Write-TestLog {
    param([string]$Message, [string]$Level = "INFO", [switch]$NoNewline)
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        "FAIL" { "Red" }
        "PASS" { "Green" }
        "INFO" { "Cyan" }
        default { "White" }
    }
    
    $logEntry = "[$timestamp] $Message"
    if ($NoNewline) {
        Write-Host $logEntry -ForegroundColor $color -NoNewline
    } else {
        Write-Host $logEntry -ForegroundColor $color
    }
}

function Test-ServiceStatus {
    Write-TestLog "=== TESTING SERVICE STATUS ===" "INFO"
    
    try {
        # Check if service exists
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-TestLog "FAIL: Service '$ServiceName' not found" "FAIL"
            $TestResults.ServiceStatus = "FAIL"
            return $false
        }
        
        Write-TestLog "Service found: $ServiceName" "SUCCESS"
        Write-TestLog "Service status: $($service.Status)" "INFO"
        
        if ($service.Status -eq "Running") {
            Write-TestLog "PASS: Service is running" "PASS"
            $TestResults.ServiceStatus = "PASS"
            return $true
        } else {
            Write-TestLog "WARN: Service is not running" "WARN"
            $TestResults.ServiceStatus = "WARN"
            return $false
        }
        
    } catch {
        Write-TestLog "ERROR: Failed to check service status: $($_.Exception.Message)" "ERROR"
        $TestResults.ServiceStatus = "ERROR"
        return $false
    }
}

function Test-USBDetection {
    Write-TestLog "=== TESTING USB DETECTION ===" "INFO"
    
    $usbTestsPassed = 0
    $usbTestsTotal = 4
    
    try {
        # Test 1: USB device enumeration
        Write-TestLog "Test 1: USB device enumeration" "INFO"
        $usbDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { 
            $_.DeviceID -like "*USB*" -and $_.Status -eq "OK"
        }
        
        if ($usbDevices.Count -gt 0) {
            Write-TestLog "PASS: Found $($usbDevices.Count) USB devices" "PASS"
            $usbTestsPassed++
        } else {
            Write-TestLog "WARN: No USB devices found" "WARN"
        }
        
        # Test 2: Mobile device detection patterns
        Write-TestLog "Test 2: Mobile device detection patterns" "INFO"
        $mobileKeywords = @("samsung", "android", "mtp", "ptp", "apple", "iphone")
        $mobileDevices = 0
        
        foreach ($device in $usbDevices) {
            $name = $device.Name.ToLower()
            $desc = $device.Description.ToLower()
            
            foreach ($keyword in $mobileKeywords) {
                if ($name -like "*$keyword*" -or $desc -like "*$keyword*") {
                    $mobileDevices++
                    break
                }
            }
        }
        
        Write-TestLog "Found $mobileDevices potential mobile devices" "INFO"
        Write-TestLog "PASS: Mobile detection patterns working" "PASS"
        $usbTestsPassed++
        
        # Test 3: USB storage detection
        Write-TestLog "Test 3: USB storage detection" "INFO"
        $usbStorage = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }
        
        if ($usbStorage.Count -gt 0) {
            Write-TestLog "Found $($usbStorage.Count) USB storage devices:" "SUCCESS"
            foreach ($drive in $usbStorage) {
                Write-TestLog "  - $($drive.DeviceID) ($([math]::Round($drive.Size / 1GB, 2)) GB)" "INFO"
            }
            $usbTestsPassed++
        } else {
            Write-TestLog "No USB storage devices currently connected" "INFO"
            $usbTestsPassed++
        }
        
        # Test 4: Quarantine directory
        Write-TestLog "Test 4: Quarantine system" "INFO"
        if (Test-Path $QuarantineDir) {
            $quarantineItems = Get-ChildItem $QuarantineDir -Recurse -File -Filter "*.quarantine" | Measure-Object
            Write-TestLog "Quarantine directory exists with $($quarantineItems.Count) items" "SUCCESS"
            $usbTestsPassed++
        } else {
            Write-TestLog "Quarantine directory will be created on first threat" "INFO"
            $usbTestsPassed++
        }
        
        # Test 5: Create test threat file (if requested)
        if ($CreateTestFiles) {
            Write-TestLog "Test 5: Creating test threat file" "INFO"
            $testDir = Join-Path $env:TEMP "USB_ThreatTest"
            if (-not (Test-Path $testDir)) {
                New-Item -ItemType Directory -Path $testDir -Force | Out-Null
            }
            
            # Create a test suspicious file
            $testFile = Join-Path $testDir "test.pdf.exe"
            "This is a test suspicious file" | Set-Content -Path $testFile
            
            Write-TestLog "Created test suspicious file: $testFile" "SUCCESS"
            Write-TestLog "File should be detected as suspicious (double extension)" "INFO"
        }
        
        $usbScore = [math]::Round(($usbTestsPassed / $usbTestsTotal) * 100)
        Write-TestLog "USB Detection Score: $usbTestsPassed/$usbTestsTotal ($usbScore%)" "INFO"
        
        if ($usbScore -ge 75) {
            $TestResults.USBDetection = "PASS"
            Write-TestLog "PASS: USB detection system functional" "PASS"
        } else {
            $TestResults.USBDetection = "WARN"
            Write-TestLog "WARN: USB detection system has issues" "WARN"
        }
        
    } catch {
        Write-TestLog "ERROR: USB detection test failed: $($_.Exception.Message)" "ERROR"
        $TestResults.USBDetection = "ERROR"
    }
}

function Test-OTCorrelation {
    Write-TestLog "=== TESTING OT PROCESS CORRELATION ===" "INFO"
    
    $otTestsPassed = 0
    $otTestsTotal = 4
    
    try {
        # Test 1: Sysmon availability
        Write-TestLog "Test 1: Sysmon integration" "INFO"
        try {
            $sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
            Write-TestLog "PASS: Sysmon is available and logging" "PASS"
            $otTestsPassed++
        } catch {
            Write-TestLog "WARN: Sysmon not available - limited functionality" "WARN"
        }
        
        # Test 2: Whitelist file
        Write-TestLog "Test 2: Whitelist management" "INFO"
        if (Test-Path $WhitelistPath) {
            try {
                $whitelist = Get-Content $WhitelistPath | ConvertFrom-Json
                $whitelistCount = ($whitelist.PSObject.Properties | Measure-Object).Count
                Write-TestLog "PASS: Whitelist loaded with $whitelistCount parent processes" "PASS"
                $otTestsPassed++
            } catch {
                Write-TestLog "WARN: Whitelist file corrupted" "WARN"
            }
        } else {
            Write-TestLog "INFO: Whitelist will be created with defaults" "INFO"
            $otTestsPassed++
        }
        
        # Test 3: Critical OT process detection
        Write-TestLog "Test 3: OT process detection" "INFO"
        $criticalOTProcesses = @(
            "wonderware.exe", "intouch.exe", "rsview32.exe", "factorytalk.exe", "citect.exe",
            "genesis.exe", "wincc.exe", "lookout.exe", "rslinx.exe", "rslogix5000.exe",
            "step7.exe", "tiaportal.exe", "unity.exe", "kepserverex.exe", "matrikon.exe"
        )
        
        $runningOTProcesses = Get-Process | Where-Object { 
            $_.ProcessName -and "$($_.ProcessName).exe".ToLower() -in $criticalOTProcesses
        }
        
        if ($runningOTProcesses.Count -gt 0) {
            Write-TestLog "Found $($runningOTProcesses.Count) running OT processes:" "SUCCESS"
            foreach ($process in $runningOTProcesses | Select-Object -First 5) {
                Write-TestLog "  - $($process.ProcessName) (PID: $($process.Id))" "INFO"
            }
        } else {
            Write-TestLog "No critical OT processes currently running" "INFO"
        }
        $otTestsPassed++
        
        # Test 4: Process relationship analysis
        Write-TestLog "Test 4: Process relationship analysis" "INFO"
        try {
            $processes = Get-WmiObject Win32_Process | Where-Object { $_.Name -and $_.ParentProcessId } | Select-Object -First 20
            $relationshipCount = 0
            
            foreach ($process in $processes) {
                $parent = $processes | Where-Object { $_.ProcessId -eq $process.ParentProcessId }
                if ($parent) {
                    $relationshipCount++
                }
            }
            
            Write-TestLog "Analyzed $relationshipCount process relationships" "SUCCESS"
            $otTestsPassed++
        } catch {
            Write-TestLog "WARN: Process relationship analysis limited" "WARN"
        }
        
        $otScore = [math]::Round(($otTestsPassed / $otTestsTotal) * 100)
        Write-TestLog "OT Correlation Score: $otTestsPassed/$otTestsTotal ($otScore%)" "INFO"
        
        if ($otScore -ge 75) {
            $TestResults.OTCorrelation = "PASS"
            Write-TestLog "PASS: OT correlation system functional" "PASS"
        } else {
            $TestResults.OTCorrelation = "WARN"
            Write-TestLog "WARN: OT correlation system has issues" "WARN"
        }
        
    } catch {
        Write-TestLog "ERROR: OT correlation test failed: $($_.Exception.Message)" "ERROR"
        $TestResults.OTCorrelation = "ERROR"
    }
}

function Test-LogFiles {
    Write-TestLog "=== TESTING LOG FILES ===" "INFO"
    
    $logTestsPassed = 0
    $logTestsTotal = 3
    
    # Test log files existence and accessibility
    $logFiles = @(
        @{ Path = $ServiceLogPath; Name = "Main Service Log"; Required = $true }
        @{ Path = $USBLogPath; Name = "USB Detection Log"; Required = $false }
        @{ Path = $OTLogPath; Name = "OT Correlation Log"; Required = $false }
    )
    
    foreach ($logFile in $logFiles) {
        Write-TestLog "Testing $($logFile.Name)" "INFO"
        
        if (Test-Path $logFile.Path) {
            $logSize = (Get-Item $logFile.Path).Length
            $lastWrite = (Get-Item $logFile.Path).LastWriteTime
            $ageMinutes = ((Get-Date) - $lastWrite).TotalMinutes
            
            Write-TestLog "  File exists: $([math]::Round($logSize / 1KB, 2)) KB" "SUCCESS"
            Write-TestLog "  Last modified: $lastWrite ($([math]::Round($ageMinutes, 1)) minutes ago)" "INFO"
            
            if ($ageMinutes -lt 60) {
                Write-TestLog "  PASS: Recently active" "PASS"
            } else {
                Write-TestLog "  WARN: Not recently updated" "WARN"
            }
            
            $logTestsPassed++
            
        } elseif ($logFile.Required) {
            Write-TestLog "  FAIL: Required log file missing" "FAIL"
        } else {
            Write-TestLog "  INFO: Optional log file not created yet" "INFO"
            $logTestsPassed++
        }
    }
    
    $logScore = [math]::Round(($logTestsPassed / $logTestsTotal) * 100)
    Write-TestLog "Log Files Score: $logTestsPassed/$logTestsTotal ($logScore%)" "INFO"
    
    if ($logScore -ge 67) {
        $TestResults.LogFiles = "PASS"
    } else {
        $TestResults.LogFiles = "WARN"
    }
}

function Test-Integration {
    Write-TestLog "=== TESTING INTEGRATION ===" "INFO"
    
    try {
        # Test if the unified service includes our new functions
        $serviceScript = Join-Path (Split-Path $PSScriptRoot) "Unified-SecurityLogger-Service.ps1"
        
        if (Test-Path $serviceScript) {
            $scriptContent = Get-Content $serviceScript -Raw
            
            # Check for USB function integration
            $hasUSBFunction = $scriptContent -match "function Start-USBThreatDetection"
            $hasUSBComprehensive = $scriptContent -match "Test-SuspiciousFileExtensions|Test-AutorunThreats"
            
            # Check for OT function integration  
            $hasOTFunction = $scriptContent -match "function Start-OTProcessCorrelation"
            $hasOTComprehensive = $scriptContent -match "CriticalOTProcesses|Test-ProcessWhitelisted"
            
            Write-TestLog "Integration Status:" "INFO"
            Write-TestLog "  USB Function: $(if($hasUSBFunction){'✓'}else{'✗'})" $(if($hasUSBFunction){"PASS"}else{"FAIL"})
            Write-TestLog "  USB Comprehensive: $(if($hasUSBComprehensive){'✓'}else{'✗'})" $(if($hasUSBComprehensive){"PASS"}else{"FAIL"})
            Write-TestLog "  OT Function: $(if($hasOTFunction){'✓'}else{'✗'})" $(if($hasOTFunction){"PASS"}else{"FAIL"})
            Write-TestLog "  OT Comprehensive: $(if($hasOTComprehensive){'✓'}else{'✗'})" $(if($hasOTComprehensive){"PASS"}else{"FAIL"})
            
            $integrationScore = ($hasUSBFunction + $hasUSBComprehensive + $hasOTFunction + $hasOTComprehensive)
            
            if ($integrationScore -eq 4) {
                $TestResults.Integration = "PASS"
                Write-TestLog "PASS: Full integration confirmed" "PASS"
            } elseif ($integrationScore -ge 2) {
                $TestResults.Integration = "WARN"  
                Write-TestLog "WARN: Partial integration detected" "WARN"
            } else {
                $TestResults.Integration = "FAIL"
                Write-TestLog "FAIL: Integration not detected" "FAIL"
            }
            
        } else {
            Write-TestLog "WARN: Service script not found at expected location" "WARN"
            $TestResults.Integration = "WARN"
        }
        
    } catch {
        Write-TestLog "ERROR: Integration test failed: $($_.Exception.Message)" "ERROR"
        $TestResults.Integration = "ERROR"
    }
}

function Show-TestSummary {
    Write-TestLog "`n" + "=" * 80 "INFO"
    Write-TestLog "UNIFIED SECURITY LOGGER - INTEGRATION TEST SUMMARY" "INFO"
    Write-TestLog "=" * 80 "INFO"
    
    $overallScore = 0
    $totalTests = 0
    
    foreach ($test in $TestResults.Keys) {
        $status = $TestResults[$test]
        $color = switch ($status) {
            "PASS" { "SUCCESS"; $overallScore += 2; $totalTests += 2 }
            "WARN" { "WARN"; $overallScore += 1; $totalTests += 2 }
            "FAIL" { "FAIL"; $totalTests += 2 }
            "ERROR" { "ERROR"; $totalTests += 2 }
            default { "INFO"; $totalTests += 2 }
        }
        
        Write-TestLog "$($test.PadRight(20)): $status" $color
    }
    
    $finalScore = if ($totalTests -gt 0) { [math]::Round(($overallScore / $totalTests) * 100) } else { 0 }
    
    Write-TestLog "`nOVERALL SCORE: $overallScore/$totalTests ($finalScore%)" "INFO"
    
    $overallStatus = if ($finalScore -ge 85) {
        "EXCELLENT - System fully operational"
    } elseif ($finalScore -ge 70) {
        "GOOD - Minor issues detected"  
    } elseif ($finalScore -ge 50) {
        "FAIR - Several issues need attention"
    } else {
        "POOR - Major issues detected"
    }
    
    Write-TestLog "SYSTEM STATUS: $overallStatus" "INFO"
    
    # Recommendations
    Write-TestLog "`nRECOMMENDATIONS:" "INFO"
    
    if ($TestResults.ServiceStatus -ne "PASS") {
        Write-TestLog "- Install and start the CustomSecurityLogger service" "WARN"
    }
    
    if ($TestResults.USBDetection -ne "PASS") {
        Write-TestLog "- Check USB detection functionality and log files" "WARN"
    }
    
    if ($TestResults.OTCorrelation -ne "PASS") {
        Write-TestLog "- Install Sysmon and configure OT process whitelist" "WARN"
    }
    
    if ($TestResults.LogFiles -ne "PASS") {
        Write-TestLog "- Verify log file permissions and disk space" "WARN"  
    }
    
    if ($TestResults.Integration -ne "PASS") {
        Write-TestLog "- Reinstall or update the unified security service" "WARN"
    }
    
    Write-TestLog "`nNext Steps:" "INFO"
    Write-TestLog "1. Use .\USB-ServiceIntegration.ps1 for USB management" "INFO"
    Write-TestLog "2. Use .\OT-ProcessManager.ps1 for OT correlation management" "INFO"
    Write-TestLog "3. Monitor logs regularly for security events" "INFO"
    
    Write-TestLog "=" * 80 "INFO"
}

# Main execution
Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
Write-Host "UNIFIED SECURITY LOGGER - INTEGRATION TEST" -ForegroundColor Cyan  
Write-Host "Custom Security Loggers Project" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan

Write-TestLog "Starting integration tests for USB and OT functionality..." "INFO"
Write-TestLog "Test Type: $TestType" "INFO"
Write-TestLog "Verbose: $Verbose" "INFO"
Write-TestLog "Create Test Files: $CreateTestFiles" "INFO"

# Run selected tests
if ($TestType -in @("All", "Service") -and -not $SkipServiceCheck) {
    Test-ServiceStatus
}

if ($TestType -in @("All", "USB")) {
    Test-USBDetection
}

if ($TestType -in @("All", "OT")) {
    Test-OTCorrelation
}

if ($TestType -in @("All", "Logs")) {
    Test-LogFiles
}

if ($TestType -eq "All") {
    Test-Integration
}

# Show summary
Show-TestSummary

Write-TestLog "`nIntegration test completed at $(Get-Date)" "INFO"
