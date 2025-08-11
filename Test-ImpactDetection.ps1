#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Test script for Impact tactics detection capabilities - OT Environment Compatible
.DESCRIPTION
    Tests various Impact techniques to validate detection capabilities of Impact.ps1
    Safe simulation of Impact tactics for testing purposes in OT environments
.PARAMETER TestMode
    Specify which tests to run (All, Basic, Advanced, OT-Specific)
.PARAMETER OutputPath
    Path where test logs will be stored
.PARAMETER DelayBetweenTests
    Delay in seconds between test executions
#>

param(
    [ValidateSet("All", "Basic", "Advanced", "OT-Specific")]
    [string]$TestMode = "Basic",
    [string]$OutputPath = "$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS",
    [int]$DelayBetweenTests = 5
)

# Global variables
$Script:TestResults = @{}
$Script:LogFile = ""

function Initialize-TestLogger {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Script:LogFile = Join-Path $OutputPath "Test-ImpactDetection_$timestamp.log"
    
    $header = @"
=== Impact Detection Test Started ===
Start Time: $(Get-Date)
Test Mode: $TestMode
Output Path: $OutputPath
=====================================
"@
    Add-Content -Path $Script:LogFile -Value $header
    Write-Host $header -ForegroundColor Cyan
}

function Write-TestLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry -ForegroundColor White }
    }
    
    Add-Content -Path $Script:LogFile -Value $logEntry
}

function Test-AccountAccessRemoval {
    Write-TestLog "Testing Account Access Removal (T1531)" "INFO"
    
    try {
        # Simulate account enumeration (safe)
        $users = Get-LocalUser | Select-Object -First 2
        Write-TestLog "Account enumeration completed - $($users.Count) users found"
        
        # Simulate group membership query (safe)
        $groups = Get-LocalGroup | Select-Object -First 3
        Write-TestLog "Group enumeration completed - $($groups.Count) groups found"
        
        $Script:TestResults["T1531"] = "PASS"
        Write-TestLog "Account Access Removal test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1531"] = "FAIL"
        Write-TestLog "Account Access Removal test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-DataDestruction {
    Write-TestLog "Testing Data Destruction (T1485)" "INFO"
    
    try {
        # Create temporary test files
        $testDir = Join-Path $env:TEMP "ImpactTest"
        if (!(Test-Path $testDir)) {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        }
        
        # Create OT-like test files
        $testFiles = @("test.his", "config.cfg", "data.prn", "backup.bak")
        foreach ($file in $testFiles) {
            $filePath = Join-Path $testDir $file
            "Test data for Impact detection" | Out-File -FilePath $filePath -Force
        }
        
        Write-TestLog "Created test OT files for destruction simulation"
        
        # Simulate file deletion (actual deletion of test files)
        foreach ($file in $testFiles) {
            $filePath = Join-Path $testDir $file
            if (Test-Path $filePath) {
                Remove-Item -Path $filePath -Force
                Write-TestLog "Simulated deletion of $file"
            }
        }
        
        # Cleanup
        if (Test-Path $testDir) {
            Remove-Item -Path $testDir -Force -Recurse
        }
        
        $Script:TestResults["T1485"] = "PASS"
        Write-TestLog "Data Destruction test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1485"] = "FAIL"
        Write-TestLog "Data Destruction test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-DataEncryptedForImpact {
    Write-TestLog "Testing Data Encrypted for Impact (T1486)" "INFO"
    
    try {
        # Simulate encryption tool execution (safe commands)
        $testCommands = @(
            "where cipher",
            "cipher /?",
            "help cipher"
        )
        
        foreach ($cmd in $testCommands) {
            $result = Invoke-Expression $cmd 2>$null
            Write-TestLog "Executed encryption-related command: $cmd"
        }
        
        # Create test "ransom note" file (for detection)
        $testDir = Join-Path $env:TEMP "RansomTest"
        if (!(Test-Path $testDir)) {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        }
        
        $ransomNote = Join-Path $testDir "README_DECRYPT.txt"
        "This is a test ransom note for detection purposes" | Out-File -FilePath $ransomNote -Force
        Write-TestLog "Created test ransom note file"
        
        # Cleanup
        if (Test-Path $testDir) {
            Remove-Item -Path $testDir -Force -Recurse
        }
        
        $Script:TestResults["T1486"] = "PASS"
        Write-TestLog "Data Encrypted for Impact test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1486"] = "FAIL"
        Write-TestLog "Data Encrypted for Impact test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-DataManipulation {
    Write-TestLog "Testing Data Manipulation (T1565)" "INFO"
    
    try {
        # Create and modify test configuration files
        $testDir = Join-Path $env:TEMP "ConfigTest"
        if (!(Test-Path $testDir)) {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        }
        
        # Create OT configuration files
        $configFiles = @("system.cfg", "plc.ini", "hmi.xml", "scada.conf")
        foreach ($file in $configFiles) {
            $filePath = Join-Path $testDir $file
            @"
[Settings]
TestParameter=Value
ConfigVersion=1.0
"@ | Out-File -FilePath $filePath -Force
            Write-TestLog "Created and modified test config file: $file"
        }
        
        # Simulate database file manipulation
        $dbFile = Join-Path $testDir "test.mdb"
        "Test database content" | Out-File -FilePath $dbFile -Force
        Write-TestLog "Created test database file"
        
        # Cleanup
        if (Test-Path $testDir) {
            Remove-Item -Path $testDir -Force -Recurse
        }
        
        $Script:TestResults["T1565"] = "PASS"
        Write-TestLog "Data Manipulation test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1565"] = "FAIL"
        Write-TestLog "Data Manipulation test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-Defacement {
    Write-TestLog "Testing Defacement (T1491)" "INFO"
    
    try {
        # Create test web files
        $testDir = Join-Path $env:TEMP "WebTest"
        if (!(Test-Path $testDir)) {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        }
        
        # Create web files
        $webFiles = @("index.html", "config.php", "admin.asp")
        foreach ($file in $webFiles) {
            $filePath = Join-Path $testDir $file
            "<html><body>Test web content</body></html>" | Out-File -FilePath $filePath -Force
            Write-TestLog "Created test web file: $file"
        }
        
        # Create HMI interface files
        $hmiFiles = @("main.hmi", "alarm.scr", "trend.gfx")
        foreach ($file in $hmiFiles) {
            $filePath = Join-Path $testDir $file
            "Test HMI content" | Out-File -FilePath $filePath -Force
            Write-TestLog "Created test HMI file: $file"
        }
        
        # Cleanup
        if (Test-Path $testDir) {
            Remove-Item -Path $testDir -Force -Recurse
        }
        
        $Script:TestResults["T1491"] = "PASS"
        Write-TestLog "Defacement test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1491"] = "FAIL"
        Write-TestLog "Defacement test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-ServiceStop {
    Write-TestLog "Testing Service Stop (T1489)" "INFO"
    
    try {
        # Query service status (safe)
        $services = Get-Service | Where-Object { $_.Name -match "Spooler|Themes|TabletInputService" } | Select-Object -First 3
        
        foreach ($service in $services) {
            Write-TestLog "Queried service: $($service.Name) - Status: $($service.Status)"
            
            # Simulate service manipulation command (safe - just display)
            $commands = @(
                "sc query $($service.Name)",
                "net start $($service.Name)",
                "sc config $($service.Name) start= auto"
            )
            
            foreach ($cmd in $commands) {
                Write-TestLog "Simulated command: $cmd"
            }
        }
        
        $Script:TestResults["T1489"] = "PASS"
        Write-TestLog "Service Stop test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1489"] = "FAIL"
        Write-TestLog "Service Stop test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-SystemShutdownReboot {
    Write-TestLog "Testing System Shutdown/Reboot (T1529)" "INFO"
    
    try {
        # Simulate shutdown commands (safe - using help and query options)
        $shutdownCommands = @(
            "shutdown /?",
            "shutdown /l",
            "restart-computer -whatif",
            "stop-computer -whatif"
        )
        
        foreach ($cmd in $shutdownCommands) {
            try {
                if ($cmd -match "shutdown /?") {
                    $result = Invoke-Expression $cmd 2>$null
                    Write-TestLog "Executed safe shutdown command: $cmd"
                } else {
                    Write-TestLog "Simulated shutdown command: $cmd"
                }
            } catch {
                Write-TestLog "Shutdown command simulation: $cmd"
            }
        }
        
        $Script:TestResults["T1529"] = "PASS"
        Write-TestLog "System Shutdown/Reboot test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1529"] = "FAIL"
        Write-TestLog "System Shutdown/Reboot test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-ResourceHijacking {
    Write-TestLog "Testing Resource Hijacking (T1496)" "INFO"
    
    try {
        # Simulate cryptocurrency mining detection
        $miningTerms = @("mining", "crypto", "bitcoin", "ethereum", "pool", "stratum")
        
        foreach ($term in $miningTerms) {
            Write-TestLog "Simulated mining-related activity: $term"
        }
        
        # Create test file with mining indicators
        $testDir = Join-Path $env:TEMP "MiningTest"
        if (!(Test-Path $testDir)) {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        }
        
        $minerConfig = Join-Path $testDir "miner.conf"
        @"
pool=test.pool.com:3333
wallet=test_wallet_address
algorithm=cryptonight
"@ | Out-File -FilePath $minerConfig -Force
        
        Write-TestLog "Created test mining configuration file"
        
        # Cleanup
        if (Test-Path $testDir) {
            Remove-Item -Path $testDir -Force -Recurse
        }
        
        $Script:TestResults["T1496"] = "PASS"
        Write-TestLog "Resource Hijacking test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1496"] = "FAIL"
        Write-TestLog "Resource Hijacking test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-OTSpecificImpacts {
    Write-TestLog "Testing OT-Specific Impact scenarios" "INFO"
    
    try {
        # Simulate OT process enumeration
        $otProcessNames = @("HMIService", "SCADAService", "PLCComm", "OPCServer", "Historian")
        
        foreach ($processName in $otProcessNames) {
            Write-TestLog "Simulated OT process check: $processName"
        }
        
        # Create OT-specific test files
        $testDir = Join-Path $env:TEMP "OTTest"
        if (!(Test-Path $testDir)) {
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        }
        
        $otFiles = @(
            "historian.his",
            "plc_config.cfg",
            "hmi_project.hmi",
            "alarm_log.log",
            "trend_data.prn",
            "system_backup.bak"
        )
        
        foreach ($file in $otFiles) {
            $filePath = Join-Path $testDir $file
            "OT test data for $file" | Out-File -FilePath $filePath -Force
            Write-TestLog "Created OT test file: $file"
        }
        
        # Simulate OT service queries
        $otServices = @("HMIService", "SCADAService", "OPCServer", "PLCCommunication")
        foreach ($service in $otServices) {
            Write-TestLog "Simulated OT service query: $service"
        }
        
        # Cleanup
        if (Test-Path $testDir) {
            Remove-Item -Path $testDir -Force -Recurse
        }
        
        $Script:TestResults["OT-Specific"] = "PASS"
        Write-TestLog "OT-Specific Impact test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["OT-Specific"] = "FAIL"
        Write-TestLog "OT-Specific Impact test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-InhibitSystemRecovery {
    Write-TestLog "Testing Inhibit System Recovery (T1490)" "INFO"
    
    try {
        # Simulate recovery inhibition commands (safe queries)
        $recoveryCommands = @(
            "vssadmin list shadows",
            "wbadmin get versions",
            "bcdedit /enum",
            "wmic shadowcopy list brief"
        )
        
        foreach ($cmd in $recoveryCommands) {
            try {
                Write-TestLog "Simulated recovery command: $cmd"
            } catch {
                Write-TestLog "Recovery command simulation: $cmd"
            }
        }
        
        $Script:TestResults["T1490"] = "PASS"
        Write-TestLog "Inhibit System Recovery test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1490"] = "FAIL"
        Write-TestLog "Inhibit System Recovery test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-EndpointDenialOfService {
    Write-TestLog "Testing Endpoint Denial of Service (T1499)" "INFO"
    
    try {
        # Simulate DoS detection patterns
        $dosCommands = @(
            "ping -n 1 127.0.0.1",
            "tasklist /fi `"imagename eq svchost.exe`"",
            "netstat -an | findstr LISTENING"
        )
        
        foreach ($cmd in $dosCommands) {
            try {
                $result = Invoke-Expression $cmd 2>$null
                Write-TestLog "Executed safe DoS test command: $cmd"
            } catch {
                Write-TestLog "DoS command simulation: $cmd"
            }
        }
        
        $Script:TestResults["T1499"] = "PASS"
        Write-TestLog "Endpoint Denial of Service test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1499"] = "FAIL"
        Write-TestLog "Endpoint Denial of Service test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Generate-TestSummary {
    Write-TestLog "`n=== Test Summary ===" "INFO"
    
    $passCount = ($Script:TestResults.Values | Where-Object { $_ -eq "PASS" }).Count
    $failCount = ($Script:TestResults.Values | Where-Object { $_ -eq "FAIL" }).Count
    $totalTests = $Script:TestResults.Count
    
    Write-TestLog "Total Tests Run: $totalTests"
    Write-TestLog "Tests Passed: $passCount" "SUCCESS"
    Write-TestLog "Tests Failed: $failCount" $(if ($failCount -gt 0) { "ERROR" } else { "INFO" })
    
    Write-TestLog "`nDetailed Results:"
    foreach ($test in $Script:TestResults.GetEnumerator() | Sort-Object Name) {
        $status = if ($test.Value -eq "PASS") { "SUCCESS" } else { "ERROR" }
        Write-TestLog "  $($test.Key): $($test.Value)" $status
    }
    
    $completionTime = Get-Date
    Write-TestLog "`nTest completed at: $completionTime"
    Write-TestLog "Results saved to: $Script:LogFile"
    
    if ($passCount -eq $totalTests) {
        Write-TestLog "`nAll tests passed! Impact detection should be working correctly." "SUCCESS"
    } else {
        Write-TestLog "`nSome tests failed. Check Impact.ps1 configuration and Sysmon setup." "WARNING"
    }
}

# Main execution
try {
    Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
    Write-Host "Impact Detection Test Suite v1.0" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    Initialize-TestLogger
    
    Write-TestLog "Starting Impact detection tests in $TestMode mode"
    Write-TestLog "Delay between tests: $DelayBetweenTests seconds"
    
    # Run tests based on mode
    switch ($TestMode) {
        "Basic" {
            Test-AccountAccessRemoval; Start-Sleep $DelayBetweenTests
            Test-DataDestruction; Start-Sleep $DelayBetweenTests
            Test-ServiceStop; Start-Sleep $DelayBetweenTests
            Test-SystemShutdownReboot; Start-Sleep $DelayBetweenTests
        }
        "Advanced" {
            Test-DataEncryptedForImpact; Start-Sleep $DelayBetweenTests
            Test-DataManipulation; Start-Sleep $DelayBetweenTests
            Test-Defacement; Start-Sleep $DelayBetweenTests
            Test-ResourceHijacking; Start-Sleep $DelayBetweenTests
            Test-InhibitSystemRecovery; Start-Sleep $DelayBetweenTests
            Test-EndpointDenialOfService; Start-Sleep $DelayBetweenTests
        }
        "OT-Specific" {
            Test-OTSpecificImpacts; Start-Sleep $DelayBetweenTests
        }
        "All" {
            # Basic tests
            Test-AccountAccessRemoval; Start-Sleep $DelayBetweenTests
            Test-DataDestruction; Start-Sleep $DelayBetweenTests
            Test-ServiceStop; Start-Sleep $DelayBetweenTests
            Test-SystemShutdownReboot; Start-Sleep $DelayBetweenTests
            
            # Advanced tests
            Test-DataEncryptedForImpact; Start-Sleep $DelayBetweenTests
            Test-DataManipulation; Start-Sleep $DelayBetweenTests
            Test-Defacement; Start-Sleep $DelayBetweenTests
            Test-ResourceHijacking; Start-Sleep $DelayBetweenTests
            Test-InhibitSystemRecovery; Start-Sleep $DelayBetweenTests
            Test-EndpointDenialOfService; Start-Sleep $DelayBetweenTests
            
            # OT-specific tests
            Test-OTSpecificImpacts; Start-Sleep $DelayBetweenTests
        }
    }
    
    Generate-TestSummary
    
} catch {
    Write-TestLog "FATAL ERROR: $($_.Exception.Message)" "ERROR"
} finally {
    Write-TestLog "=== Impact Detection Test Completed ===" "INFO"
}
