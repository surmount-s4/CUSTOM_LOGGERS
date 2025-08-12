#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Test script for Defense Evasion Monitor - Generates test events
.DESCRIPTION
    Creates controlled test events to validate Defense Evasion detection capabilities
    Safe for testing environments - does not perform actual malicious activities
.PARAMETER TestType
    Type of test to run (All, TokenManipulation, ProcessInjection, etc.)
.PARAMETER Verbose
    Enable verbose output
#>

param(
    [ValidateSet("All", "TokenManipulation", "ProcessInjection", "Masquerading", "Registry", "ProxyExecution", "HideArtifacts", "ImpairDefenses", "Obfuscation", "IndicatorRemoval")]
    [string]$TestType = "All",
    [switch]$Verbose
)

$TestLogPath = "$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\DefenseEvasion_Test.log"

function Write-TestLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [TEST] $Message"
    Write-Host $logEntry -ForegroundColor Cyan
    Add-Content -Path $TestLogPath -Value $logEntry
}

function Test-TokenManipulation {
    Write-TestLog "Testing Token Manipulation detection (T1134)..."
    try {
        # Generate events that should trigger token manipulation detection
        Write-TestLog "Attempting to enumerate tokens (safe test)..."
        whoami /priv | Out-Null
        Start-Sleep 2
        Write-TestLog "Token Manipulation test completed"
    } catch {
        Write-TestLog "Token Manipulation test error: $($_.Exception.Message)"
    }
}

function Test-ProcessInjection {
    Write-TestLog "Testing Process Injection detection (T1055)..."
    try {
        # Safe process enumeration that may trigger detection
        Write-TestLog "Enumerating running processes..."
        Get-Process | Where-Object { $_.ProcessName -eq "explorer" } | Select-Object -First 1 | Out-Null
        Start-Sleep 2
        Write-TestLog "Process Injection test completed"
    } catch {
        Write-TestLog "Process Injection test error: $($_.Exception.Message)"
    }
}

function Test-Masquerading {
    Write-TestLog "Testing Masquerading detection (T1036)..."
    try {
        # Create a temporary file in a suspicious location
        $tempPath = "$env:TEMP\svchost_test.txt"
        Write-TestLog "Creating test file in suspicious location: $tempPath"
        "Test content" | Out-File -FilePath $tempPath -Force
        Start-Sleep 2
        Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
        Write-TestLog "Masquerading test completed"
    } catch {
        Write-TestLog "Masquerading test error: $($_.Exception.Message)"
    }
}

function Test-Registry {
    Write-TestLog "Testing Registry Modification detection (T1112)..."
    try {
        # Create and remove a test registry key
        $testKey = "HKCU:\Software\DefenseEvasionTest"
        Write-TestLog "Creating test registry key: $testKey"
        New-Item -Path $testKey -Force | Out-Null
        New-ItemProperty -Path $testKey -Name "TestValue" -Value "TestData" -Force | Out-Null
        Start-Sleep 2
        Remove-Item -Path $testKey -Force -ErrorAction SilentlyContinue
        Write-TestLog "Registry Modification test completed"
    } catch {
        Write-TestLog "Registry Modification test error: $($_.Exception.Message)"
    }
}

function Test-ProxyExecution {
    Write-TestLog "Testing System Binary Proxy Execution detection (T1218)..."
    try {
        # Use certutil to test proxy execution detection
        Write-TestLog "Testing certutil usage..."
        certutil -? | Out-Null
        Start-Sleep 2
        Write-TestLog "Proxy Execution test completed"
    } catch {
        Write-TestLog "Proxy Execution test error: $($_.Exception.Message)"
    }
}

function Test-HideArtifacts {
    Write-TestLog "Testing Hide Artifacts detection (T1564)..."
    try {
        # Create a file with suspicious naming pattern
        $hiddenFile = "$env:TEMP\.hidden_test_file.txt"
        Write-TestLog "Creating hidden test file: $hiddenFile"
        "Hidden content" | Out-File -FilePath $hiddenFile -Force
        Start-Sleep 2
        Remove-Item $hiddenFile -Force -ErrorAction SilentlyContinue
        Write-TestLog "Hide Artifacts test completed"
    } catch {
        Write-TestLog "Hide Artifacts test error: $($_.Exception.Message)"
    }
}

function Test-ImpairDefenses {
    Write-TestLog "Testing Impair Defenses detection (T1562) - SAFE MODE..."
    try {
        # Query firewall status (safe - doesn't modify)
        Write-TestLog "Querying firewall status..."
        netsh firewall show state | Out-Null
        Start-Sleep 2
        Write-TestLog "Impair Defenses test completed"
    } catch {
        Write-TestLog "Impair Defenses test error: $($_.Exception.Message)"
    }
}

function Test-Obfuscation {
    Write-TestLog "Testing Obfuscated Files detection (T1027)..."
    try {
        # Create a file with obfuscated-looking content
        $obfuscatedFile = "$env:TEMP\test_encoded_data.tmp"
        $encodedContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("This is test data"))
        Write-TestLog "Creating obfuscated test file: $obfuscatedFile"
        $encodedContent | Out-File -FilePath $obfuscatedFile -Force
        Start-Sleep 2
        Remove-Item $obfuscatedFile -Force -ErrorAction SilentlyContinue
        Write-TestLog "Obfuscation test completed"
    } catch {
        Write-TestLog "Obfuscation test error: $($_.Exception.Message)"
    }
}

function Test-IndicatorRemoval {
    Write-TestLog "Testing Indicator Removal detection (T1070) - SAFE MODE..."
    try {
        # Create and delete a test log file
        $testLogFile = "$env:TEMP\test_removal.log"
        Write-TestLog "Creating and removing test log file: $testLogFile"
        "Test log content" | Out-File -FilePath $testLogFile -Force
        Start-Sleep 1
        Remove-Item $testLogFile -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
        Write-TestLog "Indicator Removal test completed"
    } catch {
        Write-TestLog "Indicator Removal test error: $($_.Exception.Message)"
    }
}

function Run-AllTests {
    Write-TestLog "Running all Defense Evasion tests..."
    Test-TokenManipulation
    Test-ProcessInjection
    Test-Masquerading
    Test-Registry
    Test-ProxyExecution
    Test-HideArtifacts
    Test-ImpairDefenses
    Test-Obfuscation
    Test-IndicatorRemoval
    Write-TestLog "All tests completed"
}

# Main execution
try {
    Write-Host "`n" + "=" * 60 -ForegroundColor Green
    Write-Host "Defense Evasion Monitor Test Suite" -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Green
    
    Write-TestLog "Starting Defense Evasion test suite..."
    Write-TestLog "Test type: $TestType"
    Write-TestLog "IMPORTANT: These are safe tests that do not perform malicious activities"
    
    # Wait for user confirmation
    Write-Host "`nThis test will generate events that should be detected by the Defense Evasion monitor." -ForegroundColor Yellow
    Write-Host "Make sure the Defense Evasion monitor is running in another PowerShell window." -ForegroundColor Yellow
    Write-Host "`nPress Enter to continue or Ctrl+C to cancel..." -ForegroundColor White
    Read-Host
    
    switch ($TestType) {
        "All" { Run-AllTests }
        "TokenManipulation" { Test-TokenManipulation }
        "ProcessInjection" { Test-ProcessInjection }
        "Masquerading" { Test-Masquerading }
        "Registry" { Test-Registry }
        "ProxyExecution" { Test-ProxyExecution }
        "HideArtifacts" { Test-HideArtifacts }
        "ImpairDefenses" { Test-ImpairDefenses }
        "Obfuscation" { Test-Obfuscation }
        "IndicatorRemoval" { Test-IndicatorRemoval }
    }
    
    Write-Host "`n" + "=" * 60 -ForegroundColor Green
    Write-TestLog "Test suite completed successfully"
    Write-Host "Check the Defense Evasion monitor output for detected events." -ForegroundColor Green
    Write-Host "Test log saved to: $TestLogPath" -ForegroundColor White
    Write-Host "=" * 60 -ForegroundColor Green
    
} catch {
    Write-TestLog "Test suite error: $($_.Exception.Message)"
    Write-Host "Error occurred during testing. Check the log file for details." -ForegroundColor Red
}
