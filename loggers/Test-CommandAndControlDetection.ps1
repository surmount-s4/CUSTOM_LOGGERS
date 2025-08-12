#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Test script for Command And Control detection capabilities
.DESCRIPTION
    Simulates various Command And Control techniques to test the monitoring script's detection abilities.
    WARNING: This script performs potentially suspicious activities for testing purposes only.
.PARAMETER TestDuration
    Duration in seconds for each test (default: 5)
.PARAMETER OutputPath
    Path where test results will be logged
#>

param(
    [int]$TestDuration = 5,
    [string]$OutputPath = "$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS"
)

# Global variables
$Script:TestResults = @{}
$Script:TestStartTime = Get-Date

function Write-TestLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage -ForegroundColor White }
    }
    
    # Log to file
    $logFile = Join-Path $OutputPath "Test-CommandAndControlDetection_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Add-Content -Path $logFile -Value $logMessage
}

function Test-ApplicationLayerProtocol {
    Write-TestLog "Testing Application Layer Protocol (T1071)" "INFO"
    
    try {
        # Test DNS queries that might indicate tunneling
        Write-TestLog "Performing suspicious DNS queries..." "INFO"
        
        # Generate long DNS query (potential DNS tunneling)
        $longQuery = "a" * 60 + ".test-domain-for-security-testing.com"
        nslookup $longQuery 2>$null | Out-Null
        
        # Test HTTP requests from PowerShell (non-browser)
        Write-TestLog "Making HTTP request from PowerShell..." "INFO"
        try {
            Invoke-WebRequest -Uri "http://httpbin.org/get" -UseBasicParsing -TimeoutSec 5 | Out-Null
        } catch {
            # Expected to potentially fail, that's okay for testing
        }
        
        $Script:TestResults["T1071"] = "Executed"
        Write-TestLog "Application Layer Protocol test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1071"] = "Failed: $($_.Exception.Message)"
        Write-TestLog "Application Layer Protocol test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-DataEncoding {
    Write-TestLog "Testing Data Encoding (T1132)" "INFO"
    
    try {
        # Test base64 encoding operations
        Write-TestLog "Performing base64 encoding operations..." "INFO"
        
        $testString = "This is a test for C2 detection"
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($testString))
        $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
        
        # Test certutil encoding
        Write-TestLog "Testing certutil encoding..." "INFO"
        $tempFile = [System.IO.Path]::GetTempFileName()
        $encodedFile = "$tempFile.enc"
        
        "Test data for encoding" | Out-File -FilePath $tempFile -Encoding ASCII
        & certutil -encode $tempFile $encodedFile 2>$null | Out-Null
        
        # Cleanup
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        Remove-Item $encodedFile -Force -ErrorAction SilentlyContinue
        
        $Script:TestResults["T1132"] = "Executed"
        Write-TestLog "Data Encoding test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1132"] = "Failed: $($_.Exception.Message)"
        Write-TestLog "Data Encoding test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-NonStandardPort {
    Write-TestLog "Testing Non-Standard Port (T1571)" "INFO"
    
    try {
        # Test connections to non-standard ports
        Write-TestLog "Testing connections to non-standard ports..." "INFO"
        
        # Test connection to port 8080
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        try {
            $tcpClient.ConnectAsync("httpbin.org", 8080).Wait(2000)
        } catch {
            # Expected to potentially fail
        } finally {
            $tcpClient.Close()
        }
        
        # Test connection to high port number
        $tcpClient2 = New-Object System.Net.Sockets.TcpClient
        try {
            $tcpClient2.ConnectAsync("8.8.8.8", 53443).Wait(2000)
        } catch {
            # Expected to potentially fail
        } finally {
            $tcpClient2.Close()
        }
        
        $Script:TestResults["T1571"] = "Executed"
        Write-TestLog "Non-Standard Port test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1571"] = "Failed: $($_.Exception.Message)"
        Write-TestLog "Non-Standard Port test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-WebService {
    Write-TestLog "Testing Web Service (T1102)" "INFO"
    
    try {
        # Test connections to common web services from PowerShell
        Write-TestLog "Testing connections to web services..." "INFO"
        
        $webServices = @(
            "https://api.github.com/repos/octocat/Hello-World",
            "https://httpbin.org/user-agent"
        )
        
        foreach ($service in $webServices) {
            try {
                Write-TestLog "Connecting to $service..." "INFO"
                Invoke-WebRequest -Uri $service -UseBasicParsing -TimeoutSec 3 | Out-Null
                Start-Sleep -Seconds 1
            } catch {
                # Expected to potentially fail, that's okay for testing
                Write-TestLog "Connection to $service failed (expected): $($_.Exception.Message)" "INFO"
            }
        }
        
        $Script:TestResults["T1102"] = "Executed"
        Write-TestLog "Web Service test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1102"] = "Failed: $($_.Exception.Message)"
        Write-TestLog "Web Service test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-IngressToolTransfer {
    Write-TestLog "Testing Ingress Tool Transfer (T1105)" "INFO"
    
    try {
        # Simulate tool download activities
        Write-TestLog "Simulating tool download activities..." "INFO"
        
        # Test wget-like command simulation
        $testUrl = "https://httpbin.org/json"
        $tempPath = Join-Path $env:TEMP "test_download.json"
        
        # Simulate Invoke-WebRequest download
        try {
            Write-TestLog "Simulating file download to temp directory..." "INFO"
            Invoke-WebRequest -Uri $testUrl -OutFile $tempPath -UseBasicParsing -TimeoutSec 5
            
            # Create a test executable in temp to simulate tool transfer
            $testExePath = Join-Path $env:TEMP "test_tool.exe"
            Copy-Item -Path "$env:SystemRoot\System32\notepad.exe" -Destination $testExePath -ErrorAction SilentlyContinue
            
            # Cleanup
            Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
            Remove-Item $testExePath -Force -ErrorAction SilentlyContinue
            
        } catch {
            Write-TestLog "Download simulation failed (expected): $($_.Exception.Message)" "INFO"
        }
        
        # Test certutil download simulation
        Write-TestLog "Testing certutil-style download simulation..." "INFO"
        & cmd /c "echo certutil -urlcache -split -f https://httpbin.org/json temp.json"
        
        $Script:TestResults["T1105"] = "Executed"
        Write-TestLog "Ingress Tool Transfer test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1105"] = "Failed: $($_.Exception.Message)"
        Write-TestLog "Ingress Tool Transfer test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-EncryptedChannel {
    Write-TestLog "Testing Encrypted Channel (T1573)" "INFO"
    
    try {
        # Test encrypted communication patterns
        Write-TestLog "Testing encrypted communication patterns..." "INFO"
        
        # Test HTTPS connection
        try {
            Write-TestLog "Making HTTPS connection..." "INFO"
            Invoke-WebRequest -Uri "https://httpbin.org/get" -UseBasicParsing -TimeoutSec 5 | Out-Null
        } catch {
            # Expected to potentially fail
        }
        
        # Simulate encryption tool usage
        Write-TestLog "Simulating encryption tool command..." "INFO"
        & cmd /c "echo openssl enc -aes-256-cbc -in test.txt -out test.enc"
        
        $Script:TestResults["T1573"] = "Executed"
        Write-TestLog "Encrypted Channel test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1573"] = "Failed: $($_.Exception.Message)"
        Write-TestLog "Encrypted Channel test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-RemoteAccessTools {
    Write-TestLog "Testing Remote Access Tools (T1219)" "INFO"
    
    try {
        # Simulate remote access tool detection
        Write-TestLog "Simulating remote access tool activities..." "INFO"
        
        # Test RDP port connection attempt
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        try {
            Write-TestLog "Testing connection to RDP port..." "INFO"
            $tcpClient.ConnectAsync("127.0.0.1", 3389).Wait(1000)
        } catch {
            # Expected to fail on most systems
        } finally {
            $tcpClient.Close()
        }
        
        # Test VNC port connection attempt
        $tcpClient2 = New-Object System.Net.Sockets.TcpClient
        try {
            Write-TestLog "Testing connection to VNC port..." "INFO"
            $tcpClient2.ConnectAsync("127.0.0.1", 5900).Wait(1000)
        } catch {
            # Expected to fail on most systems
        } finally {
            $tcpClient2.Close()
        }
        
        $Script:TestResults["T1219"] = "Executed"
        Write-TestLog "Remote Access Tools test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1219"] = "Failed: $($_.Exception.Message)"
        Write-TestLog "Remote Access Tools test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-DynamicResolution {
    Write-TestLog "Testing Dynamic Resolution (T1568)" "INFO"
    
    try {
        # Test suspicious DNS patterns
        Write-TestLog "Testing suspicious DNS resolution patterns..." "INFO"
        
        # Generate DGA-like domain queries
        $dgaDomains = @(
            "abcd1234efgh.com",
            "xkjf9384sldk.net", 
            "mzpq8372hdsk.org"
        )
        
        foreach ($domain in $dgaDomains) {
            try {
                Write-TestLog "Querying potential DGA domain: $domain" "INFO"
                nslookup $domain 2>$null | Out-Null
                Start-Sleep -Seconds 1
            } catch {
                # Expected to fail
            }
        }
        
        # Test fast-flux-like domains
        try {
            Write-TestLog "Testing fast-flux-like domain..." "INFO"
            nslookup "test-ff-domain.tk" 2>$null | Out-Null
        } catch {
            # Expected to fail
        }
        
        $Script:TestResults["T1568"] = "Executed"
        Write-TestLog "Dynamic Resolution test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1568"] = "Failed: $($_.Exception.Message)"
        Write-TestLog "Dynamic Resolution test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Test-ProtocolTunneling {
    Write-TestLog "Testing Protocol Tunneling (T1572)" "INFO"
    
    try {
        # Simulate tunneling tool commands
        Write-TestLog "Simulating tunneling tool commands..." "INFO"
        
        # Simulate SSH tunneling commands
        & cmd /c "echo ssh -L 8080:localhost:80 user@server.com"
        & cmd /c "echo ssh -D 1080 user@proxy.com"
        
        # Simulate other tunneling tools
        & cmd /c "echo stunnel /etc/stunnel/stunnel.conf"
        & cmd /c "echo socat TCP-LISTEN:8080,fork TCP:target:80"
        
        $Script:TestResults["T1572"] = "Executed"
        Write-TestLog "Protocol Tunneling test completed" "SUCCESS"
        
    } catch {
        $Script:TestResults["T1572"] = "Failed: $($_.Exception.Message)"
        Write-TestLog "Protocol Tunneling test failed: $($_.Exception.Message)" "ERROR"
    }
}

function Show-TestSummary {
    Write-TestLog "`n=== Command And Control Detection Test Summary ===" "INFO"
    Write-TestLog "Test Start Time: $Script:TestStartTime" "INFO"
    Write-TestLog "Test End Time: $(Get-Date)" "INFO"
    Write-TestLog "Total Test Duration: $((Get-Date) - $Script:TestStartTime)" "INFO"
    Write-TestLog "`nTest Results:" "INFO"
    
    $totalTests = $Script:TestResults.Count
    $successfulTests = ($Script:TestResults.Values | Where-Object { $_ -eq "Executed" }).Count
    $failedTests = $totalTests - $successfulTests
    
    foreach ($test in $Script:TestResults.Keys | Sort-Object) {
        $status = $Script:TestResults[$test]
        $level = if ($status -eq "Executed") { "SUCCESS" } else { "ERROR" }
        Write-TestLog "  $test : $status" $level
    }
    
    Write-TestLog "`nSummary: $successfulTests/$totalTests tests executed successfully" "INFO"
    
    if ($failedTests -gt 0) {
        Write-TestLog "Note: Some test failures are expected in restricted environments" "WARNING"
    }
    
    Write-TestLog "`nNow run the CommandAndControl.ps1 monitoring script to see if it detects these activities!" "INFO"
}

# Main execution
Write-TestLog "Starting Command And Control Detection Test Suite" "INFO"
Write-TestLog "WARNING: This script generates potentially suspicious network and system activities for testing purposes only" "WARNING"
Write-TestLog "Test Duration per technique: $TestDuration seconds" "INFO"
Write-TestLog "Output Path: $OutputPath" "INFO"

try {
    # Run all tests
    Test-ApplicationLayerProtocol
    Start-Sleep -Seconds $TestDuration
    
    Test-DataEncoding
    Start-Sleep -Seconds $TestDuration
    
    Test-NonStandardPort
    Start-Sleep -Seconds $TestDuration
    
    Test-WebService
    Start-Sleep -Seconds $TestDuration
    
    Test-IngressToolTransfer
    Start-Sleep -Seconds $TestDuration
    
    Test-EncryptedChannel
    Start-Sleep -Seconds $TestDuration
    
    Test-RemoteAccessTools
    Start-Sleep -Seconds $TestDuration
    
    Test-DynamicResolution
    Start-Sleep -Seconds $TestDuration
    
    Test-ProtocolTunneling
    Start-Sleep -Seconds $TestDuration
    
} catch {
    Write-TestLog "Critical error during testing: $($_.Exception.Message)" "ERROR"
} finally {
    Show-TestSummary
}

Write-TestLog "Command And Control Detection Test Suite completed" "SUCCESS"
