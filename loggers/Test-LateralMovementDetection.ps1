#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Test script for Lateral Movement tactics monitoring - generates test events
.DESCRIPTION
    Generates various lateral movement technique events to test the LateralMovement monitor
    Windows Server 2012 compatible
.PARAMETER DelayBetweenTests
    Delay in seconds between test functions (default: 3)
.PARAMETER Verbose
    Show detailed output during testing
#>

param(
    [int]$DelayBetweenTests = 3,
    [switch]$Verbose = $false
)

Write-Host "=== Lateral Movement Monitor Test Script ===" -ForegroundColor Cyan
Write-Host "This script will generate test events for Lateral Movement techniques" -ForegroundColor Yellow
Write-Host "Make sure the LateralMovement.ps1 monitor is running in another window" -ForegroundColor Green
Write-Host ""

function Test-ExploitationRemoteServices {
    Write-Host "[TEST] Exploitation of Remote Services (T1210)" -ForegroundColor Magenta
    
    Write-Host "  Testing remote service connections..." -ForegroundColor Gray
    # Test connections to administrative ports (safe localhost connections)
    Test-NetConnection -ComputerName "127.0.0.1" -Port 135 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    Test-NetConnection -ComputerName "127.0.0.1" -Port 445 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    Test-NetConnection -ComputerName "127.0.0.1" -Port 5985 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    
    # Simulate process names that might be flagged (safe execution)
    Write-Host "  Testing process detection patterns..." -ForegroundColor Gray
    cmd /c "echo psexec simulation test" | Out-Null
    powershell -Command "Write-Output 'wmiexec simulation test'" | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-InternalSpearphishing {
    Write-Host "[TEST] Internal Spearphishing (T1534)" -ForegroundColor Magenta
    
    Write-Host "  Testing email-related activities..." -ForegroundColor Gray
    # Test email command patterns (safe simulation)
    powershell -Command "# Send-MailMessage simulation test" | Out-Null
    
    # Create temporary files that might look like email attachments
    Write-Host "  Creating temporary attachment-like files..." -ForegroundColor Gray
    $tempPath = "$env:TEMP\TestDoc_$(Get-Date -Format 'yyyyMMdd_HHmmss').docx"
    "Test document content" | Out-File -FilePath $tempPath -Force
    Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-LateralToolTransfer {
    Write-Host "[TEST] Lateral Tool Transfer (T1570)" -ForegroundColor Magenta
    
    Write-Host "  Testing file transfer commands..." -ForegroundColor Gray
    # Safe local file operations that simulate transfer commands
    $testFile = "$env:TEMP\transfer_test.txt"
    "Test content" | Out-File -FilePath $testFile -Force
    
    # Simulate various transfer command patterns
    cmd /c "echo copy test to simulate network copy" | Out-Null
    cmd /c "echo xcopy simulation test" | Out-Null
    cmd /c "echo robocopy simulation test" | Out-Null
    powershell -Command "# Download simulation test" | Out-Null
    cmd /c "echo certutil -urlcache simulation" | Out-Null
    cmd /c "echo bitsadmin transfer simulation" | Out-Null
    
    # Test network connections to common transfer ports
    Write-Host "  Testing transfer port connections..." -ForegroundColor Gray
    Test-NetConnection -ComputerName "127.0.0.1" -Port 21 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    Test-NetConnection -ComputerName "127.0.0.1" -Port 22 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-RemoteServiceSessionHijacking {
    Write-Host "[TEST] Remote Service Session Hijacking (T1563)" -ForegroundColor Magenta
    
    Write-Host "  Testing RDP session patterns..." -ForegroundColor Gray
    # Query current sessions (safe operation)
    query user 2>$null | Out-Null
    quser 2>$null | Out-Null
    
    Write-Host "  Testing SSH-related patterns..." -ForegroundColor Gray
    # Simulate SSH command patterns (safe)
    cmd /c "echo ssh simulation test with ControlMaster" | Out-Null
    powershell -Command "# ssh agent simulation test" | Out-Null
    
    # Test SSH port connection
    Test-NetConnection -ComputerName "127.0.0.1" -Port 22 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-RemoteServices {
    Write-Host "[TEST] Remote Services (T1021)" -ForegroundColor Magenta
    
    Write-Host "  Testing SMB/Admin Shares patterns..." -ForegroundColor Gray
    # Safe network commands that simulate admin share usage
    net use 2>$null | Out-Null
    cmd /c "echo net use simulation for admin shares" | Out-Null
    cmd /c "echo dir admin$ simulation" | Out-Null
    cmd /c "echo psexec simulation test" | Out-Null
    
    Write-Host "  Testing WinRM patterns..." -ForegroundColor Gray
    # Test WinRM ports
    Test-NetConnection -ComputerName "127.0.0.1" -Port 5985 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    Test-NetConnection -ComputerName "127.0.0.1" -Port 5986 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    
    Write-Host "  Testing RDP patterns..." -ForegroundColor Gray
    # Test RDP port
    Test-NetConnection -ComputerName "127.0.0.1" -Port 3389 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    
    Write-Host "  Testing SSH patterns..." -ForegroundColor Gray
    # SSH simulation
    cmd /c "echo ssh.exe simulation test" | Out-Null
    Test-NetConnection -ComputerName "127.0.0.1" -Port 22 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-ReplicationRemovableMedia {
    Write-Host "[TEST] Replication Through Removable Media (T1091)" -ForegroundColor Magenta
    
    Write-Host "  Testing removable media file creation..." -ForegroundColor Gray
    
    # Check for available drives that might be removable (safe check)
    $drives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 -or $_.DriveType -eq 1 }
    
    if ($drives) {
        Write-Host "    Found removable drives: $($drives.DeviceID -join ', ')" -ForegroundColor Gray
        # Don't actually create files on removable media - just simulate the check
        Write-Host "    Simulating file creation on removable media..." -ForegroundColor Gray
    } else {
        Write-Host "    No removable drives found - simulating with temp directory..." -ForegroundColor Gray
        # Create test files with suspicious extensions in temp
        $testFiles = @("$env:TEMP\test_autorun.inf", "$env:TEMP\test_file.exe", "$env:TEMP\test_script.bat")
        
        foreach ($file in $testFiles) {
            "Test content" | Out-File -FilePath $file -Force
            Start-Sleep -Milliseconds 100
            Remove-Item $file -Force -ErrorAction SilentlyContinue
        }
    }
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-SoftwareDeploymentTools {
    Write-Host "[TEST] Software Deployment Tools (T1072)" -ForegroundColor Magenta
    
    Write-Host "  Testing software deployment patterns..." -ForegroundColor Gray
    
    # Simulate deployment tool command patterns
    cmd /c "echo msiexec /i simulation test" | Out-Null
    cmd /c "echo psexec -s simulation test" | Out-Null
    powershell -Command "# Install-Package simulation test" | Out-Null
    cmd /c "echo wmic product install simulation" | Out-Null
    cmd /c "echo choco install simulation test" | Out-Null
    powershell -Command "# ansible simulation test" | Out-Null
    cmd /c "echo puppet simulation test" | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-TaintSharedContent {
    Write-Host "[TEST] Taint Shared Content (T1080)" -ForegroundColor Magenta
    
    Write-Host "  Testing shared location file operations..." -ForegroundColor Gray
    
    # Test file creation in Public folder (safe location)
    $publicTestFile = "$env:PUBLIC\test_file_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    "Test content for shared location" | Out-File -FilePath $publicTestFile -Force
    
    # Simulate suspicious file types
    $suspiciousFiles = @(
        "$env:TEMP\shared_test.exe",
        "$env:TEMP\shared_test.bat", 
        "$env:TEMP\shared_test.ps1"
    )
    
    foreach ($file in $suspiciousFiles) {
        "Test content" | Out-File -FilePath $file -Force
        Start-Sleep -Milliseconds 100
        Remove-Item $file -Force -ErrorAction SilentlyContinue
    }
    
    # Clean up
    Remove-Item $publicTestFile -Force -ErrorAction SilentlyContinue
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-AlternateAuthMaterial {
    Write-Host "[TEST] Use Alternate Authentication Material (T1550)" -ForegroundColor Magenta
    
    Write-Host "  Testing credential-related patterns..." -ForegroundColor Gray
    
    # Simulate credential tool command patterns (safe simulation)
    cmd /c "echo mimikatz simulation test" | Out-Null
    cmd /c "echo kerberoast simulation test" | Out-Null
    cmd /c "echo rubeus simulation test" | Out-Null
    powershell -Command "# sekurlsa simulation test" | Out-Null
    cmd /c "echo lsadump simulation test" | Out-Null
    
    Write-Host "  Testing authentication queries..." -ForegroundColor Gray
    # Safe authentication queries
    whoami /all | Out-Null
    klist 2>$null | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-WindowsManagementInstrumentation {
    Write-Host "[TEST] Windows Management Instrumentation (T1047)" -ForegroundColor Magenta
    
    Write-Host "  Testing WMI remote execution patterns..." -ForegroundColor Gray
    
    # Simulate WMI commands that might be used for lateral movement
    wmic process get name /format:csv | Out-Null
    cmd /c "echo wmic /node: simulation test" | Out-Null
    powershell -Command "Get-WmiObject Win32_Process | Select-Object -First 5" | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-DistributedComponentObjectModel {
    Write-Host "[TEST] Distributed Component Object Model (T1021.003)" -ForegroundColor Magenta
    
    Write-Host "  Testing DCOM-related patterns..." -ForegroundColor Gray
    
    # Test DCOM port connections
    Test-NetConnection -ComputerName "127.0.0.1" -Port 135 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    
    # Simulate DCOM command patterns
    cmd /c "echo dcomexec simulation test" | Out-Null
    powershell -Command "# DCOM object simulation test" | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

# Main execution
try {
    Write-Host "Starting Lateral Movement technique tests..." -ForegroundColor Green
    Write-Host "Each test will pause for $DelayBetweenTests seconds between techniques" -ForegroundColor Gray
    Write-Host ""
    
    # Run all tests
    Test-ExploitationRemoteServices
    Test-InternalSpearphishing
    Test-LateralToolTransfer
    Test-RemoteServiceSessionHijacking
    Test-RemoteServices
    Test-ReplicationRemovableMedia
    Test-SoftwareDeploymentTools
    Test-TaintSharedContent
    Test-AlternateAuthMaterial
    Test-WindowsManagementInstrumentation
    Test-DistributedComponentObjectModel
    
    Write-Host ""
    Write-Host "=== Lateral Movement Test Completed ===" -ForegroundColor Green
    Write-Host "Check the LateralMovement monitor output for detected events" -ForegroundColor Yellow
    Write-Host "Log file should be in: $env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\LateralMovement_*.log" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Techniques Tested:" -ForegroundColor White
    Write-Host "  • T1210 - Exploitation of Remote Services" -ForegroundColor Gray
    Write-Host "  • T1534 - Internal Spearphishing" -ForegroundColor Gray
    Write-Host "  • T1570 - Lateral Tool Transfer" -ForegroundColor Gray
    Write-Host "  • T1563 - Remote Service Session Hijacking" -ForegroundColor Gray
    Write-Host "  • T1021 - Remote Services (RDP, SMB, WinRM, SSH)" -ForegroundColor Gray
    Write-Host "  • T1091 - Replication Through Removable Media" -ForegroundColor Gray
    Write-Host "  • T1072 - Software Deployment Tools" -ForegroundColor Gray
    Write-Host "  • T1080 - Taint Shared Content" -ForegroundColor Gray
    Write-Host "  • T1550 - Use Alternate Authentication Material" -ForegroundColor Gray
    Write-Host "  • T1047 - Windows Management Instrumentation" -ForegroundColor Gray
    Write-Host "  • T1021.003 - Distributed Component Object Model" -ForegroundColor Gray
    
} catch {
    Write-Host "Error during testing: $($_.Exception.Message)" -ForegroundColor Red
}
