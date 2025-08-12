# ====================================================================
# Sysmon Installation Validator
# ====================================================================
# This script validates that Sysmon is properly installed and configured
# for use with the Custom Security Loggers project.
# ====================================================================

$ValidationResults = @()

function Add-ValidationResult {
    param(
        [string]$Test,
        [bool]$Passed,
        [string]$Details,
        [string]$Recommendation = ""
    )
    
    $ValidationResults += [PSCustomObject]@{
        Test = $Test
        Status = if ($Passed) { "PASS" } else { "FAIL" }
        Details = $Details
        Recommendation = $Recommendation
    }
}

function Write-ValidationHeader {
    param([string]$Title)
    Write-Host "`n" + "=" * 80 -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
}

function Write-ValidationResult {
    param($Result)
    
    $color = if ($Result.Status -eq "PASS") { "Green" } else { "Red" }
    $symbol = if ($Result.Status -eq "PASS") { "✓" } else { "✗" }
    
    Write-Host "$symbol $($Result.Test): " -NoNewline
    Write-Host $Result.Status -ForegroundColor $color
    
    if ($Result.Details) {
        Write-Host "   $($Result.Details)" -ForegroundColor Gray
    }
    
    if ($Result.Status -eq "FAIL" -and $Result.Recommendation) {
        Write-Host "   💡 Recommendation: $($Result.Recommendation)" -ForegroundColor Yellow
    }
}

# Clear previous results
$ValidationResults = @()

Write-ValidationHeader "Sysmon Installation Validator for Custom Security Loggers"

Write-Host "Starting validation of Sysmon installation..." -ForegroundColor White
Write-Host "Date: $(Get-Date)" -ForegroundColor Gray
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "User: $env:USERNAME" -ForegroundColor Gray

# Test 1: Check if running as Administrator
Write-ValidationHeader "Administrator Privileges Check"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Add-ValidationResult -Test "Administrator Privileges" -Passed $isAdmin -Details "Required for full Sysmon event access" -Recommendation "Run this script as Administrator for complete validation"

# Test 2: Check Sysmon Service
Write-ValidationHeader "Sysmon Service Status"

try {
    $sysmonService = Get-Service -Name "Sysmon*" -ErrorAction Stop
    $serviceRunning = $sysmonService.Status -eq "Running"
    
    Add-ValidationResult -Test "Sysmon Service Installed" -Passed $true -Details "Service Name: $($sysmonService.Name), Status: $($sysmonService.Status)"
    Add-ValidationResult -Test "Sysmon Service Running" -Passed $serviceRunning -Details "Service must be running to generate events" -Recommendation "Start the Sysmon service: Start-Service $($sysmonService.Name)"
    
    if ($serviceRunning) {
        # Get service details
        $serviceInfo = Get-WmiObject -Class Win32_Service -Filter "Name='$($sysmonService.Name)'"
        if ($serviceInfo) {
            Add-ValidationResult -Test "Sysmon Executable Path" -Passed $true -Details $serviceInfo.PathName
        }
    }
}
catch {
    Add-ValidationResult -Test "Sysmon Service Installed" -Passed $false -Details "Sysmon service not found" -Recommendation "Install Sysmon using the Setup-SysmonPipeline.ps1 script"
}

# Test 3: Check Event Log Access
Write-ValidationHeader "Event Log Access"

try {
    $testEvent = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
    Add-ValidationResult -Test "Sysmon Event Log Access" -Passed $true -Details "Successfully accessed Sysmon operational log"
    
    if ($testEvent) {
        Add-ValidationResult -Test "Sysmon Events Present" -Passed $true -Details "Latest event: ID $($testEvent.Id) at $($testEvent.TimeCreated)"
    } else {
        Add-ValidationResult -Test "Sysmon Events Present" -Passed $false -Details "No events found in log" -Recommendation "Generate some activity and wait a few minutes for events to appear"
    }
}
catch {
    Add-ValidationResult -Test "Sysmon Event Log Access" -Passed $false -Details $_.Exception.Message -Recommendation "Run as Administrator or check if Sysmon is properly installed"
}

# Test 4: Check Configuration
Write-ValidationHeader "Sysmon Configuration"

try {
    # Try to get Sysmon configuration from registry
    $configKey = "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"
    if (Test-Path $configKey) {
        $configData = Get-ItemProperty -Path $configKey -ErrorAction SilentlyContinue
        if ($configData.Options) {
            Add-ValidationResult -Test "Sysmon Configuration Present" -Passed $true -Details "Configuration found in registry"
        } else {
            Add-ValidationResult -Test "Sysmon Configuration Present" -Passed $false -Details "No configuration options found" -Recommendation "Apply a configuration using Setup-SysmonPipeline.ps1"
        }
    } else {
        Add-ValidationResult -Test "Sysmon Configuration Present" -Passed $false -Details "Sysmon registry key not found" -Recommendation "Reinstall Sysmon with configuration"
    }
}
catch {
    Add-ValidationResult -Test "Sysmon Configuration Check" -Passed $false -Details $_.Exception.Message
}

# Test 5: Check Configuration Files
Write-ValidationHeader "Configuration Files"

$configDir = "$env:ProgramData\CustomSecurityLogs\Configs"
$basicConfig = Join-Path $configDir "sysmon-config-basic.xml"
$comprehensiveConfig = Join-Path $configDir "sysmon-config-comprehensive.xml"

$basicExists = Test-Path $basicConfig
$comprehensiveExists = Test-Path $comprehensiveConfig

Add-ValidationResult -Test "Basic Configuration File" -Passed $basicExists -Details $basicConfig -Recommendation "Ensure configuration files are present"
Add-ValidationResult -Test "Comprehensive Configuration File" -Passed $comprehensiveExists -Details $comprehensiveConfig -Recommendation "Ensure configuration files are present"

# Test 6: Check PowerShell Cmdlets
Write-ValidationHeader "PowerShell Capabilities"

$hasGetWinEvent = Get-Command Get-WinEvent -ErrorAction SilentlyContinue
Add-ValidationResult -Test "Get-WinEvent Cmdlet Available" -Passed ($hasGetWinEvent -ne $null) -Details "Required for reading Sysmon events" -Recommendation "Update PowerShell or Windows Management Framework"

# Test 7: Test Event Generation and Detection
Write-ValidationHeader "Event Generation Test"

if ($isAdmin -and $sysmonService -and $serviceRunning) {
    try {
        Write-Host "Generating test process event..." -ForegroundColor Yellow
        
        # Generate a test event
        $testProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "echo Sysmon validation test" -PassThru -Wait -WindowStyle Hidden
        
        # Wait a moment for the event to be logged
        Start-Sleep -Seconds 3
        
        # Look for the test event
        $recentEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 -ErrorAction SilentlyContinue
        $testEvents = $recentEvents | Where-Object { $_.Message -like "*cmd.exe*" -and $_.Message -like "*Sysmon validation test*" }
        
        if ($testEvents) {
            Add-ValidationResult -Test "Event Generation and Detection" -Passed $true -Details "Successfully generated and detected test event (Event ID: $($testEvents[0].Id))"
        } else {
            Add-ValidationResult -Test "Event Generation and Detection" -Passed $false -Details "Test event not found in recent events" -Recommendation "Check Sysmon configuration and wait longer for events to appear"
        }
    }
    catch {
        Add-ValidationResult -Test "Event Generation and Detection" -Passed $false -Details $_.Exception.Message
    }
} else {
    Add-ValidationResult -Test "Event Generation and Detection" -Passed $false -Details "Cannot test - requires Administrator privileges and running Sysmon service"
}

# Test 8: Check Custom Logger Integration
Write-ValidationHeader "Custom Logger Integration"

$loggerDir = "$env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS"
$testScript = Join-Path $loggerDir "Test-SysmonDetection.ps1"

if (Test-Path $testScript) {
    Add-ValidationResult -Test "Custom Logger Test Script Available" -Passed $true -Details $testScript
    
    try {
        Write-Host "Running Custom Logger test script..." -ForegroundColor Yellow
        $testOutput = & $testScript 2>&1
        $testSuccess = $LASTEXITCODE -eq 0
        Add-ValidationResult -Test "Custom Logger Test Execution" -Passed $testSuccess -Details "Test script executed"
    }
    catch {
        Add-ValidationResult -Test "Custom Logger Test Execution" -Passed $false -Details $_.Exception.Message
    }
} else {
    Add-ValidationResult -Test "Custom Logger Test Script Available" -Passed $false -Details "Test script not found at $testScript"
}

# Test 9: Check Log Directory Structure
Write-ValidationHeader "Directory Structure"

$logDir = "$env:ProgramData\CustomSecurityLogs"
$sysmonDir = Join-Path $logDir "Sysmon"
$configDirCheck = Join-Path $logDir "Configs"

Add-ValidationResult -Test "Main Log Directory" -Passed (Test-Path $logDir) -Details $logDir
Add-ValidationResult -Test "Sysmon Directory" -Passed (Test-Path $sysmonDir) -Details $sysmonDir
Add-ValidationResult -Test "Config Directory" -Passed (Test-Path $configDirCheck) -Details $configDirCheck

# Display Results Summary
Write-ValidationHeader "Validation Results Summary"

$totalTests = $ValidationResults.Count
$passedTests = ($ValidationResults | Where-Object Status -eq "PASS").Count
$failedTests = $totalTests - $passedTests

Write-Host "Total Tests: $totalTests" -ForegroundColor White
Write-Host "Passed: $passedTests" -ForegroundColor Green
Write-Host "Failed: $failedTests" -ForegroundColor Red

if ($failedTests -eq 0) {
    Write-Host "`n🎉 All tests passed! Sysmon is properly configured for Custom Security Loggers." -ForegroundColor Green
} elseif ($failedTests -le 2) {
    Write-Host "`n⚠️  Minor issues detected. Sysmon should work but may have limited functionality." -ForegroundColor Yellow
} else {
    Write-Host "`n❌ Multiple issues detected. Sysmon may not work properly with Custom Security Loggers." -ForegroundColor Red
}

Write-ValidationHeader "Detailed Results"

foreach ($result in $ValidationResults) {
    Write-ValidationResult $result
}

# Generate recommendations
Write-ValidationHeader "Recommendations"

$failedResults = $ValidationResults | Where-Object Status -eq "FAIL"
if ($failedResults) {
    Write-Host "To fix the detected issues:" -ForegroundColor Yellow
    $failedResults | ForEach-Object {
        if ($_.Recommendation) {
            Write-Host "• $($_.Test): $($_.Recommendation)" -ForegroundColor White
        }
    }
} else {
    Write-Host "No issues detected. Your Sysmon installation is ready for use with Custom Security Loggers!" -ForegroundColor Green
}

Write-ValidationHeader "Next Steps"

Write-Host "1. If any tests failed, address the recommendations above" -ForegroundColor White
Write-Host "2. Run your Custom Security Logger scripts to start monitoring" -ForegroundColor White
Write-Host "3. Check Event Viewer periodically for Sysmon events:" -ForegroundColor White
Write-Host "   Applications and Services Logs > Microsoft > Windows > Sysmon > Operational" -ForegroundColor Gray
Write-Host "4. Monitor log files in: $env:ProgramData\CustomSecurityLogs\" -ForegroundColor White
Write-Host "5. For issues, check the setup log: $env:ProgramData\CustomSecurityLogs\sysmon-setup.log" -ForegroundColor White

Write-Host "`nValidation completed at $(Get-Date)" -ForegroundColor Gray
