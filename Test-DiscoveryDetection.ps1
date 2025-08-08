#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Test script for Discovery tactics monitoring - generates test events
.DESCRIPTION
    Generates various discovery technique events to test the Discovery monitor
    Windows Server 2012 compatible
#>

param(
    [switch]$Verbose = $false,
    [int]$DelayBetweenTests = 2
)

Write-Host "=== Discovery Monitor Test Script ===" -ForegroundColor Cyan
Write-Host "This script will generate test events for Discovery techniques" -ForegroundColor Yellow
Write-Host "Make sure the Discovery.ps1 monitor is running in another window" -ForegroundColor Green
Write-Host ""

function Test-AccountDiscovery {
    Write-Host "[TEST] Account Discovery (T1087)" -ForegroundColor Magenta
    
    # Local account discovery
    Write-Host "  Testing local account discovery..." -ForegroundColor Gray
    net user | Out-Null
    Get-LocalUser -ErrorAction SilentlyContinue | Out-Null
    whoami | Out-Null
    
    # Domain account discovery (if domain joined)
    Write-Host "  Testing domain account discovery..." -ForegroundColor Gray
    net group "Domain Users" 2>$null | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-ApplicationWindowDiscovery {
    Write-Host "[TEST] Application Window Discovery (T1010)" -ForegroundColor Magenta
    
    Write-Host "  Testing application window discovery..." -ForegroundColor Gray
    tasklist /fo table | Out-Null
    Get-Process | Select-Object -First 5 | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-FileDirectoryDiscovery {
    Write-Host "[TEST] File and Directory Discovery (T1083)" -ForegroundColor Magenta
    
    Write-Host "  Testing file and directory discovery..." -ForegroundColor Gray
    dir $env:TEMP | Out-Null
    Get-ChildItem $env:USERPROFILE -ErrorAction SilentlyContinue | Select-Object -First 10 | Out-Null
    tree $env:TEMP /f | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-NetworkServiceDiscovery {
    Write-Host "[TEST] Network Service Discovery (T1046)" -ForegroundColor Magenta
    
    Write-Host "  Testing network service discovery..." -ForegroundColor Gray
    Test-NetConnection -ComputerName "127.0.0.1" -Port 80 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    Test-NetConnection -ComputerName "127.0.0.1" -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-NetworkShareDiscovery {
    Write-Host "[TEST] Network Share Discovery (T1135)" -ForegroundColor Magenta
    
    Write-Host "  Testing network share discovery..." -ForegroundColor Gray
    net view \\localhost 2>$null | Out-Null
    net share | Out-Null
    Get-SmbShare -ErrorAction SilentlyContinue | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-ProcessDiscovery {
    Write-Host "[TEST] Process Discovery (T1057)" -ForegroundColor Magenta
    
    Write-Host "  Testing process discovery..." -ForegroundColor Gray
    tasklist /v | Out-Null
    Get-Process | Select-Object -First 10 | Out-Null
    wmic process get name,processid,commandline /format:csv | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-QueryRegistry {
    Write-Host "[TEST] Query Registry (T1012)" -ForegroundColor Magenta
    
    Write-Host "  Testing registry queries..." -ForegroundColor Gray
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /v ProductName 2>$null | Out-Null
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name ProductName -ErrorAction SilentlyContinue | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-RemoteSystemDiscovery {
    Write-Host "[TEST] Remote System Discovery (T1018)" -ForegroundColor Magenta
    
    Write-Host "  Testing remote system discovery..." -ForegroundColor Gray
    ping -n 1 127.0.0.1 | Out-Null
    arp -a | Out-Null
    nslookup localhost 2>$null | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-SoftwareDiscovery {
    Write-Host "[TEST] Software Discovery (T1518)" -ForegroundColor Magenta
    
    Write-Host "  Testing software discovery..." -ForegroundColor Gray
    Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Select-Object -First 5 | Out-Null
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object -First 5 | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-SystemInformationDiscovery {
    Write-Host "[TEST] System Information Discovery (T1082)" -ForegroundColor Magenta
    
    Write-Host "  Testing system information discovery..." -ForegroundColor Gray
    systeminfo | Out-Null
    hostname | Out-Null
    Get-ComputerInfo -ErrorAction SilentlyContinue | Out-Null
    ver | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-SystemNetworkConfigDiscovery {
    Write-Host "[TEST] System Network Configuration Discovery (T1016)" -ForegroundColor Magenta
    
    Write-Host "  Testing network configuration discovery..." -ForegroundColor Gray
    ipconfig /all | Out-Null
    Get-NetIPConfiguration -ErrorAction SilentlyContinue | Out-Null
    route print | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-SystemNetworkConnectionsDiscovery {
    Write-Host "[TEST] System Network Connections Discovery (T1049)" -ForegroundColor Magenta
    
    Write-Host "  Testing network connections discovery..." -ForegroundColor Gray
    netstat -an | Out-Null
    Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object -First 10 | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-SystemOwnerUserDiscovery {
    Write-Host "[TEST] System Owner/User Discovery (T1033)" -ForegroundColor Magenta
    
    Write-Host "  Testing system owner/user discovery..." -ForegroundColor Gray
    whoami /all | Out-Null
    query user 2>$null | Out-Null
    quser 2>$null | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-SystemServiceDiscovery {
    Write-Host "[TEST] System Service Discovery (T1007)" -ForegroundColor Magenta
    
    Write-Host "  Testing system service discovery..." -ForegroundColor Gray
    sc query | Out-Null
    Get-Service | Select-Object -First 10 | Out-Null
    net start | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-SystemTimeDiscovery {
    Write-Host "[TEST] System Time Discovery (T1124)" -ForegroundColor Magenta
    
    Write-Host "  Testing system time discovery..." -ForegroundColor Gray
    time /t | Out-Null
    date /t | Out-Null
    Get-Date | Out-Null
    w32tm /query /status 2>$null | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-PasswordPolicyDiscovery {
    Write-Host "[TEST] Password Policy Discovery (T1201)" -ForegroundColor Magenta
    
    Write-Host "  Testing password policy discovery..." -ForegroundColor Gray
    net accounts | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-PermissionGroupsDiscovery {
    Write-Host "[TEST] Permission Groups Discovery (T1069)" -ForegroundColor Magenta
    
    Write-Host "  Testing permission groups discovery..." -ForegroundColor Gray
    net localgroup | Out-Null
    net localgroup Administrators | Out-Null
    Get-LocalGroup -ErrorAction SilentlyContinue | Out-Null
    
    # Domain groups (if domain joined)
    net group "Domain Admins" 2>$null | Out-Null
    
    Start-Sleep -Seconds $DelayBetweenTests
}

function Test-BrowserInformationDiscovery {
    Write-Host "[TEST] Browser Information Discovery (T1217)" -ForegroundColor Magenta
    
    Write-Host "  Testing browser information discovery..." -ForegroundColor Gray
    
    # Check for common browser paths (read-only access)
    $browserPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default",
        "$env:APPDATA\Mozilla\Firefox\Profiles",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
    )
    
    foreach ($path in $browserPaths) {
        if (Test-Path $path) {
            Get-ChildItem $path -ErrorAction SilentlyContinue | Select-Object -First 5 | Out-Null
        }
    }
    
    Start-Sleep -Seconds $DelayBetweenTests
}

# Main execution
try {
    Write-Host "Starting Discovery technique tests..." -ForegroundColor Green
    Write-Host "Each test will pause for $DelayBetweenTests seconds between techniques" -ForegroundColor Gray
    Write-Host ""
    
    # Run all tests
    Test-AccountDiscovery
    Test-ApplicationWindowDiscovery
    Test-FileDirectoryDiscovery
    Test-NetworkServiceDiscovery
    Test-NetworkShareDiscovery
    Test-ProcessDiscovery
    Test-QueryRegistry
    Test-RemoteSystemDiscovery
    Test-SoftwareDiscovery
    Test-SystemInformationDiscovery
    Test-SystemNetworkConfigDiscovery
    Test-SystemNetworkConnectionsDiscovery
    Test-SystemOwnerUserDiscovery
    Test-SystemServiceDiscovery
    Test-SystemTimeDiscovery
    Test-PasswordPolicyDiscovery
    Test-PermissionGroupsDiscovery
    Test-BrowserInformationDiscovery
    
    Write-Host ""
    Write-Host "=== Discovery Test Completed ===" -ForegroundColor Green
    Write-Host "Check the Discovery monitor output for detected events" -ForegroundColor Yellow
    Write-Host "Log file should be in: $env:ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\Discovery_*.log" -ForegroundColor Cyan
    
} catch {
    Write-Host "Error during testing: $($_.Exception.Message)" -ForegroundColor Red
}
