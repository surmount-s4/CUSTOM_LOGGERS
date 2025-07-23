# Comprehensive Security Script Testing
# Run this script while InitialAccess.ps1 is running in another PowerShell window

Write-Host "=== Security Script Testing Suite ===" -ForegroundColor Green
Write-Host "System Information:" -ForegroundColor Yellow
Write-Host "- HasSysmon: $((Get-Service -Name Sysmon -ErrorAction SilentlyContinue) -ne $null)" -ForegroundColor Gray
Write-Host "- HasWinEvent: $((Get-Command Register-WinEvent -ErrorAction SilentlyContinue) -ne $null)" -ForegroundColor Gray
Write-Host "- Running as Admin: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" -ForegroundColor Gray

Write-Host "`nMake sure InitialAccess.ps1 is running in another PowerShell window!" -ForegroundColor Yellow
$continue = Read-Host "Press Enter to continue or 'q' to quit"
if ($continue -eq 'q') { exit }

# Test 1: Registry Persistence Detection
Write-Host "`n=== Test 1: Registry Persistence Detection ===" -ForegroundColor Cyan
Write-Host "Adding test registry entries..." -ForegroundColor White

# Simple registry entry
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityTest1" -Value "notepad.exe" -PropertyType String -Force | Out-Null
Write-Host "Added: SecurityTest1 = notepad.exe" -ForegroundColor Green

Start-Sleep 7  # Wait for detection (5 second timer + buffer)

# Suspicious registry entry with risk indicators
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityTest2" -Value "powershell.exe -bypass -hidden -encodedcommand dGVzdA==" -PropertyType String -Force | Out-Null
Write-Host "Added: SecurityTest2 = powershell.exe -bypass -hidden -encodedcommand dGVzdA==" -ForegroundColor Green

Start-Sleep 7

# Test 2: Process Chain Detection (WMI-based since WinEvent is disabled)
Write-Host "`n=== Test 2: Process Chain Detection ===" -ForegroundColor Cyan
Write-Host "Testing WMI-based process monitoring..." -ForegroundColor White

# Start a process that looks like a browser
$browserSim = Start-Process notepad -PassThru -WindowStyle Minimized
Start-Sleep 2

# Rename the process in memory to simulate browser (this is just for testing)
Write-Host "Launching PowerShell from simulated browser context..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoProfile -Command Start-Sleep 3; Write-Host 'Test PowerShell execution completed'; exit" -WindowStyle Hidden

Start-Sleep 5
if (!$browserSim.HasExited) { Stop-Process $browserSim -Force -ErrorAction SilentlyContinue }

# Test 3: LOLBin Detection
Write-Host "`n=== Test 3: Living-off-the-Land Binary Detection ===" -ForegroundColor Cyan
Write-Host "Testing mshta with suspicious arguments..." -ForegroundColor White

# Use mshta instead of certutil (doesn't require admin)
try {
    $process = Start-Process mshta -ArgumentList "javascript:alert('SecurityTest');close()" -PassThru -WindowStyle Hidden -ErrorAction Stop
    Write-Host "Executed: mshta javascript:alert('SecurityTest');close()" -ForegroundColor Green
    Start-Sleep 3
    if (!$process.HasExited) { Stop-Process $process -Force -ErrorAction SilentlyContinue }
} catch {
    Write-Host "Failed to execute mshta test: $($_.Exception.Message)" -ForegroundColor Red
}

Start-Sleep 3

# Test 4: Scheduled Task Detection  
Write-Host "`n=== Test 4: Scheduled Task Detection ===" -ForegroundColor Cyan
Write-Host "Creating test scheduled task..." -ForegroundColor White

try {
    $action = New-ScheduledTaskAction -Execute "notepad.exe"
    $trigger = New-ScheduledTaskTrigger -Daily -At "12:00PM"
    Register-ScheduledTask -TaskName "SecurityTestTask_$(Get-Random)" -Action $action -Trigger $trigger -Description "Test security task" -Force | Out-Null
    Write-Host "Created scheduled task successfully" -ForegroundColor Green
    Start-Sleep 7
} catch {
    Write-Host "Failed to create scheduled task: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Network Port Listener
Write-Host "`n=== Test 5: Network Port Listener Detection ===" -ForegroundColor Cyan
Write-Host "Starting temporary HTTP listener on port 8080..." -ForegroundColor White

$job = Start-Job -ScriptBlock {
    try {
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://localhost:8080/")
        $listener.Start()
        Write-Host "HTTP Listener started on port 8080"
        Start-Sleep 35  # Run for 35 seconds to be detected by the 30-second scanner
    } catch {
        Write-Host "Port listener test failed: $_"
    } finally {
        if ($listener -and $listener.IsListening) { 
            $listener.Stop() 
            Write-Host "HTTP Listener stopped"
        }
    }
}

Write-Host "HTTP Listener job started (will run for 35 seconds)" -ForegroundColor Green
Start-Sleep 35
Remove-Job $job -Force -ErrorAction SilentlyContinue

# Test 6: Direct Process Creation Test
Write-Host "`n=== Test 6: Direct Process Creation Test ===" -ForegroundColor Cyan
Write-Host "Testing direct suspicious process creation..." -ForegroundColor White

# Create multiple suspicious processes with better error handling
$processes = @()

Write-Host "Creating PowerShell with encoded command..." -ForegroundColor Gray
try {
    $processes += Start-Process powershell -ArgumentList "-NoProfile", "-WindowStyle", "Hidden", "-Command", "Write-Host 'Test Complete'; Start-Sleep 2; Exit" -PassThru -ErrorAction Stop
    Write-Host "✓ PowerShell process created" -ForegroundColor Green
} catch {
    Write-Host "✗ PowerShell test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Start-Sleep 2

Write-Host "Creating rundll32 process..." -ForegroundColor Gray
try {
    $processes += Start-Process rundll32 -ArgumentList "shell32.dll,Control_RunDLL" -PassThru -WindowStyle Hidden -ErrorAction Stop
    Write-Host "✓ Rundll32 process created" -ForegroundColor Green
} catch {
    Write-Host "✗ Rundll32 test failed: $($_.Exception.Message)" -ForegroundColor Red
}

Start-Sleep 5

# Clean up processes
foreach ($proc in $processes) {
    if ($proc -and !$proc.HasExited) {
        Stop-Process $proc -Force -ErrorAction SilentlyContinue
    }
}

# Cleanup
Write-Host "`n=== Cleanup ===" -ForegroundColor Yellow
Write-Host "Removing test registry entries..." -ForegroundColor White
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityTest1" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityTest2" -ErrorAction SilentlyContinue

Write-Host "Removing test scheduled tasks..." -ForegroundColor White
Get-ScheduledTask | Where-Object TaskName -like "*SecurityTestTask*" | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "Removing test files..." -ForegroundColor White
Remove-Item "test_favicon.ico" -ErrorAction SilentlyContinue

Write-Host "`n=== Testing Complete ===" -ForegroundColor Green
Write-Host "Check the log file at: C:\ProgramData\CustomSecurityLogs\InitialAccess.log" -ForegroundColor Yellow
Write-Host "You can monitor it with: Get-Content 'C:\ProgramData\CustomSecurityLogs\InitialAccess.log' -Wait -Tail 10" -ForegroundColor Cyan

# Show current log content
Write-Host "`n=== Current Log Content ===" -ForegroundColor Magenta
if (Test-Path "C:\ProgramData\CustomSecurityLogs\InitialAccess.log") {
    Get-Content "C:\ProgramData\CustomSecurityLogs\InitialAccess.log" | Select-Object -Last 20
} else {
    Write-Host "Log file not found!" -ForegroundColor Red
}
