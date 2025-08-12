Write-Host "=== Security Script Testing ===" -ForegroundColor Green
Write-Host "Make sure InitialAccess.ps1 is running in another PowerShell window!" -ForegroundColor Yellow
Read-Host "Press Enter to continue"

Write-Host "`n1. Testing Registry Persistence Detection..." -ForegroundColor Cyan
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityTest1" -Value "notepad.exe" -Force
Start-Sleep 6
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityTest2" -Value "powershell.exe -bypass -hidden -enc dGVzdA==" -Force
Start-Sleep 6

Write-Host "`n2. Testing Process Chain Detection..." -ForegroundColor Cyan
# Simulate browser spawning PowerShell
$chrome = Start-Process chrome -ArgumentList "--headless" -PassThru -ErrorAction SilentlyContinue
if (-not $chrome) {
    $chrome = Start-Process notepad -PassThru -WindowStyle Hidden  # Fallback
}
Start-Sleep 2
Start-Process powershell -ArgumentList "-NoProfile -Command Write-Host 'Test completed'"
Start-Sleep 3

Write-Host "`n3. Testing LOLBin Detection..." -ForegroundColor Cyan
certutil -urlcache -split -f https://www.microsoft.com/favicon.ico favicon.ico
Start-Sleep 3

Write-Host "`n4. Testing Scheduled Task Detection..." -ForegroundColor Cyan
$action = New-ScheduledTaskAction -Execute "notepad.exe"
$trigger = New-ScheduledTaskTrigger -Daily -At "12:00PM"
Register-ScheduledTask -TaskName "SecurityTestTask" -Action $action -Trigger $trigger -Description "Test task"
Start-Sleep 6

Write-Host "`n5. Testing Network Port Detection..." -ForegroundColor Cyan
$job = Start-Job -ScriptBlock {
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:8080/")
    try {
        $listener.Start()
        Start-Sleep 35
    } catch {
        Write-Host "Port test failed: $_"
    } finally {
        if ($listener.IsListening) { $listener.Stop() }
    }
}
Start-Sleep 35

Write-Host "`n6. Cleaning up test artifacts..." -ForegroundColor Yellow
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityTest1" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityTest2" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "SecurityTestTask" -Confirm:$false -ErrorAction SilentlyContinue
Remove-Job $job -Force -ErrorAction SilentlyContinue
Remove-Item "favicon.ico" -ErrorAction SilentlyContinue
if ($chrome -and !$chrome.HasExited) { Stop-Process $chrome -Force -ErrorAction SilentlyContinue }

Write-Host "`n=== Testing Complete ===" -ForegroundColor Green
Write-Host "Check the log file at: $env:ProgramData\CustomSecurityLogs\InitialAccess.log" -ForegroundColor Yellow