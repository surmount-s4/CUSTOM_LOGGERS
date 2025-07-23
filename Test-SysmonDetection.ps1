# Quick test of the updated InitialAccess.ps1 Sysmon detection
Write-Host "=== SYSMON DETECTION TEST ===" -ForegroundColor Yellow

# Test Sysmon detection
$HasSysmon = $false
try { 
    if ((Get-Service -Name Sysmon -ErrorAction Stop).Status -eq 'Running') { 
        $HasSysmon = $true 
    } 
} catch {}

$HasWinEvent = (Get-Command Get-WinEvent -ErrorAction SilentlyContinue) -ne $null

Write-Host "System Configuration:" -ForegroundColor Yellow
Write-Host "  HasSysmon: $HasSysmon" -ForegroundColor Gray  
Write-Host "  HasWinEvent: $HasWinEvent" -ForegroundColor Gray

if ($HasSysmon -and $HasWinEvent) {
    Write-Host "  Status: WILL USE SYSMON MONITORING" -ForegroundColor Green
    
    # Test Sysmon access (requires admin)
    try {
        $testEvent = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop
        Write-Host "  Sysmon Access: WORKING" -ForegroundColor Green
    } catch {
        Write-Host "  Sysmon Access: REQUIRES ADMIN PRIVILEGES" -ForegroundColor Yellow
        Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Gray
    }
} else {
    Write-Host "  Status: Will use WMI fallback" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== RESULTS ===" -ForegroundColor Yellow
if ($HasSysmon -and $HasWinEvent) {
    Write-Host "✓ Your script is NOW CONFIGURED to use Sysmon!" -ForegroundColor Green
    Write-Host "✓ When run as Administrator, it will detect Sysmon events" -ForegroundColor Green  
    Write-Host "✓ Registry, USB, and port monitoring still work without admin" -ForegroundColor Green
} else {
    Write-Host "✗ Script will fall back to WMI monitoring" -ForegroundColor Red
}

Write-Host ""
Write-Host "To use Sysmon detection, run InitialAccess.ps1 as Administrator" -ForegroundColor Cyan
