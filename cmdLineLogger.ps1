# ==============================
# Command Line Logger
# ==============================


$logFile = "C:\Logs\cmd_commands.log"
$stateFile = "C:\Logs\lastTimestamp.txt"
$intervalSeconds = 5

if (-not (Test-Path $logFile)) { New-Item -ItemType File -Path $logFile -Force | Out-Null }

# Initialize timestamp
if (-not (Test-Path $stateFile) -or !(Get-Content $stateFile)) {
    $initTime = (Get-Date).AddMinutes(-5).ToString("o")
    Set-Content -Path $stateFile -Value $initTime
}

while ($true) {
    try {
        $lastTimeRaw = Get-Content $stateFile | Out-String
        $lastTimeStr = $lastTimeRaw.Trim()
        $startTime = [datetime]::Parse($lastTimeStr)
    } catch {
        $startTime = (Get-Date).AddMinutes(-5)
        Set-Content -Path $stateFile -Value $startTime.ToString("o")
    }

    $filter = @{
        LogName = 'Security'
        Id = 4688
        StartTime = $startTime
    }

    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $startTime } |
        Sort-Object TimeCreated

foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = $xml.Event.EventData.Data

    $parent = ($data | Where-Object { $_.Name -eq 'ParentProcessName' }).'#text'
    if ($parent -like '*cmd.exe') {
        $time      = $event.TimeCreated.ToString("o")
        $execProc  = $xml.Event.System.Execution.ProcessID
        $threadID  = $xml.Event.System.Execution.ThreadID
        $computer  = $xml.Event.System.Computer
        $newProc   = ($data | Where-Object { $_.Name -eq 'NewProcessName' }).'#text'
        $parent    = ($data | Where-Object { $_.Name -eq 'ParentProcessName' }).'#text'
        $user      = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
        $targetUsr = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $cmd       = ($data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
        
        $flattenedCmd = $cmd -replace "`r?`n", ' '
        $line = "$time | $execProc | $threadID | $computer | $newProc | $parent | $user | $targetUsr | $flattenedCmd"
        Add-Content -Path $logFile -Value $line

    }

    $startTime = $event.TimeCreated
}


    Set-Content -Path $stateFile -Value $startTime.ToString("o")
    Start-Sleep -Seconds $intervalSeconds
}
