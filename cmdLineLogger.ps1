# ==============================
# CMD Command Event Logger (CSV)
# ==============================

$logFile = "C:\Logs\cmd_commands.csv"
$stateFile = "C:\Logs\lastTimestamp.txt"
$intervalSeconds = 5

# Ensure log directory exists
$logDir = Split-Path $logFile
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# Create CSV header if file doesn't exist or is empty
if (-not (Test-Path $logFile) -or (Get-Content $logFile | Measure-Object -Line).Lines -eq 0) {
    "Time,ExecutionProcessID,ThreadID,Computer,NewProcessName,ParentProcessName,SubjectUserName,TargetUserName,CommandLine" | Out-File -FilePath $logFile -Encoding UTF8
}

# Initialize timestamp state
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
            $user      = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            $targetUsr = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $cmd       = ($data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'

            # Escape quotes and flatten newlines for CSV safety
            $flattenedCmd = ($cmd -replace "`r?`n", ' ') -replace '"', '""'
            $csvLine = """$time"",""$execProc"",""$threadID"",""$computer"",""$newProc"",""$parent"",""$user"",""$targetUsr"",""$flattenedCmd"""
            Add-Content -Path $logFile -Value $csvLine
        }

        $startTime = $event.TimeCreated.AddTicks(1)  # Ensure we don’t skip events with same timestamp
    }

    Set-Content -Path $stateFile -Value $startTime.ToString("o")
    Start-Sleep -Seconds $intervalSeconds
}
