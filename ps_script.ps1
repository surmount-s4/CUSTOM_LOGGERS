$logFile = "C:\Logs\ps_scriptblocks.csv"
$stateFile = "C:\Logs\last4104Timestamp.txt"
$intervalSeconds = 5

if (-not (Test-Path $logFile)) { New-Item -ItemType File -Path $logFile -Force | Out-Null }
if ((Get-Item $logFile).Length -eq 0) {
    "Time|User|ProcessID|ThreadID|Computer|HostApplication|ScriptBlockText" | Out-File -FilePath $logFile -Encoding utf8
}

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
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        Id = 4104
        StartTime = $startTime
    }

    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $startTime } |
        Sort-Object TimeCreated

    foreach ($event in $events) {
        $xml       = [xml]$event.ToXml()
        $data      = $xml.Event.EventData.Data

        $time      = $event.TimeCreated.ToString("o")
        $user      = $xml.Event.System.Security.UserID
        $sid       = try { (New-Object System.Security.Principal.SecurityIdentifier($user)).Translate([System.Security.Principal.NTAccount]) } catch { $user }
        $processId = $xml.Event.System.Execution.ProcessID
        $threadId  = $xml.Event.System.Execution.ThreadID
        $computer  = $xml.Event.System.Computer
        $script    = ($data | Where-Object { $_.Name -eq 'ScriptBlockText' }).'#text'
        $hostApp   = ($data | Where-Object { $_.Name -eq 'HostApplication' }).'#text'

        $trimmedScript = $script.Trim()
        if (
            $script -eq $null -or 
            $trimmedScript -eq '' -or 
            $trimmedScript -like 'prompt' -or 
            ($trimmedScript.StartsWith('{') -and $trimmedScript.EndsWith('}') -and $trimmedScript.Length -lt 80)
        ) { continue }

        $flattenedScript = $script -replace "`r?`n", ' '
        $line = "$time|$sid|$processId|$threadId|$computer|$hostApp|$flattenedScript"

        Add-Content -Path $logFile -Value $line
        $startTime = $event.TimeCreated
    }

    Set-Content -Path $stateFile -Value $startTime.ToString("o")
    Start-Sleep -Seconds $intervalSeconds
}
