$logFile = "C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\ps_scriptblocks.log"
$stateFile = "C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\last4104Timestamp.txt"
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
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        Id = 4104
        StartTime = $startTime
    }

    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $startTime } |
        Sort-Object TimeCreated

    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $data = $xml.Event.EventData.Data
        $time = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        $user = $xml.Event.System.Security.UserID
        $sid  = try { (New-Object System.Security.Principal.SecurityIdentifier($user)).Translate([System.Security.Principal.NTAccount]) } catch { $user }
        $script = ($data | Where-Object { $_.Name -eq 'ScriptBlockText' }).'#text'
        $hostApp = ($data | Where-Object { $_.Name -eq 'HostApplication' }).'#text'

    
        $trimmedScript = $script.Trim()
        if (
            $script -eq $null -or 
            $trimmedScript -eq '' -or 
            $trimmedScript -like 'prompt' -or 
            ($trimmedScript.StartsWith('{') -and $trimmedScript.EndsWith('}'))
        ) {
            continue
        }

$flattenedScript = $script -replace "`r?`n", ' '



        $line = "$time | $sid | $hostApp | $flattenedScript"

        Add-Content -Path $logFile -Value $line
        $startTime = $event.TimeCreated
    }

    Set-Content -Path $stateFile -Value $startTime.ToString("o")
    Start-Sleep -Seconds $intervalSeconds
}

z
