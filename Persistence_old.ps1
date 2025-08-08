# Enhanced Persistence & Threat Monitoring Script
# Combines baseline diff checks, file-integrity monitoring, Sysmon event log parsing,
# expanded registry keys, ETW/WMI subscriptions, and centralized log shipping.

$BaselinePath = "$env:ProgramData\CustomSecurityLogs\Baselines"
$LogPath      = "$env:ProgramData\CustomSecurityLogs\Execution-Detect.log"

# Ensure directories exist
New-Item -ItemType Directory -Path $BaselinePath -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null

function Log($msg) {
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "${timestamp} $msg" | Out-File -FilePath $LogPath -Append
}

function Compare-And-Log($Name, $Current, $BaselineFile) {
    if (!(Test-Path $BaselineFile)) {
        $Current | Out-File $BaselineFile
        Log "$Name baseline initialized"
    } else {
        $old = Get-Content $BaselineFile
        $delta = Compare-Object -ReferenceObject $old -DifferenceObject $Current
        if ($delta) {
            Log "$Name changed:"
            $delta | ForEach-Object { Log " $_" }
            $Current | Out-File $BaselineFile
        }
    }
}

# 1. Expanded Registry Keys to Monitor
$registryKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'HKLM:\SYSTEM\CurrentControlSet\Services',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs',
    'HKCU:\SOFTWARE\Classes\CLSID'  # for COM hijacks
)

function Check-Registry {
    foreach ($key in $registryKeys) {
        try {
            $output = Get-ItemProperty -Path $key -ErrorAction Stop | Out-String
            $sanitized = ($key -replace '[:\\\/]', '_')
            Compare-And-Log "Registry $key" $output "$BaselinePath\Registry_$sanitized.txt"
        } catch {
            Log "Failed to read $key : $_"
        }
    }
}

# 2. File-Integrity Monitoring for Known Persistence Paths
$filePaths = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:SystemRoot\Tasks",
    "$BaselinePath\SysmonConfig.xml",
    "$env:ProgramFiles\Windows Defender Advanced Threat Protection",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
)

function Check-Files {
    foreach ($path in $filePaths) {
        if (Test-Path $path) {
            $snapshot = Get-ChildItem -Recurse $path |
                        Select-Object FullName, LastWriteTime | Out-String
            $sanitized = ($path -replace '[:\\\/<>|"?*]', '_')
            Compare-And-Log "FileIntegrity $path" $snapshot "$BaselinePath\FI_$sanitized.txt"
        }
    }
}

# 3. Windows Event Log Queries for Persistence Events
$eventQueries = @(
    @{Log='Microsoft-Windows-Sysmon/Operational'; Ids=@(1,7,8,10)};  # process, image load, injection
    @{Log='Security';                           Ids=@(4697,4702,4673,4696)}; # service install, task create, token op
    @{Log='System';                             Ids=@(7045)}                   # new service
)

function Check-EventLogs {
    foreach ($q in $eventQueries) {
        $filter = @{LogName=$q.Log; Id=$q.Ids}
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 100 |
                  ForEach-Object { 
                      if ($_.LogName -eq 'Microsoft-Windows-Sysmon/Operational') {
                          "$($_.TimeCreated) [Sysmon] [Sysmon-ID$($_.Id)] $($_.ProviderName): $($_.Message)"
                      } else {
                          "$($_.TimeCreated) [EventLog] [ID$($_.Id)] $($_.ProviderName): $($_.Message)"
                      }
                  } | Out-String
        $sanitized = ($q.Log -replace '[:\\\/]', '_')
        Compare-And-Log "EventLog $($q.Log)" $events "$BaselinePath\EL_$sanitized.txt"
    }
}

# 4. WMI/ETW Subscription Snapshots
function Check-WMI-ETW {
    $f = Get-WmiObject -Namespace root\subscription -Class __EventFilter | Out-String
    $c = Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Out-String
    $b = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Out-String
    Compare-And-Log "WMI_Filters"   $f "$BaselinePath\WMI_Filters.txt"
    Compare-And-Log "WMI_Consumers" $c "$BaselinePath\WMI_Consumers.txt"
    Compare-And-Log "WMI_Bindings"  $b "$BaselinePath\WMI_Bindings.txt"

    $etw = wevtutil el | Out-String
    Compare-And-Log "ETW_Sessions"  $etw "$BaselinePath\ETW_Sessions.txt"
}

# 5. Sysmon Configuration Deployment
$SysmonConfigUrl = 'https://your-sysmon-config-repo/SysmonConfig.xml'
$SysmonConfig    = "$BaselinePath\SysmonConfig.xml"

function Deploy-Sysmon {
    if (!(Test-Path $SysmonConfig)) {
        Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $SysmonConfig -UseBasicParsing
        Log "Downloaded Sysmon configuration"
    }
    & sysmon -c $SysmonConfig | Out-Null
    Log "Sysmon configured/updated"
}

# 6. Centralized Log Shipping (example: Windows Event Forwarding)
function Configure-EventForwarding {
    # This stub can register the machine as a subscription client
    # and forward to a collector at wef.company.local
    Log "Event forwarding configured (stub)"
}

# Main Execution
Deploy-Sysmon
Check-Registry
Check-Files
Check-EventLogs
Check-WMI-ETW
Configure-EventForwarding
Log "=== Enhanced Persistence & Threat Monitoring Complete ==="
