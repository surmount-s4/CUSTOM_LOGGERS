# ULS Agent - Lightweight Event Collector with RabbitMQ Publishing
# Collects and parses Windows Event Logs, sends to RabbitMQ for server-side processing
# Detection logic has been moved to the server
#
# Parameters:
param(
    [int]$InitialDaysBack = 0,
    [string]$RabbitMQHost = "172.16.0.114",
    [int]$RabbitMQPort = 5672,
    [string]$RabbitMQUser = "admin",
    [string]$RabbitMQPassword = "admin",
    [string]$RabbitMQQueue = "security_events",
    [string]$RabbitMQVHost = "/",
    [string[]]$LogSources = @(
        'Microsoft-Windows-Sysmon/Operational',
        'Security',
        'System',
        'Application'
    ),
    [int]$IntervalSeconds = 5,
    [int]$BatchSize = 100,
    [string]$FallbackPath = "C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\fallback_events.json",
    [switch]$Verbose = $false
)

if ($Verbose) {
    $VerbosePreference = 'Continue'
}

# Get computer name for event tagging
$ComputerName = $env:COMPUTERNAME

Write-Host "ULS Agent Starting..."
Write-Host "Collecting events every $IntervalSeconds seconds"
Write-Host "Target log sources: $($LogSources -join ', ')"
Write-Host "RabbitMQ: $RabbitMQHost`:$RabbitMQPort"
Write-Host "Queue: $RabbitMQQueue"
Write-Host "Press Ctrl+C to stop`n"

# Initialize timestamp tracking
$lastTimestamp = if ($InitialDaysBack -gt 0) {
    (Get-Date).AddDays(-$InitialDaysBack)
} else {
    (Get-Date).AddSeconds(-$IntervalSeconds)
}

Write-Host "Starting from timestamp: $lastTimestamp"

# ============================================================================
# RABBITMQ CONNECTION SETUP
# ============================================================================

# Load RabbitMQ.Client assembly if available, otherwise use HTTP API
$useHttpApi = $false
try {
    Add-Type -Path "C:\Program Files\RabbitMQ\client\RabbitMQ.Client.dll" -ErrorAction Stop
    Write-Host "Using RabbitMQ .NET Client"
} catch {
    Write-Host "RabbitMQ .NET Client not found, using HTTP API"
    $useHttpApi = $true
}

# HTTP API fallback function
function Send-ToRabbitMQHttp {
    param(
        [string]$HostName,
        [int]$Port,
        [string]$User,
        [string]$Password,
        [string]$VHost,
        [string]$Queue,
        [string]$Message
    )
    
    $httpPort = 15672  # RabbitMQ Management HTTP API port
    $encodedVHost = [System.Web.HttpUtility]::UrlEncode($VHost)
    $uri = "http://$HostName`:$httpPort/api/exchanges/$encodedVHost/amq.default/publish"
    
    # Payload must be base64-encoded for RabbitMQ HTTP API
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($Message)
    $payloadBase64 = [Convert]::ToBase64String($payloadBytes)
    
    $body = @{
        properties = @{
            delivery_mode = 2
            content_type = "application/json"
        }
        routing_key = $Queue
        payload = $payloadBase64
        payload_encoding = "base64"
    } | ConvertTo-Json -Depth 10
    
    $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$User`:$Password"))
    $headers = @{
        "Authorization" = "Basic $auth"
        "Content-Type" = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body -ErrorAction Stop
        return $true
    } catch {
        Write-Warning "Failed to send to RabbitMQ HTTP API: $_"
        return $false
    }
}

# AMQP connection (if .NET client available)
$rabbitConnection = $null
$rabbitChannel = $null

if (-not $useHttpApi) {
    try {
        $factory = New-Object RabbitMQ.Client.ConnectionFactory
        $factory.HostName = $RabbitMQHost
        $factory.Port = $RabbitMQPort
        $factory.UserName = $RabbitMQUser
        $factory.Password = $RabbitMQPassword
        $factory.VirtualHost = $RabbitMQVHost
        
        $rabbitConnection = $factory.CreateConnection()
        $rabbitChannel = $rabbitConnection.CreateModel()
        
        # Declare queue (idempotent)
        $rabbitChannel.QueueDeclare($RabbitMQQueue, $true, $false, $false, $null)
        
        Write-Host "Connected to RabbitMQ via AMQP"
    } catch {
        Write-Warning "Failed to connect via AMQP, falling back to HTTP API: $_"
        $useHttpApi = $true
    }
}

function Send-EventsToRabbitMQ {
    param([array]$Events)
    
    if ($Events.Count -eq 0) { return $true }
    
    $jsonPayload = $Events | ConvertTo-Json -Depth 10 -Compress
    
    if (-not $useHttpApi -and $rabbitChannel -ne $null) {
        try {
            $body = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload)
            $properties = $rabbitChannel.CreateBasicProperties()
            $properties.Persistent = $true
            $properties.ContentType = "application/json"
            
            $rabbitChannel.BasicPublish("", $RabbitMQQueue, $properties, $body)
            return $true
        } catch {
            Write-Warning "AMQP publish failed: $_"
            return $false
        }
    } else {
        return Send-ToRabbitMQHttp -HostName $RabbitMQHost -Port $RabbitMQPort -User $RabbitMQUser `
            -Password $RabbitMQPassword -VHost $RabbitMQVHost -Queue $RabbitMQQueue -Message $jsonPayload
    }
}

function Save-ToFallback {
    param([array]$Events)
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fallbackFile = $FallbackPath -replace "\.json$", "_$timestamp.json"
    
    try {
        $Events | ConvertTo-Json -Depth 10 | Out-File -FilePath $fallbackFile -Encoding UTF8
        Write-Warning "Events saved to fallback file: $fallbackFile"
        return $true
    } catch {
        Write-Error "Failed to save to fallback: $_"
        return $false
    }
}

# ============================================================================
# XML PARSING HELPER FUNCTIONS
# ============================================================================

function Flatten-XmlNode {
    param([System.Xml.XmlNode]$node)

    $lines = @()
    foreach ($child in $node.ChildNodes) {
        if ($child.HasChildNodes -and $child.ChildNodes.Count -gt 1) {
            $lines += Flatten-XmlNode $child
        } else {
            if ($child.'#text' -and $child.'#text'.Trim()) {
                $lines += "$($child.LocalName): $($child.'#text')"
            }
        }
        if ($child.Attributes) {
            foreach ($attr in $child.Attributes) {
                if ($attr.Value -and $attr.Value.Trim()) {
                    $lines += "$($child.LocalName).$($attr.Name): $($attr.Value)"
                }
            }
        }
    }
    return $lines
}

function Get-XmlValue {
    param($node)
    if ($node -is [System.Xml.XmlElement]) { return $node.InnerText }
    else { return $node }
}

function Get-UserDataLines {
    param([System.Xml.XmlNode]$node, [string]$prefix = '')

    $lines = @()
    foreach ($child in $node.ChildNodes) {
        if (-not $child) { continue }

        $name = if ($child.LocalName) { $child.LocalName } else { 'Value' }
        $value = $child.InnerText
        if ($value) { $value = $value.Trim() } else { $value = '' }

        if ($child.HasChildNodes -and ($child.ChildNodes | Where-Object { $_.NodeType -eq 'Element' })) {
            $lines += Get-UserDataLines -node $child -prefix "${prefix}${name}."
        }
        elseif ($value -ne '') {
            $lines += "${prefix}${name}: $value"
        }
    }
    return $lines
}

function Get-AllEventDataValues {
    param([System.Xml.XmlNode]$event)

    if (-not $event) { return @{} }

    $values = @{}
    $nodes = @()
    try {
        $nodes = @($event.SelectNodes("//*[local-name()='EventData']/*"))
    } catch {}
    if (-not $nodes -or $nodes.Count -eq 0) {
        if ($event.Event.EventData) { $nodes = @($event.Event.EventData.ChildNodes) }
    }

    foreach ($n in $nodes) {
        if (-not $n) { continue }

        $nameAttr = $null
        if ($n.Attributes) {
            if ($n.Attributes['Name']) { $nameAttr = $n.Attributes['Name'].Value }
            else {
                foreach ($attr in $n.Attributes) {
                    if ($attr.LocalName -eq 'Name') { $nameAttr = $attr.Value; break }
                }
            }
        }

        $value = $n.InnerText
        if ($value) { $value = $value.Trim() } else { $value = '' }
        if ($value -eq '') { continue }

        $key = if ($nameAttr) { $nameAttr } else { $n.LocalName }
        $values[$key] = [string]$value
    }

    return $values
}

function Get-LogSourceAndType {
    param([System.Xml.XmlNode]$event)
    
    $channel = Get-XmlValue $event.Event.System.Channel
    $eventId = Get-XmlValue $event.Event.System.EventID
    $providerName = Get-XmlValue $event.Event.System.Provider.Name
    
    $logSource = switch -Regex ($channel) {
        'Sysmon' { 'Sysmon' }
        'Security' { 'Security' }
        'System' { 'System' }
        'Application' { 'Application' }
        default { 'Unknown' }
    }
    
    $eventCategory = switch ($logSource) {
        'Sysmon' {
            switch ($eventId) {
                1 { 'Process Creation' }
                2 { 'File Creation Time Changed' }
                3 { 'Network Connection' }
                4 { 'Sysmon Service State Changed' }
                5 { 'Process Terminated' }
                6 { 'Driver Loaded' }
                7 { 'Image Loaded' }
                8 { 'CreateRemoteThread' }
                9 { 'RawAccessRead' }
                10 { 'ProcessAccess' }
                11 { 'FileCreate' }
                12 { 'RegistryEvent (Object create and delete)' }
                13 { 'RegistryEvent (Value Set)' }
                14 { 'RegistryEvent (Key and Value Rename)' }
                15 { 'FileCreateStreamHash' }
                16 { 'ServiceConfigurationChange' }
                17 { 'PipeEvent (Pipe Created)' }
                18 { 'PipeEvent (Pipe Connected)' }
                19 { 'WmiEvent (WmiEventFilter activity detected)' }
                20 { 'WmiEvent (WmiEventConsumer activity detected)' }
                21 { 'WmiEvent (WmiEventConsumerToFilter activity detected)' }
                22 { 'DNSEvent (DNS query)' }
                23 { 'FileDelete (File Delete archived)' }
                24 { 'ClipboardChange (New content in the clipboard)' }
                25 { 'ProcessTampering (Process image change)' }
                default { "Sysmon Event $eventId" }
            }
        }
        'Security' {
            switch ($eventId) {
                4624 { 'Successful Logon' }
                4625 { 'Failed Logon' }
                4634 { 'Logoff' }
                4648 { 'Explicit Credential Logon' }
                4672 { 'Special Privileges Assigned' }
                4688 { 'Process Creation' }
                4689 { 'Process Termination' }
                4697 { 'Service Installed' }
                4698 { 'Scheduled Task Created' }
                4720 { 'User Account Created' }
                4726 { 'User Account Deleted' }
                4728 { 'Member Added to Security Group' }
                4732 { 'Member Added to Local Group' }
                4740 { 'Account Lockout' }
                4768 { 'Kerberos TGT Request' }
                4769 { 'Kerberos Service Ticket Request' }
                4771 { 'Kerberos Pre-Auth Failed' }
                5156 { 'Windows Filtering Platform Connection' }
                default { "Security Event $eventId" }
            }
        }
        'System' {
            switch ($eventId) {
                6005 { 'Event Log Service Started' }
                6006 { 'Event Log Service Stopped' }
                6008 { 'Unexpected Shutdown' }
                7034 { 'Service Crashed' }
                7035 { 'Service Control Manager' }
                7036 { 'Service Started/Stopped' }
                7040 { 'Service Start Type Changed' }
                7045 { 'Service Installed' }
                default { "System Event $eventId" }
            }
        }
        'Application' {
            if ($providerName) { "$providerName Event $eventId" }
            else { "Application Event $eventId" }
        }
        default { "Unknown Event $eventId" }
    }
    
    return @{
        LogSource = $logSource
        EventCategory = $eventCategory
    }
}

# ============================================================================
# EVENT COLLECTION FUNCTION (NO DETECTION - Server handles that)
# ============================================================================

function Get-EventsInTimeRange {
    param(
        [DateTime]$StartTime,
        [DateTime]$EndTime,
        [string[]]$LogSources
    )
    
    $xmlEvents = @()
    foreach ($logName in $LogSources) {
        try {
            Write-Verbose "Processing log: $logName (from $StartTime to $EndTime)"
            $events = Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$StartTime; EndTime=$EndTime} -ErrorAction SilentlyContinue |
                ForEach-Object { [xml]$_.ToXml() }
            $xmlEvents += $events
            if ($events.Count -gt 0) {
                Write-Host "Found $($events.Count) new events in $logName"
            }
        }
        catch {
            Write-Warning "Could not access log '$logName': $($_.Exception.Message)"
        }
    }
    
    if ($xmlEvents.Count -eq 0) {
        Write-Verbose "No new events found in time range $StartTime to $EndTime"
        return @()
    }

    # Convert XML to flat objects (parsing only, no detection)
    $events = $xmlEvents | ForEach-Object {
        $logInfo = Get-LogSourceAndType -event $_
        $eventDataValues = Get-AllEventDataValues -event $_

        # Build EventData string
        $eventData = $null
        if ($_.Event) {
            $nodes = @()
            try {
                $nodes = @($_.SelectNodes("//*[local-name()='EventData']/*"))
            } catch {}
            if (-not $nodes -or $nodes.Count -eq 0) {
                if ($_.Event.EventData) { $nodes = @($_.Event.EventData.ChildNodes) }
            }
            $lines = @()
            foreach ($n in $nodes) {
                if (-not $n) { continue }
                $nameAttr = $null
                if ($n.Attributes) {
                    if ($n.Attributes['Name']) { $nameAttr = $n.Attributes['Name'].Value }
                    else {
                        foreach ($attr in $n.Attributes) {
                            if ($attr.LocalName -eq 'Name') { $nameAttr = $attr.Value; break }
                        }
                    }
                }
                $value = $n.InnerText
                if ($value) { $value = $value.Trim() } else { $value = '' }
                if ($value -eq '') { continue }
                if ($nameAttr) { $lines += "${nameAttr}: $value" }
                else { $lines += "$($n.LocalName): $value" }
            }
            $eventData = $lines -join "`n"
        }

        $systemData = if ($_.Event.System) { (Flatten-XmlNode $_.Event.System) -join "`n" }

        $userData = $null
        if ($_.Event.UserData) {
            $lines = Get-UserDataLines -node $_.Event.UserData
            if ($lines.Count -gt 0) { $userData = $lines -join "`n" }
        }

        # Create the event object (NO detection fields populated - server will do that)
        [PSCustomObject]@{
            # Agent metadata
            agent_host = $ComputerName
            agent_timestamp = (Get-Date).ToString("o")
            
            # Normalized fields (for server-side use)
            timestamp = Get-XmlValue $_.Event.System.TimeCreated.SystemTime
            process_id = $eventDataValues["ProcessId"]
            process_name = $eventDataValues["Image"]
            command_line = $eventDataValues["CommandLine"]
            username = $eventDataValues["User"]
            source_ip = $eventDataValues["SourceIp"]
            dest_ip = $eventDataValues["DestinationIp"]
            file_path = $eventDataValues["TargetFilename"]
            registry_key = $eventDataValues["TargetObject"]

            # System Level Information (Level 0)
            TimeCreated_0 = Get-XmlValue $_.Event.System.TimeCreated.SystemTime
            ProviderName_0 = Get-XmlValue $_.Event.System.Provider.Name
            ProviderGuid_0 = Get-XmlValue $_.Event.System.Provider.Guid
            EventID_0 = Get-XmlValue $_.Event.System.EventID
            Version_0 = Get-XmlValue $_.Event.System.Version
            Level_0 = Get-XmlValue $_.Event.System.Level
            Task_0 = Get-XmlValue $_.Event.System.Task
            Opcode_0 = Get-XmlValue $_.Event.System.Opcode
            Keywords_0 = Get-XmlValue $_.Event.System.Keywords
            EventRecordID_0 = Get-XmlValue $_.Event.System.EventRecordID
            ExecutionProcessID_0 = Get-XmlValue $_.Event.System.Execution.ProcessID
            ExecutionThreadID_0 = Get-XmlValue $_.Event.System.Execution.ThreadID
            Channel_0 = Get-XmlValue $_.Event.System.Channel
            Computer_0 = Get-XmlValue $_.Event.System.Computer
            SecurityUserID_0 = Get-XmlValue $_.Event.System.Security.UserID

            # Raw Data (Level 1)
            EventData_1 = $eventData
            SystemData_1 = $systemData
            UserData_1 = $userData

            # Sysmon Fields (Level 2)
            UtcTime_2 = $eventDataValues["UtcTime"]
            ProcessGuid_2 = $eventDataValues["ProcessGuid"]
            ProcessId_2 = $eventDataValues["ProcessId"]
            Image_2 = $eventDataValues["Image"]
            FileVersion_2 = $eventDataValues["FileVersion"]
            Description_2 = $eventDataValues["Description"]
            Product_2 = $eventDataValues["Product"]
            Company_2 = $eventDataValues["Company"]
            CommandLine_2 = $eventDataValues["CommandLine"]
            CurrentDirectory_2 = $eventDataValues["CurrentDirectory"]
            User_2 = $eventDataValues["User"]
            LogonGuid_2 = $eventDataValues["LogonGuid"]
            LogonId_2 = $eventDataValues["LogonId"]
            TerminalSessionId_2 = $eventDataValues["TerminalSessionId"]
            IntegrityLevel_2 = $eventDataValues["IntegrityLevel"]
            Hashes_2 = $eventDataValues["Hashes"]
            ParentProcessGuid_2 = $eventDataValues["ParentProcessGuid"]
            ParentProcessId_2 = $eventDataValues["ParentProcessId"]
            ParentImage_2 = $eventDataValues["ParentImage"]
            ParentCommandLine_2 = $eventDataValues["ParentCommandLine"]
            RuleName_2 = $eventDataValues["RuleName"]
            TargetFilename_2 = $eventDataValues["TargetFilename"]
            CreationUtcTime_2 = $eventDataValues["CreationUtcTime"]
            PreviousCreationUtcTime_2 = $eventDataValues["PreviousCreationUtcTime"]
            Protocol_2 = $eventDataValues["Protocol"]
            Initiated_2 = $eventDataValues["Initiated"]
            SourceIsIpv6_2 = $eventDataValues["SourceIsIpv6"]
            SourceIp_2 = $eventDataValues["SourceIp"]
            SourceHostname_2 = $eventDataValues["SourceHostname"]
            SourcePort_2 = $eventDataValues["SourcePort"]
            SourcePortName_2 = $eventDataValues["SourcePortName"]
            DestinationIsIpV6_2 = $eventDataValues["DestinationIsIpV6"]
            DestinationIp_2 = $eventDataValues["DestinationIp"]
            DestinationHostname_2 = $eventDataValues["DestinationHostname"]
            DestinationPort_2 = $eventDataValues["DestinationPort"]
            DestinationPortName_2 = $eventDataValues["DestinationPortName"]
            State_2 = $eventDataValues["State"]
            Version_2 = $eventDataValues["Version"]
            SchemaVersion_2 = $eventDataValues["SchemaVersion"]
            ImageLoaded_2 = $eventDataValues["ImageLoaded"]
            Signed_2 = $eventDataValues["Signed"]
            Signature_2 = $eventDataValues["Signature"]
            SignatureStatus_2 = $eventDataValues["SignatureStatus"]
            SourceProcessGuid_2 = $eventDataValues["SourceProcessGuid"]
            SourceProcessId_2 = $eventDataValues["SourceProcessId"]
            SourceImage_2 = $eventDataValues["SourceImage"]
            TargetProcessId_2 = $eventDataValues["TargetProcessId"]
            TargetImage_2 = $eventDataValues["TargetImage"]
            NewThreadId_2 = $eventDataValues["NewThreadId"]
            StartAddress_2 = $eventDataValues["StartAddress"]
            StartModule_2 = $eventDataValues["StartModule"]
            StartFunction_2 = $eventDataValues["StartFunction"]
            Device_2 = $eventDataValues["Device"]
            SourceThreadId_2 = $eventDataValues["SourceThreadId"]
            TargetProcessGuid_2 = $eventDataValues["TargetProcessGuid"]
            GrantedAccess_2 = $eventDataValues["GrantedAccess"]
            CallTrace_2 = $eventDataValues["CallTrace"]
            EventType_2 = $eventDataValues["EventType"]
            TargetObject_2 = $eventDataValues["TargetObject"]
            Details_2 = $eventDataValues["Details"]
            NewName_2 = $eventDataValues["NewName"]
            Hash_2 = $eventDataValues["Hash"]
            Configuration_2 = $eventDataValues["Configuration"]
            ConfigurationFileHash_2 = $eventDataValues["ConfigurationFileHash"]
            PipeName_2 = $eventDataValues["PipeName"]
            Operation_2 = $eventDataValues["Operation"]
            Name_2 = $eventDataValues["Name"]
            Query_2 = $eventDataValues["Query"]
            Type_2 = $eventDataValues["Type"]
            Destination_2 = $eventDataValues["Destination"]
            Consumer_2 = $eventDataValues["Consumer"]
            Filter_2 = $eventDataValues["Filter"]
            QueryName_2 = $eventDataValues["QueryName"]
            QueryType_2 = $eventDataValues["QueryType"]
            QueryStatus_2 = $eventDataValues["QueryStatus"]
            QueryResults_2 = $eventDataValues["QueryResults"]
            IsExecutable_2 = $eventDataValues["IsExecutable"]
            Archived_2 = $eventDataValues["Archived"]
            Session_2 = $eventDataValues["Session"]
            ClientInfo_2 = $eventDataValues["ClientInfo"]
            ParentUser_2 = $eventDataValues["ParentUser"]
            RawAccessRead_2 = $eventDataValues["RawAccessRead"]
            EventNamespace_2 = $eventDataValues["EventNamespace"]

            # Security Fields (Level 3)
            LogonType_3 = $eventDataValues["LogonType"]
            TargetUserName_3 = $eventDataValues["TargetUserName"]
            IpAddress_3 = $eventDataValues["IpAddress"]
            WorkstationName_3 = $eventDataValues["WorkstationName"]
            FailureReason_3 = $eventDataValues["FailureReason"]
            NewProcessName_3 = $eventDataValues["NewProcessName"]
            SubjectUserName_3 = $eventDataValues["SubjectUserName"]
            NewProcessId_3 = $eventDataValues["NewProcessId"]
            TaskName_3 = $eventDataValues["TaskName"]
            TaskContent_3 = $eventDataValues["TaskContent"]
            ServiceName_3 = $eventDataValues["ServiceName"]
            ServiceFileName_3 = $eventDataValues["ServiceFileName"]
            ServiceType_3 = $eventDataValues["ServiceType"]
            ImagePath_3 = $eventDataValues["ImagePath"]
            AccountName_3 = $eventDataValues["AccountName"]
            ProcessName_3 = $eventDataValues["ProcessName"]
            SubjectLogonId_3 = $eventDataValues["SubjectLogonId"]
            PrivilegeList_3 = $eventDataValues["PrivilegeList"]
            OriginalFileName_3 = $eventDataValues["OriginalFileName"]
            Status_3 = $eventDataValues["Status"]
            SubStatus_3 = $eventDataValues["SubStatus"]
            CallerComputerName_3 = $eventDataValues["CallerComputerName"]
            TicketEncryptionType_3 = $eventDataValues["TicketEncryptionType"]
            CertThumbprint_3 = $eventDataValues["CertThumbprint"]
            AuthenticationPackageName_3 = $eventDataValues["AuthenticationPackageName"]
            LogonProcessName_3 = $eventDataValues["LogonProcessName"]
            SessionID_3 = $eventDataValues["SessionID"]
            ClientName_3 = $eventDataValues["ClientName"]
            ActionName_3 = $eventDataValues["ActionName"]
            Service_3 = $eventDataValues["Service"]

            # Log Source Information (Level 5)
            LogSource_5 = $logInfo.LogSource
            EventCategory_5 = $logInfo.EventCategory
        }
    }

    return $events
}

# ============================================================================
# MAIN CONTINUOUS MONITORING LOOP
# ============================================================================

$iteration = 0
$totalEventsProcessed = 0
$failedBatches = 0

try {
    while ($true) {
        $iteration++
        $currentTime = Get-Date
        
        Write-Host "`n--- Iteration $iteration at $currentTime ---"
        
        # Get events from last timestamp to now
        $events = Get-EventsInTimeRange -StartTime $lastTimestamp -EndTime $currentTime -LogSources $LogSources
        
        if ($events.Count -gt 0) {
            Write-Host "Processing $($events.Count) new events..."
            
            # Send in batches
            $batches = [System.Collections.ArrayList]@()
            for ($i = 0; $i -lt $events.Count; $i += $BatchSize) {
                $batch = $events[$i..([Math]::Min($i + $BatchSize - 1, $events.Count - 1))]
                [void]$batches.Add($batch)
            }
            
            $successCount = 0
            foreach ($batch in $batches) {
                $success = Send-EventsToRabbitMQ -Events $batch
                if ($success) {
                    $successCount += $batch.Count
                } else {
                    $failedBatches++
                    # Save to fallback on failure
                    Save-ToFallback -Events $batch
                }
            }
            
            $totalEventsProcessed += $successCount
            Write-Host "Sent $successCount events to RabbitMQ. Total processed: $totalEventsProcessed"
            
            # Display summary
            $logSummary = $events | Group-Object LogSource_5 | Select-Object Name, Count
            Write-Host "Batch Summary by Log Source:"
            $logSummary | ForEach-Object { Write-Host "  $($_.Name): $($_.Count)" }
        } else {
            Write-Host "No new events found."
        }
        
        # Update last timestamp for next iteration
        $lastTimestamp = $currentTime
        
        Write-Host "Waiting $IntervalSeconds seconds before next check..."
        Start-Sleep -Seconds $IntervalSeconds
    }
}
catch {
    Write-Host "`nMonitoring stopped: $_"
}
finally {
    # Cleanup RabbitMQ connection
    if ($rabbitChannel -ne $null) {
        try { $rabbitChannel.Close() } catch {}
    }
    if ($rabbitConnection -ne $null) {
        try { $rabbitConnection.Close() } catch {}
    }
    
    Write-Host "`nFinal Summary:"
    Write-Host "Total iterations: $iteration"
    Write-Host "Total events processed: $totalEventsProcessed"
    Write-Host "Failed batches: $failedBatches"
}
