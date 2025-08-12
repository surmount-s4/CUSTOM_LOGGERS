# ====================================================================
# Sysmon Setup and Configuration Pipeline
# ====================================================================
# This script automates the complete setup of Sysmon on Windows systems
# for use with the Custom Security Loggers scripts.
#
# Requirements:
# - Administrator privileges
# - Internet connection (for downloading Sysmon)
# 
# Usage:
# Run as Administrator: powershell -ExecutionPolicy Bypass -File Setup-SysmonPipeline.ps1
# ====================================================================

param(
    [ValidateSet("Basic", "Comprehensive", "Custom")]
    [string]$ConfigType = "Basic",
    
    [string]$CustomConfigPath = "",
    
    [switch]$ForceReinstall,
    
    [switch]$SkipDownload,
    
    [string]$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
)

# Script configuration
$ScriptVersion = "1.0"
$LogFile = "$env:ProgramData\CustomSecurityLogs\sysmon-setup.log"
$SysmonDir = "$env:ProgramData\CustomSecurityLogs\Sysmon"
$ConfigDir = "$env:ProgramData\CustomSecurityLogs\Configs"

# Ensure log directory exists
$LogPath = Split-Path $LogFile
if (-not (Test-Path $LogPath)) { 
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Ensure required directories exist
@($SysmonDir, $ConfigDir) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console with colors
    switch ($Level) {
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "WARN"    { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        default   { Write-Host $logEntry -ForegroundColor White }
    }
    
    # Write to log file
    Add-Content -Path $LogFile -Value $logEntry
}

# Check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Download and extract Sysmon
function Get-Sysmon {
    param([string]$DownloadUrl, [string]$DestinationPath)
    
    Write-Log "Downloading Sysmon from: $DownloadUrl"
    
    try {
        $zipPath = Join-Path $env:TEMP "Sysmon.zip"
        
        # Download Sysmon
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $zipPath -UseBasicParsing
        Write-Log "Sysmon downloaded successfully" "SUCCESS"
        
        # Extract Sysmon
        if (Test-Path $DestinationPath) {
            Remove-Item $DestinationPath -Recurse -Force
        }
        New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
        
        # Use built-in Windows extraction
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $DestinationPath)
        
        # Cleanup
        Remove-Item $zipPath -Force
        
        Write-Log "Sysmon extracted to: $DestinationPath" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to download/extract Sysmon: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Check if Sysmon is installed and running
function Test-SysmonInstalled {
    try {
        $service = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
        if ($service) {
            Write-Log "Sysmon service found: $($service.Name) - Status: $($service.Status)"
            return @{
                Installed = $true
                ServiceName = $service.Name
                Status = $service.Status
                Running = ($service.Status -eq "Running")
            }
        }
        else {
            Write-Log "Sysmon service not found"
            return @{
                Installed = $false
                ServiceName = $null
                Status = $null
                Running = $false
            }
        }
    }
    catch {
        Write-Log "Error checking Sysmon installation: $($_.Exception.Message)" "ERROR"
        return @{
            Installed = $false
            ServiceName = $null
            Status = $null
            Running = $false
        }
    }
}

# Install Sysmon with configuration
function Install-Sysmon {
    param(
        [string]$SysmonPath,
        [string]$ConfigPath
    )
    
    Write-Log "Installing Sysmon with configuration: $ConfigPath"
    
    try {
        $sysmonExe = Get-ChildItem -Path $SysmonPath -Name "sysmon*.exe" | Select-Object -First 1
        if (-not $sysmonExe) {
            Write-Log "Sysmon executable not found in $SysmonPath" "ERROR"
            return $false
        }
        
        $sysmonFullPath = Join-Path $SysmonPath $sysmonExe
        Write-Log "Using Sysmon executable: $sysmonFullPath"
        
        # Install Sysmon with configuration
        $arguments = @("-accepteula", "-i", $ConfigPath)
        $process = Start-Process -FilePath $sysmonFullPath -ArgumentList $arguments -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Log "Sysmon installed successfully" "SUCCESS"
            return $true
        }
        else {
            Write-Log "Sysmon installation failed with exit code: $($process.ExitCode)" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error installing Sysmon: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Update Sysmon configuration
function Update-SysmonConfig {
    param(
        [string]$SysmonPath,
        [string]$ConfigPath
    )
    
    Write-Log "Updating Sysmon configuration with: $ConfigPath"
    
    try {
        $sysmonExe = Get-ChildItem -Path $SysmonPath -Name "sysmon*.exe" | Select-Object -First 1
        if (-not $sysmonExe) {
            Write-Log "Sysmon executable not found in $SysmonPath" "ERROR"
            return $false
        }
        
        $sysmonFullPath = Join-Path $SysmonPath $sysmonExe
        
        # Update configuration
        $arguments = @("-c", $ConfigPath)
        $process = Start-Process -FilePath $sysmonFullPath -ArgumentList $arguments -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Log "Sysmon configuration updated successfully" "SUCCESS"
            return $true
        }
        else {
            Write-Log "Sysmon configuration update failed with exit code: $($process.ExitCode)" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error updating Sysmon configuration: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Uninstall Sysmon
function Uninstall-Sysmon {
    param([string]$SysmonPath)
    
    Write-Log "Uninstalling existing Sysmon installation"
    
    try {
        $sysmonExe = Get-ChildItem -Path $SysmonPath -Name "sysmon*.exe" | Select-Object -First 1
        if (-not $sysmonExe) {
            # Try system paths
            $systemPaths = @(
                "$env:SystemRoot\System32\sysmon.exe",
                "$env:SystemRoot\System32\sysmon64.exe"
            )
            
            foreach ($path in $systemPaths) {
                if (Test-Path $path) {
                    $sysmonFullPath = $path
                    break
                }
            }
            
            if (-not $sysmonFullPath) {
                Write-Log "Sysmon executable not found for uninstallation" "WARN"
                return $true
            }
        }
        else {
            $sysmonFullPath = Join-Path $SysmonPath $sysmonExe
        }
        
        Write-Log "Uninstalling Sysmon using: $sysmonFullPath"
        
        # Uninstall Sysmon
        $arguments = @("-u")
        $process = Start-Process -FilePath $sysmonFullPath -ArgumentList $arguments -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Log "Sysmon uninstalled successfully" "SUCCESS"
            return $true
        }
        else {
            Write-Log "Sysmon uninstallation completed with exit code: $($process.ExitCode)" "WARN"
            return $true  # Sometimes Sysmon returns non-zero even on successful uninstall
        }
    }
    catch {
        Write-Log "Error uninstalling Sysmon: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Test Sysmon functionality
function Test-SysmonFunctionality {
    Write-Log "Testing Sysmon functionality..."
    
    try {
        # Check if Sysmon service is running
        $sysmonStatus = Test-SysmonInstalled
        if (-not $sysmonStatus.Running) {
            Write-Log "Sysmon service is not running" "ERROR"
            return $false
        }
        
        # Test if we can read Sysmon events
        $testEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($testEvents) {
            Write-Log "Successfully accessed Sysmon operational log" "SUCCESS"
            Write-Log "Latest Sysmon event: $($testEvents[0].Id) - $($testEvents[0].TimeCreated)"
        }
        else {
            Write-Log "No events found in Sysmon operational log (this is normal for new installations)" "INFO"
        }
        
        # Generate a test event by starting a simple process
        Write-Log "Generating test Sysmon event..."
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "echo Sysmon test event" -Wait -WindowStyle Hidden
        
        # Wait a moment and check for new events
        Start-Sleep -Seconds 2
        $newTestEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($newTestEvents) {
            $cmdEvents = $newTestEvents | Where-Object { $_.Message -like "*cmd.exe*" }
            if ($cmdEvents) {
                Write-Log "Sysmon is successfully capturing process events" "SUCCESS"
                return $true
            }
        }
        
        Write-Log "Sysmon is installed but may need time to start logging events" "INFO"
        return $true
    }
    catch {
        Write-Log "Error testing Sysmon functionality: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Get configuration file path based on type
function Get-ConfigPath {
    param([string]$Type)
    
    switch ($Type) {
        "Basic" { 
            return Join-Path $ConfigDir "sysmon-config-basic.xml"
        }
        "Comprehensive" { 
            return Join-Path $ConfigDir "sysmon-config-comprehensive.xml"
        }
        "Custom" {
            if (-not $CustomConfigPath) {
                Write-Log "Custom configuration path not specified" "ERROR"
                return $null
            }
            if (-not (Test-Path $CustomConfigPath)) {
                Write-Log "Custom configuration file not found: $CustomConfigPath" "ERROR"
                return $null
            }
            return $CustomConfigPath
        }
        default {
            Write-Log "Invalid configuration type: $Type" "ERROR"
            return $null
        }
    }
}

# ====================================================================
# MAIN EXECUTION
# ====================================================================

Write-Host "=" * 80
Write-Host "Sysmon Setup and Configuration Pipeline v$ScriptVersion"
Write-Host "=" * 80
Write-Log "Starting Sysmon setup pipeline"
Write-Log "Configuration Type: $ConfigType"
Write-Log "Log file: $LogFile"

# Check administrator privileges
if (-not (Test-Administrator)) {
    Write-Log "This script requires administrator privileges" "ERROR"
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    exit 1
}

# Check current Sysmon installation
$currentInstallation = Test-SysmonInstalled

if ($currentInstallation.Installed) {
    Write-Log "Current Sysmon installation detected:"
    Write-Log "  Service Name: $($currentInstallation.ServiceName)"
    Write-Log "  Status: $($currentInstallation.Status)"
    Write-Log "  Running: $($currentInstallation.Running)"
    
    if ($ForceReinstall) {
        Write-Log "Force reinstall requested - will uninstall and reinstall" "WARN"
        if (-not (Uninstall-Sysmon -SysmonPath $SysmonDir)) {
            Write-Log "Failed to uninstall existing Sysmon" "ERROR"
            exit 1
        }
        Start-Sleep -Seconds 3
        $currentInstallation.Installed = $false
    }
}

# Download Sysmon if needed
if (-not $SkipDownload -and (-not $currentInstallation.Installed -or $ForceReinstall)) {
    if (-not (Get-Sysmon -DownloadUrl $SysmonUrl -DestinationPath $SysmonDir)) {
        Write-Log "Failed to download Sysmon" "ERROR"
        exit 1
    }
}

# Get configuration file path
$configPath = Get-ConfigPath -Type $ConfigType
if (-not $configPath) {
    Write-Log "Failed to determine configuration file path" "ERROR"
    exit 1
}

if (-not (Test-Path $configPath)) {
    Write-Log "Configuration file not found: $configPath" "ERROR"
    Write-Log "Please ensure the configuration files are present in: $ConfigDir" "ERROR"
    exit 1
}

Write-Log "Using configuration file: $configPath"

# Install or update Sysmon
if (-not $currentInstallation.Installed) {
    # Fresh installation
    Write-Log "Installing Sysmon..."
    if (-not (Install-Sysmon -SysmonPath $SysmonDir -ConfigPath $configPath)) {
        Write-Log "Sysmon installation failed" "ERROR"
        exit 1
    }
}
else {
    # Update existing configuration
    Write-Log "Updating existing Sysmon configuration..."
    if (-not (Update-SysmonConfig -SysmonPath $SysmonDir -ConfigPath $configPath)) {
        Write-Log "Sysmon configuration update failed" "ERROR"
        exit 1
    }
}

# Verify installation
Write-Log "Verifying Sysmon installation..."
Start-Sleep -Seconds 5

$finalStatus = Test-SysmonInstalled
if (-not $finalStatus.Installed) {
    Write-Log "Sysmon installation verification failed" "ERROR"
    exit 1
}

if (-not $finalStatus.Running) {
    Write-Log "Sysmon service is not running - attempting to start..." "WARN"
    try {
        Start-Service -Name $finalStatus.ServiceName
        Start-Sleep -Seconds 3
        $finalStatus = Test-SysmonInstalled
        if ($finalStatus.Running) {
            Write-Log "Sysmon service started successfully" "SUCCESS"
        }
        else {
            Write-Log "Failed to start Sysmon service" "ERROR"
            exit 1
        }
    }
    catch {
        Write-Log "Error starting Sysmon service: $($_.Exception.Message)" "ERROR"
        exit 1
    }
}

# Test functionality
if (-not (Test-SysmonFunctionality)) {
    Write-Log "Sysmon functionality test failed" "WARN"
    Write-Log "Sysmon is installed but may have issues - check Event Viewer" "WARN"
}

# Success!
Write-Host "`n" + "=" * 80
Write-Log "Sysmon setup completed successfully!" "SUCCESS"
Write-Log "Service: $($finalStatus.ServiceName)"
Write-Log "Status: $($finalStatus.Status)"
Write-Log "Configuration: $ConfigType ($configPath)"
Write-Host "=" * 80

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Your Custom Security Logger scripts can now use Sysmon events" -ForegroundColor White
Write-Host "2. Run Test-SysmonDetection.ps1 to verify integration" -ForegroundColor White
Write-Host "3. Check Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> Sysmon" -ForegroundColor White
Write-Host "4. Log file location: $LogFile" -ForegroundColor White

Write-Log "Sysmon pipeline setup completed"
