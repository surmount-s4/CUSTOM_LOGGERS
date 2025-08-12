@echo off
REM ====================================================================
REM Legacy Sysmon Setup Script - Redirects to New Pipeline
REM ====================================================================
REM This script redirects to the new comprehensive Sysmon setup pipeline
REM ====================================================================

echo.
echo ====================================================================
echo                    Legacy Sysmon Setup Script
echo ====================================================================
echo.
echo This script has been replaced with a new comprehensive pipeline!
echo.
echo The new setup provides:
echo - Automatic Sysmon download and installation
echo - Multiple configuration options (Basic/Comprehensive)
echo - Comprehensive validation and testing
echo - Better integration with Custom Security Loggers
echo.
echo Redirecting to the new setup script...
echo.
pause

REM Check if new script exists
if exist "%~dp0Setup-Sysmon.bat" (
    echo Launching new setup pipeline...
    call "%~dp0Setup-Sysmon.bat"
) else (
    echo ERROR: New setup script not found!
    echo Please ensure Setup-Sysmon.bat is in the same directory.
    echo.
    pause
)