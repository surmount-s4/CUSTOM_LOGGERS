@echo off
echo Applying simplified Sysmon configuration...
echo.

REM Check admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Run as Administrator
    pause
    exit /b 1
)

echo Current configuration:
sysmon.exe -c
echo.
echo Applying new configuration...
sysmon.exe -c "%~dp0sysmon-config-simple.xml"

if %errorlevel% == 0 (
    echo SUCCESS: Configuration applied
    echo.
    echo New configuration:
    sysmon.exe -c
) else (
    echo ERROR: Configuration failed - code %errorlevel%
)

echo.
echo Your security scripts should now detect Sysmon events!
pause
