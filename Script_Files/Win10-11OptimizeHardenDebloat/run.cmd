@echo off
color 1f
cls

:: Helper launcher for users who want to start Win10_11Util from Command Prompt
:: or File Explorer instead of opening PowerShell manually.
:: This script requests administrator rights if needed, starts
:: Win10_11Util.ps1 with ExecutionPolicy Bypass, and writes a launcher log to
:: %TEMP%\install_log.txt.

:: Set up the batch launcher log in %TEMP%.
set LOGFILE=%TEMP%\install_log.txt
echo Installation started at %DATE% %TIME% > %LOGFILE%

:: Check whether this Command Prompt already has administrator rights.
:-------------------------------------
cls
REM  --> Check for permissions
echo Checking for administrative privileges... >> %LOGFILE%
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges... >> %LOGFILE%
    echo Requesting administrative privileges...
    goto UACPrompt
) else (
    echo Admin privileges granted. >> %LOGFILE%
    goto gotAdmin
)

:UACPrompt
    REM --> Prompt for elevation and restart this launcher as administrator
    echo Creating UAC prompt... >> %LOGFILE%
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params=%*
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    echo UAC prompt executed. >> %LOGFILE%
    exit /B

:gotAdmin
    REM --> Continue from the script folder with elevated rights
    echo Admin privileges confirmed. Starting Win10_11Util. >> %LOGFILE%
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

cls

:: Remove the previous Win10_11Util PowerShell log if it exists.
if exist "%temp%\WinUtil Script for Windows 10.txt" (
    del /f /q "%temp%\WinUtil Script for Windows 10.txt" >nul 2>&1
)
if exist "%temp%\WinUtil Script for Windows 11.txt" (
    del /f /q "%temp%\WinUtil Script for Windows 11.txt" >nul 2>&1
)

:: Run the main PowerShell script from this folder.
powershell -ExecutionPolicy Bypass -File ".\Win10_11Util.ps1"

:: Record when the PowerShell run has finished and exit the launcher.
echo %DATE% %TIME% - Win10_11Util.ps1 has finished. >> %LOGFILE%

exit
 
