@echo off
color 1f
cls

:: -------------------------- Log File Setup --------------------------------------------
set LOGFILE=%TEMP%\install_log.txt
echo Installation started at %DATE% %TIME% > %LOGFILE%

:: -------------------------- BatchGotAdmin -------------------------------------------
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
    REM --> Create and execute UAC prompt to request admin privileges
    echo Creating UAC prompt... >> %LOGFILE%
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params=%*
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    echo UAC prompt executed. >> %LOGFILE%
    exit /B

:gotAdmin
    REM --> We have admin privileges now
    echo Admin privileges confirmed. Moving to the next step. >> %LOGFILE%
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

cls

:: Run Win10_11Util.ps1 in the foreground and keep batch script running in background
powershell -ExecutionPolicy Bypass -File ".\Win10_11Util.ps1"

:: Once Win10_11Util.ps1 finishes, log the result and exit
echo %DATE% %TIME% - Win10_11Util.ps1 has finished. >> %LOGFILE%

exit
 