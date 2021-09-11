@echo off
mode con cols=89 lines=34
Title Sledgehammer 2.7.2
Color 1F & goto start
Original script by pf100 @ MDL with special thanks to rpo and abbodi1406 @ MDL for code improvements.
Thanks to RetiredGeek at askwoody.com forum for original ideas on how to get MS-DEFCON rating.
Project page and source code:
https://forums.mydigitallife.net/threads/sledgehammer-windows-10-update-control.72203/
******************************************************************
You may freely modify this script as you wish, I only request that you leave the credits and the
link to the original script.
******************************************************************
Don't move this script to another folder without running it again or the tasks won't work!
This script provides manual updating for Windows 10 including Home versions.
Update Windows 10 on your schedule, not Microsoft's!
I originally wrote this script for personal use because of the lack of update options with the
original RTM release of Windows 10 Pro. I wanted to update Windows 10 when I had the free time
to manually update, just like I did with previous versions of Windows that allowed me to
set updates to manual, not when Microsoft forced it on me while I was busy using my computer.
*******************************************************************
WUMT is available here: https://forums.mydigitallife.net/threads/64939-Windows-Update-MiniTool
Windows Update Blocker is available here: http://sordum.org/files/windows-update-blocker/old/Wub_v1.0.zip
Only use Windows Update Blocker v1.0 with this script, NOT v1.1!
NSudo is available here: https://github.com/M2Team/NSudo/releases/tag/6.1
*******************************************************************
How it works: The script first checks if the OS is Windows 8.1 or older and if so
it notifies the user, then exits. Windows 10 only!
This script creates a smart Windows Defender Update task "WDU" that updates Windows
Defender every 6 hours if it's running and enabled, and doesn't update it if it's not
running and disabled, saving resources; auto-elevates, uninstalls and removes the
Windows 10 Update Assistant, disables everything in the %programfiles%\rempl folder, resets and
removes permissions from and disables these Update Hijackers:
EOSNotify.exe
WaaSMedic.exe
WaasMedicSvc.dll
WaaSMedicPS.dll
WaaSAssessment.dll
UsoClient.exe
SIHClient.exe
MusNotificationUx.exe
MusNotification.exe
osrss.dll
%ProgramFiles%\rempl
%systemroot%\UpdateAssistant
%systemroot%\UpdateAssistantV2
%systemdrive%\Windows10Upgrade
disables all WindowsUpdate tasks
makes sure the task "wub_task" is installed that runs wub at boot (to stop updates from turning
updates back on), runs wub.exe and enables and starts the windows update service (wuauserv) if
disabled, installs "WDU" Windows Defender Update task that runs every 2 hours (but doesn't update
Defender if Defender is disabled), then runs the correct version of the Windows Update MiniTool in
"auto search for updates" mode for your OS version's architecture (x86 or x64), then disables and
stops wuauserv giving you full control. No more forced automatic updates or surprise reboots.
This was written for Windows 10 Pro and Home, but works with all versions of Windows 10. Don't
change any settings in lower left of WUMT while running the script.
*******************************************************************
I also included an uninstaller.cmd that deletes the "WDU" and "wub_task" tasks, deletes the WDU.cmd
file used by WDU task, restores the rempl folder, resets Update Hijacker permissions to how they
were originally, renables "WindowsUpdate" tasks, and turns off wub (if enabled) which turns the windows update service on automatic
again, undoing everything done by the script. If you uninstall after having used the installer the
script files are removed also.
*******************************************************************
Configurator leaves the Update Hijackers disabled, but gives you the option of turning on the windows
update service temporarily to use the Store or any other operation that requires the windows update
service, such as some DISM operations, installing dotNet 3.5, App Updates, etc.
*******************************************************************
:start
::::::::::::::::::::::::::::
cd /d "%~dp0"
:::::::::::::::::::::::::::::::::::::::::
:: Automatically check & get admin rights
:::::::::::::::::::::::::::::::::::::::::
:: ECHO.
:: ECHO =============================
:: ECHO Running Admin shell
:: ECHO =============================
:: Check Privileges
:: Get Privileges
:: and
:: Invoke UAC for Privilege Escalation
:: Notify if error escalating
:: and prevent looping if escalation fails
::::::::::::::::::::::::::::
set "params=Problem_with_elevating_UAC_for_Administrator_Privileges"&if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs"
fsutil dirty query %systemdrive%  >nul 2>&1 && goto :GotPrivileges
::    The following test is to avoid infinite looping if elevating UAC for Administrator Privileges failed
If "%1"=="%params%" (echo Elevating UAC for Administrator Privileges failed&echo Right click on the script and select 'Run as administrator'&echo Press any key to exit...&pause>nul 2>&1&exit)
cmd /u /c echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "%~0", "%params%", "", "runas", 1 > "%temp%\getadmin.vbs"&cscript //nologo "%temp%\getadmin.vbs" && exit /b || (echo Elevating UAC for Administrator Privileges failed&echo Right click on the script and select 'Run as administrator'&echo Press any key to exit...&pause>nul 2>&1&exit)
:GotPrivileges
::::::::::::::::::::::::::::
::Uninstall and remove Windows 10 Update assistant.
::Disable Windows Update Service until script menu screen.
::Reset (in case of wrong Permissions), remove Permissions from and
::disable "Update Hijackers" 
::Install wub_task (prevents Windows Update service from starting after installing updates and rebooting).
::Install "WDU" task that only updates Defender if it's enabled. Otherwise it doesn't do anything.
::Enable and start the Windows Update Service (wuauserv).
::Run the correct version of WUMT for your architecture.
::Start WUMT in "auto-check for updates" mode.
::After updates are completed and WUMT is closed and/or the "reboot"
::button in WUMT is pressed, silently run wub.exe and disable and stop wuauserv
::::::::::::::::::::::::::::
::Test for Windows versions below Windows 10 and if so inform user, then exit...
::Get Windows OS build number
for /f "tokens=2 delims==" %%a in ('wmic path Win32_OperatingSystem get BuildNumber /value') do (
  set /a WinBuild=%%a
)
if %winbuild% LEQ 9600 (
echo.&echo This is not Windows 10. Press a key to exit...
pause > nul
exit
)
::::::::::::::::::::::::::::
::Determine if running 32 or 64 bit Windows OS and set variables accordingly.
wmic cpu get AddressWidth /value|find "32">nul&&set PROCESSOR_ARCHITECTURE=X86||set PROCESSOR_ARCHITECTURE=AMD64
if %PROCESSOR_ARCHITECTURE%==AMD64 (
 set "nsudovar=.\bin\NSudoCx64.exe"
 set "wumt=.\bin\wumt_x64.exe"
) else (
 set "nsudovar=.\bin\NSudoc.exe"
 set "wumt=.\bin\wumt_x86.exe"
)
::::::::::::::::::::::::::::
::Remove and/or lock Update Assistant
if exist "%systemdrive%\Windows10Upgrade\Windows10UpgraderApp.exe" ( echo Windows 10 Update Assistant detected. Preparing to uninstall.
echo The "Windows 10 Update Assistant has stopped working" dialog box may pop up.
echo If so, just close it.
echo.& echo Press a key to acknowledge this and please wait for the uninstall to finish.
echo Script will continue after uninstall and removal is completed...
pause > nul
echo Uninstalling Windows 10 Update Assistant...
%systemdrive%\Windows10Upgrade\Windows10UpgraderApp.exe /forceuninstall
timeout /t 10 /nobreak
cls)
::::::::::::::::::::::::::::
echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.
echo. & echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Initializing script...
::::::::::::::::::::::::::::
::Disable update service.
call :wuauserv d
::::::::::::::::::::::::::::
cls
echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.
echo. & echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Initializing script...
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Creating Tasks...
::::::::::::::::::::::::::::::::::
schtasks /delete /tn WDU >nul /f 2>&1
schtasks /delete /tn Wub_task /f >nul 2>&1
schtasks /Delete /Tn \Microsoft\WuWrapperScript\WDU /f >nul 2>&1
schtasks /Delete /Tn \Microsoft\WuWrapperScript\Wub_task /f >nul 2>&1
rmdir %SystemDrive%\Windows\System32\Tasks\Microsoft\WuWrapperScript /s /q >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\WuWrapperScript" /f >nul 2>&1
schtasks /Delete /Tn \Microsoft\Sledgehammer\WDU /f >nul 2>&1
schtasks /Delete /Tn \Microsoft\Sledgehammer\Wub_task /f >nul 2>&1
schtasks /Delete /Tn \Microsoft\Sledgehammer\LockFiles /f >nul 2>&1
rmdir %SystemDrive%\Windows\System32\Tasks\Microsoft\Sledgehammer /s /q >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Sledgehammer" /f >nul 2>&1
::::::::::::::::::::::::::::
takeown /f "%systemroot%\UpdateAssistant" /a >nul 2>&1
icacls "%systemroot%\UpdateAssistant" /reset >nul 2>&1
del %systemroot%\UpdateAssistant\*.* /f /q >nul 2>&1
rmdir %systemroot%\UpdateAssistant /s /q >nul 2>&1
md "%systemroot%\UpdateAssistant" >nul 2>&1
attrib +s +h "%systemroot%\UpdateAssistant" >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E "%systemroot%\System32\icacls.exe" %systemroot%\UpdateAssistant /inheritance:r /remove:g *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
takeown /f "%systemroot%\UpdateAssistantV2" /a >nul 2>&1
icacls "%systemroot%\UpdateAssistantV2" /reset >nul 2>&1
del %systemroot%\UpdateAssistantV2\*.* /f /q >nul 2>&1
md "%systemroot%\UpdateAssistantV2" >nul 2>&1
attrib +s +h "%systemroot%\UpdateAssistantV2" >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E "%systemroot%\System32\icacls.exe" %systemroot%\UpdateAssistantV2 /inheritance:r /remove:g *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
takeown /f "%SystemDrive%\Windows10Upgrade" /a >nul 2>&1
icacls "%SystemDrive%\Windows10Upgrade" /reset >nul 2>&1
del %SystemDrive%\Windows10Upgrade\*.* /f /q >nul 2>&1
rmdir %SystemDrive%\Windows10Upgrade /s /q >nul 2>&1
md "%systemdrive%\Windows10Upgrade" >nul 2>&1
attrib +s +h %systemdrive%\Windows10Upgrade >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E "%systemroot%\System32\icacls.exe" %systemdrive%\Windows10Upgrade /inheritance:r /remove:g *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
::::::::::::::::::::::::::::
::Disable rempl
if not exist "%ProgramFiles%\rempl" goto norempl
takeown /f "%ProgramFiles%\rempl" /a >nul 2>&1
icacls "%ProgramFiles%\rempl" /reset >nul 2>&1
for %%? in ("%ProgramFiles%\rempl\*") do (
takeown /f "%%?" /a >nul 2>&1
icacls "%%?" /reset >nul 2>&1
)
del %ProgramFiles%\rempl\*.* /f /q >nul 2>&1
rmdir %ProgramFiles%\rempl /s /q >nul 2>&1
:norempl
::The rempl folder doesn't exist, so create it and lock it from system access.
md "%ProgramFiles%\rempl" >nul 2>&1
attrib +s +h "%ProgramFiles%\rempl" >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E "%systemroot%\System32\icacls.exe" "%ProgramFiles%\rempl" /inheritance:r /remove:g *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
::::::::::::::::::::::::::::
:: Disable all Language Components Installer tasks
takeown /f "%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*" /a >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*" /q /c /t /reset >nul 2>&1
for %%? in ("%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*") do schtasks /change /tn "Microsoft\Windows\LanguageComponentsInstaller\%%~nx?" /disable >nul 2>&1
::::::::::::::::::::::::::::
cls
echo.&echo.&echo.
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ : ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Sledgehammer - Windows 10 Update Control ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo.&echo.&echo.
echo. & echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Initializing script...
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Creating Tasks...
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Disabling update service...
::::::::::::::::::::::::::::
:: Disable and lock all Windows Update tasks.
takeown /f "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /a >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /q /c /t /reset >nul 2>&1
for %%? in ("%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*") do schtasks /change /tn "Microsoft\Windows\WindowsUpdate\%%~nx?" /disable >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /inheritance:r /remove *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
::::::::::::::::::::::::::::
::Set list (s32list) of update hijacker files to be disabled, then disable everything in the list.
set s32list=EOSNotify.exe WaaSMedic.exe WaasMedicSvc.dll WaaSMedicPS.dll WaaSAssessment.dll UsoClient.exe
set s32list=%s32list% SIHClient.exe MusNotificationUx.exe MusNotification.exe osrss.dll
set s32=%systemroot%\System32
::If "s32list" files were previously renamed by script, restore original file names
for %%# in (%s32list%) do (
ren "%s32%\%%#"-backup "%%#" >nul 2>&1
if exist "%s32%\%%#" del "%s32%\%%#"-backup /f /q >nul 2>&1
)
::Lock files
for %%# in (%s32list%) do (
takeown /f "%s32%\%%#" /a >nul 2>&1
icacls "%s32%\%%#" /reset >nul 2>&1
if exist "%s32%\%%#" %nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E "%systemroot%\System32\icacls.exe" "%s32%\%%#" /inheritance:r /remove *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18 >nul 2>&1
)
::If files in "s32list" aren't locked for whatever reason, rename them.
for %%# in (%s32list%) do (
ren "%s32%\%%#" "%%#"-backup >nul 2>&1
if exist "%s32%\%%#"-backup del "%s32%\%%#" /f /q >nul 2>&1
)
::::::::::::::::::::::::::::
::Create WDU task, wub_task, and LockFiles task
call :create_task WDU "Windows Defender Update"
call :create_task Wub_task "Windows Update Blocker Auto-Renewal"
call :create_task LockFiles "Lock system update hijacker files"
::::::::::::::::::::::::::::
echo.&echo.&echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Windows 10 updates disabled.
echo.&echo.&echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Close window ^(click "X"^) if done.
echo.&echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ or
echo.&echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ If you want to continue to Windows Update...
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Check MS-DEFCON in browser first? (Y) or (N)
CHOICE /C NY /M "Your choice?:" >nul 2>&1
if %errorlevel%==2 start https://www.askwoody.com/ms-defcon-system/                                                       
rem pause >nul 2>&1
:splash
cls
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ::::::::::::::::::::::::::::::::
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ : ^ Welcome to manual updates! ^ :
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ::::::::::::::::::::::::::::::::
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ The Windows Update Service is now DISABLED and stopped.
echo ^ ^ The tasks "WDU" (Windows Defender Update), "wub_task" and "LockFiles" (Forces Update
echo ^ ^ ^ ^ ^ ^ ^ ^ service off and locks files) have been (re)created.
echo.
echo ^ * ^ Update Hijackers are now disabled! (see readme for details)
echo ^ * ^ If you just want to disable the Update Hijackers and not check for or install
echo ^ ^ ^ ^ updates, you may close this screen now.
echo.
echo ^ * ^ If you choose to review any available Windows updates, the script enables and
echo ^ ^ ^ ^ starts only the Windows Update Service, then runs the Windows update Manager
echo ^ ^ ^ ^ (WuMgr) or the Windows Update MiniTool (WUMT) to find and then hide or install
echo ^ ^ ^ ^ selected Windows updates. If you run WUMT, don't change WUMT settings while
echo ^ ^ ^ ^ running this script. If WuMgr or WUMT is offering updates, you need to hide or
echo ^ ^ ^ ^ install them before closing WuMgr or WUMT. 
echo.
echo ^ * ^ After checking for updates, the script stops and disables the Windows Update service
echo ^ ^ ^ ^ when WuMgr or WUMT is closed whether or not the service was previously enabled.
echo.
echo ^ * ^ If you choose to use the Store, you can enable update service in Configurator.
echo ^ ^ ^ ^ After using the Store, then either 1) disable update service or 2) continue script to
echo ^ ^ ^ ^ check for Windows updates with WuMgr or WUMT after which the update service will be
echo ^ ^ ^ ^ disabled. 
echo.
echo ^ * ^ If you move this script to another folder run it again so the tasks will work!
echo.
echo ^ * ^ The included uninstaller undoes script changes.
echo.&echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ---^>^>^> Press any key to continue. ^<^<^<---
pause > nul
::::::::::::::::::::::::::::
::Internet connection check
cls
set divider=:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
powershell -nologo "If([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet){Exit 0}Else{Exit 1}"
if %errorlevel%==0 (goto postinternetcheck)
:internetcheckerror
cls
echo.&echo.&echo.&echo.&echo.&echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Internet connection test failed. &echo.&echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Microsoft Store or Windows Updates won't work without internet. &echo.&echo. & echo %divider% & echo.&echo.&echo. ^ ^ ^ ^ ^ ^ ^ ---^>^>^> Press a key to continue if you're sure internet is working. ^<^<^<--- & echo.&echo. & echo %divider% & echo.&echo ^ ^ It's safe to cancel now if needed. Your system will not be left in an unstable state.&echo.&echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^(Ctrl-C, Alt-F4, or click "X" to cancel and exit^)&echo. & pause > nul
:postinternetcheck
::::::::::::::::::::::::::::
::Windows Update Service Configurator
cls
echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.
echo. & echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Initializing Configurator...
::disable windows update service except when wumt is run.
:wudisable
timeout -t 1 > nul
call :wuauserv d
cls
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ : ^ ^ ^ ^ Sledgehammer - Windows 10 Update Control Configurator ^ ^ ^ ^ :
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ---^>^>^> Windows Update Service is DISABLED and stopped ^(default^) ^<^<^<---
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ [E]nable Update Service temporarily to use Windows Store.
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ [1] Continue script to run Windows Update Manager (WuMgr)
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ in auto mode and check for Windows Updates.
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ [2] Continue script to run Windows Update Minitool (WUMT) 
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ in auto mode and check for Windows Updates.
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ [3] Continue script to run Windows Update Manager (WuMgr)
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ in automatic Offline Mode. *Warning: Wsusscn2.cab is
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ over 500 MB. Download will start immediately.*
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ [4] Continue script to run Windows Update Manager (WuMgr)
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ in Expert Mode.
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ [Q]uit script, or "Alt + F4", or close window, if you're
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ just verifying or are finished changing the update
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ service setting. It stays how it's set above.
echo. 
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ The Windows Update service will be automatically
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ started and stopped.
echo.&echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Please select [E], [1], [2], [3], [4], or [Q]
CHOICE /C E1234Q /M "Your choice?:" >nul 2>&1
if %errorlevel%==6 (exit) 
if %errorlevel%==5 call :startupdate bin\wumgr.exe 7971f918-a847-4430-9279-4a52d1efe18d -onclose close.cmd >nul 2>&1                  
if %errorlevel%==4 call :startupdate bin\wumgr.exe  -update -offline 7971f918-a847-4430-9279-4a52d1efe18d -onclose close.cmd >nul 2>&1   
if %errorlevel%==3 call :StartUpdate %wumt% -update "-onclose close.cmd" >nul 2>&1                                                       
if %errorlevel%==2 call :StartUpdate bin\wumgr.exe -update -online 7971f918-a847-4430-9279-4a52d1efe18d -provisioned -onclose close.cmd >nul 2>&1
cls
echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.
echo.&echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Please wait while Windows Update Service is enabled...
::enable windows update service
:wuenable
call :wuauserv e
cls
echo.&echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ : ^ ^ ^ ^ Sledgehammer - Windows 10 Update Control Configurator ^ ^ ^ ^ :
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ---^>^>^> Windows Update Service is ENABLED ^(for Store^) ^<^<^<---
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ [D]isable Update Service when finished using Store.
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ [1] Continue script to run Windows Update Manager (WuMgr)
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ in auto mode and check for Windows Updates.
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ [2] Continue script to run Windows Update Minitool (WUMT) 
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ in auto mode and check for Windows Updates.
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ [3] Continue script to run Windows Update Manager (WuMgr)
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ in automatic Offline Mode. *Warning: Wsusscn2.cab is
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ over 500 MB. Download will start immediately.*
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ [4] Continue script to run Windows Update Manager (WuMgr)
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ in Expert Mode.
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ The Windows Update service will be automatically
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ started and stopped.
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Please select [D], [1], [2], [3], or [4]
echo.
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :^ Don't close this window or update service will stay on!!!^ :
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ : ^ ^ Don't worry. Just run the script again to turn it off ^ ^ :
echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
CHOICE /C D1234 /M "Your choice?:" >nul 2>&1
if %errorlevel%==5 call :startupdate bin\wumgr.exe 7971f918-a847-4430-9279-4a52d1efe18d -onclose close.cmd >nul 2>&1                       
if %errorlevel%==4 call :startupdate bin\wumgr.exe  -update -offline 7971f918-a847-4430-9279-4a52d1efe18d -onclose close.cmd >nul 2>&1
if %errorlevel%==3 call :StartUpdate %wumt% -update "-onclose close.cmd" >nul 2>&1
if %errorlevel%==2 call :StartUpdate bin\wumgr.exe -update -online 7971f918-a847-4430-9279-4a52d1efe18d -provisioned -onclose close.cmd >nul 2>&1
if %errorlevel%==1 (
cls
echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.&echo.
echo.&echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Please wait while Windows Update Service is disabled...
goto wudisable
)
::::::::::::::::::::::::::::
:create_task
copy bin\%1.vbs task.vbs >nul & task.vbs
schtasks /delete /tn "%1" /f >nul 2>&1
schtasks /create /tn "\Microsoft\Sledgehammer\%1" /ru "SYSTEM" /xml task.xml /F >nul 2>&1 || (
cls&echo.&echo Creating %3 %2 %1 task errored.&echo.&echo.&echo Press any key to exit... & pause > nul &exit)
del task.vbs task.xml >nul 2>&1
exit /b
::::::::::::::::::::::::::::
:wuauserv
if /i "%1"=="e" (set "wub=wub.exe /e" & set "status=True") else (set "wub=wub.exe /d /p" & set "status=False")
.\bin\%wub%
timeout -t 2 > nul
set /a "max_retry=10" & set /a "i=0"
:wuauserv1
if %i%==%max_retry% (echo Operation did not complete within %max_retry% s. Press any key do exit...&pause>nul&exit)
set /a "i+=1"
WMIC Service WHERE "Name = 'Wuauserv'" GET Started | find /i "%status%" >nul && exit /b || (timeout /t 1 >nul & goto :wuauserv1)
::::::::::::::::::::::::::::
:StartUpdate
(
echo @echo off
echo :loop
echo net start wuauserv
echo timeout /t 10
echo goto loop
)>WU-keep-alive.cmd
(
echo @echo off
echo cd /d "%%~dp0"
echo del WU-keep-alive.cmd
echo .\bin\wub.exe /d /p
echo del close.cmd ^& exit
)>close.cmd
call :wuauserv e
echo CreateObject^("WScript.Shell"^).Run "WU-keep-alive.cmd",0 >WU-keep-alive.vbs&WU-keep-alive.vbs&del WU-keep-alive.vbs
Start "" %*
exit