@echo off
mode con cols=85 lines=20
Color 1F
Title Sledgehammer 2.7.2 uninstaller
::Elevate permissions
set "params=Problem_with_elevating_UAC_for_Administrator_Privileges"&if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs"
fsutil dirty query %systemdrive%  >nul 2>&1 && goto :GotPrivileges
::    The following test is to avoid infinite looping if elevating UAC for Administrator Privileges failed
If "%1"=="%params%" (echo Elevating UAC for Administrator Privileges failed&echo Right click on the script and select 'Run as administrator'&echo Press any key to exit...&pause>nul 2>&1&exit)
cmd /u /c echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "%~0", "%params%", "", "runas", 1 > "%temp%\getadmin.vbs"&cscript //nologo "%temp%\getadmin.vbs"&exit
:GotPrivileges
::Start
cd /d "%~dp0"
::::::::::::::::::::::::::::::::::
::Determine if running 32 or 64 bit Windows OS and set variables accordingly.
wmic cpu get AddressWidth /value|find "32">nul&&set PROCESSOR_ARCHITECTURE=X86||set PROCESSOR_ARCHITECTURE=AMD64
if %PROCESSOR_ARCHITECTURE%==AMD64 (
 set "nsudovar=..\bin\NSudoCx64.exe"
 ) else (
 set "nsudovar=..\bin\NSudoc.exe"
 )
::::::::::::::::::::::::::::::::::
echo. & echo  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Sledgehammer Uninstaller
echo. & echo  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ If you continue, and have no other method of controlling
echo  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ updates, UPDATES MAY START RIGHT AWAY.
echo. & echo ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ DISABLE THE INTERNET FIRST? Press (Y)es or(N).
echo. & echo ^ If you select (Y), "Network Connections" in the Control Panel will open so you can
echo ^ temporarily disable your Internet connection.
echo. & echo ^ Whether you select (Y) or (N), the next script window will stay open allowing you
echo ^ to fully uninstall the script and all associated changes that were made when you
echo ^ first ran the script.
CHOICE /C YN /M "Your choice?:" >nul 2>&1
if %errorlevel%==2 (goto nodisablenet)
%systemroot%\System32\control.exe ncpa.cpl
:nodisablenet
cls
echo. & echo. & echo. & echo. & echo. & echo. & echo.
echo  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ I have to ask if you're really sure?
echo  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ Press (Y)es to uninstall, (N)o or 
echo  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ close window to cancel...
CHOICE /C YN /M "Your choice?:" >nul 2>&1
if %errorlevel%==2 (exit)
cls
set s32=%systemroot%\System32
::::::::::::::::::::::::::::::::::
::restore rempl folder permissions and delete rempl folder
takeown /f "%ProgramFiles%\rempl" /a >nul 2>&1
icacls "%ProgramFiles%\rempl" /reset >nul 2>&1
::restore rempl file permissions
for %%? in ("%ProgramFiles%\rempl\*") do (
takeown /f "%%?" /a >nul 2>&1
icacls "%%?" /q /c /reset >nul 2>&1
rem icacls "%%?" /setowner *S-1-5-18 >nul 2>&1
)
del "%ProgramFiles%\rempl\*.*" /f /q >nul 2>&1
rmdir "%ProgramFiles%\rempl" /s /q >nul 2>&1
::::::::::::::::::::::::::::
schtasks /delete /tn WDU >nul /f 2>&1
schtasks /delete /tn Wub_task /f >nul 2>&1
schtasks /Delete /Tn \Microsoft\WuWrapperScript\WDU /f >nul 2>&1
schtasks /Delete /Tn \Microsoft\WuWrapperScript\Wub_task /f >nul 2>&1
rmdir %SystemDrive%\Windows\System32\Tasks\Microsoft\WuWrapperScript /s /q >nul 2>&1
rem timeout /t 3 >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\WuWrapperScript" /f >nul 2>&1
schtasks /Delete /Tn \Microsoft\Sledgehammer\WDU /f >nul 2>&1
schtasks /Delete /Tn \Microsoft\Sledgehammer\Wub_task /f >nul 2>&1
schtasks /Delete /Tn \Microsoft\Sledgehammer\LockFiles /f >nul 2>&1
rmdir %SystemDrive%\Windows\System32\Tasks\Microsoft\Sledgehammer /s /q >nul 2>&1
rem timeout /t 3 >nul 2>&1
%nsudovar% -ShowWindowMode:Hide -Wait -U:T -P:E reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Sledgehammer" /f >nul 2>&1
::::::::::::::::::::::::::::::::::
::Restore Language Components Installer tasks to defaults
takeown /f "%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*" /a >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*" /q /c /t /reset >nul 2>&1
for %%? in ("%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*") do schtasks /change /tn "Microsoft\Windows\LanguageComponentsInstaller\%%~nx?" /enable >nul 2>&1
schtasks /change /tn "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /disable >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\LanguageComponentsInstaller\*" /setowner *S-1-5-18 >nul 2>&1
::::::::::::::::::::::::::::::::::
::Restore Windows Update tasks to defaults
takeown /f "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /a >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /q /c /t /reset >nul 2>&1
for %%? in ("%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*") do schtasks /change /tn "Microsoft\Windows\WindowsUpdate\%%~nx?" /enable >nul 2>&1
icacls "%systemroot%\System32\Tasks\Microsoft\Windows\WindowsUpdate\*" /setowner *S-1-5-18 >nul 2>&1
::::::::::::::::::::::::::::::::::
::Restore default permissions to Update Hijacker files disabled by script
set s32list=EOSNotify.exe WaaSMedic.exe WaasMedicSvc.dll WaaSMedicPS.dll WaaSAssessment.dll UsoClient.exe
set s32list=%s32list% SIHClient.exe MusNotificationUx.exe MusNotification.exe osrss.dll
::If "s32list" files were renamed by script, restore original file names
for %%# in (%s32list%) do (
ren "%s32%\%%#"-backup "%%#" >nul 2>&1
if exist "%s32%\%%#" del "%s32%\%%#"-backup /f /q >nul 2>&1
)
::Now restore default permissions for Update Hijacker files
for %%# in (%s32list%) do (
takeown /f "%s32%\%%#" /a >nul 2>&1
icacls "%s32%\%%#" /reset >nul 2>&1
icacls "%s32%\%%#" /setowner *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 >nul 2>&1
)
::restore Update Assistant folder permissions, then delete
takeown /f "%systemroot%\UpdateAssistant" /a >nul 2>&1
icacls "%systemroot%\UpdateAssistant" /reset >nul 2>&1
icacls "%systemroot%\UpdateAssistant" /setowner *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 >nul 2>&1
del %systemroot%\UpdateAssistant\*.* /f /q >nul 2>&1
rmdir %systemroot%\UpdateAssistant /s /q >nul 2>&1
takeown /f "%systemroot%\UpdateAssistantV2" /a >nul 2>&1
icacls "%systemroot%\UpdateAssistantV2" /reset >nul 2>&1
icacls "%systemroot%\UpdateAssistantV2" /setowner *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 >nul 2>&1
del %systemroot%\UpdateAssistantV2\*.* /f /q >nul 2>&1
rmdir %systemroot%\UpdateAssistantV2 /s /q >nul 2>&1
takeown /f "%systemdrive%\Windows10Upgrade" /a >nul 2>&1
icacls "%systemdrive%\Windows10Upgrade" /reset >nul 2>&1
icacls "%systemdrive%\Windows10Upgrade" /setowner *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464 >nul 2>&1
del %SystemDrive%\Windows10Upgrade\*.* /f /q >nul 2>&1
rmdir %SystemDrive%\Windows10Upgrade /s /q >nul 2>&1
::::::::::::::::::::::::::::::::::
..\bin\wub.exe /e >nul 2>&1
timeout /t 3 >nul 2>&1
cls
if not exist unins000.exe (
echo. & echo. & echo. & echo. & echo. & echo.
echo  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ::::::::::::::::::::::::::::::::::::
echo  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :    Sledgehammer uninstalled.     :
echo  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ :     Press any key to exit...     :
echo  ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ::::::::::::::::::::::::::::::::::::
pause > nul
exit
)
rem unins000.exe /silent /norestart