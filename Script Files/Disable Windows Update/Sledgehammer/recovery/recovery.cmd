@echo off
Title Windows 10 update wrapper script 2.7.2 recovery
:: Works with all previous script versions::
echo.&echo Only run this from Windows PE or install environment.
echo.&echo Press a key to continue, or click "X" to close window...
pause > nul
:Start
cls
set "drive="
set "areyousure="
set "s32="
set "s32list="
echo. & echo (Ctrl-C) to exit script
echo.&echo Looking for valid drives...
::::::::::::::::::::::::::::::::::
::Show available drives, free disk space, drive size, and volume label
for /f "skip=1 tokens=1-4" %%a in ('WMIC LOGICALDISK GET FreeSpace^,Name^,Size^,VolumeName') do @echo wsh.echo "%%b" ^& " free=" ^& FormatNumber^(cdbl^(%%a^)/1024/1024/1024, 2^)^& " GiB,"^& " size=" ^& FormatNumber^(cdbl^(%%c^)/1024/1024/1024, 2^)^& " GiB," ^& " Volume Label=%%d" > %temp%\tmp.vbs & @if not "%%c"=="" @echo( & @cscript //nologo %temp%\tmp.vbs & del %temp%\tmp.vbs
::::::::::::::::::::::::::::::::::
::Find all drives that contain \Windows\system32\usoclient.exe
echo.
echo Looking for drives that contain \Windows\system32\usoclient.exe...
for /f "skip=1 tokens=1" %%a in ('WMIC LOGICALDISK GET Name^') do (if exist %%a\Windows\System32\usoclient.exe echo ---Drive %%a looks like a possible candidate---)
::::::::::::::::::::::::::::::::::
echo. & SET /P drive= Enter only a drive letter without colon (X and not X:) to run wrapper script recovery:
echo (Ctrl-C to exit)
echo You chose %drive%
SET /P areyousure=Is this correct? (Y/[N])?
IF /I "%areyousure%" neq "Y" goto start
::check for renamed update hijacker files
if exist %drive%:\Windows\System32\usoclient.exe-backup goto continue
)
::check for file permissions
copy %drive%:\Windows\System32\usoclient.exe %drive%:\WWStempfile
if %errorlevel% neq 1 (
echo.
echo If you see "1 file(s) copied." message above, the drive has already
echo been repaired or drive %drive% is the wrong drive.
echo Try again with the correct drive letter without colon.
echo Press any key to try again...
pause > nul
del %drive%:\WWStempfile
goto start
)
::
:continue
echo restoring default permissions to update hijacker files on %drive%:Windows\System32
::Restore default permissions to Update Hijacker files disabled by script
set s32=%drive%:\Windows\System32
set s32list=EOSNotify.exe WaaSMedic.exe WaasMedicSvc.dll WaaSMedicPS.dll WaaSAssessment.dll UsoClient.exe
set s32list=%s32list% SIHClient.exe MusNotificationUx.exe MusNotification.exe osrss.dll upfc.exe
::If "s32list" files were renamed by script, restore original file names
for %%# in (%s32list%) do (
if exist "%s32%\%%#"-backup ren "%s32%\%%#"-backup "%%#"
if exist "%s32%\%%#" del "%s32%\%%#"-backup /f /q
)
::Now restore default permissions for Update Hijacker files
for %%# in (%s32list%) do (
takeown /f "%s32%\%%#" /a
icacls "%s32%\%%#" /reset
icacls "%s32%\%%#" /setowner *S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
)
echo Permissions restoration final check. You should see "1 file(s) copied" on next line:
copy %drive%:\Windows\System32\usoclient.exe %drive%:\WWStempfile
if %errorlevel% neq 0 echo. & echo Repair failed, try again with the correct drive letter without colon & pause & goto start
del %drive%:\WWStempfile
echo ===========================================================
echo. & echo ---Update Hijacker system file permissions restored to default on drive %drive%---
echo Multiple "ERROR: The system cannot find the file specified" and other similar error messages is normal.
echo You should see multiple "SUCCESS: The file (or folder): "filename" now owned by the administrators group" messages.
echo You should see multiple "Successfully processed 1 files" messages
echo If for some reason this recovery script didn't work, re-run the recovery
echo script again and choose another detected drive.
echo No harm was done if you picked the wrong drive.
echo You may now exit the Recovery Environment and boot windows 10.
::::::::::::::::::::::::::::::::::
:END