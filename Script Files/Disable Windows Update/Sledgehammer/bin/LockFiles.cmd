::Allow only LockFiles task to run this file::
whoami /user /nh | find /i "S-1-5-18" || exit
cd /d "%~dp0"
::::::::::::::::::::::::::::
::Set list (s32list) of update hijacker files to be disabled, then disable everything in the list.
set s32list=EOSNotify.exe WaaSMedic.exe WaasMedicSvc.dll WaaSMedicPS.dll WaaSAssessment.dll UsoClient.exe
set s32list=%s32list% SIHClient.exe MusNotificationUx.exe MusNotification.exe osrss.dll
set s32=%systemroot%\System32
::If "s32list" files were previously renamed by script, restore original file names
for %%# in (%s32list%) do (
ren "%s32%\%%#"-backup "%%#"
if exist "%s32%\%%#" del "%s32%\%%#"-backup /f /q
)
::Lock files
for %%# in (%s32list%) do (
takeown /f "%s32%\%%#" /a
icacls "%s32%\%%#" /reset
if exist "%s32%\%%#" "%systemroot%\System32\icacls.exe" "%s32%\%%#" /inheritance:r /remove *S-1-5-32-544 *S-1-5-11 *S-1-5-32-545 *S-1-5-18
)
::If files in "s32list" aren't locked for whatever reason, rename them.
for %%# in (%s32list%) do (
ren "%s32%\%%#" "%%#"-backup
if exist "%s32%\%%#"-backup del "%s32%\%%#" /f /q
)
exit