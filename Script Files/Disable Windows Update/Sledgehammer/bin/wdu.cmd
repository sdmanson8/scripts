::Allow only WDU task to run this file::
whoami /user /nh | find /i "S-1-5-18" || exit
cd /d "%~dp0"
::Wait 5 minutes to prevent resource hogging after reboot with missed update::
timeout /t 300>nul 
::If WUMT or WuMgr are running, cancel Defender update and exit. If not, continue::
tasklist | findstr /i "wumt_x86.exe wumt_x64.exe wumgr.exe" && exit 1
::If Windows Defender is running, update it. If not, cancel Defender update and exit::
sc query | find /i "windefend" || exit 1
::Enable Windows Update service and update Defender, then disable Update Service::
wub.exe /e
timeout /t 10
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -SignatureUpdate
wub.exe /d /p
exit /b %errorlevel%
