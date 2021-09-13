&::Create Restore Point
Wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Windows Bloatware removal", 100, 12

&:: *** Disable Some Service ***
sc stop DiagTrack
sc stop diagnosticshub.standardcollector.service
sc stop dmwappushservice
sc stop WMPNetworkSvc
sc stop WSearch

sc config DiagTrack start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config dmwappushservice start= disabled
&:: sc config remoteRegistry start= disabled
&:: sc config TrkWks start= disabled
sc config WMPNetworkSvc start= disabled
sc config WSearch start= disabled
&:: sc config SysMain start= disabled

&:: *** SCHEDULED TASKS tweaks ***
&:: schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

&:: schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
&:: schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
&:: schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
&:: schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable *** Not sure if should be disabled, maybe related to S.M.A.R.T.
&:: schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
&:: schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
&:: schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
&:: schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
&:: The stubborn task Microsoft\Windows\SettingSync\BackgroundUploadTask can be Disabled using a simple bit change. I use a REG file for that (attached to this post).
&:: schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
&:: schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
&:: schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
&:: schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable


&:: *** &::ove Telemetry and Data Collection ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f

&:: Settings -> Privacy -> General -> Let apps use my advertising ID...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
&:: - SmartScreen Filter for Store Apps: Disable
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
&:: - Let websites provide locally...
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f

&:: WiFi Sense: HotSpot Sharing: Disable
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f
&:: WiFi Sense: Shared HotSpot Auto-Connect: Disable
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f

&:: Change Windows Updates to "Notify to schedule restart"
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v UxOption /t REG_DWORD /d 1 /f
&:: Disable P2P Update downlods outside of local network
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f


&:: *** Hide the search box from taskbar. You can still search by pressing the Win key and start typing what youre looking for ***
&:: 0 = hide completely, 1 = show only icon, 2 = show long search box
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f

&:: *** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

&:: *** Set Windows Explorer to start on This PC instead of Quick Access ***
&:: 1 = This PC, 2 = Quick access
&:: reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

&:: remove Apps
PowerShell -Command "Get-AppxPackage *3DBuilder* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Getstarted* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsAlarms* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsCamera* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bing* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MicrosoftOfficeHub* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *OneNote* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *zunemusic* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *SkypeApp* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *zunevideo* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsSoundRecorder* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bingnews* | remove-AppxPackage"
&:: PowerShell -Command "Get-AppxPackage *WindowsCalculator* | remove-AppxPackage"
&:: PowerShell -Command "Get-AppxPackage *WindowsMaps* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Sway* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *CommsPhone* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *ConnectivityStore* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Facebook* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Twitter* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *sound recorder* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bingweather* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *xboxapp* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Drawboard PDF* | remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *solitairecollection* | remove-AppxPackage"

&:: NOW JUST SOME TWEAKS
&:: *** Show hidden files in Explorer ***
&:: reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f

&:: *** Show super hidden system files in Explorer ***
&:: reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

&:: *** Show file extensions in Explorer ***
&::reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f

&:: *** Uninstall OneDrive ***
&::start /wait "" "%SYSTEMROOT%\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
&::rd C:\OneDriveTemp /Q /S >NUL 2>&1
&::rd "%USERPROFILE%\OneDrive" /Q /S >NUL 2>&1
&::rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S >NUL 2>&1
&::rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S >NUL 2>&1
&::reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
&::reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
&::echo OneDrive has been removed. Windows Explorer needs to be restarted.
pause
start /wait TASKKILL /F /IM explorer.exe
shutdown /r now
