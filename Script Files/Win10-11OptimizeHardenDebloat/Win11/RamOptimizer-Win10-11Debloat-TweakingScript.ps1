# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

Clear-Host
Write-Host "`nPlease wait a few minutes...`n"
Start-Sleep -Seconds 1
################### Starting Script ############################################################

$Host.UI.RawUI.WindowTitle = "Ram Optimizer and Windows Tweaking Script"

#Creates a PSDrive to be able to access the 'HKCR' tree
$path = Test-Path HKCR:\
IF ($path -eq $False) {New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT} ELSE {Write-Host ""}

#Kill Foreground
taskkill /F /IM "msedge.exe"
taskkill /F /IM "explorer.exe"
Clear-Host

# Updating Notepad++
Write-Host "Silently Updating Notepad++ ... Please wait..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$homeUrl = 'https://notepad-plus-plus.org'
$res = Invoke-WebRequest -UseBasicParsing $homeUrl
if ($res.StatusCode -ne 200) {throw ("status code to getDownloadUrl was not 200: "+$res.StatusCode)}
$tempUrl = ($res.Links | Where-Object {$_.outerHTML -like "*Current Version *"})[0].href
if ($tempUrl.StartsWith("/")) { $tempUrl = "$homeUrl$tempUrl" }
$res = Invoke-WebRequest -UseBasicParsing $tempUrl
if ($res.StatusCode -ne 200) {throw ("status code to getDownloadUrl was not 200: "+$res.StatusCode)}
$dlUrl = ($res.Links | Where-Object {$_.href -like "*x64.exe"})[0].href
if ($dlUrl.StartsWith("/")) { $dlUrl = "$homeUrl$dlUrl" }
$installerPath = Join-Path $env:TEMP (Split-Path $dlUrl -Leaf)
Invoke-WebRequest $dlUrl -OutFile $installerPath
Start-Process -FilePath $installerPath -Args "/S" -Verb RunAs -Wait
Remove-Item $installerPath
   Write-Host Notepad++ Updated
Start-Sleep -Milliseconds 500
Clear-Host

#####################
$url = 'https://github.com/PowerShell/PowerShell/releases/latest'
$request = [System.Net.WebRequest]::Create($url)
$response = $request.GetResponse()
$realTagUrl = $response.ResponseUri.OriginalString
$version = $realTagUrl.split('/')[-1].Trim('v')

####################
#Updating Powershell
    Write-Host "Preparing to Silently Update Powershell to Version $version ... Please wait..."
    iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Quiet"
    Write-Host "Powershell updated to $version"

################ -------------------------------------------- ######################
####################################################################################

Start-Sleep -Milliseconds 500
Clear-Host

#Lower Ram
Invoke-WebRequest -Uri https://raw.githubusercontent.com/W4RH4WK/Debloat-Windows-10/master/utils/lower-ram-usage.reg -OutFile $env:USERPROFILE\Downloads\ram-reducer.reg
regedit.exe /S $env:USERPROFILE\Downloads\ram-reducer.reg

#Enable Photo Viewer
Invoke-WebRequest -Uri https://raw.githubusercontent.com/W4RH4WK/Debloat-Windows-10/master/utils/enable-photo-viewer.reg -Outfile $env:USERPROFILE\Downloads\enable-photo-viewer.reg
regedit.exe /S $env:USERPROFILE\Downloads\enable-photo-viewer.reg

#Disable Edge Prelaunch
Invoke-WebRequest -Uri https://raw.githubusercontent.com/W4RH4WK/Debloat-Windows-10/master/utils/disable-edge-prelaunch.reg -OutFile $env:USERPROFILE\Downloads\disable-edge-prelaunch.reg
regedit.exe /S $env:USERPROFILE\Downloads\disable-edge-prelaunch.reg

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\" -Name "WindowsStore" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

# Prevents "Suggested Applications" returning
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "CloudContent" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1

# Disable some of the "new" features of Windows 10, such as forcibly installing apps you don't want, and the new annoying animation for first time login.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'CloudContent' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type "DWord" -Value '1' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -Type "DWord" -Value '1' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableFirstLogonAnimation' -Type "DWord" -Value '0' -Force

# Remove OneDrive, and stop it from showing in Explorer side menu.
C:\Windows\SysWOW64\OneDriveSetup.exe /uninstall
Remove-Item -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse -ErrorAction SilentlyContinue -Confirm:$false

# Ensure updates are downloaded from Microsoft instead of other computers on the internet.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'DeliveryOptimization' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -Type DWord -Value '0' -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'SystemSettingsDownloadMode' -Type DWord -Value '0' -Force
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\' -Name 'DeliveryOptimization'
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\' -Name 'Config'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DODownloadMode' -Type DWord -Value '0' -Force

#Create Shortcut on Desktop | Reboot to Advanced Menu
Invoke-WebRequest -Uri "https://github.com/sdmanson8/scripts/raw/main/Script%20Files/troubleshoot.ico" -OutFile "$env:USERPROFILE\Downloads\troubleshoot.ico"
$item = "$env:USERPROFILE\Downloads\troubleshoot.ico"
Move-Item $item "$env:WINDIR\troubleshoot.ico" -Force -ErrorAction SilentlyContinue -Confirm:$false
$location = "$env:WINDIR\troubleshoot.ico"

$SourceFileLocation = "$env:WINDIR\System32\shutdown.exe"
$ShortcutLocation = "$env:USERPROFILE\Desktop\Advanced Startup (REBOOT).lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutLocation)
$Shortcut.TargetPath = $SourceFileLocation
$Shortcut.IconLocation = "$location, 0"
$Shortcut.Arguments = "/r /o /f /t 00"
$Shortcut.Save()

#Disable metro boot menu
bcdedit /set {default} bootmenupolicy legacy

#Add environmental variables
setx ProgramFiles "$env:ProgramFiles" /m
setx ProgramFiles86 "$env:ProgramFiles86" /m
setx ProgramData "$env:ProgramData" /m

#Hide PerfLogs folder
attrib "$env:WINDIR\PerfLogs" +h

#Reveal Public Desktop folder
attrib "$env:PUBLIC\Desktop" -h

#Delete "Your Phone" shortcut from Desktop"
Remove-Item "$env:USERPROFILE\Desktop\Your Phone.lnk" -Force -ErrorAction SilentlyContinue -Confirm:$false

# disable Memory Compression (requires SysMain (service))
Disable-MMAgent -mc

Write-Host "Disabling service SysMain (former Superfetch)"
Get-Service "SysMain" | Set-Service -StartupType Disabled -PassThru | Stop-Service

# Disable Prefetch
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher -Type "DWORD" -Value 0 -Force

# Disable (Edge) Prelaunch
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name AllowPrelaunch -Type "DWORD" -Value 0 -Force

#Disable Services
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushsvc" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushsvc" -Name Start -Type "DWORD" -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PeerDistSvc" -Name "Start" -Type "DWORD" -Value 4 -Force

#Change Folder options
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type "DWORD" -Value 0 -Force

#Disable Slideshow during Lock Screen
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lock Screen" -Name "SlideshowEnabled" -Type "DWORD" -Value 0 -Force

#Enable Peek at desktop
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisablePreviewDesktop" -Type "DWORD" -Value 0 -Force

#Disable all Content Delivery Manager features
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RemediationRequired" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314563Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type "DWORD" -Value 0 -Force

#Disable all suggested apps
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\" -Name "SuggestedApps" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "22StokedOnIt.NotebookPro_ffs55s3hze5sr" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "2FE3CB00.PicsArt-PhotoStudio_crhqpqs3x1ygc" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "41038Axilesoft.ACGMediaPlayer_wxjjre7dryqb6" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "5CB722CC.SeekersNotesMysteriesofDarkwood_ypk0bew5psyra" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "7458BE2C.WorldofTanksBlitz_x4tje2y229k00" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "828B5831.HiddenCityMysteryofShadows_ytsefhwckbdv6" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "828B5831.TheSecretSociety-HiddenMystery_ytsefhwckbdv6" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "89006A2E.AutodeskSketchBook_tf1gferkr813w" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "9E2F88E3.Twitter_wgeqdkkx372wm" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "A278AB0D.AsphaltStreetStormRacing_h6adky7gbf63m" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "A278AB0D.DisneyMagicKingdoms_h6adky7gbf63m" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "A278AB0D.DragonManiaLegends_h6adky7gbf63m" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "A278AB0D.MarchofEmpires_h6adky7gbf63m" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "AdobeSystemsIncorporated.PhotoshopElements2018_ynb6jyjzte8ga" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "CAF9E577.Plex_aam28m9va5cke" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "DolbyLaboratories.DolbyAccess_rz1tebttyb220" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Drawboard.DrawboardPDF_gqbn7fs4pywxm" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Expedia.ExpediaHotelsFlightsCarsActivities_0wbx8rnn4qk5c" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Facebook.317180B0BB486_8xx8rvfyw5nnt" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Facebook.Facebook_8xx8rvfyw5nnt" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Facebook.InstagramBeta_8xx8rvfyw5nnt" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Fitbit.FitbitCoach_6mqt6hf9g46tw" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "flaregamesGmbH.RoyalRevolt2_g0q0z3kw54rap" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "GAMELOFTSA.Asphalt8Airborne_0pp20fcewvvtj" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "king.com.BubbleWitch3Saga_kgqvnymyfvs32" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "king.com.CandyCrushSaga_kgqvnymyfvs32" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "king.com.CandyCrushSodaSaga_kgqvnymyfvs32" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.AgeCastles_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.BingNews_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.BingSports_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.BingWeather_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "microsoft.microsoftskydrive_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.MinecraftUWP_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Microsoft.MSPaint_8wekyb3d8bbwe" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "NAVER.LINEwin8_8ptj331gd3tyt" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "Nordcurrent.CookingFever_m9bz608c1b9ra" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "SiliconBendersLLC.Sketchable_r2kxzpx527qgj" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "SpotifyAB.SpotifyMusic_zpdnekdrzrea0" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "ThumbmunkeysLtd.PhototasticCollage_nfy108tqq3p12" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "USATODAY.USATODAY_wy7mw3214mat8" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" -Name "WinZipComputing.WinZipUniversal_3ykzqggjzj4z0" -Type "DWORD" -Value 0 -Force

#Disable mouse acceleration
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type "DWORD" -Value 0 -Force

#Disable Network Location Wizard prompts
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" -Force

#Change Performance Options to Adjust for best performance
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Type "DWORD" -Value 2 -Force

#Disable "Windows protected your PC" dialogue
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type "DWORD" -Value 1 -Force

#Disable Malicious Software Removal Tool from installing
New-Item -Path "HKLM:\Software\Policies\Microsoft\MRT" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type "DWORD" -Value 1 -Force

#Disable Error Reporting
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type "DWORD" -Value 1 -Force

#Keep thumbnail cache upon Restart
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "Autorun" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name "Autorun" -Type "DWORD" -Value 0 -Force

#Increase 15 file selection limit that hides context menu items
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "MultipleInvokePromptMinimum" -Type "DWORD" -Value 999 -Force

#Download SetAcl.exe
Invoke-WebRequest -Uri https://github.com/Fahim732/Windows-10-optimize-script/raw/master/SetACL.exe -OutFile $env:USERPROFILE\Downloads\SetACL.exe
Set-Location -Path $env:USERPROFILE\Downloads

#Replace "Personalize" with "Appearance" in desktop context menu
& .\SetACL.exe -silent -on "HKCR:\DesktopBackground\Shell\Personalize" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\DesktopBackground\Shell\Personalize" -ot reg -actn ace -ace "n:Administrators;p:full"
& .\SetACL.exe -silent -on "HKCR:\DesktopBackground\Shell\Personalize\command" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\DesktopBackground\Shell\Personalize\command" -ot reg -actn ace -ace "n:Administrators;p:full"
Remove-Item -Path "HKCR:\DesktopBackground\Shell\Personalize" -Force -ErrorAction SilentlyContinue -Confirm:$false -Recurse
New-Item -Path "HKCR:\DesktopBackground\Shell\" -Name 01Appearance -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance" -Name "Icon" -Type "String" -Value "display.dll,-1" -Force | Out-Null
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance" -Name "MUIVerb" -Type "String" -Value "Appearance" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance" -Name "Position" -Type "String" -Value "Bottom" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance" -Name "Subcommands" -Type "String" -Value "" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance" -Name Shell -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell" -Name 01Background -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\01Background" -Name "Icon" -Type String -Value "imageres.dll,-110" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\01Background" -Name "MUIVerb" -Type "String" -Value "Background" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\01Background" -Name "SettingsURI" -Type "String" -Value "ms-settings:personalization-background" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\01Background" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\01Background\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\" -Name 02Colors -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\02Colors" -Name "Icon" -Type "String" -Value "themecpl.dll" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\02Colors" -Name "MUIVerb" -Type "String" -Value "Colors" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\02Colors" -Name "SettingsURI" -Type "String" -Value "ms-settings:personalization-colors" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\02Colors" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\02Colors\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\" -Name 03DesktopIcons -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\03DesktopIcons" -Name "Icon" -Type "String" -Value "desk.cpl" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\03DesktopIcons" -Name "MUIVerb" -Type "String" -Value "Desktop Icons" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\03DesktopIcons" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\03DesktopIcons\command" -Name '""' -Type "String" -Value "rundll32 shell32.dll,Control_RunDLL desk.cpl,,0" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\" -Name 04LockScreen -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\04LockScreen" -Name "Icon" -Type "String" -Value "imageres.dll,285" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\04LockScreen" -Name "MUIVerb" -Type "String" -Value "Lock Screen" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\04LockScreen" -Name "SettingsURI" -Type "String" -Value "ms-settings:lockscreen" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\04LockScreen" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\04LockScreen\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\" -Name 05MousePointers -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\05MousePointers" -Name "Icon" -Type "String" -Value "main.cpl" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\05MousePointers" -Name "MUIVerb" -Type "String" -Value "Mouse Pointers" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\05MousePointers" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\05MousePointers\command" -Name '""' -Type "String" -Value "rundll32.exe shell32.dll,Control_RunDLL main.cpl,,1" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\" -Name 06ScreenSaver -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\06ScreenSaver" -Name "Icon" -Type "String" -Value "PhotoScreensaver.scr" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\06ScreenSaver" -Name "MUIVerb" -Type "String" -Value "Screen Saver" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\06ScreenSaver" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\06ScreenSaver\command" -Name '""' -Type "String" -Value "rundll32.exe shell32.dll,Control_RunDLL desk.cpl,screensaver,@screensaver" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\07Sounds" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\07Sounds" -Name "Icon" -Type "String" -Value "mmsys.cpl" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\07Sounds" -Name "MUIVerb" -Type "String" -Value "Sounds" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\07Sounds" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\07Sounds\command" -Name '""' -Type "String" -Value "rundll32.exe shell32.dll,Control_RunDLL mmsys.cpl ,2" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\08Taskbar" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\08Taskbar" -Name "Icon" -Type "String" -Value "shell32.dll,-40" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\08Taskbar" -Name "MUIVerb" -Type "String" -Value "Taskbar" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\08Taskbar" -Name "SettingsURI" -Type "String" -Value "ms-settings:taskbar" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\08Taskbar" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\01Appearance\Shell\08Taskbar\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force

#Replace Display Settings with Settings in desktop context menu
& .\SetACL.exe -silent -on "HKCR:\DesktopBackground\Shell\Display" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\DesktopBackground\Shell\Display" -ot reg -actn ace -ace "n:Administrators;p:full"
& .\SetACL.exe -silent -on "HKCR:\DesktopBackground\Shell\Display\command" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\DesktopBackground\Shell\Display\command" -ot reg -actn ace -ace "n:Administrators;p:full"
Remove-Item -Path "HKCR:\DesktopBackground\Shell\Display" -Force -ErrorAction SilentlyContinue -Confirm:$false -Recurse
New-Item -Path "HKCR:\DesktopBackground\Shell\" -Name 02Settings -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings" -Name "MUIVerb" -Type "String" -Value "Settings" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings" -Name "Position" -Type "String" -Value "Bottom" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings" -Name "Subcommands" -Type "String" -Value "" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\" -Name shell -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 01Accounts -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\01Accounts" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\01Accounts" -Name "MUIVerb" -Type "String" -Value "Accounts" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\01Accounts" -Name "SettingsURI" -Type "String" -Value "ms-settings:yourinfo" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\01Accounts" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\01Accounts\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 02Apps -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\02Apps" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\02Apps" -Name "MUIVerb" -Type "String" -Value "Apps" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\02Apps" -Name "SettingsURI" -Type "String" -Value "ms-settings:appsfeatures" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\02Apps" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\02Apps\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 03Devices -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\03Devices" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\03Devices" -Name "MUIVerb" -Type "String" -Value "Devices" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\03Devices" -Name "SettingsURI" -Type "String" -Value "ms-settings:bluetooth" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\03Devices" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\03Devices\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 04Display -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\04Display" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\04Display" -Name "MUIVerb" -Type "String" -Value "Display" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\04Display" -Name "SettingsURI" -Type "String" -Value "ms-settings:display" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\04Display" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\04Display\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 05Ease -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\05Ease" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\05Ease" -Name "MUIVerb" -Type "String" -Value "Ease of Access" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\05Ease" -Name "SettingsURI" -Type "String" -Value "ms-settings:easeofaccess-narrator" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\05Ease" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\05Ease\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 06Gaming -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\06Gaming" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\06Gaming" -Name "MUIVerb" -Type "String" -Value "Gaming" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\06Gaming" -Name "SettingsURI" -Type "String" -Value "ms-settings:gaming-gamebar" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\06Gaming" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\06Gaming\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 07Network -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\07Network" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\07Network" -Name "MUIVerb" -Type "String" -Value "Network && Internet" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\07Network" -Name "SettingsURI" -Type "String" -Value "ms-settings:network" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\07Network" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\07Network\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 08Personalization -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\08Personalization" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\08Personalization" -Name "MUIVerb" -Type "String" -Value "Personalization" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\08Personalization" -Name "SettingsURI" -Type "String" -Value "ms-settings:themes" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\08Personalization" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\08Personalization\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 09Phone -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\09Phone" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\09Phone" -Name "MUIVerb" -Type "String" -Value "Phone" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\09Phone" -Name "SettingsURI" -Type "String" -Value "ms-settings:mobile-devices" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\09Phone\" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\09Phone\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 10Privacy -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\10Privacy" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\10Privacy" -Name "MUIVerb" -Type "String" -Value "Privacy" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\10Privacy" -Name "SettingsURI" -Type "String" -Value "ms-settings:privacy" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\10Privacy\" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\10Privacy\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 11Search -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\11Search" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\11Search" -Name "MUIVerb" -Type "String" -Value "Search" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\11Search" -Name "SettingsURI" -Type "String" -Value "ms-settings:cortana" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\11Search\" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\11Search\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 12Time -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\12Time" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\12Time" -Name "MUIVerb" -Type "String" -Value "Time && Language" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\12Time" -Name "SettingsURI" -Type "String" -Value "ms-settings:dateandtime" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\12Time\" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\12Time\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\" -Name 13Update -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\13Update" -Name "Icon" -Type "String" -Value "SystemSettingsBroker.exe" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\13Update" -Name "MUIVerb" -Type "String" -Value "Update && Security" -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\13Update" -Name "SettingsURI" -Type "String" -Value "ms-settings:windowsupdate" -Force
New-Item -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\13Update\" -Name command -Force
Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\02Settings\shell\13Update\command" -Name "DelegateExecute" -Type "String" -Value "{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}" -Force

#Add "Open Command Prompt here" to context menus
& .\SetACL.exe -silent -on "HKCR:\Directory\shell\cmd" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\Directory\shell\cmd" -ot reg -actn ace -ace "n:Administrators;p:full"
& .\SetACL.exe -silent -on "HKCR:\Directory\shell\cmd\command" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\Directory\shell\cmd\command" -ot reg -actn ace -ace "n:Administrators;p:full"
Remove-Item -Path "HKCR:\Directory\shell\cmd" -Force -ErrorAction SilentlyContinue -Confirm:$false -Recurse
New-Item -Path "HKCR:\Directory\shell\" -Name "runas" -Force
Set-ItemProperty -Path "HKCR:\Directory\shell\runas" -Name '""' -Type "String" -Value "Open Command Prompt here" -Force
Set-ItemProperty -Path "HKCR:\Directory\shell\runas" -Name "Icon" -Type "String" -Value "cmd.exe" -Force
Set-ItemProperty -Path "HKCR:\Directory\shell\runas" -Name "NeverDefault" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\Directory\shell\runas" -Name "NoWorkingDirectory" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\Directory\shell\runas" -Name "Position" -Type "String" -Value "Top" -Force
New-Item -Path "HKCR:\Directory\shell\runas\" -Name "command" -Force
cmd.exe --% /c reg add "HKCR\Directory\shell\runas\command" /v "" /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
& .\SetACL.exe -silent -on "HKCR:\Directory\Background\shell\cmd" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\Directory\Background\shell\cmd" -ot reg -actn ace -ace "n:Administrators;p:full"
& .\SetACL.exe -silent -on "HKCR:\Directory\Background\shell\cmd\command" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\Directory\Background\shell\cmd\command" -ot reg -actn ace -ace "n:Administrators;p:full"
Remove-Item -Path "HKCR:\Directory\Background\shell\cmd" -Force -ErrorAction SilentlyContinue -Confirm:$false -Recurse
New-Item -Path "HKCR:\Directory\Background\shell\" -Name "runas" -Force
Set-ItemProperty -Path "HKCR:\Directory\Background\shell\runas" -Name '""' -Type "String" -Value "Open Command Prompt here" -Force
Set-ItemProperty -Path "HKCR:\Directory\Background\shell\runas" -Name "Icon" -Type "String" -Value "cmd.exe" -Force
Set-ItemProperty -Path "HKCR:\Directory\Background\shell\runas" -Name "NeverDefault" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\Directory\Background\shell\runas" -Name "NoWorkingDirectory" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\Directory\Background\shell\runas" -Name "Position" -Type "String" -Value "Top" -Force
New-Item -Path "HKCR:\Directory\Background\shell\runas" -Name "command" -Force
cmd.exe --% /c reg add "HKCR\Directory\Background\shell\runas\command" /v "" /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
New-Item -Path "HKCR:\LibraryFolder\Shell\" -Name "runas" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\Shell\runas" -Name '""' -Type "String" -Value "Open Command Prompt here" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\Shell\runas" -Name "Icon" -Type "String" -Value "cmd.exe" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\Shell\runas" -Name "NeverDefault" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\Shell\runas" -Name "NoWorkingDirectory" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\Shell\runas" -Name "Position" -Type "String" -Value "Top" -Force
New-Item -Path "HKCR:\LibraryFolder\Shell\runas\" -Name "command" -Force
cmd.exe --% /c reg add "HKCR\LibraryFolder\Shell\runas\command" /v "" /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
New-Item -Path "HKCR:\LibraryFolder\background\shell\" -Name "runas" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\background\shell\runas" -Name '""' -Type "String" -Value "Open Command Prompt here" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\background\shell\runas" -Name "Icon" -Type "String" -Value "cmd.exe" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\background\shell\runas" -Name "NeverDefault" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\background\shell\runas" -Name "NoWorkingDirectory" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKCR:\LibraryFolder\background\shell\runas" -Name "Position" -Type "String" -Value "Top" -Force
New-Item -Path "HKCR:\LibraryFolder\background\shell\runas" -Name "command" -Force
cmd.exe --% /c reg add "HKCR\LibraryFolder\background\shell\runas\command" /v "" /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f

# "Open PowerShell window here" from Shift+Right-click context menus
& .\SetACL.exe -silent -on "HKCR:\Directory\shell\Powershell" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\Directory\shell\Powershell" -ot reg -actn ace -ace "n:Administrators;p:full"
& .\SetACL.exe -silent -on "HKCR:\Directory\shell\Powershell\command" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\Directory\shell\Powershell\command" -ot reg -actn ace -ace "n:Administrators;p:full"
Remove-Item -Path "HKCR:\Directory\shell\Powershell" -Force -ErrorAction SilentlyContinue -Confirm:$false -Recurse
& .\SetACL.exe -silent -on "HKCR:\Directory\Background\shell\Powershell" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\Directory\Background\shell\Powershell" -ot reg -actn ace -ace "n:Administrators;p:full"
& .\SetACL.exe -silent -on "HKCR:\Directory\Background\shell\Powershell\command" -ot reg -actn setowner -ownr "n:Administrators"
& .\SetACL.exe -silent -on "HKCR:\Directory\Background\shell\Powershell\command" -ot reg -actn ace -ace "n:Administrators;p:full"
Remove-Item -Path "HKCR:\Directory\Background\shell\Powershell" -Force -ErrorAction SilentlyContinue -Confirm:$false -Recurse

#Enable Windows Installer in Safe Mode
cmd.exe --% /c reg add "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\MSIServer" /v "" /t REG_SZ /d "Service" /f
cmd.exe --% /c reg add "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MSIServer" /v "" /t REG_SZ /d "Service" /f

#Increase 3 pinned contacts limit on taskbar
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" -Name "People" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "TaskbarCapacity" -Type "DWORD" -Value "999" -Force

#Disable online tips in Settings
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Type "DWORD" -Value 0 -Force

#Set Do this for all current items checked by default
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "ConfirmationCheckBoxDoForAll" -Type "DWORD" -Value 1 -Force

#Add ".bat" to "New" submenu of Desktop context menu
New-Item -Path "HKLM:\Software\Classes\.bat\" -Name "ShellNew" -Force
Set-ItemProperty -Path "HKLM:\Software\Classes\.bat\ShellNew" -Name "NullFile" -Type "String" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Classes\.bat\ShellNew" -Name "ItemName" -Type "ExpandString" -Value "@$env:WINDIR\System32\acppage.dll,-6002" -Force

#Add ".reg" to "New" submenu of Desktop context menu
New-Item -Path "HKLM:\Software\Classes\.reg\" -Name "ShellNew" -Force
Set-ItemProperty -Path "HKLM:\Software\Classes\.reg\ShellNew" -Name "NullFile" -Type "String" -Value "" -Force
Set-ItemProperty -Path "HKLM:\Software\Classes\.reg\ShellNew" -Name "ItemName" -Type "ExpandString" -Value "@$env:WINDIR\regedit.exe,-309" -Force

#Disable wide context menu
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\FlightedFeatures" -Name "ImmersiveContextMenu" -Type "DWORD" -Value 0 -Force

#Disable Sharing of handwriting data
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "TabletPC" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type "DWORD" -Value 1 -Force

#Disable Sharing of handwriting error reports
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "HandwritingErrorReports" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type "DWORD" -Value 1 -Force

#Disable Inventory Collector
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "AppCompat" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type "DWORD" -Value 1 -Force

#Disable Camera in login screen
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\AccessPage\Camera" -Name "CameraEnabled" -Type "DWORD" -Value 0 -Force

#Disable transmission of typing information
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -Type "DWORD" -Value 0 -Force

#Disable Microsoft conducting experiments with this machine
New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\current\device" -Name "System" -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\System" -Name "AllowExperimentation" -Type "DWORD" -Value 0 -Force

#Disable advertisements via Bluetooth
New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\current\device" -Name "Bluetooth" -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\device\Bluetooth" -Name "AllowAdvertising" -Type "DWORD" -Value 0 -Force

#Disable Windows Customer Experience Improvement Program
Set-ItemProperty -Path "HKLM:\Software\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type "DWORD" -Value 0 -Force

#Disable syncing of text messages to Microsoft
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "Messaging" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Type "DWORD" -Value 0 -Force

#Disable application access to user account information
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Type "String" -Value "Deny" -Force

#Disable tracking of application startups
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type "DWORD" -Value 0 -Force

#Disable application access of diagnostic information
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\" -Name "DeviceAccess" -Force
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess" -Name "Global" -Force
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global" -Name "{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" -Name "Value" -Type "String" -Value "Deny" -Force

#Disable user steps recorder
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "AppCompat" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Type "DWORD" -Value 1 -Force

#Disable telemetry
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value "4" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value "4" -Force
New-Item -Path "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger" -Name "AutoLogger-Diagtrack-Listener" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" -Name "Start" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type "DWORD" -Value 0 -Force

#Disable Input Personalization
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicyy" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type "DWORD" -Value 0 -Force

#Disable updates for Speech Recognition and Speech Synthesis
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Speech_OneCore\Preferences" -Name "ModelDownloadAllowed" -Type "DWORD" -Value 0 -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft" -Name "Speech" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Speech" -Name "AllowSpeechModelUpdate" -Type "DWORD" -Value 0 -Force

#Disable functionality to locate the system
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "LocationAndSensors" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type "DWORD" -Value 1 -Force

#Disable peer-to-peer functionality in Windows Update
New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "Config" -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type "DWORD" -Value 0 -Force

#Disable ads in File Explorer and OneDrive
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type "DWORD" -Value 0 -Force

#Disable feedback reminders
New-Item -Path "HKCU:\Software\Microsoft\" -Name "Siuf" -Force
New-Item -Path "HKCU:\Software\Microsoft\Siuf" -Name "Rules" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type "DWORD" -Value 0 -Force

#Remove Task View button from taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type "DWORD" -Value 0 -Force

#Enable clipboard history
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type "DWORD" -Value 1 -Force

#Set OEM logo
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\OEMInformation" -Name "Logo" -Type "String" -Value "$env:WINDIR\Custom\logo.bmp" -Force

#Disable Open File security warning"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1806" -Type "DWORD" -Value "00000000" -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1806" -Type "DWORD" -Value "00000000" -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\" -Name "Internet Explorer" -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name "Security" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Security" -Name "DisableSecuritySettingsCheck" -Type "DWORD" -Value "00000001" -Force

#Remove "Edit with photos" from context menus"
New-Item -Path "HKCR:\" -Name "AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" -Force
New-Item -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" -Name "Shell" -Force
New-Item -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell" -Name "ShellEdit" -Force
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "ActivatableClassId" -Type "String" -Value "App.AppX65n3t4j73ch7cremsjxn7q8bph1ma8jw.mca" -Force
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "PackageId" -Type "String" -Value "Microsoft.Windows.Photos_2017.18062.12990.0_x64__8wekyb3d8bbwe" -Force
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "ContractId" -Type "String" -Value "Windows.File" -Force
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "DesiredInitialViewState" -Type "DWORD" -Value 0 -Force
cmd.exe --% /c reg add "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" /v "" /t REG_SZ /d "@{Microsoft.Windows.Photos_2017.18062.12990.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.Windows.Photos/Resources/EditWithPhotos}" /f
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "ProgrammaticAccessOnly" -Type "String" -Value "" -Force
New-Item -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "command" -Force
Set-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit\command" -Name "DelegateExecute" -Type "String" -Value "{4ED3A719-CEA8-4BD9-910D-E252F997AFC2}" -Force

#Remove "Edit with Paint 3D" from context menus"
Remove-Item -Path "HKLM\Software\Classes\SystemFileAssociations\.bmp\Shell\3D Edit" -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path "HKLM\Software\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit" -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path "HKLM\Software\Classes\SystemFileAssociations\.jpe\Shell\3D Edit" -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path "HKLM\Software\Classes\SystemFileAssociations\.jpg\Shell\3D Edit" -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path "HKLM\Software\Classes\SystemFileAssociations\.png\Shell\3D Edit" -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path "HKLM\Software\Classes\SystemFileAssociations\.gif\Shell\3D Edit" -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path "HKLM\Software\Classes\SystemFileAssociations\.tif\Shell\3D Edit" -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path "HKLM\Software\Classes\SystemFileAssociations\.tiff\Shell\3D Edit" -Force -ErrorAction SilentlyContinue -Confirm:$false

#Remove "Include in library" from context menus
Remove-Item -Path "HKCR\Folder\ShellEx\ContextMenuHandlers\Library Location" -Force -ErrorAction SilentlyContinue -Confirm:$false

#Disable Microsoft Edge prelaunching
New-Item -Path "HKCU:\Software\Policies\Microsoft" -Name MicrosoftEdge -Force
New-Item -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge" -Name TabPreloader -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowPrelaunch" -Type "DWORD" -Value 0 -Force

#Disable Microsoft Edge tab preloading
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -Type "DWORD" -Value 0 -Force

#Change active title bar color to black
cmd.exe --% /c reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentPalette" /t REG_BINARY /d "6B 6B 6B FF 59 59 59 FF 4C 4C 4C FF 3F 3F 3F FF 33 33 33 FF 26 26 26 FF 14 14 14 FF 88 17 98 00" /f 1>NUL 2>NUL
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" -Name "StartColorMenu" -Type "DWORD" -Value "4281545523" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" -Name "AccentColorMenu" -Type "DWORD" -Value "4278190080" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "AccentColor" -Type "DWORD" -Value "4278190080" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorizationColor" -Type "DWORD" -Value "3288334336" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorizationAfterglow" -Type "DWORD" -Value "3288334336" -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type "DWORD" -Value 1 -Force

#Change inactive title bar color to grey
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "AccentColorInactive" -Type "DWORD" -Value "4280953386" -Force

#Remove acrylic blur on sign-in screen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Type "DWORD" -Value 1 -Force

#Disable Some Services 
sc stop DiagTrack
sc stop diagnosticshub.standardcollector.service
sc stop dmwappushservice
sc stop WMPNetworkSvc
sc stop WSearch

sc config DiagTrack start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config dmwappushservice start= disabled
sc config remoteRegistry start= disabled
sc config TrkWks start= disabled
sc config WMPNetworkSvc start= disabled
sc config WSearch start= disabled

# This will disable certain scheduled tasks

$tasks = @(
    "\Microsoft\Office\OfficeTelemetryAgentLogOn"
    "\Microsoft\Office\OfficeTelemetryAgentFallBack"
    "\Microsoft\Office\Office 15 Subscription Heartbeat"
    
    # Windows base scheduled tasks
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319"
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64"
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical"
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical"

    #"\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Automated)"
    #"\Microsoft\Windows\Active Directory Rights Management Services Client\AD RMS Rights Policy Template Management (Manual)"

    #"\Microsoft\Windows\AppID\EDP Policy Manager"
    #"\Microsoft\Windows\AppID\PolicyConverter"
    "\Microsoft\Windows\AppID\SmartScreenSpecific"
    #"\Microsoft\Windows\AppID\VerifiedPublisherCertStoreCheck"

    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "\Microsoft\Windows\Application Experience\StartupAppTask"

    #"\Microsoft\Windows\ApplicationData\CleanupTemporaryState"
    #"\Microsoft\Windows\ApplicationData\DsSvcCleanup"

    #"\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup"

    "\Microsoft\Windows\Autochk\Proxy"

    #"\Microsoft\Windows\Bluetooth\UninstallDeviceTask"

    #"\Microsoft\Windows\CertificateServicesClient\AikCertEnrollTask"
    #"\Microsoft\Windows\CertificateServicesClient\KeyPreGenTask"
    #"\Microsoft\Windows\CertificateServicesClient\SystemTask"
    #"\Microsoft\Windows\CertificateServicesClient\UserTask"
    #"\Microsoft\Windows\CertificateServicesClient\UserTask-Roam"

    #"\Microsoft\Windows\Chkdsk\ProactiveScan"

    #"\Microsoft\Windows\Clip\License Validation"

    "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"

    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"

    #"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan"
    #"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery"

    #"\Microsoft\Windows\Defrag\ScheduledDefrag"

    #"\Microsoft\Windows\Diagnosis\Scheduled"

    #"\Microsoft\Windows\DiskCleanup\SilentCleanup"

    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    #"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"

    #"\Microsoft\Windows\DiskFootprint\Diagnostics"

    "\Microsoft\Windows\Feedback\Siuf\DmClient"

    #"\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync"

    #"\Microsoft\Windows\FileHistory\File History (maintenance mode)"

    #"\Microsoft\Windows\LanguageComponentsInstaller\Installation"
    #"\Microsoft\Windows\LanguageComponentsInstaller\Uninstallation"

    #"\Microsoft\Windows\Location\Notifications"
    #"\Microsoft\Windows\Location\WindowsActionDialog"

    #"\Microsoft\Windows\Maintenance\WinSAT"

    #"\Microsoft\Windows\Maps\MapsToastTask"
    #"\Microsoft\Windows\Maps\MapsUpdateTask"

    #"\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents"
    #"\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic"

    "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"

    #"\Microsoft\Windows\MUI\LPRemove"

    #"\Microsoft\Windows\Multimedia\SystemSoundsService"

    #"\Microsoft\Windows\NetCfg\BindingWorkItemQueueHandler"

    #"\Microsoft\Windows\NetTrace\GatherNetworkInfo"

    #"\Microsoft\Windows\Offline Files\Background Synchronization"
    #"\Microsoft\Windows\Offline Files\Logon Synchronization"

    #"\Microsoft\Windows\PI\Secure-Boot-Update"
    #"\Microsoft\Windows\PI\Sqm-Tasks"

    #"\Microsoft\Windows\Plug and Play\Device Install Group Policy"
    #"\Microsoft\Windows\Plug and Play\Device Install Reboot Required"
    #"\Microsoft\Windows\Plug and Play\Plug and Play Cleanup"
    #"\Microsoft\Windows\Plug and Play\Sysprep Generalize Drivers"

    #"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"

    #"\Microsoft\Windows\Ras\MobilityManager"

    #"\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE"

    #"\Microsoft\Windows\Registry\RegIdleBackup"

    #"\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask"

    #"\Microsoft\Windows\RemovalTools\MRT_HB"

    #"\Microsoft\Windows\Servicing\StartComponentCleanup"

    #"\Microsoft\Windows\SettingSync\NetworkStateChangeTask"

    #"\Microsoft\Windows\Shell\CreateObjectTask"
    #"\Microsoft\Windows\Shell\FamilySafetyMonitor"
    #"\Microsoft\Windows\Shell\FamilySafetyRefresh"
    #"\Microsoft\Windows\Shell\FamilySafetyUpload"
    #"\Microsoft\Windows\Shell\IndexerAutomaticMaintenance"

    #"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask"
    #"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon"
    #"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork"

    #"\Microsoft\Windows\SpacePort\SpaceAgentTask"

    #"\Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate"
    #"\Microsoft\Windows\Sysmain\HybridDriveCacheRebalance"
    #"\Microsoft\Windows\Sysmain\ResPriStaticDbSync"
    #"\Microsoft\Windows\Sysmain\WsSwapAssessmentTask"

    #"\Microsoft\Windows\SystemRestore\SR"

    #"\Microsoft\Windows\Task Manager\Interactive"

    #"\Microsoft\Windows\TextServicesFramework\MsCtfMonitor"

    #"\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime"
    #"\Microsoft\Windows\Time Synchronization\SynchronizeTime"

    #"\Microsoft\Windows\Time Zone\SynchronizeTimeZone"

    #"\Microsoft\Windows\TPM\Tpm-HASCertRetr"
    #"\Microsoft\Windows\TPM\Tpm-Maintenance"

    #"\Microsoft\Windows\UpdateOrchestrator\Maintenance Install"
    #"\Microsoft\Windows\UpdateOrchestrator\Policy Install"
    #"\Microsoft\Windows\UpdateOrchestrator\Reboot"
    #"\Microsoft\Windows\UpdateOrchestrator\Resume On Boot"
    #"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
    #"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display"
    #"\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot"

    #"\Microsoft\Windows\UPnP\UPnPHostConfig"

    #"\Microsoft\Windows\User Profile Service\HiveUploadTask"

    #"\Microsoft\Windows\WCM\WiFiTask"

    #"\Microsoft\Windows\WDI\ResolutionHost"

    "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
    "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
    "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
    "\Microsoft\Windows\Windows Defender\Windows Defender Verification"

    "\Microsoft\Windows\Windows Error Reporting\QueueReporting"

    #"\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange"

    #"\Microsoft\Windows\Windows Media Sharing\UpdateLibrary"

    #"\Microsoft\Windows\WindowsColorSystem\Calibration Loader"

    #"\Microsoft\Windows\WindowsUpdate\Automatic App Update"
    #"\Microsoft\Windows\WindowsUpdate\Scheduled Start"
    #"\Microsoft\Windows\WindowsUpdate\sih"
    #"\Microsoft\Windows\WindowsUpdate\sihboot"

    #"\Microsoft\Windows\Wininet\CacheTask"

    #"\Microsoft\Windows\WOF\WIM-Hash-Management"
    #"\Microsoft\Windows\WOF\WIM-Hash-Validation"

    #"\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization"
    #"\Microsoft\Windows\Work Folders\Work Folders Maintenance Work"

    #"\Microsoft\Windows\Workplace Join\Automatic-Device-Join"

    #"\Microsoft\Windows\WS\License Validation"
    #"\Microsoft\Windows\WS\WSTask"

    # Scheduled tasks which cannot be disabled
    #"\Microsoft\Windows\Device Setup\Metadata Refresh"
    "\Microsoft\Windows\SettingSync\BackgroundUploadTask"

)

foreach ($task in $tasks) {
    $parts = $task.split('\')
    $name = $parts[-1]
    $path = $parts[0..($parts.length-2)] -join '\'

    Disable-ScheduledTask -TaskName "$name" -TaskPath "$path" -ErrorAction SilentlyContinue
}

#Disable MRU lists (jump lists) of XAML apps in Start Menu 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Type "DWORD" -Value 0 -Force

#Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type "DWORD" -Value 1 -Force

#Show Super Hidden System Files in Explorer
    # Ask for confirmation to Show Super Hidden System Files in Explorer
    $SuperHidden = Read-Host "Would you like to Enable Hidden Files in Explorer? (Y/N)"
    if ($SuperHidden -eq 'Y') { 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type "DWORD" -Value 1 -Force
}

#Show file extensions in Explorer
    # Ask for confirmation to Show file extensions in Explorer
    $SuperHidden = Read-Host "Would you like to Show file extensions in Explorer? (Y/N)"
    if ($SuperHidden -eq 'Y') { 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type "DWORD" -Value 0 -Force
}

Start-Sleep -Seconds 2
Write-Warning "A reboot is required for all changed to take effect"
Start-Sleep -Seconds 1

#Starting Windows Explorer
explorer.exe

Clear-Host

#Install OneDrive
    # Ask for confirmation to Install Onedrive
    $InstallOneDrive = Read-Host "Would you like to Install Onedrive? (Y/N)"
    if ($InstallOneDrive -eq 'Y') { 
	    	$OneDrive = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -Force -ErrorAction Ignore
			if (-not $OneDrive)
			{
				if (Test-Path -Path $env:SystemRoot\SysWOW64\OneDriveSetup.exe)
				{
					Write-Information -MessageData "" -InformationAction Continue
					Write-Verbose -Message $Localization.OneDriveInstalling -Verbose
					Start-Process -FilePath $env:SystemRoot\SysWOW64\OneDriveSetup.exe
				}
				else
				{
					try
					{
						# Downloading the latest OneDrive installer x64
						if ((Invoke-WebRequest -Uri https://www.google.com -UseBasicParsing -DisableKeepAlive -Method Head).StatusDescription)
						{
							Write-Information -MessageData "" -InformationAction Continue
							Write-Verbose -Message $Localization.OneDriveDownloading -Verbose

							# Parse XML to get the URL
							# https://go.microsoft.com/fwlink/p/?LinkID=844652
							$Parameters = @{
								Uri             = "https://g.live.com/1rewlive5skydrive/OneDriveProduction"
								UseBasicParsing = $true
								Verbose         = $true
							}
							$Content = Invoke-RestMethod @Parameters

							# Remove invalid chars
							[xml]$OneDriveXML = $Content -replace "﻿", ""

							$OneDriveURL = ($OneDriveXML).root.update.amd64binary.url[-1]
							$DownloadsFolder = Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}"
							$Parameters = @{
								Uri         = $OneDriveURL
								OutFile     = "$DownloadsFolder\OneDriveSetup.exe"
								SslProtocol = "Tls12"
								Verbose     = $true
							}
							Invoke-WebRequest @Parameters

							Start-Process -FilePath "$DownloadsFolder\OneDriveSetup.exe"
						}
					}
					catch [System.Net.WebException]
					{
						Write-Warning -Message $Localization.NoInternetConnection
						Write-Error -Message $Localization.NoInternetConnection -ErrorAction SilentlyContinue

						Write-Error -Message ($Localization.RestartFunction -f $MyInvocation.Line) -ErrorAction SilentlyContinue

						return
					}
				}

				Get-ScheduledTask -TaskName "Onedrive* Update*" | Enable-ScheduledTask
			}
}

Start-Sleep -Seconds 2
Write-Warning "A reboot is required for all changed to take effect"
Start-Sleep -Seconds 1

Clear-Host
 ####################### End of Script ###########################
$path = Test-Path HKCR:\
IF ($path -eq $true) {Remove-PSDrive HKCR} ELSE {Write-Host }

#Delete startup shortcut
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\startup.bat" -Force -Confirm:$false -ErrorAction SilentlyContinue

Clear-Host
#Removing Leftover Files
Remove-Item -Path $env:USERPROFILE\Downloads\SetACL.exe -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path $env:USERPROFILE\Downloads\disable-edge-prelaunch.reg -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path $env:USERPROFILE\Downloads\enable-photo-viewer.reg -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path $env:USERPROFILE\Downloads\ram-reducer.reg -Force -ErrorAction SilentlyContinue -Confirm:$false
Remove-Item -Path $env:USERPROFILE\Downloads\bloatware.ps1 -Force -ErrorAction SilentlyContinue -Confirm:$false

exit
