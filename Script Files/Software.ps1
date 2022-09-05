#requires -version 5.1
# Relaunch the script with administrator privileges
Function RequireAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
        Exit
    }
}
RequireAdmin

$Host.UI.RawUI.WindowTitle = "Install Software"

########################### Script Starting ###################################
###############################################################################

Clear-Host

#Areyousure function. Alows user to select y or n when asked to exit. Y exits and N returns to main menu.  
 function areyousure {$areyousure = read-host "Are you sure you want to exit? (y/n)"  
           if ($areyousure -eq "y"){exit}  
           if ($areyousure -eq "n"){mainmenu}  
                                } 
  #Mainmenu function. Contains the screen output for the menu and waits for and handles user input.  
 function mainmenu{  
 Clear-Host  
 echo "---------------------------------------------------------"  
 echo "        Install Software"
 echo ""
 echo ""  
 echo "    1. Grammarly"
 echo "    2. Google Chrome"
 echo "    3. Firefox"
 echo "    4. Microsoft Edge"
 echo "    5. Google Drive"
 echo "    6. Tree Size" 
 echo "    7. Office Uninstaller"
 echo "    8. ProduKey (Windows License Finder)" 
 echo "    9. PatchMyPC (100+ Applications)"
 echo "    10. Update Powershell"
 echo "    11. Plex"
 echo ""
 echo "    12. Previous Menu"
 echo ""
 echo "    13. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
 
  if ($answer -eq 1){
    Clear-Host
    # Grammarly
    Write-Output "Downloading Grammarly for Windows"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://download-editor.grammarly.com/windows/GrammarlySetup.exe" -OutFile "$downloads\GrammarlySetup.exe" -UseBasicParsing
    Write-Host "Installing Grammarly"
    Start-Process -FilePath "$downloads\GrammarlySetup.exe"
    PAUSE
    Remove-Item "$downloads\GrammarlySetup.exe"
    Write-Output "Downloading Grammarly for Microsoft Office"
    Invoke-WebRequest -Uri "https://download-office.grammarly.com/latest/GrammarlyAddInSetup.exe" -OutFile "$downloads\GrammarlyAddInSetup.exe" -UseBasicParsing
    Write-Host "Installing Grammarly for Microsoft Office"
    Start-Process -Wait -FilePath "$downloads\GrammarlyAddInSetup.exe"
    PAUSE
    Remove-Item "$downloads\GrammarlyAddInSetup.exe"
    Write-Host "Opening Webpage to Setup Grammarly Addon for Microsoft Edge"
    Start-Process "https://microsoftedge.microsoft.com/addons/detail/grammarly-for-microsoft-e/cnlefmmeadmemmdciolhbnfeacpdfbkd"

 }
   if ($answer -eq 2){
    Clear-Host
    # Install Google Chrome
    Write-Output "Installing Google Chrome"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Chrome.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
    Write-Output "Setting Chrome as Default Browser... Please Wait..."
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://github.com/sdmanson8/scripts/raw/main/Script%20Files/SetDefaultBrowser.exe" -OutFile "$downloads\SetDefaultBrowser.exe" -UseBasicParsing
    Set-Location "$downloads"
    & '.\SetDefaultBrowser.exe' HKLM "Google Chrome"
    Remove-Item "$downloads\SetDefaultBrowser.exe"
 }
   if ($answer -eq 3){
    Clear-Host
    # Install Firefox
    Write-Output "Downloading Firefox"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US" -OutFile "$downloads\firefox-latest.exe" -UseBasicParsing
    Write-Host "Installing Firefox"
    Start-Process -Wait -FilePath "$downloads\firefox-latest.exe"
    Remove-Item "$downloads\firefox-latest.exe"
	Write-Output "Setting Firefox as Default Browser... Please Wait..."
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://github.com/sdmanson8/scripts/raw/main/Script%20Files/SetDefaultBrowser.exe" -OutFile "$downloads\SetDefaultBrowser.exe" -UseBasicParsing
    Set-Location "$downloads"
    & '.\SetDefaultBrowser.exe' HKLM "Firefox-308046B0AF4A39CB"
    Remove-Item "$downloads\SetDefaultBrowser.exe"
 }
   if ($answer -eq 4){
    Clear-Host
    # Install Microsoft Edge
    Write-Output "Downloading Microsoft Edge"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://c2rsetup.officeapps.live.com/c2r/downloadEdge.aspx?platform=Default&source=EdgeStablePage&Channel=Stable&language=en" -OutFile "$downloads\MicrosoftEdgeSetup.exe" -UseBasicParsing
    Write-Host "Installing Microsoft Edge"
    Start-Process -Wait -FilePath "$downloads\MicrosoftEdgeSetup.exe"
    Remove-Item "$downloads\MicrosoftEdgeSetup.exe"
    Write-Output "Setting Microsoft Edge as Default Browser... Please Wait..."
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://github.com/sdmanson8/scripts/raw/main/Script%20Files/SetDefaultBrowser.exe" -OutFile "$downloads\SetDefaultBrowser.exe" -UseBasicParsing
    Set-Location "$downloads"
    & '.\SetDefaultBrowser.exe' HKLM "Microsoft Edge"
    Remove-Item "$downloads\SetDefaultBrowser.exe"
 }
   if ($answer -eq 5){
     Clear-Host
    # Google Drive
    Write-Host "Downloading Google Drive"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://dl.google.com/drive-file-stream/GoogleDriveSetup.exe" -OutFile "$downloads\GoogleDriveSetup.exe" -UseBasicParsing
    Write-Host "Installing Google Drive"
    Start-Process -Wait -FilePath "$downloads\GoogleDriveSetup.exe"
    Remove-Item "$downloads\GoogleDriveSetup.exe"
 }
    if ($answer -eq 6){
     Clear-Host
    # Tree Size
    Write-Host "Downloading Tree Size"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest -Uri "https://downloads.jam-software.de/treesize_free/TreeSizeFreeSetup.exe" -OutFile "$downloads\TreeSizeFreeSetup.exe" -UseBasicParsing
    Write-Host "Installing Tree Size"
    Start-Process -Wait -FilePath "$downloads\TreeSizeFreeSetup.exe"
    Remove-Item "$downloads\TreeSizeFreeSetup.exe"
 }
   if ($answer -eq 7){
    Clear-Host
    # Office Uninstaller
    Write-Output "Office Uninstaller"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest "https://aka.ms/SaRA-officeUninstallFromPC" -OutFile "$downloads\SetupProd_OffScrub.exe" -UseBasicParsing
    Write-Host "Opening Office Uninstaller"
    Start-Process -FilePath "$downloads\SetupProd_OffScrub.exe"
    PAUSE
    Remove-Item "$downloads\SetupProd_OffScrub.exe"    
 }
   if ($answer -eq 8){
    Clear-Host
    # ProduKey (Windows License Finder)
    Write-Output "Downloading ProduKey"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Invoke-WebRequest "https://www.nirsoft.net/utils/produkey-x64.zip" -OutFile "$Env:Temp\produkey-x64.zip" -UseBasicParsing
    Expand-Archive -Path "$Env:Temp\produkey-x64.zip" -DestinationPath "$downloads\ProduKey x64"
    Remove-Item "$Env:Temp\produkey-x64.zip"
    Write-Output "Opening ProduKey"
    Start-Process -Wait -FilePath "$downloads\ProduKey x64\ProduKey.exe"
    Remove-Item "$downloads\ProduKey x64\ProduKey.exe"
}
 if ($answer -eq 9){
    Clear-Host
    # prompt to download PatchMyPC
    Write-Output "Downloading PatchMyPC"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/PatchMyPC.ps1 -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }  
  if ($answer -eq 10){
    Clear-Host
    # prompt to update Powershell
    Write-Host "Preparing to Update Powershell ... Please wait..."
    iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
 } 
  if ($answer -eq 11){
    Clear-Host
    # prompt to Open Plex website
    Write-Host "Preparing to Download Plex for Windows"
    Do {
    Write-Host "Proceed to Manually download Application?" -ForegroundColor Yellow
    Write-Host https://www.plex.tv/media-server-downloads/#plex-app
    $result = Read-Host "   ( y / n ) " 
}Until ($result -eq "y" -or $result -eq "n")
if($result -eq "y"){
    Start-Process "https://www.plex.tv/media-server-downloads/#plex-app"
Exit
}
function Pause{ $null = Read-Host 'Press Enter if Application downloaded' }
	Pause
    Write-Host "Installing Plex"
	$downloads=(New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
    Start-Process -Wait -FilePath "$downloads\Plex*.exe"
    PAUSE
	Remove-Item "$downloads\Plex*.exe" -Force -ErrorAction SilentlyContinue -Confirm:$false
 }  
  if ($answer -eq 12){
    # Previous Menu
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Windows.ps1" -UseBasicParsing
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 13){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
