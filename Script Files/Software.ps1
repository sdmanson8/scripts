 #Areyousure function. Alows user to select y or n when asked to exit. Y exits and N returns to main menu.  
 function areyousure {$areyousure = read-host "Are you sure you want to exit? (y/n)"  
           if ($areyousure -eq "y"){exit}  
           if ($areyousure -eq "n"){mainmenu}  
                                } 
  #Mainmenu function. Contains the screen output for the menu and waits for and handles user input.  
 function mainmenu{  
 Clear-Host  
 echo "---------------------------------------------------------"  
 echo "        Install Other Software"
 echo ""
 echo ""  
 echo "    1. Dashlane"
 echo "    2. Grammarly"
 echo "    3. Google Chrome"
 echo "    4. Firefox"
 echo "    5. Microsoft Edge"
 echo "    6. Google Drive"
 echo "    7. Tree Size" 
 echo ""
 echo "    8. Install All of the Above"
 echo " (Choose which to install Google Chrome / Firefox)"
 echo ""
 echo "    9. Office Uninstaller"
 echo "    10. ProduKey (Windows License Finder)" 
 echo ""
 echo "    11. Previous Menu"
 echo ""
 echo "    12. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
 
  if ($answer -eq 1){
    Clear-Host
    # Dashlane Desktop
    Write-Host "Opening Webpage to Download Dashlane Desktop"
    Start-Process "https://www.dashlane.com/download/desktop#downloaded"
    PAUSE
    Write-Host "Installing Dashlane Desktop"
    Start-Process -FilePath "$env:USERPROFILE\Downloads\DashlaneInst.exe"
    PAUSE
    Remove-Item "$env:USERPROFILE\Downloads\DashlaneInst.exe"
    Write-Host "Opening Webpage to Setup Dashlane Addon for Microsoft Edge"
    Start-Process "https://microsoftedge.microsoft.com/addons/detail/dashlane-password-manag/gehmmocbbkpblljhkekmfhjpfbkclbph"
 }
  if ($answer -eq 2){
    Clear-Host
    # Grammarly
    Write-Output "Downloading Grammarly for Windows"
    Invoke-WebRequest -Uri "https://download-editor.grammarly.com/windows/GrammarlySetup.exe" -OutFile "C:\GrammarlySetup.exe"
    Write-Host "Installing Grammarly"
    Start-Process -FilePath "C:\GrammarlySetup.exe"
    PAUSE
    Remove-Item "C:\GrammarlySetup.exe"
    Write-Output "Downloading Grammarly for Microsoft Office"
    Invoke-WebRequest -Uri "https://download-office.grammarly.com/latest/GrammarlyAddInSetup.exe" -OutFile "C:\GrammarlyAddInSetup.exe"
    Write-Host "Installing Grammarly for Microsoft Office"
    Start-Process -Wait -FilePath "C:\GrammarlyAddInSetup.exe"
    PAUSE
    Remove-Item "C:\GrammarlyAddInSetup.exe"
    Write-Host "Opening Webpage to Setup Grammarly Addon for Microsoft Edge"
    Start-Process "https://microsoftedge.microsoft.com/addons/detail/grammarly-for-microsoft-e/cnlefmmeadmemmdciolhbnfeacpdfbkd"

 }
   if ($answer -eq 3){
    Clear-Host
    # Install Google Chrome
    Write-Output "Installing Google Chrome"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/Chrome.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
   if ($answer -eq 4){
    Clear-Host
    # Install Firefox
    Write-Output "Downloading Firefox"
    Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US" -OutFile "C:\firefox-latest.exe"
    Write-Host "Installing Firefox"
    Start-Process -Wait -FilePath "C:\firefox-latest.exe"
    Remove-Item "C:\firefox-latest.exe"
 }
   if ($answer -eq 5){
    Clear-Host
    # Install Microsoft Edge
    Write-Output "Downloading Microsoft Edge"
    Invoke-WebRequest -Uri "https://c2rsetup.officeapps.live.com/c2r/downloadEdge.aspx?platform=Default&source=EdgeStablePage&Channel=Stable&language=en" -OutFile "C:\MicrosoftEdgeSetup.exe"
    Write-Host "Installing Microsoft Edge"
    Start-Process -Wait -FilePath "C:\MicrosoftEdgeSetup.exe"
    Remove-Item "C:\MicrosoftEdgeSetup.exe"
 }
   if ($answer -eq 6){
     Clear-Host
    # Google Drive
    Write-Host "Downloading Google Drive"
    Invoke-WebRequest -Uri "https://dl.google.com/drive-file-stream/GoogleDriveSetup.exe" -OutFile "C:\GoogleDriveSetup.exe"
    Write-Host "Installing Google Drive"
    Start-Process -Wait -FilePath "C:\GoogleDriveSetup.exe"
    Remove-Item "C:\GoogleDriveSetup.exe"
 }
    if ($answer -eq 7){
     Clear-Host
    # Tree Size
    Write-Host "Downloading Tree Size"
    Invoke-WebRequest -Uri "https://downloads.jam-software.de/treesize_free/TreeSizeFreeSetup.exe" -OutFile "C:\TreeSizeFreeSetup.exe"
    Write-Host "Installing Tree Size"
    Start-Process -Wait -FilePath "C:\TreeSizeFreeSetup.exe"
    Remove-Item "C:\TreeSizeFreeSetup.exe"
 }
  if ($answer -eq 8){
    Clear-Host
    # Install All of the Above
    Write-Output "Install All of the Above"
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/OtherSoftware.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
   if ($answer -eq 9){
    Clear-Host
    # Office Uninstaller
    Write-Output "Office Uninstaller"
    Invoke-WebRequest "https://aka.ms/SaRA-officeUninstallFromPC" -OutFile "C:\SetupProd_OffScrub.exe"
    Start-Process -Wait -FilePath "C:\SetupProd_OffScrub.exe"
    Remove-Item "C:\SetupProd_OffScrub.exe"    
 }
   if ($answer -eq 10){
    Clear-Host
    # ProduKey (Windows License Finder)
    Write-Output "Downloading ProduKey"
    Invoke-WebRequest "https://www.nirsoft.net/utils/produkey-x64.zip" -OutFile "$Env:Temp\produkey-x64.zip"
    Expand-Archive -Path "$Env:Temp\produkey-x64.zip" -DestinationPath "C:\ProduKey x64"
    Remove-Item "$Env:Temp\produkey-x64.zip"
    Write-Output "Opening ProduKey"
    Start-Process -Wait -FilePath "C:\ProduKey x64\ProduKey.exe"
    Remove-Item "C:\ProduKey x64\ProduKey.exe"
}
  if ($answer -eq 11){
    # Previous Menu
    $ScriptFromGithHub = Invoke-WebRequest "https://raw.githubusercontent.com/sdmanson8/scripts/main/Script.ps1"
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 12){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
