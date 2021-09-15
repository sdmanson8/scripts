 #Areyousure function. Alows user to select y or n when asked to exit. Y exits and N returns to main menu.  
 function areyousure {$areyousure = read-host "Are you sure you want to exit? (y/n)"  
           if ($areyousure -eq "y"){exit}  
           if ($areyousure -eq "n"){mainmenu}  
                                } 
  #Mainmenu function. Contains the screen output for the menu and waits for and handles user input.  
 function mainmenu{  
 Clear-Host  
 echo "---------------------------------------------------------"  
 echo "        Install Other Software (HP)"
 echo ""
 echo ""  
 echo "    1. HP Driver Pack"
 echo "    2. HP Software Framework"
 echo "    3. HP Support Assistant"
 echo "    4. Dashlane"
 echo "    5. Grammarly"
 echo ""
 echo "    6. Install All of the Above"
 echo ""
 echo "    7. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  
 if ($answer -eq 1){
    Clear-Host
    # HP Driver Pack
    Write-Host "Opening Webpage to Download Drivers [Search for correct Laptop]"
    Start-Process http://ftp.ext.hp.com//pub/caps-softpaq/cmit/HP_Driverpack_Matrix_x64.html
    PAUSE
    Write-Host "Installing HP Drivers"
    Start-Process -Wait -FilePath $env:USERPROFILE\Downloads\sp*.exe
    Remove-Item $env:USERPROFILE\Downloads\sp*.exe
}  
 if ($answer -eq 2){
    Clear-Host
    # HP Software Framework
    Write-Host "Downloading HP Software Framework"
    Invoke-WebRequest -Uri http://ftp.ext.hp.com//pub/caps-softpaq/cmit/softpaq/CASLSetup.exe -OutFile C:\CASLSetup.exe
    Write-Host "Installing HP Software Framework"
    Start-Process -Wait -FilePath C:\CASLSetup.exe
    Remove-Item $env:USERPROFILE\Downloads\CASLSetup.exe
 }  
 if ($answer -eq 3){
    Clear-Host
    # HP Support Assistant
    Write-Host "Opening Webpage to Download HP Support Assistant"
    Start-Process https://support.hp.com/us-en/help/hp-support-assistant
    PAUSE
    Write-Host "Installing HP Support Assistant"
    Start-Process -Wait -FilePath $env:USERPROFILE\Downloads\sp*.exe
    Remove-Item $env:USERPROFILE\Downloads\sp*.exe
 }
  if ($answer -eq 4){
    Clear-Host
    # Dashlane Desktop
    Write-Host "Opening Webpage to Download Dashlane Desktop"
    Start-Process https://www.dashlane.com/download/desktop#downloaded
    PAUSE
    Write-Host "Installing Dashlane Desktop"
    Start-Process -Wait -FilePath $env:USERPROFILE\Downloads\DashlaneInst.exe
    Remove-Item $env:USERPROFILE\Downloads\DashlaneInst.exe
    Write-Host "Opening Webpage to Setup Dashlane Addon for Microsoft Edge"
    Start-Process https://microsoftedge.microsoft.com/addons/detail/dashlane-password-manag/gehmmocbbkpblljhkekmfhjpfbkclbph
 }
  if ($answer -eq 5){
    Clear-Host
    # Grammarly
    Write-Output "Downloading Grammarly for Windows"
    Invoke-WebRequest -Uri https://download-editor.grammarly.com/windows/GrammarlySetup.exe -OutFile "C:\GrammarlySetup.exe"
    Write-Host "Installing Grammarly"
    Start-Process -Wait -FilePath C:\GrammarlySetup.exe
    PAUSE
    Remove-Item C:\GrammarlySetup.exe
    Write-Output "Downloading Grammarly for Microsoft Office"
    Invoke-WebRequest -Uri https://download-office.grammarly.com/latest/GrammarlyAddInSetup.exe -OutFile "C:\GrammarlyAddInSetup.exe"
    Write-Host "Installing Grammarly"
    Start-Process -Wait -FilePath C:\GrammarlyAddInSetup.exe
    PAUSE
    Remove-Item C:\GrammarlySetup.exe
    Write-Host "Opening Webpage to Setup Grammarly Addon for Microsoft Edge"
    Start-Process https://microsoftedge.microsoft.com/addons/detail/grammarly-for-microsoft-e/cnlefmmeadmemmdciolhbnfeacpdfbkd

 }
  if ($answer -eq 6){
    Clear-Host
    # Install All of the Above
    Write-Output "Install All of the Above"
    $ScriptFromGithHub = Invoke-WebRequest https://raw.githubusercontent.com/sdmanson8/scripts/main/Script%20Files/OtherSoftware.ps1
    Invoke-Expression $($ScriptFromGithHub.Content)
 }
 if ($answer -eq 7){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
