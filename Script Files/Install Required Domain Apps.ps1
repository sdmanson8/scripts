 #Areyousure function. Alows user to select y or n when asked to exit. Y exits and N returns to main menu.  
 function areyousure {$areyousure = read-host "Are you sure you want to exit? (y/n)"  
           if ($areyousure -eq "y"){exit}  
           if ($areyousure -eq "n"){mainmenu}  
                                } 
  #Mainmenu function. Contains the screen output for the menu and waits for and handles user input.  
 function mainmenu{  
 clear  
 echo "---------------------------------------------------------"  
 echo "        Setup and Configure for Domain Policies"
 echo ""
 echo ""  
 echo "    1. Avaya Agent Desktop"
 echo "    2. Office 365 (Unlicensed)"
 echo "    3. Install Avaya Workspace"
 echo "    4. Install Ninja"
 echo "    5. Install ESET"
 echo "    6. Install FortiClient VPN"
 echo "    7. Install Reflex Remote Support"
 echo "    8. exit" 
 echo "" 
 echo ""
 echo "---------------------------------------------------------"  
 $answer = read-host "Please Make a Selection"  

 if ($answer -eq 1){
    clear
    # Avaya Agent Desktop
    Write-Host Opening Webpage to Download Prerequisites
    Start-Process http://avaya-accs/agentdesktop/setup.exe
    PAUSE
    Write-Host "Installing Avaya Agent Prerequisites"
    Start-Process C:\Users\sheldonm\Downloads\setup.exe
    PAUSE
    Remove-Item C:\Users\sheldonm\Downloads\setup.exe
    Write-Host Opening Webpage to Download Avaya Agent Desktop
    Start-Process http://avaya-accs/agentdesktop/CCADClickOnce.application
 }  
 if ($answer -eq 2){
    clear
    # Office 365 (Unlicensed)
    Write-Host "Opening Webpage to Download Office 365 (Unlicensed)"
    Start-Process "https://c2rsetup.officeapps.live.com/c2r/download.aspx?productReleaseID=O365ProPlusRetail&platform=X64&language=en-us&TaxRegion=db&correlationId=738b3e5c-6a37-4a2b-8f20-3cdd08477dd8&token=0d16b52a-7f7c-4147-8e28-50e755b1eb69&version=O16GA&source=O15OLSO365&Br=2"
    PAUSE
    Write-Host "Installing Office 365"
    Start-Process C:\Users\sheldonm\Downloads\OfficeSetup.exe
    PAUSE
    Remove-Item C:\Users\sheldonm\Downloads\OfficeSetup.exe
 }  
 if ($answer -eq 3){
    clear
    # Install Avaya Workplace
    Write-Output "Installing Avaya Workplace"
    msiexec.exe /i '\\zarbkfs01\Company Folder\Avaya IX Workplace Setup 3.8.0.136.14.msi' 
 }
  if ($answer -eq 4){
    clear
    # Install Ninja
    Write-Output "Installing Ninja"
    msiexec.exe /i '\\zarbkfs01\Company Folder\BU - EUC\BU - Managed Services\#Software\#NINJA_INSTALLS\REFLEX\reflexsolutionsworkstationmainoffice-4.4.6012-windows-installer.msi'
 }
  if ($answer -eq 5){
    clear
    # Install ESET
    Write-Output "Installing ESET"
    Start-Process -Wait -FilePath '\\zarbkfs01\Company Folder\BU - EUC\BU - Managed Services\#Software\ESET\AIO_FOR_ALL_CLIENTS\_WORK_STATION_AIO_ALL_CLIENTS_x64_en_US.exe' -ArgumentList '/S' -PassThru
 }
  if ($answer -eq 6){
    clear
    # Install FortiClient VPN
    Write-Output "Installing FortiClient VPN"
    Start-Process -Wait -FilePath '\\zarbkfs01\Company Folder\BU - EUC\BU - Managed Services\#Software\Fortinet\FortiClientSetup_6.0.9.0277_x64.exe' -ArgumentList '/S' -PassThru
 }
  if ($answer -eq 7){
    clear
    # Install Reflex Remote Support
    Write-Output "Installing Reflex Remote Support"
    msiexec.exe /i '\\zarbkfs01\Company Folder\BU - EUC\BU - Managed Services\#Software\RS\Reflex Internal\Reflex_RS_PCs.msi'
 }
 if ($answer -eq 8){areyousure} 
 else {write-host -ForegroundColor red "Invalid Selection"  
       sleep 5  
       mainmenu  
      }  
                }  
 mainmenu  
